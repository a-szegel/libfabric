# Peer-abort: unblocking the reorder window for non-matched protocols

## Problem

The EFA RDM receiver orders all incoming two-sided messages from a peer by a
monotonic per-peer `msg_id` through a sliding reorder window (`peer->robuf`).
The window advances only when the expected `msg_id` actually arrives. The whole
subsystem rests on one invariant: **every `msg_id` the sender allocates will
eventually arrive on the wire.** The provider upholds it two ways — it rolls
back `next_msg_id` if a send fails *synchronously* before posting
(`efa_rdm_msg.c`), and once a WR is on the wire it is *retried, never
abandoned* (RNR backoff, tx-queue replay, long-read→LONGCTS NACK fallback).
There is no third state, so the window never needs to skip an id.

MR-close cancellation introduces exactly that third state. When an application
calls `fi_close()` on a source MR while a send is in the device send queue, the
device flushes the WR with `EFA_IO_COMP_STATUS_FLUSHED (prov_errno=1)`, which
maps to `FI_ECANCELED`. This is **past** the synchronous rollback point (the id
was already posted) and will **never** be retried (the whole point of abort is
"give up"). For the first time the receiver's window expects a `msg_id` that is
guaranteed never to arrive.

For protocols where the receiver pulls data or runs a CTS handshake (LONGREAD,
RUNTREAD-with-tail-READ, LONGCTS), a matched rxe already exists and the existing
`PEER_ERROR_PKT` paths reconcile it. The gap is the protocols where the
receiver builds **no rxe and posts no device op**, so all payload rides REQ
sends from the initiator:

- **EAGER** — single REQ; emits no `PEER_ERROR_PKT` at all ("nothing to do").
- **MEDIUM** — payload sprayed across REQ sends; emit is actively suppressed when
  `bytes_acked == 0` (`efa_rdm_txe_progress_peer_abort_if_drained`).
- **RUNTING READ with zero READ bytes** (`bytes_runt == total_len`) — all payload
  in runt REQ packets, no tail READ; same shape as MEDIUM.

When such a message is flushed at the source before any segment lands, the
receiver's window parks on that `exp_msg_id` forever. Every later message that
*did* arrive (and that the sender counted as a success it owes a completion for)
is buffered behind the hole and never processed. **One hole strands the entire
tail of the stream** — observed as ~500 missing RX completions behind a single
flushed send, with only a handful of genuinely leaked rxes (a different,
pre-existing population).

## Why we never hit this before

1. **The invariant held everywhere else.** Every prior failure mode either
   rolled the id back (never posted) or retried it (posted). MR-close abort is
   the only path that posts an id and then guarantees it never arrives.
2. **MR-close as a cancellation primitive is new.** This entire effort
   (Subspace-3444) is the first use of "close the MR" instead of "tear down the
   QP" to cancel in-flight ops, so the flush-after-post race never occurred.
3. **The peer-abort design reasoned about completions, not sequencing.** EAGER/
   MEDIUM-zero correctly owe **no** CQ entry, so they were scoped as "nothing to
   do." That is true for the completion debt but not for the *reorder-window
   debt* — a separate obligation the design overlooked.
4. **It is timing-dependent and was previously invisible.** The hole only
   appears when the flushed id lands mid-stream rather than at the tail; and the
   fabtest only began verifying the RX-side completion count recently, so the
   silent stranding went unmeasured. efa-direct has no provider reorder window,
   so it never exhibits the symptom.

## Solution

Add a third, completion-free failure mode to `PEER_ERROR_PKT` whose sole job is
to unblock the reorder window:

```
#define EFA_RDM_PEER_ERROR_REF_OPE_INDEX     0  /* matched ope, owes CQ error   */
#define EFA_RDM_PEER_ERROR_REF_MSG_ID        1  /* matched rxe,  owes CQ error   */
#define EFA_RDM_PEER_ERROR_REF_MSG_ID_SKIP   2  /* NEW: skip msg_id, owes NOTHING */
```

It is kept distinct from `REF_MSG_ID` because the two have opposite semantics:
`REF_MSG_ID` writes `FI_ECANCELED` on a matched rxe that took partial data;
`REF_MSG_ID_SKIP` must **never** write a user completion (nothing was delivered).

- **Emit (sender).** EAGER: emit `REF_MSG_ID_SKIP (op_id = txe->msg_id)` from the
  tx-error handler once the TX error is written (no WRs to drain). MEDIUM /
  runt-only RUNTREAD: replace the `bytes_acked == 0` *suppress* with *emit then
  release*, reusing the existing drain-deferral so the skip packet always follows
  every data WR (ordering per mr_abort design §5).
- **Receive (target).** Extend the `PEER_ERROR_PKT` handler
  (`efa_rdm_peer_queue_aborted_msg_tombstone`): the named `msg_id` never
  arrived, so there is no rxe and no segment to act on. Reuse the existing
  out-of-order machinery instead of a side table — queue the inbound
  `PEER_ERROR_PKT` itself into the reorder window at slot `msg_id`, marked with
  the existing `EFA_RDM_PKE_ABORTED` tombstone (in the overflow list if the id is
  out of window). The unchanged reorder-window drain
  (`proc_pending_items_in_robuf`) and overflow-promotion path then slide past the
  tombstone exactly as they already do for an aborted buffered RTM. The packet's
  wire `op_id` sits at the same offset the drain reads `msg_id` from, so no new
  resolution code is needed; the only critical-path change is moving the existing
  `EFA_RDM_PKE_ABORTED` check ahead of the `msg_id` read (a control-packet
  tombstone carries no RTM `msg_id` header). An id the window has already passed
  is a clean no-op (the packet is released); a buffered segment is tombstoned in
  place. No new `msg_id` is consumed on either side — the sender reuses the failed
  send's `txe->msg_id`.

Safety: per the §5 ordering guarantee, once the skip packet is processed no
segment for that `msg_id` can still arrive (EAGER never sent one; MEDIUM /
runt-only RUNTREAD's emit is drain-deferred behind all data WRs), so queueing the
tombstone cannot race a late segment.

## Commit placement

This is a **new, separate commit** (or a small series), not an amendment to the
existing ones. Rationale:

- The listed commits build the matched-rxe / matched-txe peer-abort machinery
  (`REF_OPE_INDEX`, `REF_MSG_ID`) and are correct as landed; this is an
  independent defect (reorder-window sequencing) with its own root cause.
- It adds a new wire `ref_kind`, a new sender emit path for a protocol family
  previously declared "nothing to do," and a new receiver primitive — distinct,
  reviewable units.
- It also narrows a claim in the design doc ("EAGER needs no abort handling"),
  which deserves its own documented change rather than being folded silently into
  an existing commit.

Suggested split:

1. `prov/efa: add EFA_RDM_PEER_ERROR_REF_MSG_ID_SKIP wire mode + reorder-window
   skip` (receiver primitive + handler branch + unit tests; testable in
   isolation by fabricating the never-arrived hole directly).
2. `prov/efa: emit MSG_ID_SKIP on EAGER / MEDIUM / runt-only source-MR cancel`
   (the two sender emit sites).
3. `prov/efa: doc update — msg_id sequencing obligation for EAGER/MEDIUM abort`
   (amends the "nothing to do" claim).
