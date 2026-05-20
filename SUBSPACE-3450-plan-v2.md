# Subspace-3450 — Stop leaking internal-protocol error completions to user CQ

**Ticket:** https://sim.amazon.com/issues/Subspace-3450
**Branch:** `stop-leaking-protocol-completions-to-users-cq`
**Scope:** EFA RDM provider, receiver-side `fi_send`/`fi_recv` and `fi_tsend`/`fi_trecv`.

---

## Problem statement

For two-sided emulated send/recv, the EFA RDM provider selects one of several
wire protocols under the hood (eager, medium, longcts, longread, runtread,
and their DC variants). Some of these protocols require the **receiver** to
post device-level work against its own matched `rxe` (an RDMA READ, a CTS
send, a receipt send, or an EOR send). If that device work fails because the
peer cleanly canceled the request — for example the sender called `ibv_dereg_mr()` or
closed its endpoint while the protocol was mid-flight — the current code
writes a `fi_cq_err_entry` to the user's RX CQ. This surfaces an
internal-protocol failure as a user-visible recv CQ error, even though
from the `fi_recv` API contract no message was ever delivered.

Observed in the [Subspace-3450](https://issues.amazon.com/Subspace-3450) with
`fi_mr_abort` tagged test: receiver gets `cq_readerr 22 (Invalid argument),
provider errno: 7 (Remote memory registration is invalid...)` from a READ
the provider posted as part of the long-read RTM protocol.

## Goal

When the receiver's in-protocol device work fails with a status that
indicates the peer cleanly aborted (not a genuine local or network fault):

1. **Do not** write an error CQ entry to the user's RX CQ for a message the
   user never saw (unless LL128 protocol is active).
2. **Return the matched `fi_peer_rx_entry` back to the SRX** so the user's
   posted `fi_recv` can still match a future incoming message, rather than
   being silently consumed (unless LL128 protocol is active).
3. Optionally emit an EQ entry with a dedicated provider errno for
   observability.

This applies only to two-sided message / tagged protocols. RMA and atomic
paths were audited; although they have emulated variants that post
receiver-side device work, they are **not in scope** for this change because
the operations are one sided and do not post CQE's to the RX CQ —
see "Emulated RMA / atomic paths (out of scope)" below for the audit
result.

---

## Affected protocols

Susceptibility analysis by protocol (for `fi_send`/`fi_tsend` + `fi_recv`/`fi_trecv`):

| Protocol | Receiver-side device op tied to rxe | Failure modes | In scope for this ticket |
|---|---|---|---|
| `EAGER_{MSG,TAG}RTM`, `DC_EAGER_{MSG,TAG}RTM` | none (payload inline) | — | no |
| `MEDIUM_{MSG,TAG}RTM`, `DC_MEDIUM_{MSG,TAG}RTM` | none (payload in sender SENDs) | — | no |
| `LONGCTS_{MSG,TAG}RTM`, `DC_LONGCTS_{MSG,TAG}RTM` | CTS packet SEND; DC: receipt SEND | Sender-side `LOCAL_ERROR_INVALID_LKEY` from canceled source MR; pre-post detection via Subspace-3451's NULL desc. Receiver-side control-packet failures still left to the existing error path. | **yes (sender MR cancel)**; receiver-side CTS / receipt failures: no (follow-up) |
| `LONGREAD_{MSG,TAG}RTM` | RDMA READ; EOR SEND | `REMOTE_ERROR_BAD_ADDRESS` / `REMOTE_ERROR_ABORT` on READ (ticket trigger). EOR SEND failures go through the existing path. | **yes** |
| `RUNTREAD_{MSG,TAG}RTM` | RDMA READ (tail only); EOR SEND | Same as LONGREAD, on the tail READ only | **yes** |

The LONGREAD and RUNTREAD failures fail through the same dispatch
site: `efa_rdm_pke_handle_tx_error` → `case EFA_RDM_RXE:` in
`prov/efa/src/rdm/efa_rdm_pke_cmd.c`, when the failing packet is an
RDMA READ context packet. A single classifier + one new handler
covers both.

The LONGCTS sender-MR-cancel case is handled separately on the
sender side — see [LONGCTS sender-side abort](#longcts-sender-side-abort)
below.

### Emulated RMA / atomic paths (out of scope — confirmed by audit)

Audit of every emulated RMA and atomic protocol:

| Protocol | Receiver-side rxe allocation site | `EFA_RDM_OPE_INTERNAL` set? | User-CQ leak? |
|---|---|---|---|
| Emulated write target: `EAGER_RTW`, `DC_EAGER_RTW`, `LONGCTS_RTW`, `DC_LONGCTS_RTW`, `LONGREAD_RTW`, `RUNTCTS_RTW`, `RUNTREAD_RTW` | `efa_rdm_pke_alloc_rtw_rxe` (`efa_rdm_pke_rtw.c:68`) | yes (line 78) | no |
| Emulated read responder: `SHORT_RTR`, `LONGCTS_RTR`, `READ_RTR` | `efa_rdm_pke_rtr.c:87` | yes (line 95) | no |
| Atomic responder: `WRITE_RTA`, `DC_WRITE_RTA`, `FETCH_RTA`, `COMPARE_RTA` | `efa_rdm_pke_alloc_rta_rxe` (`efa_rdm_pke_rta.c`) | yes (line 102) | no |

Every receiver-side rxe for emulated RMA/atomic is allocated with the
`EFA_RDM_OPE_INTERNAL` flag set. In `efa_rdm_rxe_handle_error`
(`efa_rdm_ope.c:663-676`), any rxe with `OPE_INTERNAL` routes to
`efa_base_ep_write_eq_error` and returns early — no user CQ entry is
written. Same routing exists in `efa_rdm_txe_handle_error`
(`efa_rdm_ope.c:775-788`) for internal txes (e.g. the local-read
helper txe at `efa_rdm_ope.c:1768`).

Therefore no new code is needed to prevent user-CQ leaks for these
paths; the existing `OPE_INTERNAL` routing is sufficient.

**Why we can't just set `OPE_INTERNAL` on user-posted-recv rxes too.**
`OPE_INTERNAL` is a property set at **allocation time** on an ope that
the provider created for a protocol-internal reason (a responder-side
rxe for someone else's `fi_read`/`fi_write`/`fi_atomic`, or a helper
txe for a local read copy). The user never posted an op against it,
so there's no user-visible CQ contract to satisfy.

A user-posted `fi_recv` rxe is fundamentally different: the user
**did** post something and expects a signal. `OPE_INTERNAL` would
silence that signal unconditionally — which is wrong for normal
success (the user wants their success CQ entry).

Dynamically flipping `OPE_INTERNAL` on the rxe at the moment we
detect a peer-abort would also be wrong: it produces a third
behavior (silent EQ error + peer_rxe freed to the pool).

The emulated RMA/atomic paths are out of scope
because their failure disposition (EQ, no CQ) is acceptable — the
user never posted an op whose completion is expected. Our fix for
user-posted-recv rxes needs more handling than `OPE_INTERNAL` can
provide.

**Requester side of emulated read / fetch / compare atomic.** The
requester's txe is user-facing (not internal), but no receiver-side
device op is posted on it — the requester only posts the initial RTR
(or RTA). Failures on the responder's rxe are isolated to the
responder's EQ (see above). If the responder abandons mid-protocol
the requester may hang until unresponsive-peer detection fires. This
is pre-existing behavior, shared with LONGCTS, and is outside the
scope of this ticket.

**RMA write + `FI_REMOTE_CQ_DATA` — related recent change.**
PR [#12208](https://github.com/ofiwg/libfabric/pull/12208) ("prov/efa:
write CQ error instead of EQ error for unsolicited write recv")
updated the device `RDMA_WRITE_WITH_IMM` path on the target so write
failures now post an error CQ entry instead of going to the EQ,
aligning that path with the libfabric man page. The fix was not
applied to the emulated RTW protocols (`EAGER_RTW` / `LONGCTS_RTW` /
`LONGREAD_RTW`), whose target-side rxes are `EFA_RDM_OPE_INTERNAL`
and still route errors to the EQ. That is out of scope for this
ticket — for emulated RTW the user contract permits either an error
CQ entry or an error EQ entry, so the EQ disposition is acceptable.

## Failure classification

Only specific `prov_errno` values indicate "peer cleanly aborted":

- `EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS` (7) — sender's MR is
  invalid / dereg'd. Applies only to RDMA READ failures (control SENDs
  do not reference a remote MR). This is the exact symptom in the ticket.
- `EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT` (8) — connection reset by remote
  peer (sender EP closed mid-protocol). Applies to all receiver-initiated
  device ops (READ, CTS send, receipt send, EOR send).
- `EFA_IO_COMP_STATUS_REMOTE_ERROR_UNKNOWN_PEER` (14) — decide with team;
  likely also safe to treat as peer-clean-abort.

All other statuses (LOCAL_ERROR_*, UNRESP_REMOTE, BAD_LENGTH, RNR handled
elsewhere, etc.) represent genuine faults the user must continue to see.

Define in `efa_rdm_pke_cmd.c` (or a shared header):

```c
static inline bool efa_rdm_prov_errno_is_peer_abort(int prov_errno)
{
    return prov_errno == EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS ||
           prov_errno == EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT;
    /* TODO(team): decide UNKNOWN_PEER */
}
```

### Receive-buffer semantics

The Libfabric spec defines completions (CQEs or counters) as the
mechanism that tells the application when data has arrived in a buffer
and is safe to read. Per `fi_cq(3)` and `fi_cntr(3)`, **a successful
completion is what makes the buffer safe to reuse / read**; absence of
a completion means the buffer is not yet a valid delivery.

The spec itself does not explicitly promise the recv buffer is left
untouched if no successful completion is delivered. EFA layers one
opt-in guarantee on top via
[`fi_efa(7)`](/Users/szegel/Workplace/libfabric/man/fi_efa.7.md)
§`FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES`:

> "Enabling the option will guarantee data inside each 128 bytes
> aligned block being sent and received in order, **it will also
> guarantee data to be delivered to the receive buffer only once.**"

From this we derive the following rule for the re-queue remedy:

- **If `FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES` or is enabled on
  the endpoint AND the receive buffer has been touched**, we must
  preserve the "delivered only once" guarantee. In that case we cannot
  re-queue (a subsequent matching message could write the same
  128-byte block a second time). Write an
  error CQ entry to the user, do not re-queue.
- **If the option is not enabled, OR the receive buffer has not been
  touched**, re-queue is safe and preferred.

Today on efa RDM, the setopt for this option returns `-FI_EOPNOTSUPP`
unconditionally (`prov/efa/src/rdm/efa_rdm_ep_fiops.c:1771-1780`), so
the option is never active on RDM, but we will still protect against it
so that we properly protect against this case if it is implemented in the
future.

The analogous `FI_OPT_EFA_WRITE_IN_ORDER_ALIGNED_128_BYTES` concerns
RDMA write targets.  Since writing is a one sided operation, in order to
honor this flag, we would need to recv the entire message into a temporary
buffer, and then copy it to the user's buffer when all of the bytes are on the
targets side, and the transfer no longer depends on the network.  Properly
supporting this flag is out of scope for this change.

### Can requeue RXE classifier

```c
static inline bool efa_rdm_rxe_can_requeue(struct efa_rdm_ope *rxe)
{
    struct efa_rdm_ep *ep = rxe->ep;

    /* Re-queue only applies to user-posted two-sided recvs, which have
     * a peer_rxe to return to the SRX. Emulated RMA/atomic rxes are
     * EFA_RDM_OPE_INTERNAL and never reach this helper (the
     * OPE_INTERNAL branch in efa_rdm_rxe_handle_error catches them
     * first); their failure disposition is EQ error + ope release.
     */
    if (rxe->op != ofi_op_msg && rxe->op != ofi_op_tagged)
        return false;

    /* If the 128-byte "delivered only once" guarantee is active and
     * the recv buffer has already been touched by this rxe, we cannot
     * re-queue without risking a double-write to the same 128-byte
     * block. Fall through to Group B (write an error CQ entry and
     * release).
     */
    if (ep->sendrecv_in_order_aligned_128_bytes &&
        (rxe->bytes_received > 0 || rxe->bytes_copied > 0))
        return false;

    return true;
}
```

## Sender-side txe reclamation (in scope)

When the receiver re-queues its rxe or writes a CQ error, the sender still
has a live `txe` waiting for an EOR from the receiver. If we never send an ack/nack,
the sender's txe sits forever:

- `txe` is not released, leaking an entry in `ep->ope_pool`.
- `ep->num_read_msg_in_flight` is not decremented, which throttles
  future read-based protocol selection.
- No CQ entry (success or error) is ever written to the sender's TX
  CQ, so the sender's user code hangs on a missing completion.

Fix: **the receiver must signal the sender to abort** whenever it
decides to stop progressing a READ-based protocol on its side.

### New control packet: `EFA_RDM_PEER_ERROR_PKT`

Add a new extra-feature-gated control packet that the receiver sends
to the sender after deciding to abandon a READ-based protocol. Use a
new packet to keep semantics clean — we explicitly do **not** reuse
`EFA_RDM_READ_NACK_PKT`, because that packet's existing semantics on
the sender are "fall back to LONGCTS and retry." The abort semantic
is different: "give up, do not retry, write an error to the sender's
TX CQ." Overloading `READ_NACK` would either require a new flag bit
(cross-version protocol churn) and branching in the sender's existing
handler, or risk silently reinterpreting old peers' packets.

The LONGCTS fallback is not a viable abort signal because the receiver
sent a plain `READ_NACK`, the sender would try to retry via LONGCTS.
The sender would send a EFA_RDM_LONGCTS_*RTM_PKT which carries no user
data, and then wait for a CTS from the receiver.  The sender would then
try to access the deregistered MR fail with either a segfault or invalid
LKEY error. We would like to remove this extra RTT by directly telling the
sender to immediately create an error CQE for this operation.

Wire structure (mirrors `efa_rdm_read_nack_hdr`, extended with
`prov_errno`):

```c
/* Packet type ID: next available after EFA_RDM_READ_NACK_PKT=11.
 */
#define EFA_RDM_PEER_ERROR_PKT       12

struct efa_rdm_peer_error_hdr {
    EFA_RDM_BASE_HEADER();
    uint32_t send_id;   /* ID of the send op on the sender */
    uint32_t recv_id;   /* ID of the receive op on the receiver */
    uint32_t prov_errno;/* the prov_errno we saw on the receiver, for
                         * logging on the sender side */
    union {
        uint32_t connid;  /* optional, set when EFA_RDM_PKT_CONNID_HDR is on */
        uint32_t padding;
    };
};
EFA_RDM_ENSURE_HEADER_SIZE(efa_rdm_peer_error_hdr, 24);
```

Gate with a new extra feature so peers negotiate support via
handshake:

```c
/* Next free bit after EFA_RDM_EXTRA_FEATURE_UNSOLICITED_WRITE_RECV=8. */
#define EFA_RDM_EXTRA_FEATURE_PEER_ERROR   BIT_ULL(9)

static inline
bool efa_rdm_peer_support_peer_error(struct efa_rdm_peer *peer)
{
    return (peer->flags & EFA_RDM_PEER_HANDSHAKE_RECEIVED) &&
           (peer->extra_info[0] & EFA_RDM_EXTRA_FEATURE_PEER_ERROR);
}
```

Advertise support in `efa_rdm_ep_update_extra_info`:

```c
ep->extra_info[0] |= EFA_RDM_EXTRA_FEATURE_PEER_ERROR;
```

Bump `EFA_RDM_NUM_EXTRA_FEATURE_OR_REQUEST` from 9 to 10 in
`efa_rdm_protocol.h` so `nextra_p3` in the handshake carries the new
bit.

### Receiver-side behavior

When entering a LONGREAD/RUNTREAD RTM where the sender supports `PEER_ERROR`:

1. Allocate a `PEER_ERROR` pkt from `ep->efa_tx_pkt_pool`.
2. Fill in `send_id` from the RTM header's `send_id`, `recv_id` from
   `rxe->rx_id`, and `prov_errno` from the failing READ completion.
3. Post via `efa_rdm_ope_post_send_or_queue(rxe, EFA_RDM_PEER_ERROR_PKT)`.
4. Hand the rxe cleanup (re-queue for Group A, release for Group B)
   to the `PEER_ERROR` **send-completion handler**, not the
   peer-abort handler directly. This mirrors how EOR-in-flight gates
   rxe release today — we cannot release the rxe until the
   `PEER_ERROR` send has completed, because that send uses the rxe
   as its wr_id context. Introduce an `EFA_RDM_RXE_PEER_ERROR_IN_FLIGHT`
   internal flag analogous to `EFA_RDM_RXE_EOR_IN_FLIGHT`.
5. Decrement `ep->num_read_msg_in_flight` in the `PEER_ERROR` send
   path (symmetric with how EOR does it).

If the sender does **not** support `PEER_ERROR`
(`efa_rdm_peer_support_peer_error(peer)` returns false), the receiver
falls back to status quo: do not send the control packet, clean up
the rxe locally via the existing `efa_rdm_rxe_handle_error` path.
This means the receiver's user sees an error CQ entry and the
sender's txe still leaks on old peers — no regression from today.
Log a warning with peer identity so operators can track mixed-version
deployments. This fallback mirrors how `READ_NACK` handles
unsupported peers (see `efa_rdm_pke_utils.h:~207`).

### Sender-side behavior

Add a new handler `efa_rdm_pke_handle_peer_error_recv`:

```c
void efa_rdm_pke_handle_peer_error_recv(struct efa_rdm_pke *pkt_entry)
{
    struct efa_rdm_peer_error_hdr *err_hdr;
    struct efa_rdm_ope *txe;
    int err;

    err_hdr = (struct efa_rdm_peer_error_hdr *)pkt_entry->wiredata;
    txe = ofi_bufpool_get_ibuf(pkt_entry->ep->ope_pool, err_hdr->send_id);

    efa_rdm_ep_domain(pkt_entry->ep)->num_read_msg_in_flight -= 1;

    efa_rdm_pke_release_rx(pkt_entry);

    /* Write an error CQ entry to the user and release the txe. The
     * user sees a single error for the whole send operation,
     * matching the semantics of "the receive-side protocol failed
     * before delivery."
     */
    err = to_fi_errno(err_hdr->prov_errno);
    efa_rdm_txe_handle_error(txe, err, err_hdr->prov_errno);
    efa_rdm_txe_release(txe);
}
```

Dispatch from `efa_rdm_pke_proc_received` → case
`EFA_RDM_PEER_ERROR_PKT` (alongside the existing `READ_NACK_PKT`
case in `efa_rdm_pke_cmd.c:~848`).

Sender user sees a CQ error (no data was delivered, so "completion
means safe to reuse" is honored). The err code is propagated from
the receiver's `prov_errno`.

### Version mismatch behavior

Handshake completion is **required** before long-read / runt-read
RTMs are sent — those packet types are in the `EXTRA_REQ` range and
`efa_rdm_msg_post_rtm` calls `enforce_handshake_for_txe` for them
(`efa_rdm_msg.c:~150`). So by the time a receiver needs to emit
`PEER_ERROR`, the handshake is already complete and both peers'
`extra_info` bitmasks are known to both sides.

| Scenario | Sender supports `PEER_ERROR`? | Receiver supports? | Behavior |
|---|---|---|---|
| 1. New receiver, old sender | no (bit clear) | yes | Receiver checks `efa_rdm_peer_support_peer_error(peer)` → false. Falls back to writing user CQ error on its own RX CQ (status quo). Does not send `PEER_ERROR`. Sender's txe leaks (same as today). Warning logged on receiver with peer identity. |
| 2. Old receiver, new sender | yes | no | Receiver has no knowledge of `PEER_ERROR`. Writes user CQ error on its RX CQ (old behavior). Sender never receives the packet. Sender's txe leaks. Same outcome as scenario 1 in practice. |
| 3. Both new | yes | yes | Feature negotiation succeeds. Receiver sends `PEER_ERROR`; sender reaps txe and writes TX CQ error. Full fix. |
| 4. Stray `PEER_ERROR` at an old receiver | — | no | Should not happen — `PEER_ERROR` is only sent receiver→sender, and the receiver is by definition the one that sent the RTM's partner (so it's the sender for `PEER_ERROR`). If a hypothetical old receiver somehow receives one, `efa_rdm_pke_proc_received` hits its default case, logs "unknown packet type," writes EQ error, and drops the packet. Survivable, no crash. |

Net effect on mixed-version deployments: old senders continue to
leak txes when a new receiver aborts. No worse than today. Fully
solved when both peers are upgraded. Documentation note: call this
out in the release notes for the libfabric release that ships this
fix — "To fully fix peer-abort txe leaks, both peers must run
libfabric X.Y.Z or later."

## LONGCTS sender-side abort

The `PEER_ERROR_PKT` is bidirectional. In addition to the
receiver→sender direction (used by LONGREAD when the receiver's READ
fails), the sender also uses it to notify the receiver when the
sender's source MR is canceled mid-transfer during LONGCTS. This
section covers the LONGCTS scenario specifically. It builds directly
on Subspace-3451's MR-generation infrastructure, so a separate
pre-post detection mechanism is not needed in this plan.

### Scenario

The sender has started a LONGCTS send: the LONGCTS RTM is out, the
receiver matched it to a posted `fi_recv` and replied with a CTS. The
sender is now in the `ope_longcts_send_list` progress loop posting
`CTSDATA` packets from the user's source buffer using `txe->desc[]`.
The user calls `fi_close(mr)` on the source MR while CTSDATA packets
are still pending.

MR cancellation can happen on a separate thread at any time, so the
sender must handle two timing cases — both already covered by
Subspace-3451:

- **Pre-post**: the sender notices the MR is gone before it issues
  the next CTSDATA work request, via `efa_rdm_mr_gen_check_ope`
  returning false. `efa_rdm_ope_post_send` returns `-FI_ECANCELED`.
- **Post-post (async)**: a CTSDATA work request was already in
  flight when the MR was canceled. The device returns
  `EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY` (5) on the TX CQ.

In both cases the sender must:

1. Write a TX CQ error entry for the user's send op (existing
   `efa_rdm_txe_handle_error` already does this).
2. Notify the receiver so it can re-queue its rxe back into the SRX
   (Group A semantics) — the new behavior added by this plan.
3. Release the txe and decrement any LONGCTS bookkeeping (existing).

And the receiver must, on receipt of the `PEER_ERROR_PKT`:

1. Look up the matched rxe by `recv_id`.
2. Re-queue the `peer_rxe` back into the SRX (Group A).
3. Release the rxe internally; do not write a user CQ entry.

### Detection: Subspace-3451's gen check

Subspace-3451 (branch `mr_abort2`) provides the detection mechanism
for both pre-post and post-post cases:

**Pre-post** — `efa_rdm_ope_post_send` calls
`efa_rdm_mr_gen_check_ope(ope)` after preparing the packet. The check
returns false if any `desc[i]->gen != ope->desc_gen[i]`, indicating
the MR was closed (and possibly recycled) since dispatch. On
mismatch, `post_send` returns `-FI_ECANCELED` before any device WR
is submitted. Same gen check fires at three other entry points:
`efa_rdm_ope_post_read`, `efa_rdm_ope_repost_ope_queued_before_handshake`,
and `efa_rdm_ep_post_queued_pkts`.

**Post-post** — if the MR is closed *after* the WR is posted but
before the NIC processes it, the cached `efa_mr->lkey` (used at WR
construction time, also from Subspace-3451) is now stale relative
to the device's MR table. The NIC returns
`EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY` on the TX CQ. The
completion lands in `efa_rdm_cq_process_wc` →
`efa_rdm_pke_handle_tx_error` → `efa_rdm_txe_handle_error`.

Both paths converge on `efa_rdm_txe_handle_error`. We add a hook
there that sends `PEER_ERROR_PKT` when:

- `txe->op == ofi_op_msg || txe->op == ofi_op_tagged`,
- the txe is mid-LONGCTS-family transfer (e.g. on
  `ope_longcts_send_list`, or has `bytes_sent > 0` for a
  longcts-family pkt type),
- the err is `FI_ECANCELED` (gen check) or
  `LOCAL_ERROR_INVALID_LKEY` (NIC),
- the peer advertises `EFA_RDM_EXTRA_FEATURE_PEER_ERROR`.

If the peer does not support the feature, fall back to status quo
(write the TX CQ error, leave the receiver's rxe alone — the
receiver's posted recv will hang until ep close or unresponsive-peer
detection fires). Log a warning.

### Signal: reuse `EFA_RDM_PEER_ERROR_PKT`

No protocol additions. The packet type, header layout, feature
gate, and handshake negotiation defined in the
[New control packet](#new-control-packet-efa_rdm_peer_error_pkt)
section apply unchanged.

The sender fills the header with:

- `send_id = UINT32_MAX` (sentinel — sender→receiver direction).
- `recv_id = txe->rx_id` (the receiver-side rxe id, captured from
  the CTS the sender received).
- `prov_errno`: the underlying error that triggered the abort, so
  the receiver and any logging context get an accurate cause. Either
  `EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY` (post-WR-submit
  race, NIC-detected) or `FI_ECANCELED` (pre-post,
  Subspace-3451's gen check).

### Receiver-side handling for LONGCTS abort

The existing `efa_rdm_pke_handle_peer_error_recv` handler (defined
under [Sender-side behavior](#sender-side-behavior) — labeled from
the LONGREAD perspective; the function itself is direction-agnostic)
needs to recognize that `PEER_ERROR_PKT` can target either a txe
(LONGREAD direction) or an rxe (LONGCTS direction). The dispatcher
distinguishes by looking up the id:

```c
void efa_rdm_pke_handle_peer_error_recv(struct efa_rdm_pke *pkt_entry)
{
    struct efa_rdm_peer_error_hdr *err_hdr;
    struct efa_rdm_ope *ope;

    err_hdr = (struct efa_rdm_peer_error_hdr *)pkt_entry->wiredata;

    /* Is this for a local txe (LONGREAD-receiver-aborted) or a
     * local rxe (LONGCTS-sender-MR-canceled)? */
    if (err_hdr->send_id != UINT32_MAX) {
        /* LONGREAD direction: receiver told us our send failed. */
        ope = ofi_bufpool_get_ibuf(ep->ope_pool, err_hdr->send_id);
        assert(ope->type == EFA_RDM_TXE);
        efa_rdm_txe_handle_error(ope, FI_ECANCELED,
                                 FI_EFA_ERR_PEER_FAILED_OP);
        efa_rdm_txe_release(ope);
    } else {
        /* LONGCTS direction: sender told us their MR is gone. */
        ope = ofi_bufpool_get_ibuf(ep->ope_pool, err_hdr->recv_id);
        assert(ope->type == EFA_RDM_RXE);
        efa_rdm_rxe_handle_peer_aborted_op(ope, err_hdr->prov_errno,
                                           EFA_RDM_PEER_ERROR_PKT);
    }

    efa_rdm_pke_release_rx(pkt_entry);
}
```

A small bit of plumbing: the wire packet header keeps both
`send_id` and `recv_id`; whichever direction is "live" populates
its id and sets the other to `UINT32_MAX` (the `~0u` sentinel) so
the receiver knows which one to use. Document the convention in
the header definition.

### Updated affected-protocols table row

The "LONGCTS_{MSG,TAG}RTM, DC_LONGCTS_{MSG,TAG}RTM" row in the
[Affected protocols](#affected-protocols) table should change from
"no (follow-up)" to "**yes (sender MR cancel)**". Update it to:

| Protocol | Receiver-side device op tied to rxe | Failure modes | In scope |
|---|---|---|---|
| `LONGCTS_{MSG,TAG}RTM`, `DC_LONGCTS_{MSG,TAG}RTM` | CTS packet SEND; DC: receipt SEND | Sender-side `LOCAL_ERROR_INVALID_LKEY` from canceled source MR; pre-post detection via Subspace-3451's NULL desc | **yes (sender MR cancel)** |

Receiver-side control-packet failures (CTS / receipt / EOR with
`REMOTE_ERROR_ABORT`) remain out of scope — they go through the
existing `efa_rdm_rxe_handle_error` path. Revisit if they prove
problematic.

## Patch series

The work is split into a series of atomic commits, applied on top of
the [Subspace-3451](https://issues.amazon.com/Subspace-3451) commit
series (branch `mr_abort2`). Subspace-3451 introduces:

- Per-domain bufpools that retain `struct efa_mr` / `struct efa_rdm_mr`
  slot addresses for the domain lifetime, so `desc[i]` no longer
  dangles after `fi_close(mr)`.
- `efa_mr.gen` (monotonic counter, bumped on close/dereg) and
  `efa_mr.lkey` (cached at registration, never cleared).
- Per-iov capture of `desc_gen[]` and `desc_lkey[]` on every txe/rxe
  at dispatch time.
- `efa_rdm_mr_gen_check_ope(ope)` called at four post-time entry
  points (`efa_rdm_ope_post_send`, `efa_rdm_ope_post_read`,
  `efa_rdm_ope_repost_ope_queued_before_handshake`,
  `efa_rdm_ep_post_queued_pkts`) that returns `-FI_ECANCELED` if any
  desc has been recycled since dispatch.
- All RDM data path lkey reads switched to the cached `efa_mr->lkey`
  so concurrent close cannot crash the data path.

This affects our plan in two ways:

1. We **drop** the `EFA_RDM_TXE_HAD_MR` flag and the dedicated
   pre-post detection check — Subspace-3451's gen check covers both
   pre-post and post-post detection on the sender side via a
   single mechanism that returns `-FI_ECANCELED` from
   `efa_rdm_ope_post_send`.
2. We **gate** the LONGCTS sender-side `PEER_ERROR_PKT` emission on
   the prov_errno values produced by Subspace-3451's path
   (`-FI_ECANCELED` from the gen check, or `INVALID_LKEY` from the
   NIC for the rare race where a WR was already in flight).

Each commit builds standalone, passes the unit tests it introduces
(and all prior tests), and is independently revertible. The series
is ordered so user-visible behavior change lands last.

### 1. `prov/efa: add peer-abort prov_errno classifier`

Add the helper `efa_rdm_prov_errno_is_peer_abort` and the helper
`efa_rdm_pkt_is_rxe_protocol_op` in `efa_rdm_pke_cmd.c` (or a new
small header). Pure additions, no call sites yet. Tests:
table-driven unit test for both helpers covering the in-scope and
out-of-scope `prov_errno` values.

> ```
> prov/efa: add peer-abort prov_errno classifier
>
> Introduce efa_rdm_prov_errno_is_peer_abort() to identify the
> EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS / _ABORT codes that
> indicate the peer cleanly went away during an in-flight protocol
> step, and efa_rdm_pkt_is_rxe_protocol_op() to identify RDMA-READ
> context packets and the receiver-side control SENDs that ride on
> an rxe.  These helpers are used in subsequent commits to gate the
> new peer-abort handling without changing existing behavior.
> ```

### 2. `prov/efa: add EFA_RDM_PEER_ERROR_PKT control packet`

Wire-protocol additions only:

- `EFA_RDM_PEER_ERROR_PKT = 12` in `efa_rdm_protocol.h`.
- `struct efa_rdm_peer_error_hdr` (matches `efa_rdm_read_nack_hdr`
  layout plus `prov_errno`).
- `EFA_RDM_EXTRA_FEATURE_PEER_ERROR = BIT_ULL(9)` and bump
  `EFA_RDM_NUM_EXTRA_FEATURE_OR_REQUEST` from 9 to 10.
- `efa_rdm_peer_support_peer_error()` peer accessor.
- Init/print helpers (`efa_rdm_pke_init_peer_error`,
  `efa_rdm_pke_print_peer_error`) for completeness, mirroring
  `READ_NACK`.
- Advertise the feature bit in `efa_rdm_ep_update_extra_info`.
- Recognize the packet type in
  `efa_rdm_pke_proc_received`'s switch with a no-op handler
  (`efa_rdm_pke_handle_peer_error_recv` that just releases the
  pkt) so a peer that sends one to us doesn't trip the
  "unknown pkt type" assertion.

Tests: handshake unit test that asserts the new feature bit is
advertised and observed; a packet-roundtrip test that posts a
`PEER_ERROR_PKT` from one mock ep and verifies the other side
parses the header without writing to the user CQ.

> ```
> prov/efa: add EFA_RDM_PEER_ERROR_PKT control packet
>
> Define the packet type, header layout, extra-feature bit, and
> a no-op recv handler.  The new packet is advertised in the
> handshake so peers can negotiate support, but no code path
> emits it yet -- subsequent commits add the senders.
>
> The packet header carries both send_id and recv_id; whichever
> direction is live populates its id and sets the other to
> UINT32_MAX.  This lets a single packet type serve both the
> receiver->sender (LONGREAD) and sender->receiver (LONGCTS)
> abort directions.
> ```

### 3. `prov/efa: add SRX re-queue helper for peer_rx_entry`

Add `efa_rdm_srx_repost_peer_rxe()` in `efa_rdm_srx.c` that
returns a matched `fi_peer_rx_entry` to the head of the SRX's
posted-recv queue (msg, tag, and per-source variants). Reuses the
existing `util_srx_ctx` internals already touched in this file.

No call sites yet. Tests: unit test that posts a recv, peeks /
matches it, calls the helper, and asserts the entry reappears at
the head of the queue and is matchable by a subsequent message.

> ```
> prov/efa: add SRX re-queue helper for peer_rx_entry
>
> efa_rdm_srx_repost_peer_rxe() returns a util_rx_entry to the
> SRX's posted-recv queue without freeing it, restoring its
> RX_ENTRY_POSTED status and re-inserting at the head of the
> appropriate queue (msg/tag, with FI_ADDR_UNSPEC vs directed
> source).  The function asserts the SRX lock is held.
>
> Multi-recv child entries are documented as a known limitation:
> the child is freed via ofi_buf_free() and the owner's iov is
> not un-advanced.  Single-buffer recvs are the focus.
> ```

### 4. `prov/efa: add efa_rdm_rxe_handle_peer_aborted_op()`

Add the handler that re-queues or releases the rxe, depending on
the Group A / Group B classifier. Uses the helpers added in
commits 1, 2, and 4. No call sites yet — calling this function on
an unmatched rxe is a no-op.

Tests: unit tests that cover Group A (re-queue) and Group B
(error-CQ-and-release) paths, mocking the SRX lock and asserting
the right release function is invoked.

> ```
> prov/efa: add efa_rdm_rxe_handle_peer_aborted_op()
>
> New handler for receiver-side rxe failures whose root cause is a
> peer-side abort (sender MR canceled, peer EP closed, etc.).
> Group A returns the matched peer_rxe to the SRX so the user's
> posted recv survives; Group B writes a user CQ error when the
> opt-in 128-byte once-only guarantee is active and the buffer
> has been touched.  See SUBSPACE-3450 plan for full classifier
> rationale.
>
> No call sites yet -- the next commit wires this into the error
> dispatch.
> ```

### 5. `prov/efa: route peer-aborted READ failures through new handler`

Modify the `case EFA_RDM_RXE:` branch of
`efa_rdm_pke_handle_tx_error` to invoke
`efa_rdm_rxe_handle_peer_aborted_op` when the classifier matches.
Existing behavior preserved for everything else.

Tests: integration tests in `efa_unit_test_cq.c`:

- LONGREAD READ failure with `prov_errno=7` → re-queue, no user CQ.
- LONGREAD READ failure with `prov_errno=8` → re-queue, no user CQ.
- RUNTREAD tail-READ failure with `prov_errno=7` → re-queue.
- LONGREAD READ failure with `prov_errno=6` (BAD_LENGTH) →
  existing behavior preserved (CQ error written).
- LONGREAD READ failure with `prov_errno=13` (UNRESP_REMOTE) →
  existing behavior preserved.

> ```
> prov/efa: route peer-aborted READ failures through new handler
>
> When an RDMA-READ posted by the receiver as part of LONGREAD or
> RUNTREAD fails with REMOTE_ERROR_BAD_ADDRESS or REMOTE_ERROR_ABORT,
> dispatch to efa_rdm_rxe_handle_peer_aborted_op() instead of
> writing an internal-protocol error to the user's RX CQ.  The
> matched peer_rxe is returned to the SRX so the user's posted
> fi_recv survives.
>
> Subspace-3450.
> ```

### 6. `prov/efa: emit PEER_ERROR_PKT from receiver-side abort handler`

Extend `efa_rdm_rxe_handle_peer_aborted_op` to post a
`PEER_ERROR_PKT` to the sender before releasing/re-queueing the
rxe (gated on `efa_rdm_peer_support_peer_error(peer)`). Defer the
final rxe disposition to the `PEER_ERROR_PKT`
send-completion handler via a new
`EFA_RDM_RXE_PEER_ERROR_IN_FLIGHT` flag, mirroring
`EFA_RDM_RXE_EOR_IN_FLIGHT`. Decrement
`num_read_msg_in_flight` on the abort-send completion, mirroring
the EOR path.

Tests:

- Sender-side: `PEER_ERROR_PKT` recv on a live LONGREAD txe →
  TX CQ error, txe released, `num_read_msg_in_flight` decremented.
- Receiver-side fallback: peer doesn't advertise the feature →
  no `PEER_ERROR_PKT` is emitted; existing behavior preserved.

> ```
> prov/efa: emit PEER_ERROR_PKT from receiver-side abort handler
>
> When the receiver decides to abandon a LONGREAD/RUNTREAD protocol
> step due to a peer abort, send a PEER_ERROR_PKT so the sender can
> reap its txe and write a user-visible TX CQ error.  Without this
> signal the sender's txe leaks indefinitely.
>
> Gated on the peer's advertised EFA_RDM_EXTRA_FEATURE_PEER_ERROR
> bit; falls back to status quo (sender txe leaks) for old peers.
> The receiver's rxe disposition is deferred until the
> PEER_ERROR_PKT send completes, mirroring how EOR-in-flight gates
> rxe release today.
>
> Subspace-3450.
> ```

### 7. `prov/efa: handle inbound PEER_ERROR_PKT on the sender`

Replace the no-op `efa_rdm_pke_handle_peer_error_recv` from
commit 3 with the real implementation that distinguishes
direction by `send_id != UINT32_MAX` (LONGREAD) vs
`recv_id != UINT32_MAX` (LONGCTS), and dispatches to
`efa_rdm_txe_handle_error` or `efa_rdm_rxe_handle_peer_aborted_op`
accordingly.

Tests:

- LONGREAD direction: `PEER_ERROR_PKT` with `send_id` set → sender
  txe is failed and released.
- LONGCTS direction: `PEER_ERROR_PKT` with `recv_id` set → receiver
  rxe is re-queued.

> ```
> prov/efa: handle inbound PEER_ERROR_PKT on the sender
>
> Replace the placeholder PEER_ERROR_PKT recv handler with the real
> dispatcher.  send_id != UINT32_MAX selects the LONGREAD path
> (receiver told us our send failed); recv_id != UINT32_MAX selects
> the LONGCTS path (sender told us their MR is gone, re-queue our
> matched rxe).
>
> Subspace-3450.
> ```

### 8. `prov/efa: emit PEER_ERROR_PKT on LONGCTS source-MR cancel`

Extend `efa_rdm_txe_handle_error` to post `PEER_ERROR_PKT` when:

- the txe is mid-LONGCTS-family transfer (op is msg/tagged and the
  txe is on `ope_longcts_send_list` or has `bytes_sent > 0` for a
  longcts pkt type),
- the prov_errno indicates a canceled source MR, namely
  `EFA_IO_COMP_STATUS_LOCAL_ERROR_INVALID_LKEY` (post-WR-submit race)
  or `FI_ECANCELED` from Subspace-3451's
  `efa_rdm_mr_gen_check_ope` (pre-post detection),
- the peer supports `EFA_RDM_EXTRA_FEATURE_PEER_ERROR`.

Both detection paths converge on `efa_rdm_txe_handle_error` because
Subspace-3451's gen check returns `-FI_ECANCELED` from
`efa_rdm_ope_post_send`, which lands in the existing `handle_err`
fallback that calls `efa_rdm_txe_handle_error`. We do not introduce
a separate pre-post hook in this commit — 3451 already provides it.

Tests:

- LONGCTS CTSDATA sendv async-fails with `prov_errno=INVALID_LKEY`
  (post-WR-submit race) → TX CQ error written, `PEER_ERROR_PKT`
  posted with `recv_id == txe->rx_id`, `send_id == UINT32_MAX`.
- LONGCTS CTSDATA dispatch hits 3451's gen check, returns
  `-FI_ECANCELED` → TX CQ error written, `PEER_ERROR_PKT` posted.
- Same as above with peer feature bit cleared → no
  `PEER_ERROR_PKT` posted; sender still sees TX CQ error;
  receiver's rxe leaks (status quo for old peers).

> ```
> prov/efa: emit PEER_ERROR_PKT on LONGCTS source-MR cancel
>
> When a LONGCTS-family transfer hits a canceled source MR -- detected
> either by Subspace-3451's gen check returning -FI_ECANCELED before
> the WR is posted, or by the NIC returning LOCAL_ERROR_INVALID_LKEY
> for a WR that was already in flight when the MR was closed -- post
> a PEER_ERROR_PKT to the receiver so it can re-queue its rxe back
> into the SRX.  Without this signal the receiver's posted recv would
> wait indefinitely.
>
> Gated on the peer's EFA_RDM_EXTRA_FEATURE_PEER_ERROR bit.  Falls
> back to status quo (TX CQ error on sender, receiver rxe leak) for
> peers that don't support the feature.
>
> Subspace-3450.
> ```

### 9. `prov/efa: documentation update for peer-abort handling`

Update `prov/efa/docs/efa_rdm_protocol_v4.md` describing:

- `EFA_RDM_PEER_ERROR_PKT` and the bidirectional convention.
- The new feature bit and handshake negotiation.
- Receiver-side re-queue semantics (Group A) and the 128-byte
  guarantee carve-out (Group B).
- LONGCTS sender-MR-cancel detection (pre-post + post-post).

No code changes; pure docs.

> ```
> prov/efa: documentation update for peer-abort handling
>
> Document the EFA_RDM_PEER_ERROR_PKT control packet, the
> EFA_RDM_EXTRA_FEATURE_PEER_ERROR bit, the receiver-side rxe
> re-queue path, the 128-byte once-only-guarantee carve-out, and
> the LONGCTS sender-side MR-cancel handling.
>
> Subspace-3450.
> ```

### 10. `fabtests: add fi_mr_abort/longcts companion test`

Optional follow-up PR in the fabtests repo: extend the existing
`fi_mr_abort` test (or sibling) to cover the LONGCTS path
(disable read-based protocols via env var, force LONGCTS), close
the MR mid-CTSDATA, and assert:

- Sender sees a TX CQ error.
- Receiver does **not** see an RX CQ error.
- A subsequent matching message into the same posted recv buffer
  completes successfully.

> ```
> fabtests: add fi_mr_abort/longcts companion test
>
> Extend fi_mr_abort to cover the LONGCTS direction in addition to
> the existing LONGREAD coverage.  Forces LONGCTS by disabling
> RDMA-READ-based protocols, closes the MR mid-CTSDATA, and
> verifies the sender sees a TX CQ error while the receiver's
> posted recv survives and matches a subsequent message.
>
> Subspace-3450.
> ```

### Sequencing notes

- The series rebases on top of `mr_abort2` (Subspace-3451). Confirm
  3451 has landed in the target branch before merging this series.
- Commits 1–3 are pure additions, no behavior change. They can be
  reviewed/merged in any order among themselves.
- Commits 4–5 introduce the receiver-side re-queue for LONGREAD/RUNTREAD
  and are the core of the original ticket. Commits 6–7 add the
  sender-side notification. Commit 8 adds LONGCTS support, and
  benefits from Subspace-3451's gen check for the pre-post detection
  path (no separate pre-post commit is needed).
- Commit 5 is the first one with user-visible behavior change;
  bisect-friendly to land it after the supporting infrastructure.
- All mainline commits include their own unit tests; CI passes at
  every commit.

## Known limitations / follow-ups (out of scope)

- **Runt-read partial-buffer-dirty.** User posts `fi_recv`, gets no
  completion after a runt-read tail failure, but part of their buffer
  was written. Needs protocol redesign (bounce-buffer runt data) to be
  truly clean. Plan: follow-up ticket.
- **Multi-recv child entries.** First cut: when the aborted rxe came
  from a multi-recv child, free the child (decrement `multi_recv_ref` on
  the owner) but do not attempt to un-advance the owner's iov. Note as
  limitation. Ticket scope is single-buffer recvs.
- **Public `fi_peer` API for re-queue.** First cut reaches into
  `util_srx_ctx` internals from the EFA provider (`efa_rdm_srx.c`
  already does this). Follow-up: promote into `fi_ops_srx_owner` as a
  new `return_entry` (or similar) op so other peer providers can
  implement the same remedy.

## Tests

File: `prov/efa/test/efa_unit_test_cq.c` and sibling files.

Minimum coverage (use existing `efa_unit_test_mocks` + cmocka):

**Receiver-side, LONGREAD/RUNTREAD READ failure (Group A):**

- `test_efa_rdm_cq_longread_read_fail_bad_address_requeues_rxe`
  - Set up an rxe matched from SRX for LONGREAD TAGRTM.
  - Simulate an `IBV_WC_RDMA_READ` completion with
    `prov_errno = 7`.
  - Assert no CQ error entry written (`fi_cq_readerr` returns 0).
  - Assert SRX posted-recv queue length is 1 again (the peer_rxe was
    returned).
  - Assert `efa_rdm_rxe_release_internal` called (not `rxe_release`
    with free_entry).
- `test_efa_rdm_cq_longread_read_fail_abort_requeues_rxe`
  - Same as above but `prov_errno = 8`.
- `test_efa_rdm_cq_runtread_tail_fail_requeues_rxe`
  - Tail READ fails with `prov_errno = 7` before any payload is
    copied. Assert re-queue and no CQ error.

**Receiver-side, negative tests (existing error path preserved):**

- `test_efa_rdm_cq_longread_read_fail_bad_length_still_reports`
  - `prov_errno = 6` (BAD_LENGTH). Assert CQ error entry written as
    before; existing behavior unchanged.
- `test_efa_rdm_cq_longread_read_fail_unresp_remote_still_reports`
  - `prov_errno = 13` (UNRESP_REMOTE). Assert existing user-visible
    error entry preserved.

**Sender-side, LONGCTS source MR cancel (post-post detection):**

- `test_efa_rdm_cq_longcts_send_invalid_lkey_emits_peer_error`
  - Set up a txe mid-LONGCTS-send with `LONGCTS_*RTM_PKT` already
    sent and a CTSDATA work request posted.
  - Simulate an `IBV_WC_SEND` completion with `prov_errno = 5`
    (`LOCAL_ERROR_INVALID_LKEY`).
  - Assert: TX CQ error entry written for the txe.
  - Assert: a `PEER_ERROR_PKT` is posted to the peer (mock the
    pke_alloc + sendv path; verify the packet's `recv_id` matches
    `txe->rx_id` and `send_id == UINT32_MAX`).
  - Assert: txe released; `num_read_msg_in_flight` unchanged
    (LONGCTS doesn't increment it — runt-read does).

**Sender-side, LONGCTS source MR cancel (pre-post detection,
via Subspace-3451 gen check):**

- `test_efa_rdm_cq_longcts_send_mr_canceled_pre_post_emits_peer_error`
  - Set up a txe mid-LONGCTS-send. Snapshot `desc_gen[0]` from
    Subspace-3451's capture.
  - Bump the live `efa_mr->gen` to simulate the user closing and
    reopening (or the slot being recycled).
  - Drive the LONGCTS progress loop to attempt the next CTSDATA
    post.
  - Assert: `efa_rdm_mr_gen_check_ope` returns false,
    `efa_rdm_ope_post_send` returns `-FI_ECANCELED`, no device
    work request is submitted.
  - Assert: TX CQ error entry written; `PEER_ERROR_PKT` is posted
    with `prov_errno = FI_ECANCELED`.
  - This test depends on the Subspace-3451 series being applied;
    has no separate skip path because the dependency is hard.

**Sender-side, peer doesn't support `PEER_ERROR_PKT` (fallback):**

- `test_efa_rdm_cq_longcts_send_invalid_lkey_no_feature_no_emit`
  - Same setup as the post-post test above, but clear
    `peer->extra_info[0] & EFA_RDM_EXTRA_FEATURE_PEER_ERROR`.
  - Assert: TX CQ error entry written.
  - Assert: no `PEER_ERROR_PKT` is posted; warning logged.

**Receiver-side, `PEER_ERROR_PKT` for LONGCTS rxe:**

- `test_efa_rdm_cq_recv_peer_error_for_longcts_requeues_rxe`
  - Set up a receiver mid-LONGCTS-recv: rxe matched from SRX, CTS
    sent, awaiting CTSDATA.
  - Inject a `PEER_ERROR_PKT` recv with `recv_id == rxe->rx_id`
    and `send_id == UINT32_MAX`.
  - Assert: `efa_rdm_rxe_handle_peer_aborted_op` is called.
  - Assert: peer_rxe re-queued into SRX; no user CQ entry;
    `efa_rdm_rxe_release_internal` called.

**Receiver-side, `PEER_ERROR_PKT` for LONGREAD txe (preserves
existing direction):**

- `test_efa_rdm_cq_recv_peer_error_for_longread_fails_txe`
  - Set up a sender mid-LONGREAD-send (txe alive, awaiting EOR).
  - Inject a `PEER_ERROR_PKT` recv with `send_id == txe->tx_id`
    and `recv_id == UINT32_MAX`.
  - Assert: TX CQ error entry written; txe released;
    `num_read_msg_in_flight` decremented.

**fabtests:** Add a fabtests test that reproduces the ticket
scenario at smaller scale: client does a large send that picks
long-read, client `fi_close`s its source MR, server's `fi_recv`
does not see an error CQ entry, and a subsequent matching send
still completes into the already-posted buffer. Add a sibling
test for the LONGCTS direction: large send forced to use LONGCTS
(disable read-based protocols), client closes the MR mid-CTSDATA,
client sees a TX CQ error, server's `fi_recv` is re-queued and a
subsequent matching send completes. File as a follow-up PR
against fabtests.

## Files to change

| File | Change |
|---|---|
| `prov/efa/src/rdm/efa_rdm_pke_cmd.c` | Add classifier helpers; reroute RXE branch of `efa_rdm_pke_handle_tx_error`. |
| `prov/efa/src/rdm/efa_rdm_ope.c` | New `efa_rdm_rxe_handle_peer_aborted_op()`. |
| `prov/efa/src/rdm/efa_rdm_ope.h` | Declare new function. |
| `prov/efa/src/rdm/efa_rdm_srx.c` | New `efa_rdm_srx_repost_peer_rxe()` helper. |
| `prov/efa/src/rdm/efa_rdm_srx.h` | Export helper. |
| `prov/efa/src/efa_errno.h` | New `FI_EFA_ERR_PEER_FAILED_OP` prov_errno (optional). |
| `prov/efa/test/efa_unit_test_cq.c` + siblings | Unit tests described above. |
| `prov/efa/docs/efa_rdm_protocol_v4.md` | Documentation update. |

## Decisions needed before coding

4. Add SRX `return_entry` op to public `fi_peer.h` now, or keep it internal? **Recommend: internal helper first; promote in follow-up.**
