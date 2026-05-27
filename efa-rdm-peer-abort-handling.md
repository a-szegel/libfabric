# Stop leaking internal-protocol error completions to user CQ

---

## Background

For two-sided emulated send/recv, the EFA RDM provider selects one of several
wire protocols under the hood (eager, medium, longcts, longread, runtread, plus
DC variants). Some of these protocols require the **receiver** to post
device-level work against its own matched `rxe` — an RDMA READ for
LONGREAD/RUNTREAD, or control SENDs (CTS, RECEIPT, EOR) for LONGCTS.

Before this change, when that device work failed because the peer cleanly
canceled the request — for example the sender called `ibv_dereg_mr()` or closed
its endpoint while the protocol was mid-flight — the provider wrote a
`fi_cq_err_entry` to the user's RX CQ. This surfaced an internal-protocol
failure as a user-visible recv error, even though from the `fi_recv` API
contract no message was ever delivered.

## Approach

Two coordinated changes:

1. **Receiver side:** when a receiver-initiated device op fails with a
   prov_errno that means the peer cleanly aborted, return the matched
   `peer_rxe` to the SRX so the user's posted `fi_recv` survives, and write no
   user-visible CQ entry. If re-queue is unsafe, fall back to writing a CQ
   error.

2. **Bidirectional control packet:** a new `EFA_RDM_PEER_ERROR_PKT`, gated by
   the negotiated `EFA_RDM_EXTRA_FEATURE_PEER_ERROR` bit, lets either side
   notify the other when it has decided to abandon an in-flight protocol step.
   The receiver uses it to tell the sender "your send won't complete; reap the
   txe." The sender uses it to tell the receiver "my source MR is gone;
   re-queue your rxe."

The same wire packet, the same handler, and the same re-queue helper serve
both directions; direction is recovered from the local ope's type.

## Affected protocols

Per-protocol scope as shipped:

| Protocol | Receiver-side device op tied to rxe | Failure modes addressed | In scope |
|---|---|---|---|
| `EAGER_{MSG,TAG}RTM`, `DC_*` | none (payload inline) | — | no |
| `MEDIUM_{MSG,TAG}RTM`, `DC_*` | none (payload in sender SENDs) | — | no |
| `LONGCTS_{MSG,TAG}RTM`, `DC_*` | CTS / RECEIPT SEND | Sender source-MR cancel — pre-post via the MR-generation check (`-FI_ECANCELED`); post-post via NIC's `LOCAL_ERROR_INVALID_LKEY`. Receiver-side control-SEND failures left to existing path. | yes (sender direction) |
| `LONGREAD_{MSG,TAG}RTM` | RDMA READ; EOR SEND | `REMOTE_ERROR_BAD_ADDRESS` / `REMOTE_ERROR_ABORT` on READ. EOR SEND failures left to existing path. | yes |
| `RUNTREAD_{MSG,TAG}RTM` | RDMA READ (tail only); EOR SEND | Same as LONGREAD, on the tail READ. | yes |

The READ-failure path dispatches in `efa_rdm_pke_handle_tx_error` →
`case EFA_RDM_RXE`. A single `efa_rdm_pkt_is_rxe_remote_read` +
`efa_rdm_prov_errno_is_peer_abort` check covers both LONGREAD and RUNTREAD.

## Design

### Failure classification

A failure is treated as a peer-clean abort iff `prov_errno` is one of:

- `EFA_IO_COMP_STATUS_REMOTE_ERROR_BAD_ADDRESS` (7) — sender's MR is invalid
  or dereg'd. Applies to receiver-initiated RDMA READs.
- `EFA_IO_COMP_STATUS_REMOTE_ERROR_ABORT` (8) — connection reset by remote
  peer (sender EP closed mid-protocol). Applies to all receiver-initiated
  device ops.

Everything else (LOCAL_ERROR_*, UNRESP_REMOTE, BAD_LENGTH, RNR-handled-elsewhere,
etc.) continues to surface as a genuine fault — the user must continue to see
those.

LONGCTS source-MR cancel on the **sender** side is detected separately, by
either `FI_ECANCELED` (the MR-generation check, pre-post) or
`LOCAL_ERROR_INVALID_LKEY` (NIC, post-post).

### Recv-buffer semantics and the re-queue rule

Per `fi_cq(3)` and `fi_cntr(3)`, a successful completion is what makes the
buffer safe to reuse / read; absence of a completion means the buffer is not
yet a valid delivery. The spec doesn't explicitly promise the recv buffer is
left untouched if no successful completion is delivered. EFA layers one
opt-in guarantee on top via `fi_efa(7)`'s
`FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES`:

> "Enabling the option will guarantee data inside each 128 bytes aligned
> block being sent and received in order, **it will also guarantee data to
> be delivered to the receive buffer only once.**"

This produces the rule:

- If the option is active **and** the recv buffer has been touched
  (`bytes_received > 0` or `bytes_copied > 0`), we cannot re-queue — a
  subsequent matching message could write the same 128-byte block twice. Take
  the user-CQ-error path.
- Otherwise re-queue is safe and preferred.

Today the `setopt` for this option returns `-FI_EOPNOTSUPP` on RDM
(`efa_rdm_ep_fiops.c:1771-1780`), so the option is never active. The check is
in place defensively for if/when it becomes supported.

The analogous `FI_OPT_EFA_WRITE_IN_ORDER_ALIGNED_128_BYTES` (RDMA write
target) is out of scope; properly honoring it would require staging the
transfer through a temporary buffer.

### Re-queue vs user CQ error

Re-queue is taken when **all** of the following hold:

- The op is `ofi_op_msg` or `ofi_op_tagged` (re-queue makes no sense for
  emulated RMA / atomic; those rxes are `EFA_RDM_OPE_INTERNAL` and never
  reach this handler anyway).
- The matched `peer_rxe` is still attached.
- The matched `peer_rxe` is **not** a multi-recv child
  (`peer_rxe->owner_context == NULL`).
- The 128-byte once-only-delivery option is not active or the buffer is
  untouched.

The multi-recv carve-out is forced by spec: the owner buffer's iov has
already been advanced past the carved slice when the child was matched, and
the SRX has no mechanism to un-advance. `fi_cq(3)` requires an error
completion for the failed message and `fi_msg(3)` requires a single
`FI_MULTI_RECV` release entry when the owner buffer is consumed; both are
honored by the user-CQ-error path, which additionally calls
`peer_srx->owner_ops->free_entry` to decrement `multi_recv_ref` and trigger
the release CQ entry when the owner is fully consumed.

**Pre-existing limitation of the user-CQ-error path.** When we delegate to
`efa_rdm_rxe_handle_error` it intentionally does **not** release the rxe — a
TODO in that function explains: late packets may still reference the rxe;
ref counting is the proper fix. The rxe stays in `EFA_RDM_OPE_ERR` and
occupies an `ope_pool` slot until EP close, where three cleanup loops (in
`efa_rdm_peer_destruct`, `efa_rdm_ep` close, and the domain srx-lock loop)
reap it. The peer-abort handler inherits this: the user-CQ-error path is no
worse than the existing `handle_error` callers but no better either.
Long-lived EPs that hit a lot of peer-aborts will see `ope_pool` slowly
fill up; once full, new rxe allocations fail with `-FI_EAGAIN`. The
re-queue path does not have this issue — it explicitly calls
`efa_rdm_rxe_release_internal` once the `peer_rxe` is back in the SRX.
Ref-counting cleanup of the user-CQ-error path is tracked as the existing
TODO. 

### New control packet: `EFA_RDM_PEER_ERROR_PKT`

A new control packet (type ID 12), gated by a new extra-feature bit
introduced in libfabric 2.6:

```c
struct efa_rdm_peer_error_hdr {
    EFA_RDM_BASE_HEADER();
    uint32_t op_id;       /* ID of the ope owned by the receiver of this packet */
    uint32_t prov_errno;  /* prov_errno that triggered the abort, for logging */
    union {
        uint32_t connid;
        uint32_t padding;
    };
};
EFA_RDM_ENSURE_HEADER_SIZE(efa_rdm_peer_error_hdr, 16);

#define EFA_RDM_EXTRA_FEATURE_PEER_ERROR  BIT_ULL(9)
```

Two design choices worth calling out:

**Why a new packet type instead of reusing `READ_NACK`.** `READ_NACK`'s
sender-side semantic is "fall back to LONGCTS and retry." The abort
semantic is different: "give up, do not retry, write an error to the
sender's TX CQ." Overloading `READ_NACK` would require a new flag bit
(cross-version protocol churn) or risk silently reinterpreting old peers'
packets. A clean new packet type with handshake negotiation is safer.
Also, the LONGCTS retry would just hit the same dead MR a second time —
extra RTT for no benefit.

**Why a single `op_id` instead of `send_id` + `recv_id`.** The `op_id`
always references an ope owned by the *receiver of the packet* — the
sender's txe in the LONGREAD direction, the receiver's rxe in the LONGCTS
direction. The receive-side dispatcher recovers direction by looking the
ope up and inspecting its `type` field (`EFA_RDM_TXE` vs `EFA_RDM_RXE`).
One id, one type switch, no on-the-wire direction discriminator. The wire
format does not need to change if we extend the packet to other in-flight
failure modes later.

The feature is advertised in the handshake so peers negotiate support
before either side emits the packet. By the time a receiver might emit
`PEER_ERROR_PKT`, the handshake has already completed: LONGREAD / RUNTREAD
RTMs are in the `EXTRA_REQ` range and `efa_rdm_msg_post_rtm` enforces
handshake-first.

### Bidirectional use

**Receiver → sender (LONGREAD direction).** When an RDMA READ posted as
part of LONGREAD or RUNTREAD fails with a peer-abort errno:

1. The receiver applies the user-visible remedy synchronously: re-queue the
   `peer_rxe` to the SRX, **or**, if re-queue is unsafe, write a user CQ
   error (with the multi-recv `free_entry` follow-up if needed).
2. If the peer advertises `PEER_ERROR`, post a `PEER_ERROR_PKT` to the
   sender. The rxe is the wr_id context for that send, so the rxe's release
   is deferred to the send-completion handler under the
   `EFA_RDM_RXE_PEER_ERROR_IN_FLIGHT` flag.
3. If the peer does not support the feature, the local remedy still
   applies; the sender's txe leaks (status quo for old peers, warning
   logged).

The sender's inbound dispatcher sees `ope->type == EFA_RDM_TXE`, decrements
`num_read_msg_in_flight`, writes a TX CQ error via
`efa_rdm_txe_handle_error`, and releases the txe.

**Sender → receiver (LONGCTS direction).** When the sender's source MR is
canceled mid-CTSDATA — `FI_ECANCELED` from the MR-generation check, or
`LOCAL_ERROR_INVALID_LKEY` from the NIC — the existing
`efa_rdm_txe_handle_error` writes the TX CQ error and additionally posts a
`PEER_ERROR_PKT` to the receiver. Conditions on emission:

- txe is user-posted (`!(internal_flags & OPE_INTERNAL)`).
- Op is msg / tagged.
- `bytes_sent > 0` (mid-CTS-driven transfer; cheapest discriminator that
  excludes pre-CTS failures).
- err matches (`FI_ECANCELED` or `LOCAL_ERROR_INVALID_LKEY`).
- Peer advertises `PEER_ERROR`.

The receiver's inbound dispatcher sees `ope->type == EFA_RDM_RXE` and
routes through `efa_rdm_rxe_handle_peer_aborted_op` — the same handler the
receiver-side error-dispatch site uses. Re-queue / CQ-error logic is
shared between the two trigger sources.

**Loop suppression.** The peer-abort handler takes a `pkt_type` argument.
When the handler is invoked from an inbound `PEER_ERROR_PKT` (LONGCTS
direction), emission is short-circuited: the sender already knows about
the error — it told us — so sending a `PEER_ERROR_PKT` back would loop.

### Version compatibility

Handshake completion is required before any LONGREAD / RUNTREAD RTM is
sent, so by the time the abort path could fire, both peers' `extra_info`
bitmasks are known to both sides.

| Scenario | Sender supports | Receiver supports | Behavior |
|---|---|---|---|
| New ↔ new | yes | yes | Full fix. `PEER_ERROR_PKT` flows; both sides reap their opes. |
| New receiver, old sender | no | yes | Receiver gates on `efa_rdm_peer_support_peer_error(peer)` → false. Local remedy still applied. Sender's txe leaks (status quo). Warning logged. |
| Old receiver, new sender | yes | no | Receiver has no knowledge of `PEER_ERROR`. Writes its own RX CQ error (old behavior). Sender's txe leaks. |
| Stray `PEER_ERROR` at an old receiver | — | no | Default case in `efa_rdm_pke_proc_received` logs "unknown packet type," writes EQ error, drops. Survivable, no crash. |

Net: mixed-version deployments are no worse than today and fully fixed once
both peers run libfabric 2.6+. Release notes should call this out: "To
fully fix peer-abort txe leaks, both peers must run libfabric 2.6 or
later."

---

## Out of scope (audited)

### Emulated RMA / atomic paths

| Protocol | Receiver-side rxe allocation site | `EFA_RDM_OPE_INTERNAL` set? | User-CQ leak risk? |
|---|---|---|---|
| Emulated write target (`EAGER_RTW`, `DC_EAGER_RTW`, `LONGCTS_RTW`, `DC_LONGCTS_RTW`, `LONGREAD_RTW`, `RUNTCTS_RTW`, `RUNTREAD_RTW`) | `efa_rdm_pke_alloc_rtw_rxe` | yes | no |
| Emulated read responder (`SHORT_RTR`, `LONGCTS_RTR`, `READ_RTR`) | `efa_rdm_pke_rtr.c` | yes | no |
| Atomic responder (`WRITE_RTA`, `DC_WRITE_RTA`, `FETCH_RTA`, `COMPARE_RTA`) | `efa_rdm_pke_alloc_rta_rxe` | yes | no |

Every receiver-side rxe for emulated RMA / atomic is allocated with
`EFA_RDM_OPE_INTERNAL`. In `efa_rdm_rxe_handle_error` and
`efa_rdm_txe_handle_error`, any internal ope routes to
`efa_base_ep_write_eq_error` and returns early — no user CQ entry. No new
code is needed.

We can't simply set `OPE_INTERNAL` on user-posted recvs to reuse this path:
`OPE_INTERNAL` silences the success completion too, which the user wants.
Dynamically flipping the flag on abort would produce a third behavior
(silent EQ error + `peer_rxe` freed). User-posted recvs need their own
re-queue plumbing — that's what this change adds.

### Receiver-side LONGCTS / EOR control SEND failures

CTS / RECEIPT / EOR SEND failures (with `REMOTE_ERROR_ABORT`) still route
through the existing `efa_rdm_rxe_handle_error` path. They were left out
deliberately because the trigger pattern is rarer. Revisit if they prove
problematic in practice.

### `FI_OPT_EFA_WRITE_IN_ORDER_ALIGNED_128_BYTES`

Honoring this on RMA write targets would require staging the transfer
through a temporary buffer and copying once the network operation
completes. Out of scope.

### PR #12208 (RMA write + `FI_REMOTE_CQ_DATA`)

That PR moved device `RDMA_WRITE_WITH_IMM` failures from EQ to user CQ on
the target. Emulated RTW protocols (`EAGER_RTW` / `LONGCTS_RTW` /
`LONGREAD_RTW`) were intentionally not changed there: their target-side
rxes are `OPE_INTERNAL` and the EQ disposition is acceptable per the man
page contract. Out of scope here too.

---

## Code map

| File | Change |
|---|---|
| `prov/efa/src/rdm/efa_rdm_protocol.h` | New packet type ID `EFA_RDM_PEER_ERROR_PKT` (12), feature bit `EFA_RDM_EXTRA_FEATURE_PEER_ERROR` (`BIT_ULL(9)`), `struct efa_rdm_peer_error_hdr`, `EFA_RDM_NUM_EXTRA_FEATURE_OR_REQUEST` bumped to 10. |
| `prov/efa/src/rdm/efa_rdm_pke_cmd.h` | New helpers `efa_rdm_prov_errno_is_peer_abort()` and `efa_rdm_pkt_is_rxe_remote_read()`. |
| `prov/efa/src/rdm/efa_rdm_pke_cmd.c` | Dispatch READ failures with peer-abort errno to `efa_rdm_rxe_handle_peer_aborted_op`. Wire `PEER_ERROR_PKT` into `proc_received`, `handle_send_completion`, and `handle_sent` switches. |
| `prov/efa/src/rdm/efa_rdm_peer.h` | `efa_rdm_peer_support_peer_error()` predicate. |
| `prov/efa/src/rdm/efa_rdm_ep_fiops.c` | Advertise `EFA_RDM_EXTRA_FEATURE_PEER_ERROR` in `set_extra_info`. |
| `prov/efa/src/rdm/efa_rdm_pke_nonreq.{h,c}` | `efa_rdm_pke_init_peer_error()`, `efa_rdm_pke_init_peer_error_for_ope()`, and the inbound dispatcher `efa_rdm_pke_handle_peer_error_recv()` (TXE / RXE switch on `ope->type`). |
| `prov/efa/src/rdm/efa_rdm_pke_utils.c` | `connid_ptr` case for the new packet. |
| `prov/efa/src/rdm/efa_rdm_srx.{h,c}` | `efa_rdm_srx_repost_peer_rxe()` re-queue helper. |
| `prov/efa/src/rdm/efa_rdm_ope.h` | New `peer_error_prov_errno` field on `struct efa_rdm_ope`, new `EFA_RDM_RXE_PEER_ERROR_IN_FLIGHT` flag (`BIT_ULL(19)`), declare `efa_rdm_rxe_handle_peer_aborted_op()`. |
| `prov/efa/src/rdm/efa_rdm_ope.c` | `efa_rdm_rxe_can_requeue()` (static), `efa_rdm_rxe_handle_peer_aborted_op()` with the multi-recv carve-out, LONGCTS sender-side emission appended to `efa_rdm_txe_handle_error`. |
| `prov/efa/docs/efa_rdm_protocol_v4.md` | New §4.10 documenting `PEER_ERROR_PKT`, the feature bit, and the peer-abort handling. |
| `prov/efa/test/efa_unit_test_*` | Unit tests for the classifier, the re-queue helper, the abort handler (LONGREAD + LONGCTS), the inbound dispatcher; plus an unrelated buffer-leak fix in `efa_unit_test_mr.c`. |

---

## Follow-up

- **rxe ref-counting.** The user-CQ-error path's "rxe leaks until close"
  behavior is the existing `efa_rdm_rxe_handle_error` TODO; a proper
  ref-count fix would let the rxe be reaped at last-packet-completion.
