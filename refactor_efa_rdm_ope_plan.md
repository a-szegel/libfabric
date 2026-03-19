Implementation Plan — Refactor struct efa_rdm_ope into per-protocol structures

Problem Statement:
struct efa_rdm_ope is 872 bytes (14 cache lines) and used for every TX and RX operation. Every code path loads cache lines it doesn't need because TX, RX, RMA, and atomic fields are all packed together. The goal
is to split it into per-protocol structs using poor-man's inheritance, targeting <7 cache lines per non-atomic protocol struct, with efa_proto_ naming.

Requirements:
- Replace monolithic efa_rdm_ope with base + per-protocol structs using first-member inheritance
- Single bufpool via a union struct (efa_proto_op_entry)
- Do NOT split msg sub-protocols — they share the same ope fields
- static_assert on every new struct for size budgets and hot-field cache line placement
- Rename from efa_rdm_ to efa_proto_ prefix
- Each non-atomic protocol struct < 7 cache lines (448 bytes)
- No behavior changes — pure structural refactor
- dlist entries go only where needed; dead ones get deleted
- No test modifications unless explicitly requested

Background — Why NOT split msg sub-protocols:

The msg path has sub-protocols (eager, medium, longcts, longread, runt) but they must NOT be split into separate structs. Protocol selection happens at send time in efa_rdm_msg_select_rtm() based on message size
and peer capabilities — it's a packet-level decision, not a structural one. All msg sub-protocols use the same ope fields: msg_id, tag, ignore, total_len, iov/iov_count, desc, cq_entry, fi_flags, internal_flags
, state, peer, ep, etc.

The differences between sub-protocols are in packet header construction (handled in efa_rdm_pke_rtm.c, not the ope struct) and which progress-tracking counters are used. These counters are small (8 bytes each) 
and shared across sub-protocols:
- window — longcts (CTS flow control) and RTR
- bytes_runt — runtread
- bytes_read_* — longread and runtread
- bytes_received_via_mulreq — medium and runtread RX

Sub-protocols overlap in counter usage. Runtread uses both bytes_runt AND bytes_read_*. Longread uses bytes_read_* AND window. Splitting would create a combinatorial mess for negligible savings (~1 cache line at
best for eager, but the shared counters would need a common sub-struct that medium/longcts/longread/runt all include anyway).

The real wins come from the TX/RX/RMA/atomic split, where field sets are large and non-overlapping:
- atomic_hdr + atomic_ex ≈ 216 bytes, only touched by atomic ops (~3.4 cache lines eliminated from every non-atomic op)
- bytes_write_* = 24 bytes, only RMA write
- RX-only fields (bytes_received*, cuda_copy_method, unexp_pkt, rxe_map, peer_rxe, ack_list_entry, ignore) ≈ 80 bytes eliminated from TX paths
- TX-only fields (bytes_acked, bytes_sent, local_read_pkt_entry) ≈ 24 bytes eliminated from RX paths

Key Design Decisions:

1. iov[], desc[], mr[] stay in efa_proto_op_base (128 bytes). They're accessed by all 16 source files across every protocol path. Duplicating them in tx_base and rx_base saves nothing.

2. rma_iov[] and rma_iov_count stay in efa_proto_op_base (104 bytes). Analysis shows they're used by TX msg (longread/runtread set them), TX RMA read, TX RMA write, TX atomic, RX msg (longread/runtread), RX RMA 
read (RTR responder), RX RMA write (RTW responder), and RX atomic. That's every leaf struct. Putting them in base avoids duplicating the definition everywhere for zero savings.

3. tag goes in efa_proto_op_base. It's set by TX tagged sends (efa_rdm_ep_alloc_txe), read by TX packet init functions (efa_rdm_pke_set_rtm_tag), set on RX from incoming packets (efa_rdm_pke_rtm_update_rxe), and
used in tracepoints and completion reporting on both sides.

4. window goes in both efa_proto_tx_msg and efa_proto_rx_msg (and efa_proto_rx_rma_read for RTR responder). It's not in base because eager TX msg and RMA write paths never touch it.

5. Base struct estimated size: ~350 bytes (5.5 cache lines). This leaves ~100 bytes (1.5 cache lines) of headroom for leaf-specific fields before hitting the 7 cache line budget. Non-atomic leaf structs will 
comfortably fit. efa_proto_tx_atomic will be the largest due to atomic_ex (~208 bytes) pushing it to ~560 bytes (~8.75 cache lines) — this is acceptable since atomic is the least performance-critical path and 
still a major improvement over 14 cache lines.

6. Within each struct, fields are ordered: hot fields first (accessed on every operation in that protocol), then cold fields. Within each thermal zone, order largest-to-smallest to minimize padding holes.

"Any ope" functions requiring type-switching:

These functions take a generic ope pointer and operate on both TX and RX entries. After the refactor, they take struct efa_proto_op_base * and use base->type to switch:

- efa_rdm_ope_handle_recv_completed() — switches on type to call TX vs RX completion
- efa_rdm_ope_handle_send_completed() — switches on type to call TX vs RX release
- efa_rdm_ope_post_send() / efa_rdm_ope_post_send_or_queue() / efa_rdm_ope_post_send_fallback() — used by both TX and RX (RX sends CTS/EOR/RECEIPT/READRSP/ATOMRSP)
- efa_rdm_ope_prepare_to_post_send() — accesses window, bytes_sent, bytes_runt which are in leaf structs; needs to cast based on type
- efa_rdm_ope_try_fill_desc() — operates on base fields only (iov, desc, mr)
- efa_rdm_ope_post_read() / efa_rdm_ope_prepare_to_post_read() — used by TX RMA read, TX msg (longread/runtread), and RX msg (longread responder)
- efa_rdm_ope_post_remote_write() / efa_rdm_ope_prepare_to_post_write() — TX RMA write only
- efa_rdm_ope_process_queued_ope() — progress engine queue iteration, switches on op field
- efa_rdm_ope_repost_ope_queued_before_handshake() — switches on op to dispatch to msg/rma/atomic post functions
- efa_rdm_ope_mulreq_total_data_size() — accesses total_len (base) and bytes_runt (leaf)

Domain iteration sites that use dlist_foreach_container with struct efa_rdm_ope:
- efa_domain.c: ope_queued_list iteration → changes to struct efa_proto_op_base
- efa_domain.c: ope_longcts_send_list iteration → changes to struct efa_proto_op_base
- efa_rdm_ep_fiops.c: ope_queued_list cleanup → changes to struct efa_proto_op_base

PKE interaction:
- pke->ope pointer type changes from struct efa_rdm_ope * to struct efa_proto_op_base *
- All PKE handlers that access protocol-specific fields cast from base to the appropriate leaf type

Proposed Struct Hierarchy:

efa_proto_op_base          (~350 bytes, 5.5 cache lines)
  Fields: type, ep, peer, op, state, internal_flags, fi_flags,
          tx_id, rx_id, msg_id, tag, total_len, queued_ctrl_type,
          efa_outstanding_tx_ops, iov_count, iov[4], desc[4], mr[4],
          rma_iov_count, rma_iov[4], cq_entry,
          entry, ep_entry, queued_entry, queued_pkts, peer_entry,
          [ENABLE_DEBUG: pending_recv_entry]

efa_proto_tx_base          (base + ~24 bytes)
  Added: bytes_acked, bytes_sent, local_read_pkt_entry

efa_proto_rx_base          (base + ~80 bytes)
  Added: bytes_received, bytes_received_via_mulreq, bytes_copied,
         bytes_queued_blocking_copy, cuda_copy_method, unexp_pkt,
         rxe_map, peer_rxe, ack_list_entry, ignore

Leaf TX structs:
  efa_proto_tx_msg         (tx_base + ~40 bytes: window, bytes_runt, bytes_read_*)
  efa_proto_tx_rma_read    (tx_base + ~40 bytes: bytes_read_*)
  efa_proto_tx_rma_write   (tx_base + ~24 bytes: bytes_write_*)
  efa_proto_tx_atomic      (tx_base + ~216 bytes: atomic_hdr, atomic_ex)

Leaf RX structs:
  efa_proto_rx_msg         (rx_base + ~40 bytes: window, bytes_runt, bytes_read_*)
  efa_proto_rx_rma_write   (rx_base + minimal)
  efa_proto_rx_rma_read    (rx_base + ~16 bytes: window, bytes_sent)
  efa_proto_rx_atomic      (rx_base + ~16 bytes: atomic_hdr, atomrsp_data)

efa_proto_op_entry         (union of all leaf structs — sized by largest = tx_atomic)


Estimated leaf sizes:
- efa_proto_tx_msg: ~414 bytes (6.5 cache lines) ✓
- efa_proto_tx_rma_read: ~414 bytes (6.5 cache lines) ✓
- efa_proto_tx_rma_write: ~398 bytes (6.2 cache lines) ✓
- efa_proto_tx_atomic: ~590 bytes (9.2 cache lines) — acceptable, still 60% of original
- efa_proto_rx_msg: ~470 bytes (7.3 cache lines) — slightly over 7, may need field ordering optimization
- efa_proto_rx_rma_write: ~430 bytes (6.7 cache lines) ✓
- efa_proto_rx_rma_read: ~446 bytes (7.0 cache lines) ✓
- efa_proto_rx_atomic: ~446 bytes (7.0 cache lines) ✓

Note: efa_proto_rx_msg at ~470 bytes is slightly over the 7 cache line target. This will be resolved in Task 2 (Phase 2 Design) through precise field ordering and padding analysis. If it can't be brought under 
448, we'll flag it and decide whether to accept 7.3 cache lines (still a 48% reduction from 14) or move a cold field out.

Task Breakdown:

Task 1: Phase 1 Analysis — pahole output and field classification table

Objective: Build libfabric with debug info, run pahole -C efa_rdm_ope, and produce the complete annotated field classification.

Implementation guidance:
- Build with ./configure --enable-debug && make
- Run pahole -C efa_rdm_ope on the resulting .o file
- For each field, confirm classification (base/tx/rx/msg/rma_read/rma_write/atomic) using grep across prov/efa/
- Produce table: member | offset | size | cache_line | category | hot/cold | justification
- Flag any dead fields
- Verify the base struct size estimate (~350 bytes) against actual pahole output
- Verify rma_iov is indeed used by all leaf paths (confirming it belongs in base)

Test requirements: None (analysis only).

Demo: Complete field classification table and pahole output with cache line annotations.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 2: Phase 2 Design — Define new struct layouts with static_asserts

Objective: Define the complete struct hierarchy with exact member ordering, computed offsets, and static_asserts. No code changes — design review only.

Implementation guidance:
- Define all structs from the hierarchy above
- Order fields within each struct: hot fields first (target first cache line), then cold. Within each thermal zone, order largest-to-smallest to minimize padding holes
- Manually compute offsets and verify no unnecessary holes (cross-reference with pahole output from Task 1)
- Define EFA_PROTO_STATIC_ASSERT(expr, msg) macro wrapping _Static_assert for readability
- Add static_assert(sizeof(struct efa_proto_tx_msg) <= 448, ...) for each non-atomic leaf
- Add static_assert(offsetof(struct efa_proto_op_base, <field>) < 64, ...) for hot fields in base
- If efa_proto_rx_msg exceeds 448 bytes, propose which cold field to move or accept the overage with justification
- Define the efa_proto_op_type enum with values: EFA_PROTO_TX_MSG, EFA_PROTO_TX_RMA_READ, EFA_PROTO_TX_RMA_WRITE, EFA_PROTO_TX_ATOMIC, EFA_PROTO_RX_MSG, EFA_PROTO_RX_RMA_WRITE, EFA_PROTO_RX_RMA_READ, 
EFA_PROTO_RX_ATOMIC

Test requirements: None (design review only).

Demo: Complete struct definitions with offset annotations and static_asserts. Confirm sizes. Present for review before proceeding.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 3: Create efa_proto_op.h header

Objective: Commit the new header with all struct definitions, static_asserts, the union type, and the new enum. Old header remains untouched — both coexist.

Implementation guidance:
- Create prov/efa/src/rdm/efa_proto_op.h
- Include all struct definitions from Task 2
- Include the EFA_PROTO_STATIC_ASSERT macro
- Include necessary dependencies (dlist.h, fi_iov.h, etc.)
- Do NOT modify any existing files — just ensure the new header comp

 ▸ Credits: 5.36 • Time: 2m 53s

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 3: Create efa_proto_op.h header

Objective: Commit the new header with all struct definitions, static_asserts, the union type, and the new enum. Old header remains untouched — both coexist.

Implementation guidance:
- Create prov/efa/src/rdm/efa_proto_op.h
- Include all struct definitions from Task 2
- Include the EFA_PROTO_STATIC_ASSERT macro
- Include necessary dependencies (dlist.h, fi_iov.h, etc.)
- Do NOT modify any existing files — just ensure the new header compiles when included from a single .c file

Test requirements: Build compiles with the new header included.

Demo: make succeeds. All static_asserts pass.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 4: Update bufpool allocation to use efa_proto_op_entry

Objective: Change the ope_pool to allocate sizeof(struct efa_proto_op_entry) (the union). The old struct efa_rdm_ope is still used everywhere else — this just changes the allocation size.

Implementation guidance:
- In efa_rdm_ep_fiops.c, change sizeof(struct efa_rdm_ope) to sizeof(struct efa_proto_op_entry) in the ofi_bufpool_create call
- Include efa_proto_op.h where needed
- The union size will be >= the old struct size (dominated by efa_proto_tx_atomic), so this is safe
- Update the ENABLE_EFA_POISONING memset sizes in efa_rdm_txe_release and efa_rdm_rxe_release_internal to use the union size

Test requirements: Build compiles. Existing functionality unchanged since bufpool entries are at least as large as before.

Demo: make succeeds. Bufpool now allocates union-sized entries.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 5: Change pke->ope to struct efa_proto_op_base * and refactor generic ope functions

Objective: Update the pke->ope pointer type and convert all "any ope" functions to take struct efa_proto_op_base *. This is the foundational wiring change that all subsequent tasks depend on.

Implementation guidance:
- Change struct efa_rdm_pke.ope from struct efa_rdm_ope * to struct efa_proto_op_base *
- Convert these generic functions to take struct efa_proto_op_base *:
  - efa_rdm_ope_try_fill_desc() — operates only on base fields (iov, desc, mr)
  - efa_rdm_ope_post_send() / efa_rdm_ope_post_send_or_queue() / efa_rdm_ope_post_send_fallback()
  - efa_rdm_ope_prepare_to_post_send() — needs casts to access window, bytes_sent, bytes_runt from leaf structs based on base->type
  - efa_rdm_ope_handle_recv_completed() / efa_rdm_ope_handle_send_completed()
  - efa_rdm_ope_process_queued_ope() / efa_rdm_ope_repost_ope_queued_before_handshake()
  - efa_rdm_ope_mulreq_total_data_size() — casts to access bytes_runt
  - efa_rdm_ope_post_read() / efa_rdm_ope_prepare_to_post_read()
  - efa_rdm_ope_post_remote_write() / efa_rdm_ope_prepare_to_post_write()
- Update domain iteration sites to use struct efa_proto_op_base as container type:
  - efa_domain.c: ope_queued_list and ope_longcts_send_list iteration
  - efa_rdm_ep_fiops.c: ope_queued_list cleanup
- During this task, add temporary cast macros (e.g., EFA_PROTO_BASE_FROM_OPE(ope)) to bridge old struct efa_rdm_ope * callers to the new signatures, minimizing churn per task
- TX/RX-specific functions (efa_rdm_txe_handle_error, efa_rdm_rxe_handle_error, efa_rdm_txe_report_completion, efa_rdm_rxe_report_completion, efa_rdm_txe_release, efa_rdm_rxe_release) remain on 
struct efa_rdm_ope * for now — they'll be converted in Tasks 6-10

Test requirements: Build compiles. All existing functionality unchanged — the cast macros ensure binary compatibility.

Demo: pke->ope is now struct efa_proto_op_base *. Generic functions accept the base type. Domain iteration uses the base type.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 6: Refactor TX msg path to use efa_proto_tx_msg

Objective: Convert the TX msg/tagged send path to allocate and use efa_proto_tx_msg.

Implementation guidance:
- efa_rdm_ep_alloc_txe() → efa_proto_alloc_tx_msg(): cast bufpool entry to struct efa_proto_tx_msg *, set base.type = EFA_PROTO_TX_MSG
- efa_rdm_txe_construct() → efa_proto_tx_msg_construct(): initialize only fields in efa_proto_tx_msg (base fields + bytes_acked, bytes_sent, local_read_pkt_entry + window, bytes_runt, bytes_read_*)
- efa_rdm_txe_release() → efa_proto_tx_msg_release(): clean up only relevant fields
- Update efa_rdm_msg.c send functions to use struct efa_proto_tx_msg *
- Update efa_rdm_pke_rtm.c init functions (eager/medium/longcts/longread/runtread) to take struct efa_proto_tx_msg *
- efa_rdm_txe_report_completion() and efa_rdm_txe_handle_error() convert to take struct efa_proto_tx_base * (shared by all TX leaf types)
- efa_rdm_txe_dc_ready_for_release() converts to take struct efa_proto_tx_base *

Test requirements: Build compiles. TX msg/tagged sends work correctly.

Demo: TX msg path uses the new struct. pahole -C efa_proto_tx_msg shows reduced size.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 7: Refactor RX msg path to use efa_proto_rx_msg

Objective: Convert the RX msg/tagged receive path to use efa_proto_rx_msg.

Implementation guidance:
- efa_rdm_ep_alloc_rxe() for msg/tagged ops → efa_proto_alloc_rx_msg(): cast to struct efa_proto_rx_msg *, set type
- Update efa_rdm_msg.c receive functions, efa_rdm_pke_rtm.c RX handlers, efa_rdm_srx.c
- efa_rdm_rxe_release() / efa_rdm_rxe_release_internal() → protocol-aware release
- efa_rdm_rxe_report_completion() and efa_rdm_rxe_handle_error() convert to take struct efa_proto_rx_base *
- RX-specific fields (bytes_received, cuda_copy_method, unexp_pkt, rxe_map, peer_rxe, ack_list_entry, ignore) now only exist in efa_proto_rx_base/efa_proto_rx_msg

Test requirements: Build compiles. RX msg/tagged receives work correctly.

Demo: RX msg path uses the new struct. pahole -C efa_proto_rx_msg shows reduced size.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 8: Refactor TX RMA read and TX RMA write paths

Objective: Convert RMA TX allocation to use efa_proto_tx_rma_read and efa_proto_tx_rma_write.

Implementation guidance:
- Split efa_rdm_rma_alloc_txe() into read vs write variants returning the appropriate type
- efa_rdm_rma.c read functions use struct efa_proto_tx_rma_read *
- efa_rdm_rma.c write functions use struct efa_proto_tx_rma_write *
- efa_rdm_pke_rtr.c init functions take struct efa_proto_tx_rma_read *
- efa_rdm_pke_rtw.c TX init functions take struct efa_proto_tx_rma_write *
- efa_rdm_ope_post_read() / efa_rdm_ope_prepare_to_post_read() — already take base pointer from Task 5, cast internally to access bytes_read_*
- efa_rdm_ope_post_remote_write() / efa_rdm_ope_prepare_to_post_write() — cast to efa_proto_tx_rma_write * to access bytes_write_*

Test requirements: Build compiles. RMA read and write operations work correctly.

Demo: RMA paths use new structs. pahole confirms reduced sizes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 9: Refactor TX atomic path

Objective: Convert atomic TX allocation to use efa_proto_tx_atomic.

Implementation guidance:
- efa_rdm_atomic.c: efa_rdm_atomic_alloc_txe() → returns efa_proto_tx_atomic *
- efa_rdm_pke_rta.c TX init functions take efa_proto_tx_atomic *
- atomic_hdr and atomic_ex only exist in this struct — ~216 bytes eliminated from all other paths

Test requirements: Build compiles. Atomic operations work correctly.

Demo: Atomic path uses new struct. Non-atomic paths no longer carry atomic_ex overhead.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 10: Refactor RX RMA and RX atomic paths

Objective: Convert RX-side RMA (RTW/RTR responder) and atomic (RTA responder) paths to use efa_proto_rx_rma_write, efa_proto_rx_rma_read, and efa_proto_rx_atomic.

Implementation guidance:
- efa_rdm_pke_alloc_rtw_rxe() → returns efa_proto_rx_rma_write *, sets type EFA_PROTO_RX_RMA_WRITE
- efa_rdm_pke_alloc_rtr_rxe() → returns efa_proto_rx_rma_read *, sets type EFA_PROTO_RX_RMA_READ
- efa_rdm_pke_alloc_rta_rxe() → returns efa_proto_rx_atomic *, sets type EFA_PROTO_RX_ATOMIC
- atomrsp_data only exists in efa_proto_rx_atomic
- RTW/RTR/RTA recv handlers updated to use protocol-specific types
- window and bytes_sent in efa_proto_rx_rma_read (RTR responder sends data via CTS/DATA)

Test requirements: Build compiles. RX RMA and atomic responder paths work correctly.

Demo: All RX protocol paths use new structs.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 11: Remove old struct efa_rdm_ope and complete rename

Objective: Delete the old struct definition and complete the efa_rdm_ → efa_proto_ rename for all touched functions and types.

Implementation guidance:
- Verify no code references struct efa_rdm_ope (grep)
- Remove the old struct from efa_rdm_ope.h (or remove the file entirely and redirect includes)
- Remove temporary cast macros from Task 5
- Rename all efa_rdm_ope_* functions to efa_proto_op_*
- Rename efa_rdm_txe_* → efa_proto_tx_*, efa_rdm_rxe_* → efa_proto_rx_*
- Rename EFA_RDM_TXE / EFA_RDM_RXE enum values to efa_proto_op_type values
- Rename EFA_RDM_TXE_* / EFA_RDM_RXE_* / EFA_RDM_OPE_* internal_flags defines to EFA_PROTO_*
- Update all #include directives
- Update efa_domain.h list names: ope_queued_list → proto_op_queued_list, ope_longcts_send_list → proto_op_longcts_send_list

Test requirements: Build compiles with zero warnings in prov/efa/. grep -r efa_rdm_ope prov/efa/src/ returns no hits.

Demo: Clean build. No references to old struct or old naming in source files.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Task 12: Final validation with pahole and static_assert audit

Objective: Run pahole on every new struct, confirm size budgets, verify no unnecessary holes, and document before/after comparison.

Implementation guidance:
- pahole -C efa_proto_tx_msg, pahole -C efa_proto_rx_msg, etc. for all leaf structs
- Confirm each non-atomic leaf struct ≤ 448 bytes (7 cache lines)
- Confirm efa_proto_tx_atomic is the largest and document its size
- Confirm no code path allocates the old monolithic struct
- Confirm all new structs have efa_proto_ naming
- Verify the union struct size and that the bufpool allocation matches
- Produce before/after comparison table:

| Protocol Path | Before (cache lines) | After (cache lines) | Reduction |
|---|---|---|---|
| TX msg/tagged | 14 | ~6.5 | 54% |
| TX RMA read | 14 | ~6.5 | 54% |
| TX RMA write | 14 | ~6.2 | 56% |
| TX atomic | 14 | ~9.2 | 34% |
| RX msg/tagged | 14 | ~7.3 | 48% |
| RX RMA write | 14 | ~6.7 | 52% |
| RX RMA read | 14 | ~7.0 | 50% |
| RX atomic | 14 | ~7.0 | 50% |

Test requirements: Full build. pahole output documented.

Demo: Before/after comparison table. All non-atomic paths < 50% of original 14 cache lines. All static_asserts passing.

