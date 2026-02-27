# EFA-Proto (RDM) Memory Allocation Audit
**Version:** 1.0 | **Date:** 2026-02-26

## Overview

EFA-proto (RDM protocol) provides full-featured reliable datagram messaging with protocol emulation. This document covers memory allocations specific to the EFA RDM protocol implementation.

## Key Characteristics

- **Fabric Name:** `efa`
- **Endpoint Type:** RDM (Reliable Datagram)
- **Approach:** Full protocol emulation, all libfabric features
- **Memory Overhead:** ~142 MB per endpoint (minimum)
- **Features:** Message matching, ordering, reliability, large message protocols

---

## 1. Protocol-Specific Structures

### 1.1 efa_rdm_ep (RDM Endpoint)

**Location:** `prov/efa/src/rdm/efa_rdm_ep.h`

**Size:** ~2 KB

**Allocation:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:547`
```c
efa_rdm_ep = calloc(1, sizeof(*efa_rdm_ep));
```

**Key Protocol Fields:**
- `extra_info[8]` - Protocol version/feature flags (64 bytes)
- `host_id` - Peer identification (8 bytes)
- `sendrecv_in_order_aligned_128_bytes` - Ordering flag
- `write_in_order_aligned_128_bytes` - Ordering flag
- `use_zcpy_rx` - Zero-copy receive capability
- `handle_resource_management` - Resource management flag

**Protocol State:**
- `efa_outstanding_tx_ops` - Outstanding operations counter
- `efa_rx_pkts_posted` - Posted RX packets
- `efa_rx_pkts_to_post` - Pending RX posts
- `efa_rx_pkts_held` - Held RX packets
- `user_rx_pkts_posted` - User-posted packets
- `ope_queued_before_handshake_cnt` - Pre-handshake queue

**Freed:** Lines 718, 1197

---

## 2. Protocol Buffer Pools

### 2.1 Unexpected Packet Pool

**Location:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:200`

**Allocation:**
```c
ret = efa_rdm_ep_create_pke_pool(ep,
                                 false, /* no memory registration */
                                 efa_env.unexp_pool_chunk_size,
                                 0, /* max count = 0, allowed to grow */
                                 EFA_RDM_BUFPOOL_ALIGNMENT,
                                 rx_pkt_pool_base_flags,
                                 &ep->rx_unexp_pkt_pool);
```

**Details:**
- **Entry Size:** 8320 bytes (128B pke + 8192B MTU)
- **Initial Count:** 0
- **Chunk Size:** Configurable (efa_env.unexp_pool_chunk_size)
- **Growth:** Dynamic, grows on unexpected messages
- **Memory Registered:** NO
- **Issue:** Never shrinks (Subspace-3161)

**Purpose:** Clone unexpected packets from RX pool to allow RX buffer reuse

### 2.2 Out-of-Order Packet Pool

**Location:** Line 211

**Allocation:**
```c
ret = efa_rdm_ep_create_pke_pool(ep,
                                 false, /* no memory registration */
                                 efa_env.ooo_pool_chunk_size,
                                 0, /* max count = 0, allowed to grow */
                                 EFA_RDM_BUFPOOL_ALIGNMENT,
                                 0,
                                 &ep->rx_ooo_pkt_pool);
```

**Details:**
- **Entry Size:** 8320 bytes
- **Initial Count:** 0
- **Chunk Size:** Configurable (efa_env.ooo_pool_chunk_size)
- **Growth:** Dynamic, grows on out-of-order packets
- **Memory Registered:** NO
- **Issue:** Never shrinks (Subspace-3161)

**Purpose:** Hold out-of-order packets until in-order delivery possible

### 2.3 Read Copy Packet Pool (HMEM)

**Location:** Line 217

**Allocation:**
```c
ret = efa_rdm_ep_create_pke_pool(ep,
                                 true, /* need memory registration */
                                 efa_env.readcopy_pool_size,
                                 efa_env.readcopy_pool_size,
                                 EFA_RDM_IN_ORDER_ALIGNMENT,
                                 0,
                                 &ep->rx_readcopy_pkt_pool);
```

**Details:**
- **Entry Size:** 8320 bytes
- **Count:** Configurable (efa_env.readcopy_pool_size)
- **Memory Registered:** YES
- **Alignment:** EFA_RDM_IN_ORDER_ALIGNMENT (128 bytes)
- **Condition:** Only if FI_HMEM capability AND (rx_copy_unexp OR rx_copy_ooo)
- **Tracking:** `rx_readcopy_pkt_pool_used`, `rx_readcopy_pkt_pool_max_used`

**Purpose:** Local read copy from unexpected/OOO packets to HMEM receive buffers

### 2.4 RX Atomic Response Pool

**Location:** Line 241

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->rx_atomrsp_pool, ep->mtu_size,
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit for max_cnt */
                         efa_env.atomrsp_pool_size, 0);
```

**Details:**
- **Entry Size:** MTU size (typically 8192 bytes)
- **Initial Count:** 0
- **Chunk Size:** efa_env.atomrsp_pool_size (typically 64)
- **Growth:** Dynamic
- **Memory Registered:** NO

**Purpose:** Store atomic operation response data (fetch/compare atomics)

### 2.5 Overflow PKE Pool

**Location:** Line 260

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->overflow_pke_pool,
                         sizeof(struct efa_rdm_peer_overflow_pke_list_entry),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit for max_cnt */
                         ep->base_ep.info->rx_attr->size, 0);
```

**Details:**
- **Entry Size:** ~32 bytes (list entry wrapper)
- **Initial Count:** 0
- **Chunk Size:** RX size (typically 8192)
- **Growth:** Dynamic

**Purpose:** Hold packets that overflow peer reorder buffer

---

## 3. Protocol Operation Structures

### 3.1 efa_rdm_ope (Operation Entry)

**Location:** `prov/efa/src/rdm/efa_rdm_ope.h`

**Size:** ~800 bytes

**Key Protocol Fields:**
```c
struct efa_rdm_ope {
    enum efa_rdm_ope_type type;         // TX or RX
    enum efa_rdm_ope_state state;       // Protocol state
    uint32_t msg_id;                    // Message ID
    uint64_t tag, ignore;               // Tagged messaging
    int64_t window;                     // Flow control window
    int queued_ctrl_type;               // Queued control packet
    uint32_t internal_flags;            // Protocol flags
    
    // Protocol-specific lists
    struct dlist_entry entry;           // longcts send list
    struct dlist_entry queued_entry;    // queued list
    struct dlist_entry queued_pkts;     // queued packets
    struct dlist_entry ack_list_entry;  // posted ack list
    
    // Protocol byte counters
    uint64_t bytes_runt;                // Runt protocol bytes
    uint64_t bytes_received;
    uint64_t bytes_received_via_mulreq;
    uint64_t bytes_copied;
    uint64_t bytes_queued_blocking_copy;
    uint64_t bytes_acked;
    uint64_t bytes_sent;
    uint64_t bytes_read_completed;
    uint64_t bytes_read_submitted;
    uint64_t bytes_read_total_len;
    uint64_t bytes_read_offset;
    uint64_t bytes_write_completed;
    uint64_t bytes_write_submitted;
    uint64_t bytes_write_total_len;
    
    // Protocol-specific fields
    struct efa_rdm_pke *unexp_pkt;      // Unexpected packet
    char *atomrsp_data;                 // Atomic response
    enum efa_rdm_cuda_copy_method cuda_copy_method;
    struct efa_rdm_rxe_map *rxe_map;    // RX entry map
    struct efa_rdm_pke *local_read_pkt_entry;
};
```

**Allocation:** `prov/efa/src/rdm/efa_rdm_ep_utils.c:175, 330`
```c
rxe = ofi_buf_alloc(ep->ope_pool);
txe = ofi_buf_alloc(efa_rdm_ep->ope_pool);
```

**Freed:** `prov/efa/src/rdm/efa_rdm_ope.c:160, 216`

**Protocol States:**
- `EFA_RDM_TXE_REQ` - Sending REQ packet
- `EFA_RDM_OPE_SEND` - Sending data
- `EFA_RDM_RXE_INIT` - Ready to receive
- `EFA_RDM_RXE_UNEXP` - Unexpected message
- `EFA_RDM_RXE_MATCHED` - Matched with RTM
- `EFA_RDM_RXE_RECV` - Receiving data
- `EFA_RDM_OPE_ERR` - Error state

**Protocol Flags:**
- `EFA_RDM_RXE_RECV_CANCEL`
- `EFA_RDM_TXE_DELIVERY_COMPLETE_REQUESTED`
- `EFA_RDM_OPE_QUEUED_RNR`
- `EFA_RDM_RXE_EOR_IN_FLIGHT`
- `EFA_RDM_TXE_WRITTEN_RNR_CQ_ERR_ENTRY`
- `EFA_RDM_OPE_QUEUED_CTRL`
- `EFA_RDM_TXE_NO_COMPLETION`
- `EFA_RDM_TXE_NO_COUNTER`
- `EFA_RDM_OPE_QUEUED_READ`
- `EFA_RDM_OPE_READ_NACK`
- `EFA_RDM_OPE_QUEUED_BEFORE_HANDSHAKE`
- `EFA_RDM_OPE_INTERNAL`
- `EFA_RDM_TXE_RECEIPT_RECEIVED`

---

## 4. Protocol Peer Structures

### 4.1 efa_rdm_peer

**Location:** `prov/efa/src/rdm/efa_rdm_peer.h`

**Size:** ~400 bytes

**Key Protocol Fields:**
```c
struct efa_rdm_peer {
    struct efa_rdm_ep *ep;
    bool is_self;
    bool is_local;
    uint32_t device_version;
    struct efa_conn *conn;
    uint64_t host_id;
    
    // Protocol reorder buffer
    struct efa_rdm_robuf robuf;         // ~100 bytes
    uint32_t next_msg_id;               // Next message ID
    
    // Protocol flags
    uint32_t flags;
    uint32_t nextra_p3;                 // Extra info count
    uint64_t extra_info[8];             // Protocol features
    
    // Protocol state
    size_t efa_outstanding_tx_ops;
    struct dlist_entry outstanding_tx_pkts;
    
    // RNR (Receiver Not Ready) protocol
    uint64_t rnr_backoff_begin_ts;
    uint64_t rnr_backoff_wait_time;
    int rnr_queued_pkt_cnt;
    struct dlist_entry rnr_backoff_entry;
    
    // Handshake protocol
    struct dlist_entry handshake_queued_entry;
    
    // Protocol lists
    struct dlist_entry txe_list;
    struct dlist_entry rxe_list;
    struct dlist_entry overflow_pke_list;
    
    // Runt protocol
    int64_t num_runt_bytes_in_flight;
    
    // User recv QP (protocol extension)
    struct efa_rdm_peer_user_recv_qp user_recv_qp;
    
    // Multi-request protocol
    struct efa_rdm_rxe_map rxe_map;     // ~50 bytes
};
```

**Protocol Flags:**
- `EFA_RDM_PEER_REQ_SENT`
- `EFA_RDM_PEER_HANDSHAKE_SENT`
- `EFA_RDM_PEER_HANDSHAKE_RECEIVED`
- `EFA_RDM_PEER_IN_BACKOFF`
- `EFA_RDM_PEER_HANDSHAKE_QUEUED`
- `EFA_RDM_PEER_UNRESP`

**Extra Info (Protocol Features):**
- `EFA_RDM_EXTRA_FEATURE_RDMA_READ`
- `EFA_RDM_EXTRA_FEATURE_RDMA_WRITE`
- `EFA_RDM_EXTRA_FEATURE_UNSOLICITED_WRITE_RECV`
- `EFA_RDM_EXTRA_FEATURE_DELIVERY_COMPLETE`
- `EFA_RDM_EXTRA_FEATURE_READ_NACK`
- `EFA_RDM_EXTRA_REQUEST_CONSTANT_HEADER_LENGTH`
- `EFA_RDM_EXTRA_REQUEST_CONNID_HEADER`

### 4.2 Reorder Buffer (robuf)

**Allocation:** `prov/efa/src/rdm/efa_rdm_peer.h:55-57`
```c
if (alloc_from_bufpool) {
    recvq->pending = ofi_buf_alloc(pool);  // From peer_robuf_pool
} else {
    recvq->pending = calloc(1, sizeof(struct recvwin_cirq) +
                            sizeof(struct efa_rdm_pke*) * size);
}
```

**Details:**
- **Size:** (8 × recvwin_size) + overhead
- **Default:** 16 entries = ~150 bytes
- **Purpose:** Hold out-of-order packets for in-order delivery
- **Freed:** `efa_recvwin_free()` at peer destruction

### 4.3 Overflow PKE List

**Allocation:** `prov/efa/src/rdm/efa_rdm_peer.c:183`
```c
overflow_pke_list_entry = ofi_buf_alloc(ep->overflow_pke_pool);
```

**Purpose:** Packets beyond reorder buffer capacity

**Freed:** Lines 91, 275

---

## 5. Protocol Packet Types

### 5.1 Packet Entry (pke) Protocol Fields

**Location:** `prov/efa/src/rdm/efa_rdm_pke.h`

**Protocol-Specific Fields:**
```c
struct efa_rdm_pke {
    // Protocol state
    enum efa_rdm_pke_alloc_type alloc_type;
    uint32_t flags;
    
    // Protocol chaining
    struct efa_rdm_pke *next;           // Chain MEDIUM/RUNTREAD RTM
    
    // Protocol generation counter
    uint8_t gen;                        // Incremented on each post
    
    // Protocol debug (ENABLE_DEBUG)
    #if ENABLE_DEBUG
    struct efa_rdm_pke_debug_info_buffer *debug_info;
    struct dlist_entry dbg_entry;
    #endif
};
```

**Protocol Flags:**
- `EFA_RDM_PKE_IN_USE`
- `EFA_RDM_PKE_RNR_RETRANSMIT`
- `EFA_RDM_PKE_LOCAL_READ`
- `EFA_RDM_PKE_DC_LONGCTS_DATA`
- `EFA_RDM_PKE_LOCAL_WRITE`
- `EFA_RDM_PKE_SEND_TO_USER_RECV_QP`
- `EFA_RDM_PKE_HAS_NO_BASE_HDR`
- `EFA_RDM_PKE_IN_PEER_OUTSTANDING_TX_PKTS`
- `EFA_RDM_PKE_IN_OPE_QUEUED_PKTS`

**Allocation Types:**
- `EFA_RDM_PKE_FROM_EFA_TX_POOL`
- `EFA_RDM_PKE_FROM_EFA_RX_POOL`
- `EFA_RDM_PKE_FROM_UNEXP_POOL`
- `EFA_RDM_PKE_FROM_OOO_POOL`
- `EFA_RDM_PKE_FROM_USER_RX_POOL`
- `EFA_RDM_PKE_FROM_READ_COPY_POOL`

---

## 6. Protocol Message Types

### 6.1 RTM (Request To Message) Packets

**Types:**
- `EFA_RDM_EAGER_MSGRTM_PKT` - Eager protocol
- `EFA_RDM_MEDIUM_MSGRTM_PKT` - Medium message
- `EFA_RDM_LONGCTS_MSGRTM_PKT` - Long CTS protocol
- `EFA_RDM_LONGREAD_MSGRTM_PKT` - Long read protocol
- `EFA_RDM_RUNTREAD_MSGRTM_PKT` - Runt read protocol
- `EFA_RDM_DC_EAGER_MSGRTM_PKT` - Delivery complete eager
- `EFA_RDM_DC_MEDIUM_MSGRTM_PKT` - Delivery complete medium
- `EFA_RDM_DC_LONGCTS_MSGRTM_PKT` - Delivery complete long CTS

### 6.2 RTW (Request To Write) Packets

**Types:**
- `EFA_RDM_EAGER_RTW_PKT`
- `EFA_RDM_LONGCTS_RTW_PKT`
- `EFA_RDM_LONGREAD_RTW_PKT`
- `EFA_RDM_DC_EAGER_RTW_PKT`
- `EFA_RDM_DC_LONGCTS_RTW_PKT`
- `EFA_RDM_SHORT_RTR_PKT`
- `EFA_RDM_LONGCTS_RTR_PKT`

### 6.3 Control Packets

**Types:**
- `EFA_RDM_HANDSHAKE_PKT` - Handshake protocol
- `EFA_RDM_CTS_PKT` - Clear to send
- `EFA_RDM_READRSP_PKT` - Read response
- `EFA_RDM_RMA_CONTEXT_PKT` - RMA context
- `EFA_RDM_EOR_PKT` - End of read
- `EFA_RDM_ATOMRSP_PKT` - Atomic response
- `EFA_RDM_RECEIPT_PKT` - Receipt (delivery complete)
- `EFA_RDM_READ_NACK_PKT` - Read NACK

---

## 7. Protocol Memory Overhead

### 7.1 Per-Endpoint Protocol Overhead

| Component | Size | Purpose |
|-----------|------|---------|
| rx_unexp_pkt_pool | Variable | Unexpected messages |
| rx_ooo_pkt_pool | Variable | Out-of-order messages |
| rx_readcopy_pkt_pool | Variable | HMEM local read |
| rx_atomrsp_pool | Variable | Atomic responses |
| overflow_pke_pool | Variable | Reorder overflow |
| Protocol state in ep | ~500 B | Counters, flags |
| **Total (minimum)** | **~1 KB** | Without traffic |
| **Total (active)** | **Variable** | Grows with traffic |

### 7.2 Per-Peer Protocol Overhead

| Component | Size | Purpose |
|-----------|------|---------|
| Reorder buffer | 150 B | In-order delivery |
| Overflow list | Variable | Beyond reorder capacity |
| RXE map | 50 B | Multi-request matching |
| Protocol state | ~200 B | Flags, counters, lists |
| **Total** | **~400 B** | Per peer |

### 7.3 Per-Operation Protocol Overhead

| Component | Size | Purpose |
|-----------|------|---------|
| Protocol state | ~200 B | State, flags, msg_id |
| Byte counters | ~200 B | Progress tracking |
| Protocol lists | ~100 B | Queuing, acks |
| **Total** | **~500 B** | Of 800B ope |

---

## 8. Protocol Optimizations

### 8.1 Eliminate Unexpected/OOO Pools

**Current:** Separate pools that grow but never shrink
**Proposal:** Larger RX pool (16K instead of 8K)
**Benefit:** Eliminates growth, simplifies code
**Cost:** +32 MB per endpoint
**Reference:** Subspace-967

### 8.2 Shrink Protocol Pools

**Issue:** Pools grow during surges but never shrink
**Fix:** Periodic trimming based on usage
**Benefit:** Reduces memory after traffic bursts
**Reference:** Subspace-3161

### 8.3 Optimize Protocol State

**Issue:** Large ope struct (800B) for all operations
**Proposal:** Separate context for simple RDMA ops
**Benefit:** 75% reduction for RDMA operations
**Effort:** High (major refactor)

---

## 9. Key Takeaways

**For EFA-Proto (RDM):**
1. **Protocol Overhead:** ~1 KB minimum, grows with traffic
2. **Dynamic Pools:** Unexpected/OOO pools grow but never shrink
3. **Per-Peer State:** ~400 bytes for reorder, handshake, RNR
4. **Message Protocols:** 15+ packet types for different scenarios
5. **Feature Negotiation:** Extra info flags for protocol features

**Critical Files:**
- `prov/efa/src/rdm/efa_rdm_ep.h` - Endpoint protocol state
- `prov/efa/src/rdm/efa_rdm_ope.h` - Operation protocol state
- `prov/efa/src/rdm/efa_rdm_peer.h` - Peer protocol state
- `prov/efa/src/rdm/efa_rdm_pke.h` - Packet protocol state
- `prov/efa/src/rdm/efa_rdm_protocol.h` - Protocol definitions
- `prov/efa/src/rdm/efa_rdm_pkt_type.h` - Packet types

---

**END OF DOCUMENT**
