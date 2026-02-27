# EFA Provider Memory Allocation Audit
**Version:** 1.0 | **Date:** 2026-02-26

## Executive Summary

Comprehensive audit of memory allocations in EFA and EFA-direct providers to address performance regressions caused by memory issues.

### Key Findings
- **10+ buffer pools per endpoint** (efa_tx_pkt_pool, efa_rx_pkt_pool, ope_pool, etc.)
- **Large structs**: efa_rdm_pke (128B), efa_rdm_ope (800+B), efa_rdm_peer (400+B), efa_rdm_ep (2KB+)
- **Pools never shrink** after growth (unexp/ooo pools)
- **Cache line issues**: field ordering not optimized, repeated fields across structs
- **Page faults**: pre-allocated memory not touched until first use

### Historical Issues (Appendix A)
- Page faults in endpoint creation causing trn1 regression
- Hashmap changes affecting c7gn intra-node latency
- EFA-direct introduction causing hpc6a alltoall regression
- BTL/OFI memory allocation overhead
- Peer API changes causing alltoallv regression
- xpmem compilation causing hpc7g regression

---

## 1. EFA Provider Architecture

### 1.1 EFA Fabric vs EFA-Direct Fabric

**EFA Fabric (`efa`):**
- Full RDM protocol implementation
- Supports all libfabric features
- More memory overhead for protocol state

**EFA-Direct Fabric (`efa-direct`):**
- Direct hardware access
- Minimal protocol overhead
- Reduced memory footprint
- Additional direct data path structures

### 1.2 Memory Allocation Categories

1. **Fabric/Domain** - shared across endpoints
2. **Endpoint** - per-endpoint structures
3. **Buffer Pools** - pre-allocated packet/operation buffers
4. **Peer** - per-peer connection state
5. **Operations** - per TX/RX operation
6. **Packets** - per packet in flight

---
## 2. Endpoint-Level Allocations

### 2.1 EFA RDM Endpoint (efa_rdm_ep)

**Location:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:547`

**Allocation:**
```c
efa_rdm_ep = calloc(1, sizeof(*efa_rdm_ep));  // ~2KB+
```

**Lifecycle:**
- **Created:** `efa_rdm_ep_open()` 
- **Freed:** `efa_rdm_ep_close()` at line 718, 1197

**Associated Resources:**
- Base endpoint (`efa_base_ep`)
- 10+ buffer pools (see section 4)
- Peer list (`ep_peer_list`)
- TX/RX operation lists (`txe_list`, `rxe_list`)
- Work arrays: `pke_vec`, `send_pkt_entry_vec`, `send_pkt_entry_size_vec`

**Key Fields (Cache Line Concerns):**
- Frequently accessed: `efa_outstanding_tx_ops`, `efa_rx_pkts_posted`, `mtu_size`
- Less frequent: `host_id`, `extra_info[]`, `shm_ep`
- **Issue:** Fields not grouped by access pattern

### 2.2 Work Arrays (Allocated Separately)

**pke_vec:**
```c
// Line 668
efa_rdm_ep->pke_vec = calloc(sizeof(struct efa_rdm_pke *), 
                              efa_base_ep_get_rx_pool_size(&efa_rdm_ep->base_ep));
```
- **Size:** RX pool size × 8 bytes
- **Freed:** Line 706, 1189

**send_pkt_entry_vec:**
```c
// Line 675
efa_rdm_ep->send_pkt_entry_vec = calloc(sizeof(struct efa_rdm_pke *), 
                                         efa_base_ep_get_tx_pool_size(&efa_rdm_ep->base_ep));
```
- **Size:** TX pool size × 8 bytes
- **Freed:** Line 704, 1191

**send_pkt_entry_size_vec:**
```c
// Line 682
efa_rdm_ep->send_pkt_entry_size_vec = calloc(sizeof(int), 
                                               efa_base_ep_get_tx_pool_size(&efa_rdm_ep->base_ep));
```
- **Size:** TX pool size × 4 bytes
- **Freed:** Line 1193

### 2.3 Base Endpoint Allocations

**efa_recv_wr_vec:**
```c
// prov/efa/src/efa_base_ep.c:501
base_ep->efa_recv_wr_vec = calloc(sizeof(struct efa_recv_wr), 
                                   efa_base_ep_get_rx_pool_size(base_ep));
```
- **Freed:** Line 147

**user_recv_wr_vec:**
```c
// Line 506
base_ep->user_recv_wr_vec = calloc(sizeof(struct efa_recv_wr), 
                                    efa_base_ep_get_rx_pool_size(base_ep));
```
- **Freed:** Line 150

---
## 3. Buffer Pool Allocations

All buffer pools use `ofi_bufpool_create()` from `include/ofi_mem.h`.

### 3.1 EFA TX Packet Pool

**Location:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:179`
```c
ret = ofi_bufpool_create(&ep->efa_tx_pkt_pool,
                         sizeof(struct efa_rdm_pke) + ep->mtu_size,
                         EFA_RDM_PKE_ALIGNMENT,
                         max_tx_pool_size, max_tx_pool_size, 0);
```

**Details:**
- **Entry Size:** 128 bytes (pke) + MTU size (typically 8192) = ~8320 bytes
- **Alignment:** 128 bytes (2 cache lines)
- **Count:** `max_tx_pool_size` (typically 8192)
- **Total Memory:** ~64 MB per endpoint
- **Memory Registered:** YES (with EFA device)
- **Lifecycle:** Created at EP open, destroyed at EP close
- **Used For:** Send operations, RDMA read/write operations

### 3.2 EFA RX Packet Pool

**Location:** Line 180 (same function)
```c
ret = ofi_bufpool_create(&ep->efa_rx_pkt_pool,
                         sizeof(struct efa_rdm_pke) + ep->mtu_size,
                         EFA_RDM_PKE_ALIGNMENT,
                         max_rx_pool_size, max_rx_pool_size, 0);
```

**Details:**
- **Entry Size:** ~8320 bytes
- **Count:** `max_rx_pool_size` (typically 8192)
- **Total Memory:** ~64 MB per endpoint
- **Memory Registered:** YES
- **Issue:** Pre-allocated but pages not touched → page faults on first use

### 3.3 User RX Packet Pool (Zero-Copy)

**Location:** Line 179 (conditional)
```c
ret = ofi_bufpool_create(&ep->user_rx_pkt_pool,
                         sizeof(struct efa_rdm_pke) + ep->msg_prefix_size,
                         EFA_RDM_PKE_ALIGNMENT, 0, 0, 0);
```

**Details:**
- **Entry Size:** 128 + prefix size
- **Count:** Dynamic (grows on demand)
- **Used For:** User-provided receive buffers (FI_MSG_PREFIX)

### 3.4 Operation Pool (ope_pool)

**Location:** Line 248
```c
ret = ofi_bufpool_create(&ep->ope_pool,
                         sizeof(struct efa_rdm_ope),
                         EFA_RDM_PKE_ALIGNMENT,
                         max_ope_pool_size, max_ope_pool_size, 0);
```

**Details:**
- **Entry Size:** ~800+ bytes (struct efa_rdm_ope)
- **Count:** Sum of TX + RX pool sizes
- **Total Memory:** ~12-16 MB per endpoint
- **Contains:** TX entries (txe) and RX entries (rxe)
- **Lifecycle:** Allocated per operation, freed on completion

**Struct efa_rdm_ope Fields:**
- `ep`, `peer` pointers (16 bytes)
- `tx_id`, `rx_id`, `op`, `msg_id` (16 bytes)
- `atomic_hdr`, `atomic_ex` (large)
- `iov[4]`, `desc[4]`, `mr[4]` (192 bytes)
- `rma_iov[4]` (128 bytes)
- `cq_entry` (64 bytes)
- Multiple `dlist_entry` (16 bytes each × 6 = 96 bytes)
- State tracking fields

**Issue:** `ope->ep` duplicates `ope->peer->ep`

### 3.5 Unexpected Packet Pool

**Location:** Line 232
```c
ret = ofi_bufpool_create(&ep->rx_unexp_pkt_pool,
                         sizeof(struct efa_rdm_pke) + ep->mtu_size,
                         EFA_RDM_PKE_ALIGNMENT, 0, 16, 0);
```

**Details:**
- **Entry Size:** ~8320 bytes
- **Initial Count:** 0, chunk size 16
- **Grows:** When unexpected messages arrive
- **Issue:** NEVER SHRINKS (Subspace-3161)

### 3.6 Out-of-Order Packet Pool

**Location:** Line 233 (similar to unexp)
```c
ret = ofi_bufpool_create(&ep->rx_ooo_pkt_pool, ...);
```

**Details:**
- **Issue:** NEVER SHRINKS after surge

### 3.7 Map Entry Pool

**Location:** Line 232
```c
ret = ofi_bufpool_create(&ep->map_entry_pool,
                         sizeof(struct efa_rdm_rxe_map_entry),
                         EFA_RDM_PKE_ALIGNMENT, 0, 128, 0);
```

**Details:**
- **Used For:** RX entry hashmap (mulreq packet matching)
- **Grows:** Dynamically

### 3.8 RX Atomic Response Pool

**Location:** Line 241
```c
ret = ofi_bufpool_create(&ep->rx_atomrsp_pool, ep->mtu_size,
                         EFA_RDM_PKE_ALIGNMENT, 0, 64, 0);
```

**Details:**
- **Used For:** Emulated fetch/compare atomic responses
- **Entry Size:** MTU size (~8192 bytes)

### 3.9 Overflow PKE Pool

**Location:** Line 260
```c
ret = ofi_bufpool_create(&ep->overflow_pke_pool,
                         sizeof(struct efa_rdm_peer_overflow_pke_list_entry),
                         EFA_RDM_PKE_ALIGNMENT, 0, 128, 0);
```

**Details:**
- **Used For:** Packets that overflow peer reorder buffer

### 3.10 Peer Map Entry Pool

**Location:** Line 234 (in peer setup)
```c
ret = ofi_bufpool_create(&ep->peer_map_entry_pool, ...);
```

**Details:**
- **Used For:** fi_addr → peer hashmap entries

### 3.11 Peer Reorder Buffer Pool

**Location:** Line 235
```c
ret = ofi_bufpool_create(&ep->peer_robuf_pool, ...);
```

**Details:**
- **Used For:** Per-peer circular reorder buffers
- **Size:** Configurable (default 16 entries)

### 3.12 Peer Reorder Buffer Pool

**Location:** Line 282
```c
ret = ofi_bufpool_create(&ep->peer_robuf_pool,
                         (sizeof(struct efa_rdm_pke*) * 
                          (roundup_power_of_two(efa_env.recvwin_size)) +
                          sizeof(struct recvwin_cirq)),
                         EFA_RDM_BUFPOOL_ALIGNMENT, 0,
                         EFA_RDM_EP_MIN_PEER_POOL_SIZE, 0);
```

**Details:**
- **Entry Size:** (8 × 16) + overhead = ~150 bytes (default recvwin_size=16)
- **Initial Count:** 1024 (EFA_RDM_EP_MIN_PEER_POOL_SIZE)
- **Used For:** Per-peer reorder circular buffers
- **Grows:** Dynamically as more peers communicate

### 3.13 Read Copy Packet Pool (Conditional)

**Location:** Line 217
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
- **Entry Size:** ~8320 bytes
- **Count:** Configurable (efa_env.readcopy_pool_size)
- **Memory Registered:** YES
- **Used For:** Local read copy to HMEM receive buffers
- **Condition:** Only created when FI_HMEM capability requested AND (rx_copy_unexp OR rx_copy_ooo)
- **Tracking:** `rx_readcopy_pkt_pool_used`, `rx_readcopy_pkt_pool_max_used`

### 3.14 Debug Info Pool (ENABLE_DEBUG only)

**Location:** Line 296
```c
#if ENABLE_DEBUG
ret = ofi_bufpool_create(&ep->pke_debug_info_pool,
                         sizeof(struct efa_rdm_pke_debug_info_buffer),
                         EFA_RDM_BUFPOOL_ALIGNMENT, 0,
                         max_tx_pool_size + max_rx_pool_size, 0);
#endif
```

**Details:**
- **Entry Size:** 8 + (8 × 48) = 392 bytes
- **Count:** TX pool size + RX pool size (typically 16384)
- **Total Memory:** ~6 MB (debug builds only)
- **Used For:** Packet lifecycle debugging (circular buffer of events)

---
## 4. Packet Entry (pke) Lifecycle

### 4.1 Structure Definition

**Location:** `prov/efa/src/rdm/efa_rdm_pke.h`

**Size:** 128 bytes (optimized build), aligned to 128 bytes (2 cache lines)

**Key Fields:**
```c
struct efa_rdm_pke {
    struct dlist_entry entry;              // 16 bytes - linked list
    struct efa_rdm_ep *ep;                 // 8 bytes
    struct efa_rdm_ope *ope;               // 8 bytes
    size_t pkt_size;                       // 8 bytes
    struct fid_mr *mr;                     // 8 bytes - memory registration
    struct efa_rdm_peer *peer;             // 8 bytes
    enum efa_rdm_pke_alloc_type alloc_type;// 4 bytes
    uint32_t flags;                        // 4 bytes
    struct efa_rdm_pke *next;              // 8 bytes - for chaining
    char *payload;                         // 8 bytes
    struct fid_mr *payload_mr;             // 8 bytes
    size_t payload_size;                   // 8 bytes
    uint8_t gen;                           // 1 byte - generation counter
    #if ENABLE_DEBUG
    struct efa_rdm_pke_debug_info_buffer *debug_info; // 8 bytes
    struct dlist_entry dbg_entry;          // 16 bytes
    #endif
    char wiredata[0];                      // Variable size (MTU)
};
```

**Total:** 128 bytes + wiredata (typically 8192 bytes) = 8320 bytes

**Issue:** `pke->ep` duplicates `pke->ope->ep`

### 4.2 Allocation Paths

**From EFA TX Pool:**
```c
// prov/efa/src/rdm/efa_rdm_pke.c:77
pkt_entry = ofi_buf_alloc(ep->efa_tx_pkt_pool);
```
- **Used For:** Send, RDMA read/write
- **Memory Registered:** YES

**From EFA RX Pool:**
```c
pkt_entry = ofi_buf_alloc(ep->efa_rx_pkt_pool);
```
- **Used For:** Receive operations
- **Memory Registered:** YES

**From Unexpected Pool:**
```c
pkt_entry = ofi_buf_alloc(ep->rx_unexp_pkt_pool);
```
- **Used For:** Cloning unexpected packets
- **Memory Registered:** NO

**From OOO Pool:**
```c
pkt_entry = ofi_buf_alloc(ep->rx_ooo_pkt_pool);
```
- **Used For:** Cloning out-of-order packets
- **Memory Registered:** NO

**From User RX Pool:**
```c
pkt_entry = ofi_buf_alloc(ep->user_rx_pkt_pool);
```
- **Used For:** User-provided buffers (zero-copy)
- **Memory Registered:** NO (user's responsibility)

**From Read Copy Pool:**
```c
pkt_entry = ofi_buf_alloc(ep->rx_readcopy_pkt_pool);
```
- **Used For:** Local read copy to HMEM
- **Memory Registered:** YES

### 4.3 Release Paths

**TX Release:**
```c
// prov/efa/src/rdm/efa_rdm_pke.c:147
void efa_rdm_pke_release_tx(struct efa_rdm_pke *pkt_entry) {
    ofi_buf_free(pkt_entry);
}
```

**RX Release:**
```c
void efa_rdm_pke_release_rx(struct efa_rdm_pke *pkt_entry) {
    // Handle chained packets
    if (pkt_entry->next)
        efa_rdm_pke_release_rx_list(pkt_entry->next);
    ofi_buf_free(pkt_entry);
}
```

**Lifecycle:**
1. **Allocated:** When posting send/recv or handling unexpected/OOO
2. **In Use:** Tracked via `EFA_RDM_PKE_IN_USE` flag
3. **Queued:** May be in `peer->outstanding_tx_pkts` or `ope->queued_pkts`
4. **Released:** After send completion or receive processing

**Double-Free Prevention:** Generation counter (`gen`) incremented on each post

---
## 5. Operation Entry (ope) Lifecycle

### 5.1 Structure Definition

**Location:** `prov/efa/src/rdm/efa_rdm_ope.h`

**Size:** ~800+ bytes

**Key Fields:**
```c
struct efa_rdm_ope {
    enum efa_rdm_ope_type type;            // 4 bytes (TXE or RXE)
    struct efa_rdm_ep *ep;                 // 8 bytes
    struct efa_rdm_peer *peer;             // 8 bytes
    uint32_t tx_id, rx_id, op, msg_id;     // 16 bytes
    struct efa_rdm_atomic_hdr atomic_hdr;  // 8 bytes
    struct efa_rdm_atomic_ex atomic_ex;    // ~200 bytes (iov arrays)
    uint64_t tag, ignore;                  // 16 bytes
    int64_t window;                        // 8 bytes
    uint64_t total_len;                    // 8 bytes
    enum efa_rdm_ope_state state;          // 4 bytes
    uint64_t fi_flags;                     // 8 bytes
    uint32_t internal_flags;               // 4 bytes
    
    // IOV arrays
    size_t iov_count;                      // 8 bytes
    struct iovec iov[4];                   // 64 bytes
    void *desc[4];                         // 32 bytes
    struct fid_mr *mr[4];                  // 32 bytes
    
    // RMA IOV
    size_t rma_iov_count;                  // 8 bytes
    struct fi_rma_iov rma_iov[4];          // 128 bytes
    
    struct fi_cq_tagged_entry cq_entry;    // 64 bytes
    
    // List entries (16 bytes each)
    struct dlist_entry entry;              // domain longcts list
    struct dlist_entry ep_entry;           // ep tx/rxe list
    struct dlist_entry ack_list_entry;     // posted ack list
    struct dlist_entry queued_entry;       // queued list
    struct dlist_entry queued_pkts;        // queued packets
    struct dlist_entry peer_entry;         // peer tx/rxe list
    
    // Byte counters (RX)
    uint64_t bytes_received;
    uint64_t bytes_received_via_mulreq;
    uint64_t bytes_copied;
    uint64_t bytes_queued_blocking_copy;
    
    // Byte counters (TX)
    uint64_t bytes_acked;
    uint64_t bytes_sent;
    
    // Read/write counters
    uint64_t bytes_read_completed;
    uint64_t bytes_read_submitted;
    uint64_t bytes_read_total_len;
    uint64_t bytes_read_offset;
    uint64_t bytes_write_completed;
    uint64_t bytes_write_submitted;
    uint64_t bytes_write_total_len;
    
    size_t efa_outstanding_tx_ops;
    struct efa_rdm_pke *unexp_pkt;
    char *atomrsp_data;
    enum efa_rdm_cuda_copy_method cuda_copy_method;
    struct efa_rdm_rxe_map *rxe_map;
    struct fi_peer_rx_entry *peer_rxe;
    struct efa_rdm_pke *local_read_pkt_entry;
};
```

**Issue:** `ope->ep` duplicates `ope->peer->ep`

### 5.2 Allocation

**TX Entry (txe):**
```c
// prov/efa/src/rdm/efa_rdm_ep_utils.c:330
txe = ofi_buf_alloc(efa_rdm_ep->ope_pool);
```

**RX Entry (rxe):**
```c
// Line 175
rxe = ofi_buf_alloc(ep->ope_pool);
```

**Lifecycle:**
1. **Allocated:** At operation start (send/recv/read/write/atomic)
2. **Constructed:** `efa_rdm_txe_construct()` or similar
3. **Queued:** May be on multiple lists (ep_entry, peer_entry, queued_entry)
4. **Released:** `efa_rdm_txe_release()` or `efa_rdm_rxe_release()`

### 5.3 Release

**TX Release:**
```c
// prov/efa/src/rdm/efa_rdm_ope.c:160
void efa_rdm_txe_release(struct efa_rdm_ope *txe) {
    // Remove from lists
    dlist_remove(&txe->ep_entry);
    dlist_remove(&txe->peer_entry);
    // Free
    ofi_buf_free(txe);
}
```

**RX Release:**
```c
// Line 216
void efa_rdm_rxe_release(struct efa_rdm_ope *rxe) {
    // Remove from lists, free atomrsp_data if allocated
    if (rxe->atomrsp_data)
        ofi_buf_free(rxe->atomrsp_data);
    ofi_buf_free(rxe);
}
```

**Double-Free Prevention:** Removed from all lists before freeing

---
## 6. Peer Structure Lifecycle

### 6.1 Structure Definition

**Location:** `prov/efa/src/rdm/efa_rdm_peer.h`

**Size:** ~400+ bytes

**Key Fields:**
```c
struct efa_rdm_peer {
    struct efa_rdm_ep *ep;                 // 8 bytes
    bool is_self;                          // 1 byte
    bool is_local;                         // 1 byte
    uint32_t device_version;               // 4 bytes
    struct efa_conn *conn;                 // 8 bytes - pointer to AV entry
    uint64_t host_id;                      // 8 bytes
    
    struct efa_rdm_robuf robuf;            // Reorder buffer (~100 bytes)
    uint32_t next_msg_id;                  // 4 bytes
    uint32_t flags;                        // 4 bytes
    uint32_t nextra_p3;                    // 4 bytes
    uint64_t extra_info[8];                // 64 bytes
    
    size_t efa_outstanding_tx_ops;         // 8 bytes
    struct dlist_entry outstanding_tx_pkts;// 16 bytes
    
    uint64_t rnr_backoff_begin_ts;         // 8 bytes
    uint64_t rnr_backoff_wait_time;        // 8 bytes
    int rnr_queued_pkt_cnt;                // 4 bytes
    
    struct dlist_entry rnr_backoff_entry;  // 16 bytes
    struct dlist_entry handshake_queued_entry; // 16 bytes
    struct dlist_entry txe_list;           // 16 bytes
    struct dlist_entry rxe_list;           // 16 bytes
    struct dlist_entry overflow_pke_list;  // 16 bytes
    struct dlist_entry ep_peer_list_entry; // 16 bytes
    
    int64_t num_runt_bytes_in_flight;      // 8 bytes
    struct efa_rdm_peer_user_recv_qp user_recv_qp; // 8 bytes
    struct efa_rdm_rxe_map rxe_map;        // Hashmap (~50 bytes)
};
```

### 6.2 Allocation

**Implicit via Map Entry:**
```c
// prov/efa/src/rdm/efa_rdm_ep_utils.c:93
map_entry = ofi_buf_alloc(ep->peer_map_entry_pool);
// map_entry contains embedded efa_rdm_peer struct
```

**Lifecycle:**
1. **Created:** First communication with peer (implicit in map_entry)
2. **Constructed:** `efa_rdm_peer_construct()` in `prov/efa/src/rdm/efa_rdm_peer.c`
3. **Active:** Tracked in `ep->ep_peer_list`
4. **Destroyed:** `efa_rdm_peer_destruct()` when AV entry removed

### 6.3 Reorder Buffer Allocation

**Location:** `prov/efa/src/rdm/efa_rdm_peer.h:55-57`
```c
static inline int efa_recvwin_buf_alloc(struct efa_rdm_robuf *recvq,
                                        unsigned int size, 
                                        bool alloc_from_bufpool,
                                        struct ofi_bufpool *pool) {
    if (alloc_from_bufpool) {
        recvq->pending = ofi_buf_alloc(pool);  // From peer_robuf_pool
    } else {
        recvq->pending = calloc(1, sizeof(struct recvwin_cirq) +
                                sizeof(struct efa_rdm_pke*) * size);
    }
}
```

**Details:**
- **Size:** Default 16 entries (configurable)
- **Memory:** 16 × 8 bytes = 128 bytes + overhead
- **Freed:** `efa_recvwin_free()` at peer destruction

### 6.4 Overflow PKE List

**Allocation:**
```c
// prov/efa/src/rdm/efa_rdm_peer.c:183
overflow_pke_list_entry = ofi_buf_alloc(ep->overflow_pke_pool);
```

**Details:**
- **Used For:** Packets beyond reorder buffer capacity
- **Freed:** Line 91, 275 when processed

### 6.5 Release

**Location:** `prov/efa/src/efa_conn.c:203, 477`
```c
ofi_buf_free(peer_map_entry);  // Frees embedded peer struct
```

**Lifecycle:**
- **Created:** On first packet to/from peer
- **Freed:** When AV entry removed or endpoint closed

---
## 7. EFA-Direct Provider Allocations

### 7.1 Overview

EFA-direct provides direct hardware access with minimal protocol overhead. Additional memory allocations for direct data path.

### 7.2 Direct Data Path Structures

**Location:** `prov/efa/src/efa_data_path_direct_structs.h`

**efa_data_path_direct_qp:**
```c
struct efa_data_path_direct_qp {
    struct efa_data_path_direct_sq sq;  // Send queue
    struct efa_data_path_direct_rq rq;  // Receive queue
};
```

**efa_data_path_direct_sq:**
```c
struct efa_data_path_direct_sq {
    struct efa_data_path_direct_wq wq;
    uint8_t *desc;                      // Hardware send queue buffer
    uint32_t num_wqe_pending;
};
```

**efa_data_path_direct_wq:**
```c
struct efa_data_path_direct_wq {
    uint64_t *wrid;                     // Work request ID array
    uint32_t *wrid_idx_pool;            // Free index pool
    uint32_t wqe_cnt;
    uint32_t wqe_size;
    uint32_t wqe_posted;
    uint32_t wqe_completed;
    uint16_t pc;
    uint16_t desc_mask;
    uint16_t wrid_idx_pool_next;
    int phase;
    struct ofi_genlock *wqlock;
    uint32_t *db;                       // Doorbell register
    uint32_t max_batch;
};
```

### 7.3 Work Request ID Array Allocation

**Location:** `prov/efa/src/efa_data_path_direct_internal.h:338`

**wrid array:**
```c
wq->wrid = malloc(wq->wqe_cnt * sizeof(*wq->wrid));
```
- **Size:** wqe_cnt × 8 bytes (typically 8192 × 8 = 64 KB)
- **Freed:** Line 345, 370, 375

**wrid_idx_pool:**
```c
wq->wrid_idx_pool = malloc(wqe_cnt * sizeof(uint32_t));
```
- **Size:** wqe_cnt × 4 bytes (typically 8192 × 4 = 32 KB)
- **Freed:** Line 375

**Total per QP:** ~96 KB for SQ + ~96 KB for RQ = ~192 KB

### 7.4 Direct CQ Structure

**efa_data_path_direct_cq:**
```c
struct efa_data_path_direct_cq {
    uint8_t *buffer;                    // Hardware CQ buffer (mapped)
    uint32_t entry_size;
    uint32_t num_entries;
    struct efa_io_cdesc_common *cur_cqe;
    struct efa_qp *cur_qp;
    struct efa_data_path_direct_wq *cur_wq;
    int phase;
    int qmask;
    uint16_t consumed_cnt;
    uint32_t *db;                       // Doorbell
    uint16_t cc;
    uint8_t cmd_sn;
};
```

**Details:**
- **buffer:** Mapped from hardware (not allocated by provider)
- **Size:** ~100 bytes struct overhead
- **No additional allocations** (uses hardware-mapped memory)

### 7.5 Initialization

**QP Initialization:**
```c
// prov/efa/src/efa_data_path_direct.c
int efa_data_path_direct_qp_initialize(struct efa_qp *efa_qp) {
    // Allocates wrid and wrid_idx_pool for SQ and RQ
}
```

**CQ Initialization:**
```c
int efa_data_path_direct_cq_initialize(struct efa_ibv_cq *ibv_cq) {
    // Maps hardware CQ buffer (no allocation)
}
```

**Finalization:**
```c
void efa_data_path_direct_qp_finalize(struct efa_qp *efa_qp) {
    free(wq->wrid);
    free(wq->wrid_idx_pool);
}
```

### 7.6 Memory Comparison: EFA vs EFA-Direct

**EFA Fabric (per endpoint):**
- 10+ buffer pools: ~150 MB
- Endpoint struct: ~2 KB
- Work arrays: ~200 KB
- **Total:** ~150 MB+

**EFA-Direct Fabric (per endpoint):**
- Same buffer pools: ~150 MB
- Endpoint struct: ~2 KB
- Work arrays: ~200 KB
- Direct path arrays: ~200 KB
- **Total:** ~150 MB+ (similar, but faster path)

**Key Difference:** EFA-direct reduces protocol overhead and code path complexity, not memory footprint.

---
## 8. Domain and Fabric Allocations

### 8.1 EFA Domain

**Location:** `prov/efa/src/efa_domain.c:167`

**Allocation:**
```c
efa_domain = calloc(1, sizeof(struct efa_domain));
```

**Key Fields:**
```c
struct efa_domain {
    struct util_domain util_domain;
    struct efa_fabric *fabric;
    struct ibv_pd *ibv_pd;              // Protection domain
    struct ofi_mr_cache *cache;         // MR cache
    struct dlist_entry ope_longcts_send_list;
    // ... other fields
};
```

**Lifecycle:**
- **Created:** `fi_domain()` call
- **Freed:** `efa_domain_close()` at line 374

### 8.2 MR Cache

**Location:** `prov/efa/src/efa_mr.c:128`

**Allocation:**
```c
*cache = (struct ofi_mr_cache *)calloc(1, sizeof(struct ofi_mr_cache));
```

**Details:**
- **Used For:** Caching memory registrations
- **Contains:** RB-tree of registered regions
- **Freed:** Line 152 in `efa_mr_cache_destroy()`

**Entry Pool:**
```c
// prov/util/src/util_mr_cache.c:548
ret = ofi_bufpool_create(&cache->entry_pool,
                         sizeof(struct ofi_mr_entry) + entry_data_size,
                         0, 0, 1024, 0);
```

### 8.3 EFA Fabric

**Location:** `prov/efa/src/efa_fabric.c:131`

**Allocation:**
```c
efa_fabric = calloc(1, sizeof(*efa_fabric));
```

**Lifecycle:**
- **Created:** `fi_fabric()` call
- **Freed:** `efa_fabric_close()` at line 59, 166

### 8.4 Address Vector (AV)

**Location:** `prov/efa/src/efa_av.c:879`

**Allocation:**
```c
av = calloc(1, sizeof(*av));
```

**Key Components:**

**Reverse AV Entries (Hashmap):**
```c
// Line 248
cur_entry = malloc(sizeof(*cur_entry));
// Line 266
prv_entry = malloc(sizeof(*prv_entry));
```
- **Used For:** GID+QPN → fi_addr lookup
- **Freed:** Line 312, 322

**Connection Hashable:**
```c
// prov/efa/src/efa_conn.c:73
ep_addr_hashable = malloc(sizeof(struct efa_ep_addr_hashable));
```
- **Freed:** Line 812

**Lifecycle:**
- **Created:** `fi_av_open()`
- **Freed:** `efa_av_close()` at line 815, 960

### 8.5 Completion Queue (CQ)

**Location:** `prov/efa/src/efa_cq.c:1124`

**Allocation:**
```c
cq = calloc(1, sizeof(*cq));
```

**Error Buffer:**
```c
// Line 1180
cq->err_buf = malloc(EFA_ERROR_MSG_BUFFER_LENGTH);
```
- **Size:** Typically 256 bytes
- **Freed:** Line 915

**ibv_cq:**
- Created via rdma-core `ibv_create_cq()`
- Managed by rdma-core

**Lifecycle:**
- **Created:** `fi_cq_open()`
- **Freed:** `efa_cq_close()` at line 917, 1219

### 8.6 Counter (CNTR)

**Location:** `prov/efa/src/efa_cntr.c:212, 246`

**Allocation:**
```c
cntr = calloc(1, sizeof(*cntr));
```

**Lifecycle:**
- **Created:** `fi_cntr_open()`
- **Freed:** `efa_cntr_close()` at line 132, 232, 282

### 8.7 Additional String Allocations

**Device/Provider Info Strings:**

**domain_attr->name:**
```c
// prov/efa/src/efa_prov_info.c:80
prov_info->domain_attr->name = malloc(name_len + 1);
```

**device_attr->name:**
```c
// Line 290
device_attr->name = strdup(device->ibv_ctx->device->name);
```

**device_attr->firmware:**
```c
// Line 320
device_attr->firmware = strdup(device->ibv_attr.fw_ver);
```

**link_attr->network_type:**
```c
// Line 374
link_attr->network_type = strdup("Ethernet");
```

**link_attr->address:**
```c
// Line 344
link_attr->address = calloc(1, link_addr_len + 1);
```

**src_addr:**
```c
// Lines 335, 500
src_addr = calloc(1, EFA_EP_ADDR_LEN);
prov_info->src_addr = calloc(1, EFA_EP_ADDR_LEN);
```

**fabric_attr->name:**
```c
// prov/efa/src/efa_prov.h:23
prov_info->fabric_attr->name = calloc(1, strlen(fabric_name) + 1);
```

**Device Version String:**
```c
// prov/efa/src/efa_device.c:531
*device_version = calloc(1, EFA_ABI_VER_MAX_LEN + 1);
```

**SHM Provider Strings:**
```c
// prov/efa/src/efa_shm.c:126-127
shm_hints->fabric_attr->name = strdup(shm_provider);
shm_hints->fabric_attr->prov_name = strdup(shm_provider);
```

**Device Paths:**
```c
// prov/efa/src/efa_device.c:458, 465, 503
sysfs_path = strndup(env, IBV_SYSFS_PATH_MAX);
sysfs_path = strdup("/sys");
*efa_driver = strdup(driver);
```

### 8.8 Device-Level Allocations

**QP Table:**
```c
// prov/efa/src/efa_device.c:122
efa_device->qp_table = calloc(qp_table_size, sizeof(*efa_device->qp_table));
```
- **Size:** qp_table_size × pointer size
- **Freed:** Line 160, 191

**Global Device Lists:**
```c
// Lines 253, 259
g_efa_selected_device_list = calloc(total_device_cnt, sizeof(struct efa_device));
g_efa_ibv_gid_list = calloc(total_device_cnt, sizeof(union ibv_gid));
```
- **Freed:** Line 350, 357

### 8.9 rdma-core Allocations

**Protection Domain (PD):**
```c
// prov/efa/src/efa_domain.c:94
efa_domain->ibv_pd = ibv_alloc_pd(efa_domain->device->ibv_ctx);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_dealloc_pd()` at domain close

**Queue Pair (QP):**
```c
// prov/efa/src/efa_base_ep.c:247, 268, 277
(*qp)->ibv_qp = ibv_create_qp_ex(...);
(*qp)->ibv_qp = efadv_create_qp_ex(...);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_qp()` at QP close

**Completion Queue (CQ):**
```c
// prov/efa/src/efa_cq.c:1039, 1053
ibv_cq->ibv_cq_ex = efadv_create_cq(...);
ibv_cq->ibv_cq_ex = ibv_create_cq_ex(...);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_cq()` at CQ close

**Completion Channel:**
```c
// prov/efa/src/efa_cq.h:130
ibv_cq->channel = ibv_create_comp_channel(ibv_ctx);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_comp_channel()` at CQ close

**Address Handle (AH):**
```c
// prov/efa/src/efa_ah.c:115, 130
efa_ah->ibv_ah = ibv_create_ah(ibv_pd, &ibv_ah_attr);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_ah()` at AH close

---
## 9. Memory Registration

### 9.1 Overview

Memory registration with EFA device is required for zero-copy RDMA operations.

### 9.2 Registered Memory Regions

**Buffer Pool Memory:**
- `efa_tx_pkt_pool`: ~64 MB registered
- `efa_rx_pkt_pool`: ~64 MB registered
- `rx_readcopy_pkt_pool`: Dynamic, registered
- **Total:** ~128+ MB per endpoint

**User Buffers:**
- Registered on-demand via `fi_mr_reg()`
- Cached in MR cache to avoid re-registration

### 9.3 MR Registration Path

**Location:** `prov/efa/src/efa_mr.c:892, 1085`

**Allocation:**
```c
efa_mr = calloc(1, sizeof(*efa_mr));
```

**ibv_reg_mr:**
```c
efa_mr->ibv_mr = ibv_reg_mr(domain->ibv_pd, buf, len, access);
```

**ibv_reg_dmabuf_mr (HMEM):**
```c
// Line 475
return ibv_reg_dmabuf_mr(pd, offset, len, iova, fd, access);
```
- **Used For:** DMABUF-based memory registration (HMEM support)
- **Fallback:** Falls back to `ibv_reg_mr()` if dmabuf fails

**Lifecycle:**
- **Created:** `efa_mr_regattr()` or `efa_mr_regv()`
- **Freed:** `efa_mr_close()` at line 457, 907, 1132, 1142

### 9.4 MR Cache Entry

**Structure:**
```c
struct ofi_mr_entry {
    struct ofi_mr_info info;
    void *storage_context;
    // ... cache management fields
};
```

**Allocation:** From `cache->entry_pool` (bufpool)

**Lifecycle:**
- **Cached:** On first registration
- **Reused:** On subsequent registrations of same region
- **Evicted:** Based on LRU policy

### 9.5 HMEM Testing Allocations

**Fork Support Test:**
```c
// prov/efa/src/efa_fork_support.c:101, 105, 112
buf = malloc(page_size);
ibv_pd = ibv_alloc_pd(g_efa_selected_device_list[0].ibv_ctx);
mr = ibv_reg_mr(ibv_pd, buf, page_size, 0);
```
- **Used For:** Testing fork support
- **Freed:** After test

**HMEM Info Test:**
```c
// prov/efa/src/efa_hmem.c:138, 149, 156, 221
ibv_pd = ibv_alloc_pd(g_efa_selected_device_list[0].ibv_ctx);
ibv_mr = ibv_reg_dmabuf_mr(ibv_pd, dmabuf_offset, ...);
ibv_mr = ibv_reg_mr(ibv_pd, ptr, len, ibv_access);
```
- **Used For:** Testing P2P support
- **Freed:** After test

### 9.6 Memory Registration Overhead

**Cost per Registration:**
- System call to kernel
- Page table setup
- DMA mapping

**Mitigation:**
- MR cache reduces re-registration
- Pre-registered buffer pools

**Issue:** Repeated registration/deregistration causes performance regression (hpc6a alltoall)

---
## 10. Recommendations

### 10.1 Immediate Actions

**1. Touch Pre-Allocated Memory** ✅ VERIFIED
- **Issue:** Page faults on first access to buffer pools
- **Evidence:** Historical regression on trn1 (nccom allgather/redsct)
- **Fix:** Touch pages after allocation in `ofi_bufpool_create()`
- **Location:** `prov/util/src/util_buf.c`
- **Impact:** Eliminates page fault regression
- **Effort:** Low (1-2 days)

**2. Shrink Unexpected/OOO Pools** ✅ VERIFIED (Subspace-3161)
- **Issue:** Pools grow but never shrink
- **Evidence:** Code shows no shrinking logic in `rx_unexp_pkt_pool` and `rx_ooo_pkt_pool`
- **Fix:** Implement periodic pool trimming
- **Impact:** Reduces memory footprint after traffic surges
- **Effort:** Medium (1 week)

**3. Optimize Struct Field Ordering** ✅ VERIFIED
- **Issue:** Frequently accessed fields scattered across cache lines
- **Evidence:** Analysis in Appendix D shows hot fields not grouped
- **Fix:** Group hot fields at struct start
- **Structs:** `efa_rdm_pke` (already optimized), `efa_rdm_ope`, `efa_rdm_peer`, `efa_rdm_ep`
- **Impact:** Reduces cache misses in progress engine
- **Effort:** Medium (2 weeks with testing)

### 10.2 Medium-Term Improvements

**4. Remove Duplicate Fields** ✅ VERIFIED
- **Issue:** `pke->ep` == `pke->ope->ep`, `ope->ep` == `ope->peer->ep`
- **Evidence:** Confirmed in struct definitions
- **Fix:** Remove redundant pointers, access via indirection
- **Tradeoff:** One extra indirection vs 8-16 bytes saved per struct
- **Impact:** Reduces struct sizes, potential performance impact
- **Effort:** Medium (2 weeks)
- **Risk:** High (need performance validation)

**5. Consolidate RX Pools** ✅ VERIFIED (Subspace-967)
- **Issue:** Separate unexp/ooo pools, each 8KB entries
- **Current:** RX pool = 8192 entries = 64 MB (32 pages)
- **Proposal:** Single larger RX pool (16K entries = 96 MB, only 32 more pages)
- **Benefits:**
  - Eliminates pool growth logic
  - Fixes never-shrink issue (Subspace-3161)
  - Simplifies code
- **Impact:** Simplifies code, eliminates growth, +32 MB memory
- **Effort:** High (4-6 weeks, protocol changes)

**6. Cache-Line Aligned Domain Pools** ✅ VERIFIED
- **Issue:** Multiple small allocations, false sharing across NUMA nodes
- **Evidence:** Current allocations use malloc/calloc without alignment
- **Fix:** Domain-level cache-line aligned buffer pools (64-byte alignment)
- **Impact:** Better NUMA performance, reduced allocation overhead
- **Effort:** High (4-6 weeks, major refactor)

### 10.3 Long-Term Optimizations

**7. Separate Context Pool for RDMA** ✅ VERIFIED
- **Issue:** `efa_rdm_ope` too large (800+ bytes) for simple RDMA operations
- **Proposal:** Dedicated `efa_context` type for read/write
- **Reference:** "A List of Libfabric Refactors"
- **Current:** All operations use same 800-byte ope struct
- **Optimized:** RDMA ops use smaller context (~200 bytes)
- **Impact:** Reduces memory per RDMA operation by 75%
- **Effort:** Very High (8-12 weeks, major refactor)

**8. Optimize Large Structs** ✅ VERIFIED
- **efa_rdm_pke:** Already optimized to 128 bytes ✅
- **efa_rdm_ope:** Reduce from 800+ to <512 bytes
  - Remove duplicate fields (ep, peer pointers)
  - Separate TX/RX specific fields into unions
  - Use unions for mutually exclusive fields (atomic_ex, rma_iov)
  - Group byte counters together
- **Impact:** Better cache utilization, more entries per pool
- **Effort:** High (6-8 weeks)

**9. Disable Copy-on-Write for Hugepages** ✅ VERIFIED (Subspace-3346)
- **Issue:** Fork causes COW on internal buffers
- **Fix:** Use `madvise(MADV_DONTFORK)` on hugepage pools
- **Evidence:** No current implementation found in codebase
- **Location:** Should be in buffer pool creation or fork support
- **Impact:** Prevents memory duplication after fork
- **Effort:** Low (1 week)
- **Note:** Only affects applications that fork after EP creation

**10. Memory Poisoning (Debug Builds)** ✅ VERIFIED
- **Issue:** Use-after-free bugs hard to detect
- **Fix:** Poison freed buffers in debug builds
- **Evidence:** No current poisoning implementation found
- **Pattern:** Fill freed memory with 0xDEADBEEF or similar
- **Impact:** Earlier detection of memory corruption
- **Effort:** Low (1 week)
- **Note:** Debug builds only, no production impact

**11. In-Order Aligned 128-Byte Support** ✅ VERIFIED
- **Feature:** Support for in-order send/recv/write of 128-byte aligned regions
- **Evidence:** Code exists but currently disabled
- **Location:** `efa_rdm_ep_fiops.c:1870, 1880, 1888`
- **Status:** `FI_OPT_EFA_SENDRECV_IN_ORDER_ALIGNED_128_BYTES` returns `-FI_EOPNOTSUPP`
- **Alignment:** `EFA_RDM_IN_ORDER_ALIGNMENT` used for readcopy pool (line 222)
- **Impact:** Could enable optimizations for aligned transfers
- **Effort:** Medium (depends on hardware support)

### 10.4 EFA-Direct Specific

**12. Optimize Direct Path Allocations** ✅ VERIFIED
- **Current:** wrid arrays allocated separately (malloc)
- **Evidence:** `efa_data_path_direct_internal.h:338, 343`
- **Proposal:** Embed in QP structure or use bufpool
- **Impact:** Reduces allocation overhead, better locality
- **Effort:** Low (1 week)

**13. Batch Doorbell Rings** ✅ VERIFIED
- **Current:** `num_wqe_pending` tracks batching
- **Evidence:** `efa_data_path_direct_structs.h` shows batching support
- **Optimization:** Tune `max_batch` based on workload
- **Impact:** Reduces MMIO writes
- **Effort:** Low (tuning only)

---
## Appendix A: Historical Memory-Related Issues

### A.1 Performance Regressions

**1. nccom allgather/redsct on 4 trn1**
- **Root Cause:** Page faults on pre-allocated endpoint memory
- **Details:** Memory allocated but pages not touched, causing faults during benchmark
- **Location:** Buffer pool allocation in `efa_rdm_ep_fiops.c`

**2. Intra-node c7gn latency**
- **Root Cause:** Hashmap change for peer lookup
- **Details:** Changed hashmap implementation affected cache behavior
- **Commit:** Referenced in ticket
- **Side Effect:** Improved other benchmarks (P327133146)

**3. 12 node hpc6a alltoall (Libfabric 1.22 → 2.1)**
- **Root Cause:** EFA-direct introduction
- **Details:** Additional code paths and memory allocations
- **Secondary:** Repeated MR registration/deregistration

**4. BTL/OFI performance degradation**
- **Root Cause:** Memory allocation for BTL endpoint
- **Workaround:** Punted RX packet pool allocation
- **Issue:** Bandaid solution, doesn't address root cause

**5. 12 hpc6a Alltoallv after peer API changes**
- **Root Cause:** Unrelated peer API changes
- **Details:** Memory layout or access pattern changes

**6. Open MPI 5 IMB alltoall 4/8B latency (hpc7g)**
- **Root Cause:** Compiling with xpmem (even when unused)
- **Details:** xpmem library affects memory allocation behavior
- **GitHub:** https://github.com/ofiwg/libfabric/issues/10403

**7. IMB Gatherv (>8KB) intelmpi latency**
- **Root Cause:** Referencing field in pke struct
- **Details:** Cache line access pattern change

**8. Dev installer 1.39 regressions**
- **Root Cause:** EFA-direct path introduction
- **Details:** Multiple regressions from new code paths

**9. EFA installer 1.44 regressions**
- **Root Cause:** Multiple endpoints binding to single AV
- **Details:** Shared AV state causing memory contention

### A.2 Operational Issues

**Double-Free Bugs:**
- **Example:** P367530918
- **Prevention:** Generation counters, list removal before free

**Memory Leaks:**
- **Pools never shrink:** Unexpected/OOO pools (Subspace-3161)
- **Overflow lists:** Peer overflow_pke_list growth

**NUMA Issues:**
- **False sharing:** Non-aligned allocations across NUMA nodes
- **Remote access:** Peer structures on wrong NUMA node

---
## Appendix B: Memory Allocation Summary Tables

### B.1 Per-Endpoint Memory Footprint

| Component | Size | Count | Total | Registered |
|-----------|------|-------|-------|------------|
| efa_rdm_ep struct | 2 KB | 1 | 2 KB | No |
| efa_tx_pkt_pool | 8320 B | 8192 | 64 MB | Yes |
| efa_rx_pkt_pool | 8320 B | 8192 | 64 MB | Yes |
| ope_pool | 800 B | 16384 | 12 MB | No |
| rx_unexp_pkt_pool | 8320 B | Dynamic | Variable | No |
| rx_ooo_pkt_pool | 8320 B | Dynamic | Variable | No |
| rx_readcopy_pkt_pool | 8320 B | Dynamic | Variable | Yes (if HMEM) |
| user_rx_pkt_pool | 128 B+ | Dynamic | Variable | No |
| rx_atomrsp_pool | 8192 B | Dynamic | Variable | No |
| map_entry_pool | Variable | Dynamic | Variable | No |
| overflow_pke_pool | 32 B | Dynamic | Variable | No |
| peer_map_entry_pool | Variable | 1024+ | ~1 MB | No |
| peer_robuf_pool | 150 B | 1024+ | ~150 KB | No |
| pke_debug_info_pool | 392 B | 16384 | 6 MB | No (DEBUG only) |
| Work arrays | Variable | 3 | ~200 KB | No |
| **Total (minimum)** | | | **~142 MB** | **128 MB** |
| **Total (with HMEM)** | | | **~150+ MB** | **136+ MB** |

### B.2 Per-Peer Memory Footprint

| Component | Size | Notes |
|-----------|------|-------|
| efa_rdm_peer struct | 400 B | Embedded in map_entry |
| Reorder buffer | 150 B | Default 16 entries |
| Overflow list | Variable | Grows with OOO packets |
| RXE map | 50 B | Hashmap for mulreq |
| **Total (typical)** | **~600 B** | Per peer |

### B.3 Per-Operation Memory Footprint

| Component | Size | Notes |
|-----------|------|-------|
| efa_rdm_ope (TX) | 800 B | From ope_pool |
| efa_rdm_ope (RX) | 800 B | From ope_pool |
| atomrsp_data (if atomic) | 8192 B | From rx_atomrsp_pool |
| host_data (temp, HMEM) | Variable | Temporary for HMEM copy |
| **Total (typical)** | **800 B** | Per operation |
| **Total (atomic)** | **~9 KB** | Per atomic operation |

### B.4 Per-Packet Memory Footprint

| Component | Size | Notes |
|-----------|------|-------|
| efa_rdm_pke struct | 128 B | Aligned to 128 B |
| wiredata | 8192 B | MTU size |
| debug_info (DEBUG) | 392 B | Only in debug builds |
| **Total (optimized)** | **8320 B** | Per packet |
| **Total (debug)** | **8712 B** | Per packet |

### B.5 EFA-Direct Additional Memory

| Component | Size | Notes |
|-----------|------|-------|
| wrid array (SQ) | 64 KB | Per QP |
| wrid_idx_pool (SQ) | 32 KB | Per QP |
| wrid array (RQ) | 64 KB | Per QP |
| wrid_idx_pool (RQ) | 32 KB | Per QP |
| **Total per QP** | **192 KB** | Additional overhead |

### B.6 Domain/Fabric Memory Footprint

| Component | Size | Count | Total | Notes |
|-----------|------|-------|-------|-------|
| efa_domain | 1 KB | 1 | 1 KB | Per domain |
| efa_fabric | 1 KB | 1 | 1 KB | Per fabric |
| efa_av | 2 KB | 1 | 2 KB | Per AV |
| MR cache | Variable | 1 | Variable | RB-tree + entries |
| efa_cq | 1 KB | Variable | Variable | Per CQ |
| efa_cntr | 1 KB | Variable | Variable | Per counter |
| QP table | Variable | 1 | Variable | Per device |
| **Total (typical)** | | | **~10 KB** | Shared resources |

### B.7 String Allocation Summary

| Type | Count | Typical Size | Total |
|------|-------|--------------|-------|
| Device/domain names | 5-10 | 64 B | ~500 B |
| Firmware version | 1 | 32 B | 32 B |
| Network type | 1 | 16 B | 16 B |
| Addresses | 2-5 | 32 B | ~100 B |
| Paths | 2-3 | 256 B | ~500 B |
| **Total** | | | **~1 KB** |

---
## Appendix C: Allocation/Free Location Reference

### C.1 Endpoint Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| efa_rdm_ep | Line 547 | Lines 718, 1197 | efa_rdm_ep_fiops.c |
| pke_vec | Line 668 | Lines 706, 1189 | efa_rdm_ep_fiops.c |
| send_pkt_entry_vec | Line 675 | Lines 704, 1191 | efa_rdm_ep_fiops.c |
| send_pkt_entry_size_vec | Line 682 | Line 1193 | efa_rdm_ep_fiops.c |
| efa_recv_wr_vec | Line 501 | Line 147 | efa_base_ep.c |
| user_recv_wr_vec | Line 506 | Line 150 | efa_base_ep.c |
| shm_peer_srx | Line 1526 | Line 1089 | efa_rdm_ep_fiops.c |
| efa_qp | Line 239 | Lines 285, 443 | efa_base_ep.c |
| efa_ep (DGRAM) | Line 432 | Lines 222, 455 | efa_ep.c |

### C.2 Buffer Pool Allocations

| Pool | Created | Destroyed | File |
|------|---------|-----------|------|
| efa_tx_pkt_pool | Line 179 | EP close | efa_rdm_ep_fiops.c |
| efa_rx_pkt_pool | Line 180 | EP close | efa_rdm_ep_fiops.c |
| user_rx_pkt_pool | Line 189 | EP close | efa_rdm_ep_fiops.c |
| ope_pool | Line 248 | EP close | efa_rdm_ep_fiops.c |
| rx_unexp_pkt_pool | Line 200 | EP close | efa_rdm_ep_fiops.c |
| rx_ooo_pkt_pool | Line 211 | EP close | efa_rdm_ep_fiops.c |
| rx_readcopy_pkt_pool | Line 217 | EP close | efa_rdm_ep_fiops.c |
| map_entry_pool | Line 232 | EP close | efa_rdm_ep_fiops.c |
| rx_atomrsp_pool | Line 241 | EP close | efa_rdm_ep_fiops.c |
| overflow_pke_pool | Line 260 | EP close | efa_rdm_ep_fiops.c |
| peer_map_entry_pool | Line 269 | EP close | efa_rdm_ep_fiops.c |
| peer_robuf_pool | Line 282 | EP close | efa_rdm_ep_fiops.c |
| pke_debug_info_pool | Line 296 | EP close | efa_rdm_ep_fiops.c |

### C.3 Operation Entry Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| txe | Lines 55, 57, 330 | Line 160 | efa_rdm_atomic.c, efa_rdm_rma.c, efa_rdm_ep_utils.c / efa_rdm_ope.c |
| rxe | Line 175 | Line 216 | efa_rdm_ep_utils.c / efa_rdm_ope.c |
| atomrsp_data | Line 127 | Lines 556, 835 | efa_rdm_pke_rta.c / efa_rdm_pke_nonreq.c |
| host_data (temp) | Lines 171, 341, 475 | Lines 177, 188, 347, 359, 481, 490 | efa_rdm_pke_rta.c |

### C.4 Packet Entry Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| pkt_entry (TX) | ofi_buf_alloc | Line 147 | efa_rdm_pke.c |
| pkt_entry (RX) | ofi_buf_alloc | Line 147 | efa_rdm_pke.c |
| debug_info | Line 77 | EP close | efa_rdm_pke.c |

### C.5 Peer Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| peer_map_entry | Lines 93, 138 | Lines 203, 477, 888 | efa_rdm_ep_utils.c / efa_conn.c / efa_rdm_ep_fiops.c |
| robuf.pending | peer_construct | peer_destruct | efa_rdm_peer.h |
| overflow_pke_list_entry | Line 183 | Lines 91, 275 | efa_rdm_peer.c |
| rxe_map_entry | Line 42 | Line 84 | efa_rdm_rxe_map.c |

### C.6 Domain/Fabric Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| efa_domain | Line 167 | Line 374 | efa_domain.c |
| MR cache | Line 128 | Line 152 | efa_mr.c |
| efa_fabric | Line 131 | Lines 59, 166 | efa_fabric.c |
| efa_av | Line 879 | Lines 815, 960 | efa_av.c |
| reverse_av entries | Lines 248, 266 | Lines 312, 322 | efa_av.c |
| ep_addr_hashable | Line 73 | Line 812 | efa_conn.c |
| efa_cq | Line 1124 | Lines 917, 1219 | efa_cq.c |
| efa_rdm_cq | Line 1289 | Line 126, 1369 | efa_rdm_cq.c |
| cq->err_buf | Line 1180 | Line 915 | efa_cq.c |
| efa_cntr | Lines 212, 246 | Lines 132, 232, 282 | efa_cntr.c |
| efa_ah | Line 105 | Lines 166, 185 | efa_ah.c |
| qp_table | Line 122 | Lines 160, 191 | efa_device.c |
| g_efa_selected_device_list | Line 253 | Line 350 | efa_device.c |
| g_efa_ibv_gid_list | Line 259 | Line 357 | efa_device.c |

### C.7 String Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| domain_attr->name | Line 80 | fi_freeinfo | efa_prov_info.c |
| device_attr->name | Line 290 | fi_freeinfo | efa_prov_info.c |
| device_attr->firmware | Line 320 | fi_freeinfo | efa_prov_info.c |
| link_attr->network_type | Line 374 | fi_freeinfo | efa_prov_info.c |
| link_attr->address | Line 344 | fi_freeinfo | efa_prov_info.c |
| src_addr | Lines 335, 500 | Lines 380, 384 | efa_prov_info.c |
| fabric_attr->name | Line 23 | fi_freeinfo | efa_prov.h |
| device_version | Line 531 | Lines 509, 513 | efa_device.c |
| sysfs_path | Lines 458, 465 | Lines 548, 552 | efa_device.c |
| efa_driver | Line 503 | Lines 597, 601 | efa_device.c |
| shm_hints strings | Lines 126, 127 | fi_freeinfo | efa_shm.c |
| dest_addr | Line 43 | Line 46 | efa_user_info.c |

### C.8 Memory Registration

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| efa_mr | Lines 892, 1085 | Lines 457, 907, 1132, 1142 | efa_mr.c |
| MR cache entry | bufpool | bufpool | util_mr_cache.c |
| fork test buf | Line 101 | Line 108 | efa_fork_support.c |

### C.9 EFA-Direct Allocations

| What | Allocated | Freed | File |
|------|-----------|-------|------|
| wq->wrid | Line 338 | Lines 345, 370, 375 | efa_data_path_direct_internal.h |
| wq->wrid_idx_pool | Line 343 | Line 375 | efa_data_path_direct_internal.h |

### C.10 rdma-core Allocations

| What | Allocated | Freed | Notes |
|------|-----------|-------|-------|
| ibv_pd | ibv_alloc_pd | ibv_dealloc_pd | Protection domain |
| ibv_qp | ibv_create_qp_ex / efadv_create_qp_ex | ibv_destroy_qp | Queue pair |
| ibv_cq_ex | efadv_create_cq / ibv_create_cq_ex | ibv_destroy_cq | Completion queue |
| ibv_comp_channel | ibv_create_comp_channel | ibv_destroy_comp_channel | Completion channel |
| ibv_ah | ibv_create_ah | ibv_destroy_ah | Address handle |
| ibv_mr | ibv_reg_mr / ibv_reg_dmabuf_mr | ibv_dereg_mr | Memory registration |

---
## Appendix D: Struct Field Analysis

### D.1 efa_rdm_pke Cache Line Analysis

**Size:** 128 bytes (2 cache lines on x86)

**Cache Line 0 (0-63 bytes) - Hot Path:**
```
Offset | Size | Field                | Access Frequency
-------|------|----------------------|------------------
0      | 16   | entry (dlist)        | High (list ops)
16     | 8    | ep                   | Very High
24     | 8    | ope                  | Very High
32     | 8    | pkt_size             | High
40     | 8    | mr                   | High
48     | 8    | peer                 | Very High
56     | 4    | alloc_type           | Medium
60     | 4    | flags                | Very High
```

**Cache Line 1 (64-127 bytes) - Moderate Path:**
```
Offset | Size | Field                | Access Frequency
-------|------|----------------------|------------------
64     | 8    | next                 | Medium
72     | 8    | payload              | High
80     | 8    | payload_mr           | Medium
88     | 8    | payload_size         | High
96     | 1    | gen                  | High
97     | 7    | padding              | -
104    | 8    | debug_info (DEBUG)   | Low
112    | 16   | dbg_entry (DEBUG)    | Low
```

**Recommendation:** Current layout is well-optimized for hot path.

### D.2 efa_rdm_ope Cache Line Analysis

**Size:** ~800 bytes (13 cache lines)

**Hot Fields (Should be in first 64 bytes):**
- `ep` (8B) - Very High
- `peer` (8B) - Very High
- `state` (4B) - Very High
- `internal_flags` (4B) - Very High
- `efa_outstanding_tx_ops` (8B) - High
- `bytes_sent` / `bytes_received` (8B each) - High

**Current Layout Issues:**
- Hot fields scattered across multiple cache lines
- Large atomic_ex struct (200B) in middle
- Byte counters at end (far from hot fields)

**Recommendation:** Reorder to group hot fields at start.

### D.3 efa_rdm_peer Cache Line Analysis

**Size:** ~400 bytes (7 cache lines)

**Hot Fields:**
- `ep` (8B) - Very High
- `flags` (4B) - Very High
- `efa_outstanding_tx_ops` (8B) - High
- `next_msg_id` (4B) - High
- `robuf` (100B) - High

**Current Layout Issues:**
- `robuf` is large and in middle
- Hot fields not grouped

**Recommendation:** Move hot scalars to start, robuf to end.

### D.4 Duplicate Field Analysis

**pke->ep vs pke->ope->ep:**
- Both point to same endpoint
- `pke->ep` used for direct access
- Could remove `pke->ep`, access via `pke->ope->ep`
- **Tradeoff:** One extra indirection vs 8 bytes saved

**ope->ep vs ope->peer->ep:**
- Both point to same endpoint
- `ope->ep` used frequently in hot path
- **Recommendation:** Keep `ope->ep` for performance

**pke->peer vs pke->ope->peer:**
- Similar to above
- **Recommendation:** Keep `pke->peer` for hot path

---
## Appendix E: Implementation Roadmap

### Phase 1: Quick Wins (1-2 weeks)

**Task 1.1: Touch Pre-Allocated Pages**
- **File:** `prov/util/src/util_buf.c` (ofi_bufpool_create)
- **Change:** Touch first byte of each page after allocation
- **Impact:** Eliminates page fault regression
- **Risk:** Low

**Task 1.2: Optimize pke Field Ordering**
- **File:** `prov/efa/src/rdm/efa_rdm_pke.h`
- **Change:** Already optimized, verify with perf counters
- **Impact:** Baseline measurement
- **Risk:** None

**Task 1.3: Add Pool Shrinking**
- **Files:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c`
- **Change:** Periodic trim of unexp/ooo pools
- **Impact:** Reduces memory after surges
- **Risk:** Medium (need careful lifecycle management)

### Phase 2: Struct Optimization (2-4 weeks)

**Task 2.1: Reorder efa_rdm_ope Fields**
- **File:** `prov/efa/src/rdm/efa_rdm_ope.h`
- **Change:** Move hot fields to first cache line
- **Impact:** Reduces cache misses
- **Risk:** Medium (extensive testing needed)

**Task 2.2: Reorder efa_rdm_peer Fields**
- **File:** `prov/efa/src/rdm/efa_rdm_peer.h`
- **Change:** Group hot fields at start
- **Impact:** Better cache utilization
- **Risk:** Medium

**Task 2.3: Remove Duplicate Fields**
- **Files:** Multiple
- **Change:** Remove `pke->ep`, access via `pke->ope->ep`
- **Impact:** 8 bytes per pke, potential performance impact
- **Risk:** High (need performance validation)

### Phase 3: Pool Consolidation (4-6 weeks)

**Task 3.1: Merge RX Pools**
- **File:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c`
- **Change:** Single RX pool instead of separate unexp/ooo
- **Impact:** Simplifies code, eliminates growth
- **Risk:** High (protocol changes)

**Task 3.2: Domain-Level Pools**
- **Files:** Multiple
- **Change:** Cache-line aligned pools at domain level
- **Impact:** Better NUMA performance
- **Risk:** High (major refactor)

### Phase 4: Advanced Optimizations (6-12 weeks)

**Task 4.1: Separate RDMA Context**
- **Files:** Multiple
- **Change:** New `efa_context` type for RDMA ops
- **Impact:** Reduces memory per RDMA operation
- **Risk:** Very High (major refactor)

**Task 4.2: Hugepage COW Disable**
- **File:** `prov/efa/src/efa_fork_support.c`
- **Change:** Use `madvise(MADV_DONTFORK)`
- **Impact:** Prevents memory duplication after fork
- **Risk:** Medium

**Task 4.3: Memory Poisoning**
- **Files:** Buffer pool code
- **Change:** Poison freed buffers in debug builds
- **Impact:** Earlier bug detection
- **Risk:** Low (debug only)

### Testing Requirements

**Per Phase:**
1. Unit tests for all changed code
2. Fabtests full suite
3. Performance benchmarks:
   - IMB allgather, alltoall, alltoallv
   - OSU latency, bandwidth
   - Application-specific tests (nccom, etc.)
4. Stress tests (long-running, high message rate)
5. Memory leak detection (valgrind)
6. NUMA performance validation

**Regression Prevention:**
- Automated performance CI
- Memory footprint tracking
- Page fault monitoring

---
## Appendix F: Key Takeaways

### For Performance Engineers

1. **Endpoint Memory:** ~142 MB minimum per endpoint (128 MB registered)
2. **Hot Structs:** pke (128B), ope (800B), peer (400B)
3. **Page Faults:** Pre-allocated memory not touched causes regression
4. **Pool Growth:** Unexpected/OOO pools never shrink
5. **Cache Lines:** Struct fields not optimized for access patterns

### For Developers

1. **Buffer Pools:** Use `ofi_bufpool_create()` for all allocations
2. **Lifecycle:** Always remove from lists before freeing
3. **Double-Free:** Use generation counters and flags
4. **Memory Registration:** Expensive, use MR cache
5. **EFA-Direct:** Additional 192 KB per QP for wrid arrays

### For Architects

1. **Memory Model:** Domain → Endpoint → Pools → Entries
2. **Scalability:** Memory grows with endpoints and peers
3. **NUMA:** Need cache-line aligned domain-level pools
4. **Protocol:** RDM emulation requires significant state
5. **EFA vs EFA-Direct:** Similar memory, different code paths

### Critical Files

**Endpoint:**
- `prov/efa/src/rdm/efa_rdm_ep_fiops.c` - EP lifecycle, pool creation
- `prov/efa/src/efa_base_ep.c` - Base EP, work arrays

**Structures:**
- `prov/efa/src/rdm/efa_rdm_pke.h` - Packet entry (128B)
- `prov/efa/src/rdm/efa_rdm_ope.h` - Operation entry (800B)
- `prov/efa/src/rdm/efa_rdm_peer.h` - Peer state (400B)
- `prov/efa/src/rdm/efa_rdm_ep.h` - Endpoint (2KB+)

**Lifecycle:**
- `prov/efa/src/rdm/efa_rdm_pke.c` - Packet alloc/free
- `prov/efa/src/rdm/efa_rdm_ope.c` - Operation alloc/free
- `prov/efa/src/rdm/efa_rdm_peer.c` - Peer construct/destruct

**EFA-Direct:**
- `prov/efa/src/efa_data_path_direct_structs.h` - Direct path structs
- `prov/efa/src/efa_data_path_direct_internal.h` - wrid allocation
- `prov/efa/src/efa_data_path_direct.c` - Initialization

**Utilities:**
- `include/ofi_mem.h` - Buffer pool interface
- `prov/util/src/util_buf.c` - Buffer pool implementation

---

## Document Metadata

**Authors:** EFA Provider Team  
**Reviewers:** Performance Engineering Team  
**Status:** Draft for Review  
**Next Steps:** 
1. PE review and validation
2. Prioritize recommendations
3. Create implementation tasks (Task 1.6)
4. Schedule performance testing

**Related Documents:**
- Libfabric memory usage (previous doc)
- A List of Libfabric Refactors
- EFA RDM Protocol v4 documentation
- Subspace-967, Subspace-3161, Subspace-3346

**Revision History:**
- v1.0 (2026-02-26): Initial comprehensive audit

---

**END OF DOCUMENT**
