# EFA-Direct Memory Allocation Audit v2
**Version:** 2.0 | **Date:** 2026-02-26

## Purpose

This document provides a detailed analysis of memory allocations in the EFA-direct fabric, focusing on buffer usage, access patterns, and critical data transfer paths. The goal is to understand:

1. **Every buffer allocation** - What it does, size, usage, alignment, and first access
2. **Buffer relationships** - Which buffers are used together
3. **Critical path analysis** - Memory access patterns in send/recv/read/write/poll operations
4. **Cache line optimization** - Whether frequently accessed fields are co-located

This analysis supports performance optimization by identifying:
- Page fault opportunities (first access timing)
- Cache line optimization opportunities (field co-location)
- Memory access patterns in hot paths
- Buffer pool sizing and alignment

---

## 1. Fabric

### 1.1 Overview

The fabric is the top-level resource representing the EFA-direct provider instance.

### 1.2 Buffer Allocations

#### 1.2.1 efa_fabric

**What it does:**
- Top-level fabric structure
- Holds provider-wide state
- Reference counted by domains

**Size:** ~1 KB (struct efa_fabric)

**Created:** `prov/efa/src/efa_fabric.c:131`
```c
efa_fabric = calloc(1, sizeof(*efa_fabric));
```

**Initialized:** `efa_fabric_open()` immediately after calloc
- Fields set: `util_fabric`, `fabric_fid`, reference count

**Freed:** `prov/efa/src/efa_fabric.c:59, 166`

**Used in:**
- `fi_fabric()` - Fabric creation
- `fi_domain()` - Domain creation (references fabric)
- `efa_fabric_close()` - Cleanup

**Common buffers used with:**
- None (top-level resource)

**Alignment:** Natural alignment (calloc default)

**First access (page allocation):**
- Immediately after calloc in `efa_fabric_open()`
- Fields initialized: `util_fabric`, `fabric_fid`, reference count

---

### 1.3 Memory Footprint Summary

**Per Fabric:**
- efa_fabric struct: ~1 KB
- **Total per Fabric:** ~1 KB

**Note:** Typically one fabric per process

---

## 2. Domain

### 2.1 Overview

The domain represents a protection domain and contains shared resources for all endpoints.

### 2.2 Buffer Allocations

#### 2.2.1 efa_domain

**What it does:**
- Protection domain container
- Holds MR cache
- Manages device context
- Shared by all endpoints

**Size:** ~1 KB (struct efa_domain)

**Created:** `prov/efa/src/efa_domain.c:167`
```c
efa_domain = calloc(1, sizeof(struct efa_domain));
```

**Initialized:** `efa_domain_open()` immediately after calloc
- Fields set: `util_domain`, `fabric`, `device`, `ibv_pd`

**Freed:** `prov/efa/src/efa_domain.c:374`

**Used in:**
- `fi_domain()` - Domain creation
- `fi_endpoint()` - Endpoint creation (references domain)
- `fi_mr_reg()` - Memory registration
- All endpoint operations (via ep->domain)

**Common buffers used with:**
- `ibv_pd` - Protection domain
- `MR cache` - Memory registration cache
- `efa_device` - Device structure

**Alignment:** Natural alignment (calloc default)

**First access (page allocation):**
- Immediately after calloc in `efa_domain_open()`
- Fields initialized: `util_domain`, `fabric`, `device`, `ibv_pd`

#### 2.2.2 ibv_pd (Protection Domain)

**What it does:**
- rdma-core protection domain
- Required for all memory registration
- Required for QP/CQ creation

**Size:** Opaque (managed by rdma-core)

**Created:** `prov/efa/src/efa_domain.c:94`
```c
efa_domain->ibv_pd = ibv_alloc_pd(efa_domain->device->ibv_ctx);
```

**Initialized:** By rdma-core immediately after allocation

**Freed:** `ibv_dealloc_pd()` at domain close

**Used in:**
- `ibv_reg_mr()` - Memory registration
- `ibv_create_qp_ex()` - QP creation
- `ibv_create_cq_ex()` - CQ creation
- `ibv_create_ah()` - Address handle creation

**Common buffers used with:**
- `efa_domain` - Parent structure
- All registered memory regions
- All QPs, CQs, AHs

**Alignment:** N/A (rdma-core managed)

**First access (page allocation):**
- Managed by rdma-core kernel driver
- Accessed immediately after allocation

#### 2.2.3 MR Cache

**What it does:**
- Caches memory registrations
- Avoids expensive re-registration
- RB-tree of registered regions

**Size:** Variable (struct ofi_mr_cache + entries)

**Created:** `prov/efa/src/efa_mr.c:128`
```c
*cache = (struct ofi_mr_cache *)calloc(1, sizeof(struct ofi_mr_cache));
```

**Initialized:** `efa_mr_cache_init()` immediately after calloc
- Fields set: `entry_pool`, RB-tree root, cache policy

**Freed:** `prov/efa/src/efa_mr.c:152`

**Entry Pool:** `prov/util/src/util_mr_cache.c:548`
```c
ret = ofi_bufpool_create(&cache->entry_pool,
                         sizeof(struct ofi_mr_entry) + entry_data_size,
                         0, 0, 1024, 0);
```

**Used in:**
- `fi_mr_reg()` - Check cache before registering
- `fi_mr_regattr()` - Same
- `fi_close(mr)` - Return to cache
- Send/recv operations - Validate MR

**Common buffers used with:**
- `efa_domain` - Parent
- `efa_mr` - MR entries
- User buffers - Registered memory

**Alignment:** Natural alignment

**First access (page allocation):**
- Cache struct: Immediately after calloc
- Entry pool: On first `ofi_bufpool_grow()`
- Entries: On first MR registration

---

### 2.3 Memory Footprint Summary

**Per Domain:**
- efa_domain struct: ~1 KB
- ibv_pd: Opaque (rdma-core managed, minimal)
- MR cache struct: ~1 KB
- MR cache entry pool: Variable (grows with registrations)
- MR cache entries: ~200 bytes × number of cached MRs
- **Total per Domain:** ~2 KB + (200 bytes × cached MR count)
- **Example (100 cached MRs):** ~22 KB

**Note:** Domain shared by all endpoints

---

## 3. Endpoint

### 3.1 Overview

The endpoint is the primary communication resource. For EFA-direct, it includes base endpoint structures plus direct data path components.

### 3.2 Buffer Allocations

#### 3.2.1 efa_rdm_ep

**What it does:**
- Main endpoint structure
- Contains all buffer pools
- Manages protocol state
- Holds QP and CQ references

**Size:** ~2 KB (struct efa_rdm_ep)

**Created:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:547`
```c
efa_rdm_ep = calloc(1, sizeof(*efa_rdm_ep));
```

**Initialized:** `efa_rdm_ep_open()` immediately after calloc
- Fields set: `base_ep`, `domain`, `mtu_size`, all buffer pools created

**Freed:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:718, 1197`

**Used in:**
- All send/recv/read/write operations
- CQ polling
- Progress engine
- Resource management

**Common buffers used with:**
- All buffer pools (tx/rx/ope)
- `efa_qp` - Queue pair
- `efa_cq` - Completion queue
- `efa_domain` - Parent domain

**Alignment:** Natural alignment (calloc default)

**First access (page allocation):**
- Immediately after calloc in `efa_rdm_ep_open()`
- Hot fields accessed first: `base_ep`, `domain`, `mtu_size`
- Cold fields: `extra_info[]`, `host_id`

#### 3.2.2 efa_qp (Queue Pair)

**What it does:**
- Queue pair structure
- Contains SQ and RQ
- Holds direct path structures (EFA-direct)

**Size:** ~200 bytes + direct path overhead

**Created:** `prov/efa/src/efa_base_ep.c:239`
```c
*qp = calloc(1, sizeof(struct efa_qp));
```

**Initialized:** `efa_base_ep_construct_qp()` immediately after calloc
- Fields set: `ibv_qp`, `qp_num`, `qkey`, `base_ep`
- Direct path initialized: `efa_data_path_direct_qp_initialize()` (EFA-direct)

**Freed:** `prov/efa/src/efa_base_ep.c:285, 443`

**Used in:**
- `efa_rdm_ope_post_send()` - Send operations
- `efa_rdm_pke_recvv()` - Receive operations
- `efa_rdm_ope_post_read()` - RDMA read
- `efa_rdm_ope_post_remote_write()` - RDMA write
- `efa_rdm_ep_poll()` - CQ polling

**Common buffers used with:**
- `efa_rdm_ep` - Parent endpoint
- `ibv_qp` - rdma-core QP
- `efa_data_path_direct_qp` - Direct path (EFA-direct only)
- `wrid` arrays - Work request IDs

**Alignment:** Natural alignment

**First access (page allocation):**
- Immediately after calloc in `efa_base_ep_construct_qp()`
- Fields initialized: `ibv_qp`, `qp_num`, `qkey`, `base_ep`

#### 3.2.3 wrid Array (Send Queue)

**What it does:**
- Maps WQE index to work request context
- Allows out-of-order completion handling
- Stores packet entry pointers

**Size:** 64 KB (8192 entries × 8 bytes)

**Created:** `prov/efa/src/efa_data_path_direct_internal.h:338`
```c
wq->wrid = malloc(wq->wqe_cnt * sizeof(*wq->wrid));
```

**Initialized:** `efa_data_path_direct_qp_initialize()` during QP initialization
- All entries set to NULL initially
- Populated on each send operation

**Freed:** `prov/efa/src/efa_data_path_direct_internal.h:345, 370, 375`

**Used in:**
- `efa_rdm_pke_sendv()` - Store pke pointer before send
- Send completion processing - Retrieve pke pointer
- Direct path send operations

**Common buffers used with:**
- `wrid_idx_pool` - Free index tracking
- `efa_rdm_pke` - Packet entries
- `efa_data_path_direct_sq` - Send queue

**Alignment:** Natural alignment (malloc default, typically 16 bytes)

**First access (page allocation):**
- On first send operation
- Index calculated: `wrid_idx_pool[wrid_idx_pool_next]`
- Value stored: `wrid[index] = (uint64_t)pkt_entry`

#### 3.2.4 wrid_idx_pool (Send Queue)

**What it does:**
- Tracks free slots in wrid array
- Handles out-of-order completions
- Pool of available indices

**Size:** 32 KB (8192 entries × 4 bytes)

**Created:** `prov/efa/src/efa_data_path_direct_internal.h:343`
```c
wq->wrid_idx_pool = malloc(wqe_cnt * sizeof(uint32_t));
```

**Initialized:** `efa_data_path_direct_qp_initialize()` during QP initialization
- All entries initialized: `wrid_idx_pool[i] = i` (sequential)
- `wrid_idx_pool_next` = 0

**Freed:** `prov/efa/src/efa_data_path_direct_internal.h:375`

**Used in:**
- Before send: Get free index from pool
- After completion: Return index to pool
- Direct path send/completion

**Common buffers used with:**
- `wrid` array - Index into this array
- `wrid_idx_pool_next` - Next free slot pointer

**Alignment:** Natural alignment (malloc default, typically 16 bytes)

**First access (page allocation):**
- During QP initialization
- All entries initialized: `wrid_idx_pool[i] = i`
- Sequential access, touches all pages

#### 3.2.5 wrid Array (Receive Queue)

**What it does:**
- Same as SQ wrid, for receive operations
- Maps RQ WQE to packet entry

**Size:** 64 KB (8192 entries × 8 bytes)

**Created:** `prov/efa/src/efa_data_path_direct_internal.h:338` (RQ instance)

**Initialized:** `efa_data_path_direct_qp_initialize()` during QP initialization
- All entries set to NULL initially
- Populated on each receive post

**Freed:** `prov/efa/src/efa_data_path_direct_internal.h:345, 370, 375`

**Used in:**
- `efa_rdm_pke_recvv()` - Store pke pointer before post
- Receive completion processing - Retrieve pke pointer

**Common buffers used with:**
- RQ `wrid_idx_pool`
- `efa_rdm_pke` - RX packet entries
- `efa_data_path_direct_rq` - Receive queue

**Alignment:** Natural alignment

**First access (page allocation):**
- On first receive post
- Similar pattern to SQ wrid

#### 3.2.6 wrid_idx_pool (Receive Queue)

**What it does:**
- Same as SQ wrid_idx_pool, for RQ

**Size:** 32 KB (8192 entries × 4 bytes)

**Created:** `prov/efa/src/efa_data_path_direct_internal.h:343` (RQ instance)

**Initialized:** `efa_data_path_direct_qp_initialize()` during QP initialization
- All entries initialized: `wrid_idx_pool[i] = i`
- `wrid_idx_pool_next` = 0

**Freed:** `prov/efa/src/efa_data_path_direct_internal.h:375`

**Used in:**
- Before recv post: Get free index
- After completion: Return index

**Common buffers used with:**
- RQ `wrid` array

**Alignment:** Natural alignment

**First access (page allocation):**
- During QP initialization
- All entries initialized sequentially

#### 3.2.7 efa_tx_pkt_pool

**What it does:**
- Pre-allocated send packet buffers
- Memory registered with EFA device
- Used for all send operations

**Size:** 64 MB (8192 entries × 8320 bytes)

**Created:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:179`
```c
ret = efa_rdm_ep_create_pke_pool(ep, true, 8192, 8192,
                                 EFA_RDM_PKE_ALIGNMENT,
                                 flags, &ep->efa_tx_pkt_pool);
```

**Initialized:** `efa_rdm_ep_open()` during endpoint creation
- Pool created with `ofi_bufpool_create()`
- Memory registered with `ibv_reg_mr()`
- **NOT touched** - pages remain unallocated

**Freed:** Endpoint close (`efa_rdm_ep_close()`)

**Used in:**
- `efa_rdm_ope_post_send()` - Allocate send packet
- `efa_rdm_pke_sendv()` - Send packet
- Send completion - Release packet

**Common buffers used with:**
- `efa_rdm_pke` - Packet entries
- `efa_rdm_ope` - Operation entries
- `wrid` array - Work request tracking

**Alignment:** 128 bytes (EFA_RDM_PKE_ALIGNMENT, 2 cache lines)

**First access (page allocation):**
- **ISSUE:** Pages allocated but not touched during pool creation
- **First real access:** On first send operation when `ofi_buf_alloc()` called
- **Causes page faults** during first sends (performance regression)

#### 3.2.8 efa_rx_pkt_pool

**What it does:**
- Pre-allocated receive packet buffers
- Memory registered with EFA device
- Posted to RQ for receives

**Size:** 64 MB (8192 entries × 8320 bytes)

**Created:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:180`

**Initialized:** `efa_rdm_ep_open()` during endpoint creation
- Pool created with `ofi_bufpool_create()`
- Memory registered with `ibv_reg_mr()`
- **NOT touched** - pages remain unallocated

**Freed:** Endpoint close (`efa_rdm_ep_close()`)

**Used in:**
- `efa_rdm_pke_recvv()` - Post receive buffers
- Receive completion - Process received data
- `efa_rdm_pke_release_rx()` - Release buffer

**Common buffers used with:**
- `efa_rdm_pke` - Packet entries
- `efa_rdm_ope` - RX operation entries
- RQ `wrid` array

**Alignment:** 128 bytes

**First access (page allocation):**
- **ISSUE:** Same as TX pool - pages not touched
- **First real access:** When posting initial receives
- **Causes page faults** during endpoint enable

#### 3.2.9 ope_pool

**What it does:**
- Operation entry pool
- Tracks TX and RX operations
- Contains protocol state

**Size:** ~12 MB (16384 entries × 800 bytes)

**Created:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:248`

**Initialized:** `efa_rdm_ep_open()` during endpoint creation
- Pool created with `ofi_bufpool_create()`
- Immediately grown with `ofi_bufpool_grow()` - touches first chunk
- Remaining entries allocated on demand

**Freed:** Endpoint close (`efa_rdm_ep_close()`)

**Used in:**
- `efa_rdm_ep_utils.c:330` - Allocate txe
- `efa_rdm_ep_utils.c:175` - Allocate rxe
- All send/recv/read/write operations
- `efa_rdm_ope_release()` - Free operation

**Common buffers used with:**
- `efa_rdm_ep` - Parent endpoint
- `efa_rdm_pke` - Packet entries
- `efa_rdm_peer` - Peer structures

**Alignment:** 128 bytes

**First access (page allocation):**
- Pool grown during EP open: `ofi_bufpool_grow()`
- Touches first chunk of entries
- Remaining entries: On first allocation

#### 3.2.10 efa_recv_wr_vec

**What it does:**
- Work request array for EFA receives
- Staging area for batch posting

**Size:** 512 KB (8192 entries × 64 bytes)

**Created:** `prov/efa/src/efa_base_ep.c:501`
```c
base_ep->efa_recv_wr_vec = calloc(sizeof(struct efa_recv_wr),
                                   efa_base_ep_get_rx_pool_size(base_ep));
```

**Initialized:** `efa_base_ep_construct()` immediately after calloc
- All entries zeroed by calloc
- Populated on each receive post operation

**Freed:** `prov/efa/src/efa_base_ep.c:147`

**Used in:**
- `efa_rdm_pke_recvv()` - Build receive work requests
- Batch receive posting

**Common buffers used with:**
- `efa_rx_pkt_pool` - Packet buffers
- `efa_qp` - Queue pair

**Alignment:** Natural alignment

**First access (page allocation):**
- On first receive post operation
- Sequential access pattern

#### 3.2.11 user_recv_wr_vec

**What it does:**
- Work request array for user-provided buffers
- Zero-copy receive support

**Size:** 512 KB (8192 entries × 64 bytes)

**Created:** `prov/efa/src/efa_base_ep.c:506`

**Initialized:** `efa_base_ep_construct()` immediately after calloc
- All entries zeroed by calloc
- Populated only if zero-copy receives used

**Freed:** `prov/efa/src/efa_base_ep.c:150`

**Used in:**
- User-provided buffer receives
- Zero-copy RX path

**Common buffers used with:**
- `user_rx_pkt_pool`
- User buffers

**Alignment:** Natural alignment

**First access (page allocation):**
- On first user buffer receive
- May never be accessed if zero-copy not used

---

### 3.3 Memory Footprint Summary

**Per Endpoint:**
- efa_rdm_ep struct: ~2 KB
- efa_qp struct: ~200 bytes
- **EFA-Direct specific:**
  - wrid array (SQ): 64 KB
  - wrid_idx_pool (SQ): 32 KB
  - wrid array (RQ): 64 KB
  - wrid_idx_pool (RQ): 32 KB
  - **Direct path subtotal:** 192 KB
- **Buffer pools:**
  - efa_tx_pkt_pool: 64 MB (registered)
  - efa_rx_pkt_pool: 64 MB (registered)
  - ope_pool: ~12 MB
  - efa_recv_wr_vec: 512 KB
  - user_recv_wr_vec: 512 KB
  - **Pools subtotal:** ~141 MB
- **Total per Endpoint (EFA-direct):** ~141.2 MB
- **Total per Endpoint (standard EFA):** ~141 MB

**Registered Memory:** 128 MB (TX + RX pools)

---

## 4. Completion Queue

### 4.1 Overview

The completion queue reports completion of send/recv/read/write operations. EFA-direct uses direct CQ access for lower latency.

### 4.2 Buffer Allocations

#### 4.2.1 efa_cq

**What it does:**
- Completion queue structure
- Wraps rdma-core CQ
- Manages completion processing

**Size:** ~1 KB (struct efa_cq)

**Created:** `prov/efa/src/efa_cq.c:1124`
```c
cq = calloc(1, sizeof(*cq));
```

**Initialized:** `efa_cq_open()` immediately after calloc
- Fields set: `util_cq`, `domain`, `ibv_cq_ex`, `err_buf`

**Freed:** `prov/efa/src/efa_cq.c:917, 1219`

**Used in:**
- `fi_cq_read()` - Read completions
- `fi_cq_readfrom()` - Read with source
- `fi_cq_readerr()` - Read errors
- All completion processing

**Common buffers used with:**
- `ibv_cq_ex` - rdma-core CQ
- `efa_data_path_direct_cq` - Direct CQ (EFA-direct)
- `err_buf` - Error message buffer

**Alignment:** Natural alignment

**First access (page allocation):**
- Immediately after calloc in `efa_cq_open()`
- Fields initialized: `util_cq`, `domain`, `ibv_cq_ex`

#### 4.2.2 ibv_cq_ex

**What it does:**
- rdma-core extended completion queue
- Hardware CQ mapping
- Provides completion entries

**Size:** Opaque (rdma-core managed)

**Created:** `prov/efa/src/efa_cq.c:1039, 1053`
```c
ibv_cq->ibv_cq_ex = efadv_create_cq(...);
// or fallback:
ibv_cq->ibv_cq_ex = ibv_create_cq_ex(...);
```

**Initialized:** By rdma-core immediately after creation
- Hardware CQ buffer mapped to user space
- CQ state initialized

**Freed:** `ibv_destroy_cq()` at CQ close

**Used in:**
- `ibv_start_poll()` - Begin polling
- `ibv_next_poll()` - Get next completion
- `ibv_end_poll()` - End polling
- Direct CQ access (EFA-direct)

**Common buffers used with:**
- `efa_cq` - Parent structure
- `efa_data_path_direct_cq` - Direct access structure
- Hardware CQ buffer (mapped)

**Alignment:** N/A (rdma-core managed)

**First access (page allocation):**
- Managed by rdma-core
- Hardware buffer mapped to user space
- Accessed on first poll

#### 4.2.3 efa_data_path_direct_cq

**What it does:**
- Direct access to hardware CQ
- Bypasses rdma-core abstraction
- Lower latency completion processing

**Size:** ~100 bytes (struct efa_data_path_direct_cq)

**Created:** Embedded in `efa_ibv_cq`, not separately allocated

**Initialized:** `efa_data_path_direct_cq_initialize()` in `prov/efa/src/efa_data_path_direct.c`
- Fields set: `buffer` (mapped), `entry_size`, `num_entries`, `phase`, `qmask`, `db` (mapped)

**Freed:** N/A (embedded structure, freed with parent)

**Used in:**
- Direct CQ polling (EFA-direct only)
- `efa_data_path_direct_poll()` - Poll completions
- Completion processing hot path

**Common buffers used with:**
- `buffer` - Hardware CQ buffer (mapped, not allocated)
- `cur_cqe` - Current completion entry pointer
- `cur_qp` - Current QP pointer
- `cur_wq` - Current work queue pointer
- `db` - Doorbell register (mapped)

**Alignment:** Natural alignment

**First access (page allocation):**
- During CQ initialization
- Fields set: `buffer`, `entry_size`, `num_entries`, `phase`, `qmask`
- Hardware buffer already mapped by rdma-core

#### 4.2.4 CQ Error Buffer

**What it does:**
- Stores error message strings
- Used for error reporting

**Size:** 256 bytes (EFA_ERROR_MSG_BUFFER_LENGTH)

**Created:** `prov/efa/src/efa_cq.c:1180`
```c
cq->err_buf = malloc(EFA_ERROR_MSG_BUFFER_LENGTH);
```

**Initialized:** Not initialized (filled on first error)

**Freed:** `prov/efa/src/efa_cq.c:915`

**Used in:**
- `fi_cq_readerr()` - Return error details
- Error completion processing

**Common buffers used with:**
- `efa_cq` - Parent structure
- Error CQ entries

**Alignment:** Natural alignment (malloc default)

**First access (page allocation):**
- On first error completion
- May never be accessed if no errors

---

### 4.3 Memory Footprint Summary

**Per Completion Queue:**
- efa_cq struct: ~1 KB
- ibv_cq_ex: Opaque (rdma-core managed, hardware mapped)
- efa_data_path_direct_cq: ~100 bytes (EFA-direct only)
- err_buf: 256 bytes
- **Total per CQ (EFA-direct):** ~1.4 KB
- **Total per CQ (standard EFA):** ~1.3 KB

**Note:** Hardware CQ buffer mapped by rdma-core (not counted)

---

## 5. Memory Registration

### 5.1 Overview

Memory registration pins user buffers and creates mappings for DMA access.

### 5.2 Buffer Allocations

#### 5.2.1 efa_mr

**What it does:**
- Memory region structure
- Wraps rdma-core MR
- Tracks registered buffer

**Size:** ~200 bytes (struct efa_mr)

**Created:** `prov/efa/src/efa_mr.c:892, 1085`
```c
efa_mr = calloc(1, sizeof(*efa_mr));
```

**Initialized:** `efa_mr_regattr()` or `efa_mr_regv()` immediately after calloc
- Fields set: `mr_fid`, `domain`, `ibv_mr`, `flags`

**Freed:** `prov/efa/src/efa_mr.c:457, 907, 1132, 1142`

**Used in:**
- `fi_mr_reg()` - Register memory
- `fi_mr_regattr()` - Register with attributes
- Send/recv operations - Validate buffers
- `fi_close(mr)` - Deregister

**Common buffers used with:**
- `ibv_mr` - rdma-core MR
- `efa_domain` - Parent domain
- User buffer - Registered memory
- MR cache - Cache entry

**Alignment:** Natural alignment

**First access (page allocation):**
- Immediately after calloc in `efa_mr_regattr()`
- Fields initialized: `mr_fid`, `domain`, `ibv_mr`

#### 5.2.2 ibv_mr

**What it does:**
- rdma-core memory region
- Kernel pinned pages
- DMA mapping

**Size:** Opaque (rdma-core managed)

**Created:** `prov/efa/src/efa_mr.c`
```c
efa_mr->ibv_mr = ibv_reg_mr(domain->ibv_pd, buf, len, access);
// or for HMEM:
ibv_mr = ibv_reg_dmabuf_mr(pd, offset, len, iova, fd, access);
```

**Initialized:** By rdma-core kernel driver immediately
- Pages pinned in kernel
- DMA mapping created

**Freed:** `ibv_dereg_mr()` at MR close

**Used in:**
- All RDMA operations requiring registered memory
- Send/recv with registered buffers
- RDMA read/write operations

**Common buffers used with:**
- `efa_mr` - Parent structure
- User buffer - Registered memory
- `ibv_pd` - Protection domain

**Alignment:** N/A (rdma-core managed)

**First access (page allocation):**
- Kernel pins pages during registration
- Immediate access by hardware

#### 5.2.3 MR Cache Entries

**What it does:**
- Cache registered memory regions
- Avoid re-registration overhead
- RB-tree lookup

**Size:** Variable (struct ofi_mr_entry + metadata)

**Created:** From `cache->entry_pool` (bufpool)

**Initialized:** On first MR registration (cache miss)
- Entry allocated from pool
- Fields set: `info`, `storage_context`, RB-tree links
- Inserted into RB-tree

**Freed:** Cache eviction or domain close

**Used in:**
- `fi_mr_reg()` - Check cache first
- `fi_close(mr)` - Return to cache
- Send/recv - Lookup cached MR

**Common buffers used with:**
- `ofi_mr_cache` - Cache structure
- `efa_mr` - MR structure
- User buffer - Registered memory

**Alignment:** Natural alignment (bufpool default)

**First access (page allocation):**
- On first MR registration (cache miss)
- Entry allocated from pool
- RB-tree insertion

---

### 5.3 Memory Footprint Summary

**Per Memory Registration:**
- efa_mr struct: ~200 bytes
- ibv_mr: Opaque (rdma-core managed, kernel pinned pages)
- **Total per MR:** ~200 bytes (user space)

**Per MR Cache Entry:**
- ofi_mr_entry + metadata: ~200 bytes
- **Total per cached entry:** ~200 bytes

**Note:** Kernel memory for pinned pages not counted (managed by rdma-core)

---

## 6. Address Vector

### 6.1 Overview

The address vector maps peer addresses to internal identifiers.

### 6.2 Buffer Allocations

#### 6.2.1 efa_av

**What it does:**
- Address vector structure
- Maps fi_addr to peer info
- Manages peer connections

**Size:** ~2 KB (struct efa_av)

**Created:** `prov/efa/src/efa_av.c:879`
```c
av = calloc(1, sizeof(*av));
```

**Initialized:** `efa_av_open()` immediately after calloc
- Fields set: `util_av`, `domain`, `type`, hash tables

**Freed:** `prov/efa/src/efa_av.c:815, 960`

**Used in:**
- `fi_av_insert()` - Add addresses
- `fi_av_remove()` - Remove addresses
- `fi_av_lookup()` - Lookup addresses
- All send/recv operations - Resolve destination

**Common buffers used with:**
- `efa_domain` - Parent domain
- Reverse AV entries - GID+QPN → fi_addr
- `efa_conn` - Connection structures
- `efa_rdm_peer` - Peer structures

**Alignment:** Natural alignment

**First access (page allocation):**
- Immediately after calloc in `efa_av_open()`
- Fields initialized: `util_av`, `domain`, `type`

#### 6.2.2 Reverse AV Entries

**What it does:**
- Reverse lookup: GID+QPN → fi_addr
- Used in receive path to identify sender
- Hash table entries

**Size:** Variable per entry (~64 bytes each)

**Created:** `prov/efa/src/efa_av.c:248, 266`
```c
cur_entry = malloc(sizeof(*cur_entry));
prv_entry = malloc(sizeof(*prv_entry));
```

**Initialized:** Immediately after malloc
- Fields set: GID, QPN, fi_addr
- Inserted into hash table

**Freed:** `prov/efa/src/efa_av.c:312, 322`

**Used in:**
- Receive completion - Identify sender
- `efa_av_reverse_lookup()` - Lookup fi_addr
- Peer identification

**Common buffers used with:**
- `efa_av` - Parent AV
- `efa_conn` - Connection info
- Received packets - Source GID+QPN

**Alignment:** Natural alignment (malloc default)

**First access (page allocation):**
- On first packet from new peer
- Hash table insertion
- Reverse lookup setup

#### 6.2.3 Connection Hashable

**What it does:**
- Hash table entry for connections
- Maps endpoint address to connection

**Size:** ~64 bytes (struct efa_ep_addr_hashable)

**Created:** `prov/efa/src/efa_conn.c:73`
```c
ep_addr_hashable = malloc(sizeof(struct efa_ep_addr_hashable));
```

**Initialized:** Immediately after malloc
- Fields set: endpoint address, connection pointer
- Inserted into hash table

**Freed:** `prov/efa/src/efa_conn.c:812`

**Used in:**
- Connection establishment
- Peer lookup
- Address resolution

**Common buffers used with:**
- `efa_av` - Parent AV
- `efa_conn` - Connection structure

**Alignment:** Natural alignment

**First access (page allocation):**
- On first communication with peer
- Hash table insertion

---

### 6.3 Memory Footprint Summary

**Per Address Vector:**
- efa_av struct: ~2 KB
- Reverse AV entries: ~64 bytes × number of peers
- Connection hashable: ~64 bytes × number of peers
- **Total per AV:** ~2 KB + (128 bytes × peer count)
- **Example (1000 peers):** ~130 KB

---

## 7. Counter

### 7.1 Overview

Counters track the number of completed operations. Not covered in detail in this EFA-direct document as they are less critical to the data path.

### 7.2 Memory Footprint Summary

**Per Counter:**
- efa_cntr struct: ~1 KB
- **Total per Counter:** ~1 KB

---

## 7. Critical Path Analysis

### 7.1 Overview

This section analyzes memory access patterns in the data transfer hot paths: send, receive, RDMA read, RDMA write, and CQ polling.

### 7.2 Send Path

**Entry Point:** `fi_send()` → `efa_rdm_ope_post_send()`

**Buffers Accessed (in order):**

1. **efa_rdm_ep** (cache line 0)
   - `base_ep.qp` - Get queue pair
   - `efa_outstanding_tx_ops` - Check capacity
   - `ope_pool` - Allocate operation

2. **efa_rdm_ope** (allocated from ope_pool)
   - `type` = EFA_RDM_TXE
   - `ep` - Back pointer
   - `peer` - Destination peer
   - `state` = EFA_RDM_TXE_REQ
   - `op` - Operation type
   - `total_len` - Message length
   - `iov[]` - User buffer IOVs
   - `desc[]` - Memory descriptors

3. **efa_rdm_pke** (allocated from efa_tx_pkt_pool)
   - `ep` - Endpoint pointer
   - `ope` - Operation pointer
   - `peer` - Peer pointer
   - `pkt_size` - Packet size
   - `mr` - Memory registration
   - `flags` = EFA_RDM_PKE_IN_USE
   - `alloc_type` = EFA_RDM_PKE_FROM_EFA_TX_POOL
   - `gen` - Generation counter
   - `wiredata[]` - Packet buffer

4. **efa_qp** (from ep->base_ep.qp)
   - `ibv_qp` - rdma-core QP
   - `qp_num` - QP number
   - `qkey` - QP key

5. **efa_data_path_direct_sq** (EFA-direct only)
   - `wq.wrid_idx_pool` - Get free index
   - `wq.wrid_idx_pool_next` - Next free slot
   - `wq.wrid[index]` - Store pke pointer
   - `wq.wqe_posted` - Increment posted count
   - `wq.pc` - Producer counter
   - `num_wqe_pending` - Increment pending
   - `wq.db` - Doorbell register (if batch full)

6. **efa_rdm_peer** (from ope->peer)
   - `efa_outstanding_tx_ops` - Increment
   - `next_msg_id` - Assign message ID
   - `flags` - Check handshake status

**Cache Line Analysis:**

**efa_rdm_ep hot fields (should be in first 64 bytes):**
- ✅ `base_ep` (offset 0) - GOOD
- ❌ `efa_outstanding_tx_ops` (offset ~1500) - BAD, far from start
- ✅ `ope_pool` (offset ~200) - OK

**efa_rdm_ope hot fields (should be in first 64 bytes):**
- ✅ `type` (offset 0) - GOOD
- ✅ `ep` (offset 8) - GOOD
- ✅ `peer` (offset 16) - GOOD
- ❌ `state` (offset ~100) - BAD, should be earlier
- ❌ `total_len` (offset ~120) - BAD, should be earlier

**efa_rdm_pke hot fields (first 64 bytes):**
- ✅ `entry` (offset 0) - GOOD
- ✅ `ep` (offset 16) - GOOD
- ✅ `ope` (offset 24) - GOOD
- ✅ `pkt_size` (offset 32) - GOOD
- ✅ `mr` (offset 40) - GOOD
- ✅ `peer` (offset 48) - GOOD
- ✅ `alloc_type` (offset 56) - GOOD
- ✅ `flags` (offset 60) - GOOD
**Result:** pke struct is WELL OPTIMIZED for send path

**efa_data_path_direct_wq hot fields:**
- ✅ `wrid` (offset 0) - GOOD
- ✅ `wrid_idx_pool` (offset 8) - GOOD
- ✅ `wqe_posted` (offset 24) - GOOD
- ✅ `wrid_idx_pool_next` (offset 36) - GOOD
- ✅ `pc` (offset 38) - GOOD
- ✅ `db` (offset 48) - GOOD
**Result:** Direct path struct is WELL OPTIMIZED

**Memory Access Pattern:**
- Sequential: ep → ope → pke → qp → wq
- No false sharing (different cache lines)
- **Issue:** ope and ep have hot fields scattered

### 7.3 Receive Path

**Entry Point:** Receive completion → `efa_rdm_ep_poll()`

**Buffers Accessed (in order):**

1. **efa_cq** (from fi_cq_read)
   - `ibv_cq_ex` - rdma-core CQ
   - `util_cq` - Utility CQ

2. **efa_data_path_direct_cq** (EFA-direct only)
   - `buffer` - Hardware CQ buffer
   - `cur_cqe` - Current completion entry
   - `phase` - Phase bit
   - `consumed_cnt` - Consumed count
   - `cc` - Consumer counter
   - `db` - Doorbell register

3. **efa_data_path_direct_rq** (from cur_qp)
   - `wq.wrid[index]` - Get pke pointer
   - `wq.wqe_completed` - Increment completed
   - `wq.wrid_idx_pool[next]` - Return index
   - `wq.wrid_idx_pool_next` - Update next

4. **efa_rdm_pke** (from wrid)
   - `ep` - Endpoint pointer
   - `ope` - Operation pointer (may be NULL)
   - `peer` - Peer pointer
   - `pkt_size` - Received size
   - `flags` - Check IN_USE
   - `alloc_type` - Check pool type
   - `wiredata[]` - Received data

5. **efa_rdm_ope** (if matched receive)
   - `type` = EFA_RDM_RXE
   - `state` - Update state
   - `bytes_received` - Update counter
   - `iov[]` - Destination buffers
   - `cq_entry` - Prepare completion

6. **efa_rdm_ep** (for reposting)
   - `efa_rx_pkts_posted` - Decrement
   - `efa_rx_pkts_to_post` - Increment
   - `efa_rx_pkt_pool` - Allocate new pke

**Cache Line Analysis:**

**efa_data_path_direct_cq hot fields (first 64 bytes):**
- ✅ `buffer` (offset 0) - GOOD
- ✅ `entry_size` (offset 8) - GOOD
- ✅ `num_entries` (offset 12) - GOOD
- ✅ `cur_cqe` (offset 16) - GOOD
- ✅ `cur_qp` (offset 24) - GOOD
- ✅ `cur_wq` (offset 32) - GOOD
- ✅ `phase` (offset 40) - GOOD
- ✅ `qmask` (offset 44) - GOOD
- ✅ `consumed_cnt` (offset 48) - GOOD
- ✅ `db` (offset 56) - GOOD
**Result:** Direct CQ struct is PERFECTLY OPTIMIZED

**efa_rdm_pke receive hot fields:**
- ✅ All in first cache line (same as send)
- ✅ `wiredata` immediately follows struct

**Memory Access Pattern:**
- Sequential: cq → direct_cq → wq → pke → ope → ep
- CQ polling is cache-friendly
- **Issue:** ep counters far from start

### 7.4 RDMA Read Path

**Entry Point:** `fi_read()` → `efa_rdm_ope_post_read()`

**Buffers Accessed (in order):**

1. **efa_rdm_ep**
   - `base_ep.qp` - Get queue pair
   - `efa_outstanding_tx_ops` - Check capacity
   - `ope_pool` - Allocate operation

2. **efa_rdm_ope**
   - `type` = EFA_RDM_TXE
   - `op` = ofi_op_read_req
   - `peer` - Target peer
   - `rma_iov[]` - Remote address/key
   - `iov[]` - Local buffer
   - `desc[]` - Local MR
   - `bytes_read_total_len` - Total length
   - `bytes_read_submitted` - Track progress

3. **efa_rdm_pke** (for read context)
   - `ep`, `ope`, `peer` - Pointers
   - `flags` = EFA_RDM_PKE_LOCAL_READ
   - `mr` - Local MR

4. **efa_qp**
   - `ibv_qp` - Post read WR

5. **efa_data_path_direct_sq** (EFA-direct)
   - Same as send path
   - `wq.wrid[index]` - Store pke

6. **efa_mr** (local buffer)
   - `ibv_mr` - Get lkey
   - `mr_fid.key` - Local key

**Cache Line Analysis:**

**efa_rdm_ope read-specific fields:**
- ❌ `rma_iov[]` (offset ~400) - FAR from start
- ❌ `bytes_read_total_len` (offset ~700) - FAR from start
- ❌ `bytes_read_submitted` (offset ~708) - FAR from start
**Result:** Read fields NOT co-located, scattered across struct

**Memory Access Pattern:**
- Similar to send path
- Additional MR lookup
- **Issue:** Read-specific fields far apart

### 7.5 RDMA Write Path

**Entry Point:** `fi_write()` → `efa_rdm_ope_post_remote_write()`

**Buffers Accessed (in order):**

1. **efa_rdm_ep**
   - Same as read path

2. **efa_rdm_ope**
   - `type` = EFA_RDM_TXE
   - `op` = ofi_op_write
   - `peer` - Target peer
   - `rma_iov[]` - Remote address/key
   - `iov[]` - Local buffer
   - `desc[]` - Local MR
   - `bytes_write_total_len` - Total length
   - `bytes_write_submitted` - Track progress

3. **efa_rdm_pke** (for write context)
   - Similar to read

4. **efa_qp**
   - `ibv_qp` - Post write WR

5. **efa_data_path_direct_sq** (EFA-direct)
   - Same as send/read

**Cache Line Analysis:**

**efa_rdm_ope write-specific fields:**
- ❌ `rma_iov[]` (offset ~400) - FAR from start
- ❌ `bytes_write_total_len` (offset ~750) - FAR from start
- ❌ `bytes_write_submitted` (offset ~758) - FAR from start
**Result:** Write fields NOT co-located, scattered across struct

**Memory Access Pattern:**
- Similar to read path
- **Issue:** Write-specific fields far apart

### 7.6 CQ Polling Path

**Entry Point:** `fi_cq_read()` → `efa_cq_read_direct()`

**Buffers Accessed (in order):**

1. **efa_cq**
   - `ibv_cq_ex` - Get CQ

2. **efa_data_path_direct_cq** (EFA-direct hot path)
   - `buffer` - Hardware CQ buffer
   - `cur_cqe` - Current entry pointer
   - `phase` - Check phase bit
   - `entry_size` - Entry size
   - `consumed_cnt` - Increment
   - `cc` - Consumer counter
   - `qmask` - Queue mask
   - `db` - Update doorbell (if needed)

3. **efa_io_cdesc_common** (completion entry in buffer)
   - `status` - Check completion status
   - `qp_num` - Get QP number
   - `wrid` - Get work request ID

4. **efa_qp** (lookup by qp_num)
   - `direct_qp.sq` or `direct_qp.rq` - Get WQ

5. **efa_data_path_direct_wq**
   - `wrid[wrid]` - Get context pointer
   - `wqe_completed` - Increment
   - `wrid_idx_pool[next]` - Return index
   - `wrid_idx_pool_next` - Update

6. **efa_rdm_pke** (from wrid)
   - `ope` - Get operation
   - `flags` - Check flags
   - Release or process

7. **efa_rdm_ope** (if operation)
   - `efa_outstanding_tx_ops` - Decrement
   - `bytes_sent` or `bytes_received` - Update
   - `cq_entry` - Prepare user completion

**Cache Line Analysis:**

**CQ polling hot path (efa_data_path_direct_cq):**
- ✅ ALL hot fields in first 64 bytes
- ✅ Sequential access pattern
- ✅ No cache line bouncing
**Result:** OPTIMAL for polling

**Memory Access Pattern:**
- Very cache-friendly
- Sequential buffer access
- Minimal pointer chasing
- **Best optimized path in EFA-direct**

---

## 8. Critical Path Summary

### 8.1 Well-Optimized Structures

**efa_rdm_pke (128 bytes, 2 cache lines):**
- ✅ All hot fields in first 64 bytes
- ✅ Used in all paths
- ✅ Excellent cache utilization

**efa_data_path_direct_cq (~100 bytes):**
- ✅ All hot fields in first 64 bytes
- ✅ Polling path perfectly optimized
- ✅ Sequential access pattern

**efa_data_path_direct_wq (~100 bytes):**
- ✅ Hot fields well-grouped
- ✅ Good for send/recv paths

### 8.2 Poorly-Optimized Structures

**efa_rdm_ope (800+ bytes, 13+ cache lines):**
- ❌ Hot fields scattered across multiple cache lines
- ❌ `state` at offset ~100 (should be in first 64)
- ❌ `total_len` at offset ~120 (should be in first 64)
- ❌ `efa_outstanding_tx_ops` at offset ~600 (accessed frequently)
- ❌ Read fields at offset ~700 (not co-located)
- ❌ Write fields at offset ~750 (not co-located)
- ❌ Byte counters scattered throughout

**Recommendation:** Reorder ope fields:
```c
struct efa_rdm_ope {
    // Cache line 0 (0-63): HOT fields
    enum efa_rdm_ope_type type;        // 0
    struct efa_rdm_ep *ep;             // 8
    struct efa_rdm_peer *peer;         // 16
    enum efa_rdm_ope_state state;      // 24
    uint32_t op;                       // 28
    uint64_t total_len;                // 32
    size_t efa_outstanding_tx_ops;     // 40
    uint32_t internal_flags;           // 48
    uint32_t msg_id;                   // 52
    uint64_t fi_flags;                 // 56
    
    // Cache line 1 (64-127): Byte counters
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t bytes_acked;
    uint64_t bytes_copied;
    // ... other counters
    
    // Cache line 2+: Cold fields
    // atomic_ex, iov arrays, lists, etc.
};
```

**efa_rdm_ep (2KB+):**
- ❌ `efa_outstanding_tx_ops` at offset ~1500 (accessed in every send)
- ❌ `efa_rx_pkts_posted` at offset ~1600 (accessed in every recv)
- ❌ Hot counters far from start

**Recommendation:** Move counters to start of struct

### 8.3 Page Fault Issues

**efa_tx_pkt_pool and efa_rx_pkt_pool:**
- ❌ 128 MB allocated but pages not touched
- ❌ First access causes page faults during operations
- ❌ Performance regression on first sends/receives

**Recommendation:** Touch pages during pool creation:
```c
// After ofi_bufpool_create:
for (i = 0; i < pool_size; i++) {
    char *buf = ofi_buf_alloc(pool);
    buf[0] = 0;  // Touch first byte of each entry
    ofi_buf_free(buf);
}
```

### 8.4 Cache Line Optimization Opportunities

**High Impact:**
1. Reorder `efa_rdm_ope` fields (affects all operations)
2. Move `efa_rdm_ep` counters to start (affects all operations)
3. Touch pre-allocated pool pages (eliminates page faults)

**Medium Impact:**
4. Group read-specific fields in `efa_rdm_ope`
5. Group write-specific fields in `efa_rdm_ope`

**Low Impact:**
6. Already optimized: `efa_rdm_pke`, `efa_data_path_direct_cq`, `efa_data_path_direct_wq`

---

## 9. Total Memory Footprint

### 9.1 Per-Process Breakdown

**Fabric (1):**
- 1 KB

**Domain (1):**
- 2 KB + (200 bytes × cached MRs)
- Example with 100 cached MRs: 22 KB

**Endpoint (1):**
- EFA-direct: 141.2 MB
- Standard EFA: 141 MB
- Registered memory: 128 MB

**Completion Queue (1):**
- EFA-direct: 1.4 KB
- Standard EFA: 1.3 KB

**Address Vector (1):**
- 2 KB + (128 bytes × peers)
- Example with 1000 peers: 130 KB

**Memory Registrations (variable):**
- 200 bytes per MR

**Counter (optional):**
- 1 KB each

### 9.2 Typical Configuration

**Single endpoint, 1000 peers, 100 cached MRs:**
- Fabric: 1 KB
- Domain: 22 KB
- Endpoint: 141.2 MB (EFA-direct)
- CQ: 1.4 KB
- AV: 130 KB
- **Total:** ~141.4 MB

**EFA-direct overhead vs standard EFA:** +192 KB per endpoint

### 9.3 Scaling

**Per additional endpoint:**
- +141.2 MB (EFA-direct)
- +141 MB (standard EFA)

**Per additional peer:**
- +128 bytes (AV entries)

**Per additional cached MR:**
- +200 bytes

---

**END OF DOCUMENT**
