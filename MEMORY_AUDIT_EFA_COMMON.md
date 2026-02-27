# EFA Common (Shared) Memory Allocation Audit
**Version:** 1.0 | **Date:** 2026-02-26

## Overview

This document covers memory allocations shared between both EFA and EFA-direct fabrics. These are common components used by both the standard EFA RDM protocol and the EFA-direct data path.

## Scope

**Shared by:**
- EFA fabric (`efa`) - Full RDM protocol
- EFA-direct fabric (`efa-direct`) - Direct hardware access

**Components:**
- Base endpoint structures
- Core buffer pools (TX/RX)
- Domain/fabric infrastructure
- Memory registration
- Address vector
- Completion queues
- Device management

---

## 1. Base Endpoint Structures

### 1.1 efa_base_ep

**Location:** `prov/efa/src/efa_base_ep.h`

**Size:** ~500 bytes

**Allocation:** Embedded in `efa_rdm_ep` or `efa_ep`

**Key Fields:**
```c
struct efa_base_ep {
    struct util_ep util_ep;
    struct efa_domain *domain;
    struct efa_av *av;
    struct efa_qp *qp;
    struct fid_ep *shm_ep;
    
    // Work request arrays
    struct efa_recv_wr *efa_recv_wr_vec;
    struct efa_recv_wr *user_recv_wr_vec;
    
    // Capabilities
    uint64_t caps;
    uint64_t info_caps;
    
    // Configuration
    size_t rnr_retry;
    bool rnr_retry_enable;
    bool use_zcpy_rx;
    bool write_inline;
};
```

**Shared Allocations:**

**efa_recv_wr_vec:**
```c
// prov/efa/src/efa_base_ep.c:501
base_ep->efa_recv_wr_vec = calloc(sizeof(struct efa_recv_wr), 
                                   efa_base_ep_get_rx_pool_size(base_ep));
```
- **Size:** RX pool size × sizeof(struct efa_recv_wr)
- **Typical:** 8192 × ~64 bytes = 512 KB
- **Freed:** Line 147

**user_recv_wr_vec:**
```c
// Line 506
base_ep->user_recv_wr_vec = calloc(sizeof(struct efa_recv_wr), 
                                    efa_base_ep_get_rx_pool_size(base_ep));
```
- **Size:** 512 KB (same as above)
- **Freed:** Line 150

**Total:** ~1 MB per endpoint

### 1.2 efa_qp (Queue Pair)

**Location:** `prov/efa/src/efa_base_ep.c:239`

**Allocation:**
```c
*qp = calloc(1, sizeof(struct efa_qp));
```

**Size:** ~200 bytes

**Key Fields:**
```c
struct efa_qp {
    struct ibv_qp *ibv_qp;              // rdma-core QP
    struct efa_base_ep *base_ep;
    uint32_t qp_num;
    uint32_t qkey;
    
    // EFA-direct structures (if enabled)
    #if HAVE_EFA_DATA_PATH_DIRECT
    struct efa_data_path_direct_qp direct_qp;
    #endif
};
```

**rdma-core QP:**
```c
// Line 247, 268, 277
(*qp)->ibv_qp = ibv_create_qp_ex(...);
(*qp)->ibv_qp = efadv_create_qp_ex(...);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_qp()`

**Freed:** Lines 285, 443

---

## 2. Core Buffer Pools

### 2.1 EFA TX Packet Pool

**Location:** `prov/efa/src/rdm/efa_rdm_ep_fiops.c:179`

**Allocation:**
```c
ret = efa_rdm_ep_create_pke_pool(ep,
                                 true, /* memory registration */
                                 efa_base_ep_get_tx_pool_size(&ep->base_ep),
                                 efa_base_ep_get_tx_pool_size(&ep->base_ep),
                                 EFA_RDM_BUFPOOL_ALIGNMENT,
                                 tx_pkt_pool_base_flags,
                                 &ep->efa_tx_pkt_pool);
```

**Details:**
- **Entry Size:** 128 bytes (pke) + 8192 bytes (MTU) = 8320 bytes
- **Alignment:** 128 bytes (2 cache lines)
- **Count:** Typically 8192
- **Total:** 64 MB
- **Memory Registered:** YES (with EFA device)
- **Used by:** Both EFA and EFA-direct

**Purpose:** Send operations, RDMA read/write

### 2.2 EFA RX Packet Pool

**Location:** Line 180

**Allocation:**
```c
ret = efa_rdm_ep_create_pke_pool(ep,
                                 true, /* memory registration */
                                 efa_base_ep_get_rx_pool_size(&ep->base_ep),
                                 efa_base_ep_get_rx_pool_size(&ep->base_ep),
                                 EFA_RDM_BUFPOOL_ALIGNMENT,
                                 rx_pkt_pool_base_flags,
                                 &ep->efa_rx_pkt_pool);
```

**Details:**
- **Entry Size:** 8320 bytes
- **Count:** Typically 8192
- **Total:** 64 MB
- **Memory Registered:** YES
- **Used by:** Both EFA and EFA-direct

**Purpose:** Receive operations

**Issue:** Pre-allocated but pages not touched → page faults on first use

### 2.3 User RX Packet Pool

**Location:** Line 189

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->user_rx_pkt_pool,
                         sizeof(struct efa_rdm_pke),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         ep->base_ep.info->rx_attr->size,
                         ep->base_ep.info->rx_attr->size,
                         rx_pkt_pool_base_flags);
```

**Details:**
- **Entry Size:** 128 bytes (pke only, no wiredata)
- **Count:** Dynamic (grows on demand)
- **Memory Registered:** NO
- **Used by:** Both EFA and EFA-direct

**Purpose:** User-provided receive buffers (FI_MSG_PREFIX, zero-copy)

### 2.4 Operation Pool (ope_pool)

**Location:** Line 248

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->ope_pool,
                         sizeof(struct efa_rdm_ope),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit */
                         ep->base_ep.info->tx_attr->size + 
                         ep->base_ep.info->rx_attr->size, 0);
```

**Details:**
- **Entry Size:** ~800 bytes
- **Count:** TX size + RX size (typically 16384)
- **Total:** ~12 MB
- **Memory Registered:** NO
- **Used by:** Both EFA and EFA-direct

**Purpose:** TX and RX operation entries

### 2.5 Map Entry Pool

**Location:** Line 232

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->map_entry_pool,
                         sizeof(struct efa_rdm_rxe_map_entry),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit */
                         ep->base_ep.info->rx_attr->size, 0);
```

**Details:**
- **Entry Size:** Variable (hashmap entry)
- **Initial Count:** 0
- **Chunk Size:** RX size
- **Growth:** Dynamic
- **Used by:** Both EFA and EFA-direct

**Purpose:** RX entry hashmap for multi-request packet matching

### 2.6 Peer Map Entry Pool

**Location:** Line 269

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->peer_map_entry_pool,
                         sizeof(struct efa_conn_ep_peer_map_entry),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit */
                         EFA_RDM_EP_MIN_PEER_POOL_SIZE, 0);
```

**Details:**
- **Entry Size:** Variable (contains embedded peer struct)
- **Initial Count:** 1024 (EFA_RDM_EP_MIN_PEER_POOL_SIZE)
- **Growth:** Dynamic
- **Used by:** Both EFA and EFA-direct

**Purpose:** fi_addr → peer hashmap entries

### 2.7 Peer Reorder Buffer Pool

**Location:** Line 282

**Allocation:**
```c
ret = ofi_bufpool_create(&ep->peer_robuf_pool,
                         (sizeof(struct efa_rdm_pke*) * 
                          (roundup_power_of_two(efa_env.recvwin_size)) +
                          sizeof(struct recvwin_cirq)),
                         EFA_RDM_BUFPOOL_ALIGNMENT,
                         0, /* no limit */
                         EFA_RDM_EP_MIN_PEER_POOL_SIZE, 0);
```

**Details:**
- **Entry Size:** ~150 bytes (default recvwin_size=16)
- **Initial Count:** 1024
- **Growth:** Dynamic
- **Used by:** Both EFA and EFA-direct

**Purpose:** Per-peer reorder circular buffers

---

## 3. Domain and Fabric

### 3.1 efa_domain

**Location:** `prov/efa/src/efa_domain.c:167`

**Allocation:**
```c
efa_domain = calloc(1, sizeof(struct efa_domain));
```

**Size:** ~1 KB

**Key Fields:**
```c
struct efa_domain {
    struct util_domain util_domain;
    struct efa_fabric *fabric;
    struct efa_device *device;
    struct ibv_pd *ibv_pd;              // Protection domain
    struct ofi_mr_cache *cache;         // MR cache
    struct dlist_entry ope_longcts_send_list;
    // ... other fields
};
```

**Shared by:** All endpoints on same domain

**Freed:** Line 374

### 3.2 ibv_pd (Protection Domain)

**Allocation:**
```c
// Line 94
efa_domain->ibv_pd = ibv_alloc_pd(efa_domain->device->ibv_ctx);
```

**Managed by:** rdma-core

**Freed:** `ibv_dealloc_pd()` at domain close

### 3.3 MR Cache

**Location:** `prov/efa/src/efa_mr.c:128`

**Allocation:**
```c
*cache = (struct ofi_mr_cache *)calloc(1, sizeof(struct ofi_mr_cache));
```

**Entry Pool:**
```c
// prov/util/src/util_mr_cache.c:548
ret = ofi_bufpool_create(&cache->entry_pool,
                         sizeof(struct ofi_mr_entry) + entry_data_size,
                         0, 0, 1024, 0);
```

**Purpose:** Cache memory registrations to avoid re-registration overhead

**Freed:** Line 152

### 3.4 efa_fabric

**Location:** `prov/efa/src/efa_fabric.c:131`

**Allocation:**
```c
efa_fabric = calloc(1, sizeof(*efa_fabric));
```

**Size:** ~1 KB

**Shared by:** All domains on same fabric

**Freed:** Lines 59, 166

---

## 4. Address Vector

### 4.1 efa_av

**Location:** `prov/efa/src/efa_av.c:879`

**Allocation:**
```c
av = calloc(1, sizeof(*av));
```

**Size:** ~2 KB

**Key Components:**

**Reverse AV Entries (Hashmap):**
```c
// Lines 248, 266
cur_entry = malloc(sizeof(*cur_entry));
prv_entry = malloc(sizeof(*prv_entry));
```

**Purpose:** GID+QPN → fi_addr lookup

**Freed:** Lines 312, 322

**Connection Hashable:**
```c
// prov/efa/src/efa_conn.c:73
ep_addr_hashable = malloc(sizeof(struct efa_ep_addr_hashable));
```

**Freed:** Line 812

**AV Freed:** Lines 815, 960

---

## 5. Completion Queue

### 5.1 efa_cq

**Location:** `prov/efa/src/efa_cq.c:1124`

**Allocation:**
```c
cq = calloc(1, sizeof(*cq));
```

**Size:** ~1 KB

**Error Buffer:**
```c
// Line 1180
cq->err_buf = malloc(EFA_ERROR_MSG_BUFFER_LENGTH);
```
- **Size:** 256 bytes
- **Freed:** Line 915

**ibv_cq_ex:**
```c
// Lines 1039, 1053
ibv_cq->ibv_cq_ex = efadv_create_cq(...);
ibv_cq->ibv_cq_ex = ibv_create_cq_ex(...);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_cq()`

**Completion Channel:**
```c
// prov/efa/src/efa_cq.h:130
ibv_cq->channel = ibv_create_comp_channel(ibv_ctx);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_comp_channel()`

**CQ Freed:** Lines 917, 1219

### 5.2 efa_rdm_cq

**Location:** `prov/efa/src/rdm/efa_rdm_cq.c:1289`

**Allocation:**
```c
cq = calloc(1, sizeof(*cq));
```

**Size:** ~1 KB

**Freed:** Lines 126, 1369

---

## 6. Counter

### 6.1 efa_cntr

**Location:** `prov/efa/src/efa_cntr.c:212, 246`

**Allocation:**
```c
cntr = calloc(1, sizeof(*cntr));
```

**Size:** ~1 KB

**Freed:** Lines 132, 232, 282

---

## 7. Memory Registration

### 7.1 efa_mr

**Location:** `prov/efa/src/efa_mr.c:892, 1085`

**Allocation:**
```c
efa_mr = calloc(1, sizeof(*efa_mr));
```

**Size:** ~200 bytes

**ibv_mr:**
```c
efa_mr->ibv_mr = ibv_reg_mr(domain->ibv_pd, buf, len, access);
```

**ibv_reg_dmabuf_mr (HMEM):**
```c
// Line 475
return ibv_reg_dmabuf_mr(pd, offset, len, iova, fd, access);
```

**Managed by:** rdma-core

**Freed:** Lines 457, 907, 1132, 1142

### 7.2 Registered Memory Regions

**Per Endpoint:**
- efa_tx_pkt_pool: 64 MB
- efa_rx_pkt_pool: 64 MB
- rx_readcopy_pkt_pool: Variable (if HMEM)
- **Total:** 128+ MB

**User Buffers:**
- Registered on-demand via `fi_mr_reg()`
- Cached in MR cache

---

## 8. Device Management

### 8.1 Device-Level Allocations

**QP Table:**
```c
// prov/efa/src/efa_device.c:122
efa_device->qp_table = calloc(qp_table_size, sizeof(*efa_device->qp_table));
```
- **Freed:** Lines 160, 191

**Global Device Lists:**
```c
// Lines 253, 259
g_efa_selected_device_list = calloc(total_device_cnt, sizeof(struct efa_device));
g_efa_ibv_gid_list = calloc(total_device_cnt, sizeof(union ibv_gid));
```
- **Freed:** Lines 350, 357

### 8.2 Address Handle

**Location:** `prov/efa/src/efa_ah.c:105`

**Allocation:**
```c
efa_ah = malloc(sizeof(struct efa_ah));
```

**ibv_ah:**
```c
// Lines 115, 130
efa_ah->ibv_ah = ibv_create_ah(ibv_pd, &ibv_ah_attr);
```
- **Managed by:** rdma-core
- **Freed:** `ibv_destroy_ah()`

**Freed:** Lines 166, 185

---

## 9. String Allocations

### 9.1 Provider Info Strings

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

**Freed:** `fi_freeinfo()`

### 9.2 Device Strings

**device_version:**
```c
// prov/efa/src/efa_device.c:531
*device_version = calloc(1, EFA_ABI_VER_MAX_LEN + 1);
```
- **Freed:** Lines 509, 513

**sysfs_path:**
```c
// Lines 458, 465
sysfs_path = strndup(env, IBV_SYSFS_PATH_MAX);
sysfs_path = strdup("/sys");
```
- **Freed:** Lines 548, 552

**efa_driver:**
```c
// Line 503
*efa_driver = strdup(driver);
```
- **Freed:** Lines 597, 601

---

## 10. Shared Memory Footprint

### 10.1 Per-Endpoint Shared Components

| Component | Size | Registered |
|-----------|------|------------|
| efa_base_ep | 500 B | No |
| efa_recv_wr_vec | 512 KB | No |
| user_recv_wr_vec | 512 KB | No |
| efa_qp | 200 B | No |
| efa_tx_pkt_pool | 64 MB | Yes |
| efa_rx_pkt_pool | 64 MB | Yes |
| user_rx_pkt_pool | Variable | No |
| ope_pool | 12 MB | No |
| map_entry_pool | Variable | No |
| peer_map_entry_pool | ~1 MB | No |
| peer_robuf_pool | ~150 KB | No |
| **Total (minimum)** | **~141 MB** | **128 MB** |

### 10.2 Per-Domain Shared Components

| Component | Size | Notes |
|-----------|------|-------|
| efa_domain | 1 KB | One per domain |
| MR cache | Variable | RB-tree + entries |
| ibv_pd | - | rdma-core managed |
| **Total** | **~10 KB** | Plus MR cache |

### 10.3 Per-Fabric Shared Components

| Component | Size | Notes |
|-----------|------|-------|
| efa_fabric | 1 KB | One per fabric |
| Device lists | Variable | Global |
| **Total** | **~1 KB** | Plus devices |

---

## 11. Key Takeaways

**Shared Components:**
1. **Core Pools:** 128 MB registered memory per endpoint
2. **Base Structures:** ~1 MB per endpoint (work arrays)
3. **Domain/Fabric:** ~10 KB shared across endpoints
4. **rdma-core:** PD, QP, CQ, AH managed by rdma-core
5. **MR Cache:** Reduces registration overhead

**Both EFA and EFA-direct use:**
- Same buffer pools (TX/RX/ope)
- Same base endpoint structures
- Same domain/fabric infrastructure
- Same memory registration
- Same address vector

**Difference:**
- EFA-direct adds 192 KB per QP for direct path
- EFA adds protocol-specific pools (unexp/ooo)

**Critical Files:**
- `prov/efa/src/efa_base_ep.h` - Base endpoint
- `prov/efa/src/efa_domain.c` - Domain management
- `prov/efa/src/efa_av.c` - Address vector
- `prov/efa/src/efa_cq.c` - Completion queue
- `prov/efa/src/efa_mr.c` - Memory registration
- `prov/efa/src/efa_device.c` - Device management

---

**END OF DOCUMENT**
