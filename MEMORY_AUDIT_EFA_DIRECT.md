# EFA-Direct Memory Allocation Audit
**Version:** 1.0 | **Date:** 2026-02-26

## Overview

EFA-direct fabric provides direct hardware access with minimal protocol overhead. This document covers memory allocations specific to the EFA-direct data path.

## Key Characteristics

- **Fabric Name:** `efa-direct`
- **Endpoint Type:** RDM (Reliable Datagram)
- **Approach:** Direct hardware mapping, minimal abstraction
- **Memory Overhead:** +192 KB per QP vs standard EFA
- **Performance:** Lower latency, reduced CPU overhead

---

## 1. Direct Data Path Structures

### 1.1 efa_data_path_direct_qp

**Location:** `prov/efa/src/efa_data_path_direct_structs.h`

**Size:** ~200 bytes (struct overhead)

**Components:**
```c
struct efa_data_path_direct_qp {
    struct efa_data_path_direct_sq sq;  // Send queue
    struct efa_data_path_direct_rq rq;  // Receive queue
};
```

**Lifecycle:**
- **Created:** During QP initialization
- **Initialized:** `efa_data_path_direct_qp_initialize()`
- **Freed:** `efa_data_path_direct_qp_finalize()`

---

## 2. Work Queue Structures

### 2.1 efa_data_path_direct_wq

**Size:** ~100 bytes (struct overhead)

**Key Fields:**
```c
struct efa_data_path_direct_wq {
    uint64_t *wrid;              // Work request ID array
    uint32_t *wrid_idx_pool;     // Free index pool
    uint32_t wqe_cnt;            // Work queue entry count
    uint32_t wqe_size;           // Entry size
    uint32_t wqe_posted;         // Posted count
    uint32_t wqe_completed;      // Completed count
    uint16_t pc;                 // Producer counter
    uint16_t desc_mask;          // Descriptor mask
    uint16_t wrid_idx_pool_next; // Next free index
    int phase;                   // Phase bit
    struct ofi_genlock *wqlock;  // Lock
    uint32_t *db;                // Doorbell register (mapped)
    uint32_t max_batch;          // Max batch size
};
```

---

## 3. Memory Allocations

### 3.1 Work Request ID Array (wrid)

**Location:** `prov/efa/src/efa_data_path_direct_internal.h:338`

**Allocation:**
```c
wq->wrid = malloc(wq->wqe_cnt * sizeof(*wq->wrid));
```

**Details:**
- **Size per Entry:** 8 bytes (uint64_t)
- **Typical Count:** 8192 entries
- **Total per WQ:** 64 KB
- **Per QP:** 128 KB (SQ + RQ)

**Freed:** Line 345, 370, 375

### 3.2 Work Request Index Pool (wrid_idx_pool)

**Location:** Line 343

**Allocation:**
```c
wq->wrid_idx_pool = malloc(wqe_cnt * sizeof(uint32_t));
```

**Details:**
- **Size per Entry:** 4 bytes (uint32_t)
- **Typical Count:** 8192 entries
- **Total per WQ:** 32 KB
- **Per QP:** 64 KB (SQ + RQ)

**Purpose:** Tracks free slots in wrid array for out-of-order completions

**Freed:** Line 375

### 3.3 Total Direct Path Overhead

**Per Queue Pair:**
- SQ wrid: 64 KB
- SQ wrid_idx_pool: 32 KB
- RQ wrid: 64 KB
- RQ wrid_idx_pool: 32 KB
- **Total: 192 KB**

---

## 4. Send Queue (SQ)

### 4.1 efa_data_path_direct_sq

**Size:** ~120 bytes

**Key Fields:**
```c
struct efa_data_path_direct_sq {
    struct efa_data_path_direct_wq wq;  // Work queue
    uint8_t *desc;                      // HW send queue buffer (mapped)
    uint32_t num_wqe_pending;           // Pending WQEs (batching)
};
```

**desc Buffer:**
- **Allocated by:** rdma-core (hardware mapped)
- **Not allocated by provider**
- **Size:** wqe_cnt × wqe_size (hardware dependent)

**Batching:**
- `num_wqe_pending` tracks WQEs copied to hardware but doorbell not rung
- Reduces MMIO writes
- Tunable via `max_batch`

---

## 5. Receive Queue (RQ)

### 5.1 efa_data_path_direct_rq

**Size:** ~110 bytes

**Key Fields:**
```c
struct efa_data_path_direct_rq {
    struct efa_data_path_direct_wq wq;  // Work queue
    uint8_t *buf;                       // HW receive queue buffer (mapped)
};
```

**buf Buffer:**
- **Allocated by:** rdma-core (hardware mapped)
- **Not allocated by provider**
- **Size:** wqe_cnt × wqe_size (hardware dependent)

---

## 6. Completion Queue (CQ)

### 6.1 efa_data_path_direct_cq

**Location:** `prov/efa/src/efa_data_path_direct_structs.h`

**Size:** ~100 bytes

**Key Fields:**
```c
struct efa_data_path_direct_cq {
    uint8_t *buffer;                    // HW CQ buffer (mapped)
    uint32_t entry_size;                // CQ entry size
    uint32_t num_entries;               // Total entries
    struct efa_io_cdesc_common *cur_cqe; // Current CQE
    struct efa_qp *cur_qp;              // Current QP
    struct efa_data_path_direct_wq *cur_wq; // Current WQ
    int phase;                          // Phase bit
    int qmask;                          // Queue mask
    uint16_t consumed_cnt;              // Consumed count
    uint32_t *db;                       // Doorbell (mapped)
    uint16_t cc;                        // Consumer counter
    uint8_t cmd_sn;                     // Command sequence number
};
```

**buffer:**
- **Allocated by:** rdma-core (hardware mapped)
- **Not allocated by provider**
- **No additional memory allocations**

---

## 7. Initialization and Cleanup

### 7.1 QP Initialization

**Function:** `efa_data_path_direct_qp_initialize()`
**Location:** `prov/efa/src/efa_data_path_direct.c`

**Allocates:**
1. SQ wrid array (64 KB)
2. SQ wrid_idx_pool (32 KB)
3. RQ wrid array (64 KB)
4. RQ wrid_idx_pool (32 KB)

**Total:** 192 KB per QP

### 7.2 CQ Initialization

**Function:** `efa_data_path_direct_cq_initialize()`

**Allocates:** Nothing (uses hardware-mapped buffers)

### 7.3 Cleanup

**Function:** `efa_data_path_direct_qp_finalize()`

**Frees:**
1. wq->wrid (both SQ and RQ)
2. wq->wrid_idx_pool (both SQ and RQ)

**Note:** Hardware buffers freed by rdma-core

---

## 8. Memory Comparison

### 8.1 EFA-Direct vs Standard EFA

**Standard EFA (per endpoint):**
- Buffer pools: ~142 MB
- Endpoint struct: ~2 KB
- Work arrays: ~200 KB
- **Total:** ~142 MB

**EFA-Direct (per endpoint):**
- Buffer pools: ~142 MB (same)
- Endpoint struct: ~2 KB (same)
- Work arrays: ~200 KB (same)
- Direct path arrays: ~192 KB (additional)
- **Total:** ~142.2 MB

**Difference:** +192 KB per endpoint (+0.13%)

### 8.2 Trade-offs

**Memory:**
- Minimal increase (+192 KB per QP)
- Hardware buffers managed by rdma-core

**Performance:**
- Direct hardware access (no abstraction)
- Reduced completion processing overhead
- Lower latency
- Fewer CPU cycles per operation

**Complexity:**
- Simpler code path
- Less protocol state
- Direct mapping to hardware

---

## 9. Optimization Opportunities

### 9.1 Embed wrid Arrays

**Current:** Separate malloc allocations
**Proposal:** Embed in QP structure or use bufpool
**Benefit:** Better cache locality, reduced allocation overhead
**Effort:** Low (1 week)

### 9.2 Tune Batching

**Current:** `max_batch` set at initialization
**Proposal:** Dynamic tuning based on workload
**Benefit:** Optimal doorbell ring frequency
**Effort:** Low (tuning only)

### 9.3 Reduce wrid_idx_pool Size

**Current:** Same size as wrid array
**Analysis:** May not need full-size pool for typical workloads
**Proposal:** Analyze actual usage patterns
**Benefit:** Potential 32 KB savings per WQ
**Effort:** Medium (requires profiling)

---

## 10. Key Takeaways

**For EFA-Direct:**
1. **Minimal Memory Overhead:** Only +192 KB per QP
2. **No Protocol State:** Direct hardware mapping
3. **Hardware-Managed Buffers:** CQ/SQ/RQ buffers mapped from hardware
4. **Simple Lifecycle:** Allocate wrid arrays, map hardware, done
5. **Performance Focus:** Trade minimal memory for lower latency

**Critical Files:**
- `prov/efa/src/efa_data_path_direct_structs.h` - Structure definitions
- `prov/efa/src/efa_data_path_direct_internal.h` - Allocation logic
- `prov/efa/src/efa_data_path_direct.c` - Initialization/cleanup
- `prov/efa/src/efa_data_path_direct_entry.h` - Entry points

---

**END OF DOCUMENT**
