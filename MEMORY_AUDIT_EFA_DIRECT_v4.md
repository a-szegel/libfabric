# EFA-Direct Memory Allocation Audit (v4)
## Per-Path Cache Line Optimization

**Document Version:** 4.0  
**Date:** 2026-02-27  
**Focus:** Independent cache line optimization per critical path

---

## Executive Summary

### Approach Change from v3

**v3 Approach:**
- Optimize for ALL paths simultaneously
- Pack all hot fields into single cache line
- Result: One-size-fits-all optimization

**v4 Approach:**
- Optimize EACH path independently
- Allow cache misses BETWEEN paths
- Minimize cache misses WITHIN each path
- Result: Path-specific optimizations

### Key Insight

Different paths access different subsets of fields:
- **Send path:** qp, av, domain, lock, tx_msg_flags
- **Recv path:** qp, lock, efa_recv_wr_vec, recv_wr_index, rx_msg_flags
- **RMA write path:** qp, av, domain, lock
- **RMA read path:** qp, av, domain, lock
- **CQ poll path:** qp_table, base_ep, tx_cntr, rx_cntr
- **Counter path:** tx_cntr OR rx_cntr (separate)

**Optimization Goal:** Each path should access ≤2 cache lines

---

## 1. Send Path Cache Line Analysis

### 1.1 Fields Accessed (In Order)

```
Access 1:  base_ep->qp                          (efa_base_ep + 288)
Access 2:  base_ep->av                          (efa_base_ep + 296)
Access 3:  base_ep->info->tx_attr->iov_limit    (cold - validation)
Access 4:  base_ep->info->ep_attr->msg_prefix   (cold - validation)
Access 5:  base_ep->util_ep.lock                (efa_base_ep + 256)
Access 6:  base_ep->domain->device->inline_size (cold - decision)
Access 7:  base_ep->util_ep.tx_msg_flags        (efa_base_ep + 144)
Access 8:  msg->desc[i]->ibv_mr->lkey           (external)
Access 9:  conn->ah                             (efa_conn + 0)
Access 10: conn->ep_addr                        (efa_conn + 8)
```

### 1.2 Current Cache Line Access

**efa_base_ep:**
- Line 2 (128-191): tx_msg_flags at byte 144
- Line 4 (256-319): lock at byte 256, qp at byte 288, av at byte 296

**efa_conn:**
- Line 0 (0-63): ah at byte 0, ep_addr at byte 8

**Total: 3 cache lines (efa_base_ep lines 2, 4 + efa_conn line 0)**

### 1.3 Optimized Layout for Send Path

**Goal: 2 cache lines max**

**Option A: Pack send fields together**
```c
// Cache line 0 (send-optimized)
struct efa_qp *qp;                    // +0x00
struct efa_av *av;                    // +0x08
struct efa_domain *domain;            // +0x10
struct ofi_genlock lock;              // +0x18
uint64_t tx_msg_flags;                // +0x20
// 40 bytes used, 24 bytes free
```

**Result: 1 cache line for efa_base_ep + 1 for efa_conn = 2 total** ✓

---

## 2. Recv Path Cache Line Analysis

### 2.1 Fields Accessed (In Order)

```
Access 1:  base_ep->qp                          (efa_base_ep + 288)
Access 2:  base_ep->util_ep.lock                (efa_base_ep + 256)
Access 3:  base_ep->recv_wr_index               (efa_base_ep + 368)
Access 4:  base_ep->info->rx_attr->size         (cold - validation)
Access 5:  base_ep->efa_recv_wr_vec[wr_index]   (efa_base_ep + 360)
Access 6:  base_ep->info->rx_attr->iov_limit    (cold - validation)
Access 7:  base_ep->util_ep.rx_msg_flags        (efa_base_ep + 152)
Access 8:  msg->desc[i]->ibv_mr->lkey           (external)
Access 9:  base_ep->recv_wr_index++             (efa_base_ep + 368)
```

### 2.2 Current Cache Line Access

**efa_base_ep:**
- Line 2 (128-191): rx_msg_flags at byte 152
- Line 4 (256-319): lock at byte 256, qp at byte 288
- Line 5 (320-383): efa_recv_wr_vec at byte 360, recv_wr_index at byte 368

**Total: 3 cache lines**

### 2.3 Optimized Layout for Recv Path

**Goal: 2 cache lines max**

**Option A: Pack recv fields together**
```c
// Cache line 1 (recv-optimized)
struct efa_qp *qp;                    // +0x40
struct ofi_genlock lock;              // +0x48
struct efa_recv_wr *efa_recv_wr_vec;  // +0x50
size_t recv_wr_index;                 // +0x58
uint64_t rx_msg_flags;                // +0x60
// 40 bytes used, 24 bytes free
```

**Result: 1 cache line for recv fields** ✓

---

## 3. RMA Write Path Cache Line Analysis

### 3.1 Fields Accessed (In Order)

```
Access 1:  base_ep->util_ep.lock                (efa_base_ep + 256)
Access 2:  base_ep->av                          (efa_base_ep + 296)
Access 3:  base_ep->domain                      (efa_base_ep + 280)
Access 4:  base_ep->qp                          (efa_base_ep + 288)
Access 5:  msg->desc[i]->ibv_mr->lkey           (external)
Access 6:  conn->ah                             (efa_conn + 0)
Access 7:  conn->ep_addr                        (efa_conn + 8)
```

### 3.2 Current Cache Line Access

**efa_base_ep:**
- Line 4 (256-319): lock at 256, domain at 280, qp at 288, av at 296

**efa_conn:**
- Line 0 (0-63): ah at 0, ep_addr at 8

**Total: 2 cache lines** ✓ (already optimal)

---

## 4. RMA Read Path Cache Line Analysis

### 4.1 Fields Accessed (In Order)

```
Access 1:  base_ep->domain->info->tx_attr       (cold - validation)
Access 2:  base_ep->domain->device->max_rdma    (cold - validation)
Access 3:  base_ep->util_ep.lock                (efa_base_ep + 256)
Access 4:  base_ep->av                          (efa_base_ep + 296)
Access 5:  base_ep->qp                          (efa_base_ep + 288)
Access 6:  msg->desc[i]->ibv_mr->lkey           (external)
Access 7:  conn->ah                             (efa_conn + 0)
Access 8:  conn->ep_addr                        (efa_conn + 8)
```

### 4.2 Current Cache Line Access

**efa_base_ep:**
- Line 4 (256-319): lock at 256, qp at 288, av at 296

**efa_conn:**
- Line 0 (0-63): ah at 0, ep_addr at 8

**Total: 2 cache lines** ✓ (already optimal)

---

## 5. CQ Poll Path Cache Line Analysis

### 5.1 Fields Accessed (In Order)

```
Access 1:  efa_domain->device->qp_table         (domain structure)
Access 2:  efa_domain->device->qp_table_sz_m1   (domain structure)
Access 3:  qp_table[qp_num]->base_ep            (qp_table entry)
Access 4:  base_ep->util_ep.cntrs[0]            (efa_base_ep + 160) - tx_cntr
Access 5:  base_ep->util_ep.cntrs[1]            (efa_base_ep + 168) - rx_cntr
```

### 5.2 Current Cache Line Access

**efa_domain:**
- Line ? (need to find device offset)

**qp_table:**
- Random access (1 cache line per QP lookup)

**efa_base_ep:**
- Line 2 (128-191): cntrs[0-1] at bytes 160-168

**Total: 3 cache lines** (domain + qp_table + base_ep)

### 5.3 Optimized Layout for CQ Poll Path

**Goal: Minimize base_ep access**

**Option A: Pack counters with QP**
```c
struct efa_qp {
    struct efa_base_ep *base_ep;          // +0x00
    struct util_cntr *tx_cntr;            // +0x08 (cached from base_ep)
    struct util_cntr *rx_cntr;            // +0x10 (cached from base_ep)
    struct ibv_qp *ibv_qp;                // +0x18
    // ...
};
```

**Result: 2 cache lines** (domain + qp_table) ✓

---

## 6. Counter Path Cache Line Analysis

### 6.1 TX Counter Path

```
Access 1:  base_ep->util_ep.cntrs[0]            (efa_base_ep + 160) - tx_cntr
Access 2:  tx_cntr->cnt                         (util_cntr structure)
```

### 6.2 RX Counter Path

```
Access 1:  base_ep->util_ep.cntrs[1]            (efa_base_ep + 168) - rx_cntr
Access 2:  rx_cntr->cnt                         (util_cntr structure)
```

### 6.3 Current Cache Line Access

**efa_base_ep:**
- Line 2 (128-191): cntrs[0] at 160, cntrs[1] at 168

**util_cntr:**
- Line 0: cnt field (atomic counter)

**Total: 2 cache lines per counter path**

### 6.4 Optimization

**Problem:** TX and RX counters share cache line → false sharing

**Solution:** Separate to different cache lines

```c
// Cache line 2 (TX counter)
struct util_cntr *tx_cntr;                // +0x80
char pad1[56];                            // Padding to next line

// Cache line 3 (RX counter)  
struct util_cntr *rx_cntr;                // +0xC0
char pad2[56];                            // Padding to next line
```

**Result: 1 cache line per counter path** ✓

---

## 7. Unified Structure Layout Optimization

### 7.1 Design Constraints

**Requirements:**
1. Send path: ≤2 cache lines
2. Recv path: ≤2 cache lines
3. RMA write path: ≤2 cache lines
4. RMA read path: ≤2 cache lines
5. CQ poll path: ≤3 cache lines (domain + qp_table + base_ep)
6. Counter paths: 1 cache line each (no false sharing)

**Shared Fields:**
- `qp` - Used by: send, recv, RMA write, RMA read
- `lock` - Used by: send, recv, RMA write, RMA read
- `av` - Used by: send, RMA write, RMA read
- `domain` - Used by: send, RMA write, RMA read
- `tx_cntr`, `rx_cntr` - Used by: CQ poll

### 7.2 Optimized efa_base_ep Layout

**Strategy: Group by access pattern**

```c
struct efa_base_ep_v4 {
    // ===== CACHE LINE 0 (0-63): SEND/RMA PATH =====
    struct efa_qp *qp;                    // +0x00 (all paths)
    struct efa_av *av;                    // +0x08 (send, RMA)
    struct efa_domain *domain;            // +0x10 (send, RMA)
    struct ofi_genlock lock;              // +0x18 (all paths)
    uint64_t tx_msg_flags;                // +0x20 (send)
    uint64_t tx_op_flags;                 // +0x28 (send)
    struct fi_info *info;                 // +0x30 (validation - cold)
    size_t max_msg_size;                  // +0x38 (validation - cold)
    
    // ===== CACHE LINE 1 (64-127): RECV PATH =====
    struct efa_recv_wr *efa_recv_wr_vec;  // +0x40 (recv)
    size_t recv_wr_index;                 // +0x48 (recv)
    uint64_t rx_msg_flags;                // +0x50 (recv)
    uint64_t rx_op_flags;                 // +0x58 (recv)
    size_t max_rma_size;                  // +0x60 (validation - cold)
    struct efa_recv_wr *user_recv_wr_vec; // +0x68 (RDM only)
    struct efa_qp *user_recv_qp;          // +0x70 (RDM only)
    size_t rnr_retry;                     // +0x78 (cold)
    
    // ===== CACHE LINE 2 (128-191): TX COUNTER =====
    struct util_cntr *tx_cntr;            // +0x80 (CQ poll)
    char pad1[56];                        // +0x88 (padding)
    
    // ===== CACHE LINE 3 (192-255): RX COUNTER =====
    struct util_cntr *rx_cntr;            // +0xC0 (CQ poll)
    char pad2[56];                        // +0xC8 (padding)
    
    // ===== CACHE LINE 4+ (256+): COLD FIELDS =====
    struct util_ep util_ep_rest;          // Remaining util_ep fields
    struct efa_ep_addr src_addr;          // Cold
    bool util_ep_initialized;             // Cold
    bool efa_qp_enabled;                  // Cold
    bool is_wr_started;                   // Cold
    size_t inject_msg_size;               // Cold
    size_t inject_rma_size;               // Cold
    bool use_unsolicited_write_recv;      // Cold
};
```

### 7.3 Per-Path Cache Line Access

**Send Path:**
- Line 0: qp, av, domain, lock, tx_msg_flags
- **Total: 1 cache line** ✓

**Recv Path:**
- Line 0: qp, lock
- Line 1: efa_recv_wr_vec, recv_wr_index, rx_msg_flags
- **Total: 2 cache lines** ✓

**RMA Write Path:**
- Line 0: qp, av, domain, lock
- **Total: 1 cache line** ✓

**RMA Read Path:**
- Line 0: qp, av, domain, lock
- **Total: 1 cache line** ✓

**CQ Poll Path (TX):**
- Line 2: tx_cntr
- **Total: 1 cache line** (+ domain + qp_table) ✓

**CQ Poll Path (RX):**
- Line 3: rx_cntr
- **Total: 1 cache line** (+ domain + qp_table) ✓

### 7.4 Comparison: v3 vs v4

| Path | v3 Cache Lines | v4 Cache Lines | Improvement |
|------|----------------|----------------|-------------|
| Send | 3 → 1 | 1 | Same |
| Recv | 3 → 1 | 2 | Worse |
| RMA Write | 2 | 1 | Better |
| RMA Read | 2 | 1 | Better |
| CQ Poll TX | 2 | 1 | Better |
| CQ Poll RX | 2 | 1 | Better |

**v4 Advantage:**
- Better separation of concerns
- No false sharing between TX/RX counters
- RMA paths optimized independently
- Recv path still only 2 cache lines (acceptable)

---

## 8. Alternative Layout: Recv-Optimized

### 8.1 If Recv is More Critical Than Send

```c
struct efa_base_ep_v4_recv_opt {
    // ===== CACHE LINE 0 (0-63): RECV PATH =====
    struct efa_qp *qp;                    // +0x00 (all paths)
    struct ofi_genlock lock;              // +0x08 (all paths)
    struct efa_recv_wr *efa_recv_wr_vec;  // +0x10 (recv)
    size_t recv_wr_index;                 // +0x18 (recv)
    uint64_t rx_msg_flags;                // +0x20 (recv)
    uint64_t rx_op_flags;                 // +0x28 (recv)
    struct efa_av *av;                    // +0x30 (send, RMA)
    struct efa_domain *domain;            // +0x38 (send, RMA)
    
    // ===== CACHE LINE 1 (64-127): SEND/RMA PATH =====
    uint64_t tx_msg_flags;                // +0x40 (send)
    uint64_t tx_op_flags;                 // +0x48 (send)
    struct fi_info *info;                 // +0x50 (validation)
    // ... rest
};
```

**Recv Path: 1 cache line** ✓  
**Send Path: 2 cache lines** (lines 0, 1)

---

## 9. efa_qp Optimization for CQ Poll

### 9.1 Current Layout

```c
struct efa_qp {
    struct ibv_qp *ibv_qp;                // +0x00
    struct ibv_qp_ex *ibv_qp_ex;          // +0x08
    struct efa_base_ep *base_ep;          // +0x10
    uint32_t qp_num;                      // +0x18
    uint32_t qkey;                        // +0x1C
    // ...
};
```

**CQ Poll Access:**
1. qp_table[qp_num] → efa_qp
2. efa_qp->base_ep → efa_base_ep
3. efa_base_ep->tx_cntr or rx_cntr

**Total: 3 cache lines** (qp_table + efa_qp + efa_base_ep)

### 9.2 Optimized Layout: Cache Counters in QP

```c
struct efa_qp_v4 {
    struct efa_base_ep *base_ep;          // +0x00 (CQ poll)
    struct util_cntr *tx_cntr;            // +0x08 (cached)
    struct util_cntr *rx_cntr;            // +0x10 (cached)
    struct ibv_qp *ibv_qp;                // +0x18 (send/recv)
    struct ibv_qp_ex *ibv_qp_ex;          // +0x20 (send/recv)
    uint32_t qp_num;                      // +0x28
    uint32_t qkey;                        // +0x2C
    // ...
};
```

**CQ Poll Access:**
1. qp_table[qp_num] → efa_qp
2. efa_qp->tx_cntr or rx_cntr (direct)

**Total: 2 cache lines** (qp_table + efa_qp) ✓

**Trade-off:** Duplicate counter pointers, but eliminates base_ep access

---

## 10. efa_conn Optimization

### 10.1 Current Layout (Already Optimal)

```c
struct efa_conn {
    struct efa_ah *ah;                    // +0x00 (HOT)
    struct efa_ep_addr *ep_addr;          // +0x08 (HOT)
    struct efa_av *av;                    // +0x10 (COLD)
    fi_addr_t implicit_fi_addr;           // +0x18 (COLD)
    fi_addr_t fi_addr;                    // +0x20 (COLD)
    fi_addr_t shm_fi_addr;                // +0x28 (COLD)
    // ... rest cold
};
```

**Send/RMA Access:**
- Line 0: ah, ep_addr
- **Total: 1 cache line** ✓

**No changes needed**

---

## 11. Per-Path Performance Analysis

### 11.1 Send Path

**Current (v3 analysis):**
- 3 cache lines: efa_base_ep (lines 2, 4) + efa_conn (line 0)

**Optimized (v4):**
- 2 cache lines: efa_base_ep (line 0) + efa_conn (line 0)

**Improvement: 33% reduction in cache lines**

### 11.2 Recv Path

**Current:**
- 3 cache lines: efa_base_ep (lines 2, 4, 5)

**Optimized (v4):**
- 2 cache lines: efa_base_ep (lines 0, 1)

**Improvement: 33% reduction in cache lines**

### 11.3 RMA Write Path

**Current:**
- 2 cache lines: efa_base_ep (line 4) + efa_conn (line 0)

**Optimized (v4):**
- 2 cache lines: efa_base_ep (line 0) + efa_conn (line 0)

**Improvement: Same, but better locality**

### 11.4 RMA Read Path

**Current:**
- 2 cache lines: efa_base_ep (line 4) + efa_conn (line 0)

**Optimized (v4):**
- 2 cache lines: efa_base_ep (line 0) + efa_conn (line 0)

**Improvement: Same, but better locality**

### 11.5 CQ Poll Path

**Current:**
- 3 cache lines: domain + qp_table + efa_base_ep (line 2)

**Optimized (v4 with efa_qp caching):**
- 2 cache lines: domain + qp_table (efa_qp has counters)

**Improvement: 33% reduction in cache lines**

### 11.6 Counter Paths

**Current:**
- 2 cache lines: efa_base_ep (line 2) + util_cntr
- **Problem:** TX and RX share line 2 → false sharing

**Optimized (v4):**
- 2 cache lines: efa_base_ep (line 2 or 3) + util_cntr
- **Benefit:** TX and RX on separate lines → no false sharing

**Improvement: Eliminates false sharing**

---

## 12. Implementation Recommendations

### 12.1 Priority 1: Reorder efa_base_ep

**Changes:**
1. Move qp, av, domain, lock to cache line 0
2. Move tx_msg_flags to cache line 0
3. Move efa_recv_wr_vec, recv_wr_index, rx_msg_flags to cache line 1
4. Separate tx_cntr and rx_cntr to lines 2 and 3
5. Move cold fields to line 4+

**Impact:**
- Send: 3 → 2 cache lines (33% reduction)
- Recv: 3 → 2 cache lines (33% reduction)
- RMA: 2 → 2 cache lines (better locality)
- CQ poll: 3 → 3 cache lines (no change yet)

### 12.2 Priority 2: Cache Counters in efa_qp

**Changes:**
1. Add tx_cntr, rx_cntr pointers to efa_qp
2. Initialize during QP creation
3. Use cached pointers in CQ poll path

**Impact:**
- CQ poll: 3 → 2 cache lines (33% reduction)

**Trade-off:**
- +16 bytes per efa_qp (2 pointers)
- Eliminates 1 cache line access per completion

### 12.3 Priority 3: Validate and Measure

**Steps:**
1. Implement changes
2. Run correctness tests
3. Measure cache misses with perf
4. Measure latency/throughput
5. Validate improvements

---

## 13. Expected Performance Improvements

### 13.1 Per-Path Improvements

| Path | Cache Line Reduction | Expected Latency Improvement |
|------|----------------------|------------------------------|
| Send | 33% (3→2) | 5-8% |
| Recv | 33% (3→2) | 5-8% |
| RMA Write | 0% (2→2) | 2-3% (better locality) |
| RMA Read | 0% (2→2) | 2-3% (better locality) |
| CQ Poll | 33% (3→2) | 10-15% |
| Counter | False sharing eliminated | 20-30% (multi-threaded) |

### 13.2 Overall Impact

**Single-threaded:**
- Send/recv latency: 5-8% improvement
- RMA latency: 2-3% improvement
- CQ poll throughput: 10-15% improvement

**Multi-threaded:**
- Counter false sharing eliminated: 20-30% improvement
- Overall scaling: 15-25% improvement

---

## 14. Quick Reference

### 14.1 Optimized Structure Layout

```c
struct efa_base_ep_v4 {
    // Line 0: Send/RMA (64 bytes)
    struct efa_qp *qp;                    // +0x00
    struct efa_av *av;                    // +0x08
    struct efa_domain *domain;            // +0x10
    struct ofi_genlock lock;              // +0x18
    uint64_t tx_msg_flags;                // +0x20
    uint64_t tx_op_flags;                 // +0x28
    struct fi_info *info;                 // +0x30
    size_t max_msg_size;                  // +0x38
    
    // Line 1: Recv (64 bytes)
    struct efa_recv_wr *efa_recv_wr_vec;  // +0x40
    size_t recv_wr_index;                 // +0x48
    uint64_t rx_msg_flags;                // +0x50
    uint64_t rx_op_flags;                 // +0x58
    size_t max_rma_size;                  // +0x60
    struct efa_recv_wr *user_recv_wr_vec; // +0x68
    struct efa_qp *user_recv_qp;          // +0x70
    size_t rnr_retry;                     // +0x78
    
    // Line 2: TX Counter (64 bytes)
    struct util_cntr *tx_cntr;            // +0x80
    char pad1[56];                        // Padding
    
    // Line 3: RX Counter (64 bytes)
    struct util_cntr *rx_cntr;            // +0xC0
    char pad2[56];                        // Padding
    
    // Line 4+: Cold fields
    // ... rest
};

struct efa_qp_v4 {
    struct efa_base_ep *base_ep;          // +0x00
    struct util_cntr *tx_cntr;            // +0x08 (cached)
    struct util_cntr *rx_cntr;            // +0x10 (cached)
    struct ibv_qp *ibv_qp;                // +0x18
    struct ibv_qp_ex *ibv_qp_ex;          // +0x20
    // ... rest
};
```

### 14.2 Per-Path Cache Line Access

```
Send:       Line 0 (efa_base_ep) + Line 0 (efa_conn) = 2 lines
Recv:       Line 0 + Line 1 (efa_base_ep) = 2 lines
RMA Write:  Line 0 (efa_base_ep) + Line 0 (efa_conn) = 2 lines
RMA Read:   Line 0 (efa_base_ep) + Line 0 (efa_conn) = 2 lines
CQ Poll TX: Line 0 (efa_qp) = 1 line (+ domain + qp_table)
CQ Poll RX: Line 0 (efa_qp) = 1 line (+ domain + qp_table)
```

---

**END OF DOCUMENT**
