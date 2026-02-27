# EFA-Direct Send Path Memory Access Audit
## Complete Memory Access Trace from fi_send() to Device WQE

**Date:** 2026-02-27  
**Scope:** EFA data-path-direct send operation  
**Entry Point:** `efa_post_send()` in `prov/efa/src/efa_msg.c:192`  
**Exit Point:** WQE written to device memory

---

## Overview

This document traces **every memory access** in the send path for EFA-direct, from the application calling `fi_send()` through to writing the Work Queue Element (WQE) to the device.

**Path:** `fi_send()` → `efa_post_send()` → `efa_qp_post_send()` → `efa_data_path_direct_post_send()` → `efa_data_path_direct_send_wr_post()` → Device WQE

---

## Memory Access Trace

### Phase 1: efa_post_send() - Setup and Validation

**Location:** `prov/efa/src/efa_msg.c:192-283`

#### Access 1: Read base_ep->qp
```c
struct efa_qp *qp = base_ep->qp;
```
- **Structure:** `struct efa_base_ep`
- **Field:** `qp` at offset +288
- **Size:** 8 bytes (pointer)
- **Cache Line:** 4 (bytes 256-319)
- **Purpose:** Get QP for send operation

#### Access 2: Read msg->addr
```c
conn = efa_av_addr_to_conn(base_ep->av, msg->addr);
```
- **Structure:** `struct fi_msg` (user-provided)
- **Field:** `addr`
- **Size:** 8 bytes (fi_addr_t)
- **Cache Line:** User memory (unknown)
- **Purpose:** Get destination address

#### Access 3: Read base_ep->av
```c
conn = efa_av_addr_to_conn(base_ep->av, msg->addr);
```
- **Structure:** `struct efa_base_ep`
- **Field:** `av` at offset +296
- **Size:** 8 bytes (pointer)
- **Cache Line:** 4 (bytes 256-319)
- **Purpose:** Address vector for connection lookup

#### Access 4: AV lookup (efa_av_addr_to_conn)
```c
conn = efa_av_addr_to_conn(base_ep->av, msg->addr);
```
- **Structure:** `struct efa_av` (hash table or array)
- **Access Pattern:** Hash lookup or array index
- **Cache Line:** Variable (depends on AV implementation)
- **Purpose:** Get connection structure

#### Access 5: Read conn->ep_addr
```c
assert(conn && conn->ep_addr);
```
- **Structure:** `struct efa_conn`
- **Field:** `ep_addr` at offset +8
- **Size:** 8 bytes (pointer)
- **Cache Line:** 0 (bytes 0-63)
- **Purpose:** Validate connection has endpoint address

#### Access 6: Read base_ep->info->tx_attr->iov_limit
```c
assert(msg->iov_count <= base_ep->info->tx_attr->iov_limit);
```
- **Structure:** `struct efa_base_ep` → `struct fi_info` → `struct fi_tx_attr`
- **Field:** `info` at offset +304, then `tx_attr->iov_limit`
- **Cache Line:** 4 (base_ep), then fi_info structure (cold)
- **Purpose:** Validate iov_count

#### Access 7: Read msg->msg_iov (loop)
```c
len = ofi_total_iov_len(msg->msg_iov, msg->iov_count);
```
- **Structure:** `struct fi_msg` (user-provided)
- **Field:** `msg_iov` array
- **Access Pattern:** Sequential read of iov_base and iov_len
- **Cache Line:** User memory (unknown)
- **Purpose:** Calculate total message length

#### Access 8: Read qp->ibv_qp->qp_type
```c
if (qp->ibv_qp->qp_type == IBV_QPT_UD) {
```
- **Structure:** `struct efa_qp` → `struct ibv_qp`
- **Field:** `ibv_qp` at offset +0, then `qp_type`
- **Cache Line:** 0 (efa_qp), then ibv_qp structure
- **Purpose:** Check if UD (datagram) mode

#### Access 9: Read base_ep->info->ep_attr->msg_prefix_size
```c
assert(msg->msg_iov[0].iov_len >= base_ep->info->ep_attr->msg_prefix_size);
len -= base_ep->info->ep_attr->msg_prefix_size;
```
- **Structure:** `struct fi_info` → `struct fi_ep_attr`
- **Field:** `ep_attr->msg_prefix_size`
- **Cache Line:** fi_info structure (cold)
- **Purpose:** Account for UD prefix

#### Access 10: Read base_ep->info->ep_attr->max_msg_size
```c
assert(len <= base_ep->info->ep_attr->max_msg_size);
```
- **Structure:** `struct fi_info` → `struct fi_ep_attr`
- **Field:** `ep_attr->max_msg_size`
- **Cache Line:** fi_info structure (cold)
- **Purpose:** Validate message size

#### Access 11: Lock base_ep->util_ep.lock
```c
ofi_genlock_lock(&base_ep->util_ep.lock);
```
- **Structure:** `struct efa_base_ep` → `struct util_ep`
- **Field:** `lock` at offset +256 (within util_ep)
- **Size:** 8 bytes (ofi_genlock)
- **Cache Line:** 4 (bytes 256-319)
- **Purpose:** Thread safety
- **Operation:** Atomic operation (may cause cache line bounce)

#### Access 12: Read base_ep->domain->device->efa_attr.inline_buf_size
```c
use_inline = (len <= base_ep->domain->device->efa_attr.inline_buf_size &&
              (!msg->desc || !efa_mr_is_hmem(msg->desc[0])));
```
- **Structure:** `struct efa_base_ep` → `struct efa_domain` → `struct efa_device`
- **Field:** `domain` at offset +280, then `device->efa_attr.inline_buf_size`
- **Cache Line:** 4 (base_ep), then domain structure, then device structure
- **Purpose:** Determine if inline send possible

#### Access 13: Read msg->desc[i] (if not inline)
```c
sg_list[i].lkey = ((struct efa_mr *)msg->desc[i])->ibv_mr->lkey;
```
- **Structure:** `struct fi_msg` → `struct efa_mr` → `struct ibv_mr`
- **Field:** `desc[i]` pointer, then `ibv_mr->lkey`
- **Cache Line:** User memory (msg), then efa_mr structure, then ibv_mr structure
- **Purpose:** Get memory region key for SGE

#### Access 14: Read msg->msg_iov[i] (build SGE list)
```c
sg_list[i].addr = (uintptr_t)msg->msg_iov[i].iov_base;
sg_list[i].length = msg->msg_iov[i].iov_len;
```
- **Structure:** `struct fi_msg` (user-provided)
- **Field:** `msg_iov[i].iov_base` and `iov_len`
- **Cache Line:** User memory (unknown)
- **Purpose:** Build SGE list for non-inline send

---

### Phase 2: efa_qp_post_send() - Dispatch to Direct Path

**Location:** `prov/efa/src/efa_data_path_ops.h:217-239`

#### Access 15: Read qp->data_path_direct_enabled
```c
if (qp->data_path_direct_enabled)
    return efa_data_path_direct_post_send(...);
```
- **Structure:** `struct efa_qp`
- **Field:** `data_path_direct_enabled` at offset +32
- **Size:** 1 byte (bool)
- **Cache Line:** 0 (bytes 0-63)
- **Purpose:** Check if direct path enabled

---

### Phase 3: efa_data_path_direct_post_send() - Build WQE

**Location:** `prov/efa/src/efa_data_path_direct_entry.h:376-450`

#### Access 16: Read qp->data_path_direct_qp.sq
```c
struct efa_data_path_direct_sq *sq = &qp->data_path_direct_qp.sq;
```
- **Structure:** `struct efa_qp` → `struct efa_data_path_direct_qp`
- **Field:** `data_path_direct_qp.sq` at offset +40 (within efa_qp)
- **Size:** Pointer to embedded structure
- **Cache Line:** 0 (bytes 0-63)
- **Purpose:** Get send queue structure

#### Access 17: Stack allocation - local_wqe
```c
struct efa_io_tx_wqe local_wqe = {0};
```
- **Location:** Stack (registers or L1 cache)
- **Size:** 64 bytes (WQE size)
- **Cache Line:** N/A (stack/registers)
- **Purpose:** Build WQE in fast memory before copying to device

#### Access 18: Read sq->wq.wqe_posted
```c
err = efa_post_send_validate(qp);
```
- **Structure:** `struct efa_data_path_direct_sq` → `struct efa_data_path_direct_wq`
- **Field:** `wq.wqe_posted`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Check if queue has space

#### Access 19: Read sq->wq.wqe_completed
```c
err = efa_post_send_validate(qp);
```
- **Structure:** `struct efa_data_path_direct_sq` → `struct efa_data_path_direct_wq`
- **Field:** `wq.wqe_completed`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Check available queue space

#### Access 20: Read sq->num_wqe_pending
```c
if (!sq->num_wqe_pending)
    mmio_wc_start();
```
- **Structure:** `struct efa_data_path_direct_sq`
- **Field:** `num_wqe_pending`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Check if starting fresh batch

#### Access 21: Read sq->wq.max_batch
```c
if (sq->num_wqe_pending == sq->wq.max_batch) {
```
- **Structure:** `struct efa_data_path_direct_sq` → `struct efa_data_path_direct_wq`
- **Field:** `wq.max_batch`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Check if need to ring doorbell

#### Access 22: Read ah->efa_address_handle
```c
efa_data_path_direct_set_ud_addr(meta_desc, ah, qpn, qkey);
```
- **Structure:** `struct efa_ah`
- **Field:** `efa_address_handle` (device AH index)
- **Cache Line:** efa_ah structure
- **Purpose:** Set destination address in WQE

#### Access 23: Read conn->ep_addr->qpn
```c
efa_data_path_direct_set_ud_addr(meta_desc, ah, qpn, qkey);
```
- **Structure:** `struct efa_conn` → `struct efa_ep_addr`
- **Field:** `ep_addr->qpn`
- **Cache Line:** efa_ep_addr structure
- **Purpose:** Set destination QP number

#### Access 24: Read conn->ep_addr->qkey
```c
efa_data_path_direct_set_ud_addr(meta_desc, ah, qpn, qkey);
```
- **Structure:** `struct efa_conn` → `struct efa_ep_addr`
- **Field:** `ep_addr->qkey`
- **Cache Line:** efa_ep_addr structure
- **Purpose:** Set destination QP key

#### Access 25: Read sq->wq.wrid_idx_pool_next
```c
meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq, wr_id);
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `wrid_idx_pool_next`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Get next work request ID index

#### Access 26: Write sq->wq.wrid[idx]
```c
meta_desc->req_id = efa_wq_get_next_wrid_idx(&sq->wq, wr_id);
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `wrid[idx]` array
- **Cache Line:** wrid array (separate allocation)
- **Purpose:** Store work request ID for completion

#### Access 27: Read sq->wq.pc
```c
efa_set_common_ctrl_flags(meta_desc, sq, EFA_IO_SEND);
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `pc` (producer counter)
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Set phase bit in WQE

#### Access 28: Write local_wqe (build WQE on stack)
```c
efa_data_path_direct_set_inline_data(&local_wqe, iov_count, inline_data_list);
// or
efa_data_path_direct_set_sgl(local_wqe.data.sgl, meta_desc, sge_list, iov_count);
```
- **Location:** Stack variable
- **Size:** 64 bytes
- **Cache Line:** N/A (stack/registers)
- **Purpose:** Build complete WQE in fast memory

---

### Phase 4: efa_data_path_direct_send_wr_post() - Copy WQE to Device

**Location:** `prov/efa/src/efa_data_path_direct_internal.h:562-580`

#### Access 29: Read sq->wq.pc
```c
sq_desc_idx = sq->wq.pc & sq->wq.desc_mask;
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `pc` (producer counter)
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Calculate WQE index in ring

#### Access 30: Read sq->wq.desc_mask
```c
sq_desc_idx = sq->wq.pc & sq->wq.desc_mask;
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `desc_mask`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Mask to get ring index

#### Access 31: Read sq->desc
```c
dst = (uint64_t *)((struct efa_io_tx_wqe *)sq->desc + sq_desc_idx);
```
- **Structure:** `struct efa_data_path_direct_sq`
- **Field:** `desc` (pointer to device memory)
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Get base address of WQE ring

#### Access 32: Write to device memory (8 × 8-byte stores)
```c
for (int i = 0; i < 8; i++)
    dst[i] = src[i];
```
- **Location:** Device write-combined memory
- **Size:** 64 bytes (8 × 8-byte stores)
- **Cache Line:** Write-combined buffer (not cached)
- **Purpose:** Copy WQE from stack to device memory
- **Performance:** Write-combining buffer coalesces writes

#### Access 33: Increment sq->wq.pc
```c
efa_sq_advance_post_idx(sq);
```
- **Structure:** `struct efa_data_path_direct_wq`
- **Field:** `pc` (producer counter)
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Advance producer counter

#### Access 34: Increment sq->num_wqe_pending
```c
sq->num_wqe_pending++;
```
- **Structure:** `struct efa_data_path_direct_sq`
- **Field:** `num_wqe_pending`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Track pending WQEs

---

### Phase 5: efa_data_path_direct_send_wr_ring_db() - Ring Doorbell

**Location:** `prov/efa/src/efa_data_path_direct_internal.h:582-587`

#### Access 35: mmio_flush_writes()
```c
mmio_flush_writes();
```
- **Operation:** `sfence` instruction
- **Purpose:** Ensure all WQE writes are visible to device
- **Performance:** Serializes write-combining buffer

#### Access 36: Read sq->db
```c
efa_sq_ring_doorbell(sq, sq->wq.pc);
```
- **Structure:** `struct efa_data_path_direct_sq`
- **Field:** `db` (doorbell pointer)
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Get doorbell address

#### Access 37: Write to doorbell register
```c
mmio_write32(sq->db, sq->wq.pc);
```
- **Location:** Device MMIO register
- **Size:** 4 bytes
- **Cache Line:** N/A (uncached MMIO)
- **Purpose:** Notify device of new WQEs
- **Performance:** Single MMIO write

#### Access 38: Write sq->num_wqe_pending = 0
```c
sq->num_wqe_pending = 0;
```
- **Structure:** `struct efa_data_path_direct_sq`
- **Field:** `num_wqe_pending`
- **Cache Line:** Within data_path_direct_qp structure
- **Purpose:** Reset pending counter

---

### Phase 6: Cleanup

#### Access 39: Unlock base_ep->util_ep.lock
```c
ofi_genlock_unlock(&base_ep->util_ep.lock);
```
- **Structure:** `struct efa_base_ep` → `struct util_ep`
- **Field:** `lock` at offset +256
- **Cache Line:** 4 (bytes 256-319)
- **Purpose:** Release lock
- **Operation:** Atomic operation (may cause cache line bounce)

---

## Summary Statistics

### Total Memory Accesses: 39

**By Category:**
- **efa_base_ep:** 11 accesses (qp, av, domain, info, lock)
- **efa_qp:** 3 accesses (ibv_qp, data_path_direct_enabled, data_path_direct_qp)
- **efa_data_path_direct_sq:** 12 accesses (wq fields, desc, db, num_wqe_pending)
- **efa_conn:** 4 accesses (ep_addr, ah)
- **User msg:** 5 accesses (addr, msg_iov, desc)
- **Device memory:** 2 accesses (WQE write, doorbell write)
- **Stack:** 2 accesses (local_wqe build)

**By Cache Line (efa_base_ep):**
- **Line 4 (256-319):** 5 accesses (lock, domain, qp, av, info)
- **Line 0 (efa_qp):** 3 accesses (ibv_qp, data_path_direct_enabled, data_path_direct_qp)
- **Line 0 (efa_conn):** 2 accesses (ah, ep_addr)

**Critical Path Accesses (hot):**
1. base_ep->qp (line 4)
2. base_ep->av (line 4)
3. base_ep->domain (line 4)
4. base_ep->util_ep.lock (line 4) - **2 accesses (lock/unlock)**
5. qp->data_path_direct_qp.sq (line 0)
6. sq->wq fields (within data_path_direct_qp)
7. conn->ah, conn->ep_addr (line 0)
8. Device WQE write (write-combined)
9. Device doorbell write (MMIO)

---

## Cache Line Analysis

### efa_base_ep Accesses

**Cache Line 4 (bytes 256-319):**
- util_ep.lock (2 accesses: lock + unlock)
- domain (1 access)
- qp (1 access)
- av (1 access)
- info (1 access)

**Total: 6 accesses to cache line 4**

### efa_qp Accesses

**Cache Line 0 (bytes 0-63):**
- ibv_qp (1 access)
- data_path_direct_enabled (1 access)
- data_path_direct_qp.sq (1 access + 12 field accesses)

**Total: 15 accesses to efa_qp structure**

### efa_conn Accesses

**Cache Line 0 (bytes 0-63):**
- ah (1 access)
- ep_addr (3 accesses: validation + qpn + qkey)

**Total: 4 accesses to cache line 0**

---

## Performance Bottlenecks

### 1. Lock Contention
- **Access 11 & 39:** `base_ep->util_ep.lock`
- **Impact:** Atomic operations cause cache line bouncing in multi-threaded scenarios
- **Cache Line:** 4 (shared with qp, av, domain)
- **Recommendation:** Move lock to separate cache line

### 2. Multiple Structure Traversals
- **base_ep → domain → device:** 3-level pointer chase
- **base_ep → info → tx_attr/ep_attr:** 3-level pointer chase
- **msg → desc → efa_mr → ibv_mr:** 4-level pointer chase
- **Recommendation:** Cache frequently accessed values

### 3. Write-Combining Buffer Flush
- **Access 35:** `mmio_flush_writes()` (sfence)
- **Impact:** Serializes all pending writes
- **Recommendation:** Batch multiple WQEs before doorbell

### 4. Doorbell MMIO Write
- **Access 37:** `mmio_write32(sq->db, ...)`
- **Impact:** Expensive MMIO write (~100-200 cycles)
- **Recommendation:** Use FI_MORE flag to batch sends

---

## Optimization Opportunities

### 1. Reduce efa_base_ep Cache Lines
**Current:** 1 cache line (line 4) for hot fields
**Recommendation:** Keep as-is, already optimal

### 2. Eliminate Pointer Chases
**Current:** Multiple 3-4 level pointer chases
**Recommendation:** Cache inline_buf_size in efa_qp

### 3. Batch Doorbell Rings
**Current:** Ring doorbell per send (unless FI_MORE)
**Recommendation:** Application should use FI_MORE flag

### 4. Optimize Lock Placement
**Current:** Lock shares cache line with hot fields
**Recommendation:** Move to separate cache line to reduce false sharing

---

## Multi-Threading Concerns

### 1. Lock Contention (CRITICAL)
- **Field:** `base_ep->util_ep.lock`
- **Access:** Every send operation (lock + unlock)
- **Issue:** Atomic operations cause cache line bouncing
- **Impact:** Severe performance degradation with multiple threads
- **Solution:** Per-thread send queues or lock-free design

### 2. Producer Counter (MODERATE)
- **Field:** `sq->wq.pc`
- **Access:** Read + increment per send
- **Issue:** Shared counter between threads
- **Impact:** Cache line bouncing if multiple threads send
- **Solution:** Already protected by lock, but limits scalability

### 3. Work Request ID Array (LOW)
- **Field:** `sq->wq.wrid[idx]`
- **Access:** Write per send
- **Issue:** Different indices unlikely to conflict
- **Impact:** Minimal (different cache lines)
- **Solution:** None needed

### 4. Doorbell Register (LOW)
- **Field:** `sq->db` (MMIO)
- **Access:** Write per send (or batch)
- **Issue:** MMIO writes are serialized by hardware
- **Impact:** Minimal (already slow)
- **Solution:** Batching with FI_MORE

---

## Recommendations

### High Priority

1. **Move lock to separate cache line**
   - Eliminates false sharing with qp, av, domain
   - Reduces cache line bouncing in multi-threaded scenarios

2. **Cache inline_buf_size in efa_qp**
   - Eliminates 3-level pointer chase (base_ep → domain → device)
   - Reduces cache misses

3. **Use FI_MORE flag for batching**
   - Reduces doorbell MMIO writes
   - Improves write-combining efficiency

### Medium Priority

4. **Align data_path_direct_qp to cache line**
   - Ensures sq structure doesn't span cache lines
   - Improves access locality

5. **Pre-validate iov_count and message size**
   - Move validation to control path
   - Reduces cold accesses to fi_info structure

### Low Priority

6. **Consider lock-free send queue**
   - Eliminates lock contention entirely
   - Requires per-thread send queues
   - Complex implementation

---

## Appendix: Structure Sizes

```
struct efa_base_ep:           432 bytes (7 cache lines)
struct efa_qp:                168 bytes (3 cache lines)
struct efa_data_path_direct_qp: ~128 bytes (2 cache lines)
struct efa_conn:              88 bytes (2 cache lines)
struct efa_io_tx_wqe:         64 bytes (1 cache line)
```

---

**END OF DOCUMENT**
