# EFA AV Component Refactoring Plan

**Component:** Address Vector (AV)
**Complexity:** High
**Dependencies:** Domain refactoring should be completed first
**Date:** 2026-04-07

---

## Requirements

1. No `_unsafe` function naming convention — internal helpers document locking preconditions via comments and `assert(ofi_genlock_held(...))`.
2. `efa_av` (base) contains only what efa-direct needs; everything else goes into `efa_proto_av`.
3. Keep `util_av` — it provides buffer pool, hash lookup, locking, ep_list, ref counting.
4. Eliminate `efa_conn` — merge its fields into `efa_av_entry` (base) and `efa_proto_av_entry` (protocol).
5. Both efa-direct and rdm are `FI_THREAD_SAFE` — all `fi_ops` entry points must be safe for N concurrent threads.

## Naming Conventions

| Old Name | New Name | Rationale |
|----------|----------|-----------|
| `efa_av` (shared) | `efa_av` (base only) | Stripped to efa-direct fields only |
| (new) `efa_proto_av` | — | Protocol AV embedding `efa_av` as first member |
| `efa_conn` | eliminated | Fields folded into `efa_av_entry` / `efa_proto_av_entry`. Never allocated independently. |
| (new) `efa_proto_av_entry` | — | Flat layout with same field prefix as `efa_av_entry`, plus protocol fields |

All new files and functions in the efa-protocol layer use the `efa_proto_` prefix.

---

## 1. Current State Analysis

### 1.1 Shared Struct Problem

`struct efa_av` is shared by both efa-direct and efa-protocol fabrics. It contains fields that only efa-protocol needs:

| Field | efa-direct | protocol |
|-------|-----------|----------|
| `util_av` (explicit AV), `domain`, `type`, `used_explicit` | ✓ | ✓ |
| `cur_reverse_av`, `prv_reverse_av` | ✓ | ✓ |
| `shm_rdm_av` | | ✓ |
| `util_av_implicit`, `cur/prv_reverse_av_implicit` | | ✓ |
| `implicit_av_size`, `implicit_av_lru_list`, `evicted_peers_hashset` | | ✓ |
| `used_implicit`, `shm_used` | | ✓ |

### 1.2 Fabric-Type Branching

| File | Function | Branch Logic |
|------|----------|-------------|
| `efa_av.c` | `efa_av_insert_one()` | `info_type == EFA_INFO_DGRAM` for qkey, `== EFA_INFO_RDM` for srx_lock |
| `efa_av.c` | `efa_av_insert()` | `== EFA_INFO_RDM` for srx_lock acquire/release |
| `efa_av.c` | `efa_av_remove()` | `== EFA_INFO_RDM` for srx_lock acquire/release |
| `efa_av.c` | `efa_av_close_reverse_av()` | `== EFA_INFO_RDM` for srx_lock |
| `efa_av.c` | `efa_av_close()` | `== EFA_INFO_RDM` for shm_rdm_av close |
| `efa_av.c` | `efa_av_open()` | `== EFA_INFO_RDM` for shm AV creation |
| `efa_conn.c` | `efa_conn_alloc()` | `== EFA_INFO_RDM` for shm AV insert and rdm_deinit |
| `efa_conn.c` | `efa_conn_release()` | `== EFA_INFO_RDM` for rdm_deinit |

### 1.3 Unnecessary efa_conn Abstraction

`struct efa_conn` is always embedded in `struct efa_av_entry` — never independently allocated. `conn->ep_addr` wastes 8 bytes pointing back to byte 0 of the same struct.

| Field | efa-direct | protocol |
|-------|-----------|----------|
| `ah`, `ep_addr` (pointer, redundant), `av`, `fi_addr` | ✓ | ✓ |
| `implicit_fi_addr`, `shm_fi_addr` | | ✓ |
| `implicit_av_lru_entry`, `ah_implicit_conn_list_entry` | | ✓ |
| `ep_peer_map` | | ✓ |

---

## 2. Target Architecture

### 2.1 Struct Layout

```c
// efa_av.h — base AV entry (efa-direct), 48 bytes, single cache line
struct efa_av_entry {
    uint8_t         ep_addr[EFA_EP_ADDR_LEN]; // 32B; must be first (util_av); qpn@+16, qkey@+20 — TX hot
    struct efa_ah   *ah;                       // 8B — TX hot
    fi_addr_t       fi_addr;                   // 8B — RX hot
};

struct efa_av {
    struct util_av              util_av;
    struct efa_domain           *domain;
    size_t                      used;
    enum fi_av_type             type;
    struct efa_cur_reverse_av   *cur_reverse_av;
    struct efa_prv_reverse_av   *prv_reverse_av;
};

// Reverse AV maps point to efa_av_entry (not efa_conn)
struct efa_cur_reverse_av {
    struct efa_cur_reverse_av_key key;
    struct efa_av_entry *av_entry;
    UT_hash_handle hh;
};
struct efa_prv_reverse_av {
    struct efa_prv_reverse_av_key key;
    struct efa_av_entry *av_entry;
    UT_hash_handle hh;
};

// Typed accessor — avoids raw casts everywhere
static inline struct efa_ep_addr *efa_av_entry_ep_addr(struct efa_av_entry *entry) {
    return (struct efa_ep_addr *)entry->ep_addr;
}
```

```c
// rdm/efa_proto_av.h — flat layout, same field prefix as efa_av_entry
struct efa_proto_av_entry {
    // --- cache line 1 (64 bytes): hot fields ---
    uint8_t         ep_addr[EFA_EP_ADDR_LEN]; // 32B — TX hot
    struct efa_ah   *ah;                       // 8B — TX hot
    fi_addr_t       fi_addr;                   // 8B — RX hot (explicit AV)
    fi_addr_t       implicit_fi_addr;          // 8B — RX hot (implicit AV / CQ progress)
    fi_addr_t       shm_fi_addr;               // 8B — SHM TX path
    // --- cache line 2: cold fields (control path only) ---
    struct dlist_entry  implicit_av_lru_entry;
    struct dlist_entry  ah_implicit_conn_list_entry;
    struct efa_proto_av_entry_ep_peer_map_entry *ep_peer_map;
};

struct efa_proto_av {
    struct efa_av       efa_av;                 // embedded as first member (castable)
    struct fid_av       *shm_rdm_av;
    struct util_av      util_av_implicit;
    struct efa_cur_reverse_av *cur_reverse_av_implicit;
    struct efa_prv_reverse_av *prv_reverse_av_implicit;
    size_t              used_implicit;
    size_t              shm_used;
    size_t              implicit_av_size;
    struct dlist_entry  implicit_av_lru_list;
    struct efa_ep_addr_hashable *evicted_peers_hashset;
};
```

```c
// rdm/efa_rdm_peer.h
struct efa_rdm_peer {
    struct efa_rdm_ep           *ep;
    struct efa_proto_av_entry   *av_entry;  // was: struct efa_conn *conn
    // ... rest unchanged
};
```

`efa_proto_av_entry` uses a flat layout (not embedding `efa_av_entry`) so that:
- Data path accesses are `entry->ah`, not `entry->base.ah` — zero naming overhead
- The mechanical rename from `conn->ah` → `entry->ah` is trivial across ~60 call sites
- Cache line 1 packs exactly to 64 bytes with all 5 hot fields
- No `container_of` gymnastics needed; protocol code always knows its entry type

The tradeoff — no castability between the two entry types — is fine since protocol code always works with `efa_proto_av_entry` and base code always works with `efa_av_entry`.

Typed accessor works for both:
```c
static inline struct efa_ep_addr *efa_proto_av_entry_ep_addr(struct efa_proto_av_entry *entry) {
    return (struct efa_ep_addr *)entry->ep_addr;
}
```

### 2.2 Cache Line Analysis

**Current layout (120 bytes):**
```
Cache line 1 (bytes 0-63):
  [0-31]  ep_addr[32]           ← qpn@+16, qkey@+20 (TX hot)
  [32-39] conn.ah*              ← TX hot
  [40-47] conn.ep_addr*         ← WASTED: points back to byte 0
  [48-55] conn.av*              ← not hot
  [56-63] conn.implicit_fi_addr ← RDM only

Cache line 2 (bytes 64-119):
  [64-71] conn.fi_addr          ← RX HOT but in wrong cache line!
  [72-79] conn.shm_fi_addr
  [80-119] control path only fields
```

**Proposed efa-direct (48 bytes — single cache line):**
```
  [0-31]  ep_addr[32]   ← TX hot (qpn@+16, qkey@+20)
  [32-39] ah*           ← TX hot
  [40-47] fi_addr       ← RX hot ✓
```

**Proposed efa-protocol (104 bytes — hot fields in cache line 1):**
```
Cache line 1 (64 bytes):
  [0-31]  ep_addr[32]        ← TX hot
  [32-39] ah*                ← TX hot
  [40-47] fi_addr            ← RX hot ✓
  [48-55] implicit_fi_addr   ← CQ progress hot
  [56-63] shm_fi_addr        ← SHM TX path

Cache line 2 (40 bytes, cold):
  [64-79]  implicit_av_lru_entry
  [80-95]  ah_implicit_conn_list
  [96-103] ep_peer_map*
```

### 2.3 Locking Design

Four locks participate in AV operations. Lock ordering:
```
srx_lock  →  util_av_implicit.lock  →  util_av.lock  →  domain->util_domain.lock
(outermost)                                                (innermost)
```

| Lock | Protects | Used by |
|------|----------|---------|
| `domain->srx_lock` | Shared receive context — peer structs, peer maps, CQ read vs AV insert/remove | Protocol only |
| `av->util_av_implicit.lock` | Implicit AV entries (buffer pool, hash, implicit reverse AV maps) | Protocol only |
| `av->util_av.lock` | Explicit AV entries (buffer pool, hash, reverse AV maps) | Both |
| `domain->util_domain.lock` | AH map, AH alloc/release/eviction | Both |

**Locking rules:**

1. Base fi_ops (`efa_av_insert`, `efa_av_remove`, `efa_av_lookup`, `efa_av_close`) are thread-safe — acquire `util_av.lock` internally.
2. Protocol fi_ops (`efa_proto_av_insert`, `efa_proto_av_remove`, `efa_proto_av_close`) are thread-safe — acquire full lock chain. Do NOT call base fi_ops (would double-acquire `util_av.lock`).
3. Internal helpers document preconditions via `assert(ofi_genlock_held(...))` — no locks acquired, no `_unsafe` suffix.
4. `efa_ah_alloc`/`efa_ah_release` acquire `util_domain.lock` internally — always innermost.

**Per-operation locking:**

| Operation | efa-direct | protocol |
|-----------|-----------|----------|
| `fi_av_open` | None | None |
| `fi_av_insert` | `util_av.lock` → `util_domain.lock` | `srx_lock` → `util_av_implicit.lock` → `util_av.lock` → `util_domain.lock` |
| `fi_av_remove` | `util_av.lock` → `util_domain.lock` | `srx_lock` → `util_av.lock` → `util_domain.lock` |
| `fi_av_lookup` | `util_av.lock` | `util_av.lock` |
| `fi_av_close` | `util_av.lock` → `util_domain.lock` | `srx_lock` → `util_av.lock` → `util_domain.lock`, then `util_av_implicit.lock` → `util_domain.lock` |
| CQ read (implicit insert) | N/A | `srx_lock` (held) → `util_av_implicit.lock` → `util_av.lock` → `util_domain.lock` |

**Full lock trace for `fi_av_insert` (protocol):**
```
efa_proto_av_insert                          [fi_ops entry point, thread-safe]
  ├─ LOCK srx_lock
  ├─ for each address:
  │    └─ efa_proto_av_insert_one            [internal, asserts srx_lock held]
  │         ├─ LOCK util_av_implicit.lock
  │         ├─ LOCK util_av.lock
  │         ├─ ofi_av_lookup_fi_addr_unsafe  [util_av.lock held]
  │         ├─ ofi_av_lookup_fi_addr_unsafe  [util_av_implicit.lock held]
  │         ├─ [if implicit→explicit]:
  │         │    └─ efa_proto_av_entry_implicit_to_explicit
  │         │         └─ LOCK util_av.ep_list_lock
  │         ├─ [if new address]:
  │         │    └─ efa_av_entry_init        [asserts util_av.lock held]
  │         │         └─ efa_ah_alloc
  │         │              └─ LOCK util_domain.lock  ← innermost
  │         │    └─ efa_proto_av_entry_init_shm / _init_implicit
  │         ├─ UNLOCK util_av.lock
  │         └─ UNLOCK util_av_implicit.lock
  └─ UNLOCK srx_lock
```

---

## 3. Implementation Phases

### Phase 1: Eliminate efa_conn, define new structs, mechanical rename

**Objective:** Remove `efa_conn`. Define `efa_av_entry` (base) and `efa_proto_av_entry` (protocol) with flat layouts. Mechanically rename all callers across the codebase.

**Steps:**

1. Restructure `struct efa_av_entry` in `efa_av.h`:
   - Move `ah`, `fi_addr` from `efa_conn` directly into `efa_av_entry`
   - Remove `struct efa_conn conn` member
   - Add `efa_av_entry_ep_addr()` typed helper
   - Update reverse AV structs to hold `efa_av_entry *` instead of `efa_conn *`

2. Create `struct efa_proto_av_entry` in new `rdm/efa_proto_av.h`:
   - Flat layout with same field prefix (`ep_addr`, `ah`, `fi_addr`)
   - Add protocol fields: `implicit_fi_addr`, `shm_fi_addr`, `implicit_av_lru_entry`, `ah_implicit_conn_list_entry`, `ep_peer_map`
   - Add `efa_proto_av_entry_ep_addr()` helper

3. Replace `efa_av_addr_to_conn()` with `efa_av_addr_to_entry()` returning `efa_av_entry *`

4. Update `efa_rdm_peer`: `struct efa_conn *conn` → `struct efa_proto_av_entry *av_entry`

5. Mechanical rename across ~25 files:
   - Base path (`efa_msg.c`, `efa_rma.c`, `efa_base_ep.c`, `efa_cq.c`, `efa_domain.c`, `efa_ah.c`): `conn->ah` → `entry->ah`, `conn->ep_addr->qpn` → `efa_av_entry_ep_addr(entry)->qpn`
   - Protocol path (`rdm/efa_rdm_*.c`): `conn->ah` → `entry->ah`, `conn->shm_fi_addr` → `entry->shm_fi_addr`

6. Absorb `efa_conn.c` functions:
   - Base logic (`alloc`/`release`) → `efa_av_entry_init()`/`efa_av_entry_release()` in `efa_av.c`
   - Protocol logic (`rdm_insert_shm_av`, `rdm_deinit`, `ep_peer_map_*`, `implicit_to_explicit`) → `rdm/efa_proto_av.c`
   - Delete `efa_conn.h` and `efa_conn.c`

**Test:** Full compilation. All existing unit tests pass.

**Files touched:** `efa_av.h`, `efa_av.c`, `efa_conn.h` (removed), `efa_conn.c` (removed), `rdm/efa_proto_av.h` (new), `rdm/efa_proto_av.c` (new), `efa_base_ep.h`, `efa_base_ep.c`, `efa_ep.c`, `efa_rma.c`, `efa_msg.c`, `efa_cq.c`, `efa_domain.c`, `efa_ah.c`, `rdm/efa_rdm_ep_fiops.c`, `rdm/efa_rdm_cq.c`, `rdm/efa_rdm_ep_utils.c`, `rdm/efa_rdm_peer.h`, `rdm/efa_rdm_peer.c`, `rdm/efa_rdm_pke.c`, `rdm/efa_rdm_msg.c`, `rdm/efa_rdm_ope.c`, `rdm/efa_rdm_pke_nonreq.c`, `rdm/efa_rdm_pke_print.c`, `rdm/efa_rdm_util.c`, `test/efa_unit_test_av.c`

---

### Phase 2: Separate efa_av / efa_proto_av structs, split open/close

**Objective:** Split `struct efa_av` into base and protocol versions. Split `efa_av_open`/`efa_av_close` into separate code paths with correct locking.

**Steps:**

1. Create `struct efa_proto_av` in `rdm/efa_proto_av.h`:
   - Embed `struct efa_av` as first member (castable)
   - Move protocol fields from `efa_av`: `shm_rdm_av`, `util_av_implicit`, `cur/prv_reverse_av_implicit`, `implicit_av_size`, `implicit_av_lru_list`, `evicted_peers_hashset`, `used_implicit`, `shm_used`

2. Slim down `struct efa_av` in `efa_av.h`:
   - Keep only: `util_av`, `domain`, `used`, `type`, `cur_reverse_av`, `prv_reverse_av`
   - Remove `#include "rdm/efa_rdm_protocol.h"` and `#include "rdm/efa_rdm_peer.h"`

3. Split open:
   - `efa_av_init()` — takes pre-allocated `efa_av *`, initializes fields. `context_len = sizeof(efa_av_entry) - EFA_EP_ADDR_LEN`.
   - `efa_av_open()` — efa-direct fi_ops: calloc `efa_av`, call `efa_av_init()`. No locks.
   - `efa_proto_av_open()` — protocol fi_ops: calloc `efa_proto_av`, call `efa_av_init(&proto_av->efa_av)` with `context_len = sizeof(efa_proto_av_entry) - EFA_EP_ADDR_LEN`, then init implicit AV, SHM AV, LRU list.

4. Split close:
   - `efa_av_close_internal()` — assumes locks held, does not free memory.
   - `efa_av_close()` — efa-direct fi_ops (thread-safe): acquires `util_av.lock`, calls internal, frees.
   - `efa_proto_av_close()` — protocol fi_ops (thread-safe): acquires `srx_lock → util_av.lock` for explicit cleanup, `util_av_implicit.lock` for implicit cleanup, closes SHM AV, calls `efa_av_close_internal()`, frees.

5. Wire separate `fi_ops_av` / `fi_ops` structs per fabric type.

**Test:** `test_efa_ah_cnt_one_av_efa`, `test_efa_ah_cnt_one_av_efa_direct`, `test_av_insert_duplicate_raw_addr`, `test_av_implicit` pass.

---

### Phase 3: Split insert/remove/reverse-lookup

**Objective:** Separate all AV data operations into base and protocol versions, eliminating all `info_type` branching.

**Steps:**

1. `efa_av_entry_init()` — internal helper, asserts `util_av.lock` held. Core logic: validate address, `ofi_av_insert_addr()`, set `ah`/`fi_addr`, `efa_av_reverse_av_add()`. No branching.

2. `efa_av_insert()` — efa-direct fi_ops (thread-safe): acquires `util_av.lock`, loops calling `efa_av_entry_init()`.

3. `efa_proto_av_insert_one()` — internal, asserts `srx_lock` held. Acquires `util_av_implicit.lock → util_av.lock`. Checks explicit AV, implicit AV, handles implicit→explicit migration, calls `efa_av_entry_init()` for hardware insert, handles SHM/LRU. Does NOT call `efa_av_insert` fi_ops.

4. `efa_proto_av_insert()` — protocol fi_ops (thread-safe): acquires `srx_lock`, loops calling `efa_proto_av_insert_one()`.

5. Similarly split remove: `efa_av_remove()` (base, acquires `util_av.lock`) and `efa_proto_av_remove()` (protocol, acquires `srx_lock → util_av.lock`).

6. `efa_proto_av_entry_implicit_to_explicit()` — moved from `efa_conn_implicit_to_explicit()`.

7. Reverse lookup:
   - `efa_av_reverse_lookup()` stays in base (AHN+QPN only)
   - `efa_proto_av_reverse_lookup()` / `_implicit()` move to `rdm/efa_proto_av.c` (connid-aware, LRU updates, assert `srx_lock` held)
   - Update callers in `rdm/efa_rdm_cq.c`

**Test:** `test_av_insert_duplicate_raw_addr`, `test_av_insert_duplicate_gid`, `test_av_implicit_to_explicit`, `test_av_implicit_av_lru_insertion`, `test_av_implicit_av_lru_eviction`. CQ tests for both paths.

---

### Phase 4: Wire up EP binding, cleanup, final audit

**Objective:** Wire everything together, remove all remaining `info_type` branching, update build and tests.

**Steps:**

1. `efa_base_ep.av` stays `struct efa_av *`. Protocol EP stores `struct efa_proto_av *proto_av` set during bind via `container_of`.

2. Update all protocol callers to use `ep->proto_av` for protocol-specific AV fields.

3. Audit: grep for `info_type` in AV-related files — every instance must be gone. `efa_av.c` must have zero knowledge of protocol concepts.

4. Clean up headers: `efa_av.h` must NOT include `rdm/efa_rdm_protocol.h` or `rdm/efa_rdm_peer.h`.

5. Update `Makefile.include`: add `rdm/efa_proto_av.c`, remove `efa_conn.c`.

6. Update `test/efa_unit_test_av.c`: use `efa_proto_av_entry` for implicit AV tests, `efa_av_entry` for base tests. Verify lock assertions on all internal helpers.

**Test:** Full test suite. fabtests. `test_av_multiple_ep_efa`, `test_av_multiple_ep_efa_direct`. No `info_type` branching remains. `efa_conn` fully gone.

---

## 4. Key Design Decisions

### 4.1 Flat efa_proto_av_entry (no embedding)

`efa_proto_av_entry` duplicates the field prefix (`ep_addr`, `ah`, `fi_addr`) rather than embedding `struct efa_av_entry base`. This gives:
- Zero naming overhead on data path: `entry->ah` not `entry->base.ah` (~60 call sites)
- Exact cache line packing: 5 hot fields = 64 bytes = cache line 1
- Trivial mechanical rename: `conn->ah` → `entry->ah` everywhere
- No `container_of` needed between entry types

The tradeoff — no castability between entry types — is fine since protocol code always knows it's working with `efa_proto_av_entry` and base code always knows `efa_av_entry`.

### 4.2 Eliminating efa_conn

`efa_conn` is never independently allocated. Folding its fields into the AV entries:
- Removes naming indirection (`entry->ah` vs `entry->conn.ah`)
- Eliminates `efa_conn.h` / `efa_conn.c`
- Eliminates the wasted `ep_addr*` pointer (8 bytes pointing back to byte 0)
- Replaced by `efa_av_entry_ep_addr()` typed helper

### 4.3 Cache Line Optimization

Current: `fi_addr` at byte 64 (cache line 2) — extra miss on every RX completion.
Proposed: `fi_addr` at byte 40 (cache line 1). All TX fields (`ah`, `qpn`, `qkey`) and RX field (`fi_addr`) in one cache line. Protocol adds `implicit_fi_addr` and `shm_fi_addr` to fill cache line 1 exactly at 64 bytes.

### 4.4 efa_av_init() Pre-Allocated Pointer Pattern

`efa_av_init()` takes pre-allocated `efa_av *` — `efa_proto_av_open` passes `&proto_av->efa_av`, `efa_av_open` wraps with its own calloc. Same for `efa_av_entry_init()` — takes pre-allocated `efa_av_entry *` from buffer pool.

### 4.5 AH Management

`struct efa_ah` has protocol-specific fields (`implicit_refcnt`, `implicit_conn_list`, `domain_lru_ah_list_entry`). Address in a follow-up. `efa_ah_alloc`/`efa_ah_release` acquire `util_domain.lock` internally — always innermost.

---

## 5. Testing Strategy

1. **Unit tests:** Update `efa_unit_test_av.c` — separate tests for `efa_av` and `efa_proto_av` paths
2. **Integration tests:** fabtests suite (fi_pingpong, fi_rdm_tagged_bw, etc.)
3. **Implicit AV tests:** insertion, LRU eviction, implicit-to-explicit migration
4. **Thread safety:** Thread sanitizer to catch lock ordering issues
5. **Performance:** Benchmark CQ progress path (reverse lookup is on hot path)
6. **Specific test cases:** See individual phase descriptions in §3

---

## 6. File Summary

### New Files
| File | Purpose |
|------|---------|
| `rdm/efa_proto_av.h` | `struct efa_proto_av`, `struct efa_proto_av_entry`, protocol AV declarations |
| `rdm/efa_proto_av.c` | Protocol AV open/close/insert/remove, implicit AV, reverse lookup, SHM, peer map, implicit→explicit |

### Deleted Files
| File | Reason |
|------|--------|
| `efa_conn.h` | Fields folded into `efa_av_entry` / `efa_proto_av_entry` |
| `efa_conn.c` | Functions absorbed into `efa_av.c` and `rdm/efa_proto_av.c` |

### Modified Files
| File | Changes |
|------|---------|
| `efa_av.h` | Restructure `efa_av_entry`, strip `efa_av`, add helpers, update reverse AV structs |
| `efa_av.c` | Absorb base entry init/release, add `efa_av_init()`/`efa_av_close_internal()`, remove all `info_type` branching |
| `efa_domain.c` | Wire correct `av_open` per fabric type |
| `efa_base_ep.h`/`.c`, `efa_ep.c` | `efa_conn` → `efa_av_entry` |
| `efa_msg.c`, `efa_rma.c` | `efa_conn` → `efa_av_entry`, use `efa_av_entry_ep_addr()` |
| `efa_cq.c`, `efa_ah.c` | `efa_conn` → `efa_av_entry` |
| `rdm/efa_rdm_cq.c` | Use `efa_proto_av_*` APIs |
| `rdm/efa_rdm_ep_fiops.c` | Store `efa_proto_av *`, update peer map pool |
| `rdm/efa_rdm_ep_utils.c` | Update entry/peer access |
| `rdm/efa_rdm_peer.h`/`.c` | `efa_conn *conn` → `efa_proto_av_entry *av_entry` |
| `rdm/efa_rdm_pke.c`, `efa_rdm_msg.c`, `efa_rdm_ope.c` | `efa_conn` → `efa_proto_av_entry` |
| `rdm/efa_rdm_pke_nonreq.c`, `efa_rdm_pke_print.c`, `efa_rdm_util.c` | `efa_conn` → `efa_proto_av_entry` |
| `Makefile.include` | Add new, remove deleted |
| `test/efa_unit_test_av.c` | Split tests for base vs protocol |
