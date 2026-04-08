━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# EFA AV Component Refactoring Plan

Component: Address Vector (AV)
Complexity: High
Dependencies: Domain refactoring should be completed first
Date: 2026-04-07

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## Naming Conventions

| Old Name | New Name | Rationale |
|----------|----------|-----------|
| efa_av (shared) | efa_av (base only) | Stripped to efa-direct fields only |
| efa_rdm_av | efa_proto_av | Aligns with "efa-protocol" terminology from the architecture doc; avoids confusion with the efa_rdm_ prefix used for EP/CQ/peer structs |
| efa_conn | eliminated | Fields folded into efa_av_entry / efa_proto_av_entry. Never allocated independently. |
| (new) efa_proto_av_entry | — | Protocol-layer AV entry with implicit AV, SHM, and peer management fields |

All new files and functions in the efa-protocol layer use the efa_proto_ prefix.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## 1. Current State Analysis

### 1.1 Shared Struct Problem

struct efa_av (in efa_av.h) is shared by both efa-direct and efa-protocol (RDM) fabrics. It contains fields that only efa-protocol needs:

- shm_rdm_av — SHM provider AV (RDM only)
- util_av_implicit / cur_reverse_av_implicit / prv_reverse_av_implicit — implicit AV management (RDM only)
- implicit_av_size / implicit_av_lru_list / evicted_peers_hashset — implicit AV LRU eviction (RDM only)

This causes unnecessary memory footprint for efa-direct, cache pollution, and forces fabric-type branching in shared functions.

### 1.2 Fabric-Type Branching in AV Code

The following info_type branches exist in the current AV/conn code:

| File | Function | Branch Logic |
|------|----------|-------------|
| efa_av.c | efa_av_insert_one() | info_type == EFA_INFO_DGRAM for qkey, info_type == EFA_INFO_RDM for srx_lock |
| efa_av.c | efa_av_insert() | info_type == EFA_INFO_RDM for srx_lock acquire/release |
| efa_av.c | efa_av_remove() | info_type == EFA_INFO_RDM for srx_lock acquire/release |
| efa_av.c | efa_av_close_reverse_av() | info_type == EFA_INFO_RDM for srx_lock |
| efa_av.c | efa_av_close() | info_type == EFA_INFO_RDM for shm_rdm_av close |
| efa_av.c | efa_av_open() | info_type == EFA_INFO_RDM for shm AV creation |
| efa_av.c | efa_av_reverse_lookup_rdm_implicit() | asserts srx_lock held (RDM-only function) |
| efa_conn.c | efa_conn_alloc() | info_type == EFA_INFO_RDM for shm AV insert and rdm_deinit |
| efa_conn.c | efa_conn_release() | info_type != EFA_INFO_RDM assertion, info_type == EFA_INFO_RDM for rdm_deinit |
| efa_conn.c | efa_av_reverse_av_add() | info_type == EFA_INFO_RDM assertion for prv_reverse_av |

### 1.3 RDM-Specific AV Usage (CQ Progress Path)

The RDM CQ progress path (efa_rdm_cq.c) directly accesses efa_av internals:
- efa_av_reverse_lookup_rdm() / efa_av_reverse_lookup_rdm_implicit() — reverse lookup using AHN+QPN+connid
- efa_av_insert_one() with insert_implicit_av=true — implicit AV insertion for unknown peers
- Direct access to av->util_av_implicit and av->evicted_peers_hashset

### 1.4 Unnecessary efa_conn Abstraction

struct efa_conn is always embedded inside struct efa_av_entry — it is never independently allocated:

c
struct efa_av_entry {
    uint8_t ep_addr[EFA_EP_ADDR_LEN];
    struct efa_conn conn;  // always embedded, never standalone
};


efa_av_addr_to_conn() returns &efa_av_entry->conn, and all callers just access conn->ah, conn->ep_addr, conn->fi_addr. This extra struct layer adds naming indirection without providing encapsulation.

Additionally, efa_conn bundles efa-direct and RDM-specific fields together:

- **efa-direct needs:** ah, ep_addr (pointer, redundant), fi_addr
- **RDM additionally needs:** implicit_fi_addr, shm_fi_addr, implicit_av_lru_entry, ah_implicit_conn_list_entry, ep_peer_map

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## 2. Target Architecture

### 2.1 Struct Layout

Following the updated plan (struct embedding, not fi_* layering):

c
// efa_av.h — efa-direct: flat AV entry, all hot fields in first cache line
struct efa_av_entry {
    // --- cache line 1 (64 bytes) ---
    uint8_t ep_addr[EFA_EP_ADDR_LEN];  // 32 bytes; qpn at +16, qkey at +20 — TX hot
    struct efa_ah *ah;                  // 8 bytes — TX hot
    fi_addr_t fi_addr;                  // 8 bytes — RX hot
    // 48 bytes used, 16 bytes spare
};

struct efa_av {
    struct util_av util_av;
    struct efa_domain *domain;
    size_t used;
    enum fi_av_type type;
    struct efa_cur_reverse_av *cur_reverse_av;
    struct efa_prv_reverse_av *prv_reverse_av;
    // NO implicit AV, NO shm AV, NO protocol-specific fields
};

// Reverse AV maps point to efa_av_entry
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


c
// rdm/efa_proto_av.h — efa-protocol: flat layout with same field prefix
struct efa_proto_av_entry {
    // --- cache line 1 (64 bytes): hot fields ---
    uint8_t ep_addr[EFA_EP_ADDR_LEN];  // 32 bytes; same layout prefix as efa_av_entry
    struct efa_ah *ah;                  // 8 bytes — TX hot
    fi_addr_t fi_addr;                  // 8 bytes — RX hot (explicit AV)
    fi_addr_t implicit_fi_addr;         // 8 bytes — RX hot (implicit AV / CQ progress)
    fi_addr_t shm_fi_addr;             // 8 bytes — SHM TX path
    // 64 bytes — exactly fills cache line 1
    // --- cache line 2: cold fields (control path only) ---
    struct dlist_entry implicit_av_lru_entry;       // 16 bytes
    struct dlist_entry ah_implicit_conn_list_entry;  // 16 bytes
    struct efa_proto_av_entry_ep_peer_map_entry *ep_peer_map;  // 8 bytes
};

struct efa_proto_av {
    struct efa_av efa_av;  // embedded as first member (castable)
    // --- efa-protocol specific fields below ---
    struct fid_av *shm_rdm_av;
    struct util_av util_av_implicit;
    struct efa_cur_reverse_av *cur_reverse_av_implicit;
    struct efa_prv_reverse_av *prv_reverse_av_implicit;
    size_t implicit_av_size;
    struct dlist_entry implicit_av_lru_list;
    struct efa_ep_addr_hashable *evicted_peers_hashset;
    size_t used_implicit;
    size_t shm_used;
};


c
// rdm/efa_rdm_peer.h — updated peer struct
struct efa_rdm_peer {
    struct efa_rdm_ep           *ep;
    struct efa_proto_av_entry   *av_entry;  // was: struct efa_conn *conn
    // ... rest unchanged
};


Helper for accessing ep_addr as typed struct:
c
static inline struct efa_ep_addr *efa_av_entry_ep_addr(struct efa_av_entry *entry) {
    return (struct efa_ep_addr *)entry->ep_addr;
}


Note: efa_proto_av_entry uses a flat layout (same field prefix as efa_av_entry) rather than embedding efa_av_entry as first member. This gives better ergonomics (entry->ah instead of entry->base.ah), allows
exact cache line packing, and avoids double-dereference in the data path. The tradeoff is no castability between the two entry types, which is fine since protocol code always knows it's working with
efa_proto_av_entry.

### 2.2 Cache Line Analysis

The current efa_av_entry is 120 bytes (~2 cache lines), and critically, fi_addr — read on every RX completion — lands in cache line 2. The ep_addr* pointer in efa_conn wastes 8 bytes pointing back to byte 0 of
the same struct.

Current layout (120 bytes):
Cache line 1 (bytes 0-63):
  [0-31]  ep_addr[32]           ← qpn at +16, qkey at +20 (TX hot)
  [32-39] conn.ah*              ← TX hot
  [40-47] conn.ep_addr*         ← WASTED: points back to byte 0
  [48-55] conn.av*              ← not hot
  [56-63] conn.implicit_fi_addr ← RDM only

Cache line 2 (bytes 64-119):
  [64-71] conn.fi_addr          ← RX HOT but in wrong cache line!
  [72-79] conn.shm_fi_addr      ← RDM only
  [80-95] conn.implicit_av_lru  ← control path only
  [96-111] conn.ah_implicit_conn ← control path only
  [112-119] conn.ep_peer_map*   ← control path only


Proposed layout — all hot fields in cache line 1:

For efa-direct (48 bytes, single cache line):
Cache line 1:
  [0-31]  ep_addr[32]   ← qpn at +16, qkey at +20 (TX hot)
  [32-39] ah*           ← TX hot
  [40-47] fi_addr       ← RX hot ✓ (moved from cache line 2)


For efa-protocol (104 bytes):
Cache line 1 (64 bytes):
  [0-31]  ep_addr[32]        ← TX hot
  [32-39] ah*                ← TX hot
  [40-47] fi_addr            ← RX hot ✓
  [48-55] implicit_fi_addr   ← CQ progress hot
  [56-63] shm_fi_addr        ← SHM TX path

Cache line 2 (40 bytes, cold):
  [64-79]  implicit_av_lru_entry      ← control path only
  [80-95]  ah_implicit_conn_list      ← control path only
  [96-103] ep_peer_map*               ← control path only


This eliminates the wasted ep_addr* pointer, moves fi_addr into cache line 1, and reduces entry size from 120 bytes to 48 bytes (efa-direct) or 104 bytes (protocol).

Note: util_av requires ep_addr to be the first field in the entry data. Both structs satisfy this constraint. The context_len passed to ofi_av_init() differs between the two paths.

### 2.3 Locking Design

4 locks participate in AV operations. Lock ordering (must be consistent to avoid deadlocks):
srx_lock  →  util_av_implicit.lock  →  util_av.lock  →  domain->util_domain.lock
(outermost)                                                (innermost)


| Lock | What it protects | Used by |
|------|-----------------|---------|
| domain->srx_lock | Shared receive context — peer structs, peer maps, coordinates CQ read vs AV insert/remove | RDM only |
| av->util_av_implicit.lock | Implicit AV entries (buffer pool, hash, implicit reverse AV maps) | RDM only |
| av->util_av.lock | Explicit AV entries (buffer pool, hash, reverse AV maps) | Both |
| domain->util_domain.lock | AH map (domain->ah_map), AH alloc/release/eviction | Both |

Both efa-direct and rdm are FI_THREAD_SAFE — all fi_ops control path entry points (fi_av_insert, fi_av_remove, fi_av_lookup, fi_av_close) must be safe for N concurrent threads.

Locking rules after refactoring:
1. Base efa_av fi_ops entry points (efa_av_insert, efa_av_remove, efa_av_lookup, efa_av_close) are fully thread-safe. They acquire util_av.lock internally.
2. efa_proto_av fi_ops entry points (efa_proto_av_insert, efa_proto_av_remove, efa_proto_av_close) are fully thread-safe. They acquire the full lock chain (srx_lock → util_av_implicit.lock → util_av.lock) and
call internal helpers that assume locks are held. They do NOT call the base fi_ops entry points (which would double-acquire util_av.lock).
3. Internal helpers (e.g., ofi_av_insert_addr, efa_av_entry_init, efa_av_reverse_av_add) document their locking preconditions via comments and assert(ofi_genlock_held(...)) but do not acquire locks themselves.
Both base fi_ops and proto fi_ops call these same helpers.
4. efa_ah_alloc / efa_ah_release acquire domain->util_domain.lock internally — they are always the innermost lock acquisition.

Locking per operation after refactoring:

| Operation | efa-direct locks | rdm locks |
|-----------|-----------------|-----------|
| fi_av_open | None | None |
| fi_av_insert | util_av.lock → util_domain.lock (via ah_alloc) | srx_lock → util_av_implicit.lock → util_av.lock → util_domain.lock (via ah_alloc) |
| fi_av_remove | util_av.lock → util_domain.lock (via ah_release) | srx_lock → util_av.lock → util_domain.lock (via ah_release) |
| fi_av_lookup | util_av.lock | util_av.lock (explicit only) |
| fi_av_close | util_av.lock → util_domain.lock | srx_lock → util_av.lock → util_domain.lock, then util_av_implicit.lock → util_domain.lock |
| CQ read (implicit insert) | N/A | srx_lock (already held) → util_av_implicit.lock → util_av.lock → util_domain.lock |

Full lock trace for fi_av_insert (rdm):
efa_proto_av_insert                          [fi_ops entry point, thread-safe]
  ├─ LOCK srx_lock
  ├─ for each address:
  │    └─ efa_proto_av_insert_one            [internal, assumes srx_lock held]
  │         ├─ LOCK util_av_implicit.lock
  │         ├─ LOCK util_av.lock
  │         ├─ ofi_av_lookup_fi_addr_unsafe  [no lock, util_av.lock held]
  │         ├─ ofi_av_lookup_fi_addr_unsafe  [no lock, util_av_implicit.lock held]
  │         ├─ [if implicit→explicit]:
  │         │    └─ efa_proto_av_entry_implicit_to_explicit
  │         │         └─ LOCK util_av.ep_list_lock (for foreach_unspec_addr)
  │         ├─ [if new address]:
  │         │    └─ efa_av_entry_init        [internal, assumes util_av.lock held]
  │         │         └─ efa_ah_alloc
  │         │              └─ LOCK util_domain.lock  ← innermost
  │         │    └─ efa_proto_av_entry_init_shm / efa_proto_av_entry_init_implicit
  │         ├─ UNLOCK util_av.lock
  │         └─ UNLOCK util_av_implicit.lock
  └─ UNLOCK srx_lock


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


## 3. Implementation Phases

### Phase 1: Eliminate efa_conn, fold fields into efa_av_entry

Goal: Remove the unnecessary efa_conn abstraction. Fold its fields directly into efa_av_entry (efa-direct) and the new efa_proto_av_entry (protocol).

Steps:

1. Restructure struct efa_av_entry in efa_av.h:
   - Move ah, fi_addr from efa_conn directly into efa_av_entry
   - Remove the struct efa_conn conn member
   - ep_addr stays as the first field (required by util_av)
   - The ep_addr pointer that was in efa_conn is no longer needed — callers use efa_av_entry_ep_addr(entry) helper

2. Create struct efa_proto_av_entry in new header rdm/efa_proto_av.h:
   - Flat layout with same field prefix as efa_av_entry (ep_addr, ah, fi_addr)
   - Add protocol-specific fields: implicit_fi_addr, shm_fi_addr, implicit_av_lru_entry, ah_implicit_conn_list_entry, ep_peer_map
   - Fields ordered for cache line optimization (hot fields in cache line 1)

3. Replace efa_av_addr_to_conn() with efa_av_addr_to_entry():
   - Returns struct efa_av_entry * instead of struct efa_conn *
   - All efa-direct callers (efa_msg.c, efa_rma.c, efa_base_ep.c) change from conn->ah to entry->ah, conn->ep_addr->qpn to efa_av_entry_ep_addr(entry)->qpn

4. Update efa_rdm_peer struct:
   - Change struct efa_conn *conn to struct efa_proto_av_entry *av_entry
   - All rdm callers change from peer->conn->ah to peer->av_entry->ah, peer->conn->shm_fi_addr to peer->av_entry->shm_fi_addr, etc.

5. Absorb efa_conn.c functions:
   - efa_conn_alloc() base logic → efa_av_entry_init() in efa_av.c (AH alloc, reverse AV add)
   - efa_conn_release() base logic → efa_av_entry_release() in efa_av.c
   - efa_conn_rdm_insert_shm_av(), efa_conn_rdm_deinit(), efa_conn_ep_peer_map_*(), efa_conn_implicit_to_explicit() → move to rdm/efa_proto_av.c
   - Delete efa_conn.h and efa_conn.c

Files modified:
- efa_av.h — restructure efa_av_entry, new efa_av_addr_to_entry(), add efa_av_entry_ep_addr() helper
- efa_av.c — absorb conn alloc/release logic
- Delete: efa_conn.h, efa_conn.c
- New: rdm/efa_proto_av.h — struct efa_proto_av_entry (also used by Phase 2)
- New: rdm/efa_proto_av.c — protocol-specific entry init/release/shm/peer functions
- All callers of efa_av_addr_to_conn() — mechanical update (~20 files)
- rdm/efa_rdm_peer.h — efa_conn *conn → efa_proto_av_entry *av_entry

Validation: Compile check. Existing unit tests pass.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Phase 2: Separate efa_av and efa_proto_av structs

Goal: Split struct efa_av into efa-direct and efa-protocol versions.

Steps:

1. Create struct efa_proto_av in rdm/efa_proto_av.h:
   - Embed struct efa_av as first member (castable)
   - Move shm_rdm_av, util_av_implicit, cur_reverse_av_implicit, prv_reverse_av_implicit, implicit_av_size, implicit_av_lru_list, evicted_peers_hashset, used_implicit, shm_used from efa_av

2. Slim down struct efa_av in efa_av.h:
   - Keep only: util_av, domain, used, type, cur_reverse_av, prv_reverse_av
   - Remove #include "rdm/efa_rdm_protocol.h" and #include "rdm/efa_rdm_peer.h"

3. Split efa_av_open():
   - efa_av_open() — efa-direct fi_ops entry point: allocates struct efa_av, calls efa_av_init() to initialize util_av (with context_len = sizeof(efa_av_entry) - EFA_EP_ADDR_LEN), sets up reverse AV. No shm AV,
no implicit AV. No locks acquired (construction path).
   - efa_av_init() — takes pre-allocated efa_av *, initializes fields. Used by both efa_av_open and efa_proto_av_open.
   - efa_proto_av_open() — efa-protocol fi_ops entry point in rdm/efa_proto_av.c: allocates struct efa_proto_av, calls efa_av_init() for the embedded efa_av (with
context_len = sizeof(efa_proto_av_entry) - EFA_EP_ADDR_LEN), then initializes implicit util_av, shm AV, LRU list.

4. Split efa_av_close():
   - efa_av_close() — efa-direct fi_ops entry point (thread-safe): acquires util_av.lock, releases all explicit reverse AV entries (which internally acquires util_domain.lock via efa_ah_release), calls
ofi_av_close, frees efa_av.
   - efa_av_close_internal() — assumes locks are held, does not free memory. Used by efa_proto_av_close.
   - efa_proto_av_close() — efa-protocol fi_ops entry point (thread-safe): acquires srx_lock → util_av.lock for explicit cleanup, then util_av_implicit.lock for implicit cleanup, closes SHM AV, evicted peers
hashset, calls efa_av_close_internal() for the embedded base, frees efa_proto_av.

5. Wire separate fi_ops_av and fi_ops structs:
   - efa-direct uses efa_av_fi_ops / efa_av_ops
   - efa-protocol uses efa_proto_av_fi_ops / efa_proto_av_ops

Files modified:
- efa_av.h — slim down struct, remove RDM includes
- efa_av.c — remove RDM branching, add efa_av_init() / efa_av_close_internal()
- rdm/efa_proto_av.h — struct efa_proto_av
- rdm/efa_proto_av.c — protocol AV open/close

Validation: Compile check. Unit tests pass.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Phase 3: Separate AV insert/remove operations

Goal: Split the AV insert and remove paths to eliminate fabric branching.

Steps:

1. Create efa_av_entry_init() in efa_av.c:
   - Internal helper, caller must hold util_av.lock
   - Core init logic: validate address, ofi_av_insert_addr(), set ah/fi_addr, efa_av_reverse_av_add()
   - No locking, no implicit AV check, no shm insertion, no info_type branching
   - Documents locking precondition via comment and assert(ofi_genlock_held(...))

2. Create efa_av_insert() — efa-direct fi_ops entry point (thread-safe):
   - Acquires util_av.lock
   - Simple loop calling efa_av_entry_init() per address
   - No srx_lock, no implicit AV parameters

3. Create efa_proto_av_insert_one() in rdm/efa_proto_av.c:
   - Internal helper, assumes srx_lock held
   - Acquires util_av_implicit.lock → util_av.lock
   - Checks explicit AV first, then implicit AV for existing entry
   - Handles implicit-to-explicit migration (efa_proto_av_entry_implicit_to_explicit())
   - Calls efa_av_entry_init() for the actual hardware-level insert (does NOT call efa_av_insert fi_ops — would double-acquire util_av.lock)
   - Handles shm AV insertion, implicit AV LRU management

4. Create efa_proto_av_insert() — efa-protocol fi_ops entry point (thread-safe):
   - Acquires srx_lock at the batch level
   - Calls efa_proto_av_insert_one() per address

5. Similarly split remove:
   - efa_av_remove() — efa-direct fi_ops (thread-safe): acquires util_av.lock, calls efa_av_entry_release()
   - efa_proto_av_remove() — efa-protocol fi_ops (thread-safe): acquires srx_lock → util_av.lock, calls efa_proto_av_entry_release() (which handles peer map cleanup, SHM removal, then calls base release)

6. Move efa_conn_implicit_to_explicit() to rdm/efa_proto_av.c as efa_proto_av_entry_implicit_to_explicit():
   - Purely protocol logic (peer map migration, SRX foreach_unspec_addr)

Files modified:
- efa_av.c — clean insert/remove with efa_av_entry_init() / efa_av_entry_release()
- rdm/efa_proto_av.c — protocol insert/remove with implicit AV logic, implicit-to-explicit migration

Validation: Unit tests for AV insert/remove. test_av_implicit_to_explicit, test_av_implicit_av_lru_insertion, test_av_implicit_av_lru_eviction.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


### Phase 4: Separate reverse lookup functions

Goal: Move protocol-specific reverse lookup to efa-protocol layer.

Steps:

1. Keep in efa_av.c (efa-direct):
   - efa_av_reverse_lookup() — simple (AHN, QPN) → fi_addr lookup, used by efa-direct CQ
   - efa_av_reverse_av_add() / efa_av_reverse_av_remove() — operate on explicit reverse AV only

2. Move to rdm/efa_proto_av.c (efa-protocol):
   - efa_proto_av_reverse_lookup() — checks explicit AV first, then implicit AV. Uses connid from pkt_entry for QPN collision resolution. Asserts srx_lock held.
   - efa_proto_av_reverse_lookup_implicit() — implicit AV reverse lookup with LRU update. Asserts srx_lock held.
   - The internal helper efa_av_reverse_lookup_rdm_conn() moves here since it depends on efa_rdm_pke (RDM packet entry)

3. Update callers in rdm/efa_rdm_cq.c:
   - efa_av_reverse_lookup_rdm() → efa_proto_av_reverse_lookup()
   - efa_av_reverse_lookup_rdm_implicit() → efa_proto_av_reverse_lookup_implicit()
   - efa_av_insert_one(..., insert_implicit_av=true) → efa_proto_av_insert_one(..., implicit=true)

4. Update efa_rdm_cq_get_peer_for_pkt_entry() and efa_rdm_cq_lookup_raw_addr() to use efa_proto_av instead of efa_av for implicit AV access.

Files modified:
- efa_av.h / efa_av.c — remove protocol-specific reverse lookup functions
- rdm/efa_proto_av.h / rdm/efa_proto_av.c — add protocol reverse lookup