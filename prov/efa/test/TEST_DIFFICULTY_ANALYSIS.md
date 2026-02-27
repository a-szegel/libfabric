# EFA Unit Test Analysis: Difficulty & Implementation Strategy

## Test Categories by Difficulty

### ✅ EASIEST: Info Query Tests (40+ tests)
**What they test**: fi_getinfo() with various hints and verify returned attributes
**What they need**: Only device mocking (already complete)
**Why easy**: No resource construction, just query and validate

**Examples**:
- `test_info_tx_rx_msg_order_rdm_order_none` - Check message ordering attributes
- `test_info_tx_rx_msg_order_rdm_order_sas` - Check SAS ordering
- `test_info_tx_rx_op_flags_rdm` - Check operation flags
- `test_info_tx_rx_size_rdm` - Check tx/rx size attributes
- `test_info_max_order_size_*` - Check max order size
- `test_info_direct_*` - Check efa-direct attributes

**Implementation**: 
```cpp
TEST_F(EfaUnitTestInfo, test_info_tx_rx_msg_order_rdm_order_none) {
    SetUpDevice();
    struct fi_info *hints = efa_unit_test_alloc_hints(FI_EP_RDM, "efa");
    struct fi_info *info;
    
    int err = fi_getinfo(FI_VERSION(1,14), NULL, NULL, 0, hints, &info);
    ASSERT_EQ(err, 0);
    EXPECT_EQ(info->tx_attr->msg_order, hints->tx_attr->msg_order);
    EXPECT_EQ(info->rx_attr->msg_order, hints->rx_attr->msg_order);
    
    fi_freeinfo(info);
    fi_freeinfo(hints);
}
```

**Estimated effort**: 1-2 hours for all 40 tests (mostly copy-paste from cmocka)

---

### 🟡 MEDIUM: Resource Construction Tests (50+ tests)
**What they test**: fi_fabric(), fi_domain(), fi_endpoint() construction
**What they need**: Mock resource allocation + basic state tracking

**Examples**:
- `test_efa_ep_bind_and_enable` - Bind CQ/AV to EP and enable
- `test_efa_ep_getopt/setopt` - Get/set endpoint options
- `test_efa_domain_*` - Domain creation and configuration
- `test_efa_mr_reg_*` - Memory registration tests

**Problems**:
1. Need to track resource state (fabric → domain → endpoint hierarchy)
2. Need to validate bind operations (EP must bind CQ, AV before enable)
3. Need to implement fi_enable() logic

**Solutions**:
1. Create resource tracking in test fixture:
```cpp
class EfaUnitTestWithResources : public EfaUnitTestWithDevice {
protected:
    struct fid_fabric *fabric = nullptr;
    struct fid_domain *domain = nullptr;
    struct fid_ep *ep = nullptr;
    struct fid_av *av = nullptr;
    struct fid_cq *cq = nullptr;
    
    void SetUpResources() {
        SetUpDevice();
        ASSERT_EQ(fi_fabric(info->fabric_attr, &fabric, NULL), 0);
        ASSERT_EQ(fi_domain(fabric, info, &domain, NULL), 0);
    }
};
```

2. Mock fi_enable() to validate bindings:
```c
int __wrap_fi_enable(struct fid_ep *ep) {
    // Check that CQ and AV are bound
    // Set EP state to enabled
    return 0;
}
```

**Estimated effort**: 4-6 hours (need resource tracking infrastructure)

---

### 🟠 HARD: Data Path Tests (100+ tests)
**What they test**: Send/recv operations, completion generation, packet processing
**What they need**: Mock data path + completion queue simulation

**Examples**:
- `test_efa_rdm_msg_send_*` - Send message operations
- `test_efa_rdm_pke_*` - Packet entry processing
- `test_efa_rdm_ope_*` - Operation entry management
- `test_efa_cq_*` - Completion queue operations

**Problems**:
1. Need to simulate send/recv operations
2. Need to generate completions in CQ
3. Need to track packet state machines
4. Need to simulate peer interactions

**Solutions**:
1. Create mock CQ with completion queue:
```cpp
struct MockCQ {
    std::queue<struct fi_cq_data_entry> completions;
    
    void AddCompletion(uint64_t flags, void *op_context) {
        completions.push({.flags = flags, .op_context = op_context});
    }
};
```

2. Mock ibv_start_poll to return completions:
```c
int __wrap_ibv_start_poll(struct ibv_cq_ex *cq, struct ibv_poll_cq_attr *attr) {
    MockCQ *mock_cq = get_mock_cq(cq);
    if (mock_cq->completions.empty()) return ENOENT;
    mock_cq->current = mock_cq->completions.front();
    return 0;
}
```

3. Mock send/recv to generate completions:
```c
int __wrap_ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, ...) {
    // Add send completion to CQ
    add_completion(qp->send_cq, wr->wr_id, IBV_WC_SEND);
    return 0;
}
```

**Estimated effort**: 2-3 days (complex state management)

---

### 🔴 HARDEST: Protocol Tests (50+ tests)
**What they test**: RDM protocol logic, RMA operations, multi-packet messages
**What they need**: Full protocol simulation with peer state

**Examples**:
- `test_efa_rdm_pke_proc_matched_mulreq_rtm_*` - Multi-request RTM processing
- `test_efa_rdm_rma_*` - RMA read/write operations
- `test_efa_rdm_peer_*` - Peer management and handshake
- `test_efa_rnr_*` - RNR (Receiver Not Ready) handling

**Problems**:
1. Need to simulate multi-packet message fragmentation/reassembly
2. Need to track peer state (handshake, credits, etc.)
3. Need to simulate RMA operations (read/write with remote keys)
4. Need to handle error conditions (RNR, timeouts)
5. Need to simulate packet reordering and retransmission

**Solutions**:
1. Create peer simulator:
```cpp
class PeerSimulator {
    std::map<fi_addr_t, PeerState> peers;
    
    void SimulateHandshake(fi_addr_t addr);
    void SimulateRNR(fi_addr_t addr);
    void SimulatePacketLoss(int percentage);
};
```

2. Create packet simulator:
```cpp
class PacketSimulator {
    void FragmentMessage(void *buf, size_t len, std::vector<Packet> &packets);
    void ReassembleMessage(std::vector<Packet> &packets, void *buf);
    void SimulateReorder(std::vector<Packet> &packets);
};
```

3. Mock RMA operations:
```c
int __wrap_ibv_post_send_rdma_read(struct ibv_qp *qp, ...) {
    // Simulate remote memory read
    // Copy from remote peer's memory
    // Generate completion
}
```

**Estimated effort**: 1-2 weeks (requires deep protocol understanding)

---

## Recommended Implementation Order

### Phase 1: Quick Wins (1-2 hours)
Implement all **Info Query Tests** - these are trivial and give immediate test count boost.

**Files to modify**:
- `prov/efa/test/unittest/efa_unit_test_info.cpp`

**Pattern**:
```cpp
TEST_F(EfaUnitTestInfo, test_name) {
    SetUpDevice();
    struct fi_info *hints = efa_unit_test_alloc_hints(FI_EP_RDM, "efa");
    // Set hint attributes
    struct fi_info *info;
    int err = fi_getinfo(FI_VERSION(1,14), NULL, NULL, 0, hints, &info);
    // Validate info attributes
    fi_freeinfo(info);
    fi_freeinfo(hints);
}
```

### Phase 2: Resource Infrastructure (4-6 hours)
Create resource construction fixture and implement **Resource Construction Tests**.

**New infrastructure needed**:
1. `EfaUnitTestWithResources` fixture class
2. Resource cleanup in TearDown
3. Helper functions for common resource patterns

### Phase 3: Data Path (2-3 days)
Implement mock CQ and basic send/recv for **Data Path Tests**.

**New infrastructure needed**:
1. Mock CQ with completion queue
2. Mock send/recv operations
3. Packet entry tracking

### Phase 4: Protocol (1-2 weeks)
Implement full protocol simulation for **Protocol Tests**.

**New infrastructure needed**:
1. Peer simulator
2. Packet simulator
3. RMA operation mocks
4. Error injection framework

---

## Summary

| Category | Count | Difficulty | Effort | Blocker |
|----------|-------|------------|--------|---------|
| Info Query | 40 | ✅ Easy | 1-2 hours | None |
| Resource Construction | 50 | 🟡 Medium | 4-6 hours | Resource tracking |
| Data Path | 100 | 🟠 Hard | 2-3 days | CQ simulation |
| Protocol | 50 | 🔴 Hardest | 1-2 weeks | Protocol knowledge |

**Total**: 240 skipped tests (out of 352 total)

**Recommendation**: Start with Phase 1 (Info Query Tests) for immediate impact. These tests are already passing in cmocka and just need to be ported to gtest format.
