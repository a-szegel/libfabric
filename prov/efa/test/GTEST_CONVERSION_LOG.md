# EFA Unit Test Conversion: CMocka to GoogleTest/GoogleMock

## Conversion Date: 2026-02-26

## Objective
Convert all cmocka-based unit tests in ~/libfabric/prov/efa/test to GoogleTest/GoogleMock with full rdma-core mocking to eliminate EFA device dependency.

## Reference
- PR: https://github.com/a-szegel/aws-ofi-nccl/pull/2

## Progress Status

### Phase 1: Infrastructure Setup ✓ COMPLETE
- [x] Created rdma_core_mocks.h - Mock all ibv_* and efadv_* functions
- [x] Created rdma_core_mocks.cpp - Implementation with direct symbol replacement
- [x] Created efa_mocks.h - Mock EFA internal functions  
- [x] Created efa_mocks.cpp - Implementation with linker wrapping
- [x] Created base test fixture (efa_unit_test_base.h)
- [x] Created common test utilities (efa_unit_test_base.cpp)

### Phase 2: Build System Integration ✓ COMPLETE
- [x] Created m4/check_gtest.m4 - Autoconf macro for GoogleTest detection
- [x] Updated prov/efa/configure.m4 - Add GoogleTest configuration
- [x] Updated prov/efa/Makefile.include - Add gtest build rules with --wrap flags

### Phase 3: Test File Conversion (19 files total)

#### Converted Files (3/19) ✓
1. [x] efa_unit_test_device.c → efa_unit_test_device_test.cpp (DONE)
2. [x] efa_unit_test_fork_support.c → efa_unit_test_fork_support_test.cpp (DONE)
3. [x] efa_unit_test_send.c → efa_unit_test_send_test.cpp (DONE)

#### Remaining Files (16/19) - READY TO CONVERT
4. [ ] efa_unit_test_hmem.c (3KB, ~90 lines) - HMEM tests **START HERE - SMALLEST**
5. [ ] efa_unit_test_srx.c (5KB, ~135 lines) - Shared receive context tests
6. [ ] efa_unit_test_cntr.c (6KB, ~170 lines) - Counter tests
7. [ ] efa_unit_test_msg.c (7KB, ~190 lines) - Message tests
8. [ ] efa_unit_test_rma.c (8KB, ~230 lines) - RMA tests
9. [ ] efa_unit_test_rdm_rma.c (9KB, ~240 lines) - RDM RMA tests
10. [ ] efa_unit_test_runt.c (13KB, ~350 lines) - Runt packet tests
11. [ ] efa_unit_test_mr.c (15KB, ~400 lines) - Memory region tests
12. [ ] efa_unit_test_rdm_peer.c (15KB, ~400 lines) - RDM peer tests
13. [ ] efa_unit_test_domain.c (16KB, ~430 lines) - Domain tests
14. [ ] efa_unit_test_pke.c (17KB, ~450 lines) - Packet entry tests
15. [ ] efa_unit_test_info.c (31KB, ~850 lines) - Info tests
16. [ ] efa_unit_test_av.c (31KB, ~800 lines) - Address vector tests
17. [ ] efa_unit_test_ope.c (44KB, ~1200 lines) - Operation tests
18. [ ] efa_unit_test_ep.c (76KB, ~2100 lines) - Endpoint tests **SECOND LARGEST**
19. [ ] efa_unit_test_cq.c (91KB, ~2500 lines) - Completion queue tests **LARGEST**

### Phase 4: Main Test Runner ✓ COMPLETE
- [x] Created efa_gtest_main.cpp - GoogleTest main with setup/teardown

### Phase 5: Documentation ✓ COMPLETE
- [x] Created GTEST_README.md - Developer guide for writing/running tests
- [x] Created GTEST_CONVERSION_LOG.md - This file

### Phase 6: Cleanup (After all conversions)
- [ ] Remove old cmocka test files
- [ ] Remove efa_unit_tests.h (cmocka header)
- [ ] Remove efa_unit_tests.c (cmocka main)
- [ ] Remove efa_unit_test_mocks.h (cmocka mocks)
- [ ] Remove efa_unit_test_mocks.c (cmocka mock implementations)
- [ ] Update configure.m4 to remove cmocka dependency
- [ ] Update Makefile.include to remove cmocka build rules

## Key Conversion Patterns

### CMocka → GoogleTest Mapping
```c
// CMocka
void test_function(void **state) {
    struct efa_resource *resource = *state;
    assert_int_equal(x, y);
    assert_non_null(ptr);
}

// GoogleTest
TEST_F(EfaUnitTest, TestFunction) {
    EXPECT_EQ(x, y);
    EXPECT_NE(ptr, nullptr);
}
```

### Mock Setup Pattern
```c
// CMocka
g_efa_unit_test_mocks.ibv_create_ah = &efa_mock_ibv_create_ah_return_null;
will_return(efa_mock_ibv_create_ah_return_null, NULL);

// GoogleTest
EXPECT_CALL(*rdma_mock, ibv_create_ah(_, _))
    .WillOnce(Return(nullptr));
```

### Resource Management
```c
// CMocka - uses global state and setup/teardown
static int setup(void **state) { ... }
static int teardown(void **state) { ... }

// GoogleTest - uses test fixture
class EfaUnitTest : public ::testing::Test {
protected:
    void SetUp() override { ... }
    void TearDown() override { ... }
    struct efa_resource resource;
};
```

## Build Commands

### Configure with GoogleTest
```bash
./autogen.sh
./configure --enable-gtest --with-libfabric=/opt/amazon/efa
make -j$(nproc)
```

### Run Tests
```bash
# Run all GoogleTest tests
make check

# Run specific test
./prov/efa/test/efa_unit_test_device_test

# Run with filter
./prov/efa/test/efa_unit_test_device_test --gtest_filter="*ErrorHandling*"
```

## Notes

### Mocking Strategy
- All rdma-core functions (ibv_*, efadv_*) are mocked via direct symbol replacement
- EFA internal functions use --wrap linker flag for interception
- No real EFA device required - all hardware interactions are mocked

### Test Isolation
- Each test runs in isolated fixture with fresh mocks
- No shared state between tests
- Proper cleanup in TearDown() prevents resource leaks

### Current Blockers
- None - infrastructure complete, conversion in progress

## Next Steps
1. Continue converting remaining test files (prioritize by size: smallest first)
2. Verify each converted test compiles and passes
3. Remove old cmocka files after all conversions complete
4. Update CI/CD to use GoogleTest instead of cmocka
