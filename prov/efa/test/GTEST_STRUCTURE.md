# GoogleTest Structure - Organized to Match Cmocka

## Overview

The GoogleTest unit tests are now organized to match the original cmocka test structure with 1-1 file mapping.

## File Structure

### Core Files
- `efa_unit_test_common.hpp` - Common header with mock infrastructure and base test class
- `efa_unit_test_mocks_gtest.cpp` - C wrapper functions for rdma-core mocking
- `efa_unit_test_main_gtest.cpp` - Main test runner

### Test Files (1-1 mapping with cmocka)

| Cmocka File | GoogleTest File | Test Class | Tests |
|-------------|-----------------|------------|-------|
| efa_unit_test_device.c | efa_unit_test_device_gtest.cpp | EfaUnitTestDevice | 1 |
| efa_unit_test_fork_support.c | efa_unit_test_fork_support_gtest.cpp | EfaUnitTestForkSupport | 2 |
| efa_unit_test_send.c | efa_unit_test_send_gtest.cpp | EfaUnitTestSend | 1 |

### To Be Added
- efa_unit_test_av_gtest.cpp → EfaUnitTestAv
- efa_unit_test_cntr_gtest.cpp → EfaUnitTestCntr
- efa_unit_test_cq_gtest.cpp → EfaUnitTestCq
- efa_unit_test_data_path_direct_gtest.cpp → EfaUnitTestDataPathDirect
- efa_unit_test_domain_gtest.cpp → EfaUnitTestDomain
- efa_unit_test_ep_gtest.cpp → EfaUnitTestEp
- efa_unit_test_hmem_gtest.cpp → EfaUnitTestHmem
- efa_unit_test_info_gtest.cpp → EfaUnitTestInfo
- efa_unit_test_mr_gtest.cpp → EfaUnitTestMr
- efa_unit_test_msg_gtest.cpp → EfaUnitTestMsg
- efa_unit_test_ope_gtest.cpp → EfaUnitTestOpe
- efa_unit_test_pke_gtest.cpp → EfaUnitTestPke
- efa_unit_test_rdm_peer_gtest.cpp → EfaUnitTestRdmPeer
- efa_unit_test_rdm_rma_gtest.cpp → EfaUnitTestRdmRma
- efa_unit_test_rma_gtest.cpp → EfaUnitTestRma
- efa_unit_test_rnr_gtest.cpp → EfaUnitTestRnr
- efa_unit_test_runt_gtest.cpp → EfaUnitTestRunt
- efa_unit_test_srx_gtest.cpp → EfaUnitTestSrx

## Naming Convention

### Test Class Names
- Format: `EfaUnitTest<Module>`
- Example: `EfaUnitTestDevice`, `EfaUnitTestForkSupport`
- Matches the filename without the `efa_unit_test_` prefix and `_gtest.cpp` suffix

### Test Function Names
- Keep original cmocka test names
- Format: `test_<original_name>`
- Example: `test_efa_device_construct_error_handling`
- Example: `test_efa_fork_support_request_initialize_when_ibv_fork_support_is_needed`

## Example Test File Structure

```cpp
#include "efa_unit_test_common.hpp"

// Test class for <module> tests
class EfaUnitTest<Module> : public EfaUnitTestBase {
};

TEST_F(EfaUnitTest<Module>, test_<original_test_name>) {
    // Test implementation with proper argument validation
    // Use EXPECT_CALL with Invoke to validate all arguments
    // Use ASSERT/EXPECT for result validation
}
```

## Common Header (efa_unit_test_common.hpp)

Contains:
- GoogleTest/GoogleMock includes
- rdma-core header includes with macro undefs
- RdmaCoreMock class with all MOCK_METHOD declarations
- EfaUnitTestBase fixture class
- Common using declarations

## Mock Wrapper (efa_unit_test_mocks_gtest.cpp)

Contains:
- Global mock pointer definition
- All `__wrap_*` functions that delegate to RdmaCoreMock
- Handles null mock pointer gracefully

## Build System

Makefile.include updated to:
- List all test source files individually
- Include common header directory in CPPFLAGS
- Link with GTEST_LIBS and GTEST_WRAP_FLAGS

## Benefits of This Structure

1. **Easy Navigation**: Each test file corresponds to original cmocka file
2. **Clear Organization**: Test classes group related tests
3. **Maintainability**: Easy to find and update specific tests
4. **Scalability**: Simple to add new test files
5. **Traceability**: Test names match original for easy comparison
6. **Modularity**: Each file can be developed/tested independently

## Current Status

- ✅ Infrastructure complete
- ✅ 3 test files created (device, fork_support, send)
- ✅ 4 tests passing
- ⏳ 18 test files remaining to create
- ⏳ 370 tests remaining to migrate

## Next Steps

1. Create remaining test files following the same pattern
2. Extract test function names from original cmocka files
3. Implement tests with proper argument validation
4. Add to Makefile.include SOURCES list
5. Build and verify all tests pass
