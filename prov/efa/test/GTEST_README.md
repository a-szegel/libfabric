# EFA Provider GoogleTest Unit Testing Framework

## Overview

This directory contains GoogleTest/GoogleMock-based unit tests for the EFA provider with complete rdma-core mocking. Tests run without requiring actual EFA hardware.

## Quick Start

### Install GoogleTest

```bash
# Ubuntu/Debian
sudo apt-get install libgtest-dev libgmock-dev

# RHEL/Amazon Linux
sudo yum install gtest-devel gmock-devel
```

### Build and Run

```bash
cd ~/libfabric
./autogen.sh
./configure --enable-gtest
make -j$(nproc)
make check
```

### Run Specific Tests

```bash
# Run all gtest tests
./prov/efa/test/efa_unit_test_device_test
./prov/efa/test/efa_unit_test_fork_support_test
./prov/efa/test/efa_unit_test_send_test

# Run with filter
./prov/efa/test/efa_unit_test_device_test --gtest_filter="*ErrorHandling*"

# Run with verbose output
./prov/efa/test/efa_unit_test_device_test --gtest_verbose
```

## Architecture

### Mock Framework

**rdma_core_mocks.h/cpp** - Mocks all rdma-core functions (ibv_*, efadv_*)
**efa_mocks.h/cpp** - Mocks EFA internal functions
**efa_unit_test_base.h/cpp** - Base test fixture with setup/teardown

### Test Structure

```cpp
#include "efa_unit_test_base.h"

class MyTest : public EfaUnitTest {};

TEST_F(MyTest, TestName) {
    // Setup mocks
    EXPECT_CALL(*rdma_mock, ibv_create_ah(_, _))
        .WillOnce(Return(nullptr));
    
    // Run test
    int ret = my_function();
    
    // Verify
    EXPECT_EQ(ret, -ENOMEM);
}
```

## Writing Tests

### Basic Test

```cpp
TEST_F(EfaUnitTest, MyTest) {
    EXPECT_CALL(*rdma_mock, ibv_get_device_list(_))
        .WillOnce(Return(nullptr));
    
    int ret = efa_device_construct(&device, 0);
    EXPECT_NE(ret, 0);
}
```

### Mock Return Values

```cpp
// Return simple value
EXPECT_CALL(*rdma_mock, ibv_is_fork_initialized())
    .WillOnce(Return(IBV_FORK_DISABLED));

// Set output parameter
struct ibv_device *devices[] = {&mock_device, nullptr};
EXPECT_CALL(*rdma_mock, ibv_get_device_list(_))
    .WillOnce(DoAll(SetArgPointee<0>(1), Return(devices)));
```

### Resource Construction

```cpp
TEST_F(EfaUnitTest, TestWithResource) {
    ConstructResource(FI_EP_RDM, "efa");
    
    // resource.ep, resource.domain, etc. are now available
    ASSERT_NE(resource.ep, nullptr);
    
    // Cleanup happens automatically in TearDown()
}
```

## Converting from CMocka

### Assertions

| CMocka | GoogleTest |
|--------|------------|
| `assert_int_equal(a, b)` | `EXPECT_EQ(a, b)` |
| `assert_int_not_equal(a, b)` | `EXPECT_NE(a, b)` |
| `assert_null(ptr)` | `EXPECT_EQ(ptr, nullptr)` |
| `assert_non_null(ptr)` | `EXPECT_NE(ptr, nullptr)` |
| `assert_true(x)` | `EXPECT_TRUE(x)` |
| `assert_false(x)` | `EXPECT_FALSE(x)` |

### Mocks

```c
// CMocka
g_efa_unit_test_mocks.ibv_create_ah = &mock_function;
will_return(mock_function, NULL);

// GoogleTest
EXPECT_CALL(*rdma_mock, ibv_create_ah(_, _))
    .WillOnce(Return(nullptr));
```

### Test Structure

```c
// CMocka
void test_function(void **state) {
    struct efa_resource *resource = *state;
    // test code
}

// GoogleTest
TEST_F(EfaUnitTest, FunctionName) {
    // resource is member variable
    // test code
}
```

## Mocked Functions

### rdma-core (rdma_core_mocks.h)
- `ibv_*` - All verbs functions (create_ah, destroy_ah, open_device, etc.)
- `efadv_*` - All EFA device verbs (query_device, create_cq, etc.)

### EFA Internal (efa_mocks.h)
- `efa_ah_alloc`, `efa_ah_release`
- `efa_qp_post_*` - QP operations
- `efa_ibv_cq_*` - CQ operations
- `efa_rdm_pke_*` - Packet entry operations
- `efa_rdm_ope_*` - Operation entry functions

## Adding New Tests

1. Create test file: `efa_unit_test_<module>_test.cpp`
2. Include base fixture: `#include "efa_unit_test_base.h"`
3. Define test class: `class MyModuleTest : public EfaUnitTest {};`
4. Write tests: `TEST_F(MyModuleTest, TestName) { ... }`
5. Add to Makefile.include:

```makefile
noinst_PROGRAMS += prov/efa/test/efa_unit_test_<module>_test
TESTS += prov/efa/test/efa_unit_test_<module>_test

prov_efa_test_efa_unit_test_<module>_test_SOURCES = \
    prov/efa/test/efa_gtest_main.cpp \
    prov/efa/test/efa_unit_test_base.cpp \
    prov/efa/test/rdma_core_mocks.cpp \
    prov/efa/test/efa_mocks.cpp \
    prov/efa/test/efa_unit_test_<module>_test.cpp
prov_efa_test_efa_unit_test_<module>_test_CPPFLAGS = $(efa_CPPFLAGS) $(GTEST_CPPFLAGS)
prov_efa_test_efa_unit_test_<module>_test_CXXFLAGS = -std=c++11 -Wno-error
prov_efa_test_efa_unit_test_<module>_test_LDADD = $(GTEST_LIBS) $(linkback)
prov_efa_test_efa_unit_test_<module>_test_LDFLAGS = $(GTEST_LDFLAGS) $(efa_LDFLAGS) $(GTEST_WRAP_FLAGS)
```

## Troubleshooting

### Build Errors

**"undefined reference to `ibv_*`"**
- Add function to rdma_core_mocks.cpp
- Ensure function is in MOCK_METHOD in rdma_core_mocks.h

**"undefined reference to `__wrap_efa_*`"**
- Add function to efa_mocks.cpp with __wrap_ prefix
- Add to GTEST_WRAP_FLAGS in Makefile.include

### Runtime Errors

**"Uninteresting mock function call"**
- Add EXPECT_CALL for the function, or
- Use NiceMock (already default in base fixture)

**Segmentation fault**
- Check that g_rdma_core_mock and g_efa_mock are set in SetUp()
- Verify all mocked functions return valid values

## References

- [GoogleTest Documentation](https://google.github.io/googletest/)
- [GoogleMock Cheat Sheet](https://google.github.io/googletest/gmock_cheat_sheet.html)
- [Conversion Log](GTEST_CONVERSION_LOG.md) - Track conversion progress
