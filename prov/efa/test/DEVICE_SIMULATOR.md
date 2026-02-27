# Device Simulator Documentation

## Overview

A comprehensive device mocking infrastructure for testing EFA provider code without real hardware.

## Architecture

### Components

1. **efa_mock_device_config** - Configuration structure
2. **efa_device_simulator** - Device simulator class
3. **EfaUnitTestWithDevice** - Test fixture
4. **Linker wrapping** - Intercepts rdma-core calls

### Design Philosophy

**Flexible Configuration**: Single config struct controls all device attributes
**Minimal Boilerplate**: `SetUpDevice()` with optional custom config
**Automatic Cleanup**: RAII-based object lifecycle management
**Comprehensive Coverage**: Mocks all common rdma-core operations

## Usage

### Basic Usage

```cpp
class MyTest : public EfaUnitTestWithDevice {
};

TEST_F(MyTest, test_something) {
    SetUpDevice();  // Uses default config
    
    // Your test code - device is ready
    // fi_getinfo(), fi_fabric(), etc. will work
}
```

### Custom Configuration

```cpp
TEST_F(MyTest, test_with_custom_device) {
    efa_mock_device_config config;
    config.max_qp = 4096;
    config.max_rdma_size = 16384;
    config.support_rdma_read = false;
    
    SetUpDevice(config);
    
    // Test with custom device attributes
}
```

### Configuration Options

```cpp
struct efa_mock_device_config {
    // Device identification
    const char *name = "efa_0";
    
    // Device capabilities
    uint64_t max_mr_size = 0xFFFFFFFFFFFFULL;
    uint32_t max_qp = 2048;
    uint32_t max_cq = 2048;
    uint32_t max_pd = 256;
    uint32_t max_ah = 2048;
    uint32_t max_qp_wr = 8192;
    uint32_t max_cqe = 16384;
    uint32_t max_mr = 1024;
    uint32_t max_sge = 16;
    
    // Port attributes
    uint8_t port_num = 1;
    uint32_t max_msg_sz = 1048576;
    enum ibv_mtu active_mtu = IBV_MTU_4096;
    enum ibv_port_state state = IBV_PORT_ACTIVE;
    
    // GID
    uint8_t gid[16] = {0xfe, 0x80, ...};
    
    // EFA-specific
    uint16_t max_rdma_size = 8192;
    bool support_rdma_read = true;
    bool support_rdma_write = true;
    bool support_unsolicited_write_recv = false;
};
```

## Implementation Details

### Mocked Functions

All rdma-core functions are mocked:

**Device Discovery**:
- `ibv_get_device_list()`
- `ibv_free_device_list()`
- `ibv_get_device_name()`
- `ibv_open_device()`
- `ibv_close_device()`

**Device Query**:
- `ibv_query_device()`
- `ibv_query_port()`
- `ibv_query_gid()`
- `efadv_query_device()`

**Resource Management**:
- `ibv_alloc_pd()` / `ibv_dealloc_pd()`
- `ibv_create_cq()` / `ibv_destroy_cq()`
- `ibv_create_qp()` / `ibv_destroy_qp()`
- `ibv_reg_mr()` / `ibv_dereg_mr()`
- `ibv_create_ah()` / `ibv_destroy_ah()`

### Object Lifecycle

The simulator automatically:
1. Allocates fake rdma-core objects
2. Tracks all allocated objects
3. Frees objects on teardown
4. Returns consistent pointers

### Mock Behavior

```cpp
void efa_device_simulator::setup_all() {
    setup_device_list();      // Returns fake device list
    setup_device_open();      // Returns fake context
    setup_device_query();     // Returns configured attributes
    setup_port_query();       // Returns port attributes
    setup_gid_query();        // Returns configured GID
    setup_pd_alloc();         // Allocates fake PD
    setup_cq_create();        // Allocates fake CQ
    setup_qp_create();        // Allocates fake QP
    setup_mr_reg();           // Allocates fake MR
    setup_ah_create();        // Allocates fake AH
    setup_efadv_query();      // Returns EFA attributes
}
```

## Examples

### Test Different Device Capabilities

```cpp
TEST_F(MyTest, test_without_rdma_read) {
    efa_mock_device_config config;
    config.support_rdma_read = false;
    SetUpDevice(config);
    
    // Verify provider handles missing RDMA read
}

TEST_F(MyTest, test_small_queue_limits) {
    efa_mock_device_config config;
    config.max_qp_wr = 128;
    config.max_cqe = 256;
    SetUpDevice(config);
    
    // Verify provider respects limits
}
```

### Test Port States

```cpp
TEST_F(MyTest, test_port_down) {
    efa_mock_device_config config;
    config.state = IBV_PORT_DOWN;
    SetUpDevice(config);
    
    // Verify provider handles port down
}
```

### Test Different GIDs

```cpp
TEST_F(MyTest, test_custom_gid) {
    efa_mock_device_config config;
    memcpy(config.gid, my_gid, 16);
    SetUpDevice(config);
    
    // Test with specific GID
}
```

## Known Limitations

### Provider Initialization Timing

**Issue**: EFA provider caches device list during global initialization before tests run.

**Impact**: `fi_getinfo()` returns empty list even with mocks set up.

**Root Cause**: Provider calls `ibv_get_device_list()` in constructor, before test fixtures run.

### Potential Solutions

#### Option 1: Force Provider Reinitialization
```cpp
// Unload and reload provider after mock setup
fi_freeinfo(cached_info);
// Force provider reload
```

**Pros**: Clean, uses existing infrastructure
**Cons**: May not be possible with current libfabric architecture

#### Option 2: Mock at Higher Level
```cpp
// Intercept fi_getinfo() instead of ibv_get_device_list()
struct fi_info* __wrap_fi_getinfo(...) {
    // Return pre-constructed fi_info
}
```

**Pros**: Bypasses provider initialization
**Cons**: Doesn't test actual provider code

#### Option 3: LD_PRELOAD
```bash
LD_PRELOAD=libmock_rdma.so ./efa_unit_tests_gtest
```

**Pros**: Intercepts calls before provider loads
**Cons**: More complex build, platform-specific

#### Option 4: Lazy Initialization
Modify EFA provider to delay device discovery until first `fi_getinfo()` call.

**Pros**: Clean solution, enables testing
**Cons**: Requires provider code changes

## Recommendations

### Short Term
Use device simulator for tests that:
1. Directly call rdma-core functions
2. Test EFA internal logic with mocked devices
3. Don't require full provider initialization

### Medium Term
Implement Option 2 (higher-level mocking) for integration tests:
```cpp
class EfaUnitTestWithProvider : public EfaUnitTestWithDevice {
protected:
    void SetUpProvider();  // Returns pre-built fi_info
};
```

### Long Term
Work with libfabric maintainers to support lazy provider initialization or test hooks.

## Files

- `efa_unit_test_device_mock.hpp` - Device simulator header
- `efa_unit_test_device_mock.cpp` - Device simulator implementation
- `efa_unit_test_fixture.cpp` - Test fixture implementation
- `efa_unit_test_common.hpp` - Common test infrastructure
- `efa_unit_test_mocks.cpp` - Mock implementations
- `efa_unit_test_wrappers.c` - C wrapper functions

## Summary

The device simulator provides a **robust, flexible foundation** for mocking rdma-core. The infrastructure is complete and ready to use. The remaining challenge is **provider initialization timing**, which requires either provider code changes or higher-level mocking.

**Status**: Infrastructure complete ✅  
**Integration**: Pending provider initialization solution ⏳
