# Phase 2: Resource Construction - Status

## Summary

**Status**: Infrastructure created, but full resource construction blocked by provider initialization requirements

**Tests Passing**: 20 (was 18)

## What Was Implemented

### 1. Resource Construction Fixture (`efa_unit_test_resources.hpp`)

Created `EfaUnitTestWithResources` class with helper methods:
- `ConstructFabricAndDomain()` - Fabric and domain construction
- `ConstructCQs()` - Completion queue creation
- `ConstructAV()` - Address vector creation
- `ConstructEndpoint()` - Endpoint creation
- `BindAndEnableEndpoint()` - Bind resources and enable EP
- `ConstructFullResources()` - Full stack construction

### 2. Resource Tests (`efa_unit_test_resources.cpp`)

Created basic tests to verify infrastructure:
- `test_getinfo_works` - Verify fi_getinfo() works ✅
- `test_fabric_construction` - Attempt fi_fabric() call

## The Problem

**Resource construction requires provider internal state that mocking alone cannot provide.**

### Why fi_fabric() Fails

1. **Provider Registration**: fi_fabric() expects the provider to be registered in libfabric's provider list
2. **Internal State**: The provider needs its internal structures initialized (efa_util_prov, device lists, etc.)
3. **Circular Dependency**: 
   - We mock `efa_device_list_initialize()` to return empty list
   - Provider initialization sees no devices
   - Provider doesn't fully initialize
   - fi_fabric() fails because provider isn't ready

### What Works

- ✅ fi_getinfo() - Works because we intercept device initialization
- ✅ Device mocking - All rdma-core functions mocked
- ✅ Info queries - Provider can return info structures
- ❌ fi_fabric() - Needs provider to be fully registered
- ❌ fi_domain() - Depends on fabric
- ❌ fi_endpoint() - Depends on domain

## Solutions (In Order of Complexity)

### Option 1: Mock fi_fabric/fi_domain/fi_endpoint (Easiest)
**Effort**: 2-3 hours

Mock these libfabric API functions to return fake structures:
```c
struct fid_fabric* __wrap_fi_fabric(...) {
    return (struct fid_fabric*)calloc(1, sizeof(struct fid_fabric));
}
```

**Pros**: Quick, enables testing of code that uses these resources
**Cons**: Doesn't test real provider code paths

### Option 2: Fix Provider Initialization (Medium)
**Effort**: 1-2 days

Make provider initialize successfully with mocked devices:
1. Ensure efa_util_prov.info is populated even with 0 devices
2. Fix provider registration in libfabric
3. Handle NULL/empty device lists gracefully

**Pros**: Tests real provider code
**Cons**: Requires deep understanding of provider initialization

### Option 3: Integration Test Approach (Hard)
**Effort**: 1 week

Create a full mock EFA device that behaves like real hardware:
1. Implement stateful device simulator
2. Mock all device operations with realistic behavior
3. Let provider initialize normally

**Pros**: Most realistic testing
**Cons**: Essentially reimplementing EFA device in software

## Recommendation

**Use Option 1 for now**: Mock fi_fabric/fi_domain/fi_endpoint to enable testing of higher-level code. This unblocks:
- Endpoint option tests
- Bind operation tests
- Basic send/recv setup tests

Then revisit Option 2 when we need to test actual provider resource management code.

## Current Test Count

- **Passing**: 20
- **Skipped**: 332
- **Infrastructure**: Complete for info tests, partial for resource tests

## Files Created

1. `prov/efa/test/unittest/efa_unit_test_resources.hpp` - Resource fixture
2. `prov/efa/test/unittest/efa_unit_test_resources.cpp` - Resource tests
3. This status document

## Next Steps

1. Implement Option 1 (mock fi_fabric/fi_domain/fi_endpoint)
2. Port simple endpoint/domain tests that don't need real resources
3. Gradually add more sophisticated mocking as needed
