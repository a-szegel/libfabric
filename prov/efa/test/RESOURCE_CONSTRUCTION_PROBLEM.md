# Resource Construction Problem

## The Issue

**fi_fabric() fails with -EINVAL when called in unit tests, blocking all resource construction.**

## Root Cause

The EFA provider requires full initialization before fi_fabric() can succeed, but our mocking strategy prevents this initialization:

### The Circular Dependency

```
1. Test starts
   ↓
2. Provider loads (EFA_INI constructor runs)
   ↓
3. Provider calls efa_device_list_initialize()
   ↓
4. We intercept with __wrap_efa_device_list_initialize()
   ↓
5. Our mock returns success but sets g_efa_selected_device_cnt = 0
   ↓
6. Provider sees 0 devices
   ↓
7. Provider doesn't populate efa_util_prov.info properly
   ↓
8. Provider initialization incomplete
   ↓
9. Test calls fi_getinfo() → Works! (provider can build info from empty device list)
   ↓
10. Test calls fi_fabric(info->fabric_attr, ...) → FAILS with -EINVAL
    ↓
11. fi_fabric() can't find provider because:
    - Provider not fully registered in libfabric's provider list, OR
    - fabric_attr->prov_name is NULL/incorrect, OR
    - Provider's internal state is incomplete
```

## What Works

✅ **fi_getinfo()** - Provider can return info structures even with 0 devices
✅ **Device mocking** - All 54 rdma-core functions properly mocked
✅ **Info queries** - 18 tests passing that use fi_getinfo()

## What Doesn't Work

❌ **fi_fabric()** - Returns -EINVAL (errno 22)
❌ **fi_domain()** - Can't test, depends on fabric
❌ **fi_endpoint()** - Can't test, depends on domain
❌ **fi_cq_open()** - Can't test, depends on domain
❌ **fi_av_open()** - Can't test, depends on domain

## Evidence

### Test Output
```
[ RUN      ] EfaUnitTestResources.test_fabric_construction
prov/efa/test/unittest/efa_unit_test_resources.hpp:63: Failure
Expected equality of these values:
  ret
    Which is: -22
  0
```

### Code Path
```c
// In test
SetUpDevice();  // Mocks devices
fi_getinfo(..., &info);  // SUCCESS - returns info
fi_fabric(info->fabric_attr, &fabric, NULL);  // FAILS with -22 (EINVAL)
```

### Provider Initialization (prov/efa/src/efa_prov.c)
```c
EFA_INI  // Constructor that runs when provider loads
{
    // ...
    err = efa_device_list_initialize();  // We mock this
    if (err)
        return &efa_prov;  // Returns early if no devices
    
    // This code might not run properly with 0 devices:
    for (i = 0; i < g_efa_selected_device_cnt; ++i) {
        // Build efa_util_prov.info from devices
    }
    
    efa_util_prov.info = head;  // Might be NULL if no devices
}
```

## Why This Matters

**332 tests are blocked** because they need resource construction:
- 18 AV tests - Need fi_av_open()
- 68 CQ tests - Need fi_cq_open()
- 72 EP tests - Need fi_endpoint()
- 14 Domain tests - Need fi_domain()
- 15 MR tests - Need fi_mr_reg()
- 100+ Data path tests - Need full resource stack
- 50+ Protocol tests - Need full resource stack

## Attempted Solutions

### ❌ Attempt 1: Set prov_name manually
```c
if (!info->fabric_attr->prov_name) {
    info->fabric_attr->prov_name = strdup("efa");
}
fi_fabric(info->fabric_attr, &fabric, NULL);  // Still fails
```
**Result**: Still returns -EINVAL

### ❌ Attempt 2: Use info directly from fi_getinfo
```c
fi_getinfo(..., &info);
fi_fabric(info->fabric_attr, &fabric, NULL);  // Still fails
```
**Result**: Still returns -EINVAL, even though info came from provider

### ❌ Attempt 3: Different fabric names
```c
// Tried "efa", "efa-direct", NULL
fi_fabric(info->fabric_attr, &fabric, NULL);  // All fail
```
**Result**: All return -EINVAL

## The Real Problem

**The provider's internal state is incomplete when initialized with 0 devices.**

Looking at efa_prov.c:
```c
static int efa_util_prov_initialize()
{
    // ...
    for (i = 0; i < g_efa_selected_device_cnt; ++i) {
        // Build prov_info_direct, prov_info_rdm, prov_info_dgram
    }
    
    if (!head)
        return -FI_ENODATA;  // Returns error if no devices!
    
    efa_util_prov.info = head;
    return 0;
}
```

When `g_efa_selected_device_cnt = 0`:
- Loop doesn't run
- `head` is NULL
- Function returns -FI_ENODATA
- `efa_util_prov.info` is NULL
- Provider is in incomplete state

## Solutions

### Option 1: Mock fi_fabric/fi_domain/fi_endpoint (Quick Fix)
**Effort**: 2-3 hours

Add to `efa_unit_test_mocks.cpp`:
```c
struct fid_fabric* __wrap_fi_fabric(struct fi_fabric_attr *attr, 
                                     struct fid_fabric **fabric, void *context) {
    *fabric = (struct fid_fabric*)calloc(1, sizeof(struct fid_fabric));
    (*fabric)->fid.fclass = FI_CLASS_FABRIC;
    return 0;
}
```

**Pros**: 
- Quick to implement
- Unblocks 50+ tests immediately
- Tests can verify bind operations, option setting, etc.

**Cons**:
- Doesn't test real provider resource management
- Mock resources won't have real provider behavior

### Option 2: Fix Provider Initialization (Proper Fix)
**Effort**: 1-2 days

Modify provider to handle 0 devices gracefully:

1. **Make device mock return 1 device** instead of 0:
```c
int __wrap_efa_device_list_initialize(void) {
    // Create 1 mock device with minimal attributes
    g_efa_selected_device_cnt = 1;
    g_efa_selected_device_list = create_mock_device();
    return 0;
}
```

2. **Ensure mock device has all required fields**:
```c
struct efa_device* create_mock_device() {
    struct efa_device *dev = calloc(1, sizeof(struct efa_device));
    dev->ibv_ctx = mock_ibv_context;
    dev->ibv_pd = mock_ibv_pd;
    dev->rdm_info = create_mock_rdm_info();
    dev->dgram_info = create_mock_dgram_info();
    // ... set all required fields
    return dev;
}
```

3. **Let provider initialize normally** with mock device

**Pros**:
- Tests real provider code paths
- Provider fully initialized
- All resource construction works

**Cons**:
- More complex
- Need to ensure mock device has all required fields
- May expose other initialization dependencies

### Option 3: Full Device Simulator (Overkill)
**Effort**: 1 week

Create complete mock device with stateful behavior.

**Not recommended** - too much effort for unit testing.

## Recommendation

**Start with Option 1**, then move to Option 2 if needed:

1. **Immediate** (2-3 hours): Mock fi_fabric/fi_domain/fi_endpoint
   - Unblocks 50+ tests
   - Tests can verify higher-level logic

2. **Later** (1-2 days): Implement Option 2
   - When we need to test actual resource management
   - When we need provider's real behavior

## Files Involved

### Provider Initialization
- `prov/efa/src/efa_prov.c` - EFA_INI constructor, efa_util_prov_initialize()
- `prov/efa/src/efa_device.c` - efa_device_list_initialize()

### Test Infrastructure
- `prov/efa/test/unittest/efa_unit_test_wrappers.c` - __wrap_efa_device_list_initialize()
- `prov/efa/test/unittest/efa_unit_test_device_setup.c` - SetUpDevice()
- `prov/efa/test/unittest/efa_unit_test_resources.hpp` - Resource fixture (blocked)

### Libfabric Core
- `src/fabric.c` - fi_fabric() implementation
- `include/ofi_prov.h` - Provider registration

## Next Steps

1. Decide: Option 1 (quick) or Option 2 (proper)?
2. If Option 1: Add mocks for fi_fabric/fi_domain/fi_endpoint
3. If Option 2: Fix device mock to return 1 device with full attributes
4. Port tests that need resource construction
5. Measure progress (target: 50+ more tests passing)
