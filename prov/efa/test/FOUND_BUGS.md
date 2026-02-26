# Bugs Found During Migration

## Date: 2026-02-26

### Bug #1: Original Tests Are Integration Tests, Not Unit Tests
**File**: All cmocka test files
**Severity**: High
**Description**: The existing cmocka tests are actually integration tests that require:
- Full EFA provider initialization (fi_getinfo, fi_fabric, fi_domain, fi_endpoint)
- Real EFA device structures and state
- Complex setup with resource construction helpers
- Testing actual provider behavior, not isolated units

**Root Cause**: Tests were written as integration tests to validate end-to-end provider functionality.

**Fix Applied**: No
**Status**: Design Decision Needed

**Options**:
1. Keep cmocka tests as integration tests, add NEW gtest unit tests for isolated components
2. Convert to hybrid tests that mock rdma-core but run real EFA provider code
3. Fully mock everything (would require mocking entire provider stack - massive effort)

**Recommendation**: Option 2 - Hybrid approach where we:
- Mock only rdma-core functions (ibv_*, efadv_*)
- Link against actual EFA provider code
- Let provider logic run normally
- This preserves all test functionality while removing hardware dependency

---

## Bug Template

### Bug #N: [Title]
**File**: 
**Severity**: Critical/High/Medium/Low
**Description**: 
**Root Cause**: 
**Fix Applied**: Yes/No
**Status**: Fixed/Workaround/Open
