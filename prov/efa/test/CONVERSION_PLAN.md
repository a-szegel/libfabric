# EFA Test Migration Plan

## Current Status (2026-02-26 21:05)
- Infrastructure: 100% complete
- Basic mocking: Working
- Tests passing: 4/374 (1%)

## Challenge
Converting 374 integration tests to pure unit tests while preserving functionality requires:
1. Mocking all rdma-core functions (ibv_*, efadv_*)
2. Letting EFA provider code run
3. Converting test logic from cmocka to GoogleTest
4. Estimated time: 40-60 hours of focused work

## Strategy
Given the scope, I'll convert tests in priority order:

### Phase 1: Simple Mock Tests (DONE)
- device, fork_support, send
- 4 tests passing

### Phase 2: Tests with Minimal Dependencies (NEXT)
- rnr (3 tests)
- hmem (4 tests)  
- data_path_direct (2 tests)
- Total: 9 tests

### Phase 3: Medium Complexity
- srx, cntr, rdm_rma, msg, pke, rdm_peer, rma
- Total: 59 tests

### Phase 4: Complex Tests
- domain, runt, mr, av
- Total: 65 tests

### Phase 5: Largest Files
- ope (38 tests)
- info (43 tests)
- cq (77 tests)
- ep (79 tests)
- Total: 237 tests

## Conversion Template
For each test:
1. Extract test function from .c file
2. Convert cmocka assertions to EXPECT_*/ASSERT_*
3. Add necessary mocks with EXPECT_CALL
4. Handle resource construction/destruction
5. Verify test passes

## Progress Tracking
Will update MIGRATION_STATUS.md after each file conversion.
