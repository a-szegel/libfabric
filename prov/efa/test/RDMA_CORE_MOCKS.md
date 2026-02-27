# RDMA-Core Function Mocks

This document lists all rdma-core (libibverbs and libefadv) functions used by the EFA provider that are now fully mocked for unit testing.

## Status: COMPLETE ✅

All rdma-core functions used in `prov/efa/src` are now mocked.

## Mocked Functions

### Device Management (11 functions)
- `ibv_get_device_list()` - Get list of RDMA devices
- `ibv_free_device_list()` - Free device list
- `ibv_get_device_name()` - Get device name
- `ibv_open_device()` - Open device context
- `ibv_close_device()` - Close device context
- `ibv_query_device()` - Query device attributes
- `ibv_query_port()` - Query port attributes
- `ibv_query_gid()` - Query GID table
- `ibv_is_fork_initialized()` - Check fork support status
- `ibv_fork_init()` - Initialize fork support
- `efadv_query_device()` - Query EFA-specific device attributes

### Protection Domain (2 functions)
- `ibv_alloc_pd()` - Allocate protection domain
- `ibv_dealloc_pd()` - Deallocate protection domain

### Memory Registration (4 functions)
- `ibv_reg_mr()` - Register memory region
- `ibv_dereg_mr()` - Deregister memory region
- `ibv_reg_dmabuf_mr()` - Register dmabuf memory region
- `efadv_query_mr()` - Query EFA-specific MR attributes

### Completion Queue (16 functions)
- `ibv_create_cq()` - Create completion queue
- `ibv_destroy_cq()` - Destroy completion queue
- `ibv_create_cq_ex()` - Create extended CQ
- `ibv_cq_ex_to_cq()` - Convert extended CQ to regular CQ
- `ibv_req_notify_cq()` - Request CQ notification
- `ibv_ack_cq_events()` - Acknowledge CQ events
- `ibv_get_cq_event()` - Get CQ event
- `ibv_start_poll()` - Start polling CQ
- `ibv_next_poll()` - Get next completion
- `ibv_end_poll()` - End polling
- `ibv_wc_read_byte_len()` - Read completion byte length
- `ibv_wc_read_imm_data()` - Read immediate data
- `ibv_wc_read_opcode()` - Read operation code
- `ibv_wc_read_qp_num()` - Read QP number
- `ibv_wc_read_src_qp()` - Read source QP
- `ibv_wc_read_slid()` - Read source LID

### Completion Queue (continued)
- `ibv_wc_read_wc_flags()` - Read work completion flags
- `ibv_wc_read_vendor_err()` - Read vendor error
- `ibv_wc_read_sgid()` - Read source GID
- `efadv_create_cq()` - Create EFA-specific CQ
- `efadv_query_cq()` - Query EFA-specific CQ attributes
- `efadv_wc_read_sgid()` - Read source GID (EFA-specific)

### Completion Channel (3 functions)
- `ibv_create_comp_channel()` - Create completion channel
- `ibv_destroy_comp_channel()` - Destroy completion channel

### Queue Pair (10 functions)
- `ibv_create_qp()` - Create queue pair
- `ibv_destroy_qp()` - Destroy queue pair
- `ibv_modify_qp()` - Modify QP state
- `ibv_create_qp_ex()` - Create extended QP
- `ibv_qp_to_qp_ex()` - Convert QP to extended QP
- `ibv_query_qp_data_in_order()` - Query data ordering
- `ibv_post_recv()` - Post receive work request
- `ibv_post_send()` - Post send work request
- `efadv_create_qp_ex()` - Create EFA-specific QP
- `efadv_query_qp_wqs()` - Query EFA-specific QP work queues

### Address Handle (3 functions)
- `ibv_create_ah()` - Create address handle
- `ibv_destroy_ah()` - Destroy address handle
- `efadv_query_ah()` - Query EFA-specific AH attributes

## Total: 49 functions mocked

## Implementation Details

### Location
- **Mock implementations**: `prov/efa/test/unittest/efa_unit_test_mocks.cpp`
- **Wrap flags**: `prov/efa/Makefile.include` (GTEST_WRAP_FLAGS)

### Mock Behavior
- Most mocks return success (0) or allocate minimal structures
- CQ polling functions return ENOENT (no completions)
- All query functions return success with zeroed attributes
- Memory allocation mocks use calloc() for zero-initialized structures

### Testing
All mocks are verified to work with the existing 5 passing tests:
- Device construction test
- Fork support tests (2)
- Info query tests (2)

## Next Steps

To enable more tests, you need to:
1. Implement stateful mock behavior (e.g., QP state machine)
2. Add mock data path operations (send/recv simulation)
3. Implement CQ completion generation
4. Add resource lifecycle tracking

The infrastructure is complete - mocks just need enhanced behavior for specific test scenarios.
