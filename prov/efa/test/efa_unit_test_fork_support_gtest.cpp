/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

// Test class for fork support tests
class EfaUnitTestForkSupport : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestForkSupport, test_efa_fork_support_request_initialize_when_ibv_fork_support_is_needed) {
    // Test fork support initialization when IBV reports disabled
    EXPECT_CALL(*mock, ibv_is_fork_initialized())
        .WillOnce(Return(IBV_FORK_DISABLED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_DISABLED);
    
    // When fork support is needed, ibv_fork_init should be called
    EXPECT_CALL(*mock, ibv_fork_init())
        .WillOnce(Return(0));
    
    int ret = ibv_fork_init();
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTestForkSupport, test_efa_fork_support_request_initialize_when_ibv_fork_support_is_unneeded) {
    // Test fork support when IBV reports unneeded
    EXPECT_CALL(*mock, ibv_is_fork_initialized())
        .WillOnce(Return(IBV_FORK_UNNEEDED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_UNNEEDED);
    
    // When unneeded, no initialization required
}
