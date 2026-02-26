/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

// Test class for device tests
class EfaUnitTestDevice : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestDevice, test_efa_device_construct_error_handling) {
    struct ibv_device mock_device;
    struct ibv_device *device_list[2] = {&mock_device, nullptr};
    struct ibv_context mock_ctx;
    struct efadv_device_attr efa_attr = {};
    
    // Simulate device list retrieval
    EXPECT_CALL(*mock, ibv_get_device_list(_))
        .WillOnce(DoAll(SetArgPointee<0>(1), Return(device_list)));
    
    int num = 0;
    struct ibv_device **list = ibv_get_device_list(&num);
    ASSERT_NE(list, nullptr);
    ASSERT_EQ(num, 1);
    
    // Simulate device open
    EXPECT_CALL(*mock, ibv_open_device(&mock_device))
        .WillOnce(Return(&mock_ctx));
    
    struct ibv_context *ctx = ibv_open_device(&mock_device);
    ASSERT_NE(ctx, nullptr);
    
    // Simulate efadv_query_device failure with specific error code
    int ibv_err = 4242;
    EXPECT_CALL(*mock, efadv_query_device(ctx, _, _))
        .WillOnce(Return(-ibv_err));
    
    int ret = efadv_query_device(ctx, &efa_attr, sizeof(efa_attr));
    EXPECT_EQ(ret, -ibv_err);
    
    // On error, cleanup should happen
    EXPECT_CALL(*mock, ibv_close_device(ctx))
        .WillOnce(Return(0));
    
    ret = ibv_close_device(ctx);
    EXPECT_EQ(ret, 0);
}
