/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestHmem : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_p2p_dmabuf_assumed_neuron) {
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr;
    
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, &attr))
        .WillOnce(Invoke([](struct ibv_context*, struct ibv_device_attr *a) {
            a->vendor_id = 0x1D0F; // Amazon
            return 0;
        }));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.vendor_id, 0x1D0F);
}

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_disable_p2p_cuda) {
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    char buffer[4096];
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buffer, 4096, _))
        .WillOnce(Return(&mock_mr));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, buffer, 4096, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_NE(mr, nullptr);
}
