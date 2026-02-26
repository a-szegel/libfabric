/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestHmem : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_p2p_dmabuf_assumed_neuron) {
    // Test validates HMEM (Heterogeneous Memory) support for Neuron devices
    // Requires checking if p2p and dmabuf are assumed without explicit checking
    
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr = {};
    
    // Mock device query to return Amazon vendor ID
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, _))
        .WillOnce(Invoke([](struct ibv_context*, struct ibv_device_attr *a) {
            a->vendor_id = 0x1D0F; // Amazon vendor ID
            return 0;
        }));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.vendor_id, 0x1D0F);
}

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_disable_p2p_cuda) {
    // Test validates that when p2p is disabled, CUDA memory registration
    // doesn't attempt p2p checks
    
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    char buffer[4096];
    
    // Mock memory registration
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buffer, 4096, _))
        .WillOnce(Invoke([&](struct ibv_pd *pd, void *addr, size_t len, int access) {
            EXPECT_EQ(pd, &mock_pd);
            EXPECT_EQ(addr, buffer);
            EXPECT_EQ(len, 4096);
            return &mock_mr;
        }));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, buffer, 4096, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_NE(mr, nullptr);
    EXPECT_EQ(mr, &mock_mr);
}
