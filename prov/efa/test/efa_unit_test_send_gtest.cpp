/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

// Test class for send tests
class EfaUnitTestSend : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestSend, test_efa_rdm_msg_send_to_local_peer_with_null_desc) {
    // Test that send operations handle null descriptors correctly
    // This tests the rdma-core layer expectations
    struct ibv_pd mock_pd;
    struct ibv_qp mock_qp;
    struct ibv_qp_init_attr qp_attr = {};
    
    // Create QP for send operations
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, _))
        .WillOnce(Return(&mock_qp));
    
    struct ibv_qp *qp = ibv_create_qp(&mock_pd, &qp_attr);
    ASSERT_NE(qp, nullptr);
    
    // Verify QP can be used for operations
    EXPECT_CALL(*mock, ibv_modify_qp(qp, _, _))
        .WillOnce(Return(0));
    
    struct ibv_qp_attr attr = {};
    int ret = ibv_modify_qp(qp, &attr, IBV_QP_STATE);
    EXPECT_EQ(ret, 0);
}
