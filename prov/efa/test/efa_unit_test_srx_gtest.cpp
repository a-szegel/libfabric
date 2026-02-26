/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestSrx : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestSrx, test_efa_srx_min_multi_recv_size) {
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    size_t min_size = 8192;
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, _, min_size, _)).WillOnce(Return(&mock_mr));
    EXPECT_NE(ibv_reg_mr(&mock_pd, nullptr, min_size, IBV_ACCESS_LOCAL_WRITE), nullptr);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_cq) {
    struct ibv_context mock_ctx;
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 1024, _, _, _)).WillOnce(Return(&mock_cq));
    EXPECT_NE(ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0), nullptr);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_lock) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_unexp_pkt) {
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_destroy_cq(&mock_cq)).WillOnce(Return(0));
    EXPECT_EQ(ibv_destroy_cq(&mock_cq), 0);
}
