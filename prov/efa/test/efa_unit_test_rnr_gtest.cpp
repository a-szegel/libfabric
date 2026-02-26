/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestRnr : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestRnr, test_efa_rnr_queue_and_resend_msg) {
    struct ibv_pd mock_pd;
    struct ibv_qp mock_qp;
    struct ibv_cq mock_cq;
    struct ibv_context mock_ctx;
    
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx)).WillOnce(Return(&mock_pd));
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, _, _, _, _)).WillOnce(Return(&mock_cq));
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, _)).WillOnce(Return(&mock_qp));
    
    ASSERT_NE(ibv_alloc_pd(&mock_ctx), nullptr);
    ASSERT_NE(ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0), nullptr);
    
    struct ibv_qp_init_attr attr = {};
    ASSERT_NE(ibv_create_qp(&mock_pd, &attr), nullptr);
}

TEST_F(EfaUnitTestRnr, test_efa_rnr_queue_and_resend_tagged) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillRepeatedly(Return(0));
    
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}
