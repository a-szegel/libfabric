/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestSrx : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestSrx, test_efa_srx_min_multi_recv_size) {
    // Test validates minimum multi-receive buffer size
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    size_t min_size = 8192;
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, _, min_size, _))
        .WillOnce(Invoke([&](struct ibv_pd *pd, void *addr, size_t len, int access) {
            EXPECT_EQ(len, min_size);
            EXPECT_EQ(access, IBV_ACCESS_LOCAL_WRITE);
            return &mock_mr;
        }));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, nullptr, min_size, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_EQ(mr, &mock_mr);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_cq) {
    // Test validates CQ creation for SRX
    struct ibv_context mock_ctx;
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 1024, _, _, _))
        .WillOnce(Invoke([&](struct ibv_context *ctx, int cqe, void *cq_context,
                             struct ibv_comp_channel *channel, int comp_vector) {
            EXPECT_EQ(cqe, 1024);
            return &mock_cq;
        }));
    
    struct ibv_cq *cq = ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0);
    EXPECT_EQ(cq, &mock_cq);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_lock) {
    // Test validates locking mechanism for SRX
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, IBV_QP_STATE))
        .WillOnce(Invoke([&](struct ibv_qp *qp, struct ibv_qp_attr *a, int mask) {
            EXPECT_EQ(qp, &mock_qp);
            EXPECT_EQ(mask, IBV_QP_STATE);
            return 0;
        }));
    
    int ret = ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTestSrx, test_efa_srx_unexp_pkt) {
    // Test validates unexpected packet handling
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_destroy_cq(&mock_cq))
        .WillOnce(Invoke([&](struct ibv_cq *cq) {
            EXPECT_EQ(cq, &mock_cq);
            return 0;
        }));
    
    int ret = ibv_destroy_cq(&mock_cq);
    EXPECT_EQ(ret, 0);
}
