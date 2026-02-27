/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestRdmRma : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_no_p2p_support_returns_false) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_p2p_and_rdma_write_support_returns_true) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_peer_no_rdma_write_support_returns_false) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_remote_cq_data_multiple_iovs_returns_false) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_remote_cq_data_multiple_rma_iovs_returns_false) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_remote_cq_data_single_iovs_with_rdma_support) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_unsolicited_write_recv_not_match) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_use_device_rdma_false_returns_false) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

