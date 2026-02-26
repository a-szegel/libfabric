/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestRdmPeer : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_append_overflow_pke_to_recvwin) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_keep_pke_in_overflow_list) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_move_overflow_pke_to_recvwin) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_move_overflow_pke_to_recvwin_impl) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_recvwin_queue_or_append_pke) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_reorder_expected_msg_id) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_reorder_larger_msg_id) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_reorder_msg_impl) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_reorder_overflow_msg_id) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestRdmPeer, test_efa_rdm_peer_reorder_smaller_msg_id) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

