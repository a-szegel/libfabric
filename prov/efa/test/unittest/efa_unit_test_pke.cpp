/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestPke : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_alloc_rta_rxe) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_alloc_rtr_rxe) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_alloc_rtw_rxe) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_flag_tracking) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_get_unexp) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_handle_longcts_rtm_send_completion) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_proc_matched_eager_rtm_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_proc_matched_mulreq_rtm_first_packet_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_proc_matched_mulreq_rtm_second_packet_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestPke, test_efa_rdm_pke_release_rx_list) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

