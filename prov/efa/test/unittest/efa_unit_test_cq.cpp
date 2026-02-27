/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestCq : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestCq, test_dgram_cq_read_empty_cq) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_control_getwait_no_channel) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_control_getwait_with_channel) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_control_getwaitobj) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_control_invalid_command) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_data_path_direct_disabled_by_env) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_data_path_direct_disabled_with_old_device) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_data_path_direct_enabled_with_new_device) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_data_path_direct_with_wait_obj) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_ep_list_lock_type_mutex) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_ep_list_lock_type_no_op) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_ops_override_with_counter_binding) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_poll_active_no_restart) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_mixed_success_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_no_completion) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_read_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_recv_failure) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_recv_rdma_with_imm_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_recv_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_send_failure) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_send_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_senddata_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_write_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_read_writedata_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readerr_return_value_provider_buffer) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readerr_return_value_user_buffer) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readerr_util_cq_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readfrom_input_validation) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readfrom_start_poll_error) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_readfrom_util_cq_entries) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_recv_rdma_with_imm_failure) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_sread_eagain) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_sread_enosys) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_trywait_completions_available) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_trywait_no_channel) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_cq_trywait_success) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_before_ep_enable) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_data_path_direct_disabled_with_old_device) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_data_path_direct_enabled_with_new_device) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_ibv_cq_poll_list_same_tx_rx_cq_single_ep) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_ibv_cq_poll_list_separate_tx_rx_cq_single_ep) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_post_initial_rx_pkts) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_sread_eagain) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_sread_no_wait_obj) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_efa_rdm_cq_sread_with_cqe) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_bad_recv_rdma_with_imm_status_impl) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_bad_recv_rdma_with_imm_status_use_solicited_recv) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_bad_recv_rdma_with_imm_status_use_unsolicited_recv) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_bad_recv_status) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_empty_cq) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_failed_poll) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_ignore_removed_peer) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_ex_read_recover_forgotten_peer_ah) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_ibv_cq_unsolicited_write_recv_status) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_impl_cq_read_empty_cq) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_create_error_handling) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_bad_qpn) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_impl) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_remote_abort) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_unreach_remote) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_unresp_remote) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_handshake_bad_send_status_unsupported_op) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_read_bad_send_status_invalid_qpn) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_read_bad_send_status_message_too_long) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_read_bad_send_status_unreachable_receiver) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_read_bad_send_status_unresponsive_receiver) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_cq_read_bad_send_status_unresponsive_receiver_missing_peer_host_id) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTestCq, test_rdm_fallback_to_ibv_create_cq_ex_cq_read_ignore_forgotton_peer) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, _)).WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

