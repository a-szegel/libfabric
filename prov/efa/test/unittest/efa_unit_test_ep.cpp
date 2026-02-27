/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestEp : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestEp, test_efa_base_ep_disable_unsolicited_write_recv_with_rx_cq_data) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_direct_ep_setopt_cq_flow_control_no_rx_cq_data) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_direct_ep_setopt_cq_flow_control_with_rx_cq_data) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_bind_and_enable) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_cancel) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_data_path_direct_equal_to_cq_data_path_direct_happy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_data_path_direct_equal_to_cq_data_path_direct_impl) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_data_path_direct_equal_to_cq_data_path_direct_unhappy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_getopt) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_lock_type_mutex) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_lock_type_no_op) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_open) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_setopt_hmem_p2p) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_setopt_rnr_retry) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_setopt_sizes) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_ep_setopt_use_device_rdma) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_atomic_without_caps) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_close_discard_posted_recv) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_close_shm_resource_happy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_close_shm_resource_unhappy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_data_path_direct_equal_to_cq_data_path_direct_happy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_data_path_direct_equal_to_cq_data_path_direct_unhappy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_dc_atomic_queue_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_dc_send_queue_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_dc_send_queue_limit_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_default_sizes) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_enable_ah_alloc_failure) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_enable_qp_in_order_aligned_128_bytes_bad) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_enable_qp_in_order_aligned_128_bytes_common) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_enable_qp_in_order_aligned_128_bytes_good) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_getopt) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_getopt_oversized_optlen) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_getopt_undersized_optlen) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_handshake_exchange_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_handshake_receive_and_send_valid_host_ids_with_connid) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_handshake_receive_and_send_valid_host_ids_without_connid) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_handshake_receive_valid_peer_host_id_and_do_not_send_local_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_handshake_receive_without_peer_host_id_and_do_not_send_local_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_has_valid_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_ibv_create_ah_failure) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_ignore_missing_host_id_file) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_ignore_non_hex_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_ignore_short_host_id) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_outstanding_tx_ops_decremented_with_error_completion) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_pkt_pool_page_alignment) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_post_handshake_error_handling_pke_exhaustion) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_read_queue_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rma_queue_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rma_without_caps) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rx_pkt_pool_flags) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rx_refill_impl) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rx_refill_threshold_larger_than_rx_size) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_rx_refill_threshold_smaller_than_rx_size) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_send_with_shm_no_copy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_setopt_cq_flow_control) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_setopt_homogeneous_peers) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_setopt_shared_memory_permitted) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_shm_ep_different_info) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_support_unsolicited_write_recv) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_trigger_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_tx_pkt_pool_flags) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_user_disable_p2p_zcpy_rx_disabled) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_user_p2p_not_supported_zcpy_rx_happy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_user_zcpy_rx_disabled) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_user_zcpy_rx_unhappy_due_to_no_mr_local) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_user_zcpy_rx_unhappy_due_to_sas) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_write_queue_before_handshake) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_zcpy_recv_cancel) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_ep_zcpy_recv_eagain) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_pke_get_available_copy_methods_align128) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestEp, test_efa_rdm_read_copy_pkt_pool_128_alignment) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

