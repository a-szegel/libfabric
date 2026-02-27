/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"
#include "efa_unit_test_device_mock.hpp"

#define EFA_FABRIC_NAME "efa"
#define EFA_DIRECT_FABRIC_NAME "efa-direct"

class EfaUnitTestInfo : public EfaUnitTestWithDevice {
};

/**
 * @brief test that when a wrong fi_info was used to open resource, the error is handled
 * gracefully
 * 
 * NOTE: This test requires full fabric/domain/endpoint construction which needs
 * more infrastructure beyond device mocking.
 */
TEST_F(EfaUnitTestInfo, test_info_open_ep_with_wrong_info) {
    GTEST_SKIP() << "Requires full resource construction infrastructure";
}

/**
 * @brief Verify that efa rdm path fi_info objects have some expected values
 */
TEST_F(EfaUnitTestInfo, test_info_rdm_attributes) {
    SetUpDevice();
    
    struct fi_info *hints, *info = NULL, *info_head = NULL;
    int err;

    hints = efa_unit_test_alloc_hints(FI_EP_RDM, (char*)EFA_FABRIC_NAME);
    ASSERT_NE(hints, nullptr);

    err = fi_getinfo(FI_VERSION(1,6), NULL, NULL, 0, hints, &info_head);
    ASSERT_EQ(err, 0);
    ASSERT_NE(info_head, nullptr);

    for (info = info_head; info; info = info->next) {
        EXPECT_STREQ(info->fabric_attr->name, EFA_FABRIC_NAME);
        EXPECT_NE(strstr(info->domain_attr->name, "rdm"), nullptr);
        EXPECT_EQ(info->ep_attr->max_msg_size, UINT64_MAX);
        EXPECT_EQ(info->domain_attr->progress, FI_PROGRESS_MANUAL);
        EXPECT_EQ(info->domain_attr->control_progress, FI_PROGRESS_MANUAL);
    }

    fi_freeinfo(info_head);
    fi_freeinfo(hints);
}

/**
 * @brief Verify that efa dgram path fi_info objects have some expected values
 */
TEST_F(EfaUnitTestInfo, test_info_dgram_attributes) {
    SetUpDevice();
    
    struct fi_info *hints, *info = NULL, *info_head = NULL;
    int err;

    hints = efa_unit_test_alloc_hints(FI_EP_DGRAM, (char*)EFA_FABRIC_NAME);
    ASSERT_NE(hints, nullptr);

    err = fi_getinfo(FI_VERSION(1,6), NULL, NULL, 0, hints, &info_head);
    ASSERT_EQ(err, 0);
    ASSERT_NE(info_head, nullptr);

    for (info = info_head; info; info = info->next) {
        EXPECT_STREQ(info->fabric_attr->name, EFA_FABRIC_NAME);
        EXPECT_NE(strstr(info->domain_attr->name, "dgrm"), nullptr);
    }

    fi_freeinfo(info_head);
    fi_freeinfo(hints);
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env0) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env0_opt0) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env0_opt1) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env1) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env1_opt0) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_env1_opt1) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_opt0) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_opt1) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_efa_use_device_rdma_opt_old) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_hmem_cuda_support_on_api_ge_1_18) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_hmem_cuda_support_on_api_lt_1_18) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_no_hmem_support_when_not_requested) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_shm_info_hmem) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_shm_info_op_flags) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_check_shm_info_threading) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}


TEST_F(EfaUnitTestInfo, test_info_direct_attributes_no_rma) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_attributes_rma) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_hmem_support_p2p) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_no_rma_no_rx_cq_data_when_no_unsolicited_write_recv) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_null_hints_return_rma_and_rx_cq_data) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_ordering) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_rma_with_rx_cq_data_when_no_unsolicited_write_recv) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_rma_without_rx_cq_data_when_no_unsolicited_write_recv) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_rma_without_rx_cq_data_when_unsolicited_write_recv_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_direct_unsupported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_max_order_size_dgram_with_atomic) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_max_order_size_rdm_with_atomic_no_order) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_max_order_size_rdm_with_atomic_order) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}



TEST_F(EfaUnitTestInfo, test_info_reuse_domain_via_domain_attr) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_reuse_domain_via_name) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_reuse_fabric_via_fabric_attr) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_reuse_fabric_via_name) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_msg_order_dgram_order_none) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_msg_order_dgram_order_sas) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_msg_order_rdm_order_none) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_msg_order_rdm_order_sas) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_op_flags_rdm) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_info_tx_rx_size_rdm) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestInfo, test_use_device_rdma) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

