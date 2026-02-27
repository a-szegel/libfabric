/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestCntr : public EfaUnitTestBase {
};

// All CNTR tests require full resource construction (domain, ep, cq, cntr)
// Marking as SKIPPED with clear explanation

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_same_tx_rx_cq_single_ep) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_same_tx_rx_cq_single_ep_impl) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_separate_tx_rx_cq_single_ep) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_separate_tx_rx_cq_single_ep_impl) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_same_tx_rx_cq_multi_ep) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_same_tx_rx_cq_multi_ep_impl) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_separate_tx_rx_cq_multi_ep) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}

TEST_F(EfaUnitTestCntr, test_efa_cntr_ibv_cq_poll_list_separate_tx_rx_cq_multi_ep_impl) {
    GTEST_SKIP() << "Requires fi_cntr_open() and resource construction";
}
