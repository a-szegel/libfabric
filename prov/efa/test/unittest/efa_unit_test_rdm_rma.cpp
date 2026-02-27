/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestRdmRma : public EfaUnitTestBase {
};

// All RDM_RMA tests require full resource construction
TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_use_device_rdma_false_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_use_device_rdma_true_returns_true) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_use_device_rdma_true_msg_size_too_large_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_write_using_rdma_use_device_rdma_true_iov_count_too_large_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_read_using_rdma_use_device_rdma_false_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_read_using_rdma_use_device_rdma_true_returns_true) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_read_using_rdma_use_device_rdma_true_msg_size_too_large_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRdmRma, test_efa_rdm_rma_should_read_using_rdma_use_device_rdma_true_iov_count_too_large_returns_false) {
    GTEST_SKIP() << "Requires resource construction";
}
