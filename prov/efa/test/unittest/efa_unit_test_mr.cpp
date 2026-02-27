/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestMr : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestMr, test_efa_direct_mr_reg_no_gdrcopy) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_direct_mr_reg_rdma_read_not_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_direct_mr_reg_rdma_write_not_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_internal_regv_no_shm_mr) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_all_flags_not_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_all_flags_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_no_access) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_one_flag) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_read_not_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_remote_read_write_read_only_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_mr_ofi_to_ibv_access_write_not_supported) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_rdm_mr_reg_cuda_memory) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_rdm_mr_reg_host_memory) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_rdm_mr_reg_host_memory_no_mr_local) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

TEST_F(EfaUnitTestMr, test_efa_rdm_mr_reg_host_memory_overlapping_buffers) {
    GTEST_SKIP() << "Placeholder - requires implementation";
}

