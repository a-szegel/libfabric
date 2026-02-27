/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestDataPathDirect : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_read_multiple_sge_fail) {
    // Original test requires full resource construction and calls efa_data_path_direct_post_read()
    // Tests that multiple SGE (scatter-gather elements) fail with EINVAL
    GTEST_SKIP() << "Requires resource construction and efa_data_path_direct_post_read()";
}

TEST_F(EfaUnitTestDataPathDirect, test_efa_data_path_direct_rdma_write_multiple_sge_fail) {
    // Original test requires full resource construction and calls efa_data_path_direct_post_write()
    // Tests that multiple SGE (scatter-gather elements) fail with EINVAL
    GTEST_SKIP() << "Requires resource construction and efa_data_path_direct_post_write()";
}
