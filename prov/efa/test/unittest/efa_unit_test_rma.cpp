/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestRma : public EfaUnitTestBase {
};

// All RMA tests require full resource construction
TEST_F(EfaUnitTestRma, test_efa_rma_read) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_readv) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_readmsg) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_write) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_writev) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_writemsg) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_writedata) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_inject_write) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_inject_writedata) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestRma, test_efa_rma_read_impl) {
    GTEST_SKIP() << "Requires resource construction";
}
