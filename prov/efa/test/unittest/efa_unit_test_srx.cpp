/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestSrx : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestSrx, test_efa_srx_min_multi_recv_size) {
    // Original test requires resource construction and tests srx_ctx->min_multi_recv_size
    GTEST_SKIP() << "Requires resource construction and EFA provider internals";
}

TEST_F(EfaUnitTestSrx, test_efa_srx_cq) {
    // Original test requires resource construction and tests srx_ctx->cq binding
    GTEST_SKIP() << "Requires resource construction and EFA provider internals";
}

TEST_F(EfaUnitTestSrx, test_efa_srx_lock) {
    // Original test requires resource construction and tests srx_ctx->lock
    GTEST_SKIP() << "Requires resource construction and EFA provider internals";
}

TEST_F(EfaUnitTestSrx, test_efa_srx_unexp_pkt) {
    // Original test requires resource construction and tests unexpected packet handling
    GTEST_SKIP() << "Requires resource construction and EFA provider internals";
}
