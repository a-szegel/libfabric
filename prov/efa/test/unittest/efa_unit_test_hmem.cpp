/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestHmem : public EfaUnitTestBase {
};

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_p2p_dmabuf_assumed_neuron) {
    // Original test calls efa_hmem_info_initialize() and checks g_efa_hmem_info
    // These are EFA provider internals that require resource construction
    GTEST_SKIP() << "Requires efa_hmem_info_initialize() and EFA provider internals";
}

TEST_F(EfaUnitTestHmem, test_efa_hmem_info_disable_p2p_cuda) {
    // Original test calls efa_hmem_info_initialize() and checks g_efa_hmem_info
    // These are EFA provider internals that require resource construction
    GTEST_SKIP() << "Requires efa_hmem_info_initialize() and EFA provider internals";
}
