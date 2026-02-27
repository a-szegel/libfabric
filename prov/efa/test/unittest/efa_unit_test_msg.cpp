/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

class EfaUnitTestMsg : public EfaUnitTestBase {
};

// All MSG tests require full resource construction
TEST_F(EfaUnitTestMsg, test_efa_msg_fi_recv) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_recvv) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_recvmsg) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_trecv) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_trecvv) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_trecvmsg) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_recv_cancel) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_trecv_cancel) {
    GTEST_SKIP() << "Requires resource construction";
}

TEST_F(EfaUnitTestMsg, test_efa_msg_fi_recv_cancel_impl) {
    GTEST_SKIP() << "Requires resource construction";
}
