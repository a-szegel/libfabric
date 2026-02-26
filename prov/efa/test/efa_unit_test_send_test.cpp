/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_base.h"

using ::testing::Return;

class EfaSendTest : public EfaUnitTest {};

TEST_F(EfaSendTest, MockVerification)
{
	// Simple test to verify mocking infrastructure works
	EXPECT_CALL(*rdma_mock, ibv_get_device_list(_))
		.WillOnce(Return(nullptr));

	struct ibv_device **list = ibv_get_device_list(nullptr);
	EXPECT_EQ(list, nullptr);
}
