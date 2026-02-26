/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_base.h"

using ::testing::Return;

class EfaForkSupportTest : public EfaUnitTest {};

TEST_F(EfaForkSupportTest, IbvForkInitializedReturnsDisabled)
{
	EXPECT_CALL(*rdma_mock, ibv_is_fork_initialized())
		.WillOnce(Return(IBV_FORK_DISABLED));

	int ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_DISABLED);
}

TEST_F(EfaForkSupportTest, IbvForkInitializedReturnsUnneeded)
{
	EXPECT_CALL(*rdma_mock, ibv_is_fork_initialized())
		.WillOnce(Return(IBV_FORK_UNNEEDED));

	int ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_UNNEEDED);
}
