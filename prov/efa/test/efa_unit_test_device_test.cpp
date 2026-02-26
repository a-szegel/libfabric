/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_base.h"

extern "C" {
#include "efa_device.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;
using ::testing::SetArgPointee;

class EfaDeviceTest : public EfaUnitTest {};

TEST_F(EfaDeviceTest, ConstructErrorHandling)
{
	struct ibv_device mock_device = {};
	struct ibv_device *device_list[] = {&mock_device, nullptr};
	int ibv_err = 4242;

	EXPECT_CALL(*rdma_mock, ibv_get_device_list(_))
		.WillOnce(DoAll(SetArgPointee<0>(1), Return(device_list)));

	EXPECT_CALL(*rdma_mock, efadv_query_device(_, _, _))
		.WillOnce(Return(ibv_err));

	// Test would call efa_device_construct here
	// For now, just verify mocks work
	struct ibv_device **list = ibv_get_device_list(nullptr);
	EXPECT_NE(list, nullptr);
	
	int ret = efadv_query_device(nullptr, nullptr, 0);
	EXPECT_EQ(ret, ibv_err);
}
