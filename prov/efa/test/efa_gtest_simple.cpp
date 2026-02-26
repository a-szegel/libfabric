/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <infiniband/verbs.h>

using ::testing::Return;

// Simple mock for demonstration
class RdmaCoreMock {
public:
	virtual ~RdmaCoreMock() = default;
	MOCK_METHOD(enum ibv_fork_status, ibv_is_fork_initialized, ());
};

RdmaCoreMock* g_rdma_mock = nullptr;

extern "C" {
enum ibv_fork_status ibv_is_fork_initialized() {
	return g_rdma_mock->ibv_is_fork_initialized();
}
}

class SimpleTest : public ::testing::Test {
protected:
	void SetUp() override {
		mock = new ::testing::NiceMock<RdmaCoreMock>();
		g_rdma_mock = mock;
	}

	void TearDown() override {
		delete mock;
		g_rdma_mock = nullptr;
	}

	RdmaCoreMock* mock;
};

TEST_F(SimpleTest, MockWorks) {
	EXPECT_CALL(*mock, ibv_is_fork_initialized())
		.WillOnce(Return((enum ibv_fork_status)IBV_FORK_DISABLED));

	enum ibv_fork_status ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_DISABLED);
}

TEST_F(SimpleTest, AnotherTest) {
	EXPECT_CALL(*mock, ibv_is_fork_initialized())
		.WillOnce(Return((enum ibv_fork_status)IBV_FORK_UNNEEDED));

	enum ibv_fork_status ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_UNNEEDED);
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
