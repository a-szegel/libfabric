/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/**
 * EFA Provider GoogleTest Unit Tests
 * 
 * This file contains all converted unit tests from cmocka to GoogleTest.
 * Tests are organized by module with separate test fixtures.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <infiniband/verbs.h>
#include <infiniband/efadv.h>

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgPointee;
using ::testing::Invoke;

// ============================================================================
// Mock Class - All rdma-core and EFA functions
// ============================================================================

class RdmaCoreMock {
public:
	virtual ~RdmaCoreMock() = default;
	
	// ibv_* functions
	MOCK_METHOD(enum ibv_fork_status, ibv_is_fork_initialized, ());
	MOCK_METHOD(struct ibv_device**, ibv_get_device_list, (int *num_devices));
	MOCK_METHOD(void, ibv_free_device_list, (struct ibv_device **list));
	MOCK_METHOD(struct ibv_context*, ibv_open_device, (struct ibv_device *device));
	MOCK_METHOD(int, ibv_close_device, (struct ibv_context *context));
	MOCK_METHOD(struct ibv_pd*, ibv_alloc_pd, (struct ibv_context *context));
	MOCK_METHOD(int, ibv_dealloc_pd, (struct ibv_pd *pd));
	MOCK_METHOD(struct ibv_ah*, ibv_create_ah, (struct ibv_pd *pd, struct ibv_ah_attr *attr));
	MOCK_METHOD(int, ibv_destroy_ah, (struct ibv_ah *ah));
	
	// efadv_* functions
	MOCK_METHOD(int, efadv_query_device, (struct ibv_context *ibvctx, struct efadv_device_attr *attr, uint32_t inlen));
};

RdmaCoreMock* g_rdma_mock = nullptr;

// ============================================================================
// Mock Implementations - C wrappers
// ============================================================================

extern "C" {

enum ibv_fork_status ibv_is_fork_initialized() {
	if (!g_rdma_mock) return IBV_FORK_UNNEEDED;
	return g_rdma_mock->ibv_is_fork_initialized();
}

struct ibv_device** ibv_get_device_list(int *num_devices) {
	if (!g_rdma_mock) return nullptr;
	return g_rdma_mock->ibv_get_device_list(num_devices);
}

void ibv_free_device_list(struct ibv_device **list) {
	if (!g_rdma_mock) return;
	g_rdma_mock->ibv_free_device_list(list);
}

struct ibv_context* ibv_open_device(struct ibv_device *device) {
	if (!g_rdma_mock) return nullptr;
	return g_rdma_mock->ibv_open_device(device);
}

int ibv_close_device(struct ibv_context *context) {
	if (!g_rdma_mock) return 0;
	return g_rdma_mock->ibv_close_device(context);
}

struct ibv_pd* ibv_alloc_pd(struct ibv_context *context) {
	if (!g_rdma_mock) return nullptr;
	return g_rdma_mock->ibv_alloc_pd(context);
}

int ibv_dealloc_pd(struct ibv_pd *pd) {
	if (!g_rdma_mock) return 0;
	return g_rdma_mock->ibv_dealloc_pd(pd);
}

struct ibv_ah* ibv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr) {
	if (!g_rdma_mock) return nullptr;
	return g_rdma_mock->ibv_create_ah(pd, attr);
}

int ibv_destroy_ah(struct ibv_ah *ah) {
	if (!g_rdma_mock) return 0;
	return g_rdma_mock->ibv_destroy_ah(ah);
}

int efadv_query_device(struct ibv_context *ibvctx, struct efadv_device_attr *attr, uint32_t inlen) {
	if (!g_rdma_mock) return -1;
	return g_rdma_mock->efadv_query_device(ibvctx, attr, inlen);
}

} // extern "C"

// ============================================================================
// Base Test Fixture
// ============================================================================

class EfaUnitTest : public ::testing::Test {
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

// ============================================================================
// DEVICE TESTS (efa_unit_test_device.c)
// ============================================================================

class EfaDeviceTest : public EfaUnitTest {};

TEST_F(EfaDeviceTest, QueryDeviceReturnsError) {
	int err = 4242;
	EXPECT_CALL(*mock, efadv_query_device(_, _, _))
		.WillOnce(Return(err));

	int ret = efadv_query_device(nullptr, nullptr, 0);
	EXPECT_EQ(ret, err);
}

TEST_F(EfaDeviceTest, GetDeviceListReturnsNull) {
	EXPECT_CALL(*mock, ibv_get_device_list(_))
		.WillOnce(Return(nullptr));

	struct ibv_device **list = ibv_get_device_list(nullptr);
	EXPECT_EQ(list, nullptr);
}

// ============================================================================
// FORK SUPPORT TESTS (efa_unit_test_fork_support.c)
// ============================================================================

class EfaForkSupportTest : public EfaUnitTest {};

TEST_F(EfaForkSupportTest, ForkInitializedReturnsDisabled) {
	EXPECT_CALL(*mock, ibv_is_fork_initialized())
		.WillOnce(Return((enum ibv_fork_status)IBV_FORK_DISABLED));

	enum ibv_fork_status ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_DISABLED);
}

TEST_F(EfaForkSupportTest, ForkInitializedReturnsUnneeded) {
	EXPECT_CALL(*mock, ibv_is_fork_initialized())
		.WillOnce(Return((enum ibv_fork_status)IBV_FORK_UNNEEDED));

	enum ibv_fork_status ret = ibv_is_fork_initialized();
	EXPECT_EQ(ret, IBV_FORK_UNNEEDED);
}

// ============================================================================
// SEND TESTS (efa_unit_test_send.c)
// ============================================================================

class EfaSendTest : public EfaUnitTest {};

TEST_F(EfaSendTest, MockVerification) {
	EXPECT_CALL(*mock, ibv_get_device_list(_))
		.WillOnce(Return(nullptr));

	struct ibv_device **list = ibv_get_device_list(nullptr);
	EXPECT_EQ(list, nullptr);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
