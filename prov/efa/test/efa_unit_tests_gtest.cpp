/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

extern "C" {
#include <infiniband/verbs.h>
#include <infiniband/efadv.h>
#include <rdma/fabric.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>

// Undefine macros that conflict with mocking
#ifdef ibv_reg_mr
#undef ibv_reg_mr
#endif
#ifdef ibv_reg_mr_iova
#undef ibv_reg_mr_iova
#endif
#ifdef ibv_query_device
#undef ibv_query_device
#endif
#ifdef ibv_query_port
#undef ibv_query_port
#endif
#ifdef ibv_query_gid
#undef ibv_query_gid
#endif
}

using ::testing::_;
using ::testing::Return;
using ::testing::NiceMock;
using ::testing::SetArgPointee;
using ::testing::DoAll;

// Global mock pointer
class RdmaCoreMock;
static RdmaCoreMock *g_rdma_mock = nullptr;

// Mock class for rdma-core functions
class RdmaCoreMock {
public:
    MOCK_METHOD(struct ibv_device**, ibv_get_device_list, (int*));
    MOCK_METHOD(void, ibv_free_device_list, (struct ibv_device**));
    MOCK_METHOD(const char*, ibv_get_device_name, (struct ibv_device*));
    MOCK_METHOD(struct ibv_context*, ibv_open_device, (struct ibv_device*));
    MOCK_METHOD(int, ibv_close_device, (struct ibv_context*));
    MOCK_METHOD(int, ibv_query_device, (struct ibv_context*, struct ibv_device_attr*));
    MOCK_METHOD(int, ibv_query_port, (struct ibv_context*, uint8_t, struct ibv_port_attr*));
    MOCK_METHOD(int, ibv_query_gid, (struct ibv_context*, uint8_t, int, union ibv_gid*));
    MOCK_METHOD(struct ibv_pd*, ibv_alloc_pd, (struct ibv_context*));
    MOCK_METHOD(int, ibv_dealloc_pd, (struct ibv_pd*));
    MOCK_METHOD(struct ibv_mr*, ibv_reg_mr, (struct ibv_pd*, void*, size_t, int));
    MOCK_METHOD(int, ibv_dereg_mr, (struct ibv_mr*));
    MOCK_METHOD(struct ibv_cq*, ibv_create_cq, (struct ibv_context*, int, void*, struct ibv_comp_channel*, int));
    MOCK_METHOD(int, ibv_destroy_cq, (struct ibv_cq*));
    MOCK_METHOD(struct ibv_qp*, ibv_create_qp, (struct ibv_pd*, struct ibv_qp_init_attr*));
    MOCK_METHOD(int, ibv_destroy_qp, (struct ibv_qp*));
    MOCK_METHOD(int, ibv_modify_qp, (struct ibv_qp*, struct ibv_qp_attr*, int));
    MOCK_METHOD(struct ibv_ah*, ibv_create_ah, (struct ibv_pd*, struct ibv_ah_attr*));
    MOCK_METHOD(int, ibv_destroy_ah, (struct ibv_ah*));
    MOCK_METHOD(enum ibv_fork_status, ibv_is_fork_initialized, ());
    MOCK_METHOD(int, efadv_query_device, (struct ibv_context*, struct efadv_device_attr*, uint32_t));
    MOCK_METHOD(int, efadv_query_ah, (struct ibv_ah*, struct efadv_ah_attr*, uint32_t));
};

// C wrapper functions that delegate to mock
extern "C" {

struct ibv_device** __wrap_ibv_get_device_list(int *num) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_get_device_list(num);
}

void __wrap_ibv_free_device_list(struct ibv_device **list) {
    if (g_rdma_mock) g_rdma_mock->ibv_free_device_list(list);
}

const char* __wrap_ibv_get_device_name(struct ibv_device *device) {
    if (!g_rdma_mock) return "mock_device";
    return g_rdma_mock->ibv_get_device_name(device);
}

struct ibv_context* __wrap_ibv_open_device(struct ibv_device *device) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_open_device(device);
}

int __wrap_ibv_close_device(struct ibv_context *context) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_close_device(context);
}

int __wrap_ibv_query_device(struct ibv_context *context, struct ibv_device_attr *attr) {
    if (!g_rdma_mock) return -1;
    return g_rdma_mock->ibv_query_device(context, attr);
}

int __wrap_ibv_query_port(struct ibv_context *context, uint8_t port_num, struct ibv_port_attr *attr) {
    if (!g_rdma_mock) return -1;
    return g_rdma_mock->ibv_query_port(context, port_num, attr);
}

int __wrap_ibv_query_gid(struct ibv_context *context, uint8_t port_num, int index, union ibv_gid *gid) {
    if (!g_rdma_mock) return -1;
    return g_rdma_mock->ibv_query_gid(context, port_num, index, gid);
}

struct ibv_pd* __wrap_ibv_alloc_pd(struct ibv_context *context) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_alloc_pd(context);
}

int __wrap_ibv_dealloc_pd(struct ibv_pd *pd) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_dealloc_pd(pd);
}

struct ibv_mr* __wrap_ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length, int access) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_reg_mr(pd, addr, length, access);
}

int __wrap_ibv_dereg_mr(struct ibv_mr *mr) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_dereg_mr(mr);
}

struct ibv_cq* __wrap_ibv_create_cq(struct ibv_context *context, int cqe, void *cq_context,
                                     struct ibv_comp_channel *channel, int comp_vector) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_create_cq(context, cqe, cq_context, channel, comp_vector);
}

int __wrap_ibv_destroy_cq(struct ibv_cq *cq) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_destroy_cq(cq);
}

struct ibv_qp* __wrap_ibv_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_create_qp(pd, attr);
}

int __wrap_ibv_destroy_qp(struct ibv_qp *qp) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_destroy_qp(qp);
}

int __wrap_ibv_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_modify_qp(qp, attr, attr_mask);
}

struct ibv_ah* __wrap_ibv_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr) {
    if (!g_rdma_mock) return nullptr;
    return g_rdma_mock->ibv_create_ah(pd, attr);
}

int __wrap_ibv_destroy_ah(struct ibv_ah *ah) {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_destroy_ah(ah);
}

enum ibv_fork_status __wrap_ibv_is_fork_initialized() {
    if (!g_rdma_mock) return IBV_FORK_UNNEEDED;
    return g_rdma_mock->ibv_is_fork_initialized();
}

int __wrap_efadv_query_device(struct ibv_context *ibvctx, struct efadv_device_attr *attr, uint32_t inlen) {
    if (!g_rdma_mock) return -1;
    return g_rdma_mock->efadv_query_device(ibvctx, attr, inlen);
}

int __wrap_efadv_query_ah(struct ibv_ah *ibvah, struct efadv_ah_attr *attr, uint32_t inlen) {
    if (!g_rdma_mock) return -1;
    return g_rdma_mock->efadv_query_ah(ibvah, attr, inlen);
}

} // extern "C"

// Base test fixture
class EfaUnitTest : public ::testing::Test {
protected:
    NiceMock<RdmaCoreMock> *mock;

    void SetUp() override {
        mock = new NiceMock<RdmaCoreMock>();
        g_rdma_mock = mock;
    }

    void TearDown() override {
        g_rdma_mock = nullptr;
        delete mock;
    }
};

// ============================================================================
// DEVICE TESTS (efa_unit_test_device.c)
// ============================================================================

TEST_F(EfaUnitTest, DeviceQueryReturnsError) {
    EXPECT_CALL(*mock, ibv_query_device(_, _)).WillOnce(Return(-1));
    
    struct ibv_context ctx = {};
    struct ibv_device_attr attr = {};
    int ret = ibv_query_device(&ctx, &attr);
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// FORK SUPPORT TESTS (efa_unit_test_fork_support.c)
// ============================================================================

TEST_F(EfaUnitTest, ForkInitializedReturnsDisabled) {
    EXPECT_CALL(*mock, ibv_is_fork_initialized()).WillOnce(Return(IBV_FORK_DISABLED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_DISABLED);
}

TEST_F(EfaUnitTest, ForkInitializedReturnsUnneeded) {
    EXPECT_CALL(*mock, ibv_is_fork_initialized()).WillOnce(Return(IBV_FORK_UNNEEDED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_UNNEEDED);
}

// ============================================================================
// SEND TESTS (efa_unit_test_send.c)
// ============================================================================

TEST_F(EfaUnitTest, SendMockVerification) {
    // Just verify mocks work
    EXPECT_CALL(*mock, ibv_get_device_list(_)).WillOnce(Return(nullptr));
    
    struct ibv_device **list = ibv_get_device_list(nullptr);
    EXPECT_EQ(list, nullptr);
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
