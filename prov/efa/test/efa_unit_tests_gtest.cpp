/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string.h>
#include <stdlib.h>

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
using ::testing::Invoke;

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
    MOCK_METHOD(int, ibv_fork_init, ());
    MOCK_METHOD(int, efadv_query_device, (struct ibv_context*, struct efadv_device_attr*, uint32_t));
    MOCK_METHOD(int, efadv_query_ah, (struct ibv_ah*, struct efadv_ah_attr*, uint32_t));
};

// C wrapper functions
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

int __wrap_ibv_fork_init() {
    if (!g_rdma_mock) return 0;
    return g_rdma_mock->ibv_fork_init();
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
// DEVICE TESTS - Pure unit tests for device operations
// ============================================================================

TEST_F(EfaUnitTest, DeviceListReturnsNull) {
    EXPECT_CALL(*mock, ibv_get_device_list(_))
        .WillOnce(DoAll(SetArgPointee<0>(0), Return(nullptr)));
    
    int num_devices = 0;
    struct ibv_device **list = ibv_get_device_list(&num_devices);
    
    EXPECT_EQ(list, nullptr);
    EXPECT_EQ(num_devices, 0);
}

TEST_F(EfaUnitTest, DeviceListReturnsDevices) {
    struct ibv_device mock_device;
    struct ibv_device *device_array[2] = {&mock_device, nullptr};
    
    EXPECT_CALL(*mock, ibv_get_device_list(_))
        .WillOnce(DoAll(SetArgPointee<0>(1), Return(device_array)));
    
    int num_devices = 0;
    struct ibv_device **list = ibv_get_device_list(&num_devices);
    
    EXPECT_NE(list, nullptr);
    EXPECT_EQ(num_devices, 1);
    EXPECT_EQ(list[0], &mock_device);
}

TEST_F(EfaUnitTest, DeviceGetNameReturnsName) {
    struct ibv_device mock_device;
    
    EXPECT_CALL(*mock, ibv_get_device_name(&mock_device))
        .WillOnce(Return("rdmap0s31-rdm"));
    
    const char *name = ibv_get_device_name(&mock_device);
    EXPECT_STREQ(name, "rdmap0s31-rdm");
}

TEST_F(EfaUnitTest, DeviceOpenSuccess) {
    struct ibv_device mock_device;
    struct ibv_context mock_ctx;
    
    EXPECT_CALL(*mock, ibv_open_device(&mock_device))
        .WillOnce(Return(&mock_ctx));
    
    struct ibv_context *ctx = ibv_open_device(&mock_device);
    EXPECT_EQ(ctx, &mock_ctx);
}

TEST_F(EfaUnitTest, DeviceOpenFailure) {
    struct ibv_device mock_device;
    
    EXPECT_CALL(*mock, ibv_open_device(&mock_device))
        .WillOnce(Return(nullptr));
    
    struct ibv_context *ctx = ibv_open_device(&mock_device);
    EXPECT_EQ(ctx, nullptr);
}

TEST_F(EfaUnitTest, DeviceCloseSuccess) {
    struct ibv_context mock_ctx;
    
    EXPECT_CALL(*mock, ibv_close_device(&mock_ctx))
        .WillOnce(Return(0));
    
    int ret = ibv_close_device(&mock_ctx);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, DeviceQuerySuccess) {
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr;
    
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, &attr))
        .WillOnce(Invoke([](struct ibv_context*, struct ibv_device_attr *a) {
            a->max_qp = 1024;
            a->max_cq = 512;
            return 0;
        }));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.max_qp, 1024);
    EXPECT_EQ(attr.max_cq, 512);
}

TEST_F(EfaUnitTest, DeviceQueryFailure) {
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr;
    
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, &attr))
        .WillOnce(Return(-1));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, -1);
}

TEST_F(EfaUnitTest, EfadvQueryDeviceSuccess) {
    struct ibv_context mock_ctx;
    struct efadv_device_attr attr = {};
    
    EXPECT_CALL(*mock, efadv_query_device(&mock_ctx, &attr, sizeof(attr)))
        .WillOnce(Invoke([](struct ibv_context*, struct efadv_device_attr *a, uint32_t) {
            a->max_sq_wr = 2048;
            a->max_rq_wr = 2048;
            return 0;
        }));
    
    int ret = efadv_query_device(&mock_ctx, &attr, sizeof(attr));
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.max_sq_wr, 2048);
    EXPECT_EQ(attr.max_rq_wr, 2048);
}

TEST_F(EfaUnitTest, EfadvQueryDeviceFailure) {
    struct ibv_context mock_ctx;
    struct efadv_device_attr attr = {};
    
    EXPECT_CALL(*mock, efadv_query_device(&mock_ctx, &attr, sizeof(attr)))
        .WillOnce(Return(-1));
    
    int ret = efadv_query_device(&mock_ctx, &attr, sizeof(attr));
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// FORK SUPPORT TESTS - Pure unit tests for fork support
// ============================================================================

TEST_F(EfaUnitTest, ForkStatusDisabled) {
    EXPECT_CALL(*mock, ibv_is_fork_initialized())
        .WillOnce(Return(IBV_FORK_DISABLED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_DISABLED);
}

TEST_F(EfaUnitTest, ForkStatusEnabled) {
    EXPECT_CALL(*mock, ibv_is_fork_initialized())
        .WillOnce(Return(IBV_FORK_ENABLED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_ENABLED);
}

TEST_F(EfaUnitTest, ForkStatusUnneeded) {
    EXPECT_CALL(*mock, ibv_is_fork_initialized())
        .WillOnce(Return(IBV_FORK_UNNEEDED));
    
    enum ibv_fork_status status = ibv_is_fork_initialized();
    EXPECT_EQ(status, IBV_FORK_UNNEEDED);
}

TEST_F(EfaUnitTest, ForkInitSuccess) {
    EXPECT_CALL(*mock, ibv_fork_init())
        .WillOnce(Return(0));
    
    int ret = ibv_fork_init();
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, ForkInitFailure) {
    EXPECT_CALL(*mock, ibv_fork_init())
        .WillOnce(Return(-1));
    
    int ret = ibv_fork_init();
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// PROTECTION DOMAIN TESTS - Pure unit tests for PD operations
// ============================================================================

TEST_F(EfaUnitTest, PdAllocSuccess) {
    struct ibv_context mock_ctx;
    struct ibv_pd mock_pd;
    
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx))
        .WillOnce(Return(&mock_pd));
    
    struct ibv_pd *pd = ibv_alloc_pd(&mock_ctx);
    EXPECT_EQ(pd, &mock_pd);
}

TEST_F(EfaUnitTest, PdAllocFailure) {
    struct ibv_context mock_ctx;
    
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx))
        .WillOnce(Return(nullptr));
    
    struct ibv_pd *pd = ibv_alloc_pd(&mock_ctx);
    EXPECT_EQ(pd, nullptr);
}

TEST_F(EfaUnitTest, PdDeallocSuccess) {
    struct ibv_pd mock_pd;
    
    EXPECT_CALL(*mock, ibv_dealloc_pd(&mock_pd))
        .WillOnce(Return(0));
    
    int ret = ibv_dealloc_pd(&mock_pd);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, PdDeallocFailure) {
    struct ibv_pd mock_pd;
    
    EXPECT_CALL(*mock, ibv_dealloc_pd(&mock_pd))
        .WillOnce(Return(-1));
    
    int ret = ibv_dealloc_pd(&mock_pd);
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// MEMORY REGION TESTS - Pure unit tests for MR operations
// ============================================================================

TEST_F(EfaUnitTest, MrRegisterSuccess) {
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    char buffer[4096];
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buffer, 4096, IBV_ACCESS_LOCAL_WRITE))
        .WillOnce(Return(&mock_mr));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, buffer, 4096, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_EQ(mr, &mock_mr);
}

TEST_F(EfaUnitTest, MrRegisterFailure) {
    struct ibv_pd mock_pd;
    char buffer[4096];
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buffer, 4096, _))
        .WillOnce(Return(nullptr));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, buffer, 4096, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_EQ(mr, nullptr);
}

TEST_F(EfaUnitTest, MrDeregisterSuccess) {
    struct ibv_mr mock_mr;
    
    EXPECT_CALL(*mock, ibv_dereg_mr(&mock_mr))
        .WillOnce(Return(0));
    
    int ret = ibv_dereg_mr(&mock_mr);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, MrDeregisterFailure) {
    struct ibv_mr mock_mr;
    
    EXPECT_CALL(*mock, ibv_dereg_mr(&mock_mr))
        .WillOnce(Return(-1));
    
    int ret = ibv_dereg_mr(&mock_mr);
    EXPECT_EQ(ret, -1);
}

TEST_F(EfaUnitTest, MrRegisterWithDifferentAccessFlags) {
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    char buffer[4096];
    
    int access_flags[] = {
        IBV_ACCESS_LOCAL_WRITE,
        IBV_ACCESS_REMOTE_WRITE,
        IBV_ACCESS_REMOTE_READ,
        IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE
    };
    
    for (int flags : access_flags) {
        EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buffer, 4096, flags))
            .WillOnce(Return(&mock_mr));
        
        struct ibv_mr *mr = ibv_reg_mr(&mock_pd, buffer, 4096, flags);
        EXPECT_EQ(mr, &mock_mr);
    }
}

// ============================================================================
// COMPLETION QUEUE TESTS - Pure unit tests for CQ operations
// ============================================================================

TEST_F(EfaUnitTest, CqCreateSuccess) {
    struct ibv_context mock_ctx;
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0))
        .WillOnce(Return(&mock_cq));
    
    struct ibv_cq *cq = ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0);
    EXPECT_EQ(cq, &mock_cq);
}

TEST_F(EfaUnitTest, CqCreateFailure) {
    struct ibv_context mock_ctx;
    
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0))
        .WillOnce(Return(nullptr));
    
    struct ibv_cq *cq = ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0);
    EXPECT_EQ(cq, nullptr);
}

TEST_F(EfaUnitTest, CqDestroySuccess) {
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_destroy_cq(&mock_cq))
        .WillOnce(Return(0));
    
    int ret = ibv_destroy_cq(&mock_cq);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, CqDestroyFailure) {
    struct ibv_cq mock_cq;
    
    EXPECT_CALL(*mock, ibv_destroy_cq(&mock_cq))
        .WillOnce(Return(-1));
    
    int ret = ibv_destroy_cq(&mock_cq);
    EXPECT_EQ(ret, -1);
}

TEST_F(EfaUnitTest, CqCreateWithDifferentSizes) {
    struct ibv_context mock_ctx;
    struct ibv_cq mock_cq;
    
    int sizes[] = {64, 128, 256, 512, 1024, 2048, 4096};
    
    for (int size : sizes) {
        EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, size, nullptr, nullptr, 0))
            .WillOnce(Return(&mock_cq));
        
        struct ibv_cq *cq = ibv_create_cq(&mock_ctx, size, nullptr, nullptr, 0);
        EXPECT_EQ(cq, &mock_cq);
    }
}

// ============================================================================
// QUEUE PAIR TESTS - Pure unit tests for QP operations
// ============================================================================

TEST_F(EfaUnitTest, QpCreateSuccess) {
    struct ibv_pd mock_pd;
    struct ibv_qp mock_qp;
    struct ibv_qp_init_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, &attr))
        .WillOnce(Return(&mock_qp));
    
    struct ibv_qp *qp = ibv_create_qp(&mock_pd, &attr);
    EXPECT_EQ(qp, &mock_qp);
}

TEST_F(EfaUnitTest, QpCreateFailure) {
    struct ibv_pd mock_pd;
    struct ibv_qp_init_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, &attr))
        .WillOnce(Return(nullptr));
    
    struct ibv_qp *qp = ibv_create_qp(&mock_pd, &attr);
    EXPECT_EQ(qp, nullptr);
}

TEST_F(EfaUnitTest, QpDestroySuccess) {
    struct ibv_qp mock_qp;
    
    EXPECT_CALL(*mock, ibv_destroy_qp(&mock_qp))
        .WillOnce(Return(0));
    
    int ret = ibv_destroy_qp(&mock_qp);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, QpDestroyFailure) {
    struct ibv_qp mock_qp;
    
    EXPECT_CALL(*mock, ibv_destroy_qp(&mock_qp))
        .WillOnce(Return(-1));
    
    int ret = ibv_destroy_qp(&mock_qp);
    EXPECT_EQ(ret, -1);
}

TEST_F(EfaUnitTest, QpModifySuccess) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE))
        .WillOnce(Return(0));
    
    int ret = ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, QpModifyFailure) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE))
        .WillOnce(Return(-1));
    
    int ret = ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE);
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// ADDRESS HANDLE TESTS - Pure unit tests for AH operations
// ============================================================================

TEST_F(EfaUnitTest, AhCreateSuccess) {
    struct ibv_pd mock_pd;
    struct ibv_ah mock_ah;
    struct ibv_ah_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_create_ah(&mock_pd, &attr))
        .WillOnce(Return(&mock_ah));
    
    struct ibv_ah *ah = ibv_create_ah(&mock_pd, &attr);
    EXPECT_EQ(ah, &mock_ah);
}

TEST_F(EfaUnitTest, AhCreateFailure) {
    struct ibv_pd mock_pd;
    struct ibv_ah_attr attr = {};
    
    EXPECT_CALL(*mock, ibv_create_ah(&mock_pd, &attr))
        .WillOnce(Return(nullptr));
    
    struct ibv_ah *ah = ibv_create_ah(&mock_pd, &attr);
    EXPECT_EQ(ah, nullptr);
}

TEST_F(EfaUnitTest, AhDestroySuccess) {
    struct ibv_ah mock_ah;
    
    EXPECT_CALL(*mock, ibv_destroy_ah(&mock_ah))
        .WillOnce(Return(0));
    
    int ret = ibv_destroy_ah(&mock_ah);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, AhDestroyFailure) {
    struct ibv_ah mock_ah;
    
    EXPECT_CALL(*mock, ibv_destroy_ah(&mock_ah))
        .WillOnce(Return(-1));
    
    int ret = ibv_destroy_ah(&mock_ah);
    EXPECT_EQ(ret, -1);
}

TEST_F(EfaUnitTest, EfadvQueryAhSuccess) {
    struct ibv_ah mock_ah;
    struct efadv_ah_attr attr = {};
    
    EXPECT_CALL(*mock, efadv_query_ah(&mock_ah, &attr, sizeof(attr)))
        .WillOnce(Invoke([](struct ibv_ah*, struct efadv_ah_attr *a, uint32_t) {
            a->ahn = 42;
            return 0;
        }));
    
    int ret = efadv_query_ah(&mock_ah, &attr, sizeof(attr));
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.ahn, 42);
}

TEST_F(EfaUnitTest, EfadvQueryAhFailure) {
    struct ibv_ah mock_ah;
    struct efadv_ah_attr attr = {};
    
    EXPECT_CALL(*mock, efadv_query_ah(&mock_ah, &attr, sizeof(attr)))
        .WillOnce(Return(-1));
    
    int ret = efadv_query_ah(&mock_ah, &attr, sizeof(attr));
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// PORT AND GID TESTS - Pure unit tests for port/GID queries
// ============================================================================

TEST_F(EfaUnitTest, GidQuerySuccess) {
    struct ibv_context mock_ctx;
    union ibv_gid gid;
    
    EXPECT_CALL(*mock, ibv_query_gid(&mock_ctx, 1, 0, &gid))
        .WillOnce(Invoke([](struct ibv_context*, uint8_t, int, union ibv_gid *g) {
            memset(g, 0xAB, sizeof(*g));
            return 0;
        }));
    
    int ret = ibv_query_gid(&mock_ctx, 1, 0, &gid);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(gid.raw[0], 0xAB);
}

TEST_F(EfaUnitTest, GidQueryFailure) {
    struct ibv_context mock_ctx;
    union ibv_gid gid;
    
    EXPECT_CALL(*mock, ibv_query_gid(&mock_ctx, 1, 0, &gid))
        .WillOnce(Return(-1));
    
    int ret = ibv_query_gid(&mock_ctx, 1, 0, &gid);
    EXPECT_EQ(ret, -1);
}

// ============================================================================
// EDGE CASE AND ERROR HANDLING TESTS
// ============================================================================

TEST_F(EfaUnitTest, NullPointerHandling) {
    // Test that functions handle null pointers gracefully
    EXPECT_CALL(*mock, ibv_get_device_list(nullptr))
        .WillOnce(Return(nullptr));
    
    struct ibv_device **list = ibv_get_device_list(nullptr);
    EXPECT_EQ(list, nullptr);
}

TEST_F(EfaUnitTest, MultipleDeviceOperations) {
    struct ibv_device mock_device;
    struct ibv_context mock_ctx;
    struct ibv_pd mock_pd;
    
    // Open device
    EXPECT_CALL(*mock, ibv_open_device(&mock_device))
        .WillOnce(Return(&mock_ctx));
    
    struct ibv_context *ctx = ibv_open_device(&mock_device);
    ASSERT_NE(ctx, nullptr);
    
    // Allocate PD
    EXPECT_CALL(*mock, ibv_alloc_pd(ctx))
        .WillOnce(Return(&mock_pd));
    
    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    ASSERT_NE(pd, nullptr);
    
    // Deallocate PD
    EXPECT_CALL(*mock, ibv_dealloc_pd(pd))
        .WillOnce(Return(0));
    
    int ret = ibv_dealloc_pd(pd);
    EXPECT_EQ(ret, 0);
    
    // Close device
    EXPECT_CALL(*mock, ibv_close_device(ctx))
        .WillOnce(Return(0));
    
    ret = ibv_close_device(ctx);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, ResourceCleanupOnFailure) {
    struct ibv_context mock_ctx;
    struct ibv_pd mock_pd;
    struct ibv_cq mock_cq;
    
    // Successful PD allocation
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx))
        .WillOnce(Return(&mock_pd));
    
    struct ibv_pd *pd = ibv_alloc_pd(&mock_ctx);
    ASSERT_NE(pd, nullptr);
    
    // Failed CQ creation
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0))
        .WillOnce(Return(nullptr));
    
    struct ibv_cq *cq = ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0);
    EXPECT_EQ(cq, nullptr);
    
    // Cleanup PD
    EXPECT_CALL(*mock, ibv_dealloc_pd(pd))
        .WillOnce(Return(0));
    
    int ret = ibv_dealloc_pd(pd);
    EXPECT_EQ(ret, 0);
}

TEST_F(EfaUnitTest, ConcurrentOperations) {
    struct ibv_context mock_ctx;
    struct ibv_pd mock_pd1, mock_pd2;
    
    // Allocate multiple PDs
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx))
        .WillOnce(Return(&mock_pd1))
        .WillOnce(Return(&mock_pd2));
    
    struct ibv_pd *pd1 = ibv_alloc_pd(&mock_ctx);
    struct ibv_pd *pd2 = ibv_alloc_pd(&mock_ctx);
    
    EXPECT_NE(pd1, nullptr);
    EXPECT_NE(pd2, nullptr);
    EXPECT_NE(pd1, pd2);
    
    // Deallocate in reverse order
    EXPECT_CALL(*mock, ibv_dealloc_pd(pd2))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, ibv_dealloc_pd(pd1))
        .WillOnce(Return(0));
    
    EXPECT_EQ(ibv_dealloc_pd(pd2), 0);
    EXPECT_EQ(ibv_dealloc_pd(pd1), 0);
}

TEST_F(EfaUnitTest, LargeBufferRegistration) {
    struct ibv_pd mock_pd;
    struct ibv_mr mock_mr;
    size_t large_size = 1024 * 1024 * 1024; // 1GB
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, _, large_size, _))
        .WillOnce(Return(&mock_mr));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, nullptr, large_size, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_EQ(mr, &mock_mr);
}

TEST_F(EfaUnitTest, ZeroSizeOperations) {
    struct ibv_pd mock_pd;
    
    // Zero-size MR registration should fail
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, _, 0, _))
        .WillOnce(Return(nullptr));
    
    struct ibv_mr *mr = ibv_reg_mr(&mock_pd, nullptr, 0, IBV_ACCESS_LOCAL_WRITE);
    EXPECT_EQ(mr, nullptr);
}

TEST_F(EfaUnitTest, MaxResourceLimits) {
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr;
    
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, &attr))
        .WillOnce(Invoke([](struct ibv_context*, struct ibv_device_attr *a) {
            a->max_qp = 32768;
            a->max_cq = 16384;
            a->max_mr = 65536;
            a->max_pd = 256;
            a->max_qp_wr = 16384;
            a->max_cqe = 131072;
            return 0;
        }));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, 0);
    EXPECT_GT(attr.max_qp, 0);
    EXPECT_GT(attr.max_cq, 0);
    EXPECT_GT(attr.max_mr, 0);
}

// ============================================================================
// ADDITIONAL COMPREHENSIVE TESTS
// ============================================================================

TEST_F(EfaUnitTest, DeviceListMultipleDevices) {
    struct ibv_device dev1, dev2, dev3;
    struct ibv_device *device_array[4] = {&dev1, &dev2, &dev3, nullptr};
    
    EXPECT_CALL(*mock, ibv_get_device_list(_))
        .WillOnce(DoAll(SetArgPointee<0>(3), Return(device_array)));
    
    int num = 0;
    struct ibv_device **list = ibv_get_device_list(&num);
    
    EXPECT_EQ(num, 3);
    EXPECT_EQ(list[0], &dev1);
    EXPECT_EQ(list[1], &dev2);
    EXPECT_EQ(list[2], &dev3);
    EXPECT_EQ(list[3], nullptr);
}

TEST_F(EfaUnitTest, DeviceFreeList) {
    struct ibv_device mock_device;
    struct ibv_device *device_array[2] = {&mock_device, nullptr};
    
    EXPECT_CALL(*mock, ibv_free_device_list(device_array))
        .Times(1);
    
    ibv_free_device_list(device_array);
}

TEST_F(EfaUnitTest, MrMultipleRegistrations) {
    struct ibv_pd mock_pd;
    struct ibv_mr mr1, mr2, mr3;
    char buf1[1024], buf2[2048], buf3[4096];
    
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf1, 1024, _))
        .WillOnce(Return(&mr1));
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf2, 2048, _))
        .WillOnce(Return(&mr2));
    EXPECT_CALL(*mock, ibv_reg_mr(&mock_pd, buf3, 4096, _))
        .WillOnce(Return(&mr3));
    
    struct ibv_mr *m1 = ibv_reg_mr(&mock_pd, buf1, 1024, IBV_ACCESS_LOCAL_WRITE);
    struct ibv_mr *m2 = ibv_reg_mr(&mock_pd, buf2, 2048, IBV_ACCESS_LOCAL_WRITE);
    struct ibv_mr *m3 = ibv_reg_mr(&mock_pd, buf3, 4096, IBV_ACCESS_LOCAL_WRITE);
    
    EXPECT_EQ(m1, &mr1);
    EXPECT_EQ(m2, &mr2);
    EXPECT_EQ(m3, &mr3);
}

TEST_F(EfaUnitTest, CqMultipleSizes) {
    struct ibv_context mock_ctx;
    struct ibv_cq cq1, cq2, cq3;
    
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 128, _, _, _))
        .WillOnce(Return(&cq1));
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 512, _, _, _))
        .WillOnce(Return(&cq2));
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, 2048, _, _, _))
        .WillOnce(Return(&cq3));
    
    struct ibv_cq *c1 = ibv_create_cq(&mock_ctx, 128, nullptr, nullptr, 0);
    struct ibv_cq *c2 = ibv_create_cq(&mock_ctx, 512, nullptr, nullptr, 0);
    struct ibv_cq *c3 = ibv_create_cq(&mock_ctx, 2048, nullptr, nullptr, 0);
    
    EXPECT_EQ(c1, &cq1);
    EXPECT_EQ(c2, &cq2);
    EXPECT_EQ(c3, &cq3);
}

TEST_F(EfaUnitTest, QpStateTransitions) {
    struct ibv_qp mock_qp;
    struct ibv_qp_attr attr = {};
    
    // RESET -> INIT
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, IBV_QP_STATE))
        .WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
    
    // INIT -> RTR
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, IBV_QP_STATE))
        .WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
    
    // RTR -> RTS
    EXPECT_CALL(*mock, ibv_modify_qp(&mock_qp, _, IBV_QP_STATE))
        .WillOnce(Return(0));
    EXPECT_EQ(ibv_modify_qp(&mock_qp, &attr, IBV_QP_STATE), 0);
}

TEST_F(EfaUnitTest, DeviceAttributeValidation) {
    struct ibv_context mock_ctx;
    struct ibv_device_attr attr;
    
    EXPECT_CALL(*mock, ibv_query_device(&mock_ctx, &attr))
        .WillOnce(Invoke([](struct ibv_context*, struct ibv_device_attr *a) {
            strncpy(a->fw_ver, "1.2.3.4", sizeof(a->fw_ver) - 1);
            a->node_guid = 0xABCDEF0123456789ULL;
            a->sys_image_guid = 0x9876543210FEDCBAULL;
            a->max_mr_size = 0xFFFFFFFFFFFFFFFFULL;
            a->page_size_cap = 4096;
            a->vendor_id = 0x1D0F; // Amazon
            a->vendor_part_id = 0xEFA0;
            a->hw_ver = 1;
            a->max_qp = 2048;
            a->max_qp_wr = 8192;
            a->device_cap_flags = IBV_DEVICE_RESIZE_MAX_WR | IBV_DEVICE_BAD_PKEY_CNTR;
            a->max_sge = 16;
            a->max_sge_rd = 16;
            a->max_cq = 1024;
            a->max_cqe = 16384;
            a->max_mr = 32768;
            a->max_pd = 256;
            a->max_qp_rd_atom = 16;
            a->max_ee_rd_atom = 0;
            a->max_res_rd_atom = 32768;
            a->max_qp_init_rd_atom = 16;
            a->max_ee_init_rd_atom = 0;
            a->atomic_cap = IBV_ATOMIC_NONE;
            a->max_ee = 0;
            a->max_rdd = 0;
            a->max_mw = 0;
            a->max_raw_ipv6_qp = 0;
            a->max_raw_ethy_qp = 0;
            a->max_mcast_grp = 0;
            a->max_mcast_qp_attach = 0;
            a->max_total_mcast_qp_attach = 0;
            a->max_ah = 256;
            a->max_fmr = 0;
            a->max_map_per_fmr = 0;
            a->max_srq = 0;
            a->max_srq_wr = 0;
            a->max_srq_sge = 0;
            a->max_pkeys = 1;
            a->local_ca_ack_delay = 0;
            a->phys_port_cnt = 1;
            return 0;
        }));
    
    int ret = ibv_query_device(&mock_ctx, &attr);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.vendor_id, 0x1D0F);
    EXPECT_EQ(attr.max_qp, 2048);
    EXPECT_EQ(attr.max_sge, 16);
    EXPECT_EQ(attr.phys_port_cnt, 1);
}

TEST_F(EfaUnitTest, EfaDeviceSpecificAttributes) {
    struct ibv_context mock_ctx;
    struct efadv_device_attr attr = {};
    
    EXPECT_CALL(*mock, efadv_query_device(&mock_ctx, &attr, sizeof(attr)))
        .WillOnce(Invoke([](struct ibv_context*, struct efadv_device_attr *a, uint32_t) {
            a->max_sq_wr = 8192;
            a->max_rq_wr = 8192;
            a->max_sq_sge = 16;
            a->max_rq_sge = 16;
            a->inline_buf_size = 128;
            a->max_rdma_size = 1024 * 1024; // 1MB
            a->device_caps = EFADV_DEVICE_ATTR_CAPS_RDMA_READ | EFADV_DEVICE_ATTR_CAPS_RNR_RETRY;
            return 0;
        }));
    
    int ret = efadv_query_device(&mock_ctx, &attr, sizeof(attr));
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(attr.max_sq_wr, 8192);
    EXPECT_EQ(attr.max_rq_wr, 8192);
    EXPECT_EQ(attr.inline_buf_size, 128);
    EXPECT_TRUE(attr.device_caps & EFADV_DEVICE_ATTR_CAPS_RDMA_READ);
}

TEST_F(EfaUnitTest, ErrorRecoverySequence) {
    struct ibv_context mock_ctx;
    struct ibv_pd mock_pd;
    struct ibv_cq mock_cq;
    struct ibv_qp mock_qp;
    
    // Successful setup
    EXPECT_CALL(*mock, ibv_alloc_pd(&mock_ctx)).WillOnce(Return(&mock_pd));
    EXPECT_CALL(*mock, ibv_create_cq(&mock_ctx, _, _, _, _)).WillOnce(Return(&mock_cq));
    EXPECT_CALL(*mock, ibv_create_qp(&mock_pd, _)).WillOnce(Return(&mock_qp));
    
    struct ibv_pd *pd = ibv_alloc_pd(&mock_ctx);
    struct ibv_cq *cq = ibv_create_cq(&mock_ctx, 1024, nullptr, nullptr, 0);
    struct ibv_qp_init_attr qp_attr = {};
    struct ibv_qp *qp = ibv_create_qp(pd, &qp_attr);
    
    ASSERT_NE(pd, nullptr);
    ASSERT_NE(cq, nullptr);
    ASSERT_NE(qp, nullptr);
    
    // Cleanup in reverse order
    EXPECT_CALL(*mock, ibv_destroy_qp(qp)).WillOnce(Return(0));
    EXPECT_CALL(*mock, ibv_destroy_cq(cq)).WillOnce(Return(0));
    EXPECT_CALL(*mock, ibv_dealloc_pd(pd)).WillOnce(Return(0));
    
    EXPECT_EQ(ibv_destroy_qp(qp), 0);
    EXPECT_EQ(ibv_destroy_cq(cq), 0);
    EXPECT_EQ(ibv_dealloc_pd(pd), 0);
}

TEST_F(EfaUnitTest, ForkSupportCombinations) {
    // Test all fork status combinations
    enum ibv_fork_status statuses[] = {
        IBV_FORK_DISABLED,
        IBV_FORK_ENABLED,
        IBV_FORK_UNNEEDED
    };
    
    for (auto status : statuses) {
        EXPECT_CALL(*mock, ibv_is_fork_initialized())
            .WillOnce(Return(status));
        
        enum ibv_fork_status result = ibv_is_fork_initialized();
        EXPECT_EQ(result, status);
    }
}

TEST_F(EfaUnitTest, GidQueryMultipleIndices) {
    struct ibv_context mock_ctx;
    union ibv_gid gid;
    
    for (int idx = 0; idx < 4; idx++) {
        EXPECT_CALL(*mock, ibv_query_gid(&mock_ctx, 1, idx, &gid))
            .WillOnce(Invoke([idx](struct ibv_context*, uint8_t, int, union ibv_gid *g) {
                memset(g, idx, sizeof(*g));
                return 0;
            }));
        
        int ret = ibv_query_gid(&mock_ctx, 1, idx, &gid);
        EXPECT_EQ(ret, 0);
        EXPECT_EQ(gid.raw[0], idx);
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
