/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_UNIT_TEST_COMMON_HPP
#define EFA_UNIT_TEST_COMMON_HPP

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

// Forward declaration
class RdmaCoreMock;
extern RdmaCoreMock *g_rdma_mock;

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

// Base test fixture
class EfaUnitTestBase : public ::testing::Test {
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

// Forward declaration
class efa_device_simulator;
struct efa_mock_device_config;

// Test fixture with device simulator
class EfaUnitTestWithDevice : public EfaUnitTestBase {
protected:
    efa_device_simulator *simulator = nullptr;
    
    // Setup device with default config
    void SetUpDevice();
    
    // Setup device with custom config
    void SetUpDevice(const efa_mock_device_config &config);
    
    void TearDown() override;
};

// C wrapper function declarations
extern "C" {
    int efa_unit_test_device_construct_gid_wrapper(void *efa_device_ptr, struct ibv_device *ibv_device);
    int efa_unit_test_device_check_null(void *efa_device_ptr);
    void efa_unit_test_fork_support_request_initialize_wrapper(void);
    int efa_unit_test_get_fork_status(void);
    int efa_unit_test_get_huge_page_setting(void);
    struct fi_info *efa_unit_test_alloc_hints(enum fi_ep_type ep_type, char *fabric_name);
}

#endif // EFA_UNIT_TEST_COMMON_HPP
