/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

// Global mock pointer
RdmaCoreMock *g_rdma_mock = nullptr;

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

// Define global variables needed by tests
struct efa_unit_test_mocks {
    int (*efadv_query_device)(struct ibv_context*, struct efadv_device_attr*, uint32_t);
    enum ibv_fork_status (*ibv_is_fork_initialized)();
};

struct efa_unit_test_mocks g_efa_unit_test_mocks = {nullptr, nullptr};

// Device count
int g_efa_selected_device_cnt = 0;

// Fork status
enum efa_fork_support_status {
    EFA_FORK_SUPPORT_OFF = 0,
    EFA_FORK_SUPPORT_ON,
    EFA_FORK_SUPPORT_UNNEEDED,
};
enum efa_fork_support_status g_efa_fork_status = EFA_FORK_SUPPORT_OFF;

// Environment settings
enum efa_env_huge_page_setting {
    EFA_ENV_HUGE_PAGE_UNSPEC = 0,
    EFA_ENV_HUGE_PAGE_DISABLED,
    EFA_ENV_HUGE_PAGE_ENABLED,
};

struct efa_env {
    int huge_page_setting;
};
struct efa_env efa_env = {EFA_ENV_HUGE_PAGE_UNSPEC};

// Real function declarations
enum ibv_fork_status __real_ibv_is_fork_initialized() {
    return IBV_FORK_UNNEEDED;
}
