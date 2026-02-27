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

// Additional rdma-core function mocks
int __wrap_ibv_req_notify_cq(struct ibv_cq *cq, int solicited_only) {
    return 0;
}

int __wrap_ibv_ack_cq_events(struct ibv_cq *cq, unsigned int nevents) {
    return 0;
}

int __wrap_ibv_get_cq_event(struct ibv_comp_channel *channel, struct ibv_cq **cq, void **cq_context) {
    return -1;
}

struct ibv_comp_channel* __wrap_ibv_create_comp_channel(struct ibv_context *context) {
    return (struct ibv_comp_channel*)calloc(1, sizeof(struct ibv_comp_channel));
}

int __wrap_ibv_destroy_comp_channel(struct ibv_comp_channel *channel) {
    if (channel) free(channel);
    return 0;
}

struct ibv_cq_ex* __wrap_ibv_create_cq_ex(struct ibv_context *context, struct ibv_cq_init_attr_ex *cq_attr) {
    return (struct ibv_cq_ex*)calloc(1, sizeof(struct ibv_cq_ex));
}

struct ibv_cq* __wrap_ibv_cq_ex_to_cq(struct ibv_cq_ex *cq) {
    return (struct ibv_cq*)cq;
}

int __wrap_ibv_start_poll(struct ibv_cq_ex *cq, struct ibv_poll_cq_attr *attr) {
    return ENOENT;
}

int __wrap_ibv_next_poll(struct ibv_cq_ex *cq) {
    return ENOENT;
}

void __wrap_ibv_end_poll(struct ibv_cq_ex *cq) {
}

uint32_t __wrap_ibv_wc_read_byte_len(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_imm_data(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_qp_num(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_src_qp(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_slid(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_wc_flags(struct ibv_cq_ex *cq) {
    return 0;
}

uint32_t __wrap_ibv_wc_read_vendor_err(struct ibv_cq_ex *cq) {
    return 0;
}

enum ibv_wc_opcode __wrap_ibv_wc_read_opcode(struct ibv_cq_ex *cq) {
    return IBV_WC_SEND;
}

int __wrap_ibv_wc_read_sgid(struct ibv_cq_ex *cq, union ibv_gid *sgid) {
    memset(sgid, 0, sizeof(*sgid));
    return 0;
}

struct ibv_qp_ex* __wrap_ibv_qp_to_qp_ex(struct ibv_qp *qp) {
    return (struct ibv_qp_ex*)qp;
}

struct ibv_qp* __wrap_ibv_create_qp_ex(struct ibv_context *context, struct ibv_qp_init_attr_ex *qp_attr) {
    struct ibv_qp *qp = (struct ibv_qp*)calloc(1, sizeof(struct ibv_qp));
    if (qp) {
        qp->context = context;
        qp->qp_num = 1;
    }
    return qp;
}

int __wrap_ibv_query_qp_data_in_order(struct ibv_qp *qp, enum ibv_wr_opcode op, uint32_t flags) {
    return 0;
}

int __wrap_ibv_post_recv(struct ibv_qp *qp, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad_wr) {
    return 0;
}

int __wrap_ibv_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr) {
    return 0;
}

struct ibv_mr* __wrap_ibv_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset, size_t length,
                                         uint64_t iova, int fd, int access) {
    struct ibv_mr *mr = (struct ibv_mr*)calloc(1, sizeof(struct ibv_mr));
    if (mr) {
        mr->context = pd->context;
        mr->pd = pd;
        mr->addr = (void*)iova;
        mr->length = length;
        mr->lkey = 0x1234;
        mr->rkey = 0x1234;
    }
    return mr;
}

struct ibv_cq* __wrap_efadv_create_cq(struct ibv_context *ibvctx, struct ibv_cq_init_attr_ex *attr_ex,
                                       struct efadv_cq_init_attr *efa_attr, uint32_t inlen) {
    return (struct ibv_cq*)calloc(1, sizeof(struct ibv_cq));
}

struct ibv_qp* __wrap_efadv_create_qp_ex(struct ibv_context *ibvctx, struct ibv_qp_init_attr_ex *attr_ex,
                                          struct efadv_qp_init_attr *efa_attr, uint32_t inlen) {
    struct ibv_qp *qp = (struct ibv_qp*)calloc(1, sizeof(struct ibv_qp));
    if (qp) {
        qp->context = ibvctx;
        qp->qp_num = 1;
    }
    return qp;
}

int __wrap_efadv_query_cq(struct ibv_cq *ibvcq, struct efadv_cq_attr *attr, uint32_t inlen) {
    return 0;
}

int __wrap_efadv_query_mr(struct ibv_mr *ibvmr, struct efadv_mr_attr *attr, uint32_t inlen) {
    return 0;
}

int __wrap_efadv_query_qp_wqs(struct ibv_qp *ibvqp, struct efadv_wq_attr *send_wq_attr,
                               struct efadv_wq_attr *recv_wq_attr, uint32_t inlen) {
    return 0;
}

int __wrap_efadv_wc_read_sgid(struct ibv_cq_ex *ibvcqx, union ibv_gid *sgid) {
    memset(sgid, 0, sizeof(*sgid));
    return 0;
}

} // extern "C"

// Define global variables needed by tests
struct efa_unit_test_mocks {
    int (*efadv_query_device)(struct ibv_context*, struct efadv_device_attr*, uint32_t);
    enum ibv_fork_status (*ibv_is_fork_initialized)();
};

struct efa_unit_test_mocks g_efa_unit_test_mocks = {nullptr, nullptr};

// Device count - defined in efa_unit_test_device_setup.c
extern int g_efa_selected_device_cnt;

// Fork status
enum efa_fork_support_status {
    EFA_FORK_SUPPORT_OFF = 0,
    EFA_FORK_SUPPORT_ON,
    EFA_FORK_SUPPORT_UNNEEDED,
};
enum efa_fork_support_status g_efa_fork_status = EFA_FORK_SUPPORT_OFF;
int g_efa_huge_page_setting = 0;

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
