/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_device_mock.hpp"
#include "efa_unit_test_common.hpp"
#include <cstdlib>
#include <cstring>

efa_device_simulator *g_device_simulator = nullptr;

efa_device_simulator::efa_device_simulator(const efa_mock_device_config &cfg) 
    : config(cfg) {
    
    // Allocate device
    device = (struct ibv_device*)calloc(1, sizeof(struct ibv_device));
    
    // Allocate device list
    device_list = (struct ibv_device**)calloc(2, sizeof(struct ibv_device*));
    device_list[0] = device;
    device_list[1] = nullptr;
    
    // Allocate context
    context = (struct ibv_context*)calloc(1, sizeof(struct ibv_context));
    context->device = device;
    
    // Allocate PD
    pd = (struct ibv_pd*)calloc(1, sizeof(struct ibv_pd));
    pd->context = context;
    
    // Initialize attributes
    init_device_attr();
    init_port_attr();
    init_efadv_attr();
    memcpy(&gid, config.gid, 16);
}

efa_device_simulator::~efa_device_simulator() {
    // Free allocated objects
    for (auto ah : ahs) free(ah);
    for (auto mr : mrs) free(mr);
    for (auto qp : qps) free(qp);
    for (auto cq : cqs) free(cq);
    
    free(pd);
    free(context);
    free(device);
    free(device_list);
}

void efa_device_simulator::init_device_attr() {
    memset(&device_attr, 0, sizeof(device_attr));
    device_attr.max_mr_size = config.max_mr_size;
    device_attr.max_qp = config.max_qp;
    device_attr.max_cq = config.max_cq;
    device_attr.max_pd = config.max_pd;
    device_attr.max_ah = config.max_ah;
    device_attr.max_qp_wr = config.max_qp_wr;
    device_attr.max_cqe = config.max_cqe;
    device_attr.max_mr = config.max_mr;
    device_attr.max_mw = config.max_mw;
    device_attr.max_sge = config.max_sge;
    device_attr.max_sge_rd = config.max_sge_rd;
}

void efa_device_simulator::init_port_attr() {
    memset(&port_attr, 0, sizeof(port_attr));
    port_attr.state = config.state;
    port_attr.max_mtu = IBV_MTU_4096;
    port_attr.active_mtu = config.active_mtu;
    port_attr.gid_tbl_len = 1;
    port_attr.port_cap_flags = IBV_PORT_CM_SUP;
    port_attr.max_msg_sz = config.max_msg_sz;
    port_attr.lid = 0;
}

void efa_device_simulator::init_efadv_attr() {
    memset(&efadv_attr, 0, sizeof(efadv_attr));
    efadv_attr.max_sq_wr = config.max_sq_wr;
    efadv_attr.max_rq_wr = config.max_rq_wr;
    efadv_attr.max_sq_sge = config.max_sq_sge;
    efadv_attr.max_rq_sge = config.max_rq_sge;
    efadv_attr.max_rdma_size = config.max_rdma_size;
    efadv_attr.device_caps = 0;
    if (config.support_rdma_read)
        efadv_attr.device_caps |= EFADV_DEVICE_ATTR_CAPS_RDMA_READ;
    if (config.support_rdma_write)
        efadv_attr.device_caps |= EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE;
    if (config.support_unsolicited_write_recv)
        efadv_attr.device_caps |= EFADV_DEVICE_ATTR_CAPS_UNSOLICITED_WRITE_RECV;
}

void efa_device_simulator::setup_device_list() {
    EXPECT_CALL(*g_rdma_mock, ibv_get_device_list(_))
        .WillRepeatedly(DoAll(
            SetArgPointee<0>(1),
            Return(device_list)
        ));
    
    EXPECT_CALL(*g_rdma_mock, ibv_get_device_name(_))
        .WillRepeatedly(Return(config.name));
    
    EXPECT_CALL(*g_rdma_mock, ibv_free_device_list(_))
        .WillRepeatedly(Return());
}

void efa_device_simulator::setup_device_open() {
    EXPECT_CALL(*g_rdma_mock, ibv_open_device(_))
        .WillRepeatedly(Return(context));
    
    EXPECT_CALL(*g_rdma_mock, ibv_close_device(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_device_query() {
    EXPECT_CALL(*g_rdma_mock, ibv_query_device(_, _))
        .WillRepeatedly(DoAll(
            SetArgPointee<1>(device_attr),
            Return(0)
        ));
}

void efa_device_simulator::setup_port_query() {
    EXPECT_CALL(*g_rdma_mock, ibv_query_port(_, config.port_num, _))
        .WillRepeatedly(DoAll(
            SetArgPointee<2>(port_attr),
            Return(0)
        ));
}

void efa_device_simulator::setup_gid_query() {
    EXPECT_CALL(*g_rdma_mock, ibv_query_gid(_, config.port_num, 0, _))
        .WillRepeatedly(DoAll(
            SetArgPointee<3>(gid),
            Return(0)
        ));
}

void efa_device_simulator::setup_pd_alloc() {
    EXPECT_CALL(*g_rdma_mock, ibv_alloc_pd(_))
        .WillRepeatedly(Return(pd));
    
    EXPECT_CALL(*g_rdma_mock, ibv_dealloc_pd(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_cq_create() {
    EXPECT_CALL(*g_rdma_mock, ibv_create_cq(_, _, _, _, _))
        .WillRepeatedly(Invoke([this](struct ibv_context *ctx, int cqe, 
                                       void *cq_context, 
                                       struct ibv_comp_channel *channel,
                                       int comp_vector) -> struct ibv_cq* {
            auto cq = (struct ibv_cq*)calloc(1, sizeof(struct ibv_cq));
            cq->context = ctx;
            cq->cqe = cqe;
            cqs.push_back(cq);
            return cq;
        }));
    
    EXPECT_CALL(*g_rdma_mock, ibv_destroy_cq(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_qp_create() {
    EXPECT_CALL(*g_rdma_mock, ibv_create_qp(_, _))
        .WillRepeatedly(Invoke([this](struct ibv_pd *pd, 
                                       struct ibv_qp_init_attr *attr) -> struct ibv_qp* {
            auto qp = (struct ibv_qp*)calloc(1, sizeof(struct ibv_qp));
            qp->context = pd->context;
            qp->pd = pd;
            qp->send_cq = attr->send_cq;
            qp->recv_cq = attr->recv_cq;
            qp->qp_type = attr->qp_type;
            qps.push_back(qp);
            return qp;
        }));
    
    EXPECT_CALL(*g_rdma_mock, ibv_modify_qp(_, _, _))
        .WillRepeatedly(Return(0));
    
    EXPECT_CALL(*g_rdma_mock, ibv_destroy_qp(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_mr_reg() {
    EXPECT_CALL(*g_rdma_mock, ibv_reg_mr(_, _, _, _))
        .WillRepeatedly(Invoke([this](struct ibv_pd *pd, void *addr, 
                                       size_t length, int access) -> struct ibv_mr* {
            auto mr = (struct ibv_mr*)calloc(1, sizeof(struct ibv_mr));
            mr->context = pd->context;
            mr->pd = pd;
            mr->addr = addr;
            mr->length = length;
            mr->lkey = (uint32_t)(uintptr_t)mr;
            mr->rkey = (uint32_t)(uintptr_t)mr;
            mrs.push_back(mr);
            return mr;
        }));
    
    EXPECT_CALL(*g_rdma_mock, ibv_dereg_mr(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_ah_create() {
    EXPECT_CALL(*g_rdma_mock, ibv_create_ah(_, _))
        .WillRepeatedly(Invoke([this](struct ibv_pd *pd, 
                                       struct ibv_ah_attr *attr) -> struct ibv_ah* {
            auto ah = (struct ibv_ah*)calloc(1, sizeof(struct ibv_ah));
            ah->context = pd->context;
            ah->pd = pd;
            ahs.push_back(ah);
            return ah;
        }));
    
    EXPECT_CALL(*g_rdma_mock, ibv_destroy_ah(_))
        .WillRepeatedly(Return(0));
}

void efa_device_simulator::setup_efadv_query() {
    EXPECT_CALL(*g_rdma_mock, efadv_query_device(_, _, _))
        .WillRepeatedly(DoAll(
            SetArgPointee<1>(efadv_attr),
            Return(0)
        ));
}

void efa_device_simulator::setup_all() {
    setup_device_list();
    setup_device_open();
    setup_device_query();
    setup_port_query();
    setup_gid_query();
    setup_pd_alloc();
    setup_cq_create();
    setup_qp_create();
    setup_mr_reg();
    setup_ah_create();
    setup_efadv_query();
}
