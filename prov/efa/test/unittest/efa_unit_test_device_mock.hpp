/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_UNIT_TEST_DEVICE_MOCK_HPP
#define EFA_UNIT_TEST_DEVICE_MOCK_HPP

#include <vector>
#include <memory>
#include <cstring>

#include <infiniband/verbs.h>
#include <infiniband/efadv.h>

/**
 * Configuration for a mock EFA device
 */
struct efa_mock_device_config {
    // Device identification
    const char *name = "efa_0";
    const char *dev_name = "rdmap0s31";
    const char *ibdev_name = "efa_0";
    
    // Device capabilities
    uint64_t max_mr_size = 0xFFFFFFFFFFFFULL;
    uint32_t max_qp = 2048;
    uint32_t max_cq = 2048;
    uint32_t max_pd = 256;
    uint32_t max_ah = 2048;
    uint32_t max_qp_wr = 8192;
    uint32_t max_cqe = 16384;
    uint32_t max_mr = 1024;
    uint32_t max_mw = 0;
    uint32_t max_sge = 16;
    uint32_t max_sge_rd = 1;
    
    // Port attributes
    uint8_t port_num = 1;
    uint32_t max_msg_sz = 1048576;
    uint32_t max_mtu = 4096;
    enum ibv_mtu active_mtu = IBV_MTU_4096;
    enum ibv_port_state state = IBV_PORT_ACTIVE;
    
    // GID
    uint8_t gid[16] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    
    // EFA-specific attributes
    uint32_t device_version = 0;
    uint32_t max_sq_wr = 8192;
    uint32_t max_rq_wr = 8192;
    uint32_t max_sq_sge = 16;
    uint32_t max_rq_sge = 1;
    uint16_t max_rdma_size = 8192;
    bool support_rdma_read = true;
    bool support_rdma_write = true;
    bool support_unsolicited_write_recv = false;
    
    // Constructor with defaults
    efa_mock_device_config() = default;
};

/**
 * Mock device simulator - manages fake rdma-core objects
 */
class efa_device_simulator {
public:
    efa_device_simulator(const efa_mock_device_config &config);
    ~efa_device_simulator();
    
    // Setup mock expectations
    void setup_device_list();
    void setup_device_open();
    void setup_device_query();
    void setup_port_query();
    void setup_gid_query();
    void setup_pd_alloc();
    void setup_cq_create();
    void setup_qp_create();
    void setup_mr_reg();
    void setup_ah_create();
    void setup_efadv_query();
    
    // Setup all common operations
    void setup_all();
    
    // Get mock objects
    struct ibv_device** get_device_list() { return device_list; }
    struct ibv_context* get_context() { return context; }
    struct ibv_pd* get_pd() { return pd; }
    
private:
    efa_mock_device_config config;
    
    // Mock objects
    struct ibv_device *device;
    struct ibv_device **device_list;
    struct ibv_context *context;
    struct ibv_device_attr device_attr;
    struct ibv_port_attr port_attr;
    union ibv_gid gid;
    struct ibv_pd *pd;
    struct efadv_device_attr efadv_attr;
    
    // Allocated objects tracking
    std::vector<struct ibv_cq*> cqs;
    std::vector<struct ibv_qp*> qps;
    std::vector<struct ibv_mr*> mrs;
    std::vector<struct ibv_ah*> ahs;
    
    void init_device_attr();
    void init_port_attr();
    void init_efadv_attr();
};

// Global simulator instance (set by test fixture)
extern efa_device_simulator *g_device_simulator;

#endif // EFA_UNIT_TEST_DEVICE_MOCK_HPP
