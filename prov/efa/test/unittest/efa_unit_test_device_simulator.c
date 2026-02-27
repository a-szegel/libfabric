/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_device_simulator.h"
#include "efa_device.h"
#include "efa.h"
#include <stdlib.h>
#include <string.h>

struct ibv_context* efa_device_simulator_create_context(void) {
    struct ibv_context *ctx = calloc(1, sizeof(struct ibv_context));
    if (!ctx) return NULL;
    
    // Set minimal required fields
    ctx->device = calloc(1, sizeof(struct ibv_device));
    
    return ctx;
}

struct ibv_pd* efa_device_simulator_create_pd(struct ibv_context *ctx) {
    struct ibv_pd *pd = calloc(1, sizeof(struct ibv_pd));
    if (!pd) return NULL;
    
    pd->context = ctx;
    
    return pd;
}

struct fi_info* efa_device_simulator_create_rdm_info(void) {
    struct fi_info *info = fi_allocinfo();
    if (!info) return NULL;
    
    // Ensure all pointers are valid
    if (!info->ep_attr || !info->domain_attr || !info->fabric_attr) {
        fi_freeinfo(info);
        return NULL;
    }
    
    // Set RDM endpoint attributes
    info->ep_attr->type = FI_EP_RDM;
    info->ep_attr->protocol = FI_PROTO_EFA;
    info->ep_attr->max_msg_size = UINT64_MAX;
    info->ep_attr->tx_ctx_cnt = 1;
    info->ep_attr->rx_ctx_cnt = 1;
    
    // Set domain attributes
    if (info->domain_attr->name) free(info->domain_attr->name);
    info->domain_attr->name = strdup("efa-rdm");
    info->domain_attr->threading = FI_THREAD_SAFE;
    info->domain_attr->control_progress = FI_PROGRESS_MANUAL;
    info->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    info->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
    
    // Set fabric attributes
    if (info->fabric_attr->name) free(info->fabric_attr->name);
    info->fabric_attr->name = strdup("efa");
    if (info->fabric_attr->prov_name) free(info->fabric_attr->prov_name);
    info->fabric_attr->prov_name = strdup("efa");
    
    // Set capabilities
    info->caps = FI_MSG | FI_RMA | FI_SEND | FI_RECV | FI_READ | FI_WRITE | 
                 FI_REMOTE_READ | FI_REMOTE_WRITE;
    info->mode = FI_CONTEXT;
    
    // Set address format
    info->addr_format = FI_ADDR_EFA;
    info->src_addrlen = sizeof(struct efa_ep_addr);
    
    return info;
}

struct fi_info* efa_device_simulator_create_dgram_info(void) {
    struct fi_info *info = fi_allocinfo();
    if (!info) return NULL;
    
    // Ensure all pointers are valid
    if (!info->ep_attr || !info->domain_attr || !info->fabric_attr) {
        fi_freeinfo(info);
        return NULL;
    }
    
    // Set DGRAM endpoint attributes
    info->ep_attr->type = FI_EP_DGRAM;
    info->ep_attr->protocol = FI_PROTO_EFA;
    info->ep_attr->max_msg_size = 4096;
    info->ep_attr->tx_ctx_cnt = 1;
    info->ep_attr->rx_ctx_cnt = 1;
    
    // Set domain attributes
    if (info->domain_attr->name) free(info->domain_attr->name);
    info->domain_attr->name = strdup("efa-dgrm");
    info->domain_attr->threading = FI_THREAD_SAFE;
    info->domain_attr->control_progress = FI_PROGRESS_MANUAL;
    info->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    info->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;
    
    // Set fabric attributes
    if (info->fabric_attr->name) free(info->fabric_attr->name);
    info->fabric_attr->name = strdup("efa");
    if (info->fabric_attr->prov_name) free(info->fabric_attr->prov_name);
    info->fabric_attr->prov_name = strdup("efa");
    
    // Set capabilities
    info->caps = FI_MSG | FI_SEND | FI_RECV;
    info->mode = FI_CONTEXT | FI_CONTEXT2;
    
    // Set address format
    info->addr_format = FI_ADDR_EFA;
    info->src_addrlen = sizeof(struct efa_ep_addr);
    
    return info;
}

struct efa_device* efa_device_simulator_create(void) {
    struct efa_device *device = calloc(1, sizeof(struct efa_device));
    if (!device) return NULL;
    
    // Create mock ibv_context
    device->ibv_ctx = efa_device_simulator_create_context();
    if (!device->ibv_ctx) goto err;
    
    // Set device attributes
    device->device_caps = EFADV_DEVICE_ATTR_CAPS_RDMA_READ | 
                          EFADV_DEVICE_ATTR_CAPS_RDMA_WRITE |
                          EFADV_DEVICE_ATTR_CAPS_RNR_RETRY;
    
    // Set port attributes
    device->ibv_port_attr.state = IBV_PORT_ACTIVE;
    device->ibv_port_attr.max_msg_sz = 8192;
    device->ibv_port_attr.active_mtu = IBV_MTU_4096;
    device->ibv_port_attr.lid = 1;
    device->ibv_port_attr.sm_lid = 1;
    device->ibv_port_attr.port_cap_flags = IBV_PORT_CM_SUP;
    
    // Set device attributes
    device->ibv_attr.max_qp = 1024;
    device->ibv_attr.max_qp_wr = 1024;
    device->ibv_attr.max_cq = 1024;
    device->ibv_attr.max_cqe = 16384;
    device->ibv_attr.max_mr = 1024;
    device->ibv_attr.max_pd = 256;
    device->ibv_attr.max_ah = 1024;
    device->ibv_attr.max_sge = 16;
    
    // Set EFA-specific attributes
    device->max_rdma_size = 1048576; // 1MB
    device->efa_attr.max_sq_wr = 1024;
    device->efa_attr.max_rq_wr = 1024;
    device->efa_attr.max_sq_sge = 16;
    device->efa_attr.max_rq_sge = 16;
    
    // Create info structures
    device->rdm_info = efa_device_simulator_create_rdm_info();
    if (!device->rdm_info) goto err;
    
    device->dgram_info = efa_device_simulator_create_dgram_info();
    if (!device->dgram_info) goto err;
    
    // Set GID
    memset(&device->ibv_gid, 0, sizeof(device->ibv_gid));
    device->ibv_gid.global.subnet_prefix = 0xfe80000000000000ULL;
    device->ibv_gid.global.interface_id = 0x0000000000000001ULL;
    
    // Initialize QP table
    device->qp_table = NULL;
    device->qp_table_sz_m1 = 0;
    
    return device;
    
err:
    efa_device_simulator_free(device);
    return NULL;
}

void efa_device_simulator_free(struct efa_device *device) {
    if (!device) return;
    
    if (device->rdm_info) fi_freeinfo(device->rdm_info);
    if (device->dgram_info) fi_freeinfo(device->dgram_info);
    if (device->ibv_ctx) {
        if (device->ibv_ctx->device) free(device->ibv_ctx->device);
        free(device->ibv_ctx);
    }
    free(device);
}
