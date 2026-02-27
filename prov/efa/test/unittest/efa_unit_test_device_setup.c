/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <stdlib.h>
#include <string.h>
#include "efa_device.h"

// Control variables
bool g_mock_efa_device_list_initialize = false;
int g_mock_efa_device_list_initialize_return = 0;

// Weak references to EFA globals - will bind at link time
__attribute__((weak)) struct efa_device *g_efa_selected_device_list;
__attribute__((weak)) int g_efa_selected_device_cnt;
__attribute__((weak)) union ibv_gid *g_efa_ibv_gid_list;
__attribute__((weak)) int g_efa_ibv_gid_cnt;

// Local storage for mock device list
static struct efa_device *mock_device_list = NULL;
static union ibv_gid *mock_gid_list = NULL;

void efa_mock_setup_device_list(struct ibv_context *ctx,
                                  struct ibv_device_attr *dev_attr,
                                  struct efadv_device_attr *efa_attr,
                                  struct ibv_port_attr *port_attr,
                                  union ibv_gid *gid,
                                  uint32_t max_rdma_size) {
    // Allocate device list
    mock_device_list = (struct efa_device*)calloc(1, sizeof(struct efa_device));
    
    // Setup device
    mock_device_list[0].ibv_ctx = ctx;
    memcpy(&mock_device_list[0].ibv_attr, dev_attr, sizeof(*dev_attr));
    memcpy(&mock_device_list[0].efa_attr, efa_attr, sizeof(*efa_attr));
    memcpy(&mock_device_list[0].ibv_port_attr, port_attr, sizeof(*port_attr));
    memcpy(&mock_device_list[0].ibv_gid, gid, sizeof(*gid));
    mock_device_list[0].device_caps = efa_attr->device_caps;
    mock_device_list[0].max_rdma_size = max_rdma_size;
    
    // Create minimal rdm_info
    mock_device_list[0].rdm_info = fi_allocinfo();
    if (mock_device_list[0].rdm_info) {
        mock_device_list[0].rdm_info->ep_attr->type = FI_EP_RDM;
        mock_device_list[0].rdm_info->ep_attr->max_msg_size = UINT64_MAX;
        mock_device_list[0].rdm_info->caps = FI_MSG | FI_RMA | FI_TAGGED;
        mock_device_list[0].rdm_info->mode = FI_CONTEXT;
        mock_device_list[0].rdm_info->domain_attr->name = strdup("efa-rdm");
        mock_device_list[0].rdm_info->domain_attr->progress = FI_PROGRESS_MANUAL;
        mock_device_list[0].rdm_info->domain_attr->control_progress = FI_PROGRESS_MANUAL;
        mock_device_list[0].rdm_info->fabric_attr->name = strdup("efa");
    }
    
    // Create minimal dgram_info
    mock_device_list[0].dgram_info = fi_allocinfo();
    if (mock_device_list[0].dgram_info) {
        mock_device_list[0].dgram_info->ep_attr->type = FI_EP_DGRAM;
        mock_device_list[0].dgram_info->caps = FI_MSG;
        mock_device_list[0].dgram_info->mode = FI_MSG_PREFIX | FI_CONTEXT2;
        mock_device_list[0].dgram_info->domain_attr->name = strdup("efa-dgrm");
        mock_device_list[0].dgram_info->fabric_attr->name = strdup("efa");
    }
    
    // Setup GID list
    mock_gid_list = (union ibv_gid*)calloc(1, sizeof(union ibv_gid));
    memcpy(&mock_gid_list[0], gid, sizeof(*gid));
    
    // Set the EFA globals
    g_efa_selected_device_list = mock_device_list;
    g_efa_selected_device_cnt = 1;
    g_efa_ibv_gid_list = mock_gid_list;
    g_efa_ibv_gid_cnt = 1;
}




void efa_mock_cleanup_device_list(void) {
    if (mock_device_list) {
        free(mock_device_list);
        mock_device_list = NULL;
    }
    
    if (mock_gid_list) {
        free(mock_gid_list);
        mock_gid_list = NULL;
    }
    
    // Clear the EFA globals
    g_efa_selected_device_list = NULL;
    g_efa_selected_device_cnt = 0;
    g_efa_ibv_gid_list = NULL;
    g_efa_ibv_gid_cnt = 0;
}
