/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <stdlib.h>
#include <string.h>
#include "efa_device.h"

// Control variables
bool g_mock_efa_device_list_initialize = false;
int g_mock_efa_device_list_initialize_return = 0;

// Local storage for mock device list (not the real EFA globals)
static struct efa_device *mock_device_list = NULL;
static int mock_device_cnt = 0;
static union ibv_gid *mock_gid_list = NULL;
static int mock_gid_cnt = 0;

void efa_mock_setup_device_list(struct ibv_context *ctx,
                                  struct ibv_device_attr *dev_attr,
                                  struct efadv_device_attr *efa_attr,
                                  struct ibv_port_attr *port_attr,
                                  union ibv_gid *gid,
                                  uint32_t max_rdma_size) {
    // Allocate device list
    mock_device_list = (struct efa_device*)calloc(1, sizeof(struct efa_device));
    mock_device_cnt = 1;
    
    // Setup device
    mock_device_list[0].ibv_ctx = ctx;
    memcpy(&mock_device_list[0].ibv_attr, dev_attr, sizeof(*dev_attr));
    memcpy(&mock_device_list[0].efa_attr, efa_attr, sizeof(*efa_attr));
    memcpy(&mock_device_list[0].ibv_port_attr, port_attr, sizeof(*port_attr));
    memcpy(&mock_device_list[0].ibv_gid, gid, sizeof(*gid));
    mock_device_list[0].device_caps = efa_attr->device_caps;
    mock_device_list[0].max_rdma_size = max_rdma_size;
    
    // Setup GID list
    mock_gid_list = (union ibv_gid*)calloc(1, sizeof(union ibv_gid));
    mock_gid_cnt = 1;
    memcpy(&mock_gid_list[0], gid, sizeof(*gid));
    
    // Now set the real EFA globals
    extern struct efa_device *g_efa_selected_device_list;
    extern int g_efa_selected_device_cnt;
    extern union ibv_gid *g_efa_ibv_gid_list;
    extern int g_efa_ibv_gid_cnt;
    
    g_efa_selected_device_list = mock_device_list;
    g_efa_selected_device_cnt = mock_device_cnt;
    g_efa_ibv_gid_list = mock_gid_list;
    g_efa_ibv_gid_cnt = mock_gid_cnt;
}

void efa_mock_cleanup_device_list(void) {
    if (mock_device_list) {
        free(mock_device_list);
        mock_device_list = NULL;
    }
    mock_device_cnt = 0;
    
    if (mock_gid_list) {
        free(mock_gid_list);
        mock_gid_list = NULL;
    }
    mock_gid_cnt = 0;
    
    // Clear the real EFA globals
    extern struct efa_device *g_efa_selected_device_list;
    extern int g_efa_selected_device_cnt;
    extern union ibv_gid *g_efa_ibv_gid_list;
    extern int g_efa_ibv_gid_cnt;
    
    g_efa_selected_device_list = NULL;
    g_efa_selected_device_cnt = 0;
    g_efa_ibv_gid_list = NULL;
    g_efa_ibv_gid_cnt = 0;
}
