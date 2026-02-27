/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include "efa_device.h"

// Control variables
bool g_mock_efa_device_list_initialize = false;
int g_mock_efa_device_list_initialize_return = 0;

// Local storage for mock device list
static struct efa_device *mock_device_list = NULL;
static int mock_device_cnt = 0;
static union ibv_gid *mock_gid_list = NULL;
static int mock_gid_cnt = 0;

// Get pointers to EFA globals using dlsym
static struct efa_device** get_g_efa_selected_device_list(void) {
    static struct efa_device **ptr = NULL;
    if (!ptr) {
        ptr = (struct efa_device**)dlsym(RTLD_NEXT, "g_efa_selected_device_list");
        if (!ptr) ptr = (struct efa_device**)dlsym(RTLD_DEFAULT, "g_efa_selected_device_list");
    }
    return ptr;
}

static int* get_g_efa_selected_device_cnt(void) {
    static int *ptr = NULL;
    if (!ptr) {
        ptr = (int*)dlsym(RTLD_NEXT, "g_efa_selected_device_cnt");
        if (!ptr) ptr = (int*)dlsym(RTLD_DEFAULT, "g_efa_selected_device_cnt");
    }
    return ptr;
}

static union ibv_gid** get_g_efa_ibv_gid_list(void) {
    static union ibv_gid **ptr = NULL;
    if (!ptr) {
        ptr = (union ibv_gid**)dlsym(RTLD_NEXT, "g_efa_ibv_gid_list");
        if (!ptr) ptr = (union ibv_gid**)dlsym(RTLD_DEFAULT, "g_efa_ibv_gid_list");
    }
    return ptr;
}

static int* get_g_efa_ibv_gid_cnt(void) {
    static int *ptr = NULL;
    if (!ptr) {
        ptr = (int*)dlsym(RTLD_NEXT, "g_efa_ibv_gid_cnt");
        if (!ptr) ptr = (int*)dlsym(RTLD_DEFAULT, "g_efa_ibv_gid_cnt");
    }
    return ptr;
}

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
    
    // Set the real EFA globals via dlsym
    struct efa_device **dev_list_ptr = get_g_efa_selected_device_list();
    int *dev_cnt_ptr = get_g_efa_selected_device_cnt();
    union ibv_gid **gid_list_ptr = get_g_efa_ibv_gid_list();
    int *gid_cnt_ptr = get_g_efa_ibv_gid_cnt();
    
    if (dev_list_ptr) {
        *dev_list_ptr = mock_device_list;
    } else {
        fprintf(stderr, "WARNING: Could not find g_efa_selected_device_list\n");
    }
    
    if (dev_cnt_ptr) {
        *dev_cnt_ptr = mock_device_cnt;
    } else {
        fprintf(stderr, "WARNING: Could not find g_efa_selected_device_cnt\n");
    }
    
    if (gid_list_ptr) {
        *gid_list_ptr = mock_gid_list;
    } else {
        fprintf(stderr, "WARNING: Could not find g_efa_ibv_gid_list\n");
    }
    
    if (gid_cnt_ptr) {
        *gid_cnt_ptr = mock_gid_cnt;
    } else {
        fprintf(stderr, "WARNING: Could not find g_efa_ibv_gid_cnt\n");
    }
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
    struct efa_device **dev_list_ptr = get_g_efa_selected_device_list();
    int *dev_cnt_ptr = get_g_efa_selected_device_cnt();
    union ibv_gid **gid_list_ptr = get_g_efa_ibv_gid_list();
    int *gid_cnt_ptr = get_g_efa_ibv_gid_cnt();
    
    if (dev_list_ptr) *dev_list_ptr = NULL;
    if (dev_cnt_ptr) *dev_cnt_ptr = 0;
    if (gid_list_ptr) *gid_list_ptr = NULL;
    if (gid_cnt_ptr) *gid_cnt_ptr = 0;
}
