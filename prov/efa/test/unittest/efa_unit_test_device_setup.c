/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_device.h"
#include "efa_unit_test_device_simulator.h"
#include <stdlib.h>
#include <stdbool.h>

// Global device list that provider will see
struct efa_device *g_efa_selected_device_list = NULL;
int g_efa_selected_device_cnt = 0;

// GID list
union ibv_gid *g_efa_ibv_gid_list = NULL;
int g_efa_ibv_gid_cnt = 0;

// Legacy control variables (for compatibility)
bool g_mock_efa_device_list_initialize = false;
int g_mock_efa_device_list_initialize_return = 0;

/**
 * @brief Set up a complete mock device using the device simulator
 * 
 * This creates a fully functional mock device that allows the provider
 * to initialize successfully. Called by tests, not during static init.
 */
void efa_unit_test_setup_device(void) {
    // Clean up any existing device
    if (g_efa_selected_device_list) {
        efa_device_simulator_free(g_efa_selected_device_list);
        g_efa_selected_device_list = NULL;
    }
    
    // Create one complete mock device
    // This is safe to call from tests (after main() starts)
    g_efa_selected_device_list = efa_device_simulator_create();
    if (g_efa_selected_device_list) {
        g_efa_selected_device_cnt = 1;
        
        // Set up GID list
        g_efa_ibv_gid_list = &g_efa_selected_device_list->ibv_gid;
        g_efa_ibv_gid_cnt = 1;
    } else {
        g_efa_selected_device_cnt = 0;
        g_efa_ibv_gid_list = NULL;
        g_efa_ibv_gid_cnt = 0;
    }
    
    // Note: Provider has already initialized with 0 devices during EFA_INI
    // The provider's efa_util_prov.info will be NULL or incomplete
    // Tests using fi_getinfo() will still work because the provider
    // can build info structures on-demand from the device list
}

/**
 * @brief Clean up mock device
 */
void efa_unit_test_teardown_device(void) {
    if (g_efa_selected_device_list) {
        efa_device_simulator_free(g_efa_selected_device_list);
        g_efa_selected_device_list = NULL;
    }
    g_efa_selected_device_cnt = 0;
    g_efa_ibv_gid_list = NULL;
    g_efa_ibv_gid_cnt = 0;
}

// Legacy function for compatibility
void efa_mock_cleanup_device_list(void) {
    efa_unit_test_teardown_device();
}

// Legacy function for compatibility - stub
void efa_mock_setup_device_list(struct ibv_context *ctx,
                                  struct ibv_device_attr *dev_attr,
                                  struct efadv_device_attr *efa_attr,
                                  struct ibv_port_attr *port_attr,
                                  union ibv_gid *gid,
                                  uint32_t max_rdma_size) {
    // Just use the simulator instead
    efa_unit_test_setup_device();
}
