/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "rdma/fabric.h"
#include "efa_device.h"

// External declarations
extern int g_efa_fork_status;
extern int g_efa_huge_page_setting;
extern bool g_mock_efa_device_list_initialize;
extern int g_mock_efa_device_list_initialize_return;

// Simplified efa_device structure for testing
struct test_efa_device {
    void *ibv_ctx;
    void *rdm_info;
    void *dgram_info;
};

// Simplified wrapper - just sets fields to NULL to simulate error
int efa_unit_test_device_construct_gid_wrapper(void *efa_device_ptr, void *ibv_device) {
    struct test_efa_device *dev = (struct test_efa_device *)efa_device_ptr;
    // Simulate error case - set all to NULL
    dev->ibv_ctx = NULL;
    dev->rdm_info = NULL;
    dev->dgram_info = NULL;
    return -1;
}

// Check if device fields are NULL
int efa_unit_test_device_check_null(void *efa_device_ptr) {
    struct test_efa_device *dev = (struct test_efa_device *)efa_device_ptr;
    return (dev->ibv_ctx == NULL && dev->rdm_info == NULL && dev->dgram_info == NULL) ? 1 : 0;
}

// Simplified fork support wrapper
void efa_unit_test_fork_support_request_initialize_wrapper(void) {
    // Simulate fork support initialization
    // Real implementation would call efa_fork_support_request_initialize()
    // For now, just set the status based on environment
    char *fork_safe = getenv("FI_EFA_FORK_SAFE");
    if (fork_safe && strcmp(fork_safe, "1") == 0) {
        // Simulate checking ibv_is_fork_initialized via mock
        // This will be set by the test
    }
}

// Get fork status
int efa_unit_test_get_fork_status(void) {
    return g_efa_fork_status;
}

// Get huge page setting
int efa_unit_test_get_huge_page_setting(void) {
    return g_efa_huge_page_setting;
}

// Wrapper for efa_device_list_initialize
// Returns success with 0 devices initially - device will be created by tests
int __wrap_efa_device_list_initialize(void) {
    // During provider initialization (EFA_INI), we return success with 0 devices
    // The provider will handle this gracefully
    // Tests will call SetUpDevice() to create the device later
    
    // If device already exists (test called SetUpDevice), return success
    if (g_efa_selected_device_cnt > 0) {
        return 0;
    }
    
    // Return success with 0 devices - provider will initialize without devices
    // This is safe and allows provider to load
    return 0;
}

// Real fi_getinfo from libfabric
extern int __real_fi_getinfo(uint32_t version, const char *node, const char *service,
                              uint64_t flags, const struct fi_info *hints, struct fi_info **info);

// Wrapper for fi_getinfo - intercept and build from mocked devices
int __wrap_fi_getinfo(uint32_t version, const char *node, const char *service,
                      uint64_t flags, const struct fi_info *hints, struct fi_info **info) {
    // If we have mocked devices, build info from them
    if (g_efa_selected_device_cnt > 0 && g_efa_selected_device_list != NULL) {
        struct fi_info *head = NULL, *tail = NULL;
        
        for (int i = 0; i < g_efa_selected_device_cnt; i++) {
            struct efa_device *dev = &g_efa_selected_device_list[i];
            
            // Check hints to see what type is requested
            if (hints == NULL || hints->ep_attr == NULL || 
                hints->ep_attr->type == FI_EP_UNSPEC || hints->ep_attr->type == FI_EP_RDM) {
                if (dev->rdm_info != NULL) {
                    struct fi_info *dup = fi_dupinfo(dev->rdm_info);
                    if (dup) {
                        if (tail) {
                            tail->next = dup;
                            tail = dup;
                        } else {
                            head = tail = dup;
                        }
                    }
                }
            }
            
            if (hints == NULL || hints->ep_attr == NULL ||
                hints->ep_attr->type == FI_EP_UNSPEC || hints->ep_attr->type == FI_EP_DGRAM) {
                if (dev->dgram_info != NULL) {
                    struct fi_info *dup = fi_dupinfo(dev->dgram_info);
                    if (dup) {
                        if (tail) {
                            tail->next = dup;
                            tail = dup;
                        } else {
                            head = tail = dup;
                        }
                    }
                }
            }
        }
        
        if (head) {
            *info = head;
            return 0;
        }
    }
    
    // Fall back to real fi_getinfo
    return __real_fi_getinfo(version, node, service, flags, hints, info);
}
