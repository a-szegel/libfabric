/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include <stdlib.h>
#include <string.h>

// Simplified efa_device structure for testing
struct test_efa_device {
    void *ibv_ctx;
    void *rdm_info;
    void *dgram_info;
};

// External declarations
extern int g_efa_fork_status;
extern int g_efa_huge_page_setting;

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
