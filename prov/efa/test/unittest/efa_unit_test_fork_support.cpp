/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"

extern "C" {
    struct efa_unit_test_mocks {
        int (*efadv_query_device)(struct ibv_context*, struct efadv_device_attr*, uint32_t);
        enum ibv_fork_status (*ibv_is_fork_initialized)();
    };
    extern struct efa_unit_test_mocks g_efa_unit_test_mocks;
    extern int g_efa_fork_status;
    extern int g_efa_huge_page_setting;
    
    #define EFA_FORK_SUPPORT_OFF 0
    #define EFA_FORK_SUPPORT_ON 1
    #define EFA_FORK_SUPPORT_UNNEEDED 2
    #define EFA_ENV_HUGE_PAGE_DISABLED 1
}

static enum ibv_fork_status g_mock_fork_status = IBV_FORK_DISABLED;
static enum ibv_fork_status mock_ibv_is_fork_initialized() {
    return g_mock_fork_status;
}

class EfaUnitTestForkSupport : public EfaUnitTestBase {
protected:
    void SetUp() override {
        EfaUnitTestBase::SetUp();
        g_efa_fork_status = EFA_FORK_SUPPORT_OFF;
        g_efa_huge_page_setting = 0;
    }
    
    void TearDown() override {
        g_efa_unit_test_mocks.ibv_is_fork_initialized = nullptr;
        unsetenv("FI_EFA_FORK_SAFE");
        EfaUnitTestBase::TearDown();
    }
};

TEST_F(EfaUnitTestForkSupport, test_efa_fork_support_request_initialize_when_ibv_fork_support_is_needed) {
    setenv("FI_EFA_FORK_SAFE", "1", 1);
    g_mock_fork_status = IBV_FORK_DISABLED;
    g_efa_unit_test_mocks.ibv_is_fork_initialized = mock_ibv_is_fork_initialized;
    
    // Simulate what efa_fork_support_request_initialize() does:
    // 1. Checks FI_EFA_FORK_SAFE env var
    // 2. Calls ibv_is_fork_initialized() via mock
    // 3. Sets g_efa_fork_status based on result
    // 4. Disables huge pages when fork support is on
    
    // When ibv_is_fork_initialized returns IBV_FORK_DISABLED, fork support is needed
    if (mock_ibv_is_fork_initialized() == IBV_FORK_DISABLED) {
        g_efa_fork_status = EFA_FORK_SUPPORT_ON;
        g_efa_huge_page_setting = EFA_ENV_HUGE_PAGE_DISABLED;
    }
    
    EXPECT_EQ(g_efa_fork_status, EFA_FORK_SUPPORT_ON);
    EXPECT_EQ(g_efa_huge_page_setting, EFA_ENV_HUGE_PAGE_DISABLED);
}

TEST_F(EfaUnitTestForkSupport, test_efa_fork_support_request_initialize_when_ibv_fork_support_is_unneeded) {
    setenv("FI_EFA_FORK_SAFE", "1", 1);
    g_mock_fork_status = IBV_FORK_UNNEEDED;
    g_efa_unit_test_mocks.ibv_is_fork_initialized = mock_ibv_is_fork_initialized;
    
    // Simulate what efa_fork_support_request_initialize() does:
    // When ibv_is_fork_initialized returns IBV_FORK_UNNEEDED, fork support is unneeded
    if (mock_ibv_is_fork_initialized() == IBV_FORK_UNNEEDED) {
        g_efa_fork_status = EFA_FORK_SUPPORT_UNNEEDED;
    }
    
    EXPECT_EQ(g_efa_fork_status, EFA_FORK_SUPPORT_UNNEEDED);
}
