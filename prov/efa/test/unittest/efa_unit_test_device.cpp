/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"
#include "efa_unit_test_device_mock.hpp"

extern "C" {
    struct efa_unit_test_mocks {
        int (*efadv_query_device)(struct ibv_context*, struct efadv_device_attr*, uint32_t);
        enum ibv_fork_status (*ibv_is_fork_initialized)();
    };
    extern struct efa_unit_test_mocks g_efa_unit_test_mocks;
    extern int g_efa_selected_device_cnt;
}

static int g_mock_efadv_ret = 0;
static int mock_efadv_query_device(struct ibv_context *ctx, struct efadv_device_attr *attr, uint32_t inlen) {
    return g_mock_efadv_ret;
}

class EfaUnitTestDevice : public EfaUnitTestWithDevice {
protected:
    void TearDown() override {
        g_efa_unit_test_mocks.efadv_query_device = nullptr;
        EfaUnitTestWithDevice::TearDown();
    }
};

TEST_F(EfaUnitTestDevice, test_efa_device_construct_error_handling) {
    SetUpDevice();
    
    int ibv_err = 4242;
    struct ibv_device **ibv_device_list;
    char efa_device_buf[1024] = {0};
    
    ibv_device_list = ibv_get_device_list(&g_efa_selected_device_cnt);
    ASSERT_NE(ibv_device_list, nullptr);
    
    g_mock_efadv_ret = ibv_err;
    g_efa_unit_test_mocks.efadv_query_device = mock_efadv_query_device;
    
    efa_unit_test_device_construct_gid_wrapper(efa_device_buf, ibv_device_list[0]);
    
    EXPECT_EQ(efa_unit_test_device_check_null(efa_device_buf), 1);
    
    ibv_free_device_list(ibv_device_list);
}
