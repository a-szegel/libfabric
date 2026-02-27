/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"
#include "efa_unit_test_device_mock.hpp"

void EfaUnitTestWithDevice::SetUpDevice() {
    efa_mock_device_config config;
    SetUpDevice(config);
}

void EfaUnitTestWithDevice::SetUpDevice(const efa_mock_device_config &config) {
    simulator = new efa_device_simulator(config);
    g_device_simulator = simulator;
    simulator->setup_all();
}

void EfaUnitTestWithDevice::TearDown() {
    if (simulator) {
        g_device_simulator = nullptr;
        delete simulator;
        simulator = nullptr;
    }
    EfaUnitTestBase::TearDown();
}
