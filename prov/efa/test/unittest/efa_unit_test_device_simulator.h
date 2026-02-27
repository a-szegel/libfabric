/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef EFA_UNIT_TEST_DEVICE_SIMULATOR_H
#define EFA_UNIT_TEST_DEVICE_SIMULATOR_H

#include <rdma/fabric.h>
#include <infiniband/verbs.h>
#include <infiniband/efadv.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Software device simulator that provides a complete mock EFA device
 * 
 * This creates a fully functional mock device with all attributes needed
 * for the provider to initialize successfully.
 */

/**
 * @brief Create a complete mock EFA device with all required attributes
 * 
 * @return Pointer to mock device, or NULL on failure
 */
struct efa_device* efa_device_simulator_create(void);

/**
 * @brief Free mock device created by simulator
 * 
 * @param device Device to free
 */
void efa_device_simulator_free(struct efa_device *device);

/**
 * @brief Create mock ibv_context for device
 */
struct ibv_context* efa_device_simulator_create_context(void);

/**
 * @brief Create mock ibv_pd for device
 */
struct ibv_pd* efa_device_simulator_create_pd(struct ibv_context *ctx);

/**
 * @brief Create mock rdm_info for device
 */
struct fi_info* efa_device_simulator_create_rdm_info(void);

/**
 * @brief Create mock dgram_info for device
 */
struct fi_info* efa_device_simulator_create_dgram_info(void);

#ifdef __cplusplus
}
#endif

#endif /* EFA_UNIT_TEST_DEVICE_SIMULATOR_H */
