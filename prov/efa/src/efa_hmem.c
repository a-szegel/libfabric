/*
 * Copyright (c) 2022 Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "efa.h"

/**
 * @brief determine the support status of cuda memory pointer
 *
 * @param	cuda_status[out]	cuda memory support status
 * @return	0 on success
 * 		negative libfabric error code on failure
 */
static int efa_hmem_info_update_cuda(struct efa_hmem_info *cuda_status)
{
#if HAVE_CUDA
	cudaError_t cuda_ret;
	void *ptr = NULL;
	struct ibv_mr *ibv_mr;
	int ibv_access = IBV_ACCESS_LOCAL_WRITE;
	size_t len = ofi_get_page_size() * 2;
	int ret;

	if (!ofi_hmem_is_initialized(FI_HMEM_CUDA)) {
		EFA_INFO(FI_LOG_DOMAIN,
		         "FI_HMEM_CUDA is not initialized\n");
		return 0;
	}

	if (efa_device_support_rdma_read())
		ibv_access |= IBV_ACCESS_REMOTE_READ;

	cuda_status->initialized = true;

	cuda_ret = ofi_cudaMalloc(&ptr, len);
	if (cuda_ret != cudaSuccess) {
		EFA_WARN(FI_LOG_DOMAIN,
			 "Failed to allocate CUDA buffer: %s\n",
			 ofi_cudaGetErrorString(cuda_ret));
		return -FI_ENOMEM;
	}

	ibv_mr = ibv_reg_mr(g_device_list[0].ibv_pd, ptr, len, ibv_access);
	if (!ibv_mr) {
		EFA_WARN(FI_LOG_DOMAIN,
			 "Failed to register CUDA buffer with the EFA device, FI_HMEM transfers that require peer to peer support will fail.\n");
		ofi_cudaFree(ptr);
		return 0;
	}

	ret = ibv_dereg_mr(ibv_mr);
	ofi_cudaFree(ptr);
	if (ret) {
		EFA_WARN(FI_LOG_DOMAIN,
			 "Failed to deregister CUDA buffer: %s\n",
			 fi_strerror(-ret));
		return ret;
	}

	cuda_status->p2p_supported = true;
	/* Eager and runting read protocols */
	if (rxr_env.efa_max_medium_msg_size != rxr_env_ctime_defaults.efa_max_medium_msg_size) {
		EFA_WARN(FI_LOG_DOMAIN,
		         "The following environment variable was set FI_EFA_MAX_MEDIUM_MSG_SIZE, "
		         "but EFA HMEM via Cuda API only supports eager and runting read protocols\n");
		abort();
	}

	cuda_status->max_medium_msg_size = 0;
    cuda_status->min_read_msg_size = cuda_status->max_eager_msg_size + 1;
    cuda_status->runt_size = rxr_env.efa_runt_size;
#endif
	return 0;
}

/**
 * @brief determine the support status of neuron memory pointer
 *
 * @param	neuron_status[out]	neuron memory support status
 * @return	0 on success
 * 		negative libfabric error code on failure
 */
static int efa_hmem_info_update_neuron(struct efa_hmem_info *neuron_status)
{
#if HAVE_NEURON
	struct ibv_mr *ibv_mr;
	int ibv_access = IBV_ACCESS_LOCAL_WRITE;
	void *handle;
	void *ptr = NULL;
	size_t len = ofi_get_page_size() * 2;
	int ret;

	if (!ofi_hmem_is_initialized(FI_HMEM_NEURON)) {
		EFA_INFO(FI_LOG_DOMAIN,
		         "FI_HMEM_NEURON is not initialized\n");
		return 0;
	}

	if (g_device_list[0].device_caps & EFADV_DEVICE_ATTR_CAPS_RDMA_READ) {
		ibv_access |= IBV_ACCESS_REMOTE_READ;
	} else {
		EFA_WARN(FI_LOG_DOMAIN,
			 "No EFA RDMA read support, transfers using AWS Neuron will fail.\n");
		return 0;
	}

	ptr = neuron_alloc(&handle, len);
	/*
	 * neuron_alloc will fail if application did not call nrt_init,
	 * which is ok if it's not running neuron workloads. libfabric
	 * will move on and leave neuron_status->initialized as false.
	 */
	if (!ptr) {
		EFA_INFO(FI_LOG_DOMAIN,
			"Cannot allocate Neuron buffer. \n");
		return 0;
	}

	neuron_status->initialized = true;

	ibv_mr = ibv_reg_mr(g_device_list[0].ibv_pd, ptr, len, ibv_access);
	if (!ibv_mr) {
		EFA_WARN(FI_LOG_DOMAIN,
		         "Failed to register Neuron buffer with the EFA device,"
		         "FI_HMEM transfers that require peer to peer support will fail.\n");
		neuron_free(&handle);
		return 0;
	}

	ret = ibv_dereg_mr(ibv_mr);
	neuron_free(&handle);
	if (ret) {
		EFA_WARN(FI_LOG_DOMAIN,
			 "Failed to deregister Neuron buffer: %s\n",
			 fi_strerror(-ret));
		return ret;
	}

	neuron_status->p2p_supported = true;
	/* Eager and runting read protocols */
	if (rxr_env.efa_max_medium_msg_size != rxr_env_ctime_defaults.efa_max_medium_msg_size) {
		EFA_WARN(FI_LOG_DOMAIN,
				"The following environment variable was set FI_EFA_MAX_MEDIUM_MSG_SIZE, "
				"but EFA HMEM via Neuron API only supports eager and runting read protocols\n");
		abort();
	}

	neuron_status->max_medium_msg_size = 0;
    neuron_status->min_read_msg_size = neuron_status->max_eager_msg_size + 1;
    neuron_status->runt_size = rxr_env.efa_runt_size;
#endif
	return 0;
}

/**
 * @brief determine the support status of synapseai memory pointer
 *
 * @param synapseai_status[out]	synapseai memory support status
 * @return 0 on success
 */
static int efa_hmem_info_update_synapseai(struct efa_hmem_info *synapseai_status)
{
#if HAVE_SYNAPSEAI
	if (!ofi_hmem_is_initialized(FI_HMEM_SYNAPSEAI)) {
		EFA_INFO(FI_LOG_DOMAIN,
		         "FI_HMEM_SYNAPSEAI is not initialized\n");
		return 0;
	}

	if (!(g_device_list[0].device_caps & EFADV_DEVICE_ATTR_CAPS_RDMA_READ)) {
		EFA_WARN(FI_LOG_DOMAIN,
			 "No EFA RDMA read support, transfers using Habana Gaudi will fail.\n");
		return 0;
	}

	synapseai_status->initialized = true;
	synapseai_status->p2p_supported = true;

	/*  Only the long read protocol is supported */
	if (rxr_env.efa_max_eager_msg_size != rxr_env_ctime_defaults.efa_max_eager_msg_size ||
		rxr_env.efa_max_medium_msg_size != rxr_env_ctime_defaults.efa_max_medium_msg_size ||
		rxr_env.efa_min_read_msg_size != rxr_env_ctime_defaults.efa_min_read_msg_size ||
		rxr_env.efa_runt_size != rxr_env_ctime_defaults.efa_runt_size) {
		EFA_WARN(FI_LOG_DOMAIN,
		         "One of the following environment variable(s) was set (FI_EFA_MAX_EAGER_MSG_SIZE, "
		         "FI_EFA_MAX_MEDIUM_MSG_SIZE, FI_EFA_MIN_READ_MSG_SIZE, and/or FI_EFA_RUNT_SIZE), "
		         "but EFA HMEM via Synapse API only supports long read protocol.\n");
		abort();
	}

    synapseai_status->max_eager_msg_size = 0;
    synapseai_status->max_medium_msg_size = 0;
    synapseai_status->min_read_msg_size = 0;
    synapseai_status->runt_size = 0;
#endif
	return 0;
}

/**
 * @brief Determine the support status of all HMEM devices
 * The support status is used later when
 * determining how to initiate an HMEM transfer.
 *
 * @param 	all_status[out]		an array of struct efa_hmem_info,
 * 					whose size is OFI_HMEM_MAX
 * @return	0 on success
 * 		negative libfabric error code on an unexpected error
 */
int efa_hmem_info_update_all(struct efa_domain *efa_domain)
{
	int ret, err, iface, mtu_size;
	size_t max_eager_msg_size;
	struct efa_hmem_info *all_status = efa_domain->hmem_info;

	if(g_device_cnt <= 0) {
		return -FI_ENODEV;
	}

	/* Handle max_eager_msg_size */
	mtu_size = efa_domain->device->rdm_info->ep_attr->max_msg_size;
	if (rxr_env.mtu_size > 0 && rxr_env.mtu_size < mtu_size)
		mtu_size = rxr_env.mtu_size;
	if (mtu_size > RXR_MTU_MAX_LIMIT)
		mtu_size = RXR_MTU_MAX_LIMIT;

	max_eager_msg_size = mtu_size - rxr_pkt_max_hdr_size();

	if (!fi_param_get_size_t(&rxr_prov, "max_eager_msg_size", &rxr_env.efa_max_eager_msg_size)) {
		if (rxr_env.efa_max_eager_msg_size > max_eager_msg_size) {
			fprintf(stderr,
				"Environment variable FI_EFA_MAX_EAGER_MSG_SIZE=%zu must be less than or equal to %zu\n",
				rxr_env.efa_max_eager_msg_size, max_eager_msg_size);
			abort();
		}
		max_eager_msg_size = rxr_env.efa_max_eager_msg_size;
	}

	memset(all_status, 0, OFI_HMEM_MAX * sizeof(struct efa_hmem_info));

	/* Initialize all hmem_info structures to runtime defaults */
	for (iface = 0; iface < OFI_HMEM_MAX; iface++) {
		all_status[iface].max_eager_msg_size = max_eager_msg_size;
		all_status[iface].max_medium_msg_size = rxr_env.efa_max_medium_msg_size;
		all_status[iface].min_read_msg_size = rxr_env.efa_min_read_msg_size;
		all_status[iface].runt_size = 0;
	}

	ret = 0;

	err = efa_hmem_info_update_cuda(&all_status[FI_HMEM_CUDA]);
	if (err) {
		ret = err;
		EFA_WARN(FI_LOG_DOMAIN, "check cuda support status failed! err: %d\n",
			 err);
	}

	err = efa_hmem_info_update_neuron(&all_status[FI_HMEM_NEURON]);
	if (err) {
		ret = err;
		EFA_WARN(FI_LOG_DOMAIN, "check neuron support status failed! err: %d\n",
			 err);
	}

	err = efa_hmem_info_update_synapseai(&all_status[FI_HMEM_SYNAPSEAI]);
	if (err) {
		ret = err;
		EFA_WARN(FI_LOG_DOMAIN, "check synapseai support status failed! err: %d\n",
			 err);
	}

	return ret;
}
