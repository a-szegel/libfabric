/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_test_common.hpp"
#include "efa_unit_test_device_mock.hpp"

extern "C" {
#include <rdma/fi_endpoint.h>
}

/**
 * @brief Test fixture with full resource construction (fabric, domain, endpoint)
 * 
 * This fixture extends EfaUnitTestWithDevice to provide:
 * - Fabric construction via fi_fabric()
 * - Domain construction via fi_domain()
 * - Endpoint construction via fi_endpoint()
 * - AV and CQ construction
 * - Automatic cleanup in TearDown
 */
class EfaUnitTestWithResources : public EfaUnitTestWithDevice {
protected:
    struct fi_info *info = nullptr;
    struct fid_fabric *fabric = nullptr;
    struct fid_domain *domain = nullptr;
    struct fid_ep *ep = nullptr;
    struct fid_av *av = nullptr;
    struct fid_cq *tx_cq = nullptr;
    struct fid_cq *rx_cq = nullptr;

    void SetUp() override {
        EfaUnitTestWithDevice::SetUp();
    }

    void TearDown() override {
        if (ep) fi_close(&ep->fid);
        if (av) fi_close(&av->fid);
        if (tx_cq) fi_close(&tx_cq->fid);
        if (rx_cq) fi_close(&rx_cq->fid);
        if (domain) fi_close(&domain->fid);
        if (fabric) fi_close(&fabric->fid);
        if (info) fi_freeinfo(info);
        
        EfaUnitTestWithDevice::TearDown();
    }

    /**
     * @brief Construct fabric and domain
     */
    void ConstructFabricAndDomain(enum fi_ep_type ep_type = FI_EP_RDM, const char *fabric_name = "efa") {
        SetUpDevice();
        
        struct fi_info *hints = efa_unit_test_alloc_hints(ep_type, (char*)fabric_name);
        ASSERT_NE(hints, nullptr);
        
        int ret = fi_getinfo(FI_VERSION(1,14), NULL, NULL, 0, hints, &info);
        fi_freeinfo(hints);
        ASSERT_EQ(ret, 0) << "fi_getinfo failed with " << ret;
        ASSERT_NE(info, nullptr);
        ASSERT_NE(info->fabric_attr, nullptr);
        
        // Ensure prov_name is set
        if (!info->fabric_attr->prov_name) {
            info->fabric_attr->prov_name = strdup("efa");
        }
        
        ret = fi_fabric(info->fabric_attr, &fabric, NULL);
        ASSERT_EQ(ret, 0) << "fi_fabric failed with " << ret;
        ASSERT_NE(fabric, nullptr);
        
        ret = fi_domain(fabric, info, &domain, NULL);
        ASSERT_EQ(ret, 0) << "fi_domain failed with " << ret;
        ASSERT_NE(domain, nullptr);
    }

    /**
     * @brief Construct CQs for endpoint
     */
    void ConstructCQs() {
        ASSERT_NE(domain, nullptr);
        
        struct fi_cq_attr cq_attr = {};
        cq_attr.size = 128;
        cq_attr.format = FI_CQ_FORMAT_CONTEXT;
        
        int ret = fi_cq_open(domain, &cq_attr, &tx_cq, NULL);
        ASSERT_EQ(ret, 0);
        ASSERT_NE(tx_cq, nullptr);
        
        ret = fi_cq_open(domain, &cq_attr, &rx_cq, NULL);
        ASSERT_EQ(ret, 0);
        ASSERT_NE(rx_cq, nullptr);
    }

    /**
     * @brief Construct AV for endpoint
     */
    void ConstructAV() {
        ASSERT_NE(domain, nullptr);
        
        struct fi_av_attr av_attr = {};
        av_attr.type = FI_AV_TABLE;
        
        int ret = fi_av_open(domain, &av_attr, &av, NULL);
        ASSERT_EQ(ret, 0);
        ASSERT_NE(av, nullptr);
    }

    /**
     * @brief Construct endpoint
     */
    void ConstructEndpoint() {
        ASSERT_NE(domain, nullptr);
        ASSERT_NE(info, nullptr);
        
        int ret = fi_endpoint(domain, info, &ep, NULL);
        ASSERT_EQ(ret, 0);
        ASSERT_NE(ep, nullptr);
    }

    /**
     * @brief Bind CQs and AV to endpoint and enable it
     */
    void BindAndEnableEndpoint() {
        ASSERT_NE(ep, nullptr);
        ASSERT_NE(tx_cq, nullptr);
        ASSERT_NE(rx_cq, nullptr);
        ASSERT_NE(av, nullptr);
        
        int ret = fi_ep_bind(ep, &tx_cq->fid, FI_TRANSMIT);
        ASSERT_EQ(ret, 0);
        
        ret = fi_ep_bind(ep, &rx_cq->fid, FI_RECV);
        ASSERT_EQ(ret, 0);
        
        ret = fi_ep_bind(ep, &av->fid, 0);
        ASSERT_EQ(ret, 0);
        
        ret = fi_enable(ep);
        ASSERT_EQ(ret, 0);
    }

    /**
     * @brief Construct full resource stack (fabric -> domain -> CQs -> AV -> EP)
     */
    void ConstructFullResources(enum fi_ep_type ep_type = FI_EP_RDM, const char *fabric_name = "efa") {
        ConstructFabricAndDomain(ep_type, fabric_name);
        ConstructCQs();
        ConstructAV();
        ConstructEndpoint();
        BindAndEnableEndpoint();
    }
};
