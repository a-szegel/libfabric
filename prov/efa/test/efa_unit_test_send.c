/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#include "efa_unit_tests.h"
#include "ofi_util.h"
#include "efa_rdm_ep.h"

#define MSG_SIZE 10

void test_efa_rdm_msg_send_to_local_peer_with_null_desc(struct efa_resource **state)
{
        struct efa_resource *resource = *state;
        char buf[MSG_SIZE];
        int i;
        struct iovec iov;
        struct efa_ep_addr raw_addr;
	size_t raw_addr_len = sizeof(raw_addr);
        fi_addr_t addr;
        int ret;
        struct fi_msg msg = {0};
        struct fi_msg_tagged tmsg = {0};

        efa_unit_test_resource_construct(resource, FI_EP_RDM, EFA_FABRIC_NAME);

        ret = fi_getname(&resource->ep->fid, &raw_addr, &raw_addr_len);
	assert_int_equal(ret, 0);

	raw_addr.qpn = 1;
	raw_addr.qkey = 0x1234;
	ret = fi_av_insert(resource->av, &raw_addr, 1, &addr, 0 /* flags */, NULL /* context */);
	assert_int_equal(ret, 1);

        for (i = 0; i < MSG_SIZE; i++)
                buf[i] = 'a' + i;

        iov.iov_base = buf;
        iov.iov_len = MSG_SIZE;

        efa_unit_test_construct_msg(&msg, &iov, 1, addr, NULL, 0, NULL);

        efa_unit_test_construct_tmsg(&tmsg, &iov, 1, addr, NULL, 0, NULL, 0, 0);

        /* The peer won't be verified by shm so it is expected that EAGAIN will be returned */
        ret = fi_send(resource->ep, buf, MSG_SIZE, NULL, addr, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_sendv(resource->ep, &iov, NULL, 1, addr, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_senddata(resource->ep, buf, MSG_SIZE, NULL, 0, addr, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_sendmsg(resource->ep, &msg, 0);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_tsend(resource->ep, buf, MSG_SIZE, NULL, addr, 0, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_tsendv(resource->ep, &iov, NULL, 1, addr, 0, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_tsenddata(resource->ep, buf, MSG_SIZE, NULL, 0, addr, 0, NULL);
        assert_int_equal(ret, -FI_EAGAIN);

        ret = fi_tsendmsg(resource->ep, &tmsg, 0);
        assert_int_equal(ret, -FI_EAGAIN);
}

/**
 * @brief Test that multi-packet send failure does not leave in-flight packets
 *
 * Unlike RDMA write/read which post segments individually (each with its own
 * ibv_wr_complete), the send path batches all packets via efa_rdm_pke_sendv()
 * using FI_MORE + ibv_wr_complete, making it all-or-nothing. On failure,
 * efa_rdm_ep_record_tx_op_submitted() is never called, so no packets are
 * tracked as in-flight, and the txe can be safely released.
 *
 * This test forces a medium RTM (multi-packet send) and makes the last
 * efa_qp_post_send fail, then verifies no packets are in-flight and the
 * txe_list is empty (txe was safely released by the caller).
 */
void test_efa_rdm_msg_send_multi_pkt_sendv_fail_no_inflight(
		struct efa_resource **state)
{
	struct efa_resource *resource = *state;
	struct efa_rdm_ep *efa_rdm_ep;
	struct efa_rdm_peer *peer;
	struct efa_unit_test_buff send_buff;
	fi_addr_t addr;
	struct efa_ep_addr raw_addr;
	size_t raw_addr_len = sizeof(raw_addr);
	void *desc;
	int ret;

	efa_unit_test_resource_construct_rdm_shm_disabled(resource);
	efa_rdm_ep = container_of(resource->ep, struct efa_rdm_ep,
				  base_ep.util_ep.ep_fid);

	/* Set up peer */
	ret = fi_getname(&resource->ep->fid, &raw_addr, &raw_addr_len);
	assert_int_equal(ret, 0);
	raw_addr.qpn = 1;
	raw_addr.qkey = 0x1234;
	ret = fi_av_insert(resource->av, &raw_addr, 1, &addr, 0, NULL);
	assert_int_equal(ret, 1);

	peer = efa_rdm_ep_get_peer(efa_rdm_ep, addr);
	peer->flags |= EFA_RDM_PEER_HANDSHAKE_RECEIVED;

	/*
	 * Create a buffer larger than eager max but within medium range.
	 * This forces a medium RTM which uses multiple packets.
	 * Use 16k which should require ~2 medium packets with typical MTU.
	 */
	efa_unit_test_buff_construct(&send_buff, resource, 16384);
	desc = fi_mr_desc(send_buff.mr);

	/*
	 * Mock: first efa_qp_post_send succeeds, second fails with ENOMEM.
	 * In the real ibv_wr_* path, the first WR would not be submitted
	 * (FI_MORE prevents ibv_wr_complete). The mock simulates the
	 * worst case where the first call "succeeds" independently.
	 */
	g_efa_unit_test_mocks.efa_qp_post_send = &efa_mock_efa_qp_post_send_return_mock;
	will_return(efa_mock_efa_qp_post_send_return_mock, 0);
	will_return(efa_mock_efa_qp_post_send_return_mock, ENOMEM);

	ret = fi_send(resource->ep, send_buff.buff, send_buff.size, desc,
		      addr, NULL);
	assert_int_equal(ret, -FI_EAGAIN);

	/*
	 * Verify: no packets are in-flight (efa_rdm_ep_record_tx_op_submitted
	 * was never called because efa_rdm_pke_sendv failed), and the txe was
	 * released by the caller. This confirms send is not susceptible to the
	 * partial-post double-free that affects RDMA write/read.
	 */
	assert_int_equal(efa_rdm_ep->efa_outstanding_tx_ops, 0);
	assert_true(dlist_empty(&peer->outstanding_tx_pkts));
	assert_int_equal(efa_unit_test_get_dlist_length(&efa_rdm_ep->txe_list), 0);

	efa_unit_test_buff_destruct(&send_buff);
}
