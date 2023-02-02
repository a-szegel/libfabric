/*
 * Copyright (c) 2016-2021 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
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

#ifndef _OFI_SHM_NEMESIS_H_
#define _OFI_SHM_NEMESIS_H_

#include "config.h"

#include <stdint.h>
#include <stddef.h>
#include <sys/un.h>

#include <ofi_atom.h>
#include <ofi_proto.h>
#include <ofi_mem.h>
#include <ofi_rbuf.h>
#include <ofi_tree.h>
#include <ofi_hmem.h>
#include <ofi_shm.h>

#include <rdma/providers/fi_prov.h>

#ifdef __cplusplus
extern "C" {
#endif


/* smr_msg_hdr -> nemesis_free_queue_entry */
struct nemesis_free_queue_entry {
	uint64_t		msg_id; /* Used for tagging*/
	int64_t			id; /* ??? */
	uint32_t		op; /* type of op (ex. ofi_op_msg, defined in ofi_proto.h) */
	uint16_t		transfer_type; /* nemesis transfer type */

	uint64_t		data; /* SHM Segment + relative offset within it*/
	uint64_t		size; /* Size of Data */
	uint64_t        next_ptr; /* Next SHM Segment + Offset within it */

};

/* Would like to posture that we don't need RMA structures */
/* smr_ep_name, smr_peer, and smr_map define where SHM is... hope to not change much*/


struct smr_region_nemesis {
	uint8_t		version;
	uint8_t		resv;
	uint16_t	flags;
	int		pid;
	uint8_t		cma_cap_peer;
	uint8_t		cma_cap_self;
	uint32_t	max_sar_buf_per_peer;
	void		*base_addr;
	struct smr_map	*map;
	size_t		total_size;
	size_t		sar_cnt;

	/* offsets from start of smr_region */
	size_t		cmd_queue_offset; /* receive_queue... need the head and tail ptrs of the list structure to exist here*/
	size_t      free_queue_offset; /* Start with 1 free queue... could potentially add others*/
	size_t		name_offset;
	size_t		sock_name_offset;
};

struct smr_resp {
	uint64_t	msg_id;
	uint64_t	status;
};

struct smr_inject_buf {
	union {
		uint8_t		data[SMR_INJECT_SIZE];
		struct {
			uint8_t	buf[SMR_COMP_INJECT_SIZE];
			uint8_t comp[SMR_COMP_INJECT_SIZE];
		};
	};
};

enum smr_status {
	SMR_STATUS_SUCCESS = 0, 	/* success*/
	SMR_STATUS_BUSY = FI_EBUSY, 	/* busy */

	SMR_STATUS_OFFSET = 1024, 	/* Beginning of shm-specific codes */
	SMR_STATUS_SAR_FREE, 		/* buffer can be used */
	SMR_STATUS_SAR_READY, 		/* buffer has data in it */
};

struct smr_sar_buf {
	uint8_t		buf[SMR_SAR_SIZE];
};

OFI_DECLARE_CIRQUE(struct smr_cmd, smr_cmd_queue);
OFI_DECLARE_CIRQUE(struct smr_resp, smr_resp_queue);

static inline struct smr_region *smr_peer_region(struct smr_region *smr, int i)
{
	return smr->map->peers[i].region;
}
static inline struct smr_cmd_queue *smr_cmd_queue(struct smr_region *smr)
{
	return (struct smr_cmd_queue *) ((char *) smr + smr->cmd_queue_offset);
}
static inline struct smr_resp_queue *smr_resp_queue(struct smr_region *smr)
{
	return (struct smr_resp_queue *) ((char *) smr + smr->resp_queue_offset);
}
static inline struct smr_freestack *smr_inject_pool(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->inject_pool_offset);
}
static inline struct smr_peer_data *smr_peer_data(struct smr_region *smr)
{
	return (struct smr_peer_data *) ((char *) smr + smr->peer_data_offset);
}
static inline struct smr_freestack *smr_sar_pool(struct smr_region *smr)
{
	return (struct smr_freestack *) ((char *) smr + smr->sar_pool_offset);
}
static inline const char *smr_name(struct smr_region *smr)
{
	return (const char *) smr + smr->name_offset;
}

static inline char *smr_sock_name(struct smr_region *smr)
{
	return (char *) smr + smr->sock_name_offset;
}

static inline void smr_set_map(struct smr_region *smr, struct smr_map *map)
{
	smr->map = map;
}

struct smr_attr {
	const char	*name;
	size_t		rx_count;
	size_t		tx_count;
	uint16_t	flags;
};

size_t smr_calculate_size_offsets(size_t tx_count, size_t rx_count,
				  size_t *cmd_offset, size_t *resp_offset,
				  size_t *inject_offset, size_t *sar_offset,
				  size_t *peer_offset, size_t *name_offset,
				  size_t *sock_offset);
void	smr_cma_check(struct smr_region *region, struct smr_region *peer_region);
void	smr_cleanup(void);
int	smr_map_create(const struct fi_provider *prov, int peer_count,
		       uint16_t caps, struct smr_map **map);
int	smr_map_to_region(const struct fi_provider *prov, struct smr_map *map,
			  int64_t id);
void	smr_map_to_endpoint(struct smr_region *region, int64_t id);
void	smr_unmap_from_endpoint(struct smr_region *region, int64_t id);
void	smr_exchange_all_peers(struct smr_region *region);
int	smr_map_add(const struct fi_provider *prov,
		    struct smr_map *map, const char *name, int64_t *id);
void	smr_map_del(struct smr_map *map, int64_t id);
void	smr_map_free(struct smr_map *map);

struct smr_region *smr_map_get(struct smr_map *map, int64_t id);

int	smr_create(const struct fi_provider *prov, struct smr_map *map,
		   const struct smr_attr *attr, struct smr_region *volatile *smr);
void	smr_free(struct smr_region *smr);

static inline void smr_signal(struct smr_region *smr)
{
	ofi_atomic_set32(&smr->signal, 1);
}

#ifdef __cplusplus
}
#endif

#endif /* _OFI_SHM_H_ */
