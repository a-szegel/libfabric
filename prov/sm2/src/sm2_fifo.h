/*
 * Copyright (c) 2004-2007 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2009 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2006-2007 Voltaire. All rights reserved.
 * Copyright (c) 2009-2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2010-2018 Los Alamos National Security, LLC.
 *                         All rights reserved.
 * Copyright (c) 2020      Google, LLC. All rights reserved.
 * Copyright (c) Amazon.com, Inc. or its affiliates. All rights reserved.
 *
 *  * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer listed
 *   in this license in the documentation and/or other materials
 *   provided with the distribution.
 *
 * - Neither the name of the copyright holders nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * The copyright holders provide no reassurances that the source code
 * provided does not infringe any patent, copyright, or any other
 * intellectual property rights of third parties.  The copyright holders
 * disclaim any liability to any recipient for claims brought against
 * recipient by any third party for infringement of that parties
 * intellectual property rights.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ----------------[Copyright from inclusion of MPICH code]----------------
 *
 * The following is a notice of limited availability of the code, and disclaimer
 * which must be included in the prologue of the code and in all source listings
 * of the code.
 *
 * Copyright Notice
 *  + 2002 University of Chicago
 *
 * Permission is hereby granted to use, reproduce, prepare derivative works, and
 * to redistribute to others.  This software was authored by:
 *
 * Mathematics and Computer Science Division
 * Argonne National Laboratory, Argonne IL 60439
 *
 * (and)
 *
 * Department of Computer Science
 * University of Illinois at Urbana-Champaign
 *
 *
 * 			      GOVERNMENT LICENSE
 *
 * Portions of this material resulted from work developed under a U.S.
 * Government Contract and are subject to the following license: the Government
 * is granted for itself and others acting on its behalf a paid-up,
 * nonexclusive, irrevocable worldwide license in this computer software to
 * reproduce, prepare derivative works, and perform publicly and display
 * publicly.
 *
 * 				  DISCLAIMER
 *
 * This computer code material was prepared, in part, as an account of work
 * sponsored by an agency of the United States Government.  Neither the United
 * States, nor the University of Chicago, nor any of their employees, makes any
 * warranty express or implied, or assumes any legal liability or responsibility
 * for the accuracy, completeness, or usefulness of any information, apparatus,
 * product, or process disclosed, or represents that its use would not infringe
 * privately owned rights.
 */
/*
 * Copyright (c) 2023 Amazon.com, Inc. or its affiliates. All rights reserved.
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

/*
 * Multi Writer, Single Reader FIFO Queue (Not Thread Safe)
 * This implementation of this Queue is a one directional linked list
 * with head/tail pointers where every pointer is a relative offset
 * into the Shared Memory Region.
 */

#ifndef _SM2_FIFO_H_
#define _SM2_FIFO_H_

#define SM2_FIFO_CIRCULAR_QUEUE_SIZE 1024

#include "sm2.h"
#include <string.h>
#include "ofi.h"
#include "ofi_atom.h"
#include <rdma/fi_errno.h>

/* Multiple writer, single reader queue.
 * Writes are protected with atomics.
 * Reads are not protected and assumed to be protected with user locking
 */
struct smr_fifo {
	int64_t		size;
	int64_t		size_mask;
        int64_t		read_pos;
	ofi_atomic64_t	write_pos;
	ofi_atomic64_t	free;
	uintptr_t	entries[SM2_FIFO_CIRCULAR_QUEUE_SIZE];
};

/* Initialize FIFO queue to empty state */
static inline void smr_fifo_init(struct smr_fifo *queue, uint64_t size)
{
	assert(size == roundup_power_of_two(size));
	queue->size = size;
	queue->size_mask = size - 1;
	queue->read_pos = 0;
	ofi_atomic_initialize64(&queue->write_pos, 0);
	ofi_atomic_initialize64(&queue->free, size);
	memset(queue->entries, 0, sizeof(uintptr_t) * size);  // MODIFIED THIS LINE WHEN I ADDED THE SIZE TO ENTRIES
}

//TODO figure out memory barriers
static inline int smr_fifo_commit(struct smr_fifo *queue, uintptr_t val)
{
	int64_t free, write;

	for (;;) {
		free = ofi_atomic_load_explicit64(&queue->free,
						  memory_order_relaxed);
		if (!free)
			return -FI_ENOENT;
		if (ofi_atomic_compare_exchange_weak64(
			&queue->free, &free, free - 1))
			break;
	}
	write = ofi_atomic_inc64(&queue->write_pos) - 1;//TODO add atomic to remove sub
	queue->entries[write & queue->size_mask] = val;
	return FI_SUCCESS;
}

/* All read calls within the same process must be protected by the same lock */
static inline uintptr_t smr_fifo_read(struct smr_fifo *queue)
{
	uintptr_t val;

	val = queue->entries[queue->read_pos & queue->size_mask];
	if (!val)
		return 0;

	queue->entries[queue->read_pos++ & queue->size_mask] = 0;
	ofi_atomic_inc64(&queue->free);
	return val;
}

// OLD METHODS to allow us not to change API

static inline void sm2_fifo_init(struct smr_fifo *queue)
{
	smr_fifo_init(queue, SM2_FIFO_CIRCULAR_QUEUE_SIZE);
}

static inline void *sm2_relptr_to_absptr(uintptr_t relptr, struct sm2_mmap *map)
{
	return (void *) (map->base + relptr);
}

static inline uintptr_t sm2_absptr_to_relptr(void *absptr, struct sm2_mmap *map)
{
	return (uintptr_t) ((char *) absptr - map->base);
}

static inline void sm2_fifo_write(struct sm2_ep *ep, sm2_gid_t peer_gid,
				  struct sm2_xfer_entry *xfer_entry)
{
	struct sm2_region *peer_region = sm2_mmap_ep_region(ep->mmap, peer_gid);
	struct smr_fifo *peer_fifo = sm2_recv_queue(peer_region);
	uintptr_t offset = sm2_absptr_to_relptr(xfer_entry, ep->mmap);
	smr_fifo_commit(peer_fifo, offset);
}

/* Read, Dequeue */
static inline struct sm2_xfer_entry *sm2_fifo_read(struct sm2_ep *ep)
{
	struct smr_fifo *self_fifo = sm2_recv_queue(ep->self_region);
	uintptr_t offset  = smr_fifo_read(self_fifo);
	if (!offset) {
		return NULL;
	}

	struct sm2_xfer_entry *xfer_entry = sm2_relptr_to_absptr(offset, ep->mmap);
	return xfer_entry;
}

static inline void sm2_fifo_write_back(struct sm2_ep *ep,
				       struct sm2_xfer_entry *xfer_entry)
{
	xfer_entry->hdr.proto = sm2_proto_return;
	assert(xfer_entry->hdr.sender_gid != ep->gid);
	sm2_fifo_write(ep, xfer_entry->hdr.sender_gid, xfer_entry);
}

#endif /* _SM2_FIFO_H_ */
