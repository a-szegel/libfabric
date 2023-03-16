/*
 *
 * This code was taken from OMPI, and modified to make naming neutral
 * https://github.com/open-mpi/ompi
 *
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


#include <stdatomic.h>
#include <stdbool.h>


/* TODO: Switch to using libfabric atomics, ofi_atom */

#define atomic_swap_ptr(addr, value) \
	atomic_exchange_explicit((_Atomic unsigned long *) addr, value, memory_order_relaxed)

#define atomic_compare_exchange(x, y, z) \
	__atomic_compare_exchange_n((int64_t *) (x), (int64_t *) (y), (int64_t)(z), \
								 false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)

#if defined(PLATFORM_ARCH_X86_64) && defined(PLATFORM_COMPILER_GNU) && __GNUC__ < 8
    /* work around a bug in older gcc versions where ACQUIRE seems to get
     * treated as a no-op instead */
#define BUSTED_ATOMIC_MB 1
#else
#define BUSTED_ATOMIC_MB 0
#endif

static inline void atomic_mb(void)
{
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline void atomic_rmb(void)
{
#if BUSTED_ATOMIC_MB
    __asm__ __volatile__("" : : : "memory");
#else
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
#endif
}

static inline void atomic_wmb(void)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
}
