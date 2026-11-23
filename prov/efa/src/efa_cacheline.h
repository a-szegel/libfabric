/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

#ifndef _EFA_CACHELINE_H
#define _EFA_CACHELINE_H

#include <assert.h>
#include <stddef.h>

/*
 * Compile time checks of where a struct's members sit in cache lines. A
 * struct laid out for its cache footprint states the layout with these, so a
 * change that moves a member to another line fails to build.
 */

#define EFA_CACHE_LINE_SIZE	(64)

#define EFA_CL_OF(off)		((off) / EFA_CACHE_LINE_SIZE)
#define EFA_MEMBER_END(type, m)	(offsetof(type, m) + sizeof(((type *) 0)->m) - 1)

/** Member m of type lies entirely in cache line cl. */
#define EFA_ASSERT_IN_CL(type, m, cl)						\
	static_assert(EFA_CL_OF(offsetof(type, m)) == (cl) &&			\
		      EFA_CL_OF(EFA_MEMBER_END(type, m)) == (cl),		\
		      #type "." #m " must be in cache line " #cl)

/** Members a and b start in the same cache line. */
#define EFA_ASSERT_SAME_CL(type, a, b)						\
	static_assert(EFA_CL_OF(offsetof(type, a)) ==				\
		      EFA_CL_OF(offsetof(type, b)),				\
		      #type "." #a " and " #b " must share a cache line")

/** Member m starts a cache line. */
#define EFA_ASSERT_CL_START(type, m)						\
	static_assert(offsetof(type, m) % EFA_CACHE_LINE_SIZE == 0,		\
		      #type "." #m " must start a cache line")

/** Members from the start of first to the end of last span at most n cache lines. */
#define EFA_ASSERT_SPAN_CL(type, first, last, n)				\
	static_assert(EFA_CL_OF(EFA_MEMBER_END(type, last)) -			\
		      EFA_CL_OF(offsetof(type, first)) < (n),			\
		      #type "." #first " to " #last " must fit in " #n " cache lines")

/** Type fits in n cache lines. */
#define EFA_ASSERT_MAX_CL(type, n)						\
	static_assert(sizeof(type) <= (n) * EFA_CACHE_LINE_SIZE,		\
		      #type " must fit in " #n " cache lines")

#endif
