/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
/* SPDX-FileCopyrightText: Copyright Amazon.com, Inc. or its affiliates. All rights reserved. */

/* 
 * This file creates aliases for wrapped functions so the dynamic linker can find them.
 * DO NOT include any headers that declare these functions to avoid conflicts.
 */

// Forward declarations (minimal, no includes)
struct ibv_device;
struct ibv_context;
struct ibv_device_attr;
struct ibv_port_attr;
union ibv_gid;

// Declare the __wrap_ functions as extern (they're defined in efa_unit_test_mocks.cpp)
extern struct ibv_device** __wrap_ibv_get_device_list(int *num);
extern void __wrap_ibv_free_device_list(struct ibv_device **list);
extern const char* __wrap_ibv_get_device_name(struct ibv_device *device);
extern struct ibv_context* __wrap_ibv_open_device(struct ibv_device *device);
extern int __wrap_ibv_close_device(struct ibv_context *context);
extern int __wrap_ibv_query_device(struct ibv_context *context, struct ibv_device_attr *device_attr);
extern int __wrap_ibv_query_port(struct ibv_context *context, unsigned char port_num, struct ibv_port_attr *port_attr);
extern int __wrap_ibv_query_gid(struct ibv_context *context, unsigned char port_num, int index, union ibv_gid *gid);

// Create aliases so dynamic linker resolves calls from libfabric.so to our wrappers
struct ibv_device** ibv_get_device_list(int *num) __attribute__((alias("__wrap_ibv_get_device_list")));
void ibv_free_device_list(struct ibv_device **list) __attribute__((alias("__wrap_ibv_free_device_list")));
const char* ibv_get_device_name(struct ibv_device *device) __attribute__((alias("__wrap_ibv_get_device_name")));
struct ibv_context* ibv_open_device(struct ibv_device *device) __attribute__((alias("__wrap_ibv_open_device")));
int ibv_close_device(struct ibv_context *context) __attribute__((alias("__wrap_ibv_close_device")));
int ibv_query_device(struct ibv_context *context, struct ibv_device_attr *device_attr) __attribute__((alias("__wrap_ibv_query_device")));
int ibv_query_port(struct ibv_context *context, unsigned char port_num, struct ibv_port_attr *port_attr) __attribute__((alias("__wrap_ibv_query_port")));
int ibv_query_gid(struct ibv_context *context, unsigned char port_num, int index, union ibv_gid *gid) __attribute__((alias("__wrap_ibv_query_gid")));
