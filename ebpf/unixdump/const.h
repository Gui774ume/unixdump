/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONST_H_
#define _CONST_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u64 load_pid_filter() {
    u64 pid_filter = 0;
    LOAD_CONSTANT("pid_filter", pid_filter);
    return pid_filter;
}

__attribute__((always_inline)) static u64 load_comm_filter() {
    u64 comm_filter = 0;
    LOAD_CONSTANT("comm_filter", comm_filter);
    return comm_filter;
}

__attribute__((always_inline)) static u64 load_socket_filter() {
    u64 socket_filter = 0;
    LOAD_CONSTANT("socket_filter", socket_filter);
    return socket_filter;
}

#define PATH_MAX 255
#define TASK_COMM_LEN 16
#define MAX_SEGS_PER_MSG 100
#define MAX_SEG_SIZE 1024 * 50

#endif
