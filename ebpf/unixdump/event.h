/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EVENT_H_
#define _EVENT_H_

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[TASK_COMM_LEN]);
	__type(value, u32);
	__uint(max_entries, 512);
} comm_filters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, char[PATH_MAX]);
	__type(value, u32);
	__uint(max_entries, 512);
} socket_filters SEC(".maps");

__attribute__((always_inline)) int is_process_ignored(u32 pid) {
    // check if comms are filtered
    if (load_comm_filter()) {
        char comm[TASK_COMM_LEN] = {};
        bpf_get_current_comm(&comm[0], TASK_COMM_LEN);
        u32 *filter = bpf_map_lookup_elem(&comm_filters, comm);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out event
            return 1;
        }
    }

    // check if pid is filtered
    u32 pid_filter = load_pid_filter();
    if (pid_filter > 0) {
        if (pid != pid_filter) {
            // filter out event
            return 1;
        }
    }
    return 0;
}

__attribute__((always_inline)) int is_socket_ignored(char path[PATH_MAX]) {
    if (load_socket_filter()) {
        u32 *filter = bpf_map_lookup_elem(&socket_filters, path);
        if (filter == 0 || (filter != 0 && *filter != 1)) {
            // filter out event
            return 1;
        }
    }
    return 0;
}

struct unix_event {
    u32 pid;
    u32 peer_pid;
    u32 packet_len;
    u32 socket_len;
    char comm[TASK_COMM_LEN];
    char data[PATH_MAX + MAX_SEG_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct unix_event);
	__uint(max_entries, 16);
} unix_event_gen SEC(".maps");

struct unix_event event_zero = {};

__attribute__((always_inline)) struct unix_event *new_unix_event() {
    u32 cpuID = bpf_get_smp_processor_id();
    int ret = bpf_map_update_elem(&unix_event_gen, &cpuID, &event_zero, BPF_ANY);
    if (ret < 0) {
        // should never happen
        return 0;
    }
    return bpf_map_lookup_elem(&unix_event_gen, &cpuID);
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16384 * 1024 /* 16 MB */);
} events SEC(".maps");

__attribute__((always_inline)) void send_unix_event(struct unix_event *event, u32 len) {
    bpf_ringbuf_output(&events, event, len, BPF_RB_FORCE_WAKEUP);
}

#endif