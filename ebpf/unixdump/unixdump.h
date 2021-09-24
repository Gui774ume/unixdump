/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UNIX_DUMP_H_
#define _UNIX_DUMP_H_

SEC("kprobe/unix_stream_sendmsg")
int kprobe_unix_stream_sendmsg(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // check if process is filtered
    if (is_process_ignored(pid)) {
        return 0;
    }

    // create unix event
    struct unix_event *evt = new_unix_event();
    if (evt == 0) {
        return 0;
    }

    struct unix_sock *local = 0;
    struct unix_sock *peer = 0;
    struct socket *sock = (struct socket *) PT_REGS_PARM1(ctx);

    BPF_CORE_READ_INTO(&local, sock, sk);
    if (BPF_CORE_READ(local, addr, len) > 0) {
        evt->socket_len = BPF_CORE_READ_STR_INTO(&evt->data, local, addr, name[0].sun_path);
    }

    BPF_CORE_READ_INTO(&peer, local, peer);
    if (BPF_CORE_READ(peer, addr, len) > 0) {
        evt->socket_len = BPF_CORE_READ_STR_INTO(&evt->data, peer, addr, name[0].sun_path);
    }

    if (evt->socket_len >= PATH_MAX) {
        evt->socket_len = PATH_MAX;
    }

    // check if the local or peer socket is one of the filtered unix sockets
    if (is_socket_ignored(evt->data)) {
        return 0;
    }

    evt->pid = pid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->peer_pid = BPF_CORE_READ(sock, sk, sk_peer_pid, numbers[0].nr);

    // read message content
    struct msghdr *msg = (struct msghdr *) PT_REGS_PARM2(ctx);

    if ((BPF_CORE_READ(msg, msg_iter.type) & 1) == 0 || BPF_CORE_READ(msg, msg_iter.iov_offset) != 0) {
        // ignore call
        return 0;
    }

    char *buf = 0;
    u32 len = 0;
    u64 segs_counter = 0;
    u64 nr_segs = 0;
    struct kvec *iov = 0;

    BPF_CORE_READ_INTO(&iov, msg, msg_iter.kvec);
    nr_segs = BPF_CORE_READ(msg, msg_iter.nr_segs);

    #pragma unroll
    for (int i = 0; i < MAX_SEGS_PER_MSG; i++) {
        evt->packet_len = BPF_CORE_READ(iov, iov_len);
        len = evt->packet_len;

        BPF_CORE_READ_INTO(&buf, iov, iov_base);
        bpf_probe_read_user_str(evt->data + (evt->socket_len > PATH_MAX ? PATH_MAX : evt->socket_len), len > sizeof(evt->data) - PATH_MAX ? sizeof(evt->data) - PATH_MAX : len, buf);

        len += offsetof(struct unix_event, data) + evt->socket_len;
        send_unix_event(evt, len > sizeof(*evt) ? sizeof(*evt) : len);

        iov++;
        segs_counter++;
        if (segs_counter >= nr_segs) {
            goto next;
        }
    }

next:
    return 0;
}

#endif
