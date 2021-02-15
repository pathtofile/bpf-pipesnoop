// SPDX-License-Identifier: BSD-3-Clause
#include "pipesnoop.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

int target_ppid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, int);
    __type(value, int);
} map_write_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, int);
    __type(value, int);
} map_read_fd SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, size_t);
    __type(value, unsigned long);
} map_read_pid_tgid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


// int dup2(int oldfd, int newfd);
SEC("tp/syscalls/sys_enter_dup2")
int handle_dup2_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (target_ppid != 0) {
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (pid != target_ppid && ppid != target_ppid) {
            return 0;
        }
    }
    char comm[TASK_COMM_LEN];
    bpf_core_read_str(&comm, TASK_COMM_LEN, &task->comm);

    int oldfd = ctx->args[0];
    int newfd = ctx->args[1];
    if (newfd == 1) {
        int fd = 1;
        bpf_printk("[DUP2] %s[%d] Setting stdout to fd %d\n", comm, pid, oldfd);
        bpf_map_update_elem(&map_write_fd, &pid, &fd, BPF_ANY);
    }
    else if (newfd == 0) {
        int fd = 0;
        bpf_printk("[DUP2] %s[%d] Setting stdin to fd %d\n", comm, pid, oldfd);
        bpf_map_update_elem(&map_read_fd, &pid, &fd, BPF_ANY);
    }
    return 0;
}


SEC("tp/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx)
{
    // If parent is in map, then
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    int* pfd = bpf_map_lookup_elem(&map_write_fd, &pid);
    if (pfd == 0) {
        return 0;
    }

    int map_fd = *pfd;
    int write_fd = ctx->args[0];
    if (map_fd != write_fd) {
        return 0;
    }

    // Find out what is read
    unsigned long write_buf = ctx->args[1];
    unsigned int real_size = ctx->args[2];

    // Add to ring buffer
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = pid;
    e->action = WRITE;
    e->real_size = real_size;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(&e->buff, MAX_BUF_SIZE, (char*)write_buf);
    for (int i = 0; i < MAX_BUF_SIZE; i++) {
        if (i > real_size) {
            e->buff[i] = 0x00;
        }
    }
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    int* pfd = bpf_map_lookup_elem(&map_read_fd, &pid);
    if (pfd == 0) {
        return 0;
    }

    int map_fd = *pfd;
    int write_fd = ctx->args[0];
    if (map_fd != write_fd) {
        return 0;
    }

    // Add pid_tgit to map for exit
    unsigned long read_buf = ctx->args[1];
    bpf_map_update_elem(&map_read_pid_tgid, &pid_tgid, &read_buf, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    int read_size = ctx->ret;
    if (read_size == 0) {
        return 0;
    }

    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check we're in the return of a read we want
    unsigned long* pBuff = bpf_map_lookup_elem(&map_read_pid_tgid, &pid_tgid);
    if (pBuff == 0) {
        return 0;
    }
    bpf_map_delete_elem(&map_read_pid_tgid, &pid_tgid);
    unsigned long read_buff = *pBuff;

    // Add to ring buffer
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->pid = pid;
    e->action = READ;
    e->real_size = read_size;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(&e->buff, MAX_BUF_SIZE, (char*)read_buff);
    for (int i = 0; i < MAX_BUF_SIZE; i++) {
        if (i > read_size) {
            e->buff[i] = 0x00;
        }
    }
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/syscalls/sys_exit_exit_group")
int handle_exit_group_enter(struct trace_event_raw_sys_exit *ctx)
{
    // Clear out program once it exits
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    bpf_map_delete_elem(&map_write_fd, &pid);
    bpf_map_delete_elem(&map_read_fd, &pid);
    return 0;
}
