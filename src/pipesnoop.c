// SPDX-License-Identifier: BSD-3-Clause
#include "pipesnoop.h"
#include "pipesnoop.skel.h"
#include <sys/socket.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return false;
    }
    return true;
}

static volatile sig_atomic_t stop;
void sig_int(int signo)
{
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char buff[MAX_BUF_SIZE];
    memcpy(buff, e->buff, MAX_BUF_SIZE);

    // Do super basic cleanup
    for (int i = 0; i < MAX_BUF_SIZE; i++) {
        if (buff[i] == 0x00) {
            break;
        }
        else if (buff[i] == '\n') {
            buff[i] = 0x00;
        }
        else if (buff[i] < 33 || buff[i] > 126) {
            buff[i] = '?';
        }
    }

    // Log message
    int start = 0;
    char message[MAX_BUF_SIZE+200];
    start = sprintf(message, "[*] %s[%d] ", e->comm, e->pid);
    if (e->action == WRITE) {
        start = sprintf(message+start, "wrote %d from piped stdout: '%s'",  e->real_size, buff);
    }
    else {
        start = sprintf(message+start, "read %d from piped stdin: '%s'",  e->real_size, buff);
    }

    if (e->real_size > MAX_BUF_SIZE) {
        sprintf(message+start, "<truncated>");
    }

    printf("%s\n", message);
    return 0;
}

int main(int argc, char **argv)
{
    struct pipesnoop_bpf *prog;
    int err;
    struct ring_buffer *rb = NULL;

    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything 
    if (!bump_memlock_rlimit()) {
        exit(1);
    };

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR) {
        fprintf(stderr, "Failed to set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    // Open and load BPF application 
    prog = pipesnoop_bpf__open_and_load();
    if (!prog) {
        fprintf(stderr, "Failed to open BPF progeton\n");
        return 1;
    }

    // Attach tracepoint handler 
    err = pipesnoop_bpf__attach(prog);
    if (err) {
        fprintf(stderr, "Failed to attach BPF progeton\n");
        goto cleanup;
    }

    printf("Successfully started!\n");

    // Setup and start ring buffer
    rb = ring_buffer__new(bpf_map__fd(prog->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    return 0;

cleanup:
    ring_buffer__free(rb);
    pipesnoop_bpf__destroy(prog);
    return err < 0 ? -err : 0;
}
