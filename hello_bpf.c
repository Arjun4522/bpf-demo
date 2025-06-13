// hello_bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_world(void *ctx) {
    bpf_printk("Hello world from eBPF!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
