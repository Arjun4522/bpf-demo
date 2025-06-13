// loader.c - Final version
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

static volatile int running = 1;

static void sig_handler(int sig) {
    running = 0;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    // Set up signal handling for graceful exit
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load the BPF object file
    obj = bpf_object__open("hello_bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    // Find the program by section name
    prog = bpf_object__find_program_by_name(obj, "hello_world");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach the program to the tracepoint
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Error attaching BPF program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program loaded and attached successfully!\n");
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' in another terminal to see output.\n");
    printf("Press Ctrl+C to exit...\n");

    // Keep the program running
    while (running) {
        sleep(1);
    }

    printf("\nDetaching BPF program...\n");
    
    // Cleanup
    bpf_link__destroy(link);
    bpf_object__close(obj);
    
    printf("BPF program detached successfully.\n");
    return 0;
}
