#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "memory_forensics.h"
#include "memory_forensics_basic.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static const char* get_event_type_str(int event_type) {
    switch (event_type) {
        case 1: return "ALLOC";
        case 2: return "FREE";
        case 3: return "MMAP";
        case 4: return "MUNMAP";
        case 5: return "PAGE_FAULT";
        default: return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct mem_event *e = data;
    char ts[32];
    time_t t;
    
    time(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    
    printf("%-8s %-16s %-7d %-7d %-12s 0x%-12lx %-8lu 0x%x\n",
           ts, e->comm, e->pid, e->tid, get_event_type_str(e->event_type), 
           e->addr, e->size, e->flags);
    
    return 0;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --verbose  Enable verbose output\n");
    printf("  -p PID         Filter by process ID\n");
    printf("\nBasic Memory Forensics Tool\n");
    printf("Tracks: kernel allocations, user mappings, page faults\n");
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct memory_forensics_basic_bpf *skel;
    int err;
    int target_pid = 0;
    bool verbose = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            target_pid = atoi(argv[++i]);
        }
    }
    
    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    if (verbose) {
        printf("Starting basic memory forensics tool...\n");
        if (target_pid > 0) {
            printf("Filtering for PID: %d\n", target_pid);
        }
    }
    
    /* Load and verify BPF application */
    skel = memory_forensics_basic_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* Load & verify BPF programs */
    err = memory_forensics_basic_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    /* Attach tracepoints and kprobes */
    err = memory_forensics_basic_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("%-8s %-16s %-7s %-7s %-12s %-14s %-8s %s\n",
           "TIME", "COMM", "PID", "TID", "EVENT", "ADDR", "SIZE", "FLAGS");
    printf("------------------------------------------------------------------------\n");
    
    if (verbose) {
        printf("Monitoring memory events... Press Ctrl+C to stop\n\n");
    }
    
    /* Main event loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (verbose) {
        printf("\nCleaning up...\n");
    }
    
    /* Clean up */
    ring_buffer__free(rb);
    memory_forensics_basic_bpf__destroy(skel);
    
    return err < 0 ? -err : 0;
}