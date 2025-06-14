#ifndef __MEMORY_FORENSICS_BASIC_H
#define __MEMORY_FORENSICS_BASIC_H

// Basic memory forensics event types
#define EVENT_MEM_ALLOC     1
#define EVENT_MEM_FREE      2
#define EVENT_MMAP          3
#define EVENT_MUNMAP        4
#define EVENT_PAGE_FAULT    5

// Basic memory forensics event structure
struct mem_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 event_type;
    __u64 addr;
    __u64 size;
    __u32 flags;
    char comm[16];
    __u32 cpu;
};

// Process memory statistics
struct proc_mem_stats {
    __u64 total_allocs;
    __u64 total_frees;
    __u64 current_usage;
    __u64 peak_usage;
};

#endif /* __MEMORY_FORENSICS_BASIC_H */