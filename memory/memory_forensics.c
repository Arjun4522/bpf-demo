#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EVENT_MEM_ALLOC     1
#define EVENT_MEM_FREE      2
#define EVENT_MMAP          3
#define EVENT_MUNMAP        4
#define EVENT_PAGE_FAULT    5

struct mem_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 event_type;
    u64 addr;
    u64 size;
    u32 flags;
    char comm[16];
    u32 cpu;
};

// Simple ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Basic process memory tracking
struct proc_mem_stats {
    u64 total_allocs;
    u64 total_frees;
    u64 current_usage;
    u64 peak_usage;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct proc_mem_stats);
} proc_stats SEC(".maps");

static int emit_mem_event(void *ctx, u32 event_type, u64 addr, u64 size, u32 flags) {
    struct mem_event *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->event_type = event_type;
    event->addr = addr;
    event->size = size;
    event->flags = flags;
    event->cpu = bpf_get_smp_processor_id();
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static void update_proc_stats(u32 pid, u32 event_type, u64 size) {
    struct proc_mem_stats *stats;
    struct proc_mem_stats new_stats = {0};
    
    stats = bpf_map_lookup_elem(&proc_stats, &pid);
    if (!stats) {
        bpf_map_update_elem(&proc_stats, &pid, &new_stats, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&proc_stats, &pid);
        if (!stats)
            return;
    }
    
    switch (event_type) {
        case EVENT_MEM_ALLOC:
            stats->total_allocs++;
            stats->current_usage += size;
            if (stats->current_usage > stats->peak_usage)
                stats->peak_usage = stats->current_usage;
            break;
        case EVENT_MEM_FREE:
            stats->total_frees++;
            if (stats->current_usage >= size)
                stats->current_usage -= size;
            break;
        case EVENT_MMAP:
            stats->current_usage += size;
            if (stats->current_usage > stats->peak_usage)
                stats->peak_usage = stats->current_usage;
            break;
        case EVENT_MUNMAP:
            if (stats->current_usage >= size)
                stats->current_usage -= size;
            break;
    }
}

// Basic kernel memory allocation tracking
SEC("kprobe/__kmalloc")
int BPF_KPROBE(trace_kmalloc, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (size == 0)
        return 0;
    
    emit_mem_event(ctx, EVENT_MEM_ALLOC, 0, size, 0);
    update_proc_stats(pid, EVENT_MEM_ALLOC, size);
    
    return 0;
}

SEC("kprobe/kfree")
int BPF_KPROBE(trace_kfree, const void *addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    if (addr == 0)
        return 0;
    
    emit_mem_event(ctx, EVENT_MEM_FREE, (u64)addr, 0, 0);
    // Note: We can't easily get the size in kfree, so we pass 0
    update_proc_stats(pid, EVENT_MEM_FREE, 0);
    
    return 0;
}

// User space memory mapping tracking
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 addr = (u64)ctx->args[0];
    u64 len = (u64)ctx->args[1];
    u32 prot = (u32)ctx->args[2];
    u32 flags = (u32)ctx->args[3];
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Mark executable mappings
    if (prot & 0x4) // PROT_EXEC
        flags |= 0x100;
    
    emit_mem_event(ctx, EVENT_MMAP, addr, len, flags);
    update_proc_stats(pid, EVENT_MMAP, len);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 addr = (u64)ctx->args[0];
    u64 len = (u64)ctx->args[1];
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    emit_mem_event(ctx, EVENT_MUNMAP, addr, len, 0);
    update_proc_stats(pid, EVENT_MUNMAP, len);
    
    return 0;
}

// Basic page fault tracking
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(trace_page_fault, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    if (vma) {
        unsigned long vm_flags;
        bpf_core_read(&vm_flags, sizeof(vm_flags), &vma->vm_flags);
        
        // Only track executable pages for now
        if (vm_flags & 0x4) { // VM_EXEC
            emit_mem_event(ctx, EVENT_PAGE_FAULT, address, 0, flags);
        }
    }
    return 0;
}

// Process lifecycle tracking
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct proc_mem_stats stats = {0};
    bpf_map_update_elem(&proc_stats, &pid, &stats, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&proc_stats, &pid);
    return 0;
}

char _license[] SEC("license") = "GPL";