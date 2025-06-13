# eBPF Hello World 

A simple eBPF demonstration that prints "Hello world from eBPF!" whenever the `execve` system call is triggered. This project serves as an introduction to eBPF programming and kernel tracing.

## Prerequisites

- Debian-based Linux distribution (Debian, Ubuntu, Linux Mint, etc.)
- Linux kernel 5.15 or newer (recommended)
- sudo/root access (for loading eBPF programs)
- Internet connection (for package installation)

## Quick Start

### 1. Automated Setup (Debian/Ubuntu/Mint)

```bash
# Make setup script executable
chmod +x setup.sh

# Run setup script (installs dependencies)
./setup.sh

# Install kernel-specific tools (distribution-agnostic)
sudo apt update
sudo apt install -y linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)

# Generate vmlinux.h (required for BTF - Byte Type Format)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 2. Create Makefile

Create a `Makefile` in your project directory:

```makefile
# Makefile for eBPF Hello World
CLANG = clang
LLC = llc
CC = gcc

# Flags
CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -target bpf -D__TARGET_ARCH_x86 -I.
LIBS = -lbpf -lelf -lz

# Targets
TARGET = hello_bpf
LOADER = loader

.PHONY: all clean trace

all: $(TARGET).o $(LOADER)

# Compile eBPF program
$(TARGET).o: $(TARGET).c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile loader program
$(LOADER): $(LOADER).c
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Helper target to view trace output
trace:
	@echo "Viewing eBPF trace output (Ctrl+C to exit):"
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(TARGET).o $(LOADER) vmlinux.h
```

### 3. Build and Run

```bash
# Build the project
make

# Load and run the eBPF program (in one terminal)
sudo ./loader

# View output (in another terminal)
make trace
```

### 4. Trigger the eBPF Program

Open a third terminal and run any command (like `ls`, `ps`, or `whoami`). You should see "Hello world from eBPF!" messages appear in the trace output.

## Manual Setup (Other Distributions)

For non-Debian systems, ensure you have the following packages installed:

### Red Hat/Fedora/CentOS:
```bash
# Install development tools and eBPF dependencies
sudo dnf install clang llvm bpftool libbpf-devel kernel-devel elfutils-libelf-devel zlib-devel

# Install kernel-specific tools
sudo dnf install kernel-tools-$(uname -r)
```

### Arch Linux:
```bash
# Install eBPF development packages
sudo pacman -S clang llvm bpf libbpf linux-headers elfutils zlib

# bpftool is usually included in the bpf package, or install separately:
sudo pacman -S bpftool
```

### Alpine Linux:
```bash
# Install development dependencies
sudo apk add clang llvm bpftool libbpf-dev linux-headers elfutils-dev zlib-dev

# Note: bpftool might need to be compiled from source on Alpine
```

### SUSE/openSUSE:
```bash
# Install eBPF development tools
sudo zypper install clang llvm bpftool libbpf-devel kernel-devel libelf-devel zlib-devel

# Install kernel tools
sudo zypper install kernel-tools-$(uname -r)
```

### Distribution-Agnostic bpftool Installation:

If bpftool is not available in your distribution's package manager:

```bash
# Method 1: Check if it's in kernel tools
which bpftool || sudo apt install linux-tools-$(uname -r)  # Debian/Ubuntu
which bpftool || sudo dnf install kernel-tools-$(uname -r)  # RHEL/Fedora
which bpftool || sudo zypper install kernel-tools-$(uname -r)  # SUSE

# Method 2: Compile from source (if package not available)
git clone https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
```

### Alternative vmlinux.h Generation:

If bpftool is not available, you can generate vmlinux.h alternatively:

```bash
# Method 1: From running kernel BTF (preferred)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Method 2: Download pre-generated (for common kernels)
curl -L https://raw.githubusercontent.com/libbpf/libbpf/master/include/uapi/linux/bpf.h > bpf.h
wget https://github.com/aquasecurity/btfhub/raw/main/archive/$(uname -r | cut -d'-' -f1)/$(uname -m)/vmlinux.h

# Method 3: Extract from kernel source
if [ -d "/lib/modules/$(uname -r)/build" ]; then
    make -C /lib/modules/$(uname -r)/build scripts/extract-vmlinux
    /lib/modules/$(uname -r)/build/scripts/extract-vmlinux /boot/vmlinuz-$(uname -r) > vmlinux
    pahole --btf_encode_detached vmlinux.btf vmlinux
    bpftool btf dump file vmlinux.btf format c > vmlinux.h
fi
```

### Core Requirements:
1. Build tools (gcc, make, etc.)
2. Clang/LLVM (version 10+ recommended)
3. libbpf development libraries
4. Kernel headers for your running kernel
5. bpftool (for BTF generation)
6. libelf and zlib development libraries

## Project Structure

```
.
├── hello_bpf.c     # eBPF program (kernel-space code)
├── loader.c        # User-space loader program
├── setup.sh        # Environment setup script for Debian-based systems
├── Makefile        # Build automation
├── vmlinux.h       # Generated kernel type definitions
└── README.md       # This file
```

## How It Works

1. **eBPF Program (`hello_bpf.c`)**: Attaches to the `sys_enter_execve` tracepoint
2. **Trigger**: Whenever any process executes (`execve` system call), the eBPF program runs
3. **Output**: The program writes "Hello world from eBPF!" to the kernel trace buffer using `bpf_printk()`
4. **Loader (`loader.c`)**: Keeps the program attached until interrupted (Ctrl+C)
5. **Viewing**: Output is visible via the kernel's trace pipe at `/sys/kernel/debug/tracing/trace_pipe`

## Understanding the Code

### eBPF Program Structure

```c
SEC("tracepoint/syscalls/sys_enter_execve")  // Attach point
int hello_world(void *ctx) {                 // Handler function
    bpf_printk("Hello world from eBPF!\n");  // Kernel logging
    return 0;                                // Success return
}
```

### Loader Program Flow

1. Load BPF object file (`hello_bpf.o`)
2. Find the program by name
3. Attach to the kernel tracepoint
4. Wait for user interrupt
5. Clean up and detach

## Troubleshooting

### Common Issues

#### 1. Missing vmlinux.h
```bash
# Generate vmlinux.h from kernel BTF
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Alternative: Download from kernel source
wget https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h
```

#### 2. Permission Errors
```bash
# Ensure debugfs is mounted
sudo mount -t debugfs none /sys/kernel/debug

# Check mount status
mount | grep debugfs

# Run loader with sudo
sudo ./loader
```

#### 3. Kernel Version Mismatch
```bash
# Check running kernel
uname -r

# Verify headers exist
ls /usr/src/linux-headers-$(uname -r)
# or
ls /lib/modules/$(uname -r)/build

# Install matching headers (Debian/Ubuntu)
sudo apt install linux-headers-$(uname -r)
```

#### 4. Build Errors
```bash
# Check if all dependencies are installed
clang --version
llvm-config --version
pkg-config --exists libbpf && echo "libbpf OK" || echo "libbpf missing"

# Verify bpftool installation (distribution-agnostic)
which bpftool || echo "bpftool not found"

# Install bpftool based on your distribution:
# Debian/Ubuntu:
sudo apt install linux-tools-$(uname -r) linux-cloud-tools-$(uname -r)
# RHEL/Fedora:
sudo dnf install kernel-tools-$(uname -r)
# SUSE:
sudo zypper install kernel-tools-$(uname -r)
# Arch:
sudo pacman -S bpftool
```

#### 5. No Trace Output
```bash
# Check if program is loaded
sudo bpftool prog list

# Check if tracepoint exists
sudo ls /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/

# Enable tracing
echo 1 | sudo tee /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable
```

### Debug Commands

```bash
# List loaded eBPF programs
sudo bpftool prog list

# Show program details
sudo bpftool prog show id <ID>

# List available tracepoints
sudo ls /sys/kernel/debug/tracing/events/syscalls/

# Check trace buffer
sudo cat /sys/kernel/debug/tracing/trace

# Clear trace buffer
sudo sh -c 'echo > /sys/kernel/debug/tracing/trace'
```

## Advanced Usage

### Viewing Specific Process Information

Modify the eBPF program to show more details:

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int hello_world(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("Hello from PID %d (%s)!\n", pid, comm);
    return 0;
}
```

### Different Attachment Points

You can modify the SEC annotation to attach to different events:

```c
SEC("tracepoint/syscalls/sys_enter_open")     // File opens
SEC("tracepoint/syscalls/sys_enter_write")    // Write operations
SEC("kprobe/do_sys_open")                     // Kernel probe
```

## Performance Considerations

- eBPF programs run in kernel space and should be lightweight
- Avoid complex operations or loops in eBPF code
- `bpf_printk()` has limited formatting support
- Consider using BPF maps for more complex data sharing

## Cleanup

```bash
# Remove built files
make clean

# Remove generated vmlinux.h (optional)
rm -f vmlinux.h

# Kill any running loader processes
sudo pkill -f "./loader"
```

## Learning Resources

- [eBPF Documentation](https://ebpf.io/)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf GitHub Repository](https://github.com/libbpf/libbpf)

## License

This project is licensed under GPL-2.0, matching libbpf's license requirements for eBPF programs that run in kernel space.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

---

**Note**: This is a learning project. For production eBPF applications, consider using frameworks like [Cilium](https://cilium.io/) or [BCC](https://github.com/iovisor/bcc) for more robust development.
