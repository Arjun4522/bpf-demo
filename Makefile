CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_RELEASE := $(shell uname -r)

# Debian/Mint specific kernel header paths
KERNEL_HEADERS_PATHS := \
	/usr/src/linux-headers-$(KERNEL_RELEASE) \
	/lib/modules/$(KERNEL_RELEASE)/build \
	/usr/src/linux-headers-$(KERNEL_RELEASE)-generic \
	/usr/src/linux-headers-$(KERNEL_RELEASE)-common

# Find the first existing path
KERNEL_HEADERS := $(firstword $(wildcard $(KERNEL_HEADERS_PATHS)))

# If no kernel headers found, show helpful error
ifeq ($(KERNEL_HEADERS),)
    $(error Kernel headers not found. Run 'sudo apt-get install linux-headers-$(KERNEL_RELEASE)' to install them)
endif

# BPF compilation flags optimized for Debian/Mint
BPF_CFLAGS = -O2 -g -Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-target bpf -D__TARGET_ARCH_$(ARCH) \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/arch/$(ARCH)/include \
	-I$(KERNEL_HEADERS)/include/generated \
	-I$(KERNEL_HEADERS)/include/uapi \
	-I$(KERNEL_HEADERS)/arch/$(ARCH)/include/uapi \
	-I.

# User space program flags
USER_CFLAGS = -g -Wall
USER_LIBS = -lbpf -lelf -lz

.PHONY: all clean install-deps check-deps setup

all: check-deps hello_bpf.o loader

# Check if all dependencies are available
check-deps:
	@echo "=== Checking Dependencies ==="
	@echo "Kernel headers: $(KERNEL_HEADERS)"
	@which $(CLANG) > /dev/null || (echo "ERROR: clang not found. Run 'make install-deps'" && exit 1)
	@pkg-config --exists libbpf || (echo "ERROR: libbpf not found. Run 'make install-deps'" && exit 1)
	@echo "✓ All dependencies OK"
	@echo

hello_bpf.o: hello_bpf.c
	@echo "Compiling eBPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "✓ eBPF program compiled successfully"

loader: loader.c
	@echo "Compiling loader program..."
	gcc $(USER_CFLAGS) -o $@ $< $(USER_LIBS)
	@echo "✓ Loader program compiled successfully"

clean:
	@echo "Cleaning build files..."
	rm -f *.o loader
	@echo "✓ Clean complete"

# Install all required dependencies for Debian/Mint
install-deps:
	@echo "=== Installing Dependencies for Debian/Linux Mint ==="
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		clang \
		llvm \
		libbpf-dev \
		libbpf0 \
		linux-headers-$(KERNEL_RELEASE) \
		pkg-config \
		libelf-dev \
		zlib1g-dev
	@echo "✓ Dependencies installed successfully"

# Complete setup including mounting debugfs
setup: install-deps
	@echo "=== Setting up eBPF environment ==="
	@if ! mount | grep -q debugfs; then \
		echo "Mounting debug filesystem..."; \
		sudo mount -t debugfs none /sys/kernel/debug; \
	fi
	@echo "✓ Environment setup complete"

# Helper target to run the program
run: all
	@echo "=== Running eBPF Program ==="
	@echo "Press Ctrl+C to stop..."
	@echo "Run 'make trace' in another terminal to see output"
	sudo ./loader

# Helper target to view trace output
trace:
	@echo "=== Viewing eBPF Trace Output ==="
	@echo "Press Ctrl+C to stop..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe

# Show system information
info:
	@echo "=== System Information ==="
	@echo "OS: $(shell lsb_release -d | cut -f2)"
	@echo "Kernel: $(KERNEL_RELEASE)"
	@echo "Architecture: $(ARCH)"
	@echo "Clang: $(shell clang --version 2>/dev/null | head -n1 || echo 'Not installed')"
	@echo "libbpf: $(shell pkg-config --modversion libbpf 2>/dev/null || echo 'Not found')"
	@echo "Kernel headers: $(KERNEL_HEADERS)"

# Help target
help:
	@echo "=== eBPF Project Makefile Help ==="
	@echo
	@echo "Available targets:"
	@echo "  all          - Build the project (default)"
	@echo "  clean        - Remove build files"
	@echo "  install-deps - Install all required dependencies"
	@echo "  setup        - Complete environment setup"
	@echo "  run          - Build and run the eBPF program"
	@echo "  trace        - View eBPF trace output"
	@echo "  info         - Show system information"
	@echo "  help         - Show this help message"
	@echo
	@echo "Quick start:"
	@echo "  make setup   # Install dependencies and setup environment"
	@echo "  make         # Build the project"
	@echo "  make run     # Run the program"
