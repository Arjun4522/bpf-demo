#!/bin/bash

# eBPF Project Setup Script for Debian/Linux Mint
# Run this script to set up your development environment

echo "=== eBPF Development Environment Setup for Debian/Linux Mint ==="
echo

# Update package lists
echo "1. Updating package lists..."
sudo apt-get update

# Install essential build tools
echo "2. Installing essential build tools..."
sudo apt-get install -y build-essential

# Install eBPF development dependencies
echo "3. Installing eBPF development dependencies..."
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libbpf0 \
    linux-headers-$(uname -r) \
    pkg-config \
    libelf-dev \
    zlib1g-dev

# Verify installations
echo "4. Verifying installations..."
echo -n "Clang version: "
clang --version | head -n1

echo -n "LLVM version: "
llvm-config --version

echo -n "Kernel version: "
uname -r

echo -n "Kernel headers: "
if [ -d "/usr/src/linux-headers-$(uname -r)" ]; then
    echo "✓ Found at /usr/src/linux-headers-$(uname -r)"
elif [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "✓ Found at /lib/modules/$(uname -r)/build"
else
    echo "✗ Not found - this might cause compilation issues"
fi

echo -n "libbpf: "
if pkg-config --exists libbpf; then
    echo "✓ Found (version $(pkg-config --modversion libbpf))"
else
    echo "✗ Not found"
fi

# Check if debugfs is mounted (needed for trace_pipe)
echo -n "Debug filesystem: "
if mount | grep -q debugfs; then
    echo "✓ Mounted"
else
    echo "⚠ Not mounted - mounting now..."
    sudo mount -t debugfs none /sys/kernel/debug
fi

echo
echo "=== Setup Complete! ==="
echo
echo "File naming convention:"
echo "- Source: hello_bpf.c"
echo "- Object: hello_bpf.o"
echo "- Loader: loader.c -> loader"
echo
echo "Now you can:"
echo "1. Create your project files"
echo "2. Run 'make' to build"
echo "3. Run 'sudo ./loader' to execute"
echo "4. Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see output"
echo
