# Makefile for Memory Forensics BPF Tool

APP = memory_forensics
BPF_SKEL = memory_forensics_basic.skel.h
BPF_PROG = memory_forensics_basic.bpf.o
BPF_C = memory_forensics.c

# Paths
LIBBPF_SRC = $(abspath ./libbpf/src)
LIBBPF_OBJ = $(LIBBPF_SRC)/libbpf.a

# Compiler and flags
CC = gcc
CLANG = clang
LLVM_STRIP = llvm-strip
BPFTOOL = bpftool

CFLAGS = -g -O2 -Wall
INCLUDES = -I$(LIBBPF_SRC) -I./

LDFLAGS = -lelf -lz

.PHONY: all clean run

all: $(APP) $(BPF_PROG)

$(BPF_PROG): $(BPF_C) $(LIBBPF_OBJ)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES) -c $(BPF_C) -o $@
	$(LLVM_STRIP) -g $@

$(BPF_SKEL): $(BPF_PROG)
	$(BPFTOOL) gen skeleton $< > $@

$(APP): loader.c $(BPF_SKEL) $(LIBBPF_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBBPF_OBJ) $(LDFLAGS)

clean:
	rm -f $(APP) $(BPF_PROG) $(BPF_SKEL)

run: $(APP)
	sudo ./$(APP)