# Build the CO-RE eBPF object for the Constellation runtime agent.
#
# Requirements:
#   - clang >= 14
#   - libbpf-dev (provides bpf_helpers.h, bpf_tracing.h, bpf_core_read.h)
#   - bpftool >= 7 (to dump vmlinux.h)
#
# Usage:
#   make            # produces runtime.bpf.o
#   make vmlinux.h  # regenerate vmlinux.h from the running kernel
#   make clean
#
# The userspace loader (loader_linux.go) discovers the object at:
#   $CONSTELLATION_BPF_OBJ, ./bpf/runtime.bpf.o,
#   internal/runtime/ebpf/bpf/runtime.bpf.o, /usr/lib/constellation/runtime.bpf.o

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= x86

CFLAGS = -O2 -g -Wall -Werror \
	-Wno-missing-declarations \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I.

OBJ = runtime.bpf.o
SRC = runtime.bpf.c

all: $(OBJ)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OBJ): $(SRC) vmlinux.h
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@

clean:
	rm -f $(OBJ) vmlinux.h

.PHONY: all clean
