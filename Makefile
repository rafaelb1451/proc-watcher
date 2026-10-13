# ============================================================
# Makefile - Proc-Watcher
# ============================================================

# Caminho para o bpftool (descobrimos na Fase anterior)
BPFTOOL ?= /usr/sbin/bpftool

# Caminho para o libbpf-bootstrap (assumindo que está no home)
LIBBPF_BOOTSTRAP = $(HOME)/libbpf-bootstrap

# Flags de compilação
CFLAGS = -g -O2 -Wall
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86

# Arquivos fonte
USER_SRC = src/proc_watcher.c
BPF_SRC = src/proc_watcher.bpf.c

# Arquivos gerados
BPF_OBJ = src/proc_watcher.bpf.o
SKEL_H = src/proc_watcher.skel.h
TARGET = proc-watcher

# Regra principal
all: $(TARGET)

# 1. Compilar o código eBPF (Kernel Space)
$(BPF_OBJ): $(BPF_SRC)
	clang $(BPF_CFLAGS) -I$(LIBBPF_BOOTSTRAP)/libbpf/include -I$(LIBBPF_BOOTSTRAP)/libbpf/include/uapi -c $< -o $@

# 2. Gerar o esqueleto (Skeleton) com o bpftool
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 3. Compilar o programa do User Space
$(TARGET): $(USER_SRC) $(SKEL_H)
	gcc $(CFLAGS) -I$(LIBBPF_BOOTSTRAP)/libbpf/include -I$(LIBBPF_BOOTSTRAP)/libbpf/include/uapi -I$(LIBBPF_BOOTSTRAP)/libbpf/src -I$(LIBBPF_BOOTSTRAP)/src -o $@ $< -L$(LIBBPF_BOOTSTRAP)/libbpf/src -l:libbpf.a -lelf -lz

# Limpar arquivos gerados
clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)

.PHONY: all clean