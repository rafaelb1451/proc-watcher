// ============================================================
// proc_watcher.bpf.c
// Este é o programa que roda DENTRO do kernel do Linux (eBPF).
// Ele intercepta a criação de novos processos e envia os dados
// para o user space através de um Ring Buffer.
// ============================================================

// 1. Cabeçalhos essenciais do eBPF
#include "vmlinux.h"                // Tipos do kernel (gerado automaticamente pelo libbpf-bootstrap)
#include <bpf/bpf_helpers.h>        // Funções auxiliares (bpf_printk, etc.)
#include <bpf/bpf_tracing.h>        // Macros para tracepoints
#include <bpf/bpf_core_read.h>      // Leitura segura de estruturas do kernel (CO-RE)

// 2. Licença obrigatória para carregar o programa no kernel
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 3. A Struct de Dados (o "formulário" que enviaremos para o user space)
struct event {
    __u32 pid;          // PID do processo que está sendo criado
    __u32 ppid;         // PID do processo pai
    char comm[16];      // Nome do comando (máx 16 bytes no kernel)
};

// 4. O Ring Buffer (a "esteira rolante" de comunicação kernel <-> user)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256 KB
} rb SEC(".maps");

// 5. O Programa eBPF anexado ao tracepoint sys_enter_execve
// Toda vez que um programa for executado no Linux, esta função será chamada.
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    // 5.1. Reserva espaço no Ring Buffer para o nosso evento
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e) {
        // Se o buffer estiver cheio, ignora este evento
        return 0;
    }

    // 5.2. Coleta os dados do processo atual
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;   // Parte alta = PID do processo

    // Para pegar o PPID de verdade, usamos o helper bpf_get_current_task_btf()
    // e lemos o campo real_parent->pid da task_struct do kernel (via CO-RE).
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    e->ppid = BPF_CORE_READ(task, real_parent, pid);

    // Nome do comando atual
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 5.3. Envia o evento para o user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}
