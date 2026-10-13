// proc_watcher.c (User Space)
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "proc_watcher.skel.h" // <--- Nome corrigido (sem .bpf)

static volatile sig_atomic_t stop;

static void sig_int(int signo) {
    stop = 1;
}

// Callback chamado sempre que o Ring Buffer recebe um evento
static int handle_event(void *ctx, void *data, size_t data_sz) {
    // A struct abaixo DEVE ser idêntica à do arquivo .bpf.c
    struct event {
        __u32 pid;
        __u32 ppid;
        char comm[16];
    };

    struct event *e = data;
    printf("Novo processo detectado! PID: %d, PPID: %d, Comando: %s\n", 
           e->pid, e->ppid, e->comm);
    return 0;
}

int main(int argc, char **argv) {
    struct proc_watcher_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // 1. Abre o esqueleto do BPF
    skel = proc_watcher_bpf__open();
    if (!skel) {
        fprintf(stderr, "Falha ao abrir o esqueleto BPF\n");
        return 1;
    }

    // 2. Carrega e verifica o programa BPF no kernel
    err = proc_watcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Falha ao carregar o BPF: %d\n", err);
        goto cleanup;
    }

    // 3. Anexa o programa BPF ao tracepoint
    err = proc_watcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Falha ao anexar o BPF: %d\n", err);
        goto cleanup;
    }

    // 4. Configura o Ring Buffer
    // O nome "rb" aqui deve ser o mesmo nome do mapa no .bpf.c
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Falha ao criar o Ring Buffer\n");
        goto cleanup;
    }

    printf("Escutando novos processos... Ctrl+C para sair.\n");

    // 5. Loop principal
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Erro no poll do ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    proc_watcher_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

