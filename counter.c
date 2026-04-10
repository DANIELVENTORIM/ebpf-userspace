#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <sys/stat.h>
#include <linux/if_link.h>   /* XDP_FLAGS_SKB_MODE */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static struct bpf_object *bpf_obj = NULL;
static int keep_running = 1;

static void sig_handler(int sig) {
    printf("\n[SIGNAL] Descarregando...\n");
    keep_running = 0;
}

static const char* find_bpf_object() {
    const char *paths[] = {
        "./counter.bpf.o",
        "/counter.bpf.o",
        NULL
    };
    
    for (int i = 0; paths[i] != NULL; i++) {
        struct stat sb;
        if (stat(paths[i], &sb) == 0) {
            printf("[✓] Encontrado: %s\n", paths[i]);
            return paths[i];
        }
    }
    
    printf("[ERROR] counter.bpf.o não encontrado!\n");
    return NULL;
}

int main(int argc, char **argv) {
    printf("\n╔════════════════════════════════════════════════╗\n");
    printf("║  eBPF Packet Counter - XDP Loader             ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");
    
    const char *ifname = (argc < 2) ? "eth1" : argv[1];
    int ifindex = if_nametoindex(ifname);
    
    if (!ifindex) {
        fprintf(stderr, "[ERROR] Interface '%s' não encontrada\n", ifname);
        return 1;
    }
    
    printf("[✓] Interface: %s (index: %d)\n\n", ifname, ifindex);
    
    const char *bpf_file = find_bpf_object();
    if (!bpf_file) return 1;
    
    printf("[*] Carregando programa...\n");
    bpf_obj = bpf_object__open(bpf_file);
    if (!bpf_obj) {
        fprintf(stderr, "[ERROR] Falha ao abrir\n");
        return 1;
    }
    
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "[ERROR] Falha ao carregar\n");
        return 1;
    }
    printf("[✓] Programa carregado\n");
    
    struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "xdp_packet_counter");
    if (!prog) {
        fprintf(stderr, "[ERROR] Programa não encontrado\n");
        return 1;
    }
    
    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[ERROR] FD do programa inválido\n");
        return 1;
    }
    
    printf("[*] Anexando ao XDP (modo generic - compatível com veth)...\n");
    /* XDP_FLAGS_SKB_MODE = xdpgeneric: funciona em interfaces veth do Docker */
    __u32 xdp_flags = XDP_FLAGS_SKB_MODE; ///// 
    int ret = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    
    if (ret) {
        fprintf(stderr, "[ERROR] Falha ao anexar: %s\n", strerror(errno));
        return 1;
    }
    printf("[✓] Anexado com sucesso (xdpgeneric)\n");
    
    struct bpf_map *counter_map = bpf_object__find_map_by_name(bpf_obj, "packet_counter");
    if (!counter_map) {
        fprintf(stderr, "[ERROR] Map não encontrado\n");
        return 1;
    }
    
    int map_fd = bpf_map__fd(counter_map);
    if (map_fd < 0) {
        fprintf(stderr, "[ERROR] FD do map inválido\n");
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    
    printf("\n╔═══════════════════════════════════════════════╗\n");
    printf("║     XDP Packet Counter Rodando                ║\n");
    printf("║  Interface: %-33s ║\n", ifname);
    printf("║  Pressione Ctrl+C para sair                   ║\n");
    printf("╚═══════════════════════════════════════════════╝\n\n");
    
    __u64 prev_packets = 0;
    __u64 total_packets = 0;
    int iterations = 0;
    
    while (keep_running) {
        sleep(1);        
        __u32 key = 0;
        __u64 value = 0;        
        // API moderna: 3 argumentos
        int lookup_ret = bpf_map_lookup_elem(map_fd, &key, &value);        
        if (lookup_ret == 0) {
            total_packets = value;
            __u64 diff = total_packets - prev_packets;
            prev_packets = total_packets;
            
            printf("[%3d] Total: %12llu | Taxa: %10llu pps\n",
                   ++iterations,
                   (unsigned long long)total_packets,
                   (unsigned long long)diff);
        } else {
            fprintf(stderr, "[ERROR] Erro ao ler map\n");
            keep_running = 0;
        }
    }    
    printf("\n[*] Descarregando...\n");
    bpf_xdp_attach(ifindex, -1, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(bpf_obj);
    printf("[✓] Saindo...\n\n");
    return 0;
}
