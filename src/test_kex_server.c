#include "../include/kex.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>

#define DEFAULT_PORT 8888
#define DEFAULT_SERVER_IP "0.0.0.0"
#define DEFAULT_BACKLOG 5

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h              Show this help message\n");
    fprintf(stderr, "  -i <ip>         Server IP address (default: %s)\n", DEFAULT_SERVER_IP);
    fprintf(stderr, "  -p <port>       Port number (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -k <kex>        Key exchange algorithm (ecdhp256, ecdhp384, default: ecdhp256)\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_SERVER_IP;
    int port = DEFAULT_PORT;
    kex_type_t kex_type = KEX_ECDH_P256;
    
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:k:")) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'i':
                server_ip = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'k':
                if (strcmp(optarg, "ecdhp256") == 0) {
                    kex_type = KEX_ECDH_P256;
                } else if (strcmp(optarg, "ecdhp384") == 0) {
                    kex_type = KEX_ECDH_P384;
                } else {
                    fprintf(stderr, "Unknown key exchange: %s\n", optarg);
                    return 1;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=== Key Exchange Test Server ===\n");
    printf("Listening on %s:%d\n", server_ip, port);
    printf("Algorithm: %s\n\n", kex_type_to_string(kex_type));
    
    // 创建服务器socket
    int server_fd = network_create_tcp_server_socket(server_ip, port, DEFAULT_BACKLOG);
    if (server_fd < 0) {
        return 1;
    }
    
    printf("Waiting for client connection...\n");
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept failed");
            break;
        }
        
        printf("\nClient connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // 初始化密钥交换上下文
        kex_ctx_t ctx;
        if (kex_ctx_init(&ctx, kex_type) != 0) {
            fprintf(stderr, "Error: Failed to initialize key exchange\n");
            close(client_fd);
            continue;
        }
        
        // 生成密钥对
        printf("1. Generating key pair...\n");
        if (kex_generate_keypair(&ctx) != 0) {
            fprintf(stderr, "Error: Failed to generate key pair\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        printf("   ✓ Key pair generated\n");
        
        // 接收客户端公钥
        printf("2. Receiving client public key...\n");
        uint8_t pkt_type;
        if (network_recv_all(client_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
            fprintf(stderr, "Error: Failed to receive packet type\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        if (pkt_type != 0x01) {  // PKT_TYPE_KEY_EXCHANGE
            fprintf(stderr, "Error: Unexpected packet type\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        kex_packet_t client_kex_pkt;
        if (network_recv_all(client_fd, &client_kex_pkt, sizeof(client_kex_pkt)) != sizeof(client_kex_pkt)) {
            fprintf(stderr, "Error: Failed to receive client public key\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        uint32_t client_pubkey_len = ntohl(client_kex_pkt.pubkey_len);
        if (client_pubkey_len > sizeof(client_kex_pkt.pubkey)) {
            fprintf(stderr, "Error: Client public key too large\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        // 导入客户端公钥
        if (kex_import_peer_public_key(&ctx, client_kex_pkt.pubkey, client_pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to import client public key\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        printf("   ✓ Client public key imported\n");
        
        // 导出服务器公钥
        printf("3. Exporting server public key...\n");
        unsigned char server_pubkey[512];
        size_t server_pubkey_len = sizeof(server_pubkey);
        if (kex_export_public_key(&ctx, server_pubkey, &server_pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to export server public key\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        // 发送服务器公钥
        printf("4. Sending server public key to client...\n");
        kex_packet_t server_kex_pkt;
        memset(&server_kex_pkt, 0, sizeof(server_kex_pkt));
        server_kex_pkt.kex_type = kex_type;
        server_kex_pkt.pubkey_len = htonl(server_pubkey_len);
        if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
            fprintf(stderr, "Error: Server public key too large\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        memcpy(server_kex_pkt.pubkey, server_pubkey, server_pubkey_len);
        
        if (network_send_all(client_fd, &server_kex_pkt, sizeof(server_kex_pkt)) != 0) {
            fprintf(stderr, "Error: Failed to send server public key\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        
        // 派生共享密钥
        printf("5. Deriving shared secret...\n");
        if (kex_derive_shared_secret(&ctx) != 0) {
            fprintf(stderr, "Error: Failed to derive shared secret\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        printf("   ✓ Shared secret derived (%zu bytes)\n", ctx.shared_secret_len);
        
        // 派生对称密钥和IV
        printf("\n6. Deriving symmetric keys...\n");
        unsigned char key[32], iv[16];
        if (kex_derive_symmetric_key(&ctx, 32, 16, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to derive symmetric keys\n");
            kex_ctx_cleanup(&ctx);
            close(client_fd);
            continue;
        }
        printf("   ✓ Symmetric keys derived\n");
        
        kex_ctx_cleanup(&ctx);
        close(client_fd);
        
        printf("\n=== Key exchange completed successfully ===\n");
    }
    
    close(server_fd);
    return 0;
}

