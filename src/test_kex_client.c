#include "../include/kex.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 8888
#define DEFAULT_CLIENT_IP "192.168.1.100"

static void print_hex(const unsigned char *data, size_t len, const char *label) {
    if (label) {
        printf("%s: ", label);
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h              Show this help message\n");
    fprintf(stderr, "  -i <ip>         Server IP address (default: %s)\n", DEFAULT_CLIENT_IP);
    fprintf(stderr, "  -p <port>       Port number (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -k <kex>        Key exchange algorithm (ecdhp256, ecdhp384, default: ecdhp256)\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_CLIENT_IP;
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
    
    printf("=== Key Exchange Test Client ===\n");
    printf("Connecting to %s:%d\n", server_ip, port);
    printf("Algorithm: %s\n\n", kex_type_to_string(kex_type));
    
    // 初始化密钥交换上下文
    kex_ctx_t ctx;
    if (kex_ctx_init(&ctx, kex_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize key exchange\n");
        return 1;
    }
    
    // 生成密钥对
    printf("1. Generating key pair...\n");
    if (kex_generate_keypair(&ctx) != 0) {
        fprintf(stderr, "Error: Failed to generate key pair\n");
        kex_ctx_cleanup(&ctx);
        return 1;
    }
    printf("   ✓ Key pair generated\n");
    
    // 导出公钥
    unsigned char pubkey[512];
    size_t pubkey_len = sizeof(pubkey);
    if (kex_export_public_key(&ctx, pubkey, &pubkey_len) != 0) {
        fprintf(stderr, "Error: Failed to export public key\n");
        kex_ctx_cleanup(&ctx);
        return 1;
    }
    printf("2. Public key exported (%zu bytes)\n", pubkey_len);
    
    // 连接到服务器
    int sockfd = network_create_tcp_client_socket(server_ip, port);
    if (sockfd < 0) {
        kex_ctx_cleanup(&ctx);
        return 1;
    }
    
    printf("3. Connected to server\n");
    
    // 发送数据包类型（密钥交换）
    uint8_t pkt_type = 0x01;  // PKT_TYPE_KEY_EXCHANGE
    if (network_send_all(sockfd, &pkt_type, sizeof(pkt_type)) != 0) {
        fprintf(stderr, "Error: Failed to send packet type\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    
    // 发送公钥
    kex_packet_t kex_pkt;
    memset(&kex_pkt, 0, sizeof(kex_pkt));
    kex_pkt.kex_type = kex_type;
    kex_pkt.pubkey_len = htonl(pubkey_len);
    if (pubkey_len > sizeof(kex_pkt.pubkey)) {
        fprintf(stderr, "Error: Public key too large\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    memcpy(kex_pkt.pubkey, pubkey, pubkey_len);
    
    printf("4. Sending public key to server...\n");
    if (network_send_all(sockfd, &kex_pkt, sizeof(kex_pkt)) != 0) {
        fprintf(stderr, "Error: Failed to send public key\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    
    // 接收服务器公钥
    printf("5. Receiving server public key...\n");
    kex_packet_t server_kex_pkt;
    if (network_recv_all(sockfd, &server_kex_pkt, sizeof(server_kex_pkt)) != sizeof(server_kex_pkt)) {
        fprintf(stderr, "Error: Failed to receive server public key\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    
    uint32_t server_pubkey_len = ntohl(server_kex_pkt.pubkey_len);
    if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
        fprintf(stderr, "Error: Server public key too large\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    
    // 导入服务器公钥
    if (kex_import_peer_public_key(&ctx, server_kex_pkt.pubkey, server_pubkey_len) != 0) {
        fprintf(stderr, "Error: Failed to import server public key\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    printf("   ✓ Server public key imported\n");
    
    // 派生共享密钥
    printf("6. Deriving shared secret...\n");
    if (kex_derive_shared_secret(&ctx) != 0) {
        fprintf(stderr, "Error: Failed to derive shared secret\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    printf("   ✓ Shared secret derived (%zu bytes)\n", ctx.shared_secret_len);
    print_hex(ctx.shared_secret, ctx.shared_secret_len, "   Shared secret");
    
    // 派生对称密钥和IV
    printf("\n7. Deriving symmetric keys...\n");
    unsigned char key[32], iv[16];
    if (kex_derive_symmetric_key(&ctx, 32, 16, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to derive symmetric keys\n");
        kex_ctx_cleanup(&ctx);
        close(sockfd);
        return 1;
    }
    print_hex(key, 32, "   Derived key (32 bytes)");
    print_hex(iv, 16, "   Derived IV (16 bytes)");
    
    kex_ctx_cleanup(&ctx);
    close(sockfd);
    
    printf("\n=== Key exchange completed successfully ===\n");
    return 0;
}

