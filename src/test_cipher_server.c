#include "../include/kex.h"
#include "../include/cipher.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>

#define DEFAULT_PORT 8888
#define DEFAULT_SERVER_IP "0.0.0.0"
#define DEFAULT_BACKLOG 5
#define MAX_BUFFER_SIZE 65507
#define PKT_TYPE_KEY_EXCHANGE 0x01
#define PKT_TYPE_ENCRYPTED_DATA 0x02

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
    fprintf(stderr, "  -c <cipher>     Cipher algorithm (aes128gcm, aes256gcm, aes128cbc, aes256cbc, chacha20, default: aes256gcm)\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_SERVER_IP;
    int port = DEFAULT_PORT;
    kex_type_t kex_type = KEX_ECDH_P256;
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:k:c:")) != -1) {
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
            case 'c':
                if (strcmp(optarg, "aes128gcm") == 0) {
                    cipher_type = CIPHER_AES_128_GCM;
                } else if (strcmp(optarg, "aes256gcm") == 0) {
                    cipher_type = CIPHER_AES_256_GCM;
                } else if (strcmp(optarg, "aes128cbc") == 0) {
                    cipher_type = CIPHER_AES_128_CBC;
                } else if (strcmp(optarg, "aes256cbc") == 0) {
                    cipher_type = CIPHER_AES_256_CBC;
                } else if (strcmp(optarg, "chacha20") == 0) {
                    cipher_type = CIPHER_CHACHA20_POLY1305;
                } else {
                    fprintf(stderr, "Unknown cipher: %s\n", optarg);
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
    
    printf("=== Key Exchange + Cipher Test Server ===\n");
    printf("Listening on %s:%d\n", server_ip, port);
    printf("Key Exchange: %s\n", kex_type_to_string(kex_type));
    printf("Cipher: %s\n\n", cipher_type_to_string(cipher_type));
    
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
        
        // 第一步：密钥交换
        kex_ctx_t kex_ctx;
        if (kex_ctx_init(&kex_ctx, kex_type) != 0) {
            fprintf(stderr, "Error: Failed to initialize key exchange\n");
            close(client_fd);
            continue;
        }
        
        if (kex_generate_keypair(&kex_ctx) != 0) {
            fprintf(stderr, "Error: Failed to generate key pair\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        printf("1. Performing key exchange...\n");
        
        // 接收客户端密钥交换请求
        uint8_t pkt_type;
        if (network_recv_all(client_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
            fprintf(stderr, "Error: Failed to receive packet type\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        if (pkt_type != PKT_TYPE_KEY_EXCHANGE) {
            fprintf(stderr, "Error: Unexpected packet type\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        kex_packet_t client_kex_pkt;
        if (network_recv_all(client_fd, &client_kex_pkt, sizeof(client_kex_pkt)) != sizeof(client_kex_pkt)) {
            fprintf(stderr, "Error: Failed to receive client public key\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        uint32_t client_pubkey_len = ntohl(client_kex_pkt.pubkey_len);
        if (client_pubkey_len > sizeof(client_kex_pkt.pubkey)) {
            fprintf(stderr, "Error: Client public key too large\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        if (kex_import_peer_public_key(&kex_ctx, client_kex_pkt.pubkey, client_pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to import client public key\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        unsigned char server_pubkey[512];
        size_t server_pubkey_len = sizeof(server_pubkey);
        if (kex_export_public_key(&kex_ctx, server_pubkey, &server_pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to export server public key\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        kex_packet_t server_kex_pkt;
        memset(&server_kex_pkt, 0, sizeof(server_kex_pkt));
        server_kex_pkt.kex_type = kex_type;
        server_kex_pkt.pubkey_len = htonl(server_pubkey_len);
        if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
            fprintf(stderr, "Error: Server public key too large\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        memcpy(server_kex_pkt.pubkey, server_pubkey, server_pubkey_len);
        
        if (network_send_all(client_fd, &server_kex_pkt, sizeof(server_kex_pkt)) != 0) {
            fprintf(stderr, "Error: Failed to send server public key\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        if (kex_derive_shared_secret(&kex_ctx) != 0) {
            fprintf(stderr, "Error: Failed to derive shared secret\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        int key_len = cipher_get_key_len(cipher_type);
        int iv_len = cipher_get_iv_len(cipher_type);
        unsigned char key[32], iv[16];
        if (kex_derive_symmetric_key(&kex_ctx, key_len, iv_len, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to derive symmetric keys\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        printf("   ✓ Key exchange completed\n");
        
        // 第二步：接收并解密
        printf("\n2. Waiting for encrypted message...\n");
        
        if (network_recv_all(client_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
            fprintf(stderr, "Error: Failed to receive packet type\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        if (pkt_type != PKT_TYPE_ENCRYPTED_DATA) {
            fprintf(stderr, "Error: Unexpected packet type: 0x%02x\n", pkt_type);
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        encrypted_packet_t enc_pkt;
        if (network_recv_all(client_fd, &enc_pkt.cipher_type, 
                    sizeof(enc_pkt) - offsetof(encrypted_packet_t, cipher_type)) != 
            sizeof(enc_pkt) - offsetof(encrypted_packet_t, cipher_type)) {
            fprintf(stderr, "Error: Failed to receive encrypted packet header\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        uint32_t data_len = ntohl(enc_pkt.data_len);
        uint32_t enc_iv_len = ntohl(enc_pkt.iv_len);
        uint32_t tag_len = ntohl(enc_pkt.tag_len);
        
        if (data_len > MAX_BUFFER_SIZE || enc_iv_len > sizeof(enc_pkt.iv) || tag_len > sizeof(enc_pkt.tag)) {
            fprintf(stderr, "Error: Invalid packet size\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        unsigned char buffer[MAX_BUFFER_SIZE];
        unsigned char *encrypted_data = buffer;
        if (network_recv_all(client_fd, encrypted_data, data_len) != data_len) {
            fprintf(stderr, "Error: Failed to receive encrypted data\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        cipher_ctx_t cipher_ctx;
        if (cipher_ctx_init(&cipher_ctx, cipher_type, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to initialize cipher context\n");
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        // 使用接收到的IV
        memcpy(cipher_ctx.iv, enc_pkt.iv, enc_iv_len);
        
        unsigned char *plaintext = buffer + MAX_BUFFER_SIZE / 2;
        size_t plaintext_len = MAX_BUFFER_SIZE / 2;
        if (cipher_decrypt(&cipher_ctx, encrypted_data, data_len, enc_pkt.tag, plaintext, &plaintext_len) != 0) {
            fprintf(stderr, "Error: Decryption failed!\n");
            cipher_ctx_cleanup(&cipher_ctx);
            kex_ctx_cleanup(&kex_ctx);
            close(client_fd);
            continue;
        }
        
        printf("   ✓ Message decrypted successfully\n");
        printf("   Decrypted message (%zu bytes): %.*s\n", plaintext_len, (int)plaintext_len, plaintext);
        
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(client_fd);
        
        printf("\n=== Test completed successfully ===\n");
    }
    
    close(server_fd);
    return 0;
}

