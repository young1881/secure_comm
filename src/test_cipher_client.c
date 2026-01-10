#include "../include/kex.h"
#include "../include/cipher.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <openssl/rand.h>

#define DEFAULT_PORT 8888
#define DEFAULT_CLIENT_IP "192.168.1.100"
#define PKT_TYPE_KEY_EXCHANGE 0x01
#define PKT_TYPE_ENCRYPTED_DATA 0x02

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h              Show this help message\n");
    fprintf(stderr, "  -i <ip>         Server IP address (default: %s)\n", DEFAULT_CLIENT_IP);
    fprintf(stderr, "  -p <port>       Port number (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -k <kex>        Key exchange algorithm (ecdhp256, ecdhp384, default: ecdhp256)\n");
    fprintf(stderr, "  -c <cipher>     Cipher algorithm (aes128gcm, aes256gcm, aes128cbc, aes256cbc, chacha20, default: aes256gcm)\n");
    fprintf(stderr, "  -m <message>    Message to encrypt and send\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_CLIENT_IP;
    int port = DEFAULT_PORT;
    kex_type_t kex_type = KEX_ECDH_P256;
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    const char *message = "Hello from cipher test client!";
    
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:k:c:m:")) != -1) {
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
            case 'm':
                message = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("=== Key Exchange + Cipher Test Client ===\n");
    printf("Connecting to %s:%d\n", server_ip, port);
    printf("Key Exchange: %s\n", kex_type_to_string(kex_type));
    printf("Cipher: %s\n\n", cipher_type_to_string(cipher_type));
    
    // 第一步：密钥交换
    kex_ctx_t kex_ctx;
    if (kex_ctx_init(&kex_ctx, kex_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize key exchange\n");
        return 1;
    }
    
    if (kex_generate_keypair(&kex_ctx) != 0) {
        fprintf(stderr, "Error: Failed to generate key pair\n");
        kex_ctx_cleanup(&kex_ctx);
        return 1;
    }
    
    unsigned char pubkey[512];
    size_t pubkey_len = sizeof(pubkey);
    if (kex_export_public_key(&kex_ctx, pubkey, &pubkey_len) != 0) {
        fprintf(stderr, "Error: Failed to export public key\n");
        kex_ctx_cleanup(&kex_ctx);
        return 1;
    }
    
    int sockfd = network_create_tcp_client_socket(server_ip, port);
    if (sockfd < 0) {
        kex_ctx_cleanup(&kex_ctx);
        return 1;
    }
    
    printf("1. Performing key exchange...\n");
    
    // 发送密钥交换数据包
    uint8_t pkt_type = PKT_TYPE_KEY_EXCHANGE;
    if (network_send_all(sockfd, &pkt_type, sizeof(pkt_type)) != 0) {
        fprintf(stderr, "Error: Failed to send packet type\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    kex_packet_t kex_pkt;
    memset(&kex_pkt, 0, sizeof(kex_pkt));
    kex_pkt.kex_type = kex_type;
    kex_pkt.pubkey_len = htonl(pubkey_len);
    if (pubkey_len > sizeof(kex_pkt.pubkey)) {
        fprintf(stderr, "Error: Public key too large\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    memcpy(kex_pkt.pubkey, pubkey, pubkey_len);
    
    if (network_send_all(sockfd, &kex_pkt, sizeof(kex_pkt)) != 0) {
        fprintf(stderr, "Error: Failed to send public key\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    // 接收服务器公钥
    kex_packet_t server_kex_pkt;
    if (network_recv_all(sockfd, &server_kex_pkt, sizeof(server_kex_pkt)) != sizeof(server_kex_pkt)) {
        fprintf(stderr, "Error: Failed to receive server public key\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    uint32_t server_pubkey_len = ntohl(server_kex_pkt.pubkey_len);
    if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
        fprintf(stderr, "Error: Server public key too large\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    if (kex_import_peer_public_key(&kex_ctx, server_kex_pkt.pubkey, server_pubkey_len) != 0) {
        fprintf(stderr, "Error: Failed to import server public key\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    if (kex_derive_shared_secret(&kex_ctx) != 0) {
        fprintf(stderr, "Error: Failed to derive shared secret\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    // 派生对称密钥和IV
    int key_len = cipher_get_key_len(cipher_type);
    int iv_len = cipher_get_iv_len(cipher_type);
    unsigned char key[32], iv[16];
    if (kex_derive_symmetric_key(&kex_ctx, key_len, iv_len, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to derive symmetric keys\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    printf("   ✓ Key exchange completed\n");
    
    // 第二步：加密和发送
    printf("\n2. Encrypting and sending message...\n");
    printf("   Message: %s\n", message);
    
    cipher_ctx_t cipher_ctx;
    if (cipher_ctx_init(&cipher_ctx, cipher_type, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to initialize cipher context\n");
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    // 生成新的IV用于加密
    if (RAND_bytes(cipher_ctx.iv, cipher_ctx.iv_len) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    size_t message_len = strlen(message);
    unsigned char buffer[4096];
    unsigned char *encrypted_data = buffer;
    size_t encrypted_len = sizeof(buffer) / 2;
    unsigned char tag[16];
    
    if (cipher_encrypt(&cipher_ctx, (unsigned char *)message, message_len,
                      encrypted_data, &encrypted_len, tag) != 0) {
        fprintf(stderr, "Error: Failed to encrypt message\n");
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    // 发送加密数据包
    pkt_type = PKT_TYPE_ENCRYPTED_DATA;
    if (network_send_all(sockfd, &pkt_type, sizeof(pkt_type)) != 0) {
        fprintf(stderr, "Error: Failed to send packet type\n");
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    encrypted_packet_t enc_pkt;
    enc_pkt.cipher_type = cipher_type;
    enc_pkt.data_len = htonl(encrypted_len);
    enc_pkt.iv_len = htonl(cipher_ctx.iv_len);
    enc_pkt.tag_len = htonl(cipher_ctx.tag_len);
    memcpy(enc_pkt.iv, cipher_ctx.iv, cipher_ctx.iv_len);
    memcpy(enc_pkt.tag, tag, cipher_ctx.tag_len);
    
    if (network_send_all(sockfd, &enc_pkt, sizeof(enc_pkt)) != 0) {
        fprintf(stderr, "Error: Failed to send encrypted packet header\n");
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, encrypted_data, encrypted_len) != 0) {
        fprintf(stderr, "Error: Failed to send encrypted data\n");
        cipher_ctx_cleanup(&cipher_ctx);
        kex_ctx_cleanup(&kex_ctx);
        close(sockfd);
        return 1;
    }
    
    printf("   ✓ Message encrypted and sent\n");
    
    cipher_ctx_cleanup(&cipher_ctx);
    kex_ctx_cleanup(&kex_ctx);
    close(sockfd);
    
    printf("\n=== Test completed successfully ===\n");
    return 0;
}

