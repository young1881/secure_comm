#include "../include/cipher.h"
#include "../include/sign.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <stddef.h>

#define MAX_BUFFER_SIZE 65507
#define DEFAULT_PORT 8888
#define DEFAULT_CLIENT_IP "192.168.1.100"

// 数据包类型
#define PKT_TYPE_ENCRYPTED_SIGNED 0x04

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h              Show this help message\n");
    fprintf(stderr, "  -i <ip>         Server IP address (default: %s)\n", DEFAULT_CLIENT_IP);
    fprintf(stderr, "  -p <port>       Port number (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -c <cipher>     Cipher algorithm (aes128gcm, aes256gcm, aes128cbc, aes256cbc, chacha20)\n");
    fprintf(stderr, "  -s <sign>       Signature algorithm (ecdsap256, ecdsap384)\n");
    fprintf(stderr, "  -k <key>        Encryption key (hex string, 32 bytes for AES-256, 16 bytes for AES-128)\n");
    fprintf(stderr, "  -v <iv>         Initialization vector (hex string, 12-16 bytes)\n");
    fprintf(stderr, "  -K <privkey>    Signature private key file (PEM format)\n");
    fprintf(stderr, "  -m <message>    Message to send\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_CLIENT_IP;
    int port = DEFAULT_PORT;
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    sign_type_t sign_type = SIGN_ECDSA_P256;
    const char *key_hex = NULL;
    const char *iv_hex = NULL;
    const char *privkey_file = NULL;
    const char *message = "Hello from secure client!";
    
    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:c:s:k:v:K:m:")) != -1) {
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
            case 's':
                if (strcmp(optarg, "ecdsap256") == 0) {
                    sign_type = SIGN_ECDSA_P256;
                } else if (strcmp(optarg, "ecdsap384") == 0) {
                    sign_type = SIGN_ECDSA_P384;
                } else {
                    fprintf(stderr, "Unknown signature: %s\n", optarg);
                    return 1;
                }
                break;
            case 'k':
                key_hex = optarg;
                break;
            case 'v':
                iv_hex = optarg;
                break;
            case 'K':
                privkey_file = optarg;
                break;
            case 'm':
                message = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 检查必需参数
    if (!key_hex || !iv_hex || !privkey_file) {
        fprintf(stderr, "Error: -k (key), -v (iv), and -K (private key file) are required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    printf("=== Secure Communication Client (Encrypt & Sign Only) ===\n");
    printf("Connecting to %s:%d\n", server_ip, port);
    printf("Cipher: %s\n", cipher_type_to_string(cipher_type));
    printf("Signature: %s\n", sign_type_to_string(sign_type));
    printf("\n");
    
    // 解析密钥和IV
    int key_len = cipher_get_key_len(cipher_type);
    int iv_len = cipher_get_iv_len(cipher_type);
    
    unsigned char key[32];
    unsigned char iv[16];
    
    // 从十六进制字符串解析密钥
    if (strlen(key_hex) != key_len * 2) {
        fprintf(stderr, "Error: Key length mismatch. Expected %d hex characters\n", key_len * 2);
        return 1;
    }
    for (int i = 0; i < key_len; i++) {
        if (sscanf(key_hex + i * 2, "%2hhx", &key[i]) != 1) {
            fprintf(stderr, "Error: Invalid key hex string\n");
            return 1;
        }
    }
    
    // 从十六进制字符串解析IV
    if (strlen(iv_hex) != iv_len * 2) {
        fprintf(stderr, "Error: IV length mismatch. Expected %d hex characters\n", iv_len * 2);
        return 1;
    }
    for (int i = 0; i < iv_len; i++) {
        if (sscanf(iv_hex + i * 2, "%2hhx", &iv[i]) != 1) {
            fprintf(stderr, "Error: Invalid IV hex string\n");
            return 1;
        }
    }
    
    // 初始化加密上下文
    cipher_ctx_t cipher_ctx;
    if (cipher_ctx_init(&cipher_ctx, cipher_type, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to initialize cipher context\n");
        return 1;
    }
    
    // 初始化签名上下文并导入私钥
    sign_ctx_t sign_ctx;
    if (sign_ctx_init(&sign_ctx, sign_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize sign context\n");
        cipher_ctx_cleanup(&cipher_ctx);
        return 1;
    }
    
    // 从文件读取私钥
    FILE *fp = fopen(privkey_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open private key file: %s\n", privkey_file);
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        return 1;
    }
    
    EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!privkey) {
        fprintf(stderr, "Error: Failed to read private key\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        return 1;
    }
    
    sign_ctx.private_key = privkey;
    
    // 连接到服务器
    int sockfd = network_create_tcp_client_socket(server_ip, port);
    if (sockfd < 0) {
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        return 1;
    }
    
    printf("Connected to server\n");
    printf("Sending message: %s\n", message);
    
    // 生成新的IV（每次加密使用新的IV）
    if (RAND_bytes(cipher_ctx.iv, cipher_ctx.iv_len) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    // 加密消息
    size_t message_len = strlen(message);
    unsigned char buffer[MAX_BUFFER_SIZE];
    unsigned char *encrypted_data = buffer;
    size_t encrypted_len = MAX_BUFFER_SIZE / 2;
    unsigned char tag[16];
    
    if (cipher_encrypt(&cipher_ctx, (unsigned char *)message, message_len,
                      encrypted_data, &encrypted_len, tag) != 0) {
        fprintf(stderr, "Error: Failed to encrypt message\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    // 签名（对加密数据+标签签名）
    unsigned char sig_buffer[MAX_BUFFER_SIZE / 2];
    memcpy(sig_buffer, encrypted_data, encrypted_len);
    memcpy(sig_buffer + encrypted_len, tag, cipher_ctx.tag_len);
    
    unsigned char signature[256];
    size_t sig_len = sizeof(signature);
    if (sign_data(&sign_ctx, sig_buffer, encrypted_len + cipher_ctx.tag_len,
                 signature, &sig_len) != 0) {
        fprintf(stderr, "Error: Failed to sign message\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    // 发送数据包类型
    uint8_t pkt_type = PKT_TYPE_ENCRYPTED_SIGNED;
    if (network_send_all(sockfd, &pkt_type, sizeof(pkt_type)) != 0) {
        fprintf(stderr, "Error: Failed to send packet type\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    // 发送加密数据包
    encrypted_packet_t enc_pkt;
    enc_pkt.cipher_type = cipher_type;
    enc_pkt.data_len = htonl(encrypted_len);
    enc_pkt.iv_len = htonl(cipher_ctx.iv_len);
    enc_pkt.tag_len = htonl(cipher_ctx.tag_len);
    memcpy(enc_pkt.iv, cipher_ctx.iv, cipher_ctx.iv_len);
    memcpy(enc_pkt.tag, tag, cipher_ctx.tag_len);
    
    if (network_send_all(sockfd, &enc_pkt, sizeof(enc_pkt)) != 0) {
        fprintf(stderr, "Error: Failed to send encrypted packet header\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, encrypted_data, encrypted_len) != 0) {
        fprintf(stderr, "Error: Failed to send encrypted data\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    // 发送签名数据包
    signed_packet_t sig_pkt;
    sig_pkt.sign_type = sign_type;
    sig_pkt.data_len = htonl(encrypted_len + cipher_ctx.tag_len);
    sig_pkt.sig_len = htonl(sig_len);
    
    if (network_send_all(sockfd, &sig_pkt.sign_type, sizeof(sig_pkt.sign_type)) != 0) {
        fprintf(stderr, "Error: Failed to send signature packet type\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, &sig_pkt.data_len, sizeof(sig_pkt.data_len)) != 0) {
        fprintf(stderr, "Error: Failed to send signature data length\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, &sig_pkt.sig_len, sizeof(sig_pkt.sig_len)) != 0) {
        fprintf(stderr, "Error: Failed to send signature length\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, sig_buffer, encrypted_len + cipher_ctx.tag_len) != 0) {
        fprintf(stderr, "Error: Failed to send signature data\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    if (network_send_all(sockfd, signature, sig_len) != 0) {
        fprintf(stderr, "Error: Failed to send signature\n");
        sign_ctx_cleanup(&sign_ctx);
        cipher_ctx_cleanup(&cipher_ctx);
        close(sockfd);
        return 1;
    }
    
    printf("Message sent (encrypted and signed)\n");
    
    // 清理资源
    sign_ctx_cleanup(&sign_ctx);
    cipher_ctx_cleanup(&cipher_ctx);
    close(sockfd);
    
    printf("\n=== Communication completed ===\n");
    return 0;
}
