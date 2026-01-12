#include "../include/cipher.h"
#include "../include/sign.h"
#include "../include/kex.h"
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
#define PKT_TYPE_KEY_EXCHANGE 0x01
#define PKT_TYPE_ENCRYPTED_SIGNED 0x04

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [options]\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h              Show this help message\n");
    fprintf(stderr, "  -i <ip>         Server IP address (default: %s)\n", DEFAULT_CLIENT_IP);
    fprintf(stderr, "  -p <port>       Port number (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -c <cipher>     Cipher algorithm (aes128gcm, aes256gcm, aes128cbc, aes256cbc, chacha20)\n");
    fprintf(stderr, "  -s <sign>       Signature algorithm (ecdsap256, ecdsap384)\n");
    fprintf(stderr, "  -x <kex>        Key exchange algorithm (ecdhp256, ecdhp384) - enables key exchange\n");
    fprintf(stderr, "  -k <key>        Encryption key (hex string, optional if -x is used)\n");
    fprintf(stderr, "  -v <iv>         Initialization vector (hex string, optional if -x is used)\n");
    fprintf(stderr, "  -K <privkey>    Signature private key file (PEM format, required)\n");
    fprintf(stderr, "  -m <message>    Message to send\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Note: Either use -x for key exchange OR use -k/-v for manual key/IV\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_CLIENT_IP;
    int port = DEFAULT_PORT;
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    sign_type_t sign_type = SIGN_ECDSA_P256;
    kex_type_t kex_type = KEX_ECDH_P256;
    const char *key_hex = NULL;
    const char *iv_hex = NULL;
    const char *privkey_file = NULL;
    const char *message = "Hello from secure client!";
    int use_key_exchange = 0;
    
    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:c:s:x:k:v:K:m:")) != -1) {
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
            case 'x':
                use_key_exchange = 1;
                if (strcmp(optarg, "ecdhp256") == 0) {
                    kex_type = KEX_ECDH_P256;
                } else if (strcmp(optarg, "ecdhp384") == 0) {
                    kex_type = KEX_ECDH_P384;
                } else {
                    fprintf(stderr, "Unknown key exchange: %s\n", optarg);
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
    if (!privkey_file) {
        fprintf(stderr, "Error: -K (private key file) is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!use_key_exchange && (!key_hex || !iv_hex)) {
        fprintf(stderr, "Error: Either use -x for key exchange OR provide -k (key) and -v (iv)\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (use_key_exchange && (key_hex || iv_hex)) {
        fprintf(stderr, "Warning: -x (key exchange) is specified, ignoring -k and -v options\n");
    }
    
    printf("=== Secure Communication Client (Encrypt & Sign Only) ===\n");
    printf("Connecting to %s:%d\n", server_ip, port);
    printf("Cipher: %s\n", cipher_type_to_string(cipher_type));
    printf("Signature: %s\n", sign_type_to_string(sign_type));
    if (use_key_exchange) {
        printf("Key Exchange: %s (enabled)\n", kex_type_to_string(kex_type));
    } else {
        printf("Key Exchange: Disabled (using manual keys)\n");
    }
    printf("\n");
    
    // 如果使用手动密钥，解析密钥和IV
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    
    if (!use_key_exchange) {
        int key_len = cipher_get_key_len(cipher_type);
        int iv_len = cipher_get_iv_len(cipher_type);
        
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
    }
    
    // 初始化签名上下文并导入私钥
    sign_ctx_t sign_ctx;
    if (sign_ctx_init(&sign_ctx, sign_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize sign context\n");
        return 1;
    }
    
    // 从文件读取私钥
    FILE *fp = fopen(privkey_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open private key file: %s\n", privkey_file);
        sign_ctx_cleanup(&sign_ctx);
        return 1;
    }
    
    EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!privkey) {
        fprintf(stderr, "Error: Failed to read private key\n");
        sign_ctx_cleanup(&sign_ctx);
        return 1;
    }
    
    sign_ctx.private_key = privkey;
    
    // 连接到服务器
    int sockfd = network_create_tcp_client_socket(server_ip, port);
    if (sockfd < 0) {
        sign_ctx_cleanup(&sign_ctx);
        return 1;
    }
    
    printf("Connected to server\n");
    
    // 如果使用密钥交换，先进行密钥交换
    cipher_ctx_t cipher_ctx;
    
    if (use_key_exchange) {
        printf("1. Performing key exchange...\n");
        
        // 初始化密钥交换上下文
        kex_ctx_t kex_ctx;
        if (kex_ctx_init(&kex_ctx, kex_type) != 0) {
            fprintf(stderr, "Error: Failed to initialize key exchange\n");
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        if (kex_generate_keypair(&kex_ctx) != 0) {
            fprintf(stderr, "Error: Failed to generate key pair\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        // 导出公钥
        unsigned char pubkey[512];
        size_t pubkey_len = sizeof(pubkey);
        if (kex_export_public_key(&kex_ctx, pubkey, &pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to export public key\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        // 发送密钥交换数据包
        uint8_t pkt_type = PKT_TYPE_KEY_EXCHANGE;
        if (network_send_all(sockfd, &pkt_type, sizeof(pkt_type)) != 0) {
            fprintf(stderr, "Error: Failed to send packet type\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
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
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        memcpy(kex_pkt.pubkey, pubkey, pubkey_len);
        
        if (network_send_all(sockfd, &kex_pkt, sizeof(kex_pkt)) != 0) {
            fprintf(stderr, "Error: Failed to send public key\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        // 接收服务器公钥
        kex_packet_t server_kex_pkt;
        if (network_recv_all(sockfd, &server_kex_pkt, sizeof(server_kex_pkt)) != sizeof(server_kex_pkt)) {
            fprintf(stderr, "Error: Failed to receive server public key\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        uint32_t server_pubkey_len = ntohl(server_kex_pkt.pubkey_len);
        if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
            fprintf(stderr, "Error: Server public key too large\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        if (kex_import_peer_public_key(&kex_ctx, server_kex_pkt.pubkey, server_pubkey_len) != 0) {
            fprintf(stderr, "Error: Failed to import server public key\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        if (kex_derive_shared_secret(&kex_ctx) != 0) {
            fprintf(stderr, "Error: Failed to derive shared secret\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        // 派生对称密钥和IV
        int key_len = cipher_get_key_len(cipher_type);
        int iv_len = cipher_get_iv_len(cipher_type);
        unsigned char derived_key[32], derived_iv[16];
        if (kex_derive_symmetric_key(&kex_ctx, key_len, iv_len, derived_key, derived_iv) != 0) {
            fprintf(stderr, "Error: Failed to derive symmetric keys\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        printf("   ✓ Key exchange completed\n");
        
        // 初始化加密上下文
        if (cipher_ctx_init(&cipher_ctx, cipher_type, derived_key, derived_iv) != 0) {
            fprintf(stderr, "Error: Failed to initialize cipher context\n");
            kex_ctx_cleanup(&kex_ctx);
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
        
        kex_ctx_cleanup(&kex_ctx);
        printf("\n2. Encrypting and sending message...\n");
    } else {
        // 初始化加密上下文（使用手动密钥）
        if (cipher_ctx_init(&cipher_ctx, cipher_type, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to initialize cipher context\n");
            sign_ctx_cleanup(&sign_ctx);
            close(sockfd);
            return 1;
        }
    }
    
    printf("   Message: %s\n", message);
    
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
