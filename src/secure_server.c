#include "../include/cipher.h"
#include "../include/sign.h"
#include "../include/kex.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <errno.h>

#define MAX_BUFFER_SIZE 65507
#define DEFAULT_PORT 8888
#define DEFAULT_SERVER_IP "0.0.0.0"
#define DEFAULT_BACKLOG 5

// 数据包类型
#define PKT_TYPE_KEY_EXCHANGE 0x01
#define PKT_TYPE_ENCRYPTED_SIGNED 0x04

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
    fprintf(stderr, "  -c <cipher>     Cipher algorithm (aes128gcm, aes256gcm, aes128cbc, aes256cbc, chacha20)\n");
    fprintf(stderr, "  -s <sign>       Signature algorithm (ecdsap256, ecdsap384)\n");
    fprintf(stderr, "  -x <kex>        Key exchange algorithm (ecdhp256, ecdhp384) - enables key exchange\n");
    fprintf(stderr, "  -k <key>        Encryption key (hex string, optional if -x is used)\n");
    fprintf(stderr, "  -v <iv>         Initialization vector (hex string, optional if -x is used)\n");
    fprintf(stderr, "  -K <pubkey>     Signature public key file (PEM format, optional if -x is used)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Note: Either use -x for key exchange OR use -k/-v for manual key/IV\n");
    fprintf(stderr, "      When using -x, -K is optional (signature key will be derived from KEX)\n");
}

int main(int argc, char *argv[]) {
    const char *server_ip = DEFAULT_SERVER_IP;
    int port = DEFAULT_PORT;
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    sign_type_t sign_type = SIGN_ECDSA_P256;
    kex_type_t kex_type = KEX_ECDH_P256;
    const char *key_hex = NULL;
    const char *iv_hex = NULL;
    const char *pubkey_file = NULL;
    int use_key_exchange = 0;
    
    // 解析命令行参数
    int opt;
    while ((opt = getopt(argc, argv, "hi:p:c:s:x:k:v:K:")) != -1) {
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
                pubkey_file = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 检查必需参数
    if (!use_key_exchange && !pubkey_file) {
        fprintf(stderr, "Error: -K (public key file) is required when not using key exchange\n");
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
    
    if (use_key_exchange && !pubkey_file) {
        printf("Note: Using key exchange mode - signature key will be derived from KEX session\n");
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=== Secure Communication Server (Decrypt & Verify Only) ===\n");
    printf("Listening on %s:%d\n", server_ip, port);
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
    
    // 初始化加密上下文（如果使用手动密钥）
    cipher_ctx_t *cipher_ctx_ptr = NULL;
    cipher_ctx_t cipher_ctx_static;
    if (!use_key_exchange) {
        if (cipher_ctx_init(&cipher_ctx_static, cipher_type, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to initialize cipher context\n");
            return 1;
        }
        cipher_ctx_ptr = &cipher_ctx_static;
    }
    
    // 初始化签名上下文并导入公钥
    sign_ctx_t sign_ctx;
    if (sign_ctx_init(&sign_ctx, sign_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize sign context\n");
        if (cipher_ctx_ptr) {
            cipher_ctx_cleanup(cipher_ctx_ptr);
        }
        return 1;
    }
    
    // 从文件读取公钥（如果提供了 -K 参数）
    // 如果使用密钥交换模式且未提供 -K，则跳过文件加载，将在密钥交换后自动设置
    if (pubkey_file) {
        FILE *fp = fopen(pubkey_file, "r");
        if (!fp) {
            fprintf(stderr, "Error: Failed to open public key file: %s\n", pubkey_file);
            sign_ctx_cleanup(&sign_ctx);
            if (cipher_ctx_ptr) {
                cipher_ctx_cleanup(cipher_ctx_ptr);
            }
            return 1;
        }
        
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        unsigned char *pubkey_data = malloc(file_size + 1);
        if (!pubkey_data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            fclose(fp);
            sign_ctx_cleanup(&sign_ctx);
            if (cipher_ctx_ptr) {
                cipher_ctx_cleanup(cipher_ctx_ptr);
            }
            return 1;
        }
        
        size_t read_size = fread(pubkey_data, 1, file_size, fp);
        fclose(fp);
        pubkey_data[read_size] = '\0';
        
        if (sign_import_peer_public_key(&sign_ctx, pubkey_data, read_size) != 0) {
            fprintf(stderr, "Error: Failed to import public key\n");
            free(pubkey_data);
            sign_ctx_cleanup(&sign_ctx);
            if (cipher_ctx_ptr) {
                cipher_ctx_cleanup(cipher_ctx_ptr);
            }
            return 1;
        }
        
        free(pubkey_data);
    }
    
    printf("=== Ready for secure communication ===\n\n");
    
    // 创建服务器socket
    int server_fd = network_create_tcp_server_socket(server_ip, port, DEFAULT_BACKLOG);
    if (server_fd < 0) {
        sign_ctx_cleanup(&sign_ctx);
        if (cipher_ctx_ptr) {
            cipher_ctx_cleanup(cipher_ctx_ptr);
        }
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
        
        // 如果使用密钥交换，先进行密钥交换
        cipher_ctx_t *current_cipher_ctx = cipher_ctx_ptr;
        cipher_ctx_t cipher_ctx_dynamic;
        
        if (use_key_exchange) {
            printf("1. Performing key exchange...\n");
            
            // 初始化密钥交换上下文
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
            
            // 接收客户端密钥交换请求
            uint8_t pkt_type;
            if (network_recv_all(client_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
                fprintf(stderr, "Error: Failed to receive packet type\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            if (pkt_type != PKT_TYPE_KEY_EXCHANGE) {
                fprintf(stderr, "Error: Expected key exchange packet, got 0x%02x\n", pkt_type);
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
            
            // 导出服务器公钥
            unsigned char server_pubkey[512];
            size_t server_pubkey_len = sizeof(server_pubkey);
            if (kex_export_public_key(&kex_ctx, server_pubkey, &server_pubkey_len) != 0) {
                fprintf(stderr, "Error: Failed to export server public key\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            // 发送服务器公钥
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
            
            // 派生共享密钥
            if (kex_derive_shared_secret(&kex_ctx) != 0) {
                fprintf(stderr, "Error: Failed to derive shared secret\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            // 派生对称密钥和IV
            int key_len = cipher_get_key_len(cipher_type);
            int iv_len = cipher_get_iv_len(cipher_type);
            unsigned char derived_key[32], derived_iv[16];
            if (kex_derive_symmetric_key(&kex_ctx, key_len, iv_len, derived_key, derived_iv) != 0) {
                fprintf(stderr, "Error: Failed to derive symmetric keys\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            printf("   ✓ Key exchange completed\n");
            
            /* ================= [新增代码 START] ================= */
            /* 关键修复：TC397 使用同一个随机密钥进行 KEX 和 签名。
             * 因此，我们需要将 KEX 阶段收到的公钥，复制给签名上下文，
             * 否则服务器加载的静态 -K 公钥无法验证 TC397 的动态签名。
             */
            if (sign_ctx.public_key) {
                EVP_PKEY_free(sign_ctx.public_key);
            }
            // 将 KEX 获得的对端公钥复制给 签名上下文
            sign_ctx.public_key = EVP_PKEY_dup(kex_ctx.peer_public_key);
            if (!sign_ctx.public_key) {
                fprintf(stderr, "Error: Failed to duplicate KEX public key for signature verification\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            printf("   ! Updated signature verification key from KEX session\n");
            /* ================= [新增代码 END] ==================== */
            
            // 初始化加密上下文
            if (cipher_ctx_init(&cipher_ctx_dynamic, cipher_type, derived_key, derived_iv) != 0) {
                fprintf(stderr, "Error: Failed to initialize cipher context\n");
                kex_ctx_cleanup(&kex_ctx);
                close(client_fd);
                continue;
            }
            
            current_cipher_ctx = &cipher_ctx_dynamic;
            kex_ctx_cleanup(&kex_ctx);
            printf("\n2. Ready to receive encrypted messages...\n");
        }
        
        // 通信循环
        unsigned char buffer[MAX_BUFFER_SIZE];
        while (running) {
            // 接收数据包类型
            uint8_t pkt_type;
            if (network_recv_all_timeout(client_fd, &pkt_type, sizeof(pkt_type), 5000) != sizeof(pkt_type)) {
                if (errno == ETIMEDOUT || errno == 0) {
                    continue;
                }
                printf("Client disconnected or error occurred\n");
                break;
            }
            
            if (pkt_type == PKT_TYPE_ENCRYPTED_SIGNED) {
                // 接收加密数据包头
                encrypted_packet_t enc_pkt;
                if (network_recv_all(client_fd, &enc_pkt.cipher_type, 
                            sizeof(enc_pkt) - offsetof(encrypted_packet_t, cipher_type)) != 
                    sizeof(enc_pkt) - offsetof(encrypted_packet_t, cipher_type)) {
                    printf("Error: Failed to receive encrypted packet header\n");
                    break;
                }
                
                uint32_t data_len = ntohl(enc_pkt.data_len);
                uint32_t iv_len = ntohl(enc_pkt.iv_len);
                uint32_t tag_len = ntohl(enc_pkt.tag_len);
                
                if (data_len > MAX_BUFFER_SIZE || iv_len > sizeof(enc_pkt.iv) || tag_len > sizeof(enc_pkt.tag)) {
                    printf("Error: Invalid packet size\n");
                    break;
                }
                
                // 接收加密数据
                unsigned char *encrypted_data = buffer;
                if (network_recv_all(client_fd, encrypted_data, data_len) != data_len) {
                    printf("Error: Failed to receive encrypted data\n");
                    break;
                }
                
                // 接收签名数据包头
                signed_packet_t sig_pkt;
                if (network_recv_all(client_fd, &sig_pkt.sign_type, sizeof(sig_pkt.sign_type)) != sizeof(sig_pkt.sign_type)) {
                    printf("Error: Failed to receive signature packet type\n");
                    break;
                }
                
                if (network_recv_all(client_fd, &sig_pkt.data_len, sizeof(sig_pkt.data_len)) != sizeof(sig_pkt.data_len)) {
                    printf("Error: Failed to receive signature data length\n");
                    break;
                }
                
                uint32_t sig_data_len = ntohl(sig_pkt.data_len);
                if (network_recv_all(client_fd, &sig_pkt.sig_len, sizeof(sig_pkt.sig_len)) != sizeof(sig_pkt.sig_len)) {
                    printf("Error: Failed to receive signature length\n");
                    break;
                }
                
                uint32_t sig_len = ntohl(sig_pkt.sig_len);
                if (sig_len > MAX_BUFFER_SIZE) {
                    printf("Error: Signature too large\n");
                    break;
                }
                
                // 接收签名数据（加密数据+标签）
                unsigned char *sig_data = buffer + MAX_BUFFER_SIZE / 2;
                if (network_recv_all(client_fd, sig_data, sig_data_len) != sig_data_len) {
                    printf("Error: Failed to receive signature data\n");
                    break;
                }
                
                unsigned char *signature = sig_data + sig_data_len;
                if (network_recv_all(client_fd, signature, sig_len) != sig_len) {
                    printf("Error: Failed to receive signature\n");
                    break;
                }
                
                // 验证签名
                if (verify_signature(&sign_ctx, sig_data, sig_data_len, signature, sig_len) != 0) {
                    printf("Error: Signature verification failed!\n");
                    break;
                }
                
                printf("Signature verified successfully!\n");
                
                // 更新IV（使用接收到的IV）
                memcpy(current_cipher_ctx->iv, enc_pkt.iv, iv_len);
                
                // 解密数据
                unsigned char *plaintext = buffer + MAX_BUFFER_SIZE / 2;
                size_t plaintext_len = MAX_BUFFER_SIZE / 2;
                if (cipher_decrypt(current_cipher_ctx, encrypted_data, data_len, enc_pkt.tag, plaintext, &plaintext_len) != 0) {
                    printf("Error: Decryption failed!\n");
                    break;
                }
                
                printf("Received encrypted and signed message (%zu bytes):\n", plaintext_len);
                printf("  %.*s\n", (int)plaintext_len, plaintext);
                printf("\n");
            }
        }
        
        // 清理动态分配的加密上下文
        if (use_key_exchange && current_cipher_ctx == &cipher_ctx_dynamic) {
            cipher_ctx_cleanup(&cipher_ctx_dynamic);
        }
        
        close(client_fd);
        printf("Client disconnected\n");
    }
    
    sign_ctx_cleanup(&sign_ctx);
    if (cipher_ctx_ptr) {
        cipher_ctx_cleanup(cipher_ctx_ptr);
    }
    close(server_fd);
    return 0;
}
