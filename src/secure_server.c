#include "../include/secure_protocol.h"
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

static int load_public_key_file(const char *pubkey_file, sign_ctx_t *sign_ctx) {
    FILE *fp = fopen(pubkey_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open public key file: %s\n", pubkey_file);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char *pubkey_data = malloc(file_size + 1);
    if (!pubkey_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(pubkey_data, 1, file_size, fp);
    fclose(fp);
    pubkey_data[read_size] = '\0';

    if (sign_import_peer_public_key(sign_ctx, pubkey_data, read_size) != 0) {
        fprintf(stderr, "Error: Failed to import public key\n");
        free(pubkey_data);
        return -1;
    }

    free(pubkey_data);
    return 0;
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
    
    printf("=== Ready for secure communication ===\n\n");
    
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
        
        secure_session_t session;
        if (sp_session_init(&session, client_fd, kex_type, cipher_type, sign_type) != 0) {
            fprintf(stderr, "Error: Failed to initialize protocol session\n");
            close(client_fd);
            continue;
        }

        if (pubkey_file) {
            if (load_public_key_file(pubkey_file, &session.sign) != 0) {
                sp_session_cleanup(&session);
                close(client_fd);
                continue;
            }
        }

        if (use_key_exchange) {
            printf("1. Performing key exchange...\n");
            if (sp_server_handshake(&session) != 0) {
                fprintf(stderr, "Error: Handshake failed\n");
                sp_session_cleanup(&session);
                close(client_fd);
                continue;
            }
            printf("\n2. Ready to receive encrypted messages...\n");
        } else {
            if (cipher_ctx_init(&session.cipher, cipher_type, key, iv) != 0) {
                fprintf(stderr, "Error: Failed to initialize cipher context\n");
                sp_session_cleanup(&session);
                close(client_fd);
                continue;
            }
            session.is_handshake_done = 1;
            printf("\n2. Ready to receive encrypted messages (manual key mode)...\n");
        }

        while (running) {
            unsigned char *plaintext = NULL;
            size_t plaintext_len = 0;
            if (sp_server_recv_msg(&session, &plaintext, &plaintext_len) != 0) {
                free(plaintext);
                break;
            }

            printf("Received encrypted and signed message (%zu bytes):\n", plaintext_len);
            printf("  %.*s\n\n", (int)plaintext_len, plaintext);
            free(plaintext);
        }

        sp_session_cleanup(&session);
        close(client_fd);
        printf("Client disconnected\n");
    }
    
    close(server_fd);
    return 0;
}
