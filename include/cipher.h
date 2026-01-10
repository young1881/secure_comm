#ifndef CIPHER_H
#define CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

// 加密算法类型
typedef enum {
    CIPHER_AES_128_GCM = 0x01,
    CIPHER_AES_256_GCM = 0x02,
    CIPHER_AES_128_CBC = 0x03,
    CIPHER_AES_256_CBC = 0x04,
    CIPHER_CHACHA20_POLY1305 = 0x05
} cipher_type_t;

// 加密上下文结构
typedef struct {
    cipher_type_t cipher_type;
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    unsigned char *key;           // 对称密钥
    unsigned char *iv;            // 初始化向量
    int key_len;                  // 密钥长度
    int iv_len;                   // IV长度
    int tag_len;                  // GCM标签长度
} cipher_ctx_t;

// 加密数据包结构（GCM模式）
typedef struct {
    uint8_t cipher_type;          // 加密算法类型
    uint32_t data_len;            // 数据长度（网络字节序）
    uint32_t iv_len;              // IV长度（网络字节序）
    uint32_t tag_len;             // 标签长度（网络字节序）
    uint8_t iv[16];              // 初始化向量
    uint8_t tag[16];             // 认证标签
    uint8_t data[0];             // 加密数据
} __attribute__((packed)) encrypted_packet_t;

// 函数声明

// 初始化/清理
int cipher_ctx_init(cipher_ctx_t *ctx, cipher_type_t type, const unsigned char *key, const unsigned char *iv);
int cipher_ctx_cleanup(cipher_ctx_t *ctx);

// 加密/解密
int cipher_encrypt(cipher_ctx_t *ctx, const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char *ciphertext, size_t *ciphertext_len, unsigned char *tag);
int cipher_decrypt(cipher_ctx_t *ctx, const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *tag, unsigned char *plaintext, size_t *plaintext_len);

// 工具函数
const char* cipher_type_to_string(cipher_type_t type);
const EVP_CIPHER* cipher_get_evp_cipher(cipher_type_t type);
int cipher_get_key_len(cipher_type_t type);
int cipher_get_iv_len(cipher_type_t type);
int cipher_get_tag_len(cipher_type_t type);

#endif // CIPHER_H

