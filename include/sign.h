#ifndef SIGN_H
#define SIGN_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

// 签名算法类型
typedef enum {
    SIGN_ECDSA_P256 = 0x01,
    SIGN_ECDSA_P384 = 0x02
} sign_type_t;

// 签名上下文结构
typedef struct {
    sign_type_t sign_type;
    EVP_PKEY *private_key;        // 私钥（用于签名）
    EVP_PKEY *public_key;         // 公钥（用于验签）
    EVP_MD_CTX *sign_ctx;
    EVP_MD_CTX *verify_ctx;
} sign_ctx_t;

// 签名数据包结构
typedef struct {
    uint8_t sign_type;            // 签名算法类型
    uint32_t data_len;            // 数据长度（网络字节序）
    uint32_t sig_len;            // 签名长度（网络字节序）
    uint8_t data[0];             // 原始数据（或加密数据）
    // 签名数据紧跟在data后面
} __attribute__((packed)) signed_packet_t;

// 函数声明

// 初始化/清理
int sign_ctx_init(sign_ctx_t *ctx, sign_type_t type);
int sign_ctx_cleanup(sign_ctx_t *ctx);

// 密钥生成和交换
int sign_generate_keypair(sign_ctx_t *ctx);
int sign_export_public_key(sign_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len);
int sign_import_peer_public_key(sign_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len);

// 签名/验签
int sign_data(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
              unsigned char *signature, size_t *signature_len);
int verify_signature(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
                     const unsigned char *signature, size_t signature_len);

// 工具函数
const char* sign_type_to_string(sign_type_t type);

#endif // SIGN_H

