#ifndef KEX_H
#define KEX_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

// 密钥交换算法类型
typedef enum {
    KEX_ECDH_P256 = 0x01,
    KEX_ECDH_P384 = 0x02
} kex_type_t;

// 密钥交换上下文结构
typedef struct {
    kex_type_t kex_type;
    EVP_PKEY *local_keypair;      // 本地密钥对
    EVP_PKEY *peer_public_key;    // 对端公钥
    unsigned char *shared_secret; // 共享密钥
    size_t shared_secret_len;     // 共享密钥长度
} kex_ctx_t;

// 密钥交换数据包结构
typedef struct {
    uint8_t kex_type;             // 密钥交换算法类型
    uint32_t pubkey_len;          // 公钥长度（网络字节序）
    uint8_t pubkey[512];          // 公钥数据（PEM格式）
} __attribute__((packed)) kex_packet_t;

// 函数声明

// 初始化/清理
int kex_ctx_init(kex_ctx_t *ctx, kex_type_t type);
int kex_ctx_cleanup(kex_ctx_t *ctx);

// 密钥生成和交换
int kex_generate_keypair(kex_ctx_t *ctx);
int kex_export_public_key(kex_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len);
int kex_import_peer_public_key(kex_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len);
int kex_derive_shared_secret(kex_ctx_t *ctx);

// 密钥派生
int kex_derive_symmetric_key(kex_ctx_t *ctx, int key_len, int iv_len, 
                             unsigned char *key, unsigned char *iv);

// 工具函数
const char* kex_type_to_string(kex_type_t type);

#endif // KEX_H

