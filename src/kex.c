#include "../include/kex.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// 密钥交换算法类型转字符串
const char* kex_type_to_string(kex_type_t type) {
    switch (type) {
        case KEX_ECDH_P256: return "ECDH-P256";
        case KEX_ECDH_P384: return "ECDH-P384";
        default: return "Unknown";
    }
}

// 初始化密钥交换上下文
int kex_ctx_init(kex_ctx_t *ctx, kex_type_t type) {
    memset(ctx, 0, sizeof(kex_ctx_t));
    ctx->kex_type = type;
    return 0;
}

// 清理密钥交换上下文
int kex_ctx_cleanup(kex_ctx_t *ctx) {
    if (ctx->local_keypair) {
        EVP_PKEY_free(ctx->local_keypair);
        ctx->local_keypair = NULL;
    }
    if (ctx->peer_public_key) {
        EVP_PKEY_free(ctx->peer_public_key);
        ctx->peer_public_key = NULL;
    }
    if (ctx->shared_secret) {
        OPENSSL_cleanse(ctx->shared_secret, ctx->shared_secret_len);
        free(ctx->shared_secret);
        ctx->shared_secret = NULL;
        ctx->shared_secret_len = 0;
    }
    return 0;
}

// 生成密钥对
int kex_generate_keypair(kex_ctx_t *ctx) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *keypair = NULL;
    int curve_nid;
    
    if (ctx->kex_type == KEX_ECDH_P256) {
        curve_nid = NID_X9_62_prime256v1;
    } else if (ctx->kex_type == KEX_ECDH_P384) {
        curve_nid = NID_secp384r1;
    } else {
        fprintf(stderr, "Error: Unsupported key exchange type\n");
        return -1;
    }
    
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Error: Failed to create EC key context\n");
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Error: Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0) {
        fprintf(stderr, "Error: Failed to set EC curve\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_keygen(pctx, &keypair) <= 0) {
        fprintf(stderr, "Error: Failed to generate EC key pair\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY_CTX_free(pctx);
    ctx->local_keypair = keypair;
    return 0;
}

// 导出公钥（使用EC_POINT_point2oct未压缩格式，兼容WolfSSL X9.63）
int kex_export_public_key(kex_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len) {
    if (!ctx->local_keypair) {
        fprintf(stderr, "Error: Key pair not generated\n");
        return -1;
    }
    
    // 获取EC_KEY
    const EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(ctx->local_keypair);
    if (!ec_key) {
        fprintf(stderr, "Error: Failed to get EC_KEY from EVP_PKEY\n");
        return -1;
    }
    
    // 获取EC_POINT和EC_GROUP
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!pub_point || !group) {
        fprintf(stderr, "Error: Failed to get EC_POINT or EC_GROUP\n");
        return -1;
    }
    
    // 计算所需的缓冲区大小（未压缩格式：1字节前缀 + 2*坐标长度）
    size_t required_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (required_len == 0) {
        fprintf(stderr, "Error: Failed to calculate public key length\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // 检查缓冲区大小
    if (*pubkey_len < required_len) {
        *pubkey_len = required_len;
        fprintf(stderr, "Error: Buffer too small, need %zu bytes\n", required_len);
        return -1;
    }
    
    // 导出公钥点（未压缩格式）
    size_t written_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, pubkey, required_len, NULL);
    if (written_len == 0 || written_len != required_len) {
        fprintf(stderr, "Error: Failed to export public key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    *pubkey_len = written_len;
    return 0;
}

// 导入对端公钥（使用EC_POINT_oct2point）
int kex_import_peer_public_key(kex_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len) {
    if (!pubkey || pubkey_len == 0) {
        fprintf(stderr, "Error: Invalid public key data\n");
        return -1;
    }
    
    // 根据kex_type确定曲线NID
    int curve_nid;
    size_t expected_len;
    if (ctx->kex_type == KEX_ECDH_P256) {
        curve_nid = NID_X9_62_prime256v1;
        expected_len = 65; // 1 + 32 + 32 (uncompressed format)
    } else if (ctx->kex_type == KEX_ECDH_P384) {
        curve_nid = NID_secp384r1;
        expected_len = 97; // 1 + 48 + 48 (uncompressed format)
    } else {
        fprintf(stderr, "Error: Unsupported key exchange type\n");
        return -1;
    }
    
    // 验证长度
    if (pubkey_len != expected_len) {
        fprintf(stderr, "Error: Invalid public key length %zu (expected %zu)\n", pubkey_len, expected_len);
        return -1;
    }
    
    // 创建EC_KEY
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(curve_nid);
    if (!ec_key) {
        fprintf(stderr, "Error: Failed to create EC_KEY\n");
        return -1;
    }
    
    // 获取EC_GROUP
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!group) {
        fprintf(stderr, "Error: Failed to get EC_GROUP\n");
        EC_KEY_free(ec_key);
        return -1;
    }
    
    // 创建EC_POINT
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        fprintf(stderr, "Error: Failed to create EC_POINT\n");
        EC_KEY_free(ec_key);
        return -1;
    }
    
    // 从八进制格式导入点
    if (EC_POINT_oct2point(group, pub_point, pubkey, pubkey_len, NULL) != 1) {
        fprintf(stderr, "Error: Failed to import public key point\n");
        ERR_print_errors_fp(stderr);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return -1;
    }
    
    // 设置公钥到EC_KEY
    if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        fprintf(stderr, "Error: Failed to set public key in EC_KEY\n");
        ERR_print_errors_fp(stderr);
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return -1;
    }
    
    EC_POINT_free(pub_point);
    
    // 创建EVP_PKEY
    EVP_PKEY *peer_key = EVP_PKEY_new();
    if (!peer_key) {
        fprintf(stderr, "Error: Failed to create EVP_PKEY\n");
        EC_KEY_free(ec_key);
        return -1;
    }
    
    // 将EC_KEY设置为EVP_PKEY
    if (EVP_PKEY_set1_EC_KEY(peer_key, ec_key) != 1) {
        fprintf(stderr, "Error: Failed to set EC_KEY in EVP_PKEY\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(peer_key);
        return -1;
    }
    
    EC_KEY_free(ec_key);
    ctx->peer_public_key = peer_key;
    return 0;
}

// 派生共享密钥
int kex_derive_shared_secret(kex_ctx_t *ctx) {
    if (!ctx->local_keypair || !ctx->peer_public_key) {
        fprintf(stderr, "Error: Key pair or peer public key missing\n");
        return -1;
    }
    
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(ctx->local_keypair, NULL);
    if (!derive_ctx) {
        fprintf(stderr, "Error: Failed to create derive context\n");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        fprintf(stderr, "Error: Failed to initialize key derivation\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }
    
    if (EVP_PKEY_derive_set_peer(derive_ctx, ctx->peer_public_key) <= 0) {
        fprintf(stderr, "Error: Failed to set peer key\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }
    
    // 获取共享密钥长度
    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx, NULL, &secret_len) <= 0) {
        fprintf(stderr, "Error: Failed to get secret length\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }
    
    ctx->shared_secret = malloc(secret_len);
    if (!ctx->shared_secret) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        EVP_PKEY_CTX_free(derive_ctx);
        return -1;
    }
    
    if (EVP_PKEY_derive(derive_ctx, ctx->shared_secret, &secret_len) <= 0) {
        fprintf(stderr, "Error: Failed to derive shared secret\n");
        EVP_PKEY_CTX_free(derive_ctx);
        free(ctx->shared_secret);
        ctx->shared_secret = NULL;
        return -1;
    }
    
    ctx->shared_secret_len = secret_len;
    EVP_PKEY_CTX_free(derive_ctx);
    return 0;
}

// 从共享密钥派生对称加密密钥和IV
int kex_derive_symmetric_key(kex_ctx_t *ctx, int key_len, int iv_len, 
                             unsigned char *key, unsigned char *iv) {
    if (!ctx->shared_secret) {
        fprintf(stderr, "Error: Shared secret not derived\n");
        return -1;
    }
    
    // 使用SHA256从共享密钥派生对称密钥
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error: Failed to create MD context\n");
        return -1;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    // 派生密钥
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->shared_secret, ctx->shared_secret_len) != 1 ||
        EVP_DigestUpdate(mdctx, "key", 3) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Error: Failed to derive key\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    
    size_t key_len_sz = (size_t)key_len;
    size_t hash_len_sz = (size_t)hash_len;
    size_t copy_len = key_len_sz < hash_len_sz ? key_len_sz : hash_len_sz;
    memcpy(key, hash, copy_len);
    if (key_len_sz > hash_len_sz) {
        memset(key + hash_len_sz, 0, key_len_sz - hash_len_sz);
    }
    
    // 派生IV
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, ctx->shared_secret, ctx->shared_secret_len) != 1 ||
        EVP_DigestUpdate(mdctx, "iv", 2) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Error: Failed to derive IV\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    
    size_t iv_len_sz = (size_t)iv_len;
    hash_len_sz = (size_t)hash_len;
    copy_len = iv_len_sz < hash_len_sz ? iv_len_sz : hash_len_sz;
    memcpy(iv, hash, copy_len);
    if (iv_len_sz > hash_len_sz) {
        memset(iv + hash_len_sz, 0, iv_len_sz - hash_len_sz);
    }
    
    EVP_MD_CTX_free(mdctx);
    return 0;
}

