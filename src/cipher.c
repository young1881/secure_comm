#include "../include/cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

// 加密算法类型转字符串
const char* cipher_type_to_string(cipher_type_t type) {
    switch (type) {
        case CIPHER_AES_128_GCM: return "AES-128-GCM";
        case CIPHER_AES_256_GCM: return "AES-256-GCM";
        case CIPHER_AES_128_CBC: return "AES-128-CBC";
        case CIPHER_AES_256_CBC: return "AES-256-CBC";
        case CIPHER_CHACHA20_POLY1305: return "ChaCha20-Poly1305";
        default: return "Unknown";
    }
}

// 获取加密算法对象
const EVP_CIPHER* cipher_get_evp_cipher(cipher_type_t type) {
    switch (type) {
        case CIPHER_AES_128_GCM: return EVP_aes_128_gcm();
        case CIPHER_AES_256_GCM: return EVP_aes_256_gcm();
        case CIPHER_AES_128_CBC: return EVP_aes_128_cbc();
        case CIPHER_AES_256_CBC: return EVP_aes_256_cbc();
        case CIPHER_CHACHA20_POLY1305: return EVP_chacha20_poly1305();
        default: return NULL;
    }
}

// 获取密钥长度
int cipher_get_key_len(cipher_type_t type) {
    const EVP_CIPHER *cipher = cipher_get_evp_cipher(type);
    return cipher ? EVP_CIPHER_key_length(cipher) : 0;
}

// 获取IV长度
int cipher_get_iv_len(cipher_type_t type) {
    const EVP_CIPHER *cipher = cipher_get_evp_cipher(type);
    return cipher ? EVP_CIPHER_iv_length(cipher) : 0;
}

// 获取标签长度
int cipher_get_tag_len(cipher_type_t type) {
    if (type == CIPHER_AES_128_GCM || type == CIPHER_AES_256_GCM || 
        type == CIPHER_CHACHA20_POLY1305) {
        return 16;
    }
    return 0;
}

// 初始化加密上下文
int cipher_ctx_init(cipher_ctx_t *ctx, cipher_type_t type, const unsigned char *key, const unsigned char *iv) {
    memset(ctx, 0, sizeof(cipher_ctx_t));
    ctx->cipher_type = type;
    
    const EVP_CIPHER *cipher = cipher_get_evp_cipher(type);
    if (!cipher) {
        fprintf(stderr, "Error: Unsupported cipher type\n");
        return -1;
    }
    
    ctx->key_len = EVP_CIPHER_key_length(cipher);
    ctx->iv_len = EVP_CIPHER_iv_length(cipher);
    ctx->tag_len = cipher_get_tag_len(type);
    
    ctx->key = malloc(ctx->key_len);
    ctx->iv = malloc(ctx->iv_len);
    if (!ctx->key || !ctx->iv) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        cipher_ctx_cleanup(ctx);
        return -1;
    }
    
    if (key) {
        memcpy(ctx->key, key, ctx->key_len);
    }
    if (iv) {
        memcpy(ctx->iv, iv, ctx->iv_len);
    }
    
    ctx->encrypt_ctx = EVP_CIPHER_CTX_new();
    ctx->decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!ctx->encrypt_ctx || !ctx->decrypt_ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        cipher_ctx_cleanup(ctx);
        return -1;
    }
    
    return 0;
}

// 清理加密上下文
int cipher_ctx_cleanup(cipher_ctx_t *ctx) {
    if (ctx->encrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->encrypt_ctx);
        ctx->encrypt_ctx = NULL;
    }
    if (ctx->decrypt_ctx) {
        EVP_CIPHER_CTX_free(ctx->decrypt_ctx);
        ctx->decrypt_ctx = NULL;
    }
    if (ctx->key) {
        free(ctx->key);
        ctx->key = NULL;
    }
    if (ctx->iv) {
        free(ctx->iv);
        ctx->iv = NULL;
    }
    return 0;
}

// 加密数据
int cipher_encrypt(cipher_ctx_t *ctx, const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char *ciphertext, size_t *ciphertext_len, unsigned char *tag) {
    const EVP_CIPHER *cipher = cipher_get_evp_cipher(ctx->cipher_type);
    if (!cipher) {
        return -1;
    }
    
    int len;
    int final_len;
    
    // 初始化加密上下文
    if (EVP_EncryptInit_ex(ctx->encrypt_ctx, cipher, NULL, ctx->key, ctx->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize encryption\n");
        return -1;
    }
    
    // 执行加密
    if (EVP_EncryptUpdate(ctx->encrypt_ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error: Encryption failed\n");
        return -1;
    }
    *ciphertext_len = len;
    
    // 完成加密
    if (EVP_EncryptFinal_ex(ctx->encrypt_ctx, ciphertext + len, &final_len) != 1) {
        fprintf(stderr, "Error: Encryption finalization failed\n");
        return -1;
    }
    *ciphertext_len += final_len;
    
    // 获取认证标签（GCM/ChaCha20-Poly1305）
    if (tag && ctx->tag_len > 0) {
        if (EVP_CIPHER_CTX_ctrl(ctx->encrypt_ctx, EVP_CTRL_GCM_GET_TAG, ctx->tag_len, tag) != 1) {
            fprintf(stderr, "Error: Failed to get authentication tag\n");
            return -1;
        }
    }
    
    return 0;
}

// 解密数据
int cipher_decrypt(cipher_ctx_t *ctx, const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *tag, unsigned char *plaintext, size_t *plaintext_len) {
    const EVP_CIPHER *cipher = cipher_get_evp_cipher(ctx->cipher_type);
    if (!cipher) {
        return -1;
    }
    
    int len;
    int final_len;
    
    // 初始化解密上下文
    if (EVP_DecryptInit_ex(ctx->decrypt_ctx, cipher, NULL, ctx->key, ctx->iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize decryption\n");
        return -1;
    }
    
    // 执行解密
    if (EVP_DecryptUpdate(ctx->decrypt_ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Error: Decryption failed\n");
        return -1;
    }
    *plaintext_len = len;
    
    // 对于GCM/ChaCha20-Poly1305，设置认证标签
    if (tag && ctx->tag_len > 0) {
        if (EVP_CIPHER_CTX_ctrl(ctx->decrypt_ctx, EVP_CTRL_GCM_SET_TAG, ctx->tag_len, (void*)tag) != 1) {
            fprintf(stderr, "Error: Failed to set authentication tag\n");
            return -1;
        }
    }
    
    // 完成解密并验证标签
    int ret = EVP_DecryptFinal_ex(ctx->decrypt_ctx, plaintext + len, &final_len);
    if (ret <= 0) {
        fprintf(stderr, "Error: Decryption verification failed (tag mismatch or other error)\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *plaintext_len += final_len;
    
    return 0;
}

