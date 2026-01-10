#include "../include/sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// 签名算法类型转字符串
const char* sign_type_to_string(sign_type_t type) {
    switch (type) {
        case SIGN_ECDSA_P256: return "ECDSA-P256";
        case SIGN_ECDSA_P384: return "ECDSA-P384";
        default: return "Unknown";
    }
}

// 初始化签名上下文
int sign_ctx_init(sign_ctx_t *ctx, sign_type_t type) {
    memset(ctx, 0, sizeof(sign_ctx_t));
    ctx->sign_type = type;
    ctx->sign_ctx = EVP_MD_CTX_new();
    ctx->verify_ctx = EVP_MD_CTX_new();
    if (!ctx->sign_ctx || !ctx->verify_ctx) {
        fprintf(stderr, "Error: Failed to create MD context\n");
        sign_ctx_cleanup(ctx);
        return -1;
    }
    return 0;
}

// 清理签名上下文
int sign_ctx_cleanup(sign_ctx_t *ctx) {
    if (ctx->sign_ctx) {
        EVP_MD_CTX_free(ctx->sign_ctx);
        ctx->sign_ctx = NULL;
    }
    if (ctx->verify_ctx) {
        EVP_MD_CTX_free(ctx->verify_ctx);
        ctx->verify_ctx = NULL;
    }
    if (ctx->private_key) {
        EVP_PKEY_free(ctx->private_key);
        ctx->private_key = NULL;
    }
    if (ctx->public_key) {
        EVP_PKEY_free(ctx->public_key);
        ctx->public_key = NULL;
    }
    return 0;
}

// 生成签名密钥对
int sign_generate_keypair(sign_ctx_t *ctx) {
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *keypair = NULL;
    int curve_nid;
    
    if (ctx->sign_type == SIGN_ECDSA_P256) {
        curve_nid = NID_X9_62_prime256v1;
    } else if (ctx->sign_type == SIGN_ECDSA_P384) {
        curve_nid = NID_secp384r1;
    } else {
        fprintf(stderr, "Error: Unsupported signature type\n");
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
    ctx->private_key = keypair;
    ctx->public_key = EVP_PKEY_dup(keypair);
    return 0;
}

// 导出公钥
int sign_export_public_key(sign_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len) {
    if (!ctx->public_key) {
        fprintf(stderr, "Error: Public key not generated\n");
        return -1;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "Error: Failed to create BIO\n");
        return -1;
    }
    
    if (PEM_write_bio_PUBKEY(bio, ctx->public_key) != 1) {
        fprintf(stderr, "Error: Failed to write public key\n");
        BIO_free(bio);
        return -1;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    if (*pubkey_len < bptr->length) {
        *pubkey_len = bptr->length;
        BIO_free(bio);
        return -1;
    }
    
    memcpy(pubkey, bptr->data, bptr->length);
    *pubkey_len = bptr->length;
    
    BIO_free(bio);
    return 0;
}

// 导入对端公钥
int sign_import_peer_public_key(sign_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len) {
    BIO *bio = BIO_new_mem_buf(pubkey, pubkey_len);
    if (!bio) {
        fprintf(stderr, "Error: Failed to create BIO from buffer\n");
        return -1;
    }
    
    EVP_PKEY *peer_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!peer_key) {
        fprintf(stderr, "Error: Failed to read peer public key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    if (ctx->public_key) {
        EVP_PKEY_free(ctx->public_key);
    }
    ctx->public_key = peer_key;
    return 0;
}

// 签名数据
int sign_data(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
              unsigned char *signature, size_t *signature_len) {
    if (!ctx->private_key) {
        fprintf(stderr, "Error: Private key not available\n");
        return -1;
    }
    
    const EVP_MD *md = EVP_sha256();
    
    if (EVP_DigestSignInit(ctx->sign_ctx, NULL, md, NULL, ctx->private_key) != 1) {
        fprintf(stderr, "Error: Failed to initialize signing\n");
        return -1;
    }
    
    if (EVP_DigestSignUpdate(ctx->sign_ctx, data, data_len) != 1) {
        fprintf(stderr, "Error: Failed to update signing context\n");
        return -1;
    }
    
    size_t sig_len = *signature_len;
    if (EVP_DigestSignFinal(ctx->sign_ctx, signature, &sig_len) != 1) {
        fprintf(stderr, "Error: Failed to finalize signature\n");
        return -1;
    }
    
    *signature_len = sig_len;
    return 0;
}

// 验证签名
int verify_signature(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
                     const unsigned char *signature, size_t signature_len) {
    if (!ctx->public_key) {
        fprintf(stderr, "Error: Public key not available\n");
        return -1;
    }
    
    const EVP_MD *md = EVP_sha256();
    
    if (EVP_DigestVerifyInit(ctx->verify_ctx, NULL, md, NULL, ctx->public_key) != 1) {
        fprintf(stderr, "Error: Failed to initialize verification\n");
        return -1;
    }
    
    if (EVP_DigestVerifyUpdate(ctx->verify_ctx, data, data_len) != 1) {
        fprintf(stderr, "Error: Failed to update verification context\n");
        return -1;
    }
    
    int ret = EVP_DigestVerifyFinal(ctx->verify_ctx, signature, signature_len);
    if (ret == 1) {
        return 0;  // 验证成功
    } else if (ret == 0) {
        fprintf(stderr, "Error: Signature verification failed\n");
        return -1;
    } else {
        fprintf(stderr, "Error: Signature verification error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

