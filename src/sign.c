#include "../include/sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
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

// 验证签名（支持Raw (R||S)格式和DER格式）
int verify_signature(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
                     const unsigned char *signature, size_t signature_len) {
    if (!ctx->public_key) {
        fprintf(stderr, "Error: Public key not available\n");
        return -1;
    }
    
    const EVP_MD *md = EVP_sha256();
    unsigned char *der_sig = NULL;
    size_t der_sig_len = 0;
    const unsigned char *sig_to_verify = signature;  // 用于验证的签名指针
    size_t sig_len_to_verify = signature_len;        // 用于验证的签名长度
    int ret = -1;
    
    // 确定预期的Raw签名长度（根据曲线类型）
    size_t expected_raw_len;
    if (ctx->sign_type == SIGN_ECDSA_P256) {
        expected_raw_len = 64;  // 32 bytes R + 32 bytes S
    } else if (ctx->sign_type == SIGN_ECDSA_P384) {
        expected_raw_len = 96;  // 48 bytes R + 48 bytes S
    } else {
        fprintf(stderr, "Error: Unsupported signature type\n");
        return -1;
    }
    
    // 检查是否为Raw (R||S)格式签名
    if (signature_len == expected_raw_len) {
        // Raw格式：需要转换为DER格式
        size_t coord_len = expected_raw_len / 2;  // R和S各占一半
        
        // 从Raw签名中提取R和S
        BIGNUM *r = BN_bin2bn(signature, coord_len, NULL);
        BIGNUM *s = BN_bin2bn(signature + coord_len, coord_len, NULL);
        
        if (!r || !s) {
            fprintf(stderr, "Error: Failed to convert signature to BIGNUM\n");
            if (r) BN_free(r);
            if (s) BN_free(s);
            return -1;
        }
        
        // 创建ECDSA_SIG结构
        ECDSA_SIG *sig = ECDSA_SIG_new();
        if (!sig) {
            fprintf(stderr, "Error: Failed to create ECDSA_SIG\n");
            BN_free(r);
            BN_free(s);
            return -1;
        }
        
        // 设置R和S到ECDSA_SIG（ECDSA_SIG_set0会获取所有权）
        if (ECDSA_SIG_set0(sig, r, s) != 1) {
            fprintf(stderr, "Error: Failed to set R and S in ECDSA_SIG\n");
            ERR_print_errors_fp(stderr);
            BN_free(r);
            BN_free(s);
            ECDSA_SIG_free(sig);
            return -1;
        }
        
        // 计算DER编码长度
        int der_len = i2d_ECDSA_SIG(sig, NULL);
        if (der_len <= 0) {
            fprintf(stderr, "Error: Failed to calculate DER signature length\n");
            ERR_print_errors_fp(stderr);
            ECDSA_SIG_free(sig);
            return -1;
        }
        
        // 分配DER缓冲区并编码
        der_sig = malloc(der_len);
        if (!der_sig) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            ECDSA_SIG_free(sig);
            return -1;
        }
        
        unsigned char *p = der_sig;
        der_sig_len = i2d_ECDSA_SIG(sig, &p);
        ECDSA_SIG_free(sig);
        
        if (der_sig_len != (size_t)der_len) {
            fprintf(stderr, "Error: DER encoding length mismatch\n");
            free(der_sig);
            return -1;
        }
        
        // 使用DER格式的签名进行验证
        sig_to_verify = der_sig;
        sig_len_to_verify = der_sig_len;
    }
    // 否则，假设已经是DER格式，直接使用原始签名
    
    // 初始化验证上下文
    if (EVP_DigestVerifyInit(ctx->verify_ctx, NULL, md, NULL, ctx->public_key) != 1) {
        fprintf(stderr, "Error: Failed to initialize verification\n");
        if (der_sig) free(der_sig);
        return -1;
    }
    
    // 更新验证上下文
    if (EVP_DigestVerifyUpdate(ctx->verify_ctx, data, data_len) != 1) {
        fprintf(stderr, "Error: Failed to update verification context\n");
        if (der_sig) free(der_sig);
        return -1;
    }
    
    // 最终验证
    int verify_ret = EVP_DigestVerifyFinal(ctx->verify_ctx, sig_to_verify, sig_len_to_verify);
    if (verify_ret == 1) {
        ret = 0;  // 验证成功
    } else if (verify_ret == 0) {
        fprintf(stderr, "Error: Signature verification failed\n");
        ret = -1;
    } else {
        fprintf(stderr, "Error: Signature verification error\n");
        ERR_print_errors_fp(stderr);
        ret = -1;
    }
    
    // 清理DER签名缓冲区
    if (der_sig) {
        free(der_sig);
    }
    
    return ret;
}

