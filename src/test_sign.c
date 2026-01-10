#include "../include/sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const unsigned char *data, size_t len, const char *label) {
    if (label) {
        printf("%s: ", label);
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    sign_type_t sign_type = SIGN_ECDSA_P256;
    
    if (argc > 1) {
        if (strcmp(argv[1], "p256") == 0) {
            sign_type = SIGN_ECDSA_P256;
        } else if (strcmp(argv[1], "p384") == 0) {
            sign_type = SIGN_ECDSA_P384;
        } else {
            fprintf(stderr, "Usage: %s [p256|p384]\n", argv[0]);
            return 1;
        }
    }
    
    printf("=== Signature Test ===\n");
    printf("Algorithm: %s\n\n", sign_type_to_string(sign_type));
    
    // 创建两个签名上下文（模拟发送方和接收方）
    sign_ctx_t signer_ctx, verifier_ctx;
    
    if (sign_ctx_init(&signer_ctx, sign_type) != 0 ||
        sign_ctx_init(&verifier_ctx, sign_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize contexts\n");
        return 1;
    }
    
    // 发送方生成密钥对
    printf("1. Signer generating key pair...\n");
    if (sign_generate_keypair(&signer_ctx) != 0) {
        fprintf(stderr, "Error: Signer failed to generate key pair\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    }
    printf("   ✓ Signer key pair generated\n");
    
    // 发送方导出公钥
    printf("2. Signer exporting public key...\n");
    unsigned char pubkey[512];
    size_t pubkey_len = sizeof(pubkey);
    if (sign_export_public_key(&signer_ctx, pubkey, &pubkey_len) != 0) {
        fprintf(stderr, "Error: Signer failed to export public key\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    }
    printf("   ✓ Public key exported (%zu bytes)\n", pubkey_len);
    
    // 接收方导入公钥
    printf("3. Verifier importing public key...\n");
    if (sign_import_peer_public_key(&verifier_ctx, pubkey, pubkey_len) != 0) {
        fprintf(stderr, "Error: Verifier failed to import public key\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    }
    printf("   ✓ Public key imported\n");
    
    // 测试数据
    const char *message = "This is a test message for signing and verification!";
    size_t message_len = strlen(message);
    
    printf("\nMessage: %s\n", message);
    printf("Message length: %zu bytes\n\n", message_len);
    
    // 签名
    printf("4. Signing message...\n");
    unsigned char signature[256];
    size_t sig_len = sizeof(signature);
    
    if (sign_data(&signer_ctx, (unsigned char *)message, message_len,
                 signature, &sig_len) != 0) {
        fprintf(stderr, "Error: Signing failed\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    }
    
    printf("   ✓ Signature created\n");
    printf("   Signature length: %zu bytes\n", sig_len);
    print_hex(signature, sig_len, "   Signature");
    printf("\n");
    
    // 验证签名
    printf("5. Verifying signature...\n");
    if (verify_signature(&verifier_ctx, (unsigned char *)message, message_len,
                        signature, sig_len) != 0) {
        fprintf(stderr, "Error: Signature verification failed\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    }
    
    printf("   ✓ Signature verified successfully\n\n");
    
    // 测试错误消息
    printf("6. Testing with wrong message...\n");
    const char *wrong_message = "This is a different message!";
    if (verify_signature(&verifier_ctx, (unsigned char *)wrong_message, strlen(wrong_message),
                        signature, sig_len) == 0) {
        printf("   ✗ Verification should have failed with wrong message!\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    } else {
        printf("   ✓ Verification correctly rejected wrong message\n");
    }
    
    // 测试错误签名
    printf("\n7. Testing with wrong signature...\n");
    unsigned char wrong_sig[256];
    memcpy(wrong_sig, signature, sig_len);
    wrong_sig[0] ^= 0xFF;  // 修改第一个字节
    
    if (verify_signature(&verifier_ctx, (unsigned char *)message, message_len,
                        wrong_sig, sig_len) == 0) {
        printf("   ✗ Verification should have failed with wrong signature!\n");
        sign_ctx_cleanup(&signer_ctx);
        sign_ctx_cleanup(&verifier_ctx);
        return 1;
    } else {
        printf("   ✓ Verification correctly rejected wrong signature\n");
    }
    
    // 清理
    sign_ctx_cleanup(&signer_ctx);
    sign_ctx_cleanup(&verifier_ctx);
    
    printf("\n=== Test completed successfully ===\n");
    return 0;
}

