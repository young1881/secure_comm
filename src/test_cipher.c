#include "../include/cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

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
    cipher_type_t cipher_type = CIPHER_AES_256_GCM;
    
    if (argc > 1) {
        if (strcmp(argv[1], "aes128gcm") == 0) {
            cipher_type = CIPHER_AES_128_GCM;
        } else if (strcmp(argv[1], "aes256gcm") == 0) {
            cipher_type = CIPHER_AES_256_GCM;
        } else if (strcmp(argv[1], "aes128cbc") == 0) {
            cipher_type = CIPHER_AES_128_CBC;
        } else if (strcmp(argv[1], "aes256cbc") == 0) {
            cipher_type = CIPHER_AES_256_CBC;
        } else if (strcmp(argv[1], "chacha20") == 0) {
            cipher_type = CIPHER_CHACHA20_POLY1305;
        } else {
            fprintf(stderr, "Usage: %s [aes128gcm|aes256gcm|aes128cbc|aes256cbc|chacha20]\n", argv[0]);
            return 1;
        }
    }
    
    printf("=== Cipher Test ===\n");
    printf("Algorithm: %s\n\n", cipher_type_to_string(cipher_type));
    
    // 生成密钥和IV
    int key_len = cipher_get_key_len(cipher_type);
    int iv_len = cipher_get_iv_len(cipher_type);
    
    unsigned char key[32];
    unsigned char iv[16];
    
    if (RAND_bytes(key, key_len) != 1 || RAND_bytes(iv, iv_len) != 1) {
        fprintf(stderr, "Error: Failed to generate random key/IV\n");
        return 1;
    }
    
    print_hex(key, key_len, "Key");
    print_hex(iv, iv_len, "IV");
    printf("\n");
    
    // 初始化加密上下文
    cipher_ctx_t ctx;
    if (cipher_ctx_init(&ctx, cipher_type, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to initialize cipher context\n");
        return 1;
    }
    
    // 测试数据
    const char *plaintext = "This is a test message for encryption and decryption!";
    size_t plaintext_len = strlen(plaintext);
    
    printf("Plaintext: %s\n", plaintext);
    printf("Plaintext length: %zu bytes\n\n", plaintext_len);
    
    // 加密
    printf("1. Encrypting...\n");
    unsigned char ciphertext[1024];
    size_t ciphertext_len = sizeof(ciphertext);
    unsigned char tag[16];
    
    if (cipher_encrypt(&ctx, (unsigned char *)plaintext, plaintext_len,
                      ciphertext, &ciphertext_len, tag) != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        cipher_ctx_cleanup(&ctx);
        return 1;
    }
    
    printf("   ✓ Encryption successful\n");
    printf("   Ciphertext length: %zu bytes\n", ciphertext_len);
    print_hex(ciphertext, ciphertext_len, "   Ciphertext");
    if (ctx.tag_len > 0) {
        print_hex(tag, ctx.tag_len, "   Tag");
    }
    printf("\n");
    
    // 重新初始化上下文用于解密（需要新的IV）
    cipher_ctx_cleanup(&ctx);
    if (cipher_ctx_init(&ctx, cipher_type, key, iv) != 0) {
        fprintf(stderr, "Error: Failed to reinitialize cipher context\n");
        return 1;
    }
    
    // 解密
    printf("2. Decrypting...\n");
    unsigned char decrypted[1024];
    size_t decrypted_len = sizeof(decrypted);
    
    if (cipher_decrypt(&ctx, ciphertext, ciphertext_len, tag, decrypted, &decrypted_len) != 0) {
        fprintf(stderr, "Error: Decryption failed\n");
        cipher_ctx_cleanup(&ctx);
        return 1;
    }
    
    printf("   ✓ Decryption successful\n");
    printf("   Decrypted length: %zu bytes\n", decrypted_len);
    printf("   Decrypted text: %.*s\n", (int)decrypted_len, decrypted);
    printf("\n");
    
    // 验证
    if (decrypted_len == plaintext_len && 
        memcmp(decrypted, plaintext, plaintext_len) == 0) {
        printf("✓ Plaintext matches decrypted text!\n");
    } else {
        printf("✗ Plaintext does NOT match decrypted text!\n");
        cipher_ctx_cleanup(&ctx);
        return 1;
    }
    
    // 测试错误标签（仅对AEAD模式）
    if (ctx.tag_len > 0) {
        printf("\n3. Testing with wrong tag...\n");
        unsigned char wrong_tag[16];
        memcpy(wrong_tag, tag, ctx.tag_len);
        wrong_tag[0] ^= 0xFF;  // 修改第一个字节
        
        cipher_ctx_cleanup(&ctx);
        if (cipher_ctx_init(&ctx, cipher_type, key, iv) != 0) {
            fprintf(stderr, "Error: Failed to reinitialize cipher context\n");
            return 1;
        }
        
        decrypted_len = sizeof(decrypted);
        if (cipher_decrypt(&ctx, ciphertext, ciphertext_len, wrong_tag, decrypted, &decrypted_len) == 0) {
            printf("✗ Decryption should have failed with wrong tag!\n");
            cipher_ctx_cleanup(&ctx);
            return 1;
        } else {
            printf("   ✓ Decryption correctly rejected wrong tag\n");
        }
    }
    
    cipher_ctx_cleanup(&ctx);
    
    printf("\n=== Test completed successfully ===\n");
    return 0;
}

