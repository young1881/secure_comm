#include "../include/kex.h"
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
    kex_type_t kex_type = KEX_ECDH_P256;
    
    if (argc > 1) {
        if (strcmp(argv[1], "p256") == 0) {
            kex_type = KEX_ECDH_P256;
        } else if (strcmp(argv[1], "p384") == 0) {
            kex_type = KEX_ECDH_P384;
        } else {
            fprintf(stderr, "Usage: %s [p256|p384]\n", argv[0]);
            return 1;
        }
    }
    
    printf("=== Key Exchange Test ===\n");
    printf("Algorithm: %s\n\n", kex_type_to_string(kex_type));
    
    // 创建两个密钥交换上下文（模拟客户端和服务器）
    kex_ctx_t client_ctx, server_ctx;
    
    if (kex_ctx_init(&client_ctx, kex_type) != 0 ||
        kex_ctx_init(&server_ctx, kex_type) != 0) {
        fprintf(stderr, "Error: Failed to initialize contexts\n");
        return 1;
    }
    
    // 客户端生成密钥对
    printf("1. Client generating key pair...\n");
    if (kex_generate_keypair(&client_ctx) != 0) {
        fprintf(stderr, "Error: Client failed to generate key pair\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Client key pair generated\n");
    
    // 服务器生成密钥对
    printf("2. Server generating key pair...\n");
    if (kex_generate_keypair(&server_ctx) != 0) {
        fprintf(stderr, "Error: Server failed to generate key pair\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Server key pair generated\n");
    
    // 客户端导出公钥
    printf("3. Client exporting public key...\n");
    unsigned char client_pubkey[512];
    size_t client_pubkey_len = sizeof(client_pubkey);
    if (kex_export_public_key(&client_ctx, client_pubkey, &client_pubkey_len) != 0) {
        fprintf(stderr, "Error: Client failed to export public key\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Client public key exported (%zu bytes)\n", client_pubkey_len);
    
    // 服务器导出公钥
    printf("4. Server exporting public key...\n");
    unsigned char server_pubkey[512];
    size_t server_pubkey_len = sizeof(server_pubkey);
    if (kex_export_public_key(&server_ctx, server_pubkey, &server_pubkey_len) != 0) {
        fprintf(stderr, "Error: Server failed to export public key\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Server public key exported (%zu bytes)\n", server_pubkey_len);
    
    // 客户端导入服务器公钥
    printf("5. Client importing server public key...\n");
    if (kex_import_peer_public_key(&client_ctx, server_pubkey, server_pubkey_len) != 0) {
        fprintf(stderr, "Error: Client failed to import server public key\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Client imported server public key\n");
    
    // 服务器导入客户端公钥
    printf("6. Server importing client public key...\n");
    if (kex_import_peer_public_key(&server_ctx, client_pubkey, client_pubkey_len) != 0) {
        fprintf(stderr, "Error: Server failed to import client public key\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Server imported client public key\n");
    
    // 客户端派生共享密钥
    printf("7. Client deriving shared secret...\n");
    if (kex_derive_shared_secret(&client_ctx) != 0) {
        fprintf(stderr, "Error: Client failed to derive shared secret\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Client shared secret derived (%zu bytes)\n", client_ctx.shared_secret_len);
    print_hex(client_ctx.shared_secret, client_ctx.shared_secret_len, "   Client shared secret");
    
    // 服务器派生共享密钥
    printf("8. Server deriving shared secret...\n");
    if (kex_derive_shared_secret(&server_ctx) != 0) {
        fprintf(stderr, "Error: Server failed to derive shared secret\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    printf("   ✓ Server shared secret derived (%zu bytes)\n", server_ctx.shared_secret_len);
    print_hex(server_ctx.shared_secret, server_ctx.shared_secret_len, "   Server shared secret");
    
    // 验证共享密钥是否相同
    if (client_ctx.shared_secret_len == server_ctx.shared_secret_len &&
        memcmp(client_ctx.shared_secret, server_ctx.shared_secret, client_ctx.shared_secret_len) == 0) {
        printf("\n✓ Shared secrets match!\n");
    } else {
        printf("\n✗ Shared secrets do NOT match!\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    
    // 测试密钥派生
    printf("\n9. Deriving symmetric keys...\n");
    unsigned char client_key[32], client_iv[16];
    unsigned char server_key[32], server_iv[16];
    
    if (kex_derive_symmetric_key(&client_ctx, 32, 16, client_key, client_iv) != 0 ||
        kex_derive_symmetric_key(&server_ctx, 32, 16, server_key, server_iv) != 0) {
        fprintf(stderr, "Error: Failed to derive symmetric keys\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    
    print_hex(client_key, 32, "   Client derived key");
    print_hex(server_key, 32, "   Server derived key");
    print_hex(client_iv, 16, "   Client derived IV");
    print_hex(server_iv, 16, "   Server derived IV");
    
    if (memcmp(client_key, server_key, 32) == 0 && memcmp(client_iv, server_iv, 16) == 0) {
        printf("\n✓ Derived symmetric keys match!\n");
    } else {
        printf("\n✗ Derived symmetric keys do NOT match!\n");
        kex_ctx_cleanup(&client_ctx);
        kex_ctx_cleanup(&server_ctx);
        return 1;
    }
    
    // 清理
    kex_ctx_cleanup(&client_ctx);
    kex_ctx_cleanup(&server_ctx);
    
    printf("\n=== Test completed successfully ===\n");
    return 0;
}

