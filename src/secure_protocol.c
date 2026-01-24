#include "../include/secure_protocol.h"
#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stddef.h>

#define MAX_BUFFER_SIZE 65507

int sp_session_init(secure_session_t *session, int socket_fd,
                   kex_type_t kex_alg, cipher_type_t cipher_alg, sign_type_t sign_alg) {
    memset(session, 0, sizeof(secure_session_t));
    session->socket_fd = socket_fd;
    if (kex_ctx_init(&session->kex, kex_alg) != 0) {
        return -1;
    }
    session->cipher.cipher_type = cipher_alg; // 仅记录类型，暂不初始化 Key
    if (sign_ctx_init(&session->sign, sign_alg) != 0) {
        kex_ctx_cleanup(&session->kex);
        return -1;
    }
    return 0;
}

void sp_session_cleanup(secure_session_t *session) {
    kex_ctx_cleanup(&session->kex);
    cipher_ctx_cleanup(&session->cipher);
    sign_ctx_cleanup(&session->sign);
}

int sp_server_handshake(secure_session_t *session) {
    printf("[Protocol] Starting Handshake...\n");

    // 1. 生成服务端 KEX 密钥对
    if (kex_generate_keypair(&session->kex) != 0) {
        return -1;
    }

    // 2. 接收客户端 MSG_TYPE_HANDSHAKE_INIT
    uint8_t pkt_type;
    if (network_recv_all(session->socket_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
        printf("[Protocol] Error: Failed to receive packet type\n");
        return -1;
    }
    if (pkt_type != MSG_TYPE_HANDSHAKE_INIT) {
        printf("[Protocol] Error: Expected HANDSHAKE_INIT (0x%02x), got 0x%02x\n",
               MSG_TYPE_HANDSHAKE_INIT, pkt_type);
        return -1;
    }

    kex_packet_t client_kex_pkt;
    if (network_recv_all(session->socket_fd, &client_kex_pkt, sizeof(client_kex_pkt)) != sizeof(client_kex_pkt)) {
        printf("[Protocol] Error: Failed to receive client public key\n");
        return -1;
    }

    uint32_t client_pubkey_len = ntohl(client_kex_pkt.pubkey_len);
    if (client_pubkey_len > sizeof(client_kex_pkt.pubkey)) {
        printf("[Protocol] Error: Client public key too large\n");
        return -1;
    }

    if (kex_import_peer_public_key(&session->kex, client_kex_pkt.pubkey, client_pubkey_len) != 0) {
        printf("[Protocol] Error: Failed to import client public key\n");
        return -1;
    }

    // 3. 发送服务端公钥
    unsigned char server_pubkey[512];
    size_t server_pubkey_len = sizeof(server_pubkey);
    if (kex_export_public_key(&session->kex, server_pubkey, &server_pubkey_len) != 0) {
        printf("[Protocol] Error: Failed to export server public key\n");
        return -1;
    }

    kex_packet_t server_kex_pkt;
    memset(&server_kex_pkt, 0, sizeof(server_kex_pkt));
    server_kex_pkt.kex_type = session->kex.kex_type;
    server_kex_pkt.pubkey_len = htonl(server_pubkey_len);
    if (server_pubkey_len > sizeof(server_kex_pkt.pubkey)) {
        printf("[Protocol] Error: Server public key too large\n");
        return -1;
    }
    memcpy(server_kex_pkt.pubkey, server_pubkey, server_pubkey_len);

    if (network_send_all(session->socket_fd, &server_kex_pkt, sizeof(server_kex_pkt)) != 0) {
        printf("[Protocol] Error: Failed to send server public key\n");
        return -1;
    }

    // 4. 派生对称密钥
    if (kex_derive_shared_secret(&session->kex) != 0) {
        return -1;
    }

    unsigned char key[32];
    unsigned char iv[16];
    int key_len = cipher_get_key_len(session->cipher.cipher_type);
    int iv_len = cipher_get_iv_len(session->cipher.cipher_type);
    if (kex_derive_symmetric_key(&session->kex, key_len, iv_len, key, iv) != 0) {
        return -1;
    }

    // 5. 初始化加密上下文
    if (cipher_ctx_init(&session->cipher, session->cipher.cipher_type, key, iv) != 0) {
        return -1;
    }

    // 6. [重要] 更新签名验证公钥 (从 KEX 获取)
    if (session->sign.public_key) {
        EVP_PKEY_free(session->sign.public_key);
    }
    session->sign.public_key = EVP_PKEY_dup(session->kex.peer_public_key);
    if (!session->sign.public_key) {
        printf("[Protocol] Error: Failed to duplicate KEX public key for signature verification\n");
        return -1;
    }

    session->is_handshake_done = 1;
    printf("[Protocol] Handshake Completed.\n");
    return 0;
}

int sp_server_recv_msg(secure_session_t *session, unsigned char **plaintext_out, size_t *len_out) {
    if (!session->is_handshake_done) {
        return -1;
    }

    uint8_t pkt_type;
    if (network_recv_all(session->socket_fd, &pkt_type, sizeof(pkt_type)) != sizeof(pkt_type)) {
        return -1;
    }
    if (pkt_type != MSG_TYPE_SECURE_DATA) {
        printf("[Protocol] Error: Expected SECURE_DATA (0x%02x), got 0x%02x\n",
               MSG_TYPE_SECURE_DATA, pkt_type);
        return -1;
    }

    unsigned char buffer[MAX_BUFFER_SIZE];
    encrypted_packet_t enc_pkt;
    ssize_t header_size = sizeof(enc_pkt) - offsetof(encrypted_packet_t, cipher_type);
    if (network_recv_all(session->socket_fd, &enc_pkt.cipher_type, header_size) != header_size) {
        printf("[Protocol] Error: Failed to receive encrypted packet header\n");
        return -1;
    }

    uint32_t data_len = ntohl(enc_pkt.data_len);
    uint32_t iv_len = ntohl(enc_pkt.iv_len);
    uint32_t tag_len = ntohl(enc_pkt.tag_len);

    if (data_len > MAX_BUFFER_SIZE || iv_len > sizeof(enc_pkt.iv) || tag_len > sizeof(enc_pkt.tag)) {
        printf("[Protocol] Error: Invalid packet size (data_len=%u, iv_len=%u, tag_len=%u)\n",
               data_len, iv_len, tag_len);
        return -1;
    }

    unsigned char *encrypted_data = buffer;
    if (network_recv_all(session->socket_fd, encrypted_data, data_len) != data_len) {
        printf("[Protocol] Error: Failed to receive encrypted data\n");
        return -1;
    }

    signed_packet_t sig_pkt;
    if (network_recv_all(session->socket_fd, &sig_pkt.sign_type, sizeof(sig_pkt.sign_type)) != sizeof(sig_pkt.sign_type)) {
        printf("[Protocol] Error: Failed to receive signature packet type\n");
        return -1;
    }
    if (network_recv_all(session->socket_fd, &sig_pkt.data_len, sizeof(sig_pkt.data_len)) != sizeof(sig_pkt.data_len)) {
        printf("[Protocol] Error: Failed to receive signature data length\n");
        return -1;
    }

    uint32_t sig_data_len = ntohl(sig_pkt.data_len);
    if (network_recv_all(session->socket_fd, &sig_pkt.sig_len, sizeof(sig_pkt.sig_len)) != sizeof(sig_pkt.sig_len)) {
        printf("[Protocol] Error: Failed to receive signature length\n");
        return -1;
    }

    uint32_t sig_len = ntohl(sig_pkt.sig_len);
    if (sig_len > MAX_BUFFER_SIZE) {
        printf("[Protocol] Error: Signature too large (%u > %d)\n", sig_len, MAX_BUFFER_SIZE);
        return -1;
    }

    unsigned char *sig_data = buffer + MAX_BUFFER_SIZE / 2;
    if (network_recv_all(session->socket_fd, sig_data, sig_data_len) != sig_data_len) {
        printf("[Protocol] Error: Failed to receive signature data\n");
        return -1;
    }

    unsigned char *signature = sig_data + sig_data_len;
    if (network_recv_all(session->socket_fd, signature, sig_len) != sig_len) {
        printf("[Protocol] Error: Failed to receive signature\n");
        return -1;
    }

    if (verify_signature(&session->sign, sig_data, sig_data_len, signature, sig_len) != 0) {
        printf("[Protocol] Error: Signature verification failed\n");
        return -1;
    }

    memcpy(session->cipher.iv, enc_pkt.iv, iv_len);

    unsigned char *plaintext = buffer + MAX_BUFFER_SIZE / 2;
    size_t plaintext_len = MAX_BUFFER_SIZE / 2;
    if (cipher_decrypt(&session->cipher, encrypted_data, data_len, enc_pkt.tag, plaintext, &plaintext_len) != 0) {
        printf("[Protocol] Error: Decryption failed\n");
        return -1;
    }

    *plaintext_out = malloc(plaintext_len);
    if (!*plaintext_out) {
        printf("[Protocol] Error: Memory allocation failed\n");
        return -1;
    }
    memcpy(*plaintext_out, plaintext, plaintext_len);
    *len_out = plaintext_len;
    return 0;
}
