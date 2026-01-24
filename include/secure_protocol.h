#ifndef SECURE_PROTOCOL_H
#define SECURE_PROTOCOL_H

#include "kex.h"
#include "cipher.h"
#include "sign.h"
#include "protocol_types.h"

// 协议会话上下文
typedef struct {
    int socket_fd;
    kex_ctx_t kex;
    cipher_ctx_t cipher;
    sign_ctx_t sign;
    int is_handshake_done;
} secure_session_t;

// 初始化
int sp_session_init(secure_session_t *session, int socket_fd,
                    kex_type_t kex_alg, cipher_type_t cipher_alg, sign_type_t sign_alg);
void sp_session_cleanup(secure_session_t *session);

// 子模块：服务端握手逻辑
int sp_server_handshake(secure_session_t *session);

// 子模块：接收安全消息 (解密+验签)
// 返回 0 成功，plaintext_out 需要调用者 free
int sp_server_recv_msg(secure_session_t *session, unsigned char **plaintext_out, size_t *len_out);

#endif
