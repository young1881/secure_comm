#ifndef PROTOCOL_TYPES_H
#define PROTOCOL_TYPES_H

#include <stdint.h>

// 消息类型定义
typedef enum {
    MSG_TYPE_HANDSHAKE_INIT = 0x01,  // 对应原 PKT_TYPE_KEY_EXCHANGE
    MSG_TYPE_HANDSHAKE_RESP = 0x02,  // 握手响应 (新增)
    MSG_TYPE_SECURE_DATA    = 0x04,  // 对应原 PKT_TYPE_ENCRYPTED_SIGNED
    MSG_TYPE_ERROR          = 0xFF
} msg_type_t;

// 统一协议头
typedef struct {
    uint8_t  version;       // 协议版本，例如 0x01
    uint8_t  type;          // msg_type_t
    uint16_t reserved;      // 保留/对齐
    uint32_t payload_len;   // 负载长度 (Network Byte Order)
} __attribute__((packed)) protocol_header_t;

#endif // PROTOCOL_TYPES_H
