#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// 函数声明

// Socket创建
int network_create_tcp_socket(void);
int network_create_tcp_client_socket(const char *ip, int port);
int network_create_tcp_server_socket(const char *ip, int port, int backlog);

// 数据传输
int network_send_all(int fd, const void *buf, size_t len);
ssize_t network_recv_all(int fd, void *buf, size_t len);
ssize_t network_recv_all_timeout(int fd, void *buf, size_t len, int timeout_ms);

#endif // NETWORK_H

