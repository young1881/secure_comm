#include "../include/network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

// 创建TCP socket
int network_create_tcp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// 创建TCP客户端socket并连接
int network_create_tcp_client_socket(const char *ip, int port) {
    int sockfd = network_create_tcp_socket();
    if (sockfd < 0) {
        return -1;
    }
    
    int flag = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag)) < 0) {
        perror("setsockopt TCP_NODELAY failed");
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_aton(ip, &server_addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid server IP address: %s\n", ip);
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("tcp connect failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// 创建TCP服务器socket
int network_create_tcp_server_socket(const char *ip, int port, int backlog) {
    int sockfd = network_create_tcp_socket();
    if (sockfd < 0) {
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_aton(ip, &addr.sin_addr) == 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(sockfd);
        return -1;
    }
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, backlog) < 0) {
        perror("listen failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// 发送所有数据
int network_send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

// 接收所有数据
ssize_t network_recv_all(int fd, void *buf, size_t len) {
    char *p = (char *)buf;
    size_t total = 0;
    
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return total;  // 连接关闭
        }
        total += (size_t)n;
    }
    
    return (ssize_t)total;
}

// 带超时的接收所有数据
ssize_t network_recv_all_timeout(int fd, void *buf, size_t len, int timeout_ms) {
    char *p = (char *)buf;
    size_t total = 0;
    
    while (total < len) {
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        int ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (ret == 0) {
            return total;  // 超时
        }
        
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return total;  // 连接关闭
        }
        total += (size_t)n;
    }
    
    return (ssize_t)total;
}

