#!/bin/bash

# 加密通信测试脚本
# 用于在同一台机器上测试加密通信功能

PORT=8888
SERVER_IP="127.0.0.1"

echo "=== Secure Communication Test ==="
echo ""

# 检查可执行文件是否存在
if [ ! -f "./bin/secure_server" ] || [ ! -f "./bin/secure_client" ]; then
    echo "Error: Executables not found. Please run 'make' first."
    exit 1
fi

# 检查OpenSSL是否可用
if ! command -v openssl &> /dev/null; then
    echo "Warning: OpenSSL command not found, but library should be available."
fi

echo "Starting server in background..."
./bin/secure_server -i $SERVER_IP -p $PORT &
SERVER_PID=$!

# 等待服务器启动
sleep 2

echo "Starting client..."
./bin/secure_client -i $SERVER_IP -p $PORT -m "Test message from secure client"

# 清理
echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "Test completed!"

