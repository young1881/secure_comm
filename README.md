# Orin-TC3 加密通信项目

本项目实现了 Orin 与 TC3 之间的安全加密通信。

## 设计特点

- ✅ **模块化设计**：密钥交换、加解密、签名验签功能独立，降低耦合度
- ✅ **简化功能**：
  - 服务器端：只负责解密和验签
  - 客户端：只负责加密和签名
- ✅ **独立测试**：每个功能模块都可以单独测试
- ✅ **易于扩展**：各模块接口清晰，便于修改和扩展

## 功能模块

### 1. 密钥交换模块 (kex.h/c)
- ECDH-P256 / ECDH-P384 密钥交换
- 密钥对生成、公钥导出/导入
- 共享密钥派生
- 对称密钥派生

### 2. 加解密模块 (cipher.h/c)
- AES-128-GCM / AES-256-GCM
- AES-128-CBC / AES-256-CBC
- ChaCha20-Poly1305
- 加密/解密接口

### 3. 签名验签模块 (sign.h/c)
- ECDSA-P256 / ECDSA-P384
- 密钥对生成、公钥导出/导入
- 签名/验签接口

### 4. 网络模块 (network.h/c)
- TCP socket 创建和管理
- 数据传输函数

## 项目结构

```
secure_comm/
├── include/
│   ├── kex.h          # 密钥交换模块头文件
│   ├── cipher.h       # 加解密模块头文件
│   ├── sign.h         # 签名验签模块头文件
│   └── network.h      # 网络模块头文件
├── src/
│   ├── kex.c          # 密钥交换实现
│   ├── cipher.c       # 加解密实现
│   ├── sign.c         # 签名验签实现
│   ├── network.c      # 网络功能实现
│   ├── secure_server.c    # 服务器端（解密+验签）
│   ├── secure_client.c    # 客户端（加密+签名）
│   ├── test_kex.c     # 密钥交换测试程序
│   ├── test_cipher.c  # 加解密测试程序
│   └── test_sign.c    # 签名验签测试程序
├── Makefile           # 编译脚本
└── README.md          # 说明文档
```

## 依赖要求

- **OpenSSL 库**：用于加密、密钥交换和签名功能
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libssl-dev
  
  # 验证 OpenSSL 版本
  openssl version
  ```

- **编译工具**：GCC 编译器

## 编译

```bash
cd secure_comm

# 编译服务器和客户端
make

# 编译测试程序
make test

# 清理编译文件
make clean
```

编译后的可执行文件位于 `bin/` 目录：

**完整功能程序：**
- `bin/secure_server` - 加密通信服务器程序（解密+验签）
- `bin/secure_client` - 加密通信客户端程序（加密+签名）

**本地测试程序（不需要网络）：**
- `bin/test_kex` - 密钥交换本地测试
- `bin/test_cipher` - 加解密本地测试
- `bin/test_sign` - 签名验签本地测试

**网络测试程序（可与TC3实时测试）：**
- `bin/test_kex_server` - 密钥交换测试服务器
- `bin/test_kex_client` - 密钥交换测试客户端
- `bin/test_cipher_server` - 密钥交换+加解密测试服务器
- `bin/test_cipher_client` - 密钥交换+加解密测试客户端

## 独立测试各功能模块

这些测试工具可以与TC3进行实时网络通信测试，可以单独测试各个功能模块：

### 1. 只测试密钥交换

**服务器端：**
```bash
./bin/test_kex_server -i 0.0.0.0 -p 8888 -k ecdhp256
```

**客户端：**
```bash
./bin/test_kex_client -i <服务器IP> -p 8888 -k ecdhp256
```

测试内容：
- 密钥对生成
- 公钥交换
- 共享密钥派生
- 对称密钥派生

### 2. 测试密钥交换 + 加解密

**服务器端：**
```bash
./bin/test_cipher_server -i 0.0.0.0 -p 8888 -k ecdhp256 -c aes256gcm
```

**客户端：**
```bash
./bin/test_cipher_client -i <服务器IP> -p 8888 -k ecdhp256 -c aes256gcm -m "Test message"
```

测试内容：
- 密钥交换（ECDH）
- 从共享密钥派生对称密钥
- 消息加密
- 消息解密

### 3. 测试签名验签（完整流程）

使用原始的 `secure_server` 和 `secure_client`，它们包含密钥交换+加解密+签名验签的完整流程。

## 使用服务器和客户端

### 准备工作

在使用服务器和客户端之前，需要准备密钥和密钥文件：

#### 1. 生成密钥对（用于签名）

```bash
# 生成 ECDSA-P256 密钥对
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem

# 或者生成 ECDSA-P384 密钥对
openssl ecparam -genkey -name secp384r1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

#### 2. 准备加密密钥和IV

密钥和IV需要是十六进制字符串格式。例如：
- AES-256-GCM: 密钥64个十六进制字符（32字节），IV 24-32个十六进制字符（12-16字节）
- AES-128-GCM: 密钥32个十六进制字符（16字节），IV 24-32个十六进制字符（12-16字节）

可以使用以下命令生成随机密钥和IV：

```bash
# 生成32字节密钥（64个十六进制字符）
openssl rand -hex 32

# 生成16字节IV（32个十六进制字符）
openssl rand -hex 16
```

### 启动服务器

服务器负责解密和验签：

```bash
# 基本用法
./bin/secure_server -i 0.0.0.0 -p 8888 \
    -c aes256gcm \
    -s ecdsap256 \
    -k <64位十六进制密钥> \
    -v <32位十六进制IV> \
    -K public_key.pem

# 完整示例
./bin/secure_server -i 0.0.0.0 -p 8888 \
    -c aes256gcm \
    -s ecdsap256 \
    -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    -v 0123456789abcdef0123456789abcdef \
    -K public_key.pem
```

### 启动客户端

客户端负责加密和签名：

```bash
# 基本用法
./bin/secure_client -i 192.168.1.100 -p 8888 \
    -c aes256gcm \
    -s ecdsap256 \
    -k <64位十六进制密钥> \
    -v <32位十六进制IV> \
    -K private_key.pem \
    -m "Hello from client!"

# 完整示例
./bin/secure_client -i 192.168.1.100 -p 8888 \
    -c aes256gcm \
    -s ecdsap256 \
    -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    -v 0123456789abcdef0123456789abcdef \
    -K private_key.pem \
    -m "This is a secure message"
```

### 命令行参数

#### secure_server

- `-h` : 显示帮助信息
- `-i <ip>` : 指定绑定的IP地址（默认: 0.0.0.0）
- `-p <port>` : 指定监听端口（默认: 8888）
- `-c <cipher>` : 指定加密算法
  - `aes128gcm` - AES-128-GCM
  - `aes256gcm` - AES-256-GCM（推荐）
  - `aes128cbc` - AES-128-CBC
  - `aes256cbc` - AES-256-CBC
  - `chacha20` - ChaCha20-Poly1305
- `-s <sign>` : 指定签名算法
  - `ecdsap256` - ECDSA-P256（推荐）
  - `ecdsap384` - ECDSA-P384
- `-k <key>` : 加密密钥（十六进制字符串，必需）
- `-v <iv>` : 初始化向量（十六进制字符串，必需）
- `-K <pubkey>` : 签名公钥文件（PEM格式，必需）

#### secure_client

- `-h` : 显示帮助信息
- `-i <ip>` : 指定服务器IP地址（默认: 192.168.1.100）
- `-p <port>` : 指定服务器端口（默认: 8888）
- `-c <cipher>` : 指定加密算法（同服务器）
- `-s <sign>` : 指定签名算法（同服务器）
- `-k <key>` : 加密密钥（十六进制字符串，必需）
- `-v <iv>` : 初始化向量（十六进制字符串，必需）
- `-K <privkey>` : 签名私钥文件（PEM格式，必需）
- `-m <message>` : 要发送的消息（默认: "Hello from secure client!"）

## 重要说明

### 当前 secure_server 和 secure_client 的行为

按照README中示例的方式启动 `secure_server` 和 `secure_client` 会发生：

1. **服务器端行为**：
   - 启动后监听指定端口，等待客户端连接
   - 接收到客户端连接后，进入循环等待接收 `PKT_TYPE_ENCRYPTED_SIGNED` 类型的数据包
   - 收到数据包后：
     - 先验证签名（验签）
     - 然后解密数据（解密）
     - 打印解密后的消息
   - **服务器不会发送响应**，只是接收和打印消息
   - 可以接收多个客户端的连接（每次连接处理完就断开）

2. **客户端行为**：
   - 连接到服务器
   - 使用命令行参数提供的密钥加密消息
   - 使用命令行参数提供的私钥签名
   - 发送数据包到服务器
   - **发送完成后立即退出**，不等待服务器响应

**注意**：这种方式需要手动提供密钥和IV，**不包含密钥交换流程**。如果需要测试完整的密钥交换功能，请使用下面的网络测试工具。

### 推荐使用方式

**如果需要单独测试各个功能模块，推荐使用网络测试工具：**

- **只测试密钥交换**：使用 `test_kex_server` 和 `test_kex_client`
- **测试密钥交换+加解密**：使用 `test_cipher_server` 和 `test_cipher_client`
- **完整功能（加解密+签名）**：使用 `secure_server` 和 `secure_client`

## 使用示例

### 示例1：只测试密钥交换

**终端1 - 启动密钥交换服务器：**
```bash
./bin/test_kex_server -i 0.0.0.0 -p 8888 -k ecdhp256
```

**终端2 - 启动密钥交换客户端：**
```bash
./bin/test_kex_client -i 192.168.1.100 -p 8888 -k ecdhp256
```

### 示例2：测试密钥交换 + 加解密

**终端1 - 启动加解密服务器：**
```bash
./bin/test_cipher_server -i 0.0.0.0 -p 8888 -k ecdhp256 -c aes256gcm
```

**终端2 - 启动加解密客户端：**
```bash
./bin/test_cipher_client -i 192.168.1.100 -p 8888 -k ecdhp256 -c aes256gcm -m "Hello TC3!"
```

### 示例3：基本加密通信（完整功能，需要手动提供密钥）

**终端1 - 生成密钥对：**
```bash
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem

# 生成密钥和IV
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
echo "Key: $KEY"
echo "IV: $IV"
```

**终端2 - 启动服务器：**
```bash
./bin/secure_server -i 0.0.0.0 -p 8888 \
    -c aes256gcm -s ecdsap256 \
    -k $KEY -v $IV -K public_key.pem
```

**终端3 - 启动客户端：**
```bash
./bin/secure_client -i 127.0.0.1 -p 8888 \
    -c aes256gcm -s ecdsap256 \
    -k $KEY -v $IV -K private_key.pem \
    -m "Hello, this is a secure message!"
```

### 示例2：测试各个模块

```bash
# 测试密钥交换
./bin/test_kex p256

# 测试加解密
./bin/test_cipher aes256gcm

# 测试签名验签
./bin/test_sign p256
```

## 模块接口说明

### 密钥交换模块 (kex.h)

```c
// 初始化/清理
int kex_ctx_init(kex_ctx_t *ctx, kex_type_t type);
int kex_ctx_cleanup(kex_ctx_t *ctx);

// 密钥生成和交换
int kex_generate_keypair(kex_ctx_t *ctx);
int kex_export_public_key(kex_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len);
int kex_import_peer_public_key(kex_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len);
int kex_derive_shared_secret(kex_ctx_t *ctx);
int kex_derive_symmetric_key(kex_ctx_t *ctx, int key_len, int iv_len, 
                             unsigned char *key, unsigned char *iv);
```

### 加解密模块 (cipher.h)

```c
// 初始化/清理
int cipher_ctx_init(cipher_ctx_t *ctx, cipher_type_t type, 
                    const unsigned char *key, const unsigned char *iv);
int cipher_ctx_cleanup(cipher_ctx_t *ctx);

// 加密/解密
int cipher_encrypt(cipher_ctx_t *ctx, const unsigned char *plaintext, size_t plaintext_len,
                   unsigned char *ciphertext, size_t *ciphertext_len, unsigned char *tag);
int cipher_decrypt(cipher_ctx_t *ctx, const unsigned char *ciphertext, size_t ciphertext_len,
                   const unsigned char *tag, unsigned char *plaintext, size_t *plaintext_len);
```

### 签名验签模块 (sign.h)

```c
// 初始化/清理
int sign_ctx_init(sign_ctx_t *ctx, sign_type_t type);
int sign_ctx_cleanup(sign_ctx_t *ctx);

// 密钥生成和交换
int sign_generate_keypair(sign_ctx_t *ctx);
int sign_export_public_key(sign_ctx_t *ctx, unsigned char *pubkey, size_t *pubkey_len);
int sign_import_peer_public_key(sign_ctx_t *ctx, const unsigned char *pubkey, size_t pubkey_len);

// 签名/验签
int sign_data(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
              unsigned char *signature, size_t *signature_len);
int verify_signature(sign_ctx_t *ctx, const unsigned char *data, size_t data_len,
                     const unsigned char *signature, size_t signature_len);
```

## 注意事项

1. **密钥匹配**：客户端和服务器必须使用相同的加密密钥和IV
2. **密钥对匹配**：客户端的私钥必须与服务器的公钥对应
3. **算法匹配**：客户端和服务器必须使用相同的加密算法和签名算法
4. **IV更新**：每次加密应该使用新的IV（客户端会自动生成）
5. **网络配置**：确保 Orin 和 TC3 在同一网络中，且防火墙允许相应端口通信

## 故障排除

1. **编译错误**：确保已安装 `libssl-dev`
2. **连接失败**：检查网络连接和防火墙设置
3. **解密失败**：检查密钥和IV是否匹配
4. **验签失败**：检查公钥和私钥是否匹配
5. **密钥格式错误**：确保密钥和IV是十六进制字符串格式

## 许可证

本项目仅供学习和研究使用。
