CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lssl -lcrypto
INCLUDES = -I./include
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# 源文件
KEX_SRC = $(SRC_DIR)/kex.c
CIPHER_SRC = $(SRC_DIR)/cipher.c
SIGN_SRC = $(SRC_DIR)/sign.c
NETWORK_SRC = $(SRC_DIR)/network.c
SERVER_SRC = $(SRC_DIR)/secure_server.c
CLIENT_SRC = $(SRC_DIR)/secure_client.c
TEST_KEX_SRC = $(SRC_DIR)/test_kex.c
TEST_CIPHER_SRC = $(SRC_DIR)/test_cipher.c
TEST_SIGN_SRC = $(SRC_DIR)/test_sign.c
TEST_KEX_CLIENT_SRC = $(SRC_DIR)/test_kex_client.c
TEST_KEX_SERVER_SRC = $(SRC_DIR)/test_kex_server.c
TEST_CIPHER_CLIENT_SRC = $(SRC_DIR)/test_cipher_client.c
TEST_CIPHER_SERVER_SRC = $(SRC_DIR)/test_cipher_server.c

# 目标文件
KEX_OBJ = $(OBJ_DIR)/kex.o
CIPHER_OBJ = $(OBJ_DIR)/cipher.o
SIGN_OBJ = $(OBJ_DIR)/sign.o
NETWORK_OBJ = $(OBJ_DIR)/network.o
SERVER_OBJ = $(OBJ_DIR)/secure_server.o
CLIENT_OBJ = $(OBJ_DIR)/secure_client.o
TEST_KEX_OBJ = $(OBJ_DIR)/test_kex.o
TEST_CIPHER_OBJ = $(OBJ_DIR)/test_cipher.o
TEST_SIGN_OBJ = $(OBJ_DIR)/test_sign.o
TEST_KEX_CLIENT_OBJ = $(OBJ_DIR)/test_kex_client.o
TEST_KEX_SERVER_OBJ = $(OBJ_DIR)/test_kex_server.o
TEST_CIPHER_CLIENT_OBJ = $(OBJ_DIR)/test_cipher_client.o
TEST_CIPHER_SERVER_OBJ = $(OBJ_DIR)/test_cipher_server.o

# 可执行文件
SERVER_BIN = $(BIN_DIR)/secure_server
CLIENT_BIN = $(BIN_DIR)/secure_client
TEST_KEX_BIN = $(BIN_DIR)/test_kex
TEST_CIPHER_BIN = $(BIN_DIR)/test_cipher
TEST_SIGN_BIN = $(BIN_DIR)/test_sign
TEST_KEX_CLIENT_BIN = $(BIN_DIR)/test_kex_client
TEST_KEX_SERVER_BIN = $(BIN_DIR)/test_kex_server
TEST_CIPHER_CLIENT_BIN = $(BIN_DIR)/test_cipher_client
TEST_CIPHER_SERVER_BIN = $(BIN_DIR)/test_cipher_server

.PHONY: all clean directories test test_all

all: directories $(SERVER_BIN) $(CLIENT_BIN)

test: directories $(TEST_KEX_BIN) $(TEST_CIPHER_BIN) $(TEST_SIGN_BIN)

test_all: directories $(TEST_KEX_CLIENT_BIN) $(TEST_KEX_SERVER_BIN) $(TEST_CIPHER_CLIENT_BIN) $(TEST_CIPHER_SERVER_BIN)

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 服务器和客户端
$(SERVER_BIN): $(SERVER_OBJ) $(KEX_OBJ) $(CIPHER_OBJ) $(SIGN_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_OBJ) $(KEX_OBJ) $(CIPHER_OBJ) $(SIGN_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 本地测试程序（不需要网络）
$(TEST_KEX_BIN): $(TEST_KEX_OBJ) $(KEX_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_CIPHER_BIN): $(TEST_CIPHER_OBJ) $(CIPHER_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_SIGN_BIN): $(TEST_SIGN_OBJ) $(SIGN_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 网络测试程序（可以与TC3实时测试）
$(TEST_KEX_CLIENT_BIN): $(TEST_KEX_CLIENT_OBJ) $(KEX_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_KEX_SERVER_BIN): $(TEST_KEX_SERVER_OBJ) $(KEX_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_CIPHER_CLIENT_BIN): $(TEST_CIPHER_CLIENT_OBJ) $(KEX_OBJ) $(CIPHER_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(TEST_CIPHER_SERVER_BIN): $(TEST_CIPHER_SERVER_OBJ) $(KEX_OBJ) $(CIPHER_OBJ) $(NETWORK_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install: all
	@echo "Installing binaries..."
	@mkdir -p /usr/local/bin
	@cp $(SERVER_BIN) /usr/local/bin/
	@cp $(CLIENT_BIN) /usr/local/bin/
	@echo "Installation complete!"

uninstall:
	@echo "Uninstalling binaries..."
	@rm -f /usr/local/bin/secure_server
	@rm -f /usr/local/bin/secure_client
	@echo "Uninstallation complete!"
