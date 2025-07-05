# === Configuración ===
CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = `pkg-config --libs --cflags openssl`
SRC_DIR = src
OBJ_DIR = build
BIN = server_tls

# === Fuentes y objetos ===
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# === Regla principal ===
all: $(BIN)

# === Enlazado final ===
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# === Compilación de objetos ===
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# === Limpieza ===
clean:
	rm -rf $(OBJ_DIR) $(BIN)

.PHONY: all clean
