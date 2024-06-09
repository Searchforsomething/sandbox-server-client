# Указываем компилятор
CC = gcc

# Опции линковки
LDFLAGS = -pthread

# Исходные файлы
SERVER_SRC = server.c cJSON.c
CLIENT_SRC = client.c cJSON.c

# Исполняемые файлы
SERVER_EXEC = server
CLIENT_EXEC = client

# Правило по умолчанию
all: $(SERVER_EXEC) $(CLIENT_EXEC)

# Правила компиляции и линковки для сервера
$(SERVER_EXEC): $(SERVER_SRC)
	$(CC) $(SERVER_SRC) -o $(SERVER_EXEC) $(LDFLAGS)

# Правила компиляции и линковки для клиента
$(CLIENT_EXEC): $(CLIENT_SRC)
	$(CC) $(CLIENT_SRC) -o $(CLIENT_EXEC) $(LDFLAGS)

# Правило очистки
clean:
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC) *.o

.PHONY: all clean
