#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "cJSON.h"

#define PORT 9999
#define QUARANTINE_DIR "./quarantine"

// Структура для хранения параметров запроса
typedef struct {
    int client_socket;
    char *command;
} request_t;

// Очередь запросов
request_t **queue;
int queue_size;
int queue_count = 0;
int queue_head = 0;
int queue_tail = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Обработчик сигнала завершения
void handle_sigint(int sig) {
    printf("\nЗавершение работы сервера\n");
    exit(0);
}

void print_help() {
    printf("Использование:      ./server [опции] <количество потоков>\n\n");
    printf("  -h, --help        Вывод инструкций по использованию\n\n");
}


// Функция для поиска сигнатур в файле
void find_signatures(const char *file_path, const char *signature, int sig_len, int **offsets, int *count, int *res_error) {
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        *res_error = errno;
        perror("fopen");
        return;
    }

    // Определение размера файла
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    // Выделение памяти для чтения файла
    char *buffer = (char *)malloc(file_size + 1);
    if (buffer == NULL) {
        perror("malloc");
        fclose(file);
        return;
    }

    // Чтение содержимого файла в буфер
    size_t readsize = fread(buffer, 1, file_size, file);
    buffer[readsize] = '\0'; // Добавление нулевого символа в конец буфера
    fclose(file);

    *count = 0;
    *offsets = NULL;
    char *pos = buffer;
    while ((pos = strstr(pos, signature)) != NULL) {
        *offsets = realloc(*offsets, (*count + 1) * sizeof(int));
        if (*offsets == NULL) {
            perror("realloc");
            free(buffer);
            return;
        }
        (*offsets)[(*count)++] = pos - buffer;
        pos += sig_len;
    }

    free(buffer);
}


// Функция для перемещения файла в карантин
void move_to_quarantine(const char *file_path, int *res_error) {
    // Получение имени файла из полного пути
    const char *file_name = strrchr(file_path, '/');
    if (file_name) {
        file_name++; // Переход к имени файла после '/'
    } else {
        file_name = file_path; // Если в пути нет '/', то это уже имя файла
    }

    // Формирование нового пути для файла в каталоге карантина
    size_t new_path_size = strlen(QUARANTINE_DIR) + strlen(file_name) + 2;
    char *new_path = malloc(new_path_size);
    if (new_path == NULL) {
        perror("malloc");
        return;
    }
    snprintf(new_path, new_path_size, "%s/%s", QUARANTINE_DIR, file_name);

    // Перемещение файла
    if (rename(file_path, new_path) != 0) {
        *res_error = errno;
        perror("Ошибка перемещения файла в карантин");
    } else {
        printf("Файл %s перемещен в карантин\n", file_path);
    }

    free(new_path);
}


// Обработчик клиента
void *handle_client(void *arg) {
    request_t *req = (request_t *)arg;
    char response[4096] = {0};
    cJSON *response_json = cJSON_CreateObject();
    cJSON *json = cJSON_Parse(req->command);
    if (!json) {
        cJSON_AddStringToObject(response_json, "message", "Ошибка парсинга JSON\n");
    } else {
        const cJSON *command = cJSON_GetObjectItemCaseSensitive(json, "command1");
        const cJSON *params = cJSON_GetObjectItemCaseSensitive(json, "params");

        if (cJSON_IsString(command) && params) {
            if (strcmp(command->valuestring, "CheckLocalFile") == 0) {
                const cJSON *file_path = cJSON_GetObjectItemCaseSensitive(params, "file_path");
                const cJSON *sig_hex = cJSON_GetObjectItemCaseSensitive(params, "signature");
                if (cJSON_IsString(file_path) && cJSON_IsString(sig_hex)) {
                     int sig_len = strlen(sig_hex->valuestring);


                    int *offsets = NULL;
                    int count;
                    int res_error;
                    find_signatures(file_path->valuestring, sig_hex->valuestring, sig_len, &offsets, &count, &res_error);

                    if(res_error != 0) {
                        cJSON_AddStringToObject(response_json, "error", strerror(res_error));
                    }
                    cJSON_AddNumberToObject(response_json, "count", count);
                    cJSON *offsets_json = cJSON_AddArrayToObject(response_json, "offsets");
                    for (int i = 0; i < count; i++) {
                        cJSON_AddItemToArray(offsets_json, cJSON_CreateNumber(offsets[i]));
                    }

                    free(offsets);
                } else {
                    cJSON_AddStringToObject(response_json, "message", "Неверные параметры");
                }
            } else if (strcmp(command->valuestring, "QuarantineLocalFile") == 0) {
                const cJSON *file_path = cJSON_GetObjectItemCaseSensitive(params, "file_path");
                if (cJSON_IsString(file_path)) {
                    int res_error;

                    move_to_quarantine(file_path->valuestring, &res_error);
                    if (errno != 0) {
                        cJSON_AddStringToObject(response_json, "error", strerror(res_error));
                    } else {
                        cJSON_AddStringToObject(response_json, "message", "Файл перемещен в карантин");
                    }
                } else {
                    cJSON_AddStringToObject(response_json, "message", "Неверные параметры");
                }
            } else {
                cJSON_AddStringToObject(response_json, "message", "Неизвестная команда");
            }
        } else {
            cJSON_AddStringToObject(response_json, "message", "Неверные параметры");
        }
        char *response_str = cJSON_Print(response_json);
        snprintf(response, sizeof(response), "%s\n", response_str);
        cJSON_Delete(json);
        free(response_str);
    }

    send(req->client_socket, response, strlen(response), 0);
    close(req->client_socket);
    free(req->command);
    free(req);
    return NULL;
}

// Пул потоков
void *thread_pool(void *arg) {
    while (1) {
        pthread_mutex_lock(&queue_mutex);

        while (queue_count == 0) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }

        request_t *req = queue[queue_head];
        queue_head = (queue_head + 1) % queue_size;
        queue_count--;

        pthread_mutex_unlock(&queue_mutex);

        handle_client(req);
    }
    return NULL;
}

// Инициализация очереди и пула потоков
void init_thread_pool(int num_threads) {
    pthread_t threads[num_threads];
    queue_size = num_threads * 2;
    queue = malloc(queue_size * sizeof(request_t *));

    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, thread_pool, NULL);
    }
}

int main(int argc, char *argv[]) {
    int c;
    int option_index = 0;
    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "h", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                print_help();
            return EXIT_SUCCESS;
            case '?':
                return EXIT_FAILURE;
            default:
                abort();
        }
    }

    if (argc < 2) {
        fprintf(stderr, "Использование: %s <количество потоков>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int num_threads = atoi(argv[1]);
    signal(SIGINT, handle_sigint);

    if (mkdir(QUARANTINE_DIR, 0777) && errno != EEXIST) {
        perror("Ошибка создания каталога карантина");
        exit(EXIT_FAILURE);
    }

    int server_socket, *new_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Ошибка при создании сокета");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка привязки");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Ошибка при прослушивании");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Сервер запущен и ожидает подключений...\n");

    init_thread_pool(num_threads);

    while (1) {
        new_sock = malloc(sizeof(int));
        *new_sock = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (*new_sock < 0) {
            perror("Ошибка при принятии подключения");
            free(new_sock);
            continue;
        }

        pthread_mutex_lock(&queue_mutex);
        queue[queue_tail] = malloc(sizeof(request_t));
        queue[queue_tail]->client_socket = *new_sock;
        queue[queue_tail]->command = malloc(4096);
        recv(*new_sock, queue[queue_tail]->command, 4096, 0);
        queue_tail = (queue_tail + 1) % queue_size;
        queue_count++;
        pthread_cond_signal(&queue_cond);
        pthread_mutex_unlock(&queue_mutex);
    }

    close(server_socket);
    return 0;
}
