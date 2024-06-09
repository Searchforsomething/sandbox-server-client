#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "cJSON.h"
#include <getopt.h>

#define PORT 9999
#define BUF_SIZE 4096

void print_help(){
    printf("Использование: ./client [опции] <команда> <параметры>\n\n");
    printf("===================================== Команды =====================================\n\n");
    printf("CheckLocalFile         Проверяет указанный в запросе файл на сигнатуру\n");
    printf("                       Использование: \n");
    printf("                       ./client CheckLocalFile file_path=<путь к файлу> signature=<сигнатура>\n\n");
    printf("QuarantineLocalFile    Перемещает указанный файл в карантин\n");
    printf("                       Использование: \n");
    printf("                       ./client QuarantineLocalFile file_path=<путь к файлу>\n\n");
    printf("====================================== Опции ======================================\n\n");
    printf("  -h, --help           Вывод инструкций по использованию\n\n");
}


void send_command(const char *command, int param_count, char **params) {
    int client_socket;
    struct sockaddr_in server_addr;


    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Ошибка при создании сокета");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Неверный адрес/Адрес не поддерживается");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка подключения");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "command1", command);
    cJSON *params_json = cJSON_CreateObject();

    for (int i = 0; i < param_count; i++) {
        char *param_copy = strdup(params[i]);
        char *param_name = strtok(param_copy, "=");
        char *param_value = strtok(NULL, "=");
        if (param_name && param_value) {
            cJSON_AddStringToObject(params_json, param_name, param_value);
        }
        free(param_copy);
    }

    cJSON_AddItemToObject(json, "params", params_json);

    char *json_str = cJSON_Print(json);
    send(client_socket, json_str, strlen(json_str), 0);
    cJSON_Delete(json);
    free(json_str);

	char response[4096] = {0};
    recv(client_socket, response, sizeof(response), 0);


    printf("Ответ от сервера: \n");

    cJSON *response_json = cJSON_Parse(response);
    if (command == "CheckLocalFile" && response_json == NULL) {
        perror("Ошибка парсинга JSON ответа");
        close(client_socket);
        return;
    }

    cJSON *message = cJSON_GetObjectItemCaseSensitive(response_json, "message");
    if (cJSON_IsString(message)) {
        printf("Сообщение: %s\n", message->valuestring);
    }
    cJSON *error = cJSON_GetObjectItemCaseSensitive(response_json, "error");
    if (cJSON_IsString(error)) {
        printf("Ошибка: %s\n", error->valuestring);
        return;
    }
    cJSON *count = cJSON_GetObjectItemCaseSensitive(response_json, "count");
    if (cJSON_IsNumber(count)) {
        printf("Количество вхождений: \n%d\n", count->valueint);

        cJSON *offsets = cJSON_GetObjectItemCaseSensitive(response_json, "offsets");
        if (cJSON_IsArray(offsets)) {
            int array_size = cJSON_GetArraySize(offsets);
            printf("Смещения:\n");
            for (int i = 0; i < array_size; i++) {
                cJSON *offset = cJSON_GetArrayItem(offsets, i);
                if (cJSON_IsNumber(offset)) {
                    printf("%d\n", offset->valueint);
                }
            }
        }
    }
    cJSON_Delete(response_json);
    close(client_socket);
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

    if (argc < 3) {
        fprintf(stderr, "Использование: %s <команда> <параметры>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    send_command(argv[1], argc - 2, &argv[2]);

    return 0;
}
