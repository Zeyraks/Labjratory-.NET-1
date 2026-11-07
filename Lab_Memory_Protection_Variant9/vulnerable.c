
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 96

void print_secret_flag(void) {
    printf("[!] СЕКРЕТНА ФУНКЦІЯ ВИКЛИКАНА: "
           "SECRET_DATA_LEAKED_942A5795\n");
}

void vulnerable_function(const char *input) {
    char buffer[BUFFER_SIZE];

    printf("Адреса буфера: %p\n", (void *)buffer);
    printf("Адреса функції print_secret_flag: %p\n",
           (void *)print_secret_flag);

    size_t input_length = strlen(input);

    if (input_length >= sizeof(buffer)) {
        printf("[!] Відхилено: вхідний рядок завеликий "
               "(%zu байт, максимум %zu байт).\n",
               input_length, sizeof(buffer) - 1);
        return;
    }

    memcpy(buffer, input, input_length + 1);

    printf("Скопійовано у буфер: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Використання: %s <рядок_для_копіювання>\n",
               argv[0]);
        return 1;
    }

    printf("=== Дослідження захисту пам'яті ===\n");
    printf("Варіант №9\n");
    printf("Розмір буфера: %d байт\n", BUFFER_SIZE);
    printf("Довжина вхідного рядка: %zu байт\n",
           strlen(argv[1]));

    vulnerable_function(argv[1]);

    printf("Функція завершилась нормально.\n");
    return 0;
}
