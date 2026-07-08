#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define __NR_set_crypto_xor_key 472
#define __NR_crypto_xor 473

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char* argv[])
{
    int ret;

    if (argc == 3) {
        if (!strcmp("-k", argv[1])) {
            // Definir uma nova chave para o sistema          
            ret = syscall(__NR_set_crypto_xor_key, argv[2], strlen(argv[2]));
            if (ret) {
                printf("Falha na definição da chave. Erro: %d\n", ret);
                return ret;
            }
            printf("Nova chave configurada!\n");

        } else {
            printf("Opções inválidas!");
            return -1;
        }
    } else if (argc == 2) {
        int len_content = strlen(argv[1]);
        int size_hex = len_content / 2;

        if (len_content % 2 != 0) {
            printf("Hexadecimal inválido\n");
            return -3;
        }
        // Converte a chave hexadecimal para valores em inteiros
        char content_hex[size_hex];
        for (int i = 0, j = 0; i < len_content - 1; i += 2, j++) {
            content_hex[j] = (unsigned char) (hex_char_to_int(argv[1][i]) << 4) + hex_char_to_int(argv[1][i+1]);
        }

        char *buffer = malloc(size_hex * sizeof(char));
        if (!buffer) {
            printf("Não há memória o bastante!");
            return -2;
        }
        ret = syscall(__NR_crypto_xor, content_hex, buffer, size_hex);
        if (ret) {
            printf("Falha na criptografia do conteúdo. Erro: %d\n", ret);
            return ret;
        }
        for (int i = 0; i < size_hex; i++) {
            printf("%02X", (unsigned char)buffer[i]);
        }
        printf("\n");
    } else {
        printf("Para usar o software:\nCriptografar uma mensagem: ./crypto CONTEUDO\nPara mudar a chave salva no sistema: ./crypto -k NEW_KEY\n");
    }
 
    return 0;
}
