#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "ids_ioctl.h"

#define MAX_BUFFER 2048

// Limpeza do Buffer do Teclado
void limpar_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Remoção do NewLine
void remover_newline(char *str) {
    str[strcspn(str, "\n")] = 0;
}

void imprimir_menu() {
    printf("\n=========================================\n");
    printf("    MOTOR IDS KERNEL-SPACE - CLI     \n");
    printf("=========================================\n");
    printf("[1] Verificar Status do IDS\n");
    printf("[2] Ligar / Desligar o IDS\n");
    printf("[3] Adicionar Nova Assinatura Maliciosa\n");
    printf("[4] Consultar Assinatura por ID\n");
    printf("[5] Enviar Payload para Análise\n");
    printf("[0] Sair\n");
    printf("=========================================\n");
    printf("Escolha uma opcao: ");
}

int main() {
    int fd, opcao, status, id_busca;
    char input_buffer[MAX_BUFFER];
    struct ids_assinatura sig_req;
    struct ids_payload payload_req;

    fd = open("/dev/ids_engine", O_RDWR);
    if (fd < 0) {
        perror("[-] Erro ao abrir /dev/ids_engine");
        return EXIT_FAILURE;
    }

    printf("[+] Conexão com o módulo estabelecida com sucesso!\n");

    while (1) {
        imprimir_menu();
        
        if (scanf("%d", &opcao) != 1) {
            printf("[-] Entrada inválida.\n");
            limpar_buffer();
            continue;
        }
        limpar_buffer(); // Importante para remover o buffer '\n' residual

        switch (opcao) {
            case 1: // Verificar Status do Módulo
                if (ioctl(fd, IDS_GET_STATUS, &status) < 0) {
                    perror("[-] Erro ao obter status");
                } else {
                    printf("\n[>] STATUS DO IDS: %s\n", status == 1 ? "🟢 LIGADO" : "🔴 DESLIGADO");
                }
                break;

            case 2: // Alterar Status do Módulo
                printf("Digite 1 para LIGAR ou 0 para DESLIGAR: ");
                scanf("%d", &status);
                limpar_buffer();
                
                if (status != 0 && status != 1) {
                    printf("[-] Valor inválido.\n");
                    break;
                }

                if (ioctl(fd, IDS_SET_STATUS, &status) < 0) {
                    perror("[-] Erro ao alterar status");
                } else {
                    printf("\n[+] Status alterado com sucesso!\n");
                }
                break;

            case 3: // Adicionar Assinatura
                printf("Digite a nova assinatura maliciosa: ");
                fgets(input_buffer, MAX_BUFFER, stdin);
                remover_newline(input_buffer);

                sig_req.p_user_ass = input_buffer;
                sig_req.length = strlen(input_buffer);

                if (ioctl(fd, IDS_ADD_SIGNATURE, &sig_req) < 0) {
                    perror("[-] Erro ao adicionar assinatura");
                } else {
                    printf("\n[+] Assinatura '%s' adicionada ao módulo!\n", input_buffer);
                }
                break;

            case 4: // Consultar Assinatura
                printf("Digite o ID da assinatura que deseja buscar: ");
                scanf("%d", &id_busca);
                limpar_buffer();

                sig_req.id = id_busca;
                sig_req.length = MAX_BUFFER; // Tamanho do nosso buffer
                sig_req.p_user_ass = malloc(sig_req.length);

                if (!sig_req.p_user_ass) {
                    printf("[-] Erro de alocação de memória no client.\n");
                    break;
                }

                if (ioctl(fd, IDS_GET_SIGNATURE, &sig_req) < 0) {
                    perror("[-] Erro ao buscar assinatura");
                } else {
                    printf("\n[>] Assinatura ID %d: '%s' (Tamanho no Kernel: %u bytes)\n", 
                           id_busca, sig_req.p_user_ass, sig_req.length);
                }
                
                free(sig_req.p_user_ass);
                break;

            case 5: // Enviar Payload
                printf("Insira o payload a ser inspecionado: ");
                fgets(input_buffer, MAX_BUFFER, stdin);
                remover_newline(input_buffer);

                payload_req.content = input_buffer;
                payload_req.length = strlen(input_buffer);

                printf("\n[*] Enviando payload de %d bytes para o módulo...\n", payload_req.length);
                
                if (ioctl(fd, IDS_ANALYSE, &payload_req) < 0) {
                    perror("[-] Erro na inspeção do payload");
                } else {
                    printf("[+] Inspeção concluída. Verifique o dmesg para alertas de segurança!\n");
                }
                break;

            case 0: // Sair
                printf("\n[+] Encerrando cliente e fechando conexão com o módulo...\n");
                close(fd);
                return EXIT_SUCCESS;

            default:
                printf("\n[-] Opção inválida. Tente novamente.\n");
                break;
        }
    }

    return EXIT_SUCCESS;
}