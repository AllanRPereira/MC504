#ifndef IDS_IOCTL_H
#define IDS_IOCTL_H

#include <linux/ioctl.h>

/* 
 * Primeiro definir um "Magic Number", um identificador único para 
 * o módulo IDS
 */
#define IDS_MAGIC 'I'

/*  
 * _IOW = Para escrita de dados do User-space para o Kernel-Space
 * _IOR = Leitura de dados do Kernel para o nível de Usuário
 * Argumentos: (Magic Number, Número do Comando, Tipo de Dado)
 */

// Struct para receber as assinaturas de modo flexível quanto ao tamanho
struct ids_assinatura {
    int id;             // No caso de GET de uma assinatura
    char *p_user_ass;
    unsigned int length;
};

// Struct para recebimento do payload para análise
struct ids_payload {
    char *content;
    int length;
};

#define IDS_GET_STATUS    _IOR(IDS_MAGIC, 1, int)
#define IDS_SET_STATUS    _IOW(IDS_MAGIC, 2, int)
#define IDS_ADD_SIGNATURE   _IOW(IDS_MAGIC, 3, struct ids_assinatura)
#define IDS_GET_SIGNATURE   _IOWR(IDS_MAGIC, 4, struct ids_assinatura)
#define IDS_ANALYSE         _IOW(IDS_MAGIC, 5, struct ids_payload)

#endif