#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/textsearch.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include "ids_ioctl.h"

// Lista ligada de assinaturas maliciosas armazenadas no driver
typedef struct ids_node {
    int id;
    char *assinatura;
    unsigned int length;
    struct ts_config *conf;
    struct ids_node *next;

} ids_node;

// Quantidades de assinaturas existentes
static int counter_assinaturas = 0;

// Lista Ligada para controles das regras de detecçao
static ids_node *lista_assinaturas = NULL;

// Variavel de controle interna do IDS (0 = Desligado, 1 = Ligado)
static int ids_state = 0; 


// Funçao que analisa um conteúdo de texto com as regras armazenadas
static void analyse_payload(const char *user_buffer, unsigned int buf_len) {
    struct ts_state state;
    unsigned int pos;
    unsigned int found = 0;

    if (ids_state == 0) {
        // IDS Desligado
        pr_info("IDS: O sistema de IDS esta desligado!\n");
        return;
    }

    for (ids_node *regra = lista_assinaturas; regra != NULL; regra = regra->next) {

        pos = textsearch_find_continuous(regra->conf, &state, user_buffer, buf_len);

        if (pos != UINT_MAX) {
            pr_alert("IDS [ALERTA]: Assinatura maliciosa detectada para %s no Offset %u!\n", regra->assinatura, pos);
            found += 1;
        }
    }

    if (!found) {
        pr_info("IDS: Payload inspecionado e considerado limpo!\n");
    } else {
        pr_alert("IDS: Foram encontradas %u ocorrências de assinaturas para o payload %s!!\n", found, user_buffer);
    }

}

// Funçao que processa os comandos ioctl recebidos e interage com o modulo
static long ids_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int user_val;
    struct ids_assinatura new_assinatura;
    struct ids_payload req_payload;
    char *kernel_buffer;        // Lidar com a string da assinatura
    int found = 0;

    switch (cmd) {
        case IDS_SET_STATUS:
            if (copy_from_user(&user_val, (int __user *)arg, sizeof(user_val))) {
                pr_err("IDS: Nao foi possivel obter buffer do usuario!\n");
                return -EFAULT;
            }
            ids_state = user_val;
            pr_info("IDS: Estado alterado com sucesso!\n");
            break;

        case IDS_GET_STATUS:

            if (copy_to_user((int __user *)arg, &ids_state, sizeof(ids_state))) {
                pr_err("IDS: Nao foi possivel enviar estado para o usuario!\n");
                return -EFAULT;
            }
            pr_info("IDS: Estado enviado com sucesso!\n");
            break;

        case IDS_ADD_SIGNATURE:
            if (copy_from_user(&new_assinatura, (struct ids_assinatura __user *)arg, sizeof(new_assinatura))) {
                pr_err("IDS: Nao foi possivel obter buffer do userspace!\n");
                return -EFAULT;
            }

            // Verificaçoes de tamanho da nossa Assinatura
            if (new_assinatura.length == 0 || new_assinatura.length > 4096) {
                pr_err("IDS: Tamanho da assinatura e invalido!\n");
                return -EINVAL;
            }

            kernel_buffer = kmalloc(new_assinatura.length + 1, GFP_KERNEL);
            if (!kernel_buffer) {
                pr_err("IDS: Nao foi possivel alocar memoria suficiente no kernelspace!\n");
                return -ENOMEM; 
            }

            if (copy_from_user(kernel_buffer, (char __user *)new_assinatura.p_user_ass, new_assinatura.length)) {
                kfree(kernel_buffer);
                pr_err("IDS: Falha ao copiar string da assinatura para o Kernel!\n");
                return -EFAULT;
            }

            kernel_buffer[new_assinatura.length] = '\0';

            pr_info("IDS: Regra dinâmica carregada: %s\n", kernel_buffer);

            // Adiçao da nova assinatura à lista ligada

            ids_node *new_ids_node = kmalloc(sizeof(ids_node), GFP_KERNEL);
            if (!new_ids_node) {
                pr_err("IDS: Nao foi possivel criar uma novo no, falta de memoria\n");
                kfree(kernel_buffer);
                return -ENOMEM;
            }

            new_ids_node->assinatura = kernel_buffer;
            new_ids_node->length = new_assinatura.length;
            
            new_ids_node->conf = textsearch_prepare("bm", kernel_buffer, new_assinatura.length, GFP_KERNEL, TS_AUTOLOAD);
            if (IS_ERR(new_ids_node->conf)) {
                pr_err("IDS: Falha ao carregar o algoritmo de textsearch\n");
                kfree(kernel_buffer); kfree(new_ids_node);
                return PTR_ERR(new_ids_node->conf);
            }

            new_ids_node->next = lista_assinaturas;
            new_ids_node->id = counter_assinaturas;
            counter_assinaturas++;

            // Novo head da Lista Ligada
            lista_assinaturas = new_ids_node;

            pr_info("IDS: Nova regra adicionada com sucesso ao IDS!\n");
            break;

        case IDS_GET_SIGNATURE:

            if (copy_from_user(&new_assinatura, (struct ids_assinatura __user *) arg, sizeof(new_assinatura))) {
                pr_err("IDS: Nao foi possivel obter o buffer do usuario\n");
                return -EFAULT;
            }
            for (ids_node *p = lista_assinaturas; p != NULL; p = p->next) {
                if (p->id == new_assinatura.id) {

                    if (new_assinatura.length < p->length + 1) {
                        pr_err("IDS: Tamanho do buffer alocado para a resposta e insuficiente!\n");
                        return -ENOBUFS; 
                    }

                    if (copy_to_user((char __user *) new_assinatura.p_user_ass, p->assinatura, p->length + 1)) {
                        pr_err("IDS: Falha ao enviar dados para o userspace!\n");
                        return -EFAULT;
                    }

                    new_assinatura.length = p->length;

                    if (copy_to_user((struct ids_assinatura __user *) arg, &new_assinatura, sizeof(new_assinatura))) {
                        pr_err("IDS: Falha ao enviar dados para o userspace!\n");
                        return -EFAULT;
                    }
                    found = 1;
                    break; 
                }
            }

            if (!found) {
                pr_alert("IDS: Assinatura nao foi encontrada!\n");
                return -ENOENT;
            }
            pr_info("IDS: Assinatura encontrada e retornada com sucesso!\n");
            break;
        
        case IDS_ANALYSE:
            if (copy_from_user(&req_payload, (struct ids_payload __user *) arg, sizeof(req_payload))) {
                pr_err("IDS: Nao foi possivel copiar o buffer do usuario\n");
                return -EFAULT;
            }
            if (req_payload.length == 0 || req_payload.length > 16384) {
                pr_err("IDS: Tamanho invalido para o payload\n");
                return -EINVAL;
            }
            
            kernel_buffer = kmalloc(req_payload.length + 1, GFP_KERNEL);
            if (!kernel_buffer) {
                pr_err("IDS: Falha ao alocar memoria no Kernel\n");
                return -ENOMEM;
            }

            if (copy_from_user(kernel_buffer, (char * __user) req_payload.content, req_payload.length)) {
                pr_err("IDS: Nao foi possivel copiar o conteúdo do payload\n");
                kfree(kernel_buffer);
                return -EFAULT;
            }

            kernel_buffer[req_payload.length] = '\0';

            analyse_payload(kernel_buffer, req_payload.length + 1);
            pr_info("IDS: Analise do Payload feita com sucesso!\n");
            kfree(kernel_buffer);
            return 0;

        default:
            // Comando nao reconhecido
            return -ENOTTY; 
    }

    return 0;
}

/*

* Inicializaçao e configuraçoes iniciais do modulo!

*/

// Associando a funçao na estrutura do dispositivo
static struct file_operations ids_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = ids_ioctl,    // Configuraçao para utilizar o *ioctl*
};

static dev_t ids_dev; 
static struct cdev ids_cdev;
static struct class *ids_class;
static struct device *ids_device;

static void limpeza_erros(int error_level) {
    // Estagios de limpeza e rollback das configuraçoes estabelecidas na ordem inversa!
    if (error_level >= 3)
        class_destroy(ids_class);
    if (error_level >= 2)
        cdev_del(&ids_cdev);
    if (error_level >= 1)
        unregister_chrdev_region(ids_dev, 1);

}

// Funçao de inicializaçao do modulo
static int __init ids_init(void) {
    int ret;

    // Alocaçao do Major Number e do Minor Number para o modulo
    ret = alloc_chrdev_region(&ids_dev, 0, 1, "ids_engine");
    if (ret) {
        pr_err("IDS: Falha ao alocar o número do dispositivo.\n");
        return ret;
    }

    // Inicializaçao da estrutura do modulo
    cdev_init(&ids_cdev, &ids_fops);
    ids_cdev.owner = THIS_MODULE;

    // Registrar o modulo para o driver
    ret = cdev_add(&ids_cdev, ids_dev, 1);
    if (ret) {
        pr_err("IDS: Falha ao registrar o modulo.\n");
        limpeza_erros(1); return ret;
    }

    /*
    Criaçao automatica do arquivo de comunicaçao com o driver
    evitando o comando: mknod /dev/lkcamp c <driver major> 0
    */

    ids_class = class_create("ids_class"); // Para versao do Kernel >= 6.4.0

    if (IS_ERR(ids_class)) {
        pr_err("IDS: Falha ao criar a classe\n");
        ret = PTR_ERR(ids_class);
        limpeza_erros(2); return ret;
    }

    // Cria o arquivo /dev/ids_engine efetivamente
    ids_device = device_create(ids_class, NULL, ids_dev, NULL, "ids_engine");
    if (IS_ERR(ids_device)) {
        pr_err("IDS: Falha ao criar o arquivo de comunicaçao com o modulo\n");
        ret = PTR_ERR(ids_device);
        limpeza_erros(3); return ret;
    }

    pr_info("IDS: Dispositivo /dev/ids_engine criado com sucesso!\n");
    return 0;

}

static void __exit ids_exit(void) {
    // Importante que a remoçao dos itens seja na ordem inversa que foram feitos
    // Logo, de tras para frente
    device_destroy(ids_class, ids_dev);     // 1. Remove o arquivo do /dev/
    class_destroy(ids_class);               // 2. Destroi a classe
    cdev_del(&ids_cdev);                    // 3. Remove o cdev do kernel
    unregister_chrdev_region(ids_dev, 1);   // 4. Libera os números Major/Minor

    // Liberaçao de memoria da lista_assinaturas;
    
    ids_node *regra = lista_assinaturas;
    ids_node *tmp;
    while (regra != NULL) {
        tmp = regra->next;
        kfree(regra->assinatura);
        textsearch_destroy(regra->conf);
        kfree(regra);
        regra = tmp;
    }

    pr_info("IDS: Modulo descarregado com sucesso.\n");
}

module_init(ids_init);
module_exit(ids_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Grupo Allan, Julia, Ana e Felipe");
MODULE_DESCRIPTION("Motor para sistema simples de IDS (Intrusion Detection System)");