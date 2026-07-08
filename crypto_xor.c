#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

typedef unsigned char u8;

// Chave vazia, todos os elementos iguais à 0 e até 512 bits;
static u8 crypto_xor_key[64];
static int len_crypto_key = 64;
DEFINE_MUTEX(crypto_key_mutex);

SYSCALL_DEFINE2(set_crypto_xor_key, u8 __user *, crypto_key, unsigned int, len) {

    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    if (len > 64 || len <= 0) return -EINVAL;

    u8 *buffer;
    buffer = kmalloc(len * sizeof(u8), GFP_KERNEL);

    if (!buffer) {
        return -ENOMEM;
    }

    if (copy_from_user(buffer, crypto_key, len * sizeof(u8))) {
        kfree(buffer);
        return -EFAULT;
    }

    mutex_lock(&crypto_key_mutex);
        for (int i = 0; i < len; i++) 
            crypto_xor_key[i] = buffer[i];
        len_crypto_key = len;
    mutex_unlock(&crypto_key_mutex);

    kfree(buffer);

    return 0; // Sucesso
}

SYSCALL_DEFINE3(crypto_xor, u8 __user *, content, u8 __user *, crypted, unsigned int, len)
{
    u8 *buffer_content = kmalloc(len * sizeof(u8), GFP_KERNEL);
    u8 *buffer_crypted = kmalloc(len * sizeof(u8), GFP_KERNEL);

    if (!buffer_content || !buffer_crypted) {
        if (buffer_content) kfree(buffer_content);
        if (buffer_crypted) kfree(buffer_crypted);
        return -ENOMEM;
    }

    if (copy_from_user(buffer_content, content, len*sizeof(u8))) {
        kfree(buffer_content);
        kfree(buffer_crypted);
        return -EFAULT;
    }

    mutex_lock(&crypto_key_mutex);
        for (int i = 0, j = 0; i < len; i++, j++) {
            if (j == len_crypto_key) j = 0;
            buffer_crypted[i] = buffer_content[i] ^ crypto_xor_key[j];
        }
    mutex_unlock(&crypto_key_mutex);

    if (copy_to_user(crypted, buffer_crypted, len * sizeof(u8))) {
        kfree(buffer_content);
        kfree(buffer_crypted);
        return -EFAULT;
    }

    kfree(buffer_content);
    kfree(buffer_crypted);

    return 0;
}