#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pid.h>

#define PROC_NAME "pid"

static ssize_t proc_write(struct file *file, const char __user *usr_buf,
                          size_t count, loff_t *pos) {
    char *k_mem;
    long pid;
    int rv;

    // Aloca memória para armazenar a string vinda do usuário
    k_mem = kmalloc(count, GFP_KERNEL);
    if (!k_mem) {
        return -ENOMEM;
    }

    // Copia os dados do usuário para a memória do kernel
    if (copy_from_user(k_mem, usr_buf, count)) {
        kfree(k_mem);
        return -EFAULT;
    }

    // Converte a string para um número inteiro (PID)
    rv = kstrtol(k_mem, 10, &pid);
    kfree(k_mem);

    if (rv < 0) {
        return rv;  // Retorna erro se a conversão falhar
    }

    printk(KERN_INFO "PID recebido: %ld\n", pid);

    return count;
}

static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .write = proc_write,
};

static int __init pid_module_init(void) {
    struct proc_dir_entry *entry;
    
    // Cria a entrada /proc/pid com permissões 0666 (leitura e escrita para todos)
    entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    if (!entry) {
        printk(KERN_ALERT "Falha ao criar /proc/pid\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Módulo pid_module carregado com sucesso!\n");

    return 0;
}

static void __exit pid_module_exit(void) {
    // Remove a entrada do /proc ao descarregar o módulo
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Módulo pid_module descarregado\n");
}

module_init(pid_module_init);
module_exit(pid_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo do Kernel que lida com /proc/pid");
