#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>  // Para kmalloc
#include <linux/sched.h>  // Para task_struct

static struct proc_dir_entry *pid_file;
static int pid_to_lookup = -1;  // Variável para armazenar o PID que será lido

// Função para ler o arquivo /proc/pid
ssize_t proc_read(struct file *file, char __user *usr_buf, size_t count, loff_t *pos) {
    struct task_struct *task;
    char buf[256];
    int len = 0;

    // Se pid_to_lookup não foi setado, retorne 0 (sem dados)
    if (pid_to_lookup == -1)
        return 0;

    // Obtemos a task_struct pelo PID
    task = pid_task(find_vpid(pid_to_lookup), PIDTYPE_PID);
    if (!task)
        return -EINVAL;

    // Preenche o buffer com as informações do processo
    len = snprintf(buf, sizeof(buf), "command = [%s] pid = [%d] state = [%ld]\n",
                   task->comm, task->pid, task->state);

    // Copia o conteúdo do buffer para o espaço do usuário
    if (copy_to_user(usr_buf, buf, len))
        return -EFAULT;

    return len;
}

// Função para escrever no arquivo /proc/pid
ssize_t proc_write(struct file *file, const char __user *usr_buf, size_t count, loff_t *pos) {
    char *k_mem;
    int pid;

    // Aloca memória no kernel
    k_mem = kmalloc(count, GFP_KERNEL);
    if (!k_mem)
        return -ENOMEM;

    // Copia os dados do espaço do usuário para o kernel
    if (copy_from_user(k_mem, usr_buf, count)) {
        kfree(k_mem);
        return -EFAULT;
    }

    // Converte a string para um número inteiro (PID)
    if (kstrtoint(k_mem, 10, &pid)) {
        kfree(k_mem);
        return -EINVAL;
    }

    // Armazena o PID a ser usado na leitura
    pid_to_lookup = pid;

    kfree(k_mem);
    return count;
}

// Estrutura de operações de arquivo para o /proc/pid
static const struct file_operations pid_fops = {
    .owner = THIS_MODULE,
    .read = proc_read,
    .write = proc_write,
};

// Função para criar o arquivo /proc/pid
static int pid_module_proc_init(void) {
    pid_file = proc_create("pid", 0666, NULL, &pid_fops);
    if (!pid_file) {
        printk(KERN_ERR "Unable to create /proc/pid\n");
        return -ENOMEM;
    }
    return 0;
}

// Função para remover o arquivo /proc/pid
static void pid_module_proc_exit(void) {
    remove_proc_entry("pid", NULL);
}

// Função de inicialização do módulo
static int __init pid_module_init(void) {
    int ret;

    ret = pid_module_proc_init();
    if (ret) {
        return ret;
    }

    printk(KERN_INFO "/proc/pid criado com sucesso\n");
    return 0;
}

// Função de saída do módulo
static void __exit pid_module_exit(void) {
    pid_module_proc_exit();
    printk(KERN_INFO "/proc/pid removido\n");
}

module_init(pid_module_init);
module_exit(pid_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo para testar /proc/pid");
