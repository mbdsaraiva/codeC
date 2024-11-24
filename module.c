#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/slab.h>

#define PROC_NAME "pid"  // Nome do arquivo /proc/pid
static int pid_value = 0;  // Variável para armazenar o PID gravado

// Função chamada quando há uma escrita no arquivo /proc/pid
ssize_t proc_write(struct file *file, const char __user *usr_buf,
                   size_t count, loff_t *pos)
{
    char *k_mem;
    long pid_int;
    struct pid *pid;
    struct task_struct *task;

    // Alocar memória para armazenar os dados recebidos
    k_mem = kmalloc(count, GFP_KERNEL);
    if (!k_mem)
        return -ENOMEM;

    // Copiar os dados do espaço do usuário para a memória do kernel
    if (copy_from_user(k_mem, usr_buf, count)) {
        kfree(k_mem);
        return -EFAULT;
    }

    // Converter a string recebida para inteiro
    if (kstrtol(k_mem, 10, &pid_int)) {
        kfree(k_mem);
        return -EINVAL;
    }

    // Armazenar o PID
    pid_value = (int)pid_int;

    // Liberar a memória alocada
    kfree(k_mem);

    printk(KERN_INFO "PID gravado: %d\n", pid_value);

    return count;
}

// Função chamada quando há uma leitura do arquivo /proc/pid
ssize_t proc_read(struct file *file, char __user *usr_buf,
                  size_t count, loff_t *pos)
{
    struct pid *pid_struct;
    struct task_struct *task;
    char *buf;
    int len = 0;

    // Verificar se o PID foi gravado
    if (pid_value == 0)
        return 0;

    // Obter o struct pid usando o PID gravado
    pid_struct = find_vpid(pid_value);
    if (!pid_struct)
        return 0;

    // Obter o struct task_struct associado ao PID
    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return 0;

    // Alocar espaço para armazenar a saída
    buf = kmalloc(256, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    // Preencher o buffer com as informações do processo
    len = snprintf(buf, 256, "command = [%s] pid = [%d] state = [%ld]\n",
                   task->comm, task->pid, task->state);

    // Copiar o conteúdo do buffer para o espaço do usuário
    if (copy_to_user(usr_buf, buf, len)) {
        kfree(buf);
        return -EFAULT;
    }

    // Liberar a memória alocada
    kfree(buf);

    return len;
}

// Estrutura de operações do arquivo para /proc/pid
static const struct file_operations proc_file_ops = {
    .owner = THIS_MODULE,
    .write = proc_write,
    .read = proc_read,
};

// Função chamada quando o módulo é carregado
static int __init pid_module_init(void)
{
    // Criar o arquivo /proc/pid
    if (!proc_create(PROC_NAME, 0666, NULL, &proc_file_ops)) {
        printk(KERN_ERR "Erro ao criar o arquivo /proc/pid\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Módulo /proc/pid carregado com sucesso\n");
    return 0;
}

// Função chamada quando o módulo é descarregado
static void __exit pid_module_exit(void)
{
    // Remover o arquivo /proc/pid
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Módulo /proc/pid descarregado\n");
}

module_init(pid_module_init);
module_exit(pid_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seu Nome");
MODULE_DESCRIPTION("Módulo do Kernel que exibe informações de um processo baseado no PID em /proc/pid");
