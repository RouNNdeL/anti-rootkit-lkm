#include "linux/printk.h"
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include "config.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long retval;

    if (register_kprobe(&kp) < 0)
        return 0;
    retval = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return retval;
}
#else
unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

struct file_operations *get_fop(const char *path)
{
    struct file *file;
    struct file_operations *ret;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    ret = (struct file_operations *) file->f_op;
    filp_close(file, 0);

    return ret;
}
