#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include "utils.h"
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

void free_syscall_overwrites(struct table_overwrite *head)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct table_overwrite *ov;

    list_for_each_safe (cur, tmp, &head->list) {
        ov = list_entry(cur, struct table_overwrite, list);
        list_del(cur);
        kfree(ov);
    }

    kfree(head);
}

void print_table_overwrites(const char *prefix, const struct table_overwrite *head)
{
    struct table_overwrite *ov;

    if (list_empty(&head->list)) {
        pr_info("no overwrites detected");
        return;
    }

    list_for_each_entry (ov, &head->list, list) {
        pr_warn("%s %d changed, used to be %px, now is %px", prefix, ov->index,
                (void *)ov->original_addr, (void *)ov->overwritten_addr);
    }
}
