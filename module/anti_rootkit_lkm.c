#include "linux/gfp.h"
#include "linux/kern_levels.h"
#include "linux/list.h"
#include "linux/mm.h"
#include "linux/printk.h"
#include "linux/string.h"
#include "linux/types.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Simple anti-rookit module for a security course.");
MODULE_VERSION("0.0.1");

struct syscall_overwrite {
    unsigned int nr;
    void *original_addr;
    void *overwritten_addr;
    struct list_head list;
};

static void *syscall_table_cpy[NR_syscalls];
static void **syscall_table;

static inline void _write_cr0(uint64_t val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void disable_wp(void)
{
    _write_cr0(read_cr0() & (~0x10000));
}

static inline void enable_wp(void)
{
    _write_cr0(read_cr0() | 0x10000);
}

static inline void *get_64bit_system_call_handler(void)
{
    uint64_t system_call_entry;
    rdmsrl(MSR_LSTAR, system_call_entry);
    return (void *)system_call_entry;
}

#define ENTRY_DO_CALL_OFFSET 0x77

static void **find_syscall_table(void)
{
    unsigned char *entry_syscall;
    unsigned char *do_syscall;
    unsigned char *addr;
    void **syscall_table = NULL;
    int offset;

    entry_syscall = get_64bit_system_call_handler();

    // First byte of call is the opcode, following 4 bytes are the signed offset
    offset = *((int *)(entry_syscall + ENTRY_DO_CALL_OFFSET + 1));

    // The call offset should include the 5 instruction bytes
    do_syscall = entry_syscall + offset + ENTRY_DO_CALL_OFFSET + 5;
    printk(KERN_DEBUG "sym.do_syscall_64 is @ %px", do_syscall);

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

static void copy_syscall_table(void)
{
    memcpy(syscall_table_cpy, syscall_table, sizeof(syscall_table_cpy));
}

static void recover_syscall_table(struct syscall_overwrite *head)
{
    struct syscall_overwrite *ov;

    printk(KERN_INFO "Recovering syscall table");
    disable_wp();
    list_for_each_entry (ov, &head->list, list) {
        syscall_table[ov->nr] = ov->original_addr;
    }
    enable_wp();
}

static struct syscall_overwrite *syscall_overwrites(void)
{
    unsigned int nr;
    struct syscall_overwrite *head = kmalloc(sizeof(*head), GFP_KERNEL);
    INIT_LIST_HEAD(&head->list);

    if (head == NULL)
        return NULL;

    for (nr = 0; nr < NR_syscalls; ++nr) {
        if (syscall_table_cpy[nr] != syscall_table[nr]) {
            struct syscall_overwrite *ov = kmalloc(sizeof(*ov), GFP_KERNEL);
            if (ov == NULL)
                return NULL;

            ov->nr = nr;
            ov->original_addr = syscall_table_cpy[nr];
            ov->overwritten_addr = syscall_table[nr];
            list_add(&ov->list, &head->list);
        }
    }

    return head;
}

static void free_syscall_overwrites(struct syscall_overwrite *head)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct syscall_overwrite *ov;

    list_for_each_safe (cur, tmp, &head->list) {
        ov = list_entry(cur, struct syscall_overwrite, list);
        list_del(cur);
        kfree(ov);
    }

    kfree(head);
}

static void print_syscall_overwrites(struct syscall_overwrite *head)
{
    struct syscall_overwrite *ov;

    if (list_empty(&head->list)) {
        printk(KERN_INFO "No overwrites detected");
        return;
    }

    list_for_each_entry (ov, &head->list, list) {
        printk(KERN_WARNING "syscall %d changed, used to be %px, now is %px",
               ov->nr, ov->original_addr, ov->overwritten_addr);
    }
}

static int __init anti_rootkit_init(void)
{
    struct syscall_overwrite *head;

    printk(KERN_INFO "Loading anti-rootkit module");

    syscall_table = find_syscall_table();

    if (syscall_table == NULL)
        return 1;

    printk(KERN_INFO "syscall_table is @ %px", syscall_table);

    copy_syscall_table();

    disable_wp();
    syscall_table[300] = (void *)0xdeafbeef;
    syscall_table[323] = (void *)0x12345678;
    enable_wp();

    head = syscall_overwrites();
    if (head == NULL)
        return 1;

    print_syscall_overwrites(head);
    recover_syscall_table(head);
    free_syscall_overwrites(head);

    head = syscall_overwrites();
    if (head == NULL)
        return 1;

    print_syscall_overwrites(head);
    free_syscall_overwrites(head);

    printk(KERN_INFO "Done");

    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
