#include "linux/logic_pio.h"
#include <linux/gfp.h>
#include <linux/kern_levels.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
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
#include "config.h"

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
static void *syscall_handler;

// Newwer kernel versions prevent clearing the WP bit
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

static inline void *get_syscall_64_handler(void)
{
    uint64_t system_call_entry;
    rdmsrl(MSR_LSTAR, system_call_entry);
    return (void *)system_call_entry;
}

static inline void set_syscall_64_handler(void *val)
{
    wrmsrl(MSR_LSTAR, (unsigned long)val);
}

#define ENTRY_DO_CALL_OFFSET 0x77

static void **find_syscall_table(void)
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

// Kernel consistency check #1
static inline bool wp_set(void)
{
    return (read_cr0() & 0x10000) > 0;
}

// Kernel consistency check #2
static inline bool syscall_handler_changed(void)
{
    return get_syscall_64_handler() != syscall_handler;
}

static inline void recover_syscall_handler(void)
{
    set_syscall_64_handler(syscall_handler);
}

static void copy_syscall_table(void)
{
    memcpy(syscall_table_cpy, syscall_table, sizeof(syscall_table_cpy));
}

static void recover_syscall_table(struct syscall_overwrite *head)
{
    struct syscall_overwrite *ov;

    log_info("Recovering syscall table");
    disable_wp();
    list_for_each_entry (ov, &head->list, list) {
        syscall_table[ov->nr] = ov->original_addr;
    }
    enable_wp();
}

// Kernel consistency check #3
static struct syscall_overwrite *find_syscall_overrides(void)
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
        log_info("No overwrites detected");
        return;
    }

    list_for_each_entry (ov, &head->list, list) {
        log_warn("syscall %d changed, used to be %px, now is %px", ov->nr,
                 ov->original_addr, ov->overwritten_addr);
    }
}

static inline void check_syscall_table(void)
{
    struct syscall_overwrite *head;

    head = find_syscall_overrides();
    if (head != NULL) {
        print_syscall_overwrites(head);
#if RECOVER_SYSCALL_TABLE
        recover_syscall_table(head);
#endif /* RECOVER_SYSCALL_TABLE */
        free_syscall_overwrites(head);
    }
}

static inline void check_wp(void)
{
    if (!wp_set()) {
        log_warn("cr0 WP bit cleared");
#if RECOVER_WP
        log_info("Recovering cr0 WP bit");
        enable_wp();
#endif /* RECOVER_WP */
    }
}

static inline void check_syscall_handler(void)
{
    if (syscall_handler_changed()) {
        log_warn("syscall entry address changed");
#if RECOVER_MSR_LSTAR
        log_info("recovering syscall entry address");
        recover_syscall_handler();
#endif /* RECOVER_MSR_LSTAR */
    }
}

static void check_all(void)
{
#if DETECT_WP
    check_wp();
#endif /* DETECT_WP */

#if DETECT_SYSCALL_TABLE
    check_syscall_table();
#endif /* DETECT_SYSCALL_TABLE */

#if DETECT_MSR_LSTAR
    check_syscall_handler();
#endif /* DETECT_MSR_LSTAR */
}

static bool save_legit(void)
{
    syscall_table = find_syscall_table();
    if (syscall_table == NULL)
        return false;

    log_info("syscall_table is @ %px", syscall_table);
    copy_syscall_table();

    syscall_handler = get_syscall_64_handler();

    return false;
}

static int __init anti_rootkit_init(void)
{
    log_info("Loading anti-rootkit module");

    save_legit();

    disable_wp();
    syscall_table[300] = (void *)0xdeafbeef;
    syscall_table[323] = (void *)0x12345678;

    set_syscall_64_handler((void *)0x87654321);

    check_all();

    log_info("Done");

    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    log_info("Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
