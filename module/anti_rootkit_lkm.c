#include "linux/rculist.h"
#define pr_fmt(fmt) "antirootkit: " fmt

#include "asm/pgtable_types.h"
#include "linux/logic_pio.h"
#include "linux/vmalloc.h"
#include <linux/gfp.h>
#include <linux/ftrace.h>
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
#include <linux/version.h>
#include <linux/kprobes.h>
#include <asm/errno.h>
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

static void *syscall_table_cpy[NR_syscalls];
static void **syscall_table;
static void *syscall_handler;

struct syscall_overwrite {
    unsigned int nr;
    void *original_addr;
    void *overwritten_addr;
    struct list_head list;
};

struct wrapped_mod {
    struct module *mod;
    struct list_head list;
};

LIST_HEAD(mod_list);
struct list_head *real_module_list;

/*
 * ftrace hooking from https://github.com/ilammy/ftrace-hook
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long lookup_name(const char *name)
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
static unsigned long lookup_name(const char *name)
{
    return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
struct ftrace_regs {
    struct pt_regs regs;
};
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

// Newer kernel versions prevent clearing the WP bit
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

    pr_info("Recovering syscall table");
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
        pr_info("No overwrites detected");
        return;
    }

    list_for_each_entry (ov, &head->list, list) {
        pr_warn("syscall %d changed, used to be %px, now is %px", ov->nr,
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
        pr_warn("cr0 WP bit cleared");
#if RECOVER_WP
        pr_info("Recovering cr0 WP bit");
        enable_wp();
#endif /* RECOVER_WP */
    }
}

static inline void check_syscall_handler(void)
{
    if (syscall_handler_changed()) {
        pr_warn("syscall entry address changed");
#if RECOVER_MSR_LSTAR
        pr_info("recovering syscall entry address");
        recover_syscall_handler();
#endif /* RECOVER_MSR_LSTAR */
    }
}

static void check_module_on_list(struct module *mod)
{
    bool on_list;
    struct module *mod_iter;

    on_list = false;
    list_for_each_entry (mod_iter, real_module_list, list) {
        if (mod_iter == mod) {
            on_list = true;
        }
    }

    if (!on_list) {
        pr_warn("module '%s' appears to have removed itself from the module list",
                mod->name);
#if RECOVER_MODULE_LIST
        list_add_rcu(&mod->list, real_module_list);
        pr_info("module '%s' has been added back to the module list",
                mod->name);
#endif /* RECOVER_MODULE_LIST */
    }
}

static inline void check_all_modules_on_list(void) {
    struct wrapped_mod *w_mod; 

    list_for_each_entry(w_mod, &mod_list, list) {
        check_module_on_list(w_mod->mod);
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

#if DETECT_MODULE_LIST 
    check_all_modules_on_list();
#endif /* DETECT_MODULE_LIST */
}

static bool save_legit(void)
{
    syscall_table = find_syscall_table();
    if (syscall_table == NULL)
        return false;

    pr_info("syscall_table is @ %px", syscall_table);
    copy_syscall_table();

    syscall_handler = get_syscall_64_handler();

    return false;
}

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = lookup_name(hook->name);

    if (!hook->address) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->original) = hook->address;
#endif

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    regs->regs.ip = (unsigned long)hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->regs.ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hook() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
    int err;

    err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    pr_info("registering hook for %s @ %px", hook->name, hook->original);

    /*
     * We're going to modify %rip register so we'll need IPMODIFY flag
     * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
     * is useless if we change %rip so disable it with RECURSION_SAFE.
     * We'll perform our own checks for trace function reentry.
     */
    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    }
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }

    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }

    return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

static void (*real_free_module)(struct module *mod);

static void fh_free_module(struct module *mod)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct wrapped_mod *w_mod;

    list_for_each_safe (cur, tmp, &mod_list) {
        w_mod = list_entry(cur, struct wrapped_mod, list);
        if (w_mod->mod == mod) {
            list_del(cur);
            kfree(w_mod);
            pr_info("unregistered module '%s'", mod->name);
        }
    }

    real_free_module(mod);
}

static int (*real_do_init_module)(struct module *mod);

static int fh_do_init_module(struct module *mod)
{
    int ret;
    struct wrapped_mod *w_mod;

    w_mod = kmalloc(sizeof(struct wrapped_mod), GFP_KERNEL);

    ret = real_do_init_module(mod);

    if (ret == 0) {
        if (w_mod) {
            w_mod->mod = mod;
            list_add(&w_mod->list, &mod_list);
            pr_info("registered module '%s'", mod->name);
        } else {
            pr_err("unable to allocate memory for wrapped_mod");
        }
    }

#if DETECT_MODULE_LIST
    // We are running after the module has been initialized,
    // if it removed itself from the module list during init
    // we can already detect it
    check_module_on_list(mod);
#endif /* DETECT_MODULE_LIST */

    return ret;
}

#define HOOK(_name, _function, _original)                                      \
    {                                                                          \
        .name = _name, .function = (_function), .original = (_original),       \
    }

static struct ftrace_hook hooks[] = {
    HOOK("do_init_module", fh_do_init_module, &real_do_init_module),
    HOOK("free_module", fh_free_module, &real_free_module),
};

static int __init anti_rootkit_init(void)
{
    int err;

    pr_info("Loading anti-rootkit module");
    real_module_list = THIS_MODULE->list.next;
    save_legit();

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    disable_wp();
    syscall_table[300] = (void *)0xdeafbeef;
    syscall_table[323] = (void *)0x12345678;
    set_syscall_64_handler((void *)0x87654321);

    check_all();
    pr_info("Done");

    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    pr_info("Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
