#include <linux/module.h>
#include <linux/kernel.h>
#include "config.h"
#include "utils.h"
#include "syscall_table.h"
#include "syscall_handler.h"
#include "module_list.h"
#include "ftrace_hooks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Simple anti-rookit module for a security course.");
MODULE_VERSION("1.0.0");

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

// Kernel consistency check #1
static inline bool wp_set(void)
{
    return (read_cr0() & 0x10000) > 0;
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

static void check_all(void)
{
#if DETECT_WP
    check_wp();
#endif /* DETECT_WP */

#if DETECT_SYSCALL_TABLE
    syscall_table_check();
#endif /* DETECT_SYSCALL_TABLE */

#if DETECT_MSR_LSTAR
    syscall_handler_check();
#endif /* DETECT_MSR_LSTAR */

#if DETECT_MODULE_LIST
    module_list_check_all();
#endif /* DETECT_MODULE_LIST */
}

static struct ftrace_hook hooks[] = {
    HOOK("do_init_module", fh_do_init_module, &real_do_init_module),
    HOOK("free_module", fh_free_module, &real_free_module),
};

static int __init anti_rootkit_init(void)
{
    int err;
    void **syscall_table;

    pr_info("Loading anti-rootkit module");

    if (!syscall_table_init())
        return -1;
    syscall_handler_init();
    module_list_init();

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    syscall_table = find_syscall_table();

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
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    free_mod_list();

    pr_info("Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
