#include <linux/sched.h>
#include <linux/sched/prio.h>
#include <uapi/linux/sched/types.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
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

static struct task_struct *interval_task;

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
    pr_info("Running all checks");
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

static int interval_thread_fn(void *args)
{
    pr_info("Starting the interval thread, will run every %ds", CHECK_INTERVAL);

    while (!kthread_should_stop()) {
        check_all();
        // TODO: Change to something better to allow for an early exit
        ssleep(CHECK_INTERVAL);
    }

    do_exit(0);

    return 0;
}

static struct ftrace_hook hooks[] = {
    HOOK("do_init_module", fh_do_init_module, &real_do_init_module),
    HOOK("free_module", fh_free_module, &real_free_module),
};

static int __init anti_rootkit_init(void)
{
    int err;

    pr_info("Loading anti-rootkit module");

    if (!syscall_table_init())
        return -ENXIO;
    syscall_handler_init();
    module_list_init();

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    check_all();

    interval_task = kthread_run(interval_thread_fn, NULL, "interval_thread");

    pr_info("Init done");
    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    pr_info("Unloading anti-rootkit module\n");

    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    free_mod_list();
    kthread_stop(interval_task);

    pr_info("Unload done\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
