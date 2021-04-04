#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/prio.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <uapi/linux/sched/types.h>
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
static struct kobject *check_kobject;
static time64_t last_check_time;

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
    struct time;
    last_check_time = ktime_get_real_seconds();

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
        pr_info("Running checks from interval");
        check_all();
        // TODO: Change to something better to allow for an early exit
        ssleep(CHECK_INTERVAL);
    }

    do_exit(0);

    return 0;
}

static int single_thread_fn(void *args)
{
    check_all();
    do_exit(0);
    return 0;
}

static void schedule_single_check(void)
{
    kthread_run(single_thread_fn, NULL, "antirootkit_single_run");
}

static ssize_t sys_last_check_show(struct kobject *kobj,
                                   struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%lld\n", last_check_time);
}

static ssize_t sys_last_check_store(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count)
{
    return count;
}

static const struct kobj_attribute sys_last_check =
        __ATTR(last_check, 0440, sys_last_check_show, sys_last_check_store);

static ssize_t sys_check_show(struct kobject *kobj, struct kobj_attribute *attr,
                              char *buf)
{
    return sprintf(buf, "%d\n", 0);
}

static ssize_t sys_check_store(struct kobject *kobj,
                               struct kobj_attribute *attr, const char *buf,
                               size_t count)
{
    if (buf[0] == '1') {
        pr_info("Check requested by the user");
        schedule_single_check();
    } else {
        pr_warn("Invalid value written to sysfs trigger");
    }

    return count;
}

static const struct kobj_attribute sys_check_attr =
        __ATTR(check, 0660, sys_check_show, sys_check_store);

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

    check_kobject = kobject_create_and_add("antirootkit", kernel_kobj);
    err = sysfs_create_file(check_kobject, &sys_check_attr.attr);
    if (err) {
        pr_err("Unable to register sysfs check file");
        return err;
    }

    err = sysfs_create_file(check_kobject, &sys_last_check.attr);
    if (err) {
        pr_err("Unable to register sysfs last check file");
        return err;
    }

    check_all();

    interval_task =
            kthread_run(interval_thread_fn, NULL, "antirootkit_interval_run");

    pr_info("Init done");
    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    pr_info("Unloading anti-rootkit module\n");

    kobject_put(check_kobject);
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    free_mod_list();
    kthread_stop(interval_task);

    pr_info("Unload done\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
