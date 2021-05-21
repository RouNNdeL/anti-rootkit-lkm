#include "linux/pm.h"
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/types.h>
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
#include "fops.h"
#include "idt.h"
#include "pinned_bits.h"
#include "important_functions.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Simple anti-rookit module for a security course.");
MODULE_VERSION("1.0.0");

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#define CHECK_PINNED_BITS (1 << 0)
#define CHECK_SYSCALL_TABLE (1 << 1)
#define CHECK_MSR_LSTAR (1 << 2)
#define CHECK_MODULE_LIST (1 << 3)
#define CHECK_FOPS (1 << 4)
#define CHECK_IDT (1 << 5)
#define CHECK_IMPORTANT_FUNCTIONS (1 << 6)

static struct task_struct *interval_task;
static struct kobject *check_kobject;
static time64_t last_check_time;
static unsigned int loaded_checks;

static void check_all(void)
{
    last_check_time = ktime_get_real_seconds();

    pr_info("running all checks");
#if DETECT_PINNED_BITS
    if (loaded_checks & CHECK_PINNED_BITS)
        pinned_bits_check();
#endif /* DETECT_PINNED_BITS */

#if DETECT_SYSCALL_TABLE
    if (loaded_checks & CHECK_SYSCALL_TABLE)
        syscall_table_check();
#endif /* DETECT_SYSCALL_TABLE */

#if DETECT_MSR_LSTAR
    if (loaded_checks & CHECK_MSR_LSTAR)
        syscall_handler_check();
#endif /* DETECT_MSR_LSTAR */

#if DETECT_MODULE_LIST
    if (loaded_checks & CHECK_MODULE_LIST)
        module_list_check_all();
#endif /* DETECT_MODULE_LIST */

#if DETECT_FOPS
    if (loaded_checks & CHECK_FOPS)
        fops_check_all();
#endif /* DETECT_FOPS */

#if DETECT_IDT
    if (loaded_checks & CHECK_IDT)
        idt_check();
#endif /* DETECT_IDT */

#if DETECT_IMPORTANT_FUNCTIONS
    if (loaded_checks & CHECK_IMPORTANT_FUNCTIONS)
        important_functions_check();
#endif /* DETECT_IMPORTANT_FUNCTIONS */
}

static int interval_thread_fn(void *args)
{
    int i;
    pr_info("starting the interval thread, will run every %ds", CHECK_INTERVAL);

    while (!kthread_should_stop()) {
        pr_info("running checks from interval");
        check_all();
        for (i = 0; i < CHECK_INTERVAL; ++i) {
            ssleep(1);
            if (kthread_should_stop())
                break;
        }
    }

    return 0;
}

static int single_thread_fn(void *args)
{
    check_all();
    return 0;
}

static void schedule_single_check(void)
{
    kthread_run(single_thread_fn, NULL, "antirootkit_single_run");
}

void mod_list_callback(struct module *mod, int flags)
{
    schedule_single_check();
}

static ssize_t last_check_show(struct kobject *kobj,
                               struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%lld\n", last_check_time);
}

static const struct kobj_attribute sys_last_check =
        __ATTR_RO_MODE(last_check, 0440);

static ssize_t check_store(struct kobject *kobj, struct kobj_attribute *attr,
                           const char *buf, size_t count)
{
    if (buf[0] == '1') {
        pr_info("check requested by the user");
        schedule_single_check();
    } else {
        pr_warn("invalid value written to sysfs trigger");
    }

    return count;
}

static const struct kobj_attribute sys_check_attr = __ATTR_WO(check);

static struct ftrace_hook hooks[] = {
    HOOK("do_init_module", fh_do_init_module, &real_do_init_module),
    HOOK("free_module", fh_free_module, &real_free_module),
};

static bool checks_init(void)
{
    int err;
    bool ret = true;

    loaded_checks = 0;

    err = syscall_table_init();
    if (err) {
        pr_err("unable to find syscall table");
        ret = false;
    } else {
        loaded_checks |= CHECK_SYSCALL_TABLE;
    }

    syscall_handler_init();
    loaded_checks |= CHECK_MSR_LSTAR;

    module_list_init();
    module_list_set_callback(mod_list_callback);

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        pr_err("uable to install hooks");
        ret = false;
    } else {
        loaded_checks |= CHECK_MODULE_LIST;
    }

    err = fops_init();
    if (err) {
        pr_err("unable to clone file operations");
        ret = false;
    } else {
        loaded_checks |= CHECK_FOPS;
    }

    err = idt_init();
    if (err) {
        pr_err("unable to find IDT");
        ret = false;
    } else {
        loaded_checks |= CHECK_IDT;
    }

    important_functions_init();
    loaded_checks |= CHECK_IMPORTANT_FUNCTIONS;

    return ret;
}

static int init_sysfs(void)
{
    int err;

    check_kobject = kobject_create_and_add("antirootkit", kernel_kobj);
    err = sysfs_create_file(check_kobject, &sys_check_attr.attr);
    if (err) {
        pr_err("unable to register sysfs check file");
        return err;
    }

    err = sysfs_create_file(check_kobject, &sys_last_check.attr);
    if (err) {
        pr_err("unable to register sysfs last check file");
        return err;
    }

    return 0;
}

static void cleanup_checks(void)
{
    if (loaded_checks & CHECK_MODULE_LIST) {
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
        free_mod_list();
    }
}

static int __init anti_rootkit_init(void)
{
    int err;

    pr_info("loading anti-rootkit module");

    if (!checks_init()) {
        pr_err("unable to initialize one of the enabled modules");
    }

    err = init_sysfs();
    if (err) {
        cleanup_checks();
        return err;
    }

    check_all();

    interval_task =
            kthread_run(interval_thread_fn, NULL, "antirootkit_interval_run");

    pr_info("init done");

    return 0;
}

static void __exit anti_rootkit_exit(void)
{
    pr_info("unloading anti-rootkit module");
    kobject_put(check_kobject);
    cleanup_checks();
    kthread_stop(interval_task);
    pr_info("unload done");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
