#include <linux/rculist.h>
#include <asm/fcntl.h>
#include "module_list.h"
#include "config.h"
#include "utils.h"

#ifdef PTREGS_SYSCALL_STUBS
asmlinkage long (*real_delete_module)(struct pt_regs *regs);
#else
asmlinkage long (*real_delete_module)(const char __user *name_user,
                                      unsigned int flags);
#endif /* PTREGS_SYSCALL_STUBS */

typedef int (*release_mod_ptr)(struct module *);
release_mod_ptr try_release_module_ref;

LIST_HEAD(mod_list);
struct list_head *real_module_list;

void module_list_check_all(void)
{
    struct wrapped_mod *w_mod;

    list_for_each_entry (w_mod, &mod_list, list) {
        module_list_check(w_mod->mod);
    }
}

void module_list_init(void)
{
    real_module_list = THIS_MODULE->list.next;
    try_release_module_ref =
            (release_mod_ptr)lookup_name("try_release_module_ref");
}

void free_mod_list(void)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct wrapped_mod *w_mod;

    list_for_each_safe (cur, tmp, &mod_list) {
        w_mod = list_entry(cur, struct wrapped_mod, list);
        list_del(cur);
        kfree(w_mod);
    }
}

static void unregister_module(struct module *mod)
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
}

static void unload_module(struct module *mod)
{
    long ret;
    const char *name;
#ifdef PTREGS_SYSCALL_STUBS
    struct pt_regs regs;
#endif

    /* flags = O_NONBLOCK | O_TRUNC; */
    /* name = mod->name; */

    /* pr_info("unloading '%s' using sys_delete_module", name); */
    /* #ifdef PTREGS_SYSCALL_STUBS */
    /* regs.di = (unsigned long)name; */
    /* regs.si = flags; */
    /* ret = real_delete_module(&regs); */
    /* #else */
    /* ret = real_delete_module(name, flags); */
    /* #endif /1* PTREGS_SYSCALL_STUBS *1/ */

#if FORCE_UNLOAD_SUSPECT_MODULE
    if (ret) {
        pr_info("unloading '%s' forcefully", name);
        real_free_module(mod);
        ret = 0;
    }
#endif

    if (ret) {
        pr_warn("failed to unload '%s', errno %ld", name, ret);
    } else {
        pr_info("successfully unloaded module");
    }
}

void module_list_check(struct module *mod)
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
#if UNLOAD_SUSPECT_MODULE
        unregister_module(mod);
        unload_module(mod);
#endif /* UNLOAD_SUSPECT_MODULE */
#endif /* RECOVER_MODULE_LIST */
    }
}

void fh_free_module(struct module *mod)
{
    unregister_module(mod);

    real_free_module(mod);
}

int fh_do_init_module(struct module *mod)
{
    int ret;
    struct wrapped_mod *w_mod;

    ret = real_do_init_module(mod);

    if (ret == 0) {
        w_mod = kmalloc(sizeof(struct wrapped_mod), GFP_KERNEL);
        if (w_mod != NULL) {
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
    module_list_check(mod);
#endif /* DETECT_MODULE_LIST */

    return ret;
}
