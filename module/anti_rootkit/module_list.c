#include "linux/compiler.h"
#include "linux/percpu-refcount.h"
#include <linux/rculist.h>
#include <asm/fcntl.h>

#include "module_list.h"
#include "config.h"
#include "utils.h"

static LIST_HEAD(mod_list);
static struct list_head *real_module_list;
static mod_list_change callback = NULL;

void module_list_set_callback(mod_list_change c)
{
    callback = c;
}

void module_list_check_all(void)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct wrapped_mod *w_mod;

    // We need the safe iterator, since modules can be removed during the check
    list_for_each_safe (cur, tmp, &mod_list) {
        w_mod = list_entry(cur, struct wrapped_mod, list);
        module_list_check(w_mod->mod);
    }
}

void module_list_init(void)
{
    real_module_list = THIS_MODULE->list.next;
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

void module_list_check(struct module *mod)
{
    bool on_list;
    struct module *mod_iter;

    on_list = false;
    list_for_each_entry (mod_iter, real_module_list, list) {
        if (mod_iter == mod)
            on_list = true;
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

    /*
     * Tail call optimization can interfere with recursion detection based on
     * return address on the stack. Disable it to avoid machine hangups.
     */
    barrier();
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
            w_mod->load_time = ktime_get_real_seconds();
            list_add(&w_mod->list, &mod_list);
            pr_info("registered module '%s'", mod->name);
        } else {
            pr_err("unable to allocate memory for wrapped_mod");
        }
    }

    if (callback)
        callback(mod, MOD_LIST_LOAD);

    return ret;
}
