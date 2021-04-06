#ifndef _ANTI_ROOTKIT_MODULE_LIST
#define _ANTI_ROOTKIT_MODULE_LIST

#include <linux/time64.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/slab.h>

struct wrapped_mod {
    struct module *mod;
    time64_t load_time;
    struct list_head list;
};

#define MOD_LIST_UNLOAD 1
#define MOD_LIST_LOAD 2
typedef void (*mod_list_change)(struct module *mod, int flags);
void module_list_set_callback(mod_list_change c);

void module_list_check(struct module *mod);

extern void (*real_free_module)(struct module *);
void fh_free_module(struct module *mod);

extern int (*real_do_init_module)(struct module *);
int fh_do_init_module(struct module *mod);

void free_mod_list(void);
void module_list_check_all(void);
void module_list_init(void);

#endif
