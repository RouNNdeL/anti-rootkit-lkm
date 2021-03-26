#include <linux/module.h>

void (*real_free_module)(struct module *);
int (*real_do_init_module)(struct module *);
