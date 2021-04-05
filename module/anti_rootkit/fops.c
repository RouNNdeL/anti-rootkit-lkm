#include <linux/fs.h>
#include "config.h"
#include "utils.h"
#include "fops.h"

static struct important_fops org_sysfs_fops;
static struct important_fops org_procfs_fops;
static struct important_fops org_root_fops;

static void copy_important_fops(struct important_fops *cpy,
                                const struct file_operations *org)
{
    if (org->read)
        memcpy(cpy->read, org->read, FOPS_WATCH_SIZE);
    if (org->write)
        memcpy(cpy->write, org->write, FOPS_WATCH_SIZE);
    if (org->open)
        memcpy(cpy->open, org->open, FOPS_WATCH_SIZE);
    if (org->iterate)
        memcpy(cpy->iterate, org->iterate, FOPS_WATCH_SIZE);
}

static int validate_fops(const struct important_fops *cpy,
                         const struct file_operations *org)
{
    int ret = 0;

    if (org->read && memcmp(cpy->read, org->read, FOPS_WATCH_SIZE))
        ret |= FOPS_OVERWRITE_READ;
    if (org->write && memcmp(cpy->write, org->write, FOPS_WATCH_SIZE))
        ret |= FOPS_OVERWRITE_WRITE;
    if (org->open && memcmp(cpy->open, org->open, FOPS_WATCH_SIZE))
        ret |= FOPS_OVERWRITE_OPEN;
    if (org->iterate && memcmp(cpy->iterate, org->iterate, FOPS_WATCH_SIZE))
        ret |= FOPS_OVERWRITE_ITERATE;

    return ret;
}

static void fops_recover(const struct important_fops *cpy,
                         struct file_operations *org)
{
    pr_info("recovering fops");
    wp_disable();
    if (org->read)
        memcpy(org->read, cpy->read, FOPS_WATCH_SIZE);
    if (org->write)
        memcpy(org->write, cpy->write, FOPS_WATCH_SIZE);
    if (org->open)
        memcpy(org->open, cpy->open, FOPS_WATCH_SIZE);
    if (org->iterate)
        memcpy(org->iterate, cpy->iterate, FOPS_WATCH_SIZE);
    wp_enable();
}

static void fops_print_overwrites(int overwrites,
                                  const struct important_fops *cpy,
                                  const struct file_operations *org)
{
    if (overwrites & FOPS_OVERWRITE_READ)
        pr_warn("'read' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_WRITE)
        pr_warn("'write' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_OPEN)
        pr_warn("'open' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_ITERATE)
        pr_warn("'iterate' file operations overwrite detected");
}

static void fops_check(const struct important_fops *cpy,
                       struct file_operations *org)
{
    int overwrites = validate_fops(cpy, org);
    if (!overwrites)
        return;
    pr_info("fops overwrites: %d", overwrites);
    fops_print_overwrites(overwrites, cpy, org);
#if RECOVER_FOPS
    fops_recover(cpy, org);
#endif /* RECOVER_FOPS */
}

int fops_init(void)
{
    struct file_operations *fops;
    fops = get_fop("/sys");
    if (!fops)
        return -ENXIO;
    copy_important_fops(&org_sysfs_fops, fops);

    fops = get_fop("/proc");
    if (!fops)
        return -ENXIO;
    copy_important_fops(&org_procfs_fops, fops);

    fops = get_fop("/");
    if (!fops)
        return -ENXIO;
    copy_important_fops(&org_root_fops, fops);

    return 0;
}

void fops_check_all(void)
{
    struct file_operations *fops;

    fops = get_fop("/sys");
    pr_info("checking sysfs file operations");
    if (!fops) {
        pr_err("unable to get sysfs file operations");
        return;
    }
    fops_check(&org_sysfs_fops, fops);

    fops = get_fop("/proc");
    pr_info("checking root file operations");
    if (!fops) {
        pr_err("unable to get sysfs file operations");
        return;
    }
    fops_check(&org_sysfs_fops, fops);

    fops = get_fop("/");
    pr_info("checking root file operations");
    if (!fops) {
        pr_err("unable to get root file operations");
        return;
    }
    fops_check(&org_root_fops, fops);
}
