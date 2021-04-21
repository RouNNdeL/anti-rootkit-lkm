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
    fprot_safe_cpy(&cpy->read, org->read);
    fprot_safe_cpy(&cpy->read_iter, org->read_iter);
    fprot_safe_cpy(&cpy->write, org->write);
    fprot_safe_cpy(&cpy->write_iter, org->write_iter);
    fprot_safe_cpy(&cpy->open, org->open);
    fprot_safe_cpy(&cpy->iterate, org->iterate);

    cpy->read.addr = org->read;
    cpy->read_iter.addr = org->read_iter;
    cpy->write.addr = org->write;
    cpy->write_iter.addr = org->write_iter;
    cpy->open.addr = org->open;
    cpy->iterate.addr = org->iterate;
}

static int validate_fops(const struct important_fops *cpy)
{
    int ret = 0;

    if (fprot_validate(&cpy->read))
        ret |= FOPS_OVERWRITE_READ;
    if (fprot_validate(&cpy->read_iter))
        ret |= FOPS_OVERWRITE_READ_ITER;
    if (fprot_validate(&cpy->write))
        ret |= FOPS_OVERWRITE_WRITE;
    if (fprot_validate(&cpy->write_iter))
        ret |= FOPS_OVERWRITE_WRITE_ITER;
    if (fprot_validate(&cpy->open))
        ret |= FOPS_OVERWRITE_OPEN;
    if (fprot_validate(&cpy->iterate))
        ret |= FOPS_OVERWRITE_ITERATE;

    return ret;
}

static void fops_recover(const struct important_fops *cpy)
{
    pr_info("recovering fops");
    wp_disable();

    fprot_recover(&cpy->read);
    fprot_recover(&cpy->read_iter);
    fprot_recover(&cpy->write);
    fprot_recover(&cpy->write_iter);
    fprot_recover(&cpy->open);
    fprot_recover(&cpy->iterate);

    wp_enable();
}

static void fops_print_overwrites(int overwrites)
{
    if (overwrites & FOPS_OVERWRITE_READ)
        pr_warn("'read' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_READ_ITER)
        pr_warn("'read_iter' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_WRITE)
        pr_warn("'write' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_WRITE_ITER)
        pr_warn("'write_iter' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_OPEN)
        pr_warn("'open' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_ITERATE)
        pr_warn("'iterate' file operations overwrite detected");
}

static void fops_check(const struct important_fops *cpy)
{
    int overwrites = validate_fops(cpy);
    if (!overwrites)
        return;
    pr_info("fops overwrites: %d", overwrites);
    fops_print_overwrites(overwrites);
#if RECOVER_FOPS
    fops_recover(cpy);
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
    fops_check(&org_sysfs_fops);
    fops_check(&org_procfs_fops);
    fops_check(&org_root_fops);
}
