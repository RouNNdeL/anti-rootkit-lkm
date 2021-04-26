#include <linux/fs.h>
#include <linux/kallsyms.h>

#include "config.h"
#include "fops.h"
#include "utils.h"

static struct important_fops org_sysfs_fops;
static struct important_fops org_procfs_fops;
static struct important_fops org_rootfs_fops;

#define PRINT_SYMBOL(buf, fops, name)                                          \
    if (fops->name) {                                                          \
        sprint_symbol(buf, (unsigned long)fops->name);                         \
        pr_info(#name " is %s@%px", buf, fops->name);                          \
    }

static void print_fops(const struct file_operations *fops)
{
    char buf[KSYM_NAME_LEN];

    PRINT_SYMBOL(buf, fops, read);
    PRINT_SYMBOL(buf, fops, read_iter);
    PRINT_SYMBOL(buf, fops, write);
    PRINT_SYMBOL(buf, fops, write_iter);
    PRINT_SYMBOL(buf, fops, iterate_shared);
    PRINT_SYMBOL(buf, fops, llseek);
    PRINT_SYMBOL(buf, fops, fsync);
}

static void copy_important_fops(struct important_fops *cpy, const struct file_operations *org)
{
    fprot_safe_cpy(&cpy->read, org->read);
    cpy->read.addr = org->read;

    fprot_safe_cpy(&cpy->read_iter, org->read_iter);
    cpy->read_iter.addr = org->read_iter;

    fprot_safe_cpy(&cpy->write, org->write);
    cpy->write.addr = org->write;

    fprot_safe_cpy(&cpy->write_iter, org->write_iter);
    cpy->write_iter.addr = org->write_iter;

    fprot_safe_cpy(&cpy->iterate_shared, org->iterate_shared);
    cpy->iterate_shared.addr = org->iterate_shared;

    fprot_safe_cpy(&cpy->llseek, org->llseek);
    cpy->llseek.addr = org->llseek;

    fprot_safe_cpy(&cpy->fsync, org->fsync);
    cpy->fsync.addr = org->fsync;

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
    if (fprot_validate(&cpy->iterate_shared))
        ret |= FOPS_OVERWRITE_ITERATE_SHARED;
    if (fprot_validate(&cpy->llseek))
        ret |= FOPS_OVERWRITE_LLSEEK;
    if (fprot_validate(&cpy->fsync))
        ret |= FOPS_OVERWRITE_FSYNC;

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
    fprot_recover(&cpy->iterate_shared);
    fprot_recover(&cpy->llseek);
    fprot_recover(&cpy->fsync);

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
    if (overwrites & FOPS_OVERWRITE_ITERATE_SHARED)
        pr_warn("'iterate_shared' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_LLSEEK)
        pr_warn("'llseek' file operations overwrite detected");
    if (overwrites & FOPS_OVERWRITE_FSYNC)
        pr_warn("'fsync' file operations overwrite detected");
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
    print_fops(fops);

    fops = get_fop("/proc");
    if (!fops)
        return -ENXIO;
    copy_important_fops(&org_procfs_fops, fops);
    print_fops(fops);

    fops = get_fop("/");
    if (!fops)
        return -ENXIO;
    copy_important_fops(&org_rootfs_fops, fops);
    print_fops(fops);

    return 0;
}

void fops_check_all(void)
{
    pr_info("checking fops: 'sysfs'");
    fops_check(&org_sysfs_fops);

    pr_info("checking fops: 'procfs'");
    fops_check(&org_procfs_fops);

    pr_info("checking fops: 'rootfs'");
    fops_check(&org_rootfs_fops);

}

