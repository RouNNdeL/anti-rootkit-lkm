#ifndef _ANTI_ROOTKIT_UTILS
#define _ANTI_ROOTKIT_UTILS

#include <linux/list.h>
#include <linux/slab.h>
#include <asm/special_insns.h>

// Newer kernel versions prevent clearing the WP bit
static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void wp_disable(void)
{
    _write_cr0(read_cr0() & (~0x10000));
}

static inline void wp_enable(void)
{
    _write_cr0(read_cr0() | 0x10000);
}

unsigned long lookup_name(const char *name);

struct file_operations *get_fop(const char *path);

struct table_overwrite {
    unsigned int index;
    unsigned long original_addr;
    unsigned long overwritten_addr;
    struct list_head list;
};

void free_table_overwrites(struct table_overwrite *head);
void print_table_overwrites(const char *prefix,
                            const struct table_overwrite *head);

#define FUN_PROTECT_SIZE 12
struct fun_protector {
    uint8_t head[FUN_PROTECT_SIZE];
    void *addr;
};

static inline int fprot_safe_cpy(const struct fun_protector *fprot, void *addr)
{
    if (addr)
        memcpy((void *)fprot->head, addr, FUN_PROTECT_SIZE);

    return 0;
}

static inline int fprot_validate(const struct fun_protector *fprot)
{
    if (fprot->addr)
        return memcmp(fprot->addr, fprot->head, FUN_PROTECT_SIZE);

    return 0;
}

static inline void fprot_recover(const struct fun_protector *fprot)
{
    if (fprot->addr)
        memcpy(fprot->addr, fprot->head, FUN_PROTECT_SIZE);
}

#endif
