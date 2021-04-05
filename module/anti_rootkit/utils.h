#ifndef _ANTI_ROOTKIT_UTILS
#define _ANTI_ROOTKIT_UTILS

#include <asm/special_insns.h>
#include <linux/list.h>
#include <linux/slab.h>

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

void free_syscall_overwrites(struct table_overwrite *head);
void print_table_overwrites(const char *prefix, const struct table_overwrite *head);

#endif
