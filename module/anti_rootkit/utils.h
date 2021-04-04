#ifndef _ANTI_ROOTKIT_UTILS
#define _ANTI_ROOTKIT_UTILS

#include <asm/special_insns.h>

// Newer kernel versions prevent clearing the WP bit
static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void wp_disable(void)
{
    _write_cr0(read_cr0 () & (~0x10000));
}

static inline void wp_enable(void)
{
    _write_cr0(read_cr0() | 0x10000);
}

unsigned long lookup_name(const char* name);

struct file_operations *get_fop(const char *path);

#endif
