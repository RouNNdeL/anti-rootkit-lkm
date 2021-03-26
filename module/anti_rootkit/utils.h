#ifndef _ANTI_ROOTKIT_UTILS
#define _ANTI_ROOTKIT_UTILS

#include <asm/special_insns.h>

// Newer kernel versions prevent clearing the WP bit
static inline void _write_cr0(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline void disable_wp(void)
{
    _write_cr0(read_cr0 () & (~0x10000));
}

static inline void enable_wp(void)
{
    _write_cr0(read_cr0() | 0x10000);
}

unsigned long lookup_name(const char* name);

#endif
