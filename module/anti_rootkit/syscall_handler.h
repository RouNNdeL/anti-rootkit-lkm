#ifndef _ANTI_ROOTKIT_SYSCALL_HANDLER
#define _ANTI_ROOTKIT_SYSCALL_HANDLER

#include <asm/msr.h>
#include <asm/msr-index.h>
#include "config.h"

static inline void *get_syscall_64_handler(void)
{
    unsigned long system_call_entry;
    rdmsrl(MSR_LSTAR, system_call_entry);
    return (void *)system_call_entry;
}

static inline void set_syscall_64_handler(void *val)
{
    wrmsrl(MSR_LSTAR, (unsigned long)val);
}

bool syscall_handler_changed(void);
void syscall_handler_recover(void);
void syscall_handler_check(void);
void syscall_handler_init(void);


#endif
