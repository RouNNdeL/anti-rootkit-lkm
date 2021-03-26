#ifndef _ANTI_ROOTKIT_SYSCALL_TABLE
#define _ANTI_ROOTKIT_SYSCALL_TABLE

#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include "config.h"

#define ENTRY_DO_CALL_OFFSET 0x77

struct syscall_overwrite {
    unsigned int nr;
    void *original_addr;
    void *overwritten_addr;
    struct list_head list;
};

struct syscall_overwrite *find_syscall_overrides(void);

void print_syscall_overwrites(struct syscall_overwrite *head);
void syscall_table_recover(struct syscall_overwrite *head);
void free_syscall_overwrites(struct syscall_overwrite *head);
void copy_syscall_table(void);
bool syscall_table_init(void);

void **find_syscall_table(void);

static inline void syscall_table_check(void)
{
    struct syscall_overwrite *head;

    head = find_syscall_overrides();
    if (head != NULL) {
        print_syscall_overwrites(head);
#if RECOVER_SYSCALL_TABLE
        syscall_table_recover(head);
#endif /* RECOVER_SYSCALL_TABLE */
        free_syscall_overwrites(head);
    }
}

#endif
