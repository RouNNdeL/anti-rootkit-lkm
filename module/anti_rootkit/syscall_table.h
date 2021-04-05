#ifndef _ANTI_ROOTKIT_SYSCALL_TABLE
#define _ANTI_ROOTKIT_SYSCALL_TABLE

#include <linux/list.h>
#include <linux/syscalls.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include "config.h"
#include "utils.h"

#define ENTRY_DO_CALL_OFFSET 0x77

struct table_overwrite *find_syscall_overrides(void);

void syscall_table_recover(const struct table_overwrite *head);
void free_syscall_overwrites(struct table_overwrite *head);
void copy_syscall_table(void);
int syscall_table_init(void);

void **find_syscall_table(void);

static inline void syscall_table_check(void)
{
    struct table_overwrite *head;

    head = find_syscall_overrides();
    if (head == NULL) {
        pr_err("Unable to get syscall overwrites");
        return;
    }

    if (!list_empty(&head->list)) {
        print_table_overwrites("syscall table", head);
#if RECOVER_SYSCALL_TABLE
        syscall_table_recover(head);
#endif /* RECOVER_SYSCALL_TABLE */
        free_syscall_overwrites(head);
    }
}

#endif
