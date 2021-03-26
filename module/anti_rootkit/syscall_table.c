#include <linux/gfp.h>
#include <linux/slab.h>
#include <asm/page_types.h>
#include "syscall_table.h"
#include "syscall_handler.h"
#include "utils.h"
#include "config.h"

static void **syscall_table;
static void *syscall_table_cpy[NR_syscalls];

void copy_syscall_table(void)
{
    memcpy(syscall_table_cpy, syscall_table, sizeof(syscall_table_cpy));
}

bool syscall_table_init(void) {
    syscall_table = find_syscall_table();
    if (syscall_table == NULL)
        return false;

    pr_info("syscall_table is @ %px", syscall_table);
    copy_syscall_table();

    return true;
}

void syscall_table_recover(struct syscall_overwrite *head)
{
    struct syscall_overwrite *ov;

    pr_info("Recovering syscall table");
    disable_wp();
    list_for_each_entry (ov, &head->list, list) {
        syscall_table[ov->nr] = ov->original_addr;
    }
    enable_wp();
}

struct syscall_overwrite *find_syscall_overrides(void)
{
    unsigned int nr;
    struct syscall_overwrite *head = kmalloc(sizeof(*head), GFP_KERNEL);
    INIT_LIST_HEAD(&head->list);

    if (head == NULL)
        return NULL;

    for (nr = 0; nr < NR_syscalls; ++nr) {
        if (syscall_table_cpy[nr] != syscall_table[nr]) {
            struct syscall_overwrite *ov = kmalloc(sizeof(*ov), GFP_KERNEL);
            if (ov == NULL)
                return NULL;

            ov->nr = nr;
            ov->original_addr = syscall_table_cpy[nr];
            ov->overwritten_addr = syscall_table[nr];
            list_add(&ov->list, &head->list);
        }
    }

    return head;
}

void **find_syscall_table(void)
{
    unsigned char *entry_syscall;
    unsigned char *do_syscall;
    unsigned char *addr;
    void **syscall_table = NULL;
    int offset;

    entry_syscall = get_syscall_64_handler();

    // First byte of call is the opcode, following 4 bytes are the signed offset
    offset = *((int *)(entry_syscall + ENTRY_DO_CALL_OFFSET + 1));

    // The call offset should include the 5 instruction bytes
    do_syscall = entry_syscall + offset + ENTRY_DO_CALL_OFFSET + 5;
    pr_debug("sym.do_syscall_64 is @ %px", do_syscall);

    for (addr = do_syscall; addr < do_syscall + 0xff; ++addr) {
        if (addr[0] == 0x48 && addr[1] == 0x8b && addr[2] == 0x04 &&
            addr[3] == 0xc5) {
            offset = *((int *)(addr + 4));
            // Sign extend
            syscall_table = (void **)(offset < 0 ? 0xffffffff00000000 | offset :
                                                   offset);
            break;
        }
    }

    return syscall_table;
}


// Kernel consistency check #3
void free_syscall_overwrites(struct syscall_overwrite *head)
{
    struct list_head *cur;
    struct list_head *tmp;
    struct syscall_overwrite *ov;

    list_for_each_safe (cur, tmp, &head->list) {
        ov = list_entry(cur, struct syscall_overwrite, list);
        list_del(cur);
        kfree(ov);
    }

    kfree(head);
}

void print_syscall_overwrites(struct syscall_overwrite *head)
{
    struct syscall_overwrite *ov;

    if (list_empty(&head->list)) {
        pr_info("No overwrites detected");
        return;
    }

    list_for_each_entry (ov, &head->list, list) {
        pr_warn("syscall %d changed, used to be %px, now is %px", ov->nr,
                ov->original_addr, ov->overwritten_addr);
    }
}
