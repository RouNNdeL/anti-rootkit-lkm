#include "config.h"

#include <asm/desc_defs.h>
#include <asm/segment.h>
#include <asm/desc.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "utils.h"
#include "idt.h"

#define IDT_TABLE_SIZE (IDT_ENTRIES * sizeof(gate_desc))
#define GATE_DESC_TO_LONG(g)                                                   \
    (unsigned long)(((unsigned long)(g)->offset_low) |                         \
                    ((unsigned long)(g)->offset_middle << 16) |                \
                    ((unsigned long)(g)->offset_high << 32))

static gate_desc idt_copy[IDT_ENTRIES];
static gate_desc *idt_table;

int idt_init(void)
{
    struct desc_ptr idt_info;
    store_idt(&idt_info);
    pr_info("IDT is @ %px with size %d", (void *) idt_info.address, idt_info.size);

    if (idt_info.size != IDT_TABLE_SIZE - 1)
        return -ENXIO;

    memcpy(idt_copy, (void *)idt_info.address, idt_info.size);
    idt_table = (gate_desc *)idt_info.address;

    return 0;
}

static inline long cmp_gate_desc(gate_desc *g1, gate_desc *g2)
{
    return GATE_DESC_TO_LONG(g1) - GATE_DESC_TO_LONG(g2);
}

static struct table_overwrite *find_idt_overwrites(void)
{
    unsigned int i;
    struct table_overwrite *head = kmalloc(sizeof(*head), GFP_KERNEL);
    INIT_LIST_HEAD(&head->list);

    if (head == NULL)
        return NULL;

    for (i = 0; i < IDT_ENTRIES; ++i) {
        if (cmp_gate_desc(&idt_table[i], &idt_copy[i]) != 0) {
            struct table_overwrite *ov = kmalloc(sizeof(*ov), GFP_KERNEL);
            if (ov == NULL)
                return NULL;

            ov->index = i;
            ov->original_addr = GATE_DESC_TO_LONG(&idt_copy[i]);
            ov->overwritten_addr = GATE_DESC_TO_LONG(&idt_table[i]);
            list_add(&ov->list, &head->list);
        }
    }

    return head;
}

void idt_recover(struct table_overwrite *head)
{
    struct table_overwrite *ov;

    pr_info("recovering idt table");
    wp_disable();
    list_for_each_entry (ov, &head->list, list) {
        idt_table[ov->index].offset_high = ov->original_addr >> 32;
        idt_table[ov->index].offset_middle = (ov->original_addr >> 16) & 0xffff;
        idt_table[ov->index].offset_low = ov->original_addr & 0xffff;
    }
    wp_enable();
}

void idt_check(void)
{
    struct table_overwrite *head;

    head = find_idt_overwrites();
    print_table_overwrites("idt", head);
    /* idt_recover(head); */
    free_syscall_overwrites(head);
}
