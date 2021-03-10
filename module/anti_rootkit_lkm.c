#include "asm-generic/fcntl.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "linux/string.h"
#include "linux/types.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <asm/msr.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/msr-index.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krzysztof Zdulski");
MODULE_DESCRIPTION("Simple anti-rookit module for a security course.");
MODULE_VERSION("0.0.1");

void *find_virt_start(void) {
    return phys_to_virt(0);
}

void *find_start_symbol(void) {
    unsigned long addr = 0xffffffff80000000;
    char buf[256];

    while(sprint_symbol(buf, addr) < 20 && addr < 0xffffffffffffffff) {
        addr += 0x100;
    }

    printk(KERN_INFO "We found some symbols, %s @ %px", buf, (void *) addr);

    return (void *) (addr & 0xfffffffffff00000);
}

/* static inline */
/* u8* get_32bit_system_call_handler(void) */
/* { */
/* 	struct desc_ptr interrupt_descriptor_table; */
/* 	gate_desc* interrupt_gates; */

/* 	store_idt(&interrupt_descriptor_table); */
/* 	interrupt_gates = (gate_desc*) interrupt_descriptor_table.address; */

/* 	return (u8*) gate_offset(interrupt_gates[IA32_SYSCALL_VECTOR]); */
/* } */

static inline
void *get_64bit_system_call_handler(void)
{
	uint64_t system_call_entry;
	rdmsrl(MSR_LSTAR, system_call_entry);
	return (void *) system_call_entry;
}

#define ENTRY_DO_CALL_OFFSET 0x77

void **find_syscall_table(void) {
    uint8_t *entry_syscall;
    uint8_t *do_syscall;
    void **syscall_table = NULL;
    uint8_t *addr;
    int32_t offset;

    entry_syscall = get_64bit_system_call_handler();

    // First byte of call is the opcode, following 4 bytes are the signed offset
    offset = *((int *) (entry_syscall + ENTRY_DO_CALL_OFFSET + 1));

    // The call offset should include the 5 instruction bytes 
    do_syscall = entry_syscall + offset + ENTRY_DO_CALL_OFFSET + 5;
    printk(KERN_DEBUG "sym.do_syscall_64 is @ %px", do_syscall);

    for(addr = do_syscall; addr < do_syscall + 0xff; ++addr) {
        if(addr[0] == 0x48 && addr[1] == 0x8b && addr[2] == 0x04 && addr[3] == 0xc5) {
            offset = *((int *) (addr + 4));
            printk(KERN_INFO "offset : %d", offset);
            syscall_table = (void **) (offset < 0 ? 0xffffffff00000000 | offset : offset);
            break;
        }
    }

    return syscall_table;
}

static int __init anti_rootkit_init(void) {
    void **syscall_table;

    printk(KERN_INFO "Loading anti-rootkit module");

    syscall_table = find_syscall_table();
    printk(KERN_INFO "syscall_table is @ %px", syscall_table);
    
    printk(KERN_INFO "Done");

    return 0;
}

static void __exit anti_rootkit_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
