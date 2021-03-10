#include "asm-generic/fcntl.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "linux/string.h"
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

void *find_do_syscall_64(void) {
    void *entry_syscall_addr;
    void *do_syscall_addr;
    int do_syscall_offset;

    entry_syscall_addr = get_64bit_system_call_handler();

    // First byte of call is the opcode, following 4 bytes are the signed offset
    do_syscall_offset = *((int *) (entry_syscall_addr + ENTRY_DO_CALL_OFFSET + 1));

    // The call offset should include the 5 instruction bytes 
    do_syscall_addr = entry_syscall_addr + do_syscall_offset + ENTRY_DO_CALL_OFFSET + 5;
    printk(KERN_INFO "sym.do_syscall_64 is @ %px", do_syscall_addr);

    return do_syscall_addr;
}

static int __init anti_rootkit_init(void) {
    printk(KERN_INFO "Loading anti-rootkit module");

    find_do_syscall_64();
    
    printk(KERN_INFO "Done");

    return 0;
}

static void __exit anti_rootkit_exit(void) {
    printk(KERN_INFO "Goodbye, World!\n");
}

module_init(anti_rootkit_init);
module_exit(anti_rootkit_exit);
