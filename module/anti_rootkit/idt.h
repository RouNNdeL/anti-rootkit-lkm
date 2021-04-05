#ifndef _ANTI_ROOTKIT_IDT
#define _ANTI_ROOTKIT_IDT

#include "config.h"

int idt_init(void);
void idt_check(void);

#endif
