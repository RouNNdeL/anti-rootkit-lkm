KERNEL ?= /lib/modules/$(shell uname -r)/build
MOD_NAME = anti_rootkit
SRCFILES = $(filter-out $(wildcard *.mod.c), $(wildcard *.c))
OBJFILES = $(SRCFILES:.c=.o)

obj-m += $(MOD_NAME).o
$(MOD_NAME)-objs += fops.o ftrace_hooks.o globals.o idt.o main.o module_list.o important_functions.o syscall_handler.o syscall_table.o utils.o pinned_bits.o 

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
