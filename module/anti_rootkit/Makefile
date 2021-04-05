MOD_NAME = anti_rootkit
SRCFILES = $(filter-out $(wildcard *.mod.c), $(wildcard *.c))
OBJFILES = $(SRCFILES:.c=.o)

obj-m += $(MOD_NAME).o
$(MOD_NAME)-objs += main.o ftrace_hooks.o globals.o module_list.o syscall_handler.o syscall_table.o utils.o fops.o idt.o

all:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) modules

clean:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) clean
