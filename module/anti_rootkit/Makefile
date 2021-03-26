SRCFILES = $(filter-out *.mod.c, $(wildcard *.c))
OBJFILES = $(SRCFILES:.c=.o)


obj-m += anti_rootkit.o
anti_rootkit-objs += main.o utils.o syscall_table.o syscall_handler.o module_list.o ftrace_hooks.o globals.o

all:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) modules

clean:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) clean
