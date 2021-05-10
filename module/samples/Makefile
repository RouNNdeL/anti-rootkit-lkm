KERNEL ?= /lib/modules/$(shell uname -r)/build
SRCFILES = $(filter-out $(wildcard *.mod.c), $(wildcard *.c))
OBJFILES = $(SRCFILES:.c=.o)

obj-m += sample_module_list.o sample_pinned_bits.o sample_syscall_table.o sample_syscall_handler.o sample_fops.o

all:
	make -C $(KERNEL) M=$(PWD) modules

clean:
	make -C $(KERNEL) M=$(PWD) clean
