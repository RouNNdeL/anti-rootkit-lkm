SRCFILES = $(filter-out $(wildcard *.mod.c), $(wildcard *.c))
OBJFILES = $(SRCFILES:.c=.o)
TARGET = anti_rootkit


obj-m += $(TARGET).o
anti_rootkit-objs += $(OBJFILES)

all:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) modules

clean:
	make -C /home/kris/dev/code/c/bso/kernel M=$(PWD) clean
