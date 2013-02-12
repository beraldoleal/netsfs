obj-m += netsfs.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build

all: clean
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules

test: all
	sudo dmesg -c
	clear
	sudo insmod netsfs.ko
	dmesg
	sudo strace mount -t netsfs none /net

clean:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD) clean 
