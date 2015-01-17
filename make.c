Obj-m := hello_world.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell PWD)
all:
 $(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD)
clean:
 rm -rf *.o *.ko *.symvers *.mod.* *.order
