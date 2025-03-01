# Define the module name
obj-m += rootsterr.o

EXTRA_CFLAGS=-I$(PWD)/syscalls
# List all object files that make up the module
rootsterr-objs := syscalls/openat.o rootster.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) $(MAKE_OPTS) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $(MAKE_OPTS) clean

