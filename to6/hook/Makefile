# Makefile to build FLIP kernel modules
#
# Author:
# Giovanni Bembo
# Departement of computer engineering
# University of Rome "Tor Vergata"
# Rome, Italy
# syntax:
# make -f Makefile.jB CFLAGS_gvn_hook.o=-DjB
# sudo make -f Makefile.jB install

ifneq ($(KERNELRELEASE),)

obj-m := directo6.o

else

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	cp directo6.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter/

endif

.PHONY: clean

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c Module.* modules.*
