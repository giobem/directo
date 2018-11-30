# Makefile of DirecTo6 kernel modules
#
# Author:
# Giovanni Bembo
# Departement of computer engineering
# University of Rome "Tor Vergata"
# Rome, Italy

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
