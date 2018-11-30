# Makefile of DirecToBot kernel modules
#
# Author:
# Giovanni Bembo
# Departement of computer engineering
# University of Rome "Tor Vergata"
# Rome, Italy

ifneq ($(KERNELRELEASE),)

obj-m := directobot.o

else

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	cp directobot.ko /lib/modules/$(shell uname -r)/kernel/net/netfilter/

endif

.PHONY: clean

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c Module.* modules.*
