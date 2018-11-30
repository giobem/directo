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

default:
	gcc -o directo6 ../../common/dirtlib.c ../../common/icmplib.c ../../common/tcpudplib.c tcpudp.c icmp.c translator.c directo6.c
	cp directo6 /sbin
