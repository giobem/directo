# Makefile to build FLIP kernel modules
#
# Author:
# Giovanni Bembo
# Departement of computer engineering
# University of Rome "Tor Vergata"
# Rome, Italy

default:
	gcc -lsqlite3 -o directobot ../../common/dirtlib.c ../../common/icmplib.c ../../common/tcpudplib.c relay_server.c state_table.c icmp.c tcpudp.c directobot.c
	cp directobot /sbin
