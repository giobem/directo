#ifndef __DIRT_STATE_TABLE__
#define __DIRT_STATE_TABLE__

#include <linux/types.h>
#include <netinet/ip6.h>

#define MAX_SQL_STATEMENT_SIZE 0x200

void init_ST();
int ststore(uint32_t,uint16_t,uint16_t,struct in6_addr *,uint8_t);
uint32_t stget
(uint32_t,uint16_t,uint16_t,struct in6_addr *,uint8_t,uint8_t,int);
#endif
