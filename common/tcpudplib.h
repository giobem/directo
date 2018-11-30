#ifndef __DIRT_TCPUDP_LIB__
#define __DIRT_TCPUDP_LIB__

#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define MAX_TCP_PAYLOAD_LEN 1485
#define MAX_UDP_PAYLOAD_LEN 1497

__be16 tcp_udp_v4_checksum
(struct in_addr,struct in_addr,uint8_t,const void *,uint16_t);

__be16 tcp_udp_v6_checksum
(const struct in6_addr *,const struct in6_addr *,__u8,const void *,__u32);

#endif
