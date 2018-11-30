#ifndef __DIRTBOT_ICMP_LIB__
#define __DIRTBOT_ICMP_LIB__

#include <stdint.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#define MAX_ICMP_PAYLOAD_LEN 1485

int build_icmp4(struct icmphdr *,struct icmp6_hdr *);
int build_icmp6(struct icmp6_hdr *,struct icmphdr *);
unsigned short icmp_cksum(unsigned short *,int);
uint16_t icmp6_checksum(struct ip6_hdr,struct icmp6_hdr,uint8_t *,int);

#endif
