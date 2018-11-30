#ifndef __DIRT_TCPUDP__
#define __DIRT_TCPUDP__

#include <linux/types.h>
#include <netinet/ip6.h>

void sendto4tcp
(
 unsigned char *,unsigned char *,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int,uint8_t
 );
void sendto6tcp
(
 unsigned char *,unsigned char *,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int,uint8_t
 );
void sendto4udp
(
 unsigned char *const,unsigned char *const,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int,uint8_t
 );
void sendto6udp
(
 unsigned char *const,unsigned char *const,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int,uint8_t
 );

#endif
