#ifndef __DIRTBOT_ICMP__
#define __DIRTBOT_ICMP__

void sendto4icmp
(
 unsigned char *const,unsigned char *const,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int,uint8_t
 );
void sendto6icmp
(
 unsigned char *const,unsigned char *const,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int,uint8_t
 );

#endif
