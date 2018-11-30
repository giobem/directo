#ifndef __DIRT6_ICMP__
#define __DIRT6_ICMP__

void send_to_relay_icmp
(
 unsigned char *,unsigned char *,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int
 );
void rcv_from_relay_icmp
(
 unsigned char *,unsigned char *,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int
 );

#endif
