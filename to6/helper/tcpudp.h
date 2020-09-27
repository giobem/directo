#ifndef __DIRT6_TCPUDP__
#define __DIRT6_TCPUDP__

#include <netinet/ip.h>
#include <netinet/ip6.h>

#define MAX_INTERNET_WINDOW_SIZE 1444

void send_to_relay_tcp_fragment
(
 unsigned char *,unsigned char *,struct iphdr *,struct iphdr *,
 struct sockaddr_in,int
 );
void send_to_relay_tcp
(
 unsigned char *,unsigned char *,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int
 );
void rcv_from_relay_tcp
(
 unsigned char *,unsigned char *,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int
 );
void send_to_relay_udp
(
 unsigned char *,unsigned char *,struct ip6_hdr *,struct iphdr *,
 struct sockaddr_in,int
 );
void rcv_from_relay_udp
(
 unsigned char *,unsigned char *,struct iphdr *,struct ip6_hdr *,
 struct sockaddr_in6,int
 );

#endif
