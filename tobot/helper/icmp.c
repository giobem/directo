#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include "../../common/dirtlib.h"
#include "../../common/icmplib.h"
#include "icmp.h"

void sendto4icmp
(
 unsigned char *const pkt,unsigned char *const buffer,struct ip6_hdr *hdr6,
 struct iphdr *hdr4,struct sockaddr_in s_in,int raws_icmp,uint8_t flags
 )
{
  unsigned char *icmp6_data,*icmp4_data;
  struct direct_footer *drtftr;
  struct icmphdr *icmph;
  struct icmp6_hdr *icmp6h;
  int icmp6_data_len,icmp4_data_len;

  s_in.sin_port=0;
  icmp6_data=
    (unsigned char *)
    (pkt+sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr));
  icmp6_data_len=
    ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct icmp6_hdr)-
    sizeof(struct direct_footer)-sizeof(struct in_addr);
  if
    (
     icmp6_data_len+sizeof(struct in6_addr)+sizeof(struct direct_footer)
     >
     MAX_ICMP_PAYLOAD_LEN
     )
    return;
  icmph=(struct icmphdr *)(buffer+sizeof(struct iphdr));
  icmp6h=(struct icmp6_hdr *)(pkt+sizeof(struct ip6_hdr));
  if (build_icmp4(icmph,icmp6h))
    return;
  memcpy
    (
     (((unsigned char *)icmph)+sizeof(struct icmphdr)),icmp6_data,
     icmp6_data_len
     );
  memcpy
    (
     (((unsigned char *)icmph)+sizeof(struct icmphdr)+icmp6_data_len),
     &(hdr6->ip6_src),sizeof(struct in6_addr)
           );
  drtftr=
    (struct direct_footer *)
    (
     ((unsigned char *)icmph)+sizeof(struct icmphdr)+icmp6_data_len+
     sizeof(struct in6_addr)
     );
  hdr4->tot_len=
    htons
    (
     sizeof(struct direct_footer)+sizeof(struct in6_addr)+icmp6_data_len+
     sizeof(struct icmphdr)+sizeof(struct iphdr)
     );
  drtftr->len=
    htons
    (
     ntohs(hdr4->tot_len)-
     (sizeof(struct in6_addr)+sizeof(struct direct_footer))
     );
  drtftr->code=RELAY_TO6;
  hdr4->protocol=IPPROTO_ICMP;
  icmph->checksum=0;
  icmph->checksum=
    icmp_cksum((unsigned short *)icmph,sizeof(struct icmphdr));
  hdr4->check=csum((unsigned short *)pkt,ntohs(hdr4->tot_len));
  sendto
    (
     raws_icmp,buffer,ntohs(hdr4->tot_len),0,(struct sockaddr *)&s_in,
     sizeof(struct sockaddr_in)
     );
}

void sendto6icmp
(
 unsigned char *const pkt,unsigned char *const buffer,struct iphdr *hdr4,
 struct ip6_hdr *hdr6,struct sockaddr_in6 s6_in,int raws_icmp6,uint8_t flags
 )
{
  unsigned char *icmp4_data,*icmp6_data,*ipv4_footer;
  struct direct_footer *drtftr;
  struct icmphdr *icmp4h;
  struct icmp6_hdr *icmp6h;
  int icmp4_data_len;

  icmp4_data=
    (unsigned char *)
    (pkt+sizeof(struct iphdr)+sizeof(struct icmphdr));
  icmp4_data_len=
    ntohs(hdr4->tot_len)-sizeof(struct icmphdr)-sizeof(struct iphdr)-
    sizeof(struct in6_addr)-sizeof(struct direct_footer);
  if
    (
     icmp4_data_len+sizeof(struct in_addr)+sizeof(struct direct_footer)
     >
     MAX_ICMP_PAYLOAD_LEN
     )
    return;
  icmp6h=(struct icmp6_hdr *)(buffer+sizeof(struct ip6_hdr));
  icmp4h=(struct icmphdr *)(pkt+sizeof(struct iphdr));
  if (build_icmp6(icmp6h,icmp4h))
    return;
  icmp6_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct icmp6_hdr);
  memcpy(icmp6_data,icmp4_data,icmp4_data_len);
  ipv4_footer=icmp6_data+icmp4_data_len;
  memcpy(ipv4_footer,&(hdr4->saddr),sizeof(struct in_addr));
  drtftr=(struct direct_footer *)(ipv4_footer+sizeof(struct in_addr));
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
    htons
    (
     sizeof(struct direct_footer)+sizeof(struct in_addr)+icmp4_data_len+
     sizeof(struct icmp6_hdr)
     );
  drtftr->len=
    htons
    (
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-
     (sizeof(struct in_addr)+sizeof(struct direct_footer))
     );
  drtftr->code=RELAY_TO4DR;
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt=IPPROTO_ICMPV6;
  icmp6h->icmp6_cksum=0;
  icmp6h->icmp6_cksum=
    icmp6_checksum
    (
     *hdr6,*icmp6h,icmp6_data,sizeof(struct direct_footer)+
     sizeof(struct in_addr)+icmp4_data_len
     );
  sendto
    (
     raws_icmp6,buffer,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr),
     0,(struct sockaddr *)&s6_in,sizeof(struct sockaddr_in6)
     );
}
