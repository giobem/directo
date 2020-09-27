#include <errno.h>

#include <string.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "directo6.h"
#include "tcpudp.h"
#include "../../common/dirtlib.h"
#include "../../common/tcpudplib.h"

void send_to_relay_tcp_fragment
(
 unsigned char *pkt,unsigned char *buffer,struct iphdr *hdr4_full,
 struct iphdr *hdr4_frag,struct sockaddr_in s_in,int raws_tcp
 )
{
  unsigned char *hdr4_frag_data,*hdr4_full_data,*ipv6_footer_data;
  struct direct_footer *drtftr;

  hdr4_frag_data=buffer+sizeof(struct iphdr);
  hdr4_full_data=pkt+sizeof(struct iphdr);
  memcpy
    (
     hdr4_frag_data,hdr4_full_data,
     ntohs(hdr4_full->tot_len)-sizeof(struct iphdr)
     );
  hdr4_frag->tot_len=hdr4_full->tot_len;
  hdr4_frag->frag_off=hdr4_full->frag_off;
  hdr4_frag->protocol=IPPROTO_TCP;
  hdr4_frag->check=csum((unsigned short *)pkt,ntohs(hdr4_frag->tot_len));
  sendto
    (
     raws_tcp,buffer,ntohs(hdr4_frag->tot_len),0,(struct sockaddr *)&(s_in),
     sizeof(struct sockaddr_in)
     );
}

void send_to_relay_tcp
(
 unsigned char *pkt,unsigned char *buffer,struct ip6_hdr *hdr6,
 struct iphdr *hdr4,struct sockaddr_in s_in,int raws_tcp
 )
{
  unsigned char *tcp6_data,*tcp4_data,*ipv6_footer_data;
  struct direct_footer *drtftr;
  struct tcphdr *tcph,*tcp6h;
  int tcp6_data_len;

  tcp6_data=
    (unsigned char *)(pkt+sizeof(struct ip6_hdr)+sizeof(struct tcphdr));
  tcp6_data_len=
    ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct tcphdr);
  //  if (tcp6_data_len>MAX_TCP_PAYLOAD_LEN)
  //    return;
  tcph=(struct tcphdr *)(buffer+sizeof(struct iphdr));
  tcp6h=(struct tcphdr *)(pkt+sizeof(struct ip6_hdr));
  memcpy(tcph,tcp6h,sizeof(struct tcphdr));
  tcp4_data=buffer+sizeof(struct iphdr)+sizeof(struct tcphdr);
  memcpy(tcp4_data,tcp6_data,tcp6_data_len);
  ipv6_footer_data=tcp4_data+tcp6_data_len;
  memcpy(ipv6_footer_data,&(hdr6->ip6_dst),sizeof(struct in6_addr));
  drtftr=
    (struct direct_footer *)(ipv6_footer_data+sizeof(struct in6_addr));
  hdr4->tot_len=
    htons
    (
     sizeof(struct direct_footer)+sizeof(struct in6_addr)+
     tcp6_data_len+sizeof(struct tcphdr)+sizeof(struct iphdr)
     );
  drtftr->len=
    htons
    (
     ntohs(hdr4->tot_len)-
     (sizeof(struct in6_addr)+sizeof(struct direct_footer))
     );
  drtftr->code=RELAY_TO6;
  hdr4->protocol=IPPROTO_TCP;
  tcph->check=0;
  tcph->check=
    tcp_udp_v4_checksum
    (
     *((struct in_addr *)(&(hdr4->saddr))),
     *((struct in_addr *)(&(hdr4->daddr))),
     IPPROTO_TCP,
     (void *)tcph,
     (ntohs(hdr4->tot_len)-sizeof(struct iphdr))
     );
  hdr4->check=csum((unsigned short *)pkt,ntohs(hdr4->tot_len));
  if (tcp6_data_len<=MAX_TCP_PAYLOAD_LEN)
    sendto
      (
       raws_tcp,buffer,ntohs(hdr4->tot_len),0,(struct sockaddr *)&(s_in),
       sizeof(struct sockaddr_in)
       );
}

void rcv_from_relay_tcp
(
 unsigned char *pkt,unsigned char *buffer,struct iphdr *hdr4,
 struct ip6_hdr *hdr6,struct sockaddr_in6 s6_in,int raws_tcp6
 )
{
  unsigned char *tcp4_data,*tcp6_data;
  struct tcphdr *tcp4h,*tcp6h;
  int tcp4_data_len;

  tcp4_data=
    (unsigned char *)(pkt+sizeof(struct iphdr)+sizeof(struct tcphdr));
  tcp4_data_len=
    ntohs(hdr4->tot_len)-sizeof(struct tcphdr)-sizeof(struct iphdr)-
    sizeof(struct in6_addr)-sizeof(struct direct_footer);
  if (tcp4_data_len>MAX_TCP_PAYLOAD_LEN)
    {dirtlog("tcp4 too large");return;}
  tcp6h=(struct tcphdr *)(buffer+sizeof(struct ip6_hdr));
  tcp4h=(struct tcphdr *)(pkt+sizeof(struct iphdr));
  memcpy(tcp6h,tcp4h,sizeof(struct tcphdr));
  tcp6_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
  memcpy(tcp6_data,tcp4_data,tcp4_data_len);
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
    htons(tcp4_data_len+sizeof(struct tcphdr));
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt=IPPROTO_TCP;
  tcp6h->check=0;
  tcp6h->check=
    tcp_udp_v6_checksum
    (
     &(hdr6->ip6_src),&(hdr6->ip6_dst),IPPROTO_TCP,(void *)tcp6h,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)
     );
  sendto
    (
     raws_tcp6,buffer,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr),0,
     (struct sockaddr *)&(s6_in),sizeof(struct sockaddr_in6)
     );
}

void send_to_relay_udp
(
 unsigned char *pkt,unsigned char *buffer,struct ip6_hdr *hdr6,
 struct iphdr *hdr4,struct sockaddr_in s_in,int raws_udp
 )
{
  unsigned char *udp6_data,*udp4_data,*ipv6_footer_data;
  struct direct_footer *drtftr;
  struct udphdr *udph,*udp6h;
  int udp6_data_len;

  udp6_data=
    (unsigned char *)(pkt+sizeof(struct ip6_hdr)+sizeof(struct udphdr));
  udp6_data_len=
    ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct udphdr);
  if (udp6_data_len>MAX_UDP_PAYLOAD_LEN)
    return;
  udph=(struct udphdr *)(buffer+sizeof(struct iphdr));
  udp6h=(struct udphdr *)(pkt+sizeof(struct ip6_hdr));
  udph->source=udp6h->source;
  udph->dest=udp6h->dest;
  udp4_data=buffer+sizeof(struct iphdr)+sizeof(struct udphdr);
  memcpy(udp4_data,udp6_data,udp6_data_len);
  ipv6_footer_data=udp4_data+udp6_data_len;
  memcpy(ipv6_footer_data,&(hdr6->ip6_dst),sizeof(struct in6_addr));
  drtftr=
    (struct direct_footer *)(ipv6_footer_data+sizeof(struct in6_addr));
  hdr4->tot_len=
    htons
    (
     sizeof(struct direct_footer)+sizeof(struct in6_addr)+
     udp6_data_len+sizeof(struct udphdr)+sizeof(struct iphdr)
     );
  drtftr->len=
    htons
    (
     ntohs(hdr4->tot_len)-
     (sizeof(struct in6_addr)+sizeof(struct direct_footer))
     );
  drtftr->code=RELAY_TO6;
  hdr4->protocol=IPPROTO_UDP;
  udph->len=
    htons
    (
     sizeof(struct udphdr)+udp6_data_len+sizeof(struct direct_footer)+
     sizeof(struct in6_addr)
     );
  udph->check=0;
  udph->check=
    tcp_udp_v4_checksum
    (
     *((struct in_addr *)(&(hdr4->saddr))),
     *((struct in_addr *)(&(hdr4->daddr))),
     IPPROTO_UDP,
     (void *)udph,
     (ntohs(hdr4->tot_len)-sizeof(struct iphdr))
     );
  hdr4->check=csum((unsigned short *)pkt,ntohs(hdr4->tot_len));
  sendto
    (
     raws_udp,buffer,
     ntohs(hdr4->tot_len),0,
     (struct sockaddr *)&s_in,sizeof(struct sockaddr_in)
     );
}

void rcv_from_relay_udp
(
 unsigned char *pkt,unsigned char *buffer,struct iphdr *hdr4,
 struct ip6_hdr *hdr6,struct sockaddr_in6 s6_in,int raws_udp6
 )
{
  unsigned char *udp4_data,*udp6_data;
  struct udphdr *udp4h,*udp6h;
  int udp4_data_len;

  udp4_data=
    (unsigned char *)(pkt+sizeof(struct iphdr)+sizeof(struct udphdr));
  udp4_data_len=
    ntohs(hdr4->tot_len)-sizeof(struct udphdr)-sizeof(struct iphdr)-
    sizeof(struct in6_addr)-sizeof(struct direct_footer);
  if (udp4_data_len>MAX_UDP_PAYLOAD_LEN)
    return;
  udp6h=(struct udphdr *)(buffer+sizeof(struct ip6_hdr));
  udp4h=(struct udphdr *)(pkt+sizeof(struct iphdr));
  udp6h->source=udp4h->source;
  udp6h->dest=udp4h->dest;
  udp6_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct udphdr);
  memcpy(udp6_data,udp4_data,udp4_data_len);
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
    htons(udp4_data_len+sizeof(struct udphdr));
  udp6h->len=htons(sizeof(struct udphdr)+udp4_data_len);
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt=IPPROTO_UDP;
  udp6h->check=0;
  udp6h->check=
    tcp_udp_v6_checksum
    (
     &(hdr6->ip6_src),&(hdr6->ip6_dst),IPPROTO_UDP,(void *)udp6h,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)
     );
  sendto
    (
     raws_udp6,buffer,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr),0,
     (struct sockaddr *)&s6_in,sizeof(struct sockaddr_in6)
     );
}
