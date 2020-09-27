#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "../../common/dirtlib.h"
#include "../../common/tcpudplib.h"
#include "directobot.h"
#include "state_table.h"
#include "tcpudp.h"

void sendto4tcp
(
 unsigned char *pkt,unsigned char *buffer,struct ip6_hdr *hdr6s,
 struct iphdr *hdr4s,struct sockaddr_in s_in,int raws_tcp,uint8_t flags
 )
{
  struct iphdr *hdr4;
  struct ip6_hdr *hdr6;
  unsigned char *tcp6_data,*tcp4_data,*ipv6_footer,*cs,*drft;
  struct direct_footer *drtftr;
  struct tcphdr *tcph,*tcp6h;
  int tcp6_data_len,i,is;
  uint32_t ip4dst;
  unsigned char *swap;

  hdr4=(struct iphdr *)buffer;
  hdr6=(struct ip6_hdr *)pkt;
  tcp6_data=
    (unsigned char *)(pkt+sizeof(struct ip6_hdr)+sizeof(struct tcphdr));
  tcph=(struct tcphdr *)(buffer+sizeof(struct iphdr));
  tcp6h=(struct tcphdr *)(pkt+sizeof(struct ip6_hdr));
  switch (flags)
    {
    case RELAY_TO4DR:
      {
        tcp6_data_len=
          ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct tcphdr)-
          sizeof(struct in_addr)-sizeof(struct direct_footer);
        if (
            tcp6_data_len+sizeof(struct in6_addr)+sizeof(struct direct_footer)
            >
            MAX_TCP_PAYLOAD_LEN
            )
          return;
        break;
      }
    case RELAY_TO4:
      {
        tcp6_data_len=
          ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct tcphdr)-
          sizeof(struct in_addr)-sizeof(struct direct_footer);
        if (tcp6_data_len>MAX_TCP_PAYLOAD_LEN)
          return;
        break;
      }
    case NO_CODE:
      {
        if
          (
           (
            ip4dst=
            stget(0,tcp6h->dest,tcp6h->source,&(hdr6->ip6_src),1,IPPROTO_TCP,0)
            )
           )
          {
            hdr4->daddr=ip4dst;
            s_in.sin_addr=*((struct in_addr *)&ip4dst);
           }
        else
          return;
        tcp6_data_len=
          ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct tcphdr);
        if (
            tcp6_data_len+sizeof(struct in_addr)+sizeof(struct direct_footer)
            >
            MAX_TCP_PAYLOAD_LEN
            )
          return;
        flags=RELAY_TO4DR;
        break;
      }
    default:
      return;
    }
  memcpy(tcph,tcp6h,sizeof(struct tcphdr));
  tcp4_data=buffer+sizeof(struct iphdr)+sizeof(struct tcphdr);
  memcpy(tcp4_data,tcp6_data,tcp6_data_len);
  switch (flags)
    {
    case RELAY_TO4DR:
      {
        ipv6_footer=tcp4_data+tcp6_data_len;
        memcpy(ipv6_footer,&(hdr6->ip6_src),sizeof(struct in6_addr));
        drtftr=
          (struct direct_footer *)(ipv6_footer+sizeof(struct in6_addr));
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
        break;
      }
    default:
      {
        hdr4->tot_len=
          htons(tcp6_data_len+sizeof(struct tcphdr)+sizeof(struct iphdr));
        ststore
          (hdr4->daddr,tcp6h->dest,tcp6h->source,&(hdr6->ip6_src),IPPROTO_TCP);
        break;
      }
    }
  hdr4->protocol=IPPROTO_TCP;
  tcph->check=0;
  tcph->check=
    tcp_udp_v4_checksum
    (
     *((struct in_addr *)(&(hdr4->saddr))),
     *((struct in_addr *)(&(hdr4->daddr))),IPPROTO_TCP,(void *)tcph,
     (ntohs(hdr4->tot_len)-sizeof(struct iphdr))
     );
  hdr4->check=csum((unsigned short *)pkt,ntohs(hdr4->tot_len));
  sendto
    (
     raws_tcp,buffer,ntohs(hdr4->tot_len),0,(struct sockaddr *)&(s_in),
     sizeof(struct sockaddr_in)
     );
}

void sendto6tcp_fragment
(
 unsigned char *pkt,unsigned char *buffer,struct ip6_hdr *hdr6_full,
 struct ip6_hdr *hdr6_frag,struct sockaddr_in6 s6_in,int raws_tcp6,
 uint8_t flags
 )
{
  unsigned char *hdr6_frag_data,*hdr6_full_data;
  struct ip6_frag *hdr6_frag_hdr;

  hdr6_frag_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct ip6_frag);
  hdr6_full_data=pkt+sizeof(struct ip6_hdr);
  hdr6_frag_hdr=(struct ip6_frag *)(buffer+sizeof(struct ip6_hdr));
  memcpy
    (
     hdr6_frag_data,hdr6_full_data,
     ntohs(hdr6_full->ip6_ctlun.ip6_un1.ip6_un1_plen)
     );
  hdr6_frag->ip6_ctlun.ip6_un1.ip6_un1_plen=
    hdr6_full->ip6_ctlun.ip6_un1.ip6_un1_plen;
  int a;
  a=sendto
    (
     raws_tcp6,buffer,
     ntohs(hdr6_frag->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr)
     +sizeof(struct ip6_frag),
     0,
     (struct sockaddr *)&(s6_in),
     sizeof(struct sockaddr_in6)
     );
}

void sendto6tcp
(
 unsigned char *pkt,unsigned char *buffer,struct iphdr *hdr4,
 struct ip6_hdr *hdr6,struct sockaddr_in6 s6_in,int raws_tcp6,uint8_t flags
 )
{
  unsigned char *tcp4_data,*tcp6_data,*ipv4_footer,*cs;
  struct direct_footer *drtftr;
  struct tcphdr *tcp4h,*tcp6h;
  uint16_t is;
  int tcp4_data_len;
  unsigned char *swap;

  tcp4_data=
    (unsigned char *)(pkt+sizeof(struct iphdr)+sizeof(struct tcphdr));
  tcp6h=(struct tcphdr *)(buffer+sizeof(struct ip6_hdr));
  tcp4h=(struct tcphdr *)(pkt+sizeof(struct iphdr));
  switch (flags)
    {
    case RELAY_TO6DR:
      {
        tcp4_data_len=
          ntohs(hdr4->tot_len)-sizeof(struct tcphdr)-sizeof(struct iphdr)-
          sizeof(struct in6_addr)-sizeof(struct direct_footer);
        break;
      }
    case RELAY_TO6:
      {
        tcp4_data_len=
          ntohs(hdr4->tot_len)-sizeof(struct tcphdr)-sizeof(struct iphdr)-
          sizeof(struct in6_addr)-sizeof(struct direct_footer);
        break;
      }
    case NO_CODE:
      {
      }
    }
  memcpy(tcp6h,tcp4h,sizeof(struct tcphdr));
  tcp6_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct tcphdr);
  memcpy(tcp6_data,tcp4_data,tcp4_data_len);
  if (flags==RELAY_TO6DR)
    {
      ipv4_footer=tcp6_data+tcp4_data_len;
      memcpy(ipv4_footer,&(hdr4->saddr),sizeof(struct in_addr));
      drtftr=
        (struct direct_footer *)(ipv4_footer+sizeof(struct in_addr));
      hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
        htons
        (
         sizeof(struct direct_footer)+sizeof(struct in_addr)+
         tcp4_data_len+sizeof(struct tcphdr)
         );
      drtftr->len=
        htons
        (
         ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-
         (sizeof(struct in_addr)+sizeof(struct direct_footer))
         );
      drtftr->code=RELAY_TO4;
    }
  else
    {
      hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
        htons(tcp4_data_len+sizeof(struct tcphdr));
      ststore
        (hdr4->saddr,tcp4h->source,tcp4h->dest,&(hdr6->ip6_dst),IPPROTO_TCP);
    }
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt=IPPROTO_TCP;
  tcp6h->check=0;
  tcp6h->check=
    tcp_udp_v6_checksum
    (
     &(hdr6->ip6_src),&(hdr6->ip6_dst),IPPROTO_TCP,(void *)tcp6h,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)
     );
  if (ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)<=MAX_TCP_PAYLOAD_LEN)
    sendto
    (
     raws_tcp6,buffer,
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr),
     0,(struct sockaddr *)&(s6_in),sizeof(struct sockaddr_in6)
     );
}

void sendto4udp
(
 unsigned char *const pkt,unsigned char *const buffer,struct ip6_hdr *hdr6,
 struct iphdr *hdr4,struct sockaddr_in s_in,int raws_udp,uint8_t flags
 )
{
  unsigned char *udp6_data,*udp4_data,*ipv6_footer;
  struct direct_footer *drtftr;
  struct udphdr *udph,*udp6h;
  int udp6_data_len,i;
  uint32_t ip4dst;

  udp6_data=
    (unsigned char *)(pkt+sizeof(struct ip6_hdr)+sizeof(struct udphdr));
  udp6_data_len=
    ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-sizeof(struct udphdr);
  udph=(struct udphdr *)(buffer+sizeof(struct iphdr));
  udp6h=(struct udphdr *)(pkt+sizeof(struct ip6_hdr));
  udph->source=udp6h->source;
  udph->dest=udp6h->dest;
  udp4_data=buffer+sizeof(struct iphdr)+sizeof(struct udphdr);
  switch (flags)
    {
    case NO_CODE:
      {
        if
          (
           (
            ip4dst=
            stget(0,udp6h->dest,udp6h->source,&(hdr6->ip6_src),1,IPPROTO_UDP,0)
            )
           )
          {
            hdr4->daddr=ip4dst;
            s_in.sin_addr=*((struct in_addr *)&ip4dst);
          }
        else
          return;
        udp6_data_len+=sizeof(struct direct_footer)+sizeof(struct in_addr);
        flags=RELAY_TO4DR;
      }
    case RELAY_TO4DR:
      {
        udp6_data_len-=(sizeof(struct direct_footer)+sizeof(struct in_addr));
        if (
            udp6_data_len+sizeof(struct in6_addr)+
            sizeof(struct direct_footer)
            >
            MAX_UDP_PAYLOAD_LEN
            )
          return;
        break;
      }
    default: break;
    }
  memcpy(udp4_data,udp6_data,udp6_data_len);
  switch (flags)
    {
    case RELAY_TO4DR:
      {
        ipv6_footer=udp4_data+udp6_data_len;
        memcpy(ipv6_footer,&(hdr6->ip6_src),sizeof(struct in6_addr));
        drtftr=
          (struct direct_footer *)(ipv6_footer+sizeof(struct in6_addr));
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
        udph->len=
          htons
          (
           sizeof(struct udphdr)+udp6_data_len+
           sizeof(struct direct_footer)+
           sizeof(struct in6_addr)
           );
        break;
      }
    default:
      {
        hdr4->tot_len=
          htons(udp6_data_len+sizeof(struct udphdr)+sizeof(struct iphdr));
        udph->len=htons(sizeof(struct udphdr)+udp6_data_len);
        ststore
          (hdr4->daddr,udp6h->dest,udp6h->source,&(hdr6->ip6_src),IPPROTO_UDP);
        break;
      }
    }
  hdr4->protocol=IPPROTO_UDP;
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
     raws_udp,buffer,ntohs(hdr4->tot_len),0,(struct sockaddr *)&(s_in),
     sizeof(struct sockaddr_in)
     );
}

void sendto6udp
(
 unsigned char *const pkt,unsigned char *const buffer,struct iphdr *hdr4,
 struct ip6_hdr *hdr6,struct sockaddr_in6 s6_in,int raws_udp6,uint8_t flags
 )
{
  unsigned char *udp4_data,*udp6_data,*ipv4_footer;
  struct direct_footer *drtftr;
  struct udphdr *udp4h,*udp6h;
  int udp4_data_len;

  udp4_data=
    (unsigned char *)(pkt+sizeof(struct iphdr)+sizeof(struct udphdr));
  udp4_data_len=
    ntohs(hdr4->tot_len)-sizeof(struct udphdr)-sizeof(struct iphdr)-
    sizeof(struct in6_addr)-sizeof(struct direct_footer);
  if (flags==RELAY_TO6DR)
    if (
        udp4_data_len+sizeof(struct in_addr)+sizeof(struct direct_footer)
        >
        MAX_UDP_PAYLOAD_LEN
        )
      return;
  udp6h=(struct udphdr *)(buffer+sizeof(struct ip6_hdr));
  udp4h=(struct udphdr *)(pkt+sizeof(struct iphdr));
  udp6h->source=udp4h->source;
  udp6h->dest=udp4h->dest;
  udp6_data=buffer+sizeof(struct ip6_hdr)+sizeof(struct udphdr);
  memcpy(udp6_data,udp4_data,udp4_data_len);
  if (flags==RELAY_TO6DR)
    {
      ipv4_footer=udp6_data+udp4_data_len;
      memcpy(ipv4_footer,&(hdr4->saddr),sizeof(struct in_addr));
      drtftr=
        (struct direct_footer *)(ipv4_footer+sizeof(struct in_addr));
      hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
        htons
        (
         sizeof(struct direct_footer)+sizeof(struct in_addr)+
         udp4_data_len+sizeof(struct udphdr)
         );
      drtftr->len=
        htons
        (
         ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)-
         (sizeof(struct in_addr)+sizeof(struct direct_footer))
         );
      drtftr->code=RELAY_TO4;
      udp6h->len=
        htons
        (
         sizeof(struct udphdr)+udp4_data_len+
         sizeof(struct direct_footer)+
         sizeof(struct in_addr)
         );
    }
  else
    {
      hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen=
        htons(udp4_data_len+sizeof(struct udphdr));
      udp6h->len=htons(sizeof(struct udphdr)+udp4_data_len);
      ststore
        (hdr4->saddr,udp4h->source,udp4h->dest,&(hdr6->ip6_dst),IPPROTO_UDP);
    }
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
     ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr),
     0,(struct sockaddr *)&(s6_in),sizeof(struct sockaddr_in6)
     );
}
