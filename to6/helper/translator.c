#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include "directo6.h"
#include "icmp.h"
#include "tcpudp.h"
#include "../../common/dirtlib.h"

//#define RAND_MAX 0xffff

int one=1;
int sock_max_len=14000;
const int *oneval=&one;
static int raws_icmp=0;
static int raws_icmp6=0;
static int raws_tcp=0;
static int raws_tcp6=0;
static int raws_udp=0;
static int raws_udp6=0;

struct in_addr ipv4_relay,ip4src;
struct in6_addr ipv6_relay,ip6src;
struct sockaddr_in sendsocket,s_in;
struct sockaddr_in6 s6_in;

void rcv_from_relay(unsigned char *pkt,int pkt_len)
{
  unsigned char *ipv4_footer;
  struct direct_footer *drtftr;
  struct iphdr *hdr4;
  struct ip6_hdr *hdr6;
  unsigned char buffer[DIRECTO6_BUFFER_SIZE];

  //  memset(buffer,0,DIRECTO6_BUFFER_SIZE);
  hdr6=(struct ip6_hdr *)buffer;
  drtftr=(struct direct_footer *)(pkt+pkt_len-sizeof(struct direct_footer));
  hdr4=(struct iphdr *)pkt;
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_hlim=hdr4->ttl;
  hdr6->ip6_ctlun.ip6_un2_vfc=hdr4->tos;
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_flow=htonl(0x60000000);
  memcpy(&(hdr6->ip6_dst),&ip6src,sizeof(struct in6_addr));
  memcpy
    (
     &(hdr6->ip6_src),
     (struct in6_addr *)(((unsigned char *)drtftr)-sizeof(struct in6_addr)),
     sizeof(struct in6_addr)
     );
  memcpy(&s6_in.sin6_addr,&ip6src,sizeof(struct in6_addr));
  switch (hdr4->protocol)
    {
    case IPPROTO_UDP:
      {
	rcv_from_relay_udp(pkt,buffer,hdr4,hdr6,s6_in,raws_udp6);
	break;
      }
    case IPPROTO_TCP:
      {
	rcv_from_relay_tcp(pkt,buffer,hdr4,hdr6,s6_in,raws_tcp6);
        break;
      }
    case IPPROTO_ICMP:
      {
	rcv_from_relay_icmp(pkt,buffer,hdr4,hdr6,s6_in,raws_icmp6);
        break;
      }
    default: return;
    }
}

void send_to_relay(unsigned char *pkt,int pkt_len)
{
  struct ip6_hdr *hdr6;
  struct tcphdr *tcph;
  uint8_t v6protocol;
  struct iphdr *hdr4;
  unsigned char buffer[DIRECTO6_BUFFER_SIZE];

  //  memset(buffer,0,DIRECTO6_BUFFER_SIZE);
  hdr4=(struct iphdr *)buffer;
  hdr6=(struct ip6_hdr *)pkt;
  hdr4->ihl=5;
  hdr4->version=4;
  hdr4->ttl=hdr6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
  hdr4->tos=hdr6->ip6_ctlun.ip6_un2_vfc;
  hdr4->id=htons((uint16_t)rand());
  hdr4->frag_off=0; hdr4->check=0;
  memcpy(&(hdr4->saddr),&ip4src,sizeof(struct in_addr));
  memcpy(&(hdr4->daddr),&ipv4_relay,sizeof(struct in_addr));
  switch (hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
    case IPPROTO_UDP:
      {
	send_to_relay_udp(pkt,buffer,hdr6,hdr4,s_in,raws_udp);
	break;
      }
    case IPPROTO_TCP:
      {
	send_to_relay_tcp(pkt,buffer,hdr6,hdr4,s_in,raws_tcp);
	break;
      }
    case IPPROTO_ICMPV6:
      {
	send_to_relay_icmp(pkt,buffer,hdr6,hdr4,s_in,raws_icmp);
	break;
      }
    default: return;
    }
}

void set_host(char *ipv4,char *ipv6)
{
  inet_pton(AF_INET,ipv4,&ip4src);
  inet_pton(AF_INET6,ipv6,&ip6src);
}

void set_relay(char *ipv4,char *ipv6)
{
  inet_pton(AF_INET,ipv4,&ipv4_relay);
  inet_pton(AF_INET6,ipv6,&ipv6_relay);
}

int setsocket(unsigned char *host,unsigned char *relay)
{
  if ((raws_udp=socket(PF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -7;
  if ((raws_tcp=socket(PF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -8;
  if ((raws_icmp=socket(PF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -9;
  if (setsockopt(raws_icmp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -10;
  if (setsockopt(raws_tcp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -11;
  if (setsockopt(raws_udp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -12;
  if ((raws_udp6=socket(AF_INET6,SOCK_RAW,IPPROTO_RAW))==-1)
    return -1;
  if ((raws_tcp6=socket(AF_INET6,SOCK_RAW,IPPROTO_RAW))==-1)
    return -2;
  if ((raws_icmp6=socket(AF_INET6,SOCK_RAW,IPPROTO_RAW))==-1)
    return -3;
  if (setsockopt(raws_icmp6,IPPROTO_IPV6,IP_HDRINCL,oneval,sizeof(one))<0)
    return -4;
  if (setsockopt(raws_tcp6,IPPROTO_IPV6,IP_HDRINCL,oneval,sizeof(one))<0)
    return -5;
  if (setsockopt(raws_udp6,IPPROTO_IPV6,IP_HDRINCL,oneval,sizeof(one))<0)
    return -6;
  if (fcntl(raws_icmp,F_SETFL,fcntl(raws_icmp,F_GETFL,0)|O_NONBLOCK)<0)
    return -13;
  if (fcntl(raws_udp,F_SETFL,fcntl(raws_udp,F_GETFL,0)|O_NONBLOCK)<0)
    return -14;
  if (fcntl(raws_tcp,F_SETFL,fcntl(raws_tcp,F_GETFL,0)|O_NONBLOCK)<0)
    return -15;
  if (fcntl(raws_icmp6,F_SETFL,fcntl(raws_icmp6,F_GETFL,0)|O_NONBLOCK)<0)
    return -16;
  if (fcntl(raws_udp6,F_SETFL,fcntl(raws_udp6,F_GETFL,0)|O_NONBLOCK)<0)
    return -17;
  if (fcntl(raws_tcp6,F_SETFL,fcntl(raws_tcp6,F_GETFL,0)|O_NONBLOCK)<0)
    return -18;
  s6_in.sin6_family=AF_INET6;
  s6_in.sin6_flowinfo=0;
  s6_in.sin6_scope_id=0;
  s_in.sin_family=AF_INET;
  inet_pton(AF_INET,relay,&s_in.sin_addr);
  return 0;
}
