#include <fcntl.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "../../common/dirtlib.h"
#include "relay_server.h"
#include "state_table.h"
#include "tcpudp.h"

typedef uint64_t u64;

extern unsigned char *buffer;

int one=1;
const int *oneval=&one;
static int raws_icmp=0;
static int raws_icmp6=0;
static int raws_tcp=0;
static int raws_tcp6=0;
static int raws_udp=0;
static int raws_udp6=0;

struct in_addr ip4src;
struct in6_addr ip6src;
struct sockaddr_in s_in;
struct sockaddr_in6 s6_in;

void sendto4(unsigned char *const pkt,int pkt_len,uint8_t flags)
{
  struct direct_footer *drtftr;
  struct ip6_hdr *hdr6;
  struct tcphdr *tcph;
  uint8_t v6protocol;
  struct iphdr *hdr4;

  //  memset(buffer,0,DIRECTOBOT_BUFFER_SIZE);
  hdr4=(struct iphdr *)buffer;
  hdr6=(struct ip6_hdr *)pkt;
  switch (flags)
    {
    case RELAY_TO4DR:
      {
	drtftr=
	  (struct direct_footer *)(pkt+pkt_len-sizeof(struct direct_footer));
	memcpy
	  (
	   &(hdr4->daddr),
	   (struct in_addr *)
	   (((unsigned char *)drtftr)-sizeof(struct in_addr)),
	   sizeof(struct in_addr)
	   );
	memcpy
	  (
	   &s_in.sin_addr,
	   (struct in_addr *)
	   (((unsigned char *)drtftr)-sizeof(struct in_addr)),
	   sizeof(struct in_addr)
	   );	
	break;
      }
    default:
      {
	drtftr=NULL;
	break;
      }
    }
  hdr4->ihl=5;
  hdr4->version=4;
  hdr4->ttl=hdr6->ip6_ctlun.ip6_un1.ip6_un1_hlim;
  hdr4->tos=hdr6->ip6_ctlun.ip6_un2_vfc;
  hdr4->id=htons((uint16_t)rand());
  hdr4->frag_off=0; hdr4->check=0;
  memcpy(&(hdr4->saddr),&ip4src,sizeof(struct in_addr));
  switch (hdr6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
    case IPPROTO_TCP:
      {
        sendto4tcp(pkt,buffer,hdr6,hdr4,s_in,raws_tcp,flags);
        break;
      }
    case IPPROTO_UDP:
      {
	sendto4udp(pkt,buffer,hdr6,hdr4,s_in,raws_udp,flags);
        break;
      }
    case IPPROTO_ICMPV6:
      {
	sendto4icmp(pkt,buffer,hdr6,hdr4,s_in,raws_icmp,flags);
        break;
      }
    default:
      return;
    }
}

void sendto6(unsigned char *pkt,int pkt_len,uint8_t flags)
{
  struct direct_footer *drtftr;
  struct iphdr *hdr4;
  struct ip6_hdr *hdr6;

  //  memset(buffer,0,DIRECTOBOT_BUFFER_SIZE);
  hdr6=(struct ip6_hdr *)buffer;
  drtftr=(struct direct_footer *)(pkt+pkt_len-sizeof(struct direct_footer));
  hdr4=(struct iphdr *)pkt;
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_hlim=hdr4->ttl;
  hdr6->ip6_ctlun.ip6_un2_vfc=hdr4->tos;
  hdr6->ip6_ctlun.ip6_un1.ip6_un1_flow=htonl(0x60000000);
  memcpy(&(hdr6->ip6_src),&ip6src,sizeof(struct in6_addr));
  memcpy
    (
     &(hdr6->ip6_dst),
     (struct in6_addr *)(((unsigned char *)drtftr)-sizeof(struct in6_addr)),
     sizeof(struct in6_addr)
     );
  memcpy
    (
     &s6_in.sin6_addr,
     (struct in6_addr *)(((unsigned char *)drtftr)-sizeof(struct in6_addr)),
     sizeof(struct in6_addr)
     );
  switch (hdr4->protocol)
    {
    case IPPROTO_TCP:
      {
        sendto6tcp(pkt,buffer,hdr4,hdr6,s6_in,raws_tcp6,flags);
        break;
      }
    case IPPROTO_UDP:
      {
	sendto6udp(pkt,buffer,hdr4,hdr6,s6_in,raws_udp6,flags);
	break;
      }
    case IPPROTO_ICMP:
      {
	sendto6icmp(pkt,buffer,hdr4,hdr6,s6_in,raws_icmp6,flags);
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

int setsocket(void)
{
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
  if ((raws_udp=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -7;
  if ((raws_tcp=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -8;
  if ((raws_icmp=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))==-1)
    return -9;
  if (setsockopt(raws_icmp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -10;
  if (setsockopt(raws_tcp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -11;
  if (setsockopt(raws_udp,IPPROTO_IP,IP_HDRINCL,oneval,sizeof(one))<0)
    return -12;
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
  s_in.sin_family=AF_INET;
  s6_in.sin6_family=AF_INET6;
  s6_in.sin6_flowinfo=0;
  s6_in.sin6_scope_id=0;
  s6_in.sin6_port=0;
  return 0;
}
