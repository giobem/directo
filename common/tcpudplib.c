#include <assert.h>
#include <string.h>
#include "tcpudplib.h"

static __be16 ip_checksum_fold(uint64_t sum)
{
  while (sum&~0xffffffffULL)
    sum=(sum>>32)+(sum&0xffffffffULL);
  while (sum&0xffff0000ULL)
    sum=(sum>>16)+(sum & 0xffffULL);
  return ~sum;
}

static uint64_t ip_checksum_partial(const void *p,size_t len,uint64_t sum)
{
  const uint32_t *p32;
  const uint16_t *p16;
  const uint8_t *p8;

  p32=(const uint32_t *)(p);
  for (; len>=sizeof(*p32); len-=sizeof(*p32))
    sum+=*p32++;
  p16=(const uint16_t *)(p32);
  if (len>=2)
    {
      sum+=*p16++;
      len-=sizeof(*p16);
    }
  if (len>0)
    {
      p8=(const uint8_t *)(p16);
      sum+=ntohs(*p8<<8);
    }
  return sum;
}

static uint64_t tcp_udp_v4_header_checksum_partial
(struct in_addr src_ip,struct in_addr dst_ip,uint8_t protocol,uint16_t len)
{
  struct ipv4_pseudo_header_t
  {
    union {
      struct header {
        struct in_addr src_ip;
        struct in_addr dst_ip;
        uint8_t mbz;
        uint8_t protocol;
        uint16_t length;
      } fields;
      uint32_t words[3];
    };
  };
  struct ipv4_pseudo_header_t pseudo_header;
  assert(sizeof(pseudo_header)==12);
  pseudo_header.fields.src_ip=src_ip;
  pseudo_header.fields.dst_ip=dst_ip;
  pseudo_header.fields.mbz=0;
  pseudo_header.fields.protocol=protocol;
  pseudo_header.fields.length=htons(len);
  return ip_checksum_partial(&pseudo_header,sizeof(pseudo_header),0);
}

static uint64_t tcp_udp_v6_header_checksum_partial
(
 const struct in6_addr *src_ip,const struct in6_addr *dst_ip,__u8 protocol,
 __u32 len
 )
{
  struct ipv6_pseudo_header_t
  {
    union
    {
      struct header
      {
        struct in6_addr src_ip;
        struct in6_addr dst_ip;
        __be32 length;
        __u8 mbz[3];
        __u8 next_header;
      } fields;
      __u32 words[10];
    };
  };
  struct ipv6_pseudo_header_t pseudo_header;

  assert(sizeof(pseudo_header)==40);
  pseudo_header.fields.src_ip=*src_ip;
  pseudo_header.fields.dst_ip=*dst_ip;
  pseudo_header.fields.length=htonl(len);
  memset(pseudo_header.fields.mbz,0,sizeof(pseudo_header.fields.mbz));
  pseudo_header.fields.next_header=protocol;
  return ip_checksum_partial(&pseudo_header,sizeof(pseudo_header),0);
}

__be16 tcp_udp_v4_checksum
(
 struct in_addr src_ip,struct in_addr dst_ip,uint8_t protocol,
 const void *payload,uint16_t len
 )
{
  uint64_t sum;

  sum=tcp_udp_v4_header_checksum_partial(src_ip,dst_ip,protocol,len);
  sum=ip_checksum_partial(payload,len,sum);
  return ip_checksum_fold(sum);
}

__be16 tcp_udp_v6_checksum
(
 const struct in6_addr *src_ip,const struct in6_addr *dst_ip,__u8 protocol,
 const void *payload,__u32 len
 )
{
  uint64_t sum;

  sum=tcp_udp_v6_header_checksum_partial(src_ip,dst_ip,protocol,len);
  sum=ip_checksum_partial(payload,len,sum);
  return ip_checksum_fold(sum);
}
