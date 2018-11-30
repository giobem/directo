#include <netinet/ip.h>
#include "dirtlib.h"

int ip6_cmp(struct in6_addr *a,struct in6_addr *b)
{
  int i;

  for(i=0; i<16; ++i)
    {
      if (a->s6_addr[i]<b->s6_addr[i])
	return -1;
      else if (a->s6_addr[i]>b->s6_addr[i])
	return 1;
    }
  return 0;
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum=0;
  while (nbytes>1)
    {
      sum+=*ptr++;
      nbytes-=2;
    }
  if (nbytes==1)
    {
      oddbyte=0;
      *((u_char*)&oddbyte)=*(u_char*)ptr;
      sum+=oddbyte;
    }
  sum=(sum>>16)+(sum&0xffff);
  sum=sum+(sum>>16);
  answer=(short)~sum;
  return answer;
}

int chk_in4_msg(unsigned char *pkt,int pkt_len)
{
  struct direct_footer *drft;
  struct iphdr *hdr4;

  drft=(struct direct_footer *)(pkt+pkt_len-sizeof(struct direct_footer));
  hdr4=(struct iphdr *)pkt;
  switch (drft->code)
    {
    case RELAY_TO6:
      {
        if
          (
           ntohs(hdr4->tot_len)
           ==
           ntohs(drft->len)+sizeof(struct in6_addr)+
           sizeof(struct direct_footer)
           )
          return RELAY_TO6;
        else
          return NO_CODE;
      }
    default:
      return NO_CODE;
    }
}

int chk_in6_msg(unsigned char *pkt,int pkt_len)
{
  struct direct_footer *drft;
  struct ip6_hdr *hdr6;

  drft=(struct direct_footer *)(pkt+pkt_len-sizeof(struct direct_footer));
  hdr6=(struct ip6_hdr *)pkt;
  /*  drft=
    (struct direct_footer *)
    (
     pkt+ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)+sizeof(struct ip6_hdr)-
     sizeof(struct direct_footer)
     );*/
  switch (drft->code)
    {
    case RELAY_TO4:
    case RELAY_TO4DR:
      {
        if
          (
           ntohs(hdr6->ip6_ctlun.ip6_un1.ip6_un1_plen)
           ==
           ntohs(drft->len)+sizeof(struct in_addr)+sizeof(struct direct_footer)
           )
          return drft->code;
        else
          return NO_CODE;
      }
    default:
      return NO_CODE;
    }
}
