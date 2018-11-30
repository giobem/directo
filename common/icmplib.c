#include <netinet/ip6.h>
#include "icmplib.h"

uint16_t checksum(uint16_t *addr, int len)
{
  int count=len;
  register uint32_t sum=0;
  uint16_t answer=0;

  while (count>1)
    {
      sum+=*(addr++);
      count-=2;
    }
  if (count>0)
    sum+=*(uint8_t *)addr;
  while (sum>>16)
    sum=(sum&0xffff)+(sum>>16);
  answer=~sum;
  return (answer);
}

int build_icmp4(struct icmphdr *icmp4,struct icmp6_hdr *icmp6)
{
  memset(icmp4,0,sizeof(struct icmphdr));
  switch (icmp6->icmp6_type)
    {
    case ICMP6_ECHO_REQUEST:
      {
        icmp4->type=ICMP_ECHO;
        icmp4->un.echo.id=icmp6->icmp6_id;
        icmp4->un.echo.sequence=icmp6->icmp6_seq;
        return 0;
      }
    case ICMP6_ECHO_REPLY:
      {
        icmp4->type=ICMP_ECHOREPLY;
        icmp4->un.echo.id=icmp6->icmp6_id;
        icmp4->un.echo.sequence=icmp6->icmp6_seq;
        return 0;
      }
      //What follows is for completeness only       
    case ICMP6_DST_UNREACH:
      {
        icmp4->type=ICMP_DEST_UNREACH;
        switch (icmp6->icmp6_code)
          {
          case ICMP6_DST_UNREACH_NOROUTE:
          case ICMP6_DST_UNREACH_BEYONDSCOPE:
          case ICMP6_DST_UNREACH_ADDR:
            {
              icmp4->code=ICMP_HOST_UNREACH;
              return 0;
            }
          case ICMP6_DST_UNREACH_NOPORT:
            {
              icmp4->code=ICMP_PORT_UNREACH;
              return 0;
            }
          case ICMP6_DST_UNREACH_ADMIN:
            {
              icmp4->code=ICMP_HOST_ANO;
              return 0;
            }
          default: return -1;
          }
      }
    case ICMP6_PARAM_PROB:
      {
        switch (icmp6->icmp6_code)
          {
          case ICMP6_PARAMPROB_NEXTHEADER:
            {
              icmp4->type=ICMP_DEST_UNREACH;
              icmp4->code=ICMP_PROT_UNREACH;
              icmp4->un.echo.id=htons(0x900);
              return 0;
            }
          case ICMP6_PARAMPROB_HEADER:
          case ICMP6_PARAMPROB_OPTION:
            {
              icmp4->type=ICMP_PARAMETERPROB;
              icmp4->code=0;
              switch (icmp6->icmp6_dataun.icmp6_un_data8[0])
                {
                case 0:
                  {
                    icmp4->un.echo.id=htons(0x0);
                    return 0;
                  }
                case 1:
                  {
                    icmp4->un.echo.id=htons(0x100);
                    return 0;
                  }
                case 4:
                case 5:
                  {
                    icmp4->un.echo.id=htons(0x200);
                    return 0;
                  }
                case 7:
                  {
                    icmp4->un.echo.id=htons(0x800);
                    return 0;
                  }
                case 6:
                  {
                    icmp4->un.echo.id=htons(0x900);
                    return 0;
                  }
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                case 13:
                case 14:
                case 15:
                case 16:
                case 17:
                case 18:
                case 19:
                case 20:
                case 21:
                case 22:
                case 23:
                  {
                    icmp4->un.echo.id=htons(0xc00);
                    return 0;
                  }
                case 24:
                case 25:
                case 26:
                case 27:
                case 28:
                case 29:
                case 30:
                case 31:
                case 32:
                case 33:
                case 34:
                case 35:
                case 36:
                case 37:
                case 38:
                case 39:
                  {
                    icmp4->un.echo.id=htons(0x1000);
                    return 0;
                  }
                default: return 0;
                }
            }
          default: return -3;
          }
      }
    case ICMP6_PACKET_TOO_BIG:
      {
        icmp4->type=ICMP_DEST_UNREACH;
        icmp4->code=ICMP_FRAG_NEEDED;
        icmp4->un.frag.mtu=1280;
        return 0;
      }
    case ICMP6_TIME_EXCEEDED:
      {
        icmp4->type=ICMP_TIME_EXCEEDED;
        return 0;
      }
    case MLD_LISTENER_QUERY:
    case MLD_LISTENER_REPORT:
    case MLD_LISTENER_REDUCTION: return -4;
    case ND_ROUTER_SOLICIT:
    case ND_REDIRECT: return -5;
    default: return 1;
    }
}

int build_icmp6(struct icmp6_hdr *icmp6,struct icmphdr *icmp4)
{
  memset(icmp6,0,sizeof(struct icmp6_hdr));
  switch (icmp4->type)
    {
    case ICMP_ECHO:
      {
        icmp6->icmp6_type=ICMP6_ECHO_REQUEST;
        icmp6->icmp6_id=icmp4->un.echo.id;
        icmp6->icmp6_seq=icmp4->un.echo.sequence;
        return 0;
      }
    case ICMP_ECHOREPLY:
      {
        icmp6->icmp6_type=ICMP6_ECHO_REPLY;
        icmp6->icmp6_id=icmp4->un.echo.id;
        icmp6->icmp6_seq=icmp4->un.echo.sequence;
        return 0;
      }
    default: return 1;
    }
}

unsigned short icmp_cksum(unsigned short *addr, int len)
{
  register int sum=0,nleft=len;
  u_short answer=0;
  register u_short *w=addr;

  while (nleft>1)
    {
      sum+=*w++;
      nleft-=2;
    }
  if (nleft==1)
    {
      *(u_char *)(&answer)=*(u_char *)w;
      sum+=answer;
    }
  sum=(sum>>16)+(sum & 0xffff);
  sum+=(sum>>16);
  answer=~sum;
  return (answer);
}

uint16_t icmp6_checksum
(
 struct ip6_hdr iphdr,struct icmp6_hdr icmp6hdr,uint8_t *payload,
 int payloadlen
 )
{
  char buf[MAX_ICMP_PAYLOAD_LEN+4];
  char *ptr;
  int chksumlen=0;
  int i;

  ptr=&buf[0];
  memcpy(ptr,&iphdr.ip6_src.s6_addr,sizeof(iphdr.ip6_src.s6_addr));
  ptr+=sizeof(iphdr.ip6_src);
  chksumlen+=sizeof(iphdr.ip6_src);
  memcpy(ptr,&iphdr.ip6_dst.s6_addr,sizeof(iphdr.ip6_dst.s6_addr));
  ptr+=sizeof(iphdr.ip6_dst.s6_addr);
  chksumlen+=sizeof(iphdr.ip6_dst.s6_addr);
  *ptr=0;
  ptr++;
  *ptr=0;
  ptr++;
  *ptr=(sizeof(struct icmp6_hdr)+payloadlen)/256;
  ptr++;
  *ptr=(sizeof(struct icmp6_hdr)+payloadlen)%256;
  ptr++;
  chksumlen+=4;
  *ptr=0;
  ptr++;
  *ptr=0;
  ptr++;
  *ptr=0;
  ptr++;
  chksumlen+=3;
  memcpy(ptr,&iphdr.ip6_nxt,sizeof(iphdr.ip6_nxt));
  ptr+=sizeof(iphdr.ip6_nxt);
  chksumlen+=sizeof(iphdr.ip6_nxt);
  memcpy(ptr,&icmp6hdr.icmp6_type,sizeof(icmp6hdr.icmp6_type));
  ptr+=sizeof(icmp6hdr.icmp6_type);
  chksumlen+=sizeof(icmp6hdr.icmp6_type);
  memcpy(ptr,&icmp6hdr.icmp6_code,sizeof(icmp6hdr.icmp6_code));
  ptr+=sizeof(icmp6hdr.icmp6_code);
  chksumlen+=sizeof(icmp6hdr.icmp6_code);
  memcpy(ptr,&icmp6hdr.icmp6_id,sizeof(icmp6hdr.icmp6_id));
  ptr+=sizeof(icmp6hdr.icmp6_id);
  chksumlen+=sizeof(icmp6hdr.icmp6_id);
  memcpy(ptr,&icmp6hdr.icmp6_seq,sizeof(icmp6hdr.icmp6_seq));
  ptr+=sizeof(icmp6hdr.icmp6_seq);
  chksumlen+=sizeof(icmp6hdr.icmp6_seq);
  *ptr=0;
  ptr++;
  *ptr=0;
  ptr++;
  chksumlen+=2;
  memcpy(ptr,payload,payloadlen*sizeof(uint8_t));
  ptr+=payloadlen;
  chksumlen+=payloadlen;
  for (i=0; i<payloadlen%2; i++,ptr++)
    {
      *ptr=0;
      ptr+=1;
      chksumlen+=1;
    }
  return checksum((uint16_t *)buf,chksumlen);
}
