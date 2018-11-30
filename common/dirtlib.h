#ifndef __DIRTLIB__
#define __DIRTLIB__

#include <netinet/ip6.h>

#define DIRECT_INCOMING 0
#define DIRECT_OUTGOING 1
#define FROM4_INCOMING  2
#define FROM6_INCOMING  3
#define NO_CODE   127
#define RELAY_TO6 128
#define RELAY_TO4 129
#define RELAY_TO6DR 130
#define RELAY_TO4DR 131

struct direct_footer
{
  uint16_t len;
  uint8_t code;
  uint8_t sp; //Must be zero.
};

unsigned short csum(unsigned short *,int);
int chk_in4_msg(unsigned char *,int);
int chk_in6_msg(unsigned char *,int);
int ip6_cmp(struct in6_addr *,struct in6_addr *);

#endif
