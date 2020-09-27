#ifndef __DIRECTO6_TRANSLATOR__
#define __DIRECTO6_TRANSLATOR__

void send_to_fragment(unsigned char *,int);
void rcv_from_relay(unsigned char *,int);
void send_to_relay(unsigned char *,int);
void ipv6_mtu_autored(unsigned char *,int);
void set_host(char *,char *);
void set_relay(char *,char *);
int setsocket(unsigned char *,unsigned char *);

#endif
