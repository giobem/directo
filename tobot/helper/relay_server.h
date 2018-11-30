#ifndef __DIRT_RELAY_SERVER__
#define __DIRT_RELAY_SERVER__

unsigned char *buffer;

void sendto4(unsigned char *const,int,uint8_t);
void sendto6(unsigned char *const,int,uint8_t);
void set_host(char *,char *);
int setsocket();

#endif
