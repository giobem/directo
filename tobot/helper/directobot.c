#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "directobot.h"
#include "../../common/dirtlib.h"
#include "relay_server.h"

#define HOST_FILE_PATH "/etc/direct_host.conf"

sqlite3 *damDBconn,*damDB;
int pid,v4sock_in,v4sock_out;
char haddr4[0x10],haddr6[0x28];
uint16_t EXCLUDED_TCP_PP[MAX_EXCLUDED_PORTS];
uint16_t EXCLUDED_UDP_PP[MAX_EXCLUDED_PORTS];

void read_host_conf(FILE *drfp)
{
  char c;
  int i=0;
  char line[0xff];

  fscanf(drfp,"%s\t%[^\n]",haddr4,haddr6);
  set_host(haddr4,haddr6);
  do
    {
      memset(line,0,0xff);
      if (fscanf(drfp,"%s",line)==EOF)
	break;
    }
  while (memcmp(line,"TCP",3)&&memcmp(line,"UDP",3));
  if (!memcmp(line,"TCP",3))
    do
      {
	if (fscanf(drfp,"%d%c",&(EXCLUDED_TCP_PP[i]),&c)==EOF)
	  break;;
	i++;
      }
    while (c!='\n');
  else if (!memcmp(line,"UDP",3))
    do
      {
        if (fscanf(drfp,"%d%c",&(EXCLUDED_TCP_PP[i]),&c)==EOF)
	  break;;
        i++;
      }
    while (c!='\n');
  i=0;
  do
    {
      memset(line,0,0xff);
      if (fscanf(drfp,"%s",line)==EOF)
	break;
    }
  while (memcmp(line,"TCP",3)&&memcmp(line,"UDP",3));
  if (!memcmp(line,"TCP",3))
    do
      {
        if (fscanf(drfp,"%d%c",&(EXCLUDED_TCP_PP[i]),&c)==EOF)
	  break;
        i++;
      }
    while (c!='\n');
  else if (!memcmp(line,"UDP",3))
    do
      {
        if (fscanf(drfp,"%d%c",&(EXCLUDED_TCP_PP[i]),&c)==EOF)
	  break;
        i++;
      }
    while (c!='\n');
}

int main(int argc,char *argv[])
{
  uint16_t *conf_msg;
  FILE *drfp;
  unsigned char code;
  int to4_dirt_dev,to6_dirt_dev,direct_msg_len,i=0;
  struct sockaddr_in sendsocket,receivesocket;
  unsigned char *direct_msg;

  direct_msg=malloc(DIRECTOBOT_BUFFER_SIZE);
  buffer=malloc(DIRECTOBOT_BUFFER_SIZE);
  if ((drfp=fopen(HOST_FILE_PATH,"r"))==NULL)
    {
      perror("Cannot access to direct_host.conf");
      return -4;
    }
  memset(direct_msg,0,DIRECTOBOT_BUFFER_SIZE);
  memset(EXCLUDED_TCP_PP,0,sizeof(uint16_t)*MAX_EXCLUDED_PORTS);
  memset(EXCLUDED_UDP_PP,0,sizeof(uint16_t)*MAX_EXCLUDED_PORTS);
  read_host_conf(drfp);
  fclose(drfp);
  if
    (
     (v4sock_in=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0
     ||
     (v4sock_out=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0
     ||
     setsocket()
     )
    {
      perror("Cannot create sockets");
      return -1;
    }
  sendsocket.sin_family=AF_INET;
  inet_aton("127.0.0.1",&sendsocket.sin_addr);
  sendsocket.sin_port=htons(DIRECT_TO_KERNEL);
  receivesocket.sin_family=AF_INET;
  receivesocket.sin_addr.s_addr=htonl(INADDR_ANY);
  receivesocket.sin_port=htons(DIRECT_TO_HELPER);
  direct_msg[0]=TCPCONF;
  conf_msg=(uint16_t *)(&(direct_msg[3]));
  while (EXCLUDED_TCP_PP[i])
    {
      conf_msg[i]=htons(EXCLUDED_TCP_PP[i]);
      i++;
    }
  conf_msg=(uint16_t *)(&(direct_msg[1]));
  *conf_msg=htons(i);
  if 
    (
     sendto
     (
      v4sock_out,direct_msg,ntohs((*conf_msg)*sizeof(uint16_t))+3,0,
      (struct sockaddr *)&sendsocket,sizeof(struct sockaddr_in)
      )
     <=
     0
     )
    {
      perror("Cannot configure kernel module");
      return -3;
    }
  i=0;
  memset(direct_msg,0,DIRECTOBOT_BUFFER_SIZE);
  direct_msg[0]=UDPCONF;
  conf_msg=(uint16_t *)(&(direct_msg[3]));
  while (EXCLUDED_UDP_PP[i])
    {
      conf_msg[i]=htons(EXCLUDED_UDP_PP[i]);
      i++;
    }
  conf_msg=(uint16_t *)(&(direct_msg[1]));
  *conf_msg=htons(i);
  if
    (
     sendto
     (
      v4sock_out,direct_msg,ntohs(*conf_msg)+3,0,
      (struct sockaddr *)&sendsocket,sizeof (struct sockaddr_in)
      )
     <=
     0
     )
    {
      perror("Cannot configure kernel module");
      return -3;
    }
  if 
    (bind(v4sock_in,(struct sockaddr *)&receivesocket,sizeof(receivesocket))<0)
    {
      perror("Cannot bind port");
      return -2;
    }
  if (sqlite3_open("/dev/shm/damDB.tmp",&damDB))
    {
      perror("Cannot create DAM tables");
      return -6;
    }
  init_ST();
  srand(time(NULL));
  if ((to6_dirt_dev=open("/dev/dirt6",O_RDONLY))==-1)
    {
      perror("Cannot translate IPv4 packets");
      return -41;
    }
  if ((to4_dirt_dev=open("/dev/dirt4",O_RDONLY))==-1)
    {
      perror("Cannot translate IPv6 packets");
      return -42;
    }
  while (1)
    {
      direct_msg_len=read(to6_dirt_dev,direct_msg,DIRECTOBOT_BUFFER_SIZE);
      usleep(1);
      switch (direct_msg[0])
        {
        case FROM6_INCOMING:
          break;
        case FROM4_INCOMING:
          {
            switch (chk_in4_msg(&(direct_msg[1]),direct_msg_len-1))
              {
              case NO_CODE:
                {
                  sendto6(&(direct_msg[1]),direct_msg_len-1,NO_CODE);
                  break;
                }
              case RELAY_TO6:
                {
                  sendto6(&(direct_msg[1]),direct_msg_len-1,RELAY_TO6);
                  break;
                }
              case RELAY_TO6DR:
                {
                  sendto6(&(direct_msg[1]),direct_msg_len-1,RELAY_TO6DR);
                  break;
                }
              case GO:
                break;
              case EXITNOW:
                {
                  close(to6_dirt_dev);
                  sqlite3_close(damDB);
                  wait(&pid);
                  system("rm -f /dev/shm/damDB.tmp");
                  return 0;
                }
              default: break;
              }
          }
        default: break;
        }
      direct_msg_len=read(to4_dirt_dev,direct_msg,DIRECTOBOT_BUFFER_SIZE);
      switch (direct_msg[0])
        {
        case FROM4_INCOMING:
          break;
        case FROM6_INCOMING:
          {
            switch (chk_in6_msg(&(direct_msg[1]),direct_msg_len-1))
              {
              case NO_CODE:
                {
                  sendto4(&(direct_msg[1]),direct_msg_len-1,NO_CODE);
                  break;
                }
              case RELAY_TO4:
                {
                  sendto4(&(direct_msg[1]),direct_msg_len-1,RELAY_TO4);
                  break;
                }
              case RELAY_TO4DR:
                {
                  sendto4(&(direct_msg[1]),direct_msg_len-1,RELAY_TO4DR);
                  break;
                }
              default: break;
              }
          }
        case GO:
          break;
        case EXITNOW:
          {
            close(to6_dirt_dev);
            sqlite3_close(damDB);
            wait(&pid);
            system("rm -f /dev/shm/damDB.tmp");
            return 0;
          }
        default:
          break;
        }
    }
}
