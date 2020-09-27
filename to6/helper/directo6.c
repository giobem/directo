#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "directo6.h"
#include "translator.h"
#include "../../common/dirtlib.h"

#define HOST_FILE_PATH "/etc/direct_host.conf"
#define RELAY_FILE_PATH "/etc/direct_relay.conf"

unsigned char *direct_msg;
int v4sock_out,v4sock_in,dream=1,to4_dirt_dev,to6_dirt_dev;
struct sigaction to_relay_sig,from_relay_sig;
char haddr4[0x10],haddr6[0x28],raddr4[0x10],raddr6[0x28];

void read_host_conf(FILE *drfp)
{
  fscanf(drfp,"%s\t%[^\n]",haddr4,haddr6);
  set_host(haddr4,haddr6);
}

void read_relay_conf(FILE *drfp)
{
  fscanf(drfp,"%s\t%[^\n]",raddr4,raddr6);
  set_relay(raddr4,raddr6);
}

int main(int argc,char *argv[])
{
  FILE *drfp;
  struct ip6_hdr *hdr6;
  unsigned char code;
  int pid,direct_msg_len;
  pid_t to_relay_pid,from_relay_pid;
  struct in_addr relay4;
  struct in6_addr local6;
  struct sockaddr_in sendsocket,receivesocket;

  direct_msg=malloc(DIRECTO6_BUFFER_SIZE);
  if ((drfp=fopen(RELAY_FILE_PATH,"r"))==NULL)
    {
      dirtlog("Cannot access to direct_relay.conf");
      return -3;
    }
  read_relay_conf(drfp);
  fclose(drfp);
  if ((drfp=fopen(HOST_FILE_PATH,"r"))==NULL)
    {
      dirtlog("Cannot access to direct_host.conf");
      return -4;
    }
  read_host_conf(drfp);
  fclose(drfp);
  if
    (
     (v4sock_out=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0
     ||
     (v4sock_in=socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0
     ||
     setsocket(haddr4,raddr4)
     )
    {
      dirtlog("Cannot create sockets");
      return -1;
    }
  sendsocket.sin_family=AF_INET;
  inet_aton("127.0.0.1",&sendsocket.sin_addr);
  sendsocket.sin_port=htons(DIRECT_TO_KERNEL);
  receivesocket.sin_family=AF_INET;
  receivesocket.sin_addr.s_addr=htonl(INADDR_ANY);
  receivesocket.sin_port=htons(DIRECT_TO_HELPER);
  direct_msg[0]=RELAY4CONF;
  inet_pton(PF_INET,raddr4,&relay4);
  inet_pton(PF_INET6,haddr6,&local6);
  memcpy(&(direct_msg[1]),&relay4,sizeof(struct in_addr));
  memcpy(&(direct_msg[5]),&local6,sizeof(struct in6_addr));
  if
    (
     sendto
     (
      v4sock_out,direct_msg,
      sizeof(unsigned char)+sizeof(struct in_addr)+sizeof(struct in6_addr),0,
      (struct sockaddr *)&sendsocket,sizeof(struct sockaddr_in)
      )
     <=
     0
     )
    {
      dirtlog("Cannot configure kernel module");
      return -3;
    }
  if
    (bind(v4sock_in,(struct sockaddr *)&receivesocket,sizeof(receivesocket))<0)
    {
      dirtlog("Cannot bind port");
      return -2;
    }
  pid=fork();
  if (!pid)
    {
      memcpy(&(direct_msg[1]),&to_relay_pid,sizeof(pid_t));
      while
        (
         sendto
         (
          v4sock_out,direct_msg,sizeof(unsigned char)+sizeof(pid_t),0,
          (struct sockaddr *)&sendsocket,sizeof(struct sockaddr_in)
          )
         <=
         0
         )
        {
          dirtlog("Cannot configure kernel module");
          return -3;
        }
      srand(time(NULL));
      while ((to4_dirt_dev=open("/dev/dirt4",O_RDONLY))==-1)
        usleep(200);
      while (1)
        {
          direct_msg_len=read(to4_dirt_dev,direct_msg,DIRECTO6_BUFFER_SIZE);
          switch (direct_msg[0])
            {
            case DIRECT_OUTGOING_TO_FRAG:
              {
                send_to_fragment(&(direct_msg[1]),direct_msg_len-1);
                continue;
              }
            case DIRECT_OUTGOING:
              break;
            case GO:
              continue;
            case EXITNOW:
              {
                close(to4_dirt_dev);
                wait(&pid);
                return 0;
              }
            default:
              continue;
            }
          send_to_relay(&(direct_msg[1]),direct_msg_len-1);
        }
    }
  else
    {
      while
        (
         sendto
         (
          v4sock_out,direct_msg,sizeof(unsigned char)+sizeof(int),0,
          (struct sockaddr *)&sendsocket,sizeof(struct sockaddr_in)
          )
         <=
         0
         )
        {
          dirtlog("Cannot configure kernel module");
          return -3;
        }
      srand(time(NULL));
      while ((to6_dirt_dev=open("/dev/dirt6",O_RDONLY))==-1)
        usleep(200);
      while (1)
        {
          direct_msg_len=read(to6_dirt_dev,direct_msg,DIRECTO6_BUFFER_SIZE);
          switch (direct_msg[0])
            {
            case DIRECT_INCOMING:
              break;
            case GO:
              continue;
            case EXITNOW:
              {
                close(to6_dirt_dev);
                return 0;
              }
            default:
              continue;
            }
          rcv_from_relay(&(direct_msg[1]),direct_msg_len-1);
        }
    }
}

