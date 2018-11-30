#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "directo6.h"
#include "translator.h"

#define HOST_FILE_PATH "/etc/direct_host.conf"
#define RELAY_FILE_PATH "/etc/direct_relay.conf"

int pid,v4sock_out,v4sock_in,dream=1;
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
  int to4_dirt_dev,to6_dirt_dev,direct_msg_len;
  struct in_addr relay4;
  struct in6_addr local6;
  struct sockaddr_in sendsocket,receivesocket;
  unsigned char *direct_msg;

  direct_msg=malloc(DIRECTO6_BUFFER_SIZE);
  if ((drfp=fopen(RELAY_FILE_PATH,"r"))==NULL)
    {
      perror("Cannot access to direct_relay.conf");
      return -3;
    }
  read_relay_conf(drfp);
  fclose(drfp);
  if ((drfp=fopen(HOST_FILE_PATH,"r"))==NULL)
    {
      perror("Cannot access to direct_host.conf");
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
      perror("Cannot create sockets");
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
      perror("Cannot configure kernel module");
      return -3;
    }
  if 
    (bind(v4sock_in,(struct sockaddr *)&receivesocket,sizeof(receivesocket))<0)
    {
      perror("Cannot bind port");
      return -2;
    }
  pid=fork();
  if (!pid)
    {
      srand(time(NULL));
      if ((to4_dirt_dev=open("/dev/dirt4",O_RDONLY))==-1)
        {
          perror("Cannot translate IPv6 packets");
          return -41;
        }
      while (1)
	{ 
	  usleep(200);
	  direct_msg_len=read(to4_dirt_dev,direct_msg,DIRECTO6_BUFFER_SIZE);
	  switch (direct_msg[0])
	    {
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
  else if (pid>0)
    {
      if ((to6_dirt_dev=open("/dev/dirt6",O_RDONLY))==-1)
        {
          perror("Cannot translate IPv4 packets");
          return -42;
        }
      while (1)
        {
	  usleep(200);
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
