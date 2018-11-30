#include <stdio.h>
#include <string.h>
#include "directobot.h"
#include "state_table.h"

void init_ST(void)
{
  sqlite3_exec
    (
     damDB,
     "create table ST_UDP (IPv4 char(16),to6_src int,to6_dst int,IPv6 char(48),ts int,primary key (IPv4,to6_src,to6_dst,IPv6));",
     NULL,NULL,NULL
     );
  sqlite3_exec
    (
     damDB,
     "create table ST_TCP (IPv4 char(16),to6_src int,to6_dst int,IPv6 char(40),ts int,primary key (IPv4,to6_src,to6_dst,IPv6));",
     NULL,NULL,NULL
     );
}

unsigned int stadd
(uint32_t src4,uint16_t srcp,uint16_t dstp,struct in6_addr *dst6,uint8_t proto)
{
  char *insert;
  char IPv4[0x10],IPv6[0x28],to6sp[0x6],to6dp[0x6];
  char 
    insert_tcp[MAX_SQL_STATEMENT_SIZE]=
    "insert or replace into ST_TCP (IPv4,to6_src,to6_dst,IPv6,ts) values (",
    insert_udp[MAX_SQL_STATEMENT_SIZE]=
    "insert or replace into ST_UDP (IPv4,to6_src,to6_dst,IPv6,ts) values (";
  
  switch (proto)
    {
    case IPPROTO_TCP:
      {
	insert=insert_tcp;
	break;
      }
    case IPPROTO_UDP:
      {
        insert=insert_udp;
        break;
      } 
    default:
      return 0;
    }
  sprintf(IPv4,"%u",src4);
  inet_ntop(AF_INET6,dst6,IPv6,sizeof(struct ip6_hdr));
  sprintf(to6sp,"%d",srcp);
  sprintf(to6dp,"%d",dstp);
  strcat(insert,IPv4);
  strcat(insert,",");
  strcat(insert,to6sp);
  strcat(insert,",");
  strcat(insert,to6dp);
  strcat(insert,",'");
  strcat(insert,IPv6);
  strcat
    (
     insert,
     "',strftime('%s','now'));"
     );
  if ((sqlite3_exec(damDB,insert,NULL,NULL,NULL))!=SQLITE_OK)
    return 0;
  return 1;
}

uint32_t stget
(
 uint32_t src4,uint16_t srcp,uint16_t dstp,struct in6_addr *dst6,
 uint8_t ipv6_available,uint8_t proto,int col
)
{
  char *stget,*stget2;
  sqlite3_stmt *res;
  uint32_t rv=0;
  char IPv4[0x10],IPv6[0x28],to6sp[0x6],to6dp[0x6];
  char 
    stget_tcp[MAX_SQL_STATEMENT_SIZE]="select ",
    stget_udp[MAX_SQL_STATEMENT_SIZE]="select ",
    stget2_tcp[]="from ST_TCP where ",
    stget2_udp[]="from ST_UDP where ";

  switch (proto)
    {
    case IPPROTO_TCP:
      {
	stget=stget_tcp; stget2=stget2_tcp;
	break;
      }
    case IPPROTO_UDP:
      {
        stget=stget_udp; stget2=stget2_udp;
        break;
      } 
    default:
      return 0;
    }
  switch (col)
    { 
    case 0:
      { 
        strcat(stget,"IPv4 ");
	break;
      }
    case 1:
      {
        strcat(stget,"to6_src ");
        break;
      }
    case 2:
      { 
        strcat(stget,"to6_dst ");
        break;
      } 
    case 3:
      { 
        strcat(stget,"IPv6");
        break;
      } 
    default:
      return 0;
    }
  strcat(stget,stget2);
  if (src4)
    {
      strcat(stget,"IPv4=");
      sprintf(IPv4,"%u",src4);
      strcat(stget,IPv4);
    }
  if (srcp)
    {
      if (src4)
	strcat(stget," and ");
      strcat(stget,"to6_src=");
      sprintf(to6sp,"%d",srcp);
      strcat(stget,to6sp);
    }
  if (dstp)
    {
      if (src4||srcp)
        strcat(stget," and ");
      strcat(stget,"to6_dst=");
      sprintf(to6dp,"%d",dstp);
      strcat(stget,to6dp);
    }
  if (ipv6_available)
    {
      if (src4||srcp||dstp)
        strcat(stget," and ");
      strcat(stget,"IPv6='");
      inet_ntop(AF_INET6,dst6,IPv6,sizeof(struct ip6_hdr));
      strcat(stget,IPv6);
      strcat(stget,"'");
    }
  strcat(stget,";");
  sqlite3_prepare_v2(damDB,stget,-1,&res,NULL);
  if ((sqlite3_step(res))==SQLITE_ROW)
    switch (col)
      {
      case 0:
      case 1:
      case 2:
	rv=sqlite3_column_int(res,0);
      case 3:
	{
	  //	  sqlite3_column_str(res,3);
	}
      default:
	break;
      }
  sqlite3_finalize(res);
  return rv;
}

int ststore
(uint32_t src4,uint16_t srcp,uint16_t dstp,struct in6_addr *dst6,uint8_t proto)
{
  return stadd(src4,srcp,dstp,dst6,proto);
}
