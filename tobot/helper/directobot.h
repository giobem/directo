#ifndef __DIRECTOBOT__
#define __DIRECTOBOT__

#include <sqlite3.h>

#define FROM4_INCOMING_TO_FRAG 6
#define FROM6_INCOMING_TO_FRAG 7

#define DIRECT_TO_HELPER 8197
#define DIRECT_TO_KERNEL 8198
#define DIRECTOBOT_BUFFER_SIZE 0x10001
#define MAX_EXCLUDED_PORTS 0xff

#define TCPCONF    32
#define UDPCONF    33
#define RELAY4CONF 34
#define GO        253
#define EXITNOW   254

extern sqlite3 *damDB;

#endif
