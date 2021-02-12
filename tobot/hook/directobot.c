#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/version.h>
#include <net/ndisc.h>

#define DESCRIPTION "Directobot"
#define AUTHOR "Giovanni Bembo"
#define MODULE_VERS "0.1"
#define MODULE_NAME "directobot"

#define NIC "eth0"
#define MAX_TO4_PKT_SIZE 1537
#define MAX_TO6_PKT_SIZE 1537

#define DIRECT_TO_HELPER 8197
#define DIRECT_TO_KERNEL 8198
#define MIN_CONF 2
#define MAX_EXCLUDED_PORTS 0xff
#define FROM4_INCOMING 2
#define FROM6_INCOMING 3
#define FROM4_INCOMING_TO_FRAG 6
#define FROM6_INCOMING_TO_FRAG 7
#define TCPCONF 32
#define UDPCONF 33
#define GO 253
#define EXITNOW 254
#define MAX_PACKET_BUFFERS 0x10
#define MAX_PACKET_BUFFER_SIZE 0x10001
#define MAX_HELPER_READ_WRITE_RETRY MAX_PACKET_BUFFERS*2

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_LICENSE("GPL");

static struct socket *clientsocket=NULL;
static int RUN,to4_jptr,to6_jptr,to4_dev_major,to6_dev_major,exitnow=0,wkup=0;
static struct mutex to4_sem,to6_sem;
static struct nf_hook_ops ipv4_PRE,ipv6_PRE;
static struct sockaddr_in to_helper;
static uint16_t tcp_p[MAX_EXCLUDED_PORTS];
static uint16_t udp_p[MAX_EXCLUDED_PORTS];
static struct class *dev_class;
static struct device *to4_dirt_dev,*to6_dirt_dev;
struct cdev *kernel_cdev;
static atomic_t to4_iptr,to6_iptr;
static DECLARE_WAIT_QUEUE_HEAD(to_queue);

static struct
{
  unsigned char buff[MAX_PACKET_BUFFER_SIZE];
  atomic_t len;
} to4_pkt[MAX_PACKET_BUFFERS+1],to6_pkt[MAX_PACKET_BUFFERS+1];

ssize_t to4_dirt(struct file *filp,char *buff,size_t count,loff_t *offp)
{
  unsigned char go=GO;
  int rv,l,iptrt;

  mutex_unlock(&to4_sem);
  mutex_lock(&to4_sem);
  wait_event_interruptible(to_queue,wkup>0);
  wkup--;
  iptrt=atomic_read(&to4_iptr);
  if (exitnow)
    {
      mutex_unlock(&to4_sem);
      mutex_unlock(&to6_sem);
      go=EXITNOW;
      return copy_to_user(buff,&go,sizeof(char));
    }
  if (to4_jptr!=iptrt)
    {
      if (iptrt==to4_jptr-1||((iptrt==0)&&(to4_jptr==MAX_PACKET_BUFFERS-1)))
        printk(KERN_ALERT "Buffer full!");
      if ((l=atomic_read(&(to4_pkt[to4_jptr].len))))
        {
          switch (to4_pkt[to4_jptr].buff[1]&0xf0)
            {
            case 0x60:
              break;
            default:
              return copy_to_user(buff,&go,sizeof(char));
            }
          if (l>MAX_TO4_PKT_SIZE)
            to4_pkt[to4_jptr].buff[0]=FROM6_INCOMING_TO_FRAG;
          else
            to4_pkt[to4_jptr].buff[0]=FROM6_INCOMING;
          rv=
            copy_to_user
            (
             buff,
             (unsigned char *)(to4_pkt[to4_jptr].buff),
             atomic_read(&(to4_pkt[to4_jptr].len))
             );
          rv=atomic_read(&(to4_pkt[to4_jptr].len));
          atomic_set(&(to4_pkt[to4_jptr].len),0);
          to4_jptr++;
          if (to4_jptr==MAX_PACKET_BUFFERS)
            to4_jptr=0;
          return rv;
        }
    }
  return copy_to_user(buff,&go,sizeof(char));
}

ssize_t to6_dirt
(struct file *filp,char *buff,size_t count,loff_t *offp)
{
  unsigned char go=GO;
  int rv,l,iptrt;

  mutex_unlock(&to6_sem);
  mutex_lock(&to6_sem);
  wait_event_interruptible(to_queue,wkup>0);
  wkup--;
  iptrt=atomic_read(&to6_iptr);
  if (exitnow)
    {
      mutex_unlock(&to4_sem);
      mutex_unlock(&to6_sem);
      go=EXITNOW;
      return copy_to_user(buff,&go,sizeof(char));
    }
  if (to6_jptr!=iptrt)
    {
      if (iptrt==to6_jptr-1||((iptrt==0)&&(to6_jptr==MAX_PACKET_BUFFERS-1)))
        printk(KERN_ALERT "Buffer full!");
      if ((l=atomic_read(&(to6_pkt[to6_jptr].len))))
        {
          switch (to6_pkt[to6_jptr].buff[1]&0xf0)
            {
            case 0x40:
              break;
            default:
              return copy_to_user(buff,&go,sizeof(char));
            }
          if (l>MAX_TO6_PKT_SIZE)
            to6_pkt[to6_jptr].buff[0]=FROM4_INCOMING_TO_FRAG;
          else
            to6_pkt[to6_jptr].buff[0]=FROM4_INCOMING;
          rv=
            copy_to_user
            (
             buff,
             (unsigned char *)(to6_pkt[to6_jptr].buff),
             atomic_read(&(to6_pkt[to6_jptr].len))
             );
          rv=atomic_read(&(to6_pkt[to6_jptr].len));
          atomic_set(&(to6_pkt[to6_jptr].len),0);
          to6_jptr++;
          if (to6_jptr==MAX_PACKET_BUFFERS)
            to6_jptr=0;
          return rv;
        }
    }
  return copy_to_user(buff,&go,sizeof(char));
}

struct file_operations to4_fops={.read=to4_dirt,};
struct file_operations to6_fops={.read=to6_dirt,};

void load_conf(struct sk_buff *skb,void *transport_hdr)
{
  unsigned char *data;
  uint16_t *port;
  static int tcp_configured=0,udp_configured=0;
  int len,i;

  data=((unsigned char *)transport_hdr)+sizeof(struct udphdr);
  switch (*data)
    {
    case TCPCONF:
      {
        if (!tcp_configured)
          {
            port=(uint16_t *)(&(data[1]));
            len=ntohs(port[0]);
            for (i=0; i<len; i++)
              tcp_p[i]=ntohs(port[i+1]);
            tcp_configured=1;
            RUN++;
          }
        break;
      }
    case UDPCONF:
      {
        if (!udp_configured)
          {
            port=(uint16_t *)(&(data[1]));
            len=ntohs(port[0]);
            for (i=0; i<len; i++)
              udp_p[i]=ntohs(port[i+1]);
            udp_configured=1;
            RUN++;
          }
        break;
      }
    default: break;
    }
  kfree_skb(skb);
}

unsigned int ipv6_handler_PRE
(
 unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
 const struct net_device *out, int (*okfn)(struct sk_buff *)
 )
{
  struct icmp6hdr *icmp6;
  struct ipv6hdr *hdr6;
  register int iptrt;
  atomic_t tot_len;

  if (RUN<MIN_CONF)
    return NF_ACCEPT;
  hdr6=skb_header_pointer(skb,0,0,NULL);
  switch (hdr6->nexthdr)
    {
    case IPPROTO_ICMPV6:
      {
        icmp6=skb_header_pointer(skb,sizeof(struct ipv6hdr),0,NULL);;
        switch (icmp6->icmp6_type)
          {
          case ICMPV6_ECHO_REPLY:
          case ICMPV6_ECHO_REQUEST:
            break;
          case NDISC_ROUTER_SOLICITATION:
          case NDISC_ROUTER_ADVERTISEMENT:
          case NDISC_NEIGHBOUR_SOLICITATION:
          case NDISC_NEIGHBOUR_ADVERTISEMENT:
          case NDISC_REDIRECT:
            return NF_ACCEPT;
          default:
            {
              kfree_skb(skb);
              return NF_DROP;
            }
          }
        break;
      }
    case IPPROTO_UDP:
      break;
    case IPPROTO_TCP:
      break;
    default:
      {
        kfree_skb(skb);
        return NF_DROP;
      }
    }
  if (atomic_read(&to4_iptr)>=MAX_PACKET_BUFFERS)
    atomic_set(&to4_iptr,0);
  iptrt=atomic_inc_return(&to4_iptr)-1;
  atomic_set
    (
     &(tot_len),
     sizeof(unsigned char)+sizeof(struct ipv6hdr)+ntohs(hdr6->payload_len)
     );
  skb_copy_bits(skb,0,&(to4_pkt[iptrt].buff[1]),atomic_read(&(tot_len))-1);
  atomic_set(&(to4_pkt[iptrt].len),atomic_read(&(tot_len)));
  wkup=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to_queue);
  kfree_skb(skb);
  return NF_STOLEN;
}

unsigned int ipv4_handler_PRE
(
 unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
 const struct net_device *out, int (*okfn)(struct sk_buff *)
 )
{
  struct icmphdr *icmp4;
  struct iphdr *hdr4;
  struct tcphdr *tcp4;
  struct udphdr *udp4;
  register int i,iptrt;
  atomic_t tot_len;

  hdr4=skb_header_pointer(skb,0,0,NULL);
  switch (hdr4->protocol)
    {
    case IPPROTO_ICMP:
      {
        if (RUN<MIN_CONF)
          return NF_ACCEPT;
        if (hdr4->saddr==0x100007f||hdr4->daddr==0x100007f)
          return NF_ACCEPT;
        icmp4=skb_header_pointer(skb,sizeof(struct iphdr),0,NULL);
        switch (icmp4->type)
          {
          case ICMP_ECHOREPLY:
          case ICMP_ECHO:
            break;
          default:
            {
              kfree_skb(skb);
              return NF_DROP;
            }
          }
        break;
      }
    case IPPROTO_TCP:
      {
        if (RUN<MIN_CONF)
          return NF_ACCEPT;
        if (hdr4->saddr==0x100007f||hdr4->daddr==0x100007f)
          return NF_ACCEPT;
        tcp4=skb_header_pointer(skb,sizeof(struct iphdr),0,NULL);
        i=0;
        while (tcp_p[i]!=0)
          {
            if (ntohs(tcp4->dest)==tcp_p[i]||ntohs(tcp4->source)==tcp_p[i])
              return NF_ACCEPT;
            i++;
          }
        break;
      }
    case IPPROTO_UDP:
      {
        udp4=skb_header_pointer(skb,sizeof(struct iphdr),0,NULL);
        if (RUN<MIN_CONF)
          {
            if (
                hdr4->saddr==0x100007f
                &&
                hdr4->daddr==0x100007f
                &&
                ntohs(udp4->dest)==DIRECT_TO_KERNEL
                )
              {
                load_conf(skb,udp4);
                return NF_STOLEN;
              }
            return NF_ACCEPT;
          }
        if (hdr4->saddr==0x100007f||hdr4->daddr==0x100007f)
          return NF_ACCEPT;
        i=0;
        while (udp_p[i]!=0)
          {
            if (ntohs(udp4->dest)==udp_p[i]||ntohs(udp4->source)==udp_p[i])
              return NF_ACCEPT;
            i++;
          }
        break;
      }
    default:
      {
        kfree_skb(skb);
        return NF_DROP;
      }
    }
  if (atomic_read(&to6_iptr)>=MAX_PACKET_BUFFERS)
    atomic_set(&to6_iptr,0);
  iptrt=atomic_inc_return(&to6_iptr)-1;
  atomic_set(&(tot_len),sizeof(unsigned char)+ntohs(hdr4->tot_len));
  skb_copy_bits(skb,0,&(to6_pkt[iptrt].buff[1]),atomic_read(&(tot_len))-1);
  atomic_set(&(to6_pkt[iptrt].len),atomic_read(&(tot_len)));
  wkup=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to_queue);
  kfree_skb(skb);
  return NF_STOLEN;
}

void register_handlers(void)
{
  ipv4_PRE.hook=(nf_hookfn *)ipv4_handler_PRE;
  ipv4_PRE.pf=PF_INET;
  ipv4_PRE.hooknum=NF_INET_LOCAL_IN;//NF_INET_PRE_ROUTING for fragments;
  ipv4_PRE.priority=NF_IP_PRI_FIRST;
  ipv6_PRE.hook=(nf_hookfn *)ipv6_handler_PRE;
  ipv6_PRE.pf=PF_INET6;
  ipv6_PRE.hooknum=NF_INET_LOCAL_IN;//NF_INET_PRE_ROUTING for fragments;
  ipv6_PRE.priority=NF_IP6_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_register_net_hook(&init_net,&ipv4_PRE);
  nf_register_net_hook(&init_net,&ipv6_PRE);
#else
  nf_register_hook(&ipv4_PRE);
  nf_register_hook(&ipv6_PRE);
#endif
}

void unregister_handlers(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_unregister_net_hook(&init_net,&ipv4_PRE);
  nf_unregister_net_hook(&init_net,&ipv6_PRE);
#else
  nf_unregister_hook(&ipv4_PRE);
  nf_unregister_hook(&ipv6_PRE);
#endif
  memset(&ipv4_PRE,0,sizeof(struct nf_hook_ops));
  memset(&ipv6_PRE,0,sizeof(struct nf_hook_ops));
}

int char_dev_init(void)
{
  to4_dev_major=register_chrdev(0,"dirt4",&to4_fops);
  if (to4_dev_major<0)
    return to4_dev_major;
  dev_class=class_create(THIS_MODULE,"dirt_class");
  if (IS_ERR(dev_class))
    {
      unregister_chrdev(to4_dev_major,"dirt4");
      return PTR_ERR(dev_class);
    }
  to4_dirt_dev=
    device_create(dev_class,NULL,MKDEV(to4_dev_major,0),NULL,"dirt4");
  if (IS_ERR(to4_dirt_dev))
    {
      class_destroy(dev_class);
      unregister_chrdev(to4_dev_major,"dirt4");
      return PTR_ERR(to4_dirt_dev);
    }
  to6_dev_major=register_chrdev(0,"dirt6",&to6_fops);
  if (to6_dev_major<0)
    {
      device_destroy(dev_class,MKDEV(to4_dev_major,0));
      class_destroy(dev_class);
      unregister_chrdev(to4_dev_major,"dirt4");
      return to6_dev_major;
    }
  to6_dirt_dev=
    device_create(dev_class,NULL,MKDEV(to6_dev_major,0),NULL,"dirt6");
  if (IS_ERR(to6_dirt_dev))
    {
      device_destroy(dev_class,MKDEV(to4_dev_major,0));
      class_destroy(dev_class);
      unregister_chrdev(to4_dev_major,"dirt4");
      unregister_chrdev(to6_dev_major,"dirt6");
      return PTR_ERR(to6_dirt_dev);
    }
  return 0;
}

void char_dev_cleanup(void)
{
  device_destroy(dev_class,MKDEV(to6_dev_major,0));
  device_destroy(dev_class,MKDEV(to4_dev_major,0));
  class_destroy(dev_class);
  unregister_chrdev(to6_dev_major,"dirt6");
  unregister_chrdev(to4_dev_major,"dirt4");
}

int init_local_sockets(void)
{
  if (sock_create(PF_INET,SOCK_DGRAM,IPPROTO_UDP,&clientsocket)<0)
    {
      printk(KERN_ERR "Error creating client socket.\n");
      return -EIO;
    }
  return 0;
}

void release_local_sockets(void)
{
  if (clientsocket)
    sock_release(clientsocket);
}

int helper_run(void)
{
  char *argv1[]={"/bin/sh","-c","/sbin/directobot",NULL};
  char *argv2[]=
    {"/bin/sh","-c","/usr/sbin/ethtool -K "NIC" gro off",NULL};
  char *envp[]={"HOME=/",NULL};
  int rv;

  if ((rv=call_usermodehelper(argv1[0],argv1,envp,UMH_WAIT_EXEC))<0)
    printk(KERN_ALERT "Error: helper not loaded.\n");
  if ((rv=call_usermodehelper(argv2[0],argv2,envp,UMH_WAIT_EXEC))<0)
    printk(KERN_ALERT "Error: cannot disable Generic Receive Offloading.\n");
  return rv;
}

void helper_exit(void)
{
  char *argv[]={"/usr/bin/killall","directobot",NULL};
  char *envp[]={"HOME=/",NULL};
  int rv;

  if ((rv=call_usermodehelper(argv[0],argv,envp,UMH_WAIT_EXEC))<0)
    printk(KERN_ALERT "Error: helper does not quit.\n");
  msleep(0x5dc);
  return;
}

static int __init direct_init(void)
{
  int rv=0,i;

  RUN=0; to4_jptr=0; to6_jptr=0;
  atomic_set(&to4_iptr,0);
  atomic_set(&to6_iptr,0);
  for (i=0; i<MAX_PACKET_BUFFERS; i++)
    {
      atomic_set(&(to4_pkt[i].len),0);
      atomic_set(&(to6_pkt[i].len),0);
    }
  if ((rv=char_dev_init()))
    return rv;
  if ((rv=init_local_sockets()))
    {
      char_dev_cleanup();
      return rv;
    }
  memset(&to_helper,0,sizeof(struct sockaddr_in));
  to_helper.sin_family=AF_INET;
  to_helper.sin_addr.s_addr=0x100007f;//in_aton("127.0.0.1");
  to_helper.sin_port=htons(DIRECT_TO_HELPER);
  mutex_init(&to4_sem);
  mutex_init(&to6_sem);
  register_handlers();
  memset(tcp_p,0,sizeof(uint16_t)*MAX_EXCLUDED_PORTS);
  memset(udp_p,0,sizeof(uint16_t)*MAX_EXCLUDED_PORTS);
  if ((rv=helper_run())<0)
    {
      unregister_handlers();
      release_local_sockets();
      char_dev_cleanup();
      return rv;
    }
  printk(KERN_ALERT "Directobot module loaded\n");
  return 0;
}

static void __exit direct_exit(void)
{
  exitnow=1;
  mutex_unlock(&to4_sem);
  mutex_unlock(&to6_sem);
  wkup=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to_queue);
  unregister_handlers();
  release_local_sockets();
  msleep(0x5dc);
  char_dev_cleanup();
  printk(KERN_ALERT "Directobot module unloaded\n");
}

module_init(direct_init);
module_exit(direct_exit);
