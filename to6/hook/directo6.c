#include <asm/siginfo.h>
#include <linux/cdev.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/version.h>
#include <net/ndisc.h>

#define DESCRIPTION "Directo6"
#define AUTHOR "Giovanni Bembo"
#define MODULE_VERS "0.1"
#define MODULE_NAME "directo6"

#define NIC "eth0"
#define MAX_INCOMING_PKT_SIZE 1537
#define MAX_OUTGOING_PKT_SIZE 1537

#define DIRECT_TO_HELPER 8197
#define DIRECT_TO_KERNEL 8198
#define DIRECT_INCOMING 0
#define DIRECT_OUTGOING 1
#define DIRECT_OUTGOING_TO_FRAG 4
#define MIN_CONF 1
#define RELAY4CONF   34
#define GO 253
#define EXITNOW 254
#define MAX_PACKET_BUFFERS 0x8
#define MAX_PACKET_BUFFER_SIZE 0x10001
#define MAX_HELPER_READ_WRITE_RETRY MAX_PACKET_BUFFERS

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_LICENSE("GPL");

static int RUN,to4_jptr,to6_jptr,to4_dev_major,to6_dev_major,exitnow=0,wkup4=0,
  wkup6=0;
static __u32 raddr4;
static atomic_t to4_iptr,to6_iptr;
static DECLARE_WAIT_QUEUE_HEAD(to4_queue);
static DECLARE_WAIT_QUEUE_HEAD(to6_queue);
static struct in6_addr saddr6;
static struct socket *clientsocket=NULL;
static struct mutex to4_sem,to6_sem;
static struct nf_hook_ops ipv4_PRE,ipv6_LOCAL_OUT;
static struct sockaddr_in to_helper;
static struct class *dev_class;
static struct device *to4_dirt_dev,*to6_dirt_dev;
struct cdev *kernel_cdev;

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
  wait_event_interruptible(to4_queue,wkup4>0);
  wkup4--;
  iptrt=atomic_read(&to4_iptr);
  if (exitnow)
    {
      mutex_unlock(&to4_sem);
      mutex_unlock(&to6_sem);
      go=EXITNOW;
      rv=copy_to_user(buff,&go,sizeof(char));
      return sizeof(char);
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
              {
                rv=copy_to_user(buff,&go,sizeof(char));
                return sizeof(char);
              }
            }
          if (l>MAX_OUTGOING_PKT_SIZE)
            to4_pkt[to4_jptr].buff[0]=DIRECT_OUTGOING_TO_FRAG;
          else
            to4_pkt[to4_jptr].buff[0]=DIRECT_OUTGOING;
          rv=copy_to_user(buff,(unsigned char *)(to4_pkt[to4_jptr].buff),l);
          atomic_set(&(to4_pkt[to4_jptr].len),0);
          to4_jptr++;
          if (to4_jptr==MAX_PACKET_BUFFERS)
            to4_jptr=0;
          return l;
        }
    }
  rv=copy_to_user(buff,&go,sizeof(char));
  return sizeof(char);
}

ssize_t to6_dirt
(struct file *filp,char *buff,size_t count,loff_t *offp)
{
  unsigned char go=GO;
  int rv,l,iptrt;

  mutex_unlock(&to6_sem);
  mutex_lock(&to6_sem);
  wait_event_interruptible(to6_queue,wkup6>0);
  wkup6--;
  iptrt=atomic_read(&to6_iptr);
  if (exitnow)
    {
      mutex_unlock(&to4_sem);
      mutex_unlock(&to6_sem);
      go=EXITNOW;
      rv=copy_to_user(buff,&go,sizeof(char));
      return sizeof(char);
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
              {
                rv=copy_to_user(buff,&go,sizeof(char));
                return sizeof(char);
              }
            }
          to6_pkt[to6_jptr].buff[0]=DIRECT_INCOMING;
          rv=copy_to_user(buff,(unsigned char *)(to6_pkt[to6_jptr].buff),l);
          atomic_set(&(to6_pkt[to6_jptr].len),0);
          to6_jptr++;
          if (to6_jptr==MAX_PACKET_BUFFERS)
            to6_jptr=0;
          return l;
        }
    }
  rv=copy_to_user(buff,&go,sizeof(char));
  return sizeof(char);
}

struct file_operations to4_fops={.read=to4_dirt,};
struct file_operations to6_fops={.read=to6_dirt,};

void load_conf(struct sk_buff *skb,void *transport_hdr)
{
  unsigned char *data;
  static int host_configured=0;

  data=((unsigned char *)transport_hdr)+sizeof(struct udphdr);
  switch (*data)
    {
    case RELAY4CONF:
      {
        if (!host_configured)
          {
            raddr4=*((__u32 *)(&(data[1])));
            memcpy(&saddr6,&(data[5]),sizeof(struct in6_addr));
            RUN++;
            host_configured++;
          }
        break;
      }
    default: break;
    }
  kfree_skb(skb);
}

unsigned int ipv4_handler_PRE
(
 unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
 const struct net_device *out,int (*okfn)(struct sk_buff *)
 )
{
  struct icmphdr *icmp4;
  struct iphdr *hdr4;
  struct udphdr *udp4;
  register int iptrt;
  atomic_t tot_len;

  hdr4=skb_header_pointer(skb,0,0,NULL);
  switch (hdr4->protocol)
    {
    case IPPROTO_ICMP:
      {
        if (RUN<MIN_CONF)
          return NF_ACCEPT;
        else if (hdr4->saddr==raddr4)
          {
            icmp4=skb_header_pointer(skb,sizeof(struct iphdr),0,NULL);
            switch (icmp4->type)
              {
              case ICMP_ECHOREPLY:
              case ICMP_ECHO:
                break;
              default:
                return NF_ACCEPT;
              }
          }
        else
          return NF_ACCEPT;
        break;
      }
    case IPPROTO_UDP:
      {
        if (RUN<MIN_CONF)
          {
            udp4=skb_header_pointer(skb,sizeof(struct iphdr),0,NULL);
            if
              (
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
            if (hdr4->saddr==raddr4)
              return NF_DROP;
          }
        else if (hdr4->saddr==raddr4)
          break;
        return NF_ACCEPT;
      }
    case IPPROTO_TCP:
      {
        if (RUN<MIN_CONF)
          return NF_ACCEPT;
        if (hdr4->saddr==raddr4)
          break;
        return NF_ACCEPT;
      }
    default:
      return NF_ACCEPT;
    }
  if (atomic_read(&to6_iptr)>=MAX_PACKET_BUFFERS)
    atomic_set(&to6_iptr,0);
  iptrt=atomic_inc_return(&to6_iptr)-1;
  atomic_set(&(tot_len),sizeof(unsigned char)+ntohs(hdr4->tot_len));
  skb_copy_bits(skb,0,&(to6_pkt[iptrt].buff[1]),atomic_read(&(tot_len))-1);
  atomic_set(&(to6_pkt[iptrt].len),atomic_read(&(tot_len)));
  wkup6=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to6_queue);
  return NF_STOLEN;
}

unsigned int ipv6_handler_LOCAL_OUT
(
 unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
 const struct net_device *out,int (*okfn)(struct sk_buff *)
 )
{
  struct icmp6hdr *icmp6;
  struct ipv6hdr *hdr6;
  register int i,iptrt;
  atomic_t tot_len;

  if (RUN<MIN_CONF)
    return NF_ACCEPT;
  hdr6=skb_header_pointer(skb,0,0,NULL);
  for (i=0; i<sizeof(struct in6_addr); i++)
    if
      (((unsigned char *)(&(hdr6->daddr)))[i]!=((unsigned char *)(&saddr6))[i])
      break;
  if (i==sizeof(struct in6_addr))
    return NF_ACCEPT;
  switch (hdr6->nexthdr)
    {
    case IPPROTO_ICMPV6:
      {
        icmp6=skb_header_pointer(skb,sizeof(struct ipv6hdr),0,NULL);
        switch (icmp6->icmp6_type)
          {
          case ICMPV6_ECHO_REQUEST:
            break;
          default:
            return NF_ACCEPT;
          }
        break;
      }
    case IPPROTO_UDP:
      break;
    case IPPROTO_TCP:
      break;
    default:
      return NF_ACCEPT;
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
  wkup4=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to4_queue);
  return NF_STOLEN;
}

void register_handlers(void)
{
  ipv4_PRE.hook=(nf_hookfn *)ipv4_handler_PRE;
  ipv4_PRE.pf=PF_INET;
  ipv4_PRE.hooknum=NF_INET_PRE_ROUTING;
  ipv4_PRE.priority=NF_IP_PRI_LAST;
  ipv6_LOCAL_OUT.hook=(nf_hookfn *)ipv6_handler_LOCAL_OUT;
  ipv6_LOCAL_OUT.pf=PF_INET6;
  ipv6_LOCAL_OUT.hooknum=NF_INET_LOCAL_OUT;
  ipv6_LOCAL_OUT.priority=NF_IP6_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_register_net_hook(&init_net,&ipv4_PRE);
  nf_register_net_hook(&init_net,&ipv6_LOCAL_OUT);
#else
  nf_register_hook(&ipv4_PRE);
  nf_register_hook(&ipv6_LOCAL_OUT);
#endif
}

void unregister_handlers(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  nf_unregister_net_hook(&init_net,&ipv4_PRE);
  nf_unregister_net_hook(&init_net,&ipv6_LOCAL_OUT);
#else
  nf_unregister_hook(&ipv4_PRE);
  nf_unregister_hook(&ipv6_LOCAL_OUT);
#endif
  memset(&ipv4_PRE,0,sizeof(struct nf_hook_ops));
  memset(&ipv6_LOCAL_OUT,0,sizeof(struct nf_hook_ops));
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
  char *argv1[]={"/sbin/directo6",NULL};
  char *argv2[]=
    {"/bin/sh","-c","/usr/sbin/ethtool -K "NIC" gso off",NULL};
  char *envp[]={"HOME=/",NULL};
  int rv;

  if ((rv=call_usermodehelper(argv1[0],argv1,envp,UMH_WAIT_EXEC))<0)
    printk(KERN_ALERT "Error: helper not loaded.\n");
  if ((rv=call_usermodehelper(argv2[0],argv2,envp,UMH_WAIT_EXEC))<0)
    printk
      (KERN_ALERT "Error: cannot disable Generic Send Offloading.\n");
  return rv;
}

void helper_exit(void)
{
  char *argv[]={"/usr/bin/killall","directo6",NULL};
  char *envp[]={"HOME=/",NULL};

  if (call_usermodehelper(argv[0],argv,envp,UMH_WAIT_PROC)<0)
    printk(KERN_ALERT "Error: cannot kill helper.\n");
  msleep(0x5dc);
  return;
}

static int __init direct_init(void)
{
  int rv=0,i;

  preempt_disable();
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
  memset(&saddr6,0,sizeof(struct in6_addr));
  to_helper.sin_family=AF_INET;
  to_helper.sin_addr.s_addr=0x100007f;//in_aton("127.0.0.1");
  to_helper.sin_port=htons(DIRECT_TO_HELPER);
  mutex_init(&to4_sem);
  mutex_init(&to6_sem);
  register_handlers();
  if ((rv=helper_run())<0)
    {
      unregister_handlers();
      release_local_sockets();
      char_dev_cleanup();
      return rv;
    }
  printk(KERN_ALERT "Directo6 module loaded\n");
  return 0;
}

static void __exit direct_exit(void)
{
  exitnow=1;
  mutex_unlock(&to4_sem);
  mutex_unlock(&to6_sem);
  wkup4=MAX_HELPER_READ_WRITE_RETRY;
  wkup6=MAX_HELPER_READ_WRITE_RETRY;
  wake_up_interruptible(&to4_queue);
  wake_up_interruptible(&to6_queue);
  unregister_handlers();
  release_local_sockets();
  msleep(0x5dc);
  char_dev_cleanup();
  printk(KERN_ALERT "Directo6 module unloaded.\n");
}

module_init(direct_init);
module_exit(direct_exit);
