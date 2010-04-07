#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>

#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th)  (((th)->th_x2 & 0xf0) >> 4)

struct conntimer {
  char label[256];
  struct timeval udpstart;
  struct timeval udpend;
  struct timeval tcpstart;
  struct timeval tcpfirstrecv;
  struct timeval tcpend;
};

int handle_udp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *eth_hdr=(struct ether_header*)(packet);
  const struct ip *iph=(struct ip*)(packet+sizeof(struct ether_header));
  const struct udphdr *udph;
  struct timeval ts = pkthdr->ts;
  struct conntimer *timer = (struct conntimer*)(args);

  printf("UDP for %s Timeval: %ld.%.6ld\n",timer->label,ts.tv_sec,(long)ts.tv_usec);
  return 1;
}

int handle_tcp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *ethh;
  const struct ip *iph;
  const struct tcphdr *tcph;
  const struct timeval ts = pkthdr->ts;

  ethh=(struct ether_header*)(packet);
  iph=(struct ip*)(packet+14); /* sizeof(struct ether_header) */
  tcph = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));

  ((tcph->th_flags) & TH_SYN) ? printf(" SYN "): printf("     ");
  ((tcph->th_flags) & TH_ACK) ? printf(" ACK "): printf("     ");;

  printf(" %ld.%.6ld (%5i of %5i) from %15s ",ts.tv_sec,(long)ts.tv_usec,pkthdr->caplen,pkthdr->len,inet_ntoa(iph->ip_src));
  printf("to %15s\n",inet_ntoa(iph->ip_dst));
  return 1;
}

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
  const struct ip *iph=(struct ip*)(packet+sizeof(struct ether_header));

  if (iph->ip_off & IP_MF) 
  {
    printf("Oh dear lord I'm fragmented!  ");
  }

  if (iph->ip_p == IPPROTO_TCP)
  {
    handle_tcp(args, pkthdr,packet);
  }
  else if (iph->ip_p == IPPROTO_UDP)
  {
    handle_udp(args,pkthdr,packet);
  }
}

int main(int argc,char **argv)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    u_char* args = NULL;
    struct conntimer timer = {"",{0,0},{0,0},{0,0},{0,0},{0,0}};

    if(argc < 2)
    {
        fprintf(stdout,"Usage: %s <label> <\"filters\">\n",argv[0]);
        return 0;
    }

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
      printf("%s\n",errbuf);
      exit(1);
    }

    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    {
      printf("pcap_open_live(): %s\n",errbuf);
      exit(1);
    }

    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    strncpy(timer.label,argv[1],strlen(argv[1]+1));

    pcap_loop(descr,-1,my_callback,(u_char*)&timer);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
