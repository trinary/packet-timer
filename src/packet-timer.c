#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "dnsreq.h"

#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th)  ((th)->th_x2)
#define SIZE_ETHER  14

struct options {
  char label[256];
  char protocol[256];
  struct in_addr selfaddr;
};

struct gentimer {
  char label[256];
  struct timeval start;
  struct timeval send;
  struct timeval ack;
  struct timeval recv;
  struct timeval end;
};

struct gentimer *cur_timer = NULL;

struct gentimer* new_timer(const char* label)
{
  struct gentimer *tm = (struct gentimer*)malloc(sizeof(struct gentimer));
  if(tm==NULL)
  {
    return NULL;
  }
  strncpy(tm->label,label,strlen(label));
  tm->start.tv_sec=0;tm->start.tv_usec=0;
  tm->ack.tv_sec=0;tm->ack.tv_usec=0;
  tm->recv.tv_sec=0;tm->recv.tv_usec=0;
  tm->end.tv_sec=0;tm->end.tv_usec=0;
  return tm;
}

int print_timings(struct options *opts,struct gentimer *tm)
{
  struct timeval tmp;
  char timestr[64];
  timeval_subtract(&tmp,&(tm->send),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|%s|%s|%s|Time to First Send\t%s\n",opts->label,opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&(tm->ack),&(tm->start));
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|%s|%s|%s|Time to First ACK\t%s\n",opts->label,opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&tm->recv,&tm->start);
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|%s|%s|%s|Time to first RX\t%s\n",opts->label,opts->protocol,tm->label,timestr);

  timeval_subtract(&tmp,&tm->end,&tm->start);
  snprintf(timestr,63,"%ld.%.6ld",tmp.tv_sec,(long)tmp.tv_usec);
  printf("Net|%s|%s|%s|Time to Connection Close\t%s\n",opts->label,opts->protocol,tm->label,timestr);
  return 1;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
  int i;
  int gap;
  const u_char *ch;

  printf("%05d   ", offset);

  ch = payload;
  for(i = 0; i < len; i++) {
    printf("%02x ", *ch);
    ch++;
    /* print extra space after 8th */
    if (i == 7)
      printf(" ");
  }
  if (len < 8)
    printf(" ");

  if (len < 16) {
    gap = 16 - len;
    for (i = 0; i < gap; i++) {
      printf("   ");
    }
  }
  printf("   ");

  ch = payload;
  for(i = 0; i < len; i++) {
    if (isprint(*ch))
      printf("%c", *ch);
    else
      printf(".");
    ch++;
  }

  printf("\n");

  return;
}

void print_payload(const u_char *payload, int len)
{

  int len_rem = len;
  int line_width = 16;			/* number of bytes per line */
  int line_len;
  int offset = 0;					/* zero-based offset counter */
  const u_char *ch = payload;

  if (len <= 0)
    return;

  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset);
    return;
  }

  for ( ;; ) {
    line_len = line_width % len_rem;
    print_hex_ascii_line(ch, line_len, offset);
    len_rem = len_rem - line_len;
    ch = ch + line_len;
    offset = offset + line_width;
    if (len_rem <= line_width) {
      print_hex_ascii_line(ch, len_rem, offset);
      break;
    }
  }

  return;
}

/* from the glibc manual */
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_usec < y->tv_usec) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
    y->tv_usec -= 1000000 * nsec;
    y->tv_sec += nsec;
  }
  if (x->tv_usec - y->tv_usec > 1000000) {
    int nsec = (y->tv_usec - x->tv_usec) / 1000000;
    y->tv_usec += 1000000 * nsec;
    y->tv_sec -= nsec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec = x->tv_sec - y->tv_sec;
  result->tv_usec = x->tv_usec - y->tv_usec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

int handle_http(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *ethh;
  const struct ip *iph;
  const struct tcphdr *tcph;
  const struct timeval ts = pkthdr->ts;
  struct options *opts = (struct options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  const char *payload;


  ethh=(struct ether_header*)(packet);
  iph=(struct ip*)(packet+14); /* sizeof(struct ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (struct tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->doff*4;

  payload=(u_char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);
 
/*  printf("payload offset:%i, size %i\n",SIZE_ETHER+size_ip+size_tcp,size_payload);*/ 

  if((tcph->syn) && !(tcph->ack) && (size_payload == 0))
  {
    if(cur_timer==NULL)
    {
      cur_timer = new_timer("unknown");
    }
    cur_timer->start = ts;
  }

  if(strncmp(payload,"GET ",4)==0)
  {
    strcpy(cur_timer->label,"GET");
    cur_timer->send = ts;
  }

  if(strncmp(payload,"PUT ",4)==0)
  {
    strcpy(cur_timer->label,"PUT");
    cur_timer->send = ts;
  }

  if(strncmp(payload,"POST ",5)==0)
  {
    strcpy(cur_timer->label,"POST");
    cur_timer->send = ts;
  }


  if((size_payload == 0) && (tcph->ack) && !(tcph->syn) && (opts->selfaddr.s_addr == iph->ip_dst.s_addr))
  {
    if(cur_timer != NULL && cur_timer->ack.tv_sec == 0)
    {
      cur_timer->ack = ts;
    }
  }

  if ((strncmp(payload,"HTTP/1.",7)==0) && (opts->selfaddr.s_addr == iph->ip_dst.s_addr))
  {
    if(cur_timer != NULL && cur_timer->recv.tv_sec == 0)
    {
      cur_timer->recv = ts;
    }
  }

  if(tcph->fin)
  {
    if(cur_timer != NULL && cur_timer->end.tv_sec == 0)
    {
      cur_timer->end = ts;
      print_timings(opts,cur_timer);
      free(cur_timer);
      cur_timer=NULL;
    }
  }

  /* print_payload(payload,size_payload); */
  return 1;
}


int handle_dns(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *ethh;
  const struct ip *iph;
  const struct udphdr *udph;
  const struct timeval ts = pkthdr->ts;
  const struct dns_header *dnsh;
  struct options *opts = (struct options*)(args);
  int size_ip;
  int size_udp;
  int size_payload;
  const char *payload;

  ethh=(struct ether_header*)(packet);
  iph=(struct ip*)(packet+14); /* sizeof(struct ether_header) */
  size_ip = IP_HL(iph)*4;
  size_udp = 8;

  udph=(struct udphdr*)(packet+SIZE_ETHER+size_ip);

  payload=(u_char *)(packet + SIZE_ETHER + size_ip + size_udp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_udp);

  dnsh = (struct dns_header*)(payload);

  printf("id %u qr %u op %u aa %u tc %u rd %u ra %u ad %u cd %u rcode %u #qd %u #an %u #ns %u #ar %u\n",
      dnsh->id,dnsh->qr,dnsh->opcode,dnsh->aa,dnsh->tc,dnsh->rd,dnsh->ra,dnsh->ad,dnsh->cd,dnsh->rcode,
      ntohs(dnsh->qdcount),ntohs(dnsh->ancount),ntohs(dnsh->nscount),ntohs(dnsh->arcount));

  print_payload(payload,ntohs(udph->len));

}

int handle_udp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *eth_hdr=(struct ether_header*)(packet);
  const struct ip *iph=(struct ip*)(packet+14);
  const struct udphdr *udph;
  int size_ip;
  struct timeval ts = pkthdr->ts;
  struct options *opts = (struct options*)(args);

  size_ip = IP_HL(iph)*4;

  udph=(struct udphdr*)(packet+SIZE_ETHER+size_ip);



  if((ntohs(udph->dest) == 53) || ntohs(udph->source) == 53)
  {
    handle_dns(args,pkthdr,packet);
  }
  return 1;
}

int handle_tcp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  struct options *opts = (struct options*)(args);

  if (strcmp(opts->protocol,"http")==0)
  {
    handle_http(args,pkthdr,packet);
  }
  else if (strcmp(opts->protocol,"cifs")==0)
  {
  }
  else if (strcmp(opts->protocol,"ftp")==0)
  {
  }
  else if (strcmp(opts->protocol,"mapi")==0)
  {
  }

  return 1;
}


void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
  const struct ip *iph=(struct ip*)(packet+sizeof(struct ether_header));

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
    struct options opts = {"","",{0}};
    char selfip[INET_ADDRSTRLEN];
    struct ifaddrs *ifaddrstruct=NULL,*tmpaddr;

    if(argc < 2)
    {
        fprintf(stdout,"Usage: %s <label> <protocol> <\"filters\">\n",argv[0]);
        return 0;
    }

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
      printf("%s\n",errbuf);
      exit(1);
    }

    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    getifaddrs(&ifaddrstruct);
    tmpaddr = ifaddrstruct;
    while (ifaddrstruct!=NULL)
    {
      if(ifaddrstruct->ifa_addr->sa_family==AF_INET && strcmp(ifaddrstruct->ifa_name,dev)==0)
      {
        opts.selfaddr=((struct sockaddr_in *)ifaddrstruct->ifa_addr)->sin_addr;
      }
      ifaddrstruct=ifaddrstruct->ifa_next;
    }
    freeifaddrs(tmpaddr);

    inet_ntop(AF_INET,(const void*)&opts.selfaddr,selfip,INET_ADDRSTRLEN);

    printf("set selfaddr to %s\n",selfip);

    descr = pcap_open_live(dev,BUFSIZ,1,2000,errbuf);
    if(descr == NULL)
    {
      printf("pcap_open_live(): %s\n",errbuf);
      exit(1);
    }

    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[3],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }

    strncpy(opts.label,   argv[1],strlen(argv[1]));
    strncpy(opts.protocol,argv[2],strlen(argv[2]));

    pcap_loop(descr,60,my_callback,(u_char*)&opts);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
