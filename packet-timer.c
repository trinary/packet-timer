#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>

#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th)  ((th)->th_x2)
#define SIZE_ETHER  14

struct options {
  char label[256];
  char protocol[256];
  bpf_u_int32 selfaddr;
};

struct gentimer {
  char label[256];
  struct timeval start;
  struct timeval end;
};

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
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

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
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
  char srcip[INET_ADDRSTRLEN];
  char dstip[INET_ADDRSTRLEN];
  struct options *opts = (struct options*)(args);
  int size_ip;
  int size_tcp;
  int size_payload;
  const char *payload;

  ethh=(struct ether_header*)(packet);
  iph=(struct ip*)(packet+14); /* sizeof(struct ether_header) */
  size_ip = IP_HL(iph)*4;
  tcph = (struct tcphdr*)(packet+SIZE_ETHER+size_ip);
  size_tcp= tcph->th_off*4;

  /* printf("payload offset: %i + %i + %i = %i\n",SIZE_ETHER,size_ip,size_tcp,SIZE_ETHER+size_ip+size_tcp); */

  payload=(u_char *)(packet + SIZE_ETHER + size_ip + size_tcp);
  size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);



  if (strncmp(payload,"GET ",4)==0)
  {
    printf("GET issued at %ld.%.6ld\n",ts.tv_sec,(long)ts.tv_usec);
  }

  if (strncmp(payload,"HTTP/1.1 ",9)==0)
  {
    printf("HTTP recv at %ld.%.6ld\n",ts.tv_sec,(long)ts.tv_usec);
  }

/*  print_payload(payload,size_payload); */
  return 1;
}

int handle_udp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *eth_hdr=(struct ether_header*)(packet);
  const struct ip *iph=(struct ip*)(packet+sizeof(struct ether_header));
  const struct udphdr *udph;
  struct timeval ts = pkthdr->ts;
  struct options *opts = (struct options*)(args);

  printf("UDP for %s Timeval: %ld.%.6ld\n",opts->label,ts.tv_sec,(long)ts.tv_usec);
  return 1;
}

int handle_tcp(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
  const struct ether_header *ethh;
  const struct ip *iph;
  const struct tcphdr *tcph;
  const struct timeval ts = pkthdr->ts;
  char srcip[INET_ADDRSTRLEN];
  char dstip[INET_ADDRSTRLEN];
  struct options *opts = (struct options*)(args);

  ethh=(struct ether_header*)(packet);
  iph=(struct ip*)(packet+14); /* sizeof(struct ether_header) */
  tcph = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip));

  /*
  ((tcph->th_flags) & TH_SYN) ? printf(" SYN "): printf("     ");
  ((tcph->th_flags) & TH_ACK) ? printf(" ACK "): printf("     ");
  */

  inet_ntop(AF_INET,(const void*)&iph->ip_src,srcip,INET_ADDRSTRLEN);
  inet_ntop(AF_INET,(const void*)&iph->ip_dst,dstip,INET_ADDRSTRLEN);

  /*
  printf(" %ld.%.6ld (%5i of %5i) from %15s to %15s, protocol %s\n",ts.tv_sec,(long)ts.tv_usec,pkthdr->caplen,pkthdr->len,srcip,dstip,opts->protocol);
  */

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
    struct options opts = {"","",0};

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

    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
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

    pcap_loop(descr,-1,my_callback,(u_char*)&opts);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
