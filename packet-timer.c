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

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
  struct timeval ts = pkthdr->ts;

  const struct ether_header *eth_hdr=(struct ether_header*)(packet);
  const struct ip *ip_hdr=(struct ip*)(packet+sizeof(struct ether_header));

  if (ip_hdr->ip_p == IPPROTO_TCP)
  {
    printf("TCP found at Timeval: %ld.%.6ld\n",ts.tv_sec,(long)ts.tv_usec);
  }
  else if (ip_hdr->ip_p == IPPROTO_UDP)
  {
    printf("UDP found at Timeval: %ld.%.6ld\n",ts.tv_sec,(long)ts.tv_usec);
  }
}


int main(int argc,char **argv)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    char label[1024];
    pcap_t* descr;
    struct bpf_program fp;
    bpf_u_int32 maskp;
    bpf_u_int32 netp;
    u_char* args = NULL;

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

    pcap_loop(descr,-1,my_callback,(u_char*)label);

    fprintf(stdout,"\nfinished\n");
    return 0;
}
