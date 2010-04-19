// api includes
#include<pcapp/capture_descriptor.h>
#include<pcapp/dnsreq.h>
#include<pcapp/network_device.h>
#include<pcapp/timer/cifs_timer.h>
#include<pcapp/timer/dns_timer.h>
#include<pcapp/timer/ftp_timer.h>
#include<pcapp/timer/http_timer.h>
#include<pcapp/timer/mapi_timer.h>
#include<pcapp/timer/options.h>
#include<pcapp/timer/timeval.h>


// tp includes
#include <pcap.h>

// std includes
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <iostream>
#include <stdexcept>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#ifndef IP_HL
#define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
#define TH_OFF(th)  ((th)->th_x2)
#define SIZE_ETHER  14
#endif

using namespace pcapp::timer;
using namespace pcapp;


HTTPTimer *cur_http_timer = NULL;
DNSTimer  *cur_dns_timer  = NULL;
FTPTimer  *cur_ftp_timer  = NULL;
CIFSTimer *cur_cifs_timer  = NULL;
MAPITimer *cur_mapi_timer  = NULL;



/*
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
  // print extra space after 8th
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

  void print_tcpflags(const tcphdr *tcph)
  {
  if(tcph->urg)
  { printf("U"); }
  else
  { printf(" "); }
  if(tcph->ack)
  { printf("A"); }
  else
  { printf(" "); }
  if(tcph->psh)
  { printf("P"); }
  else
  { printf(" "); }
  if(tcph->rst)
  { printf("R"); }
  else
  { printf(" "); }
  if(tcph->syn)
  { printf("S"); }
  else
  { printf(" "); }
  if(tcph->fin)
  { printf("F"); }
  else
  { printf(" "); }
  }

  void print_payload(const u_char *payload, int len)
  {
  int len_rem = len;
  int line_width = 16;
  int line_len;
  int offset = 0;
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
*/

//#############################################################################
int handle_http(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);
    
    if(cur_http_timer == NULL)
    {
        //std::cout<<"allocating http timer"<<std::endl;
        cur_http_timer = new HTTPTimer("Other");
    }

    //    std::cout<<"calling http handle_data"<<std::endl;
    cur_http_timer->handleData(opts, pkthdr, packet);

    return 1;
}

//#############################################################################
int handle_dns(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);
    
    if(cur_dns_timer == NULL)
    {
        cur_dns_timer = new DNSTimer(opts->label);
    }
    
    cur_dns_timer->handleData(opts, pkthdr, packet);
    return 1;
}

//#############################################################################
int handle_ftp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_ftp_timer==NULL)
    {
        cur_ftp_timer = new FTPTimer("All");
    }

    cur_ftp_timer->handleData(opts, pkthdr, packet);
    return 1;
}    

//#############################################################################
int handle_cifs(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_cifs_timer==NULL)
    {
        cur_cifs_timer = new CIFSTimer("All");
    }

    cur_cifs_timer->handleData(opts, pkthdr, packet);
    return 1;
}    

//#############################################################################
int handle_mapi(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);

    if(cur_mapi_timer==NULL)
    {
        cur_mapi_timer = new MAPITimer("All");
    }

    cur_mapi_timer->handleData(opts, pkthdr, packet);
    return 1;
}

//#############################################################################
int handle_udp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    const ip *iph=(ip*)(packet+14);
    const udphdr *udph;
    int size_ip;

    size_ip = IP_HL(iph)*4;
    udph=(udphdr*)(packet+SIZE_ETHER+size_ip);

    if((ntohs(udph->dest) == 53) || ntohs(udph->source) == 53)
    {
        handle_dns(args,pkthdr,packet);
    }
    return 1;
}

//#############################################################################
int handle_tcp(u_char* args, const pcap_pkthdr* pkthdr, const u_char* packet)
{
    Options *opts = (Options*)(args);
    //std::cout<<"got tcp"<<std::endl;

    if (strcmp(opts->protocol,"HTTP") == 0 || 
        strcmp(opts->protocol,"REST") == 0 || 
        strcmp(opts->protocol,"GET(REST)") == 0 ||
        strcmp(opts->protocol,"POST(REST)") == 0 || 
        strcmp(opts->protocol,"WebWalk") == 0)
    {
        //std::cout<<"decided it's tcp::http"<<std::endl;
        handle_http(args,pkthdr,packet);
    }
    else if (strcmp(opts->protocol,"CIFS")==0)
    {
        std::cout<<"decided it's tcp::cifs"<<std::endl;
        handle_cifs(args,pkthdr,packet);
    }
    else if (strcmp(opts->protocol,"FTP")==0)
    {
        std::cout<<"decided it's tcp::ftp"<<std::endl;
        handle_ftp(args,pkthdr,packet);
    }
    else if (strcmp(opts->protocol,"MAPI")==0)
    {
        std::cout<<"decided it's tcp::mapi"<<std::endl;
        handle_mapi(args,pkthdr,packet);
    }
    else
    {
        std::cout<<"decided it's tcp::wtf"<<std::endl;
    }
    return 1;
}

//#############################################################################
void my_callback(u_char *args,const pcap_pkthdr* pkthdr,const u_char* packet)
{
    //std::cout<<"callback called"<<std::endl;
    const ip *iph=(ip*)(packet+sizeof(ether_header));

    if (iph->ip_p == IPPROTO_TCP)
    {
        //std::cout<<"decided it's tcp"<<std::endl;
        handle_tcp(args, pkthdr,packet);
    }
    else if (iph->ip_p == IPPROTO_UDP)
    {
        //std::cout<<"decided it's udp"<<std::endl;
        handle_udp(args,pkthdr,packet);
    }
}

//#############################################################################
int main(int argc,char **argv)
{
    int rReturnValue = 0;

    if(argc < 5)
    {
        fprintf(stdout,"Usage: %s <localhost IP> <label> <protocol> <\"filters\">\n",argv[0]);
        return 0;
    }

    try
    {
        // get the device from pcap
        NetworkDevice tNetworkDevice;
        std::cout<<"Got device"<<std::endl;
        
        // then get the network
        bpf_u_int32 maskp;
        bpf_u_int32 netp;
        tNetworkDevice.lookUpNetwork(&netp, &maskp);
        std::cout<<"Looked up Network"<<std::endl;

        // get capture descriptor
        SharedCaptureDescriptorTS tCaptureDescriptor = 
            tNetworkDevice.getCaptureDescriptor(BUFSIZ);
        std::cout<<"got pcap capture descriptor"<<std::endl;

        
        // compile expression argument
        tCaptureDescriptor->compileFilter(argv[4], netp);
        std::cout<<"compiled pcap filter"<<std::endl;

        
        // create options
        Options opts = {"","",{0}};
        //ifaddrs *ifaddrstruct=NULL,*tmpaddr;
        
        /*
        getifaddrs(&ifaddrstruct);
        tmpaddr = ifaddrstruct;
        while (ifaddrstruct!=NULL)
        {
            if((ifaddrstruct->ifa_addr->sa_family == AF_INET) && 
               (tNetworkDevice.getName() == 
                std::string(ifaddrstruct->ifa_name)))
            {
                opts.selfaddr=((sockaddr_in *)ifaddrstruct->ifa_addr)->sin_addr;
            }
            ifaddrstruct=ifaddrstruct->ifa_next;
        }
        freeifaddrs(tmpaddr);
        printf("Looked up our self-addr\n");
        */
        
        strncpy(opts.label, argv[2], strlen(argv[2]));
        strncpy(opts.protocol, argv[3], strlen(argv[3]));
        inet_pton(AF_INET, argv[1], &(opts.selfaddr));

        // start the sniffing loop
        std::cout<<"starting loop"<<std::endl;
        tCaptureDescriptor->runLoop(-1, my_callback, (u_char*)&opts);
        
    } 
    catch(const std::runtime_error & eProblem)
    {
        std::cout<<"Problem occurred: "
                 <<eProblem.what()<<std::endl;
        rReturnValue = 1;
    }

    return rReturnValue;
}
