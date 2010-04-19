/*
 * Copyright (C) 2000-2004 Absolute Performance, Inc.
 * All Rights Reserved
 *
 * THIS IS PROPRIETARY SOFTWARE DEVELOPED FOR THE SYSSHEP PROJECT AT
 * ABSOLUTE PERFORMANCE, INC.; IT MAY NOT BE DISCLOSED TO THIRD PARTIES,
 * COPIED OR DUPLICATED IN ANY FORM, IN WHOLE OR IN PART, WITHOUT THE PRIOR
 * WRITTEN PERMISSION OF ABSOLUTE PERFORMANCE, INC.
 *
 * FURTHERMORE, THIS SOFTWARE IS DISTRIBUTED AS IS, AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NOT EVENT SHALL ABSOLUTE PERFORMANCE BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE AND OTHERWISE) ARISING IN ANY
 * WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.  RECEIVING PARTY MAY NOT REVERSE ENGINEER, DECOMPILE OR
 * DISASSEMBLE ANY SOFTWARE DISCLOSED TO RECEIVING PARTY.
 *
 */


// class header
#include<pcapp/timer/dns_timer.h>

// api includes
#include <pcapp/dnsreq.h>

// tp includes
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// std includes
#include<cstring>
#include<iostream>

// use own class's namespace
using namespace pcapp::timer;
using namespace pcapp;

//#############################################################################
/***************************** public interface ******************************/
//#############################################################################

#ifndef IP_HL
  #define IP_HL(ip)   (((ip)->ip_hl) & 0x0f)
  #define TH_OFF(th)  ((th)->th_x2)
  #define SIZE_ETHER  14
#endif

//#############################################################################
DNSTimer::DNSTimer(const std::string & aLabel)
    :
    _Label(aLabel),
    _ID(0),
    _StartTime(),
    _TimeOfAuthentication()
{
}

//#############################################################################
void 
DNSTimer::handleData(Options *opts,
                   const pcap_pkthdr* pkthdr,
                   const u_char* packet)
{
    const ether_header *ethh;
    const ip *iph;
    const udphdr *udph;
    Timeval ts(pkthdr->ts);
    const dns_header *dnsh;
    int size_ip;
    int size_udp;
    int size_payload;
    const char *payload;
    const char *req_dns_str;
    char req_str[1024] = "";
    
    ethh=(ether_header*)(packet);
    iph=(ip*)(packet+14); /* sizeof(ether_header) */
    size_ip = IP_HL(iph)*4;
    size_udp = 8;
    
    udph=(udphdr*)(packet+SIZE_ETHER+size_ip);
    
    payload=(const char *)(packet + SIZE_ETHER + size_ip + size_udp);
    size_payload = ntohs(iph->ip_len) - (size_ip + size_udp);
    
    dnsh = (dns_header*)(payload);

    if(!_StartTime.isSet())
    {
        if (dnsh->qr == 0)
        {
            req_dns_str=payload+12;
            dns_q_to_str(req_dns_str,req_str);
            if (strcmp(req_str,opts->label)==0)
            {
                _Label = opts->label;
                _ID = dnsh->id;
                _StartTime = ts;
            }
        }
    }
    else if ((dnsh->qr == 1) && (dnsh->ancount > 0))
    {
        if ((dnsh->id == _ID))
        {
            _TimeOfAuthentication = ts;
            printTimings(*opts);
            
            _Label = "";
            _ID = 0;
            _StartTime.clear();
            _TimeOfAuthentication.clear();
        }
    }
    
}

//#############################################################################
void
DNSTimer::printTimings(const Options & aOptions) const
{
    Timeval tmp;

    tmp = _TimeOfAuthentication - _StartTime;
    std::string tTimeString = tmp.format();

    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|DNS|Total Time\t"<<tmp.format()<<std::endl;
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################


//#############################################################################
int
DNSTimer::dns_q_to_str(const char* dns,char* str)
{
  char x=dns[0];
  const char *pt=dns;
  char size=0;

  while (x != 0)
  {
    if(size>0)
    {
      strcat(str,".");
      size++;
    }
    strncpy(str+size,pt+1,x);
    size+=x;
    pt += x+1;
    x=pt[0];
  }
  return 1;
}
