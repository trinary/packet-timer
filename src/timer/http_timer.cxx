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
#include<pcapp/timer/http_timer.h>

// api includes

// tp includes
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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
HTTPTimer::HTTPTimer(const std::string & aLabel)
:
    _Label(aLabel),
    _StartTime(),
    _SendTime(),
    _AckTime(),
    _RecvTime(),
    _EndTime()
{
}

//#############################################################################
void 
HTTPTimer::handleData(Options *opts,
                      const pcap_pkthdr* pkthdr,
                      const u_char* packet)
{
    const ether_header *ethh;
    const ip *iph;
    const tcphdr *tcph;
    const timeval ts = pkthdr->ts;
    int size_ip;
    int size_tcp;
    int size_payload;
    const char *payload;
    
    
    ethh=(ether_header*)(packet);
    iph=(ip*)(packet+14); /* sizeof(ether_header) */
    size_ip = IP_HL(iph)*4;
    tcph = (tcphdr*)(packet+SIZE_ETHER+size_ip);
    size_tcp= tcph->doff*4;
    
    payload=(const char *)(packet + SIZE_ETHER + size_ip + size_tcp);
    size_payload = ntohs(iph->ip_len) - (size_ip + size_tcp);
    

    if(!_StartTime.isSet())
    {
        if((tcph->syn) &&
           !(tcph->ack) && 
           (size_payload == 0) &&
           (opts->selfaddr.s_addr != iph->ip_dst.s_addr))
        {
            _StartTime = ts;
        }
    }
    else if(!_AckTime.isSet())
    {
        if((size_payload == 0) && 
            (tcph->ack) &&
           !(tcph->syn) &&
           (opts->selfaddr.s_addr != iph->ip_dst.s_addr))
        {
            _AckTime = ts;
        }
    }
    else if(!_SendTime.isSet())
    {
        if((strncmp(payload,"GET ",4) == 0))
        {
            _Label = "GET";
            _SendTime = ts;
        }
        else if((strncmp(payload,"PUT ",4) == 0))
        {
            _Label = "PUT";
            _SendTime = ts;
        }
        else if((strncmp(payload,"POST ",5) == 0))
        {
            _Label = "POST";
            _SendTime = ts;
        }
    }
    else if(!_RecvTime.isSet())
    {
        if ((strncmp(payload,"HTTP/1.",7) == 0) &&
            (opts->selfaddr.s_addr == iph->ip_dst.s_addr))
        {
            _RecvTime = ts;
        }
    }
    else if(tcph->fin)
    {
        _EndTime = ts;
        printTimings(*opts);

        _Label="Other";
        _StartTime.clear();
        _SendTime.clear();
        _AckTime.clear();
        _RecvTime.clear();
        _EndTime.clear();
    } 
}

//#############################################################################
void
HTTPTimer::printTimings(const Options & aOptions) const
{
    Timeval tmp;

    tmp = _AckTime - _StartTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|"<<_Label
             <<"|Time to First ACK\t"<<tmp.format()<<std::endl;
    
    tmp = _SendTime - _AckTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|"<<_Label
             <<"|Ack to First Send\t"<<tmp.format()<<std::endl;;
    
    tmp = _RecvTime - _SendTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|"<<_Label
             <<"|Send to First Recv\t"<<tmp.format()<<std::endl;

    tmp = _EndTime - _RecvTime;
    std::cout<<"Net|Protocol|"<<aOptions.protocol
             <<"|Time|"<<_Label
             <<"|Recv to Connection Close\t"<<tmp.format()<<std::endl;
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

