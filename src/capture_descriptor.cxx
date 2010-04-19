/*
 * Copyright(C) 2000-2004 Absolute Performance, Inc.
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
#include<pcapp/capture_descriptor.h>

// api includes

// tp includes

// std includes

// system includes
#include<cstring>
#include<stdexcept>

using namespace pcapp;

//#############################################################################
/***************************** public interface ******************************/
//#############################################################################

//#############################################################################
CaptureDescriptor::CaptureDescriptor(const std::string & aNetworkingDevice,
                                     int aBuffersize,
                                     bool aPromiscuous,
                                     int aReadTimeoutInMilliseconds,
                                     bool aSuperCareful)
:
    _FilterCode(),
    _PCAPDescriptor(NULL)
{
    char tErrorBuffer[PCAP_ERRBUF_SIZE];
    tErrorBuffer[0] = 0;

    _PCAPDescriptor = pcap_open_live(aNetworkingDevice.c_str(),
                                     aBuffersize,
                                     aPromiscuous,
                                     aReadTimeoutInMilliseconds,
                                     tErrorBuffer);
    if(_PCAPDescriptor == NULL)
    {
        throw std::runtime_error("Could not get PCAP Descriptor from pcap "
                                 "interface.  Error: " + 
                                 std::string(tErrorBuffer));
    }
    else if(aSuperCareful && (strlen(tErrorBuffer) > 0))
    {
        throw std::runtime_error("PCAP Descriptor could not be obtained "
                                 "without one or more warnings: " + 
                                 std::string(tErrorBuffer));
    }
}

//#############################################################################
void
CaptureDescriptor::compileFilter(const std::string & aExpression,
                                 bpf_u_int32 aSubnetMask,
                                 bool aOptimized)
{
    // because we can't be certain that this c interface interprets *any* TRUE
    // value properly

    int tOptimization = 0;
    if(aOptimized)
    {
        tOptimization = 1;
    }

    if(pcap_compile(_PCAPDescriptor,
                    &_FilterCode,
                    aExpression.c_str(),
                    tOptimization,
                    aSubnetMask) == -1)
    {
        throw std::runtime_error("CaptureDescriptor::compileFilter failed: " +
                                 std::string(pcap_geterr(_PCAPDescriptor)));
    }
    
    setFilter();
}

//#############################################################################
void
CaptureDescriptor::runLoop(int aNumberOfTimes,
                           pcap_handler aCallback,
                           u_char *aDataToHandToCallback)
{
    pcap_loop(_PCAPDescriptor,
              aNumberOfTimes,
              aCallback,
              aDataToHandToCallback);
}

//#############################################################################
CaptureDescriptor::~CaptureDescriptor()
{
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

//#############################################################################
void
CaptureDescriptor::setFilter()
{
    if(pcap_setfilter(_PCAPDescriptor,
                      &_FilterCode) == -1)
    {
        throw std::runtime_error("CaptureDescriptor::setFilter failed: " +
                                 std::string(pcap_geterr(_PCAPDescriptor)));
    } 
}

