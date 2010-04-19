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
#include<pcapp/network_device.h>

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
NetworkDevice::NetworkDevice()
:
    _PCAPNetworkDevice(NULL)
{
    char tErrorBuffer[PCAP_ERRBUF_SIZE];
    tErrorBuffer[0] = 0;
    
    _PCAPNetworkDevice = pcap_lookupdev(tErrorBuffer);
    if(_PCAPNetworkDevice == NULL)
    {
        throw std::runtime_error("pcapp::NetworkDevice constructur failed: " + 
                                 std::string(tErrorBuffer));
    }
}

//#############################################################################
SharedCaptureDescriptorTS
NetworkDevice::getCaptureDescriptor(int aBufferSize,
                                    bool aPromiscuous,
                                    int aReadTimeoutInMilliseconds,
                                    bool aSuperCareful)
{
    SharedCaptureDescriptorTS rCaptureDescriptor;
    rCaptureDescriptor.reset(new CaptureDescriptor(_PCAPNetworkDevice,
                                                   aBufferSize,
                                                   aPromiscuous,
                                                   aReadTimeoutInMilliseconds,
                                                   aSuperCareful));
    return rCaptureDescriptor;
}

//#############################################################################
std::string
NetworkDevice::getName() const
{
    std::string rName("");
    if(_PCAPNetworkDevice != NULL)
    {
        rName = _PCAPNetworkDevice;
    }
    return rName;
}

//#############################################################################
void
NetworkDevice::lookUpNetwork(bpf_u_int32 * aLocalNetwork,
                             bpf_u_int32 * aSubnetMask)
{
    char tErrorBuffer[PCAP_ERRBUF_SIZE];
    tErrorBuffer[0] = 0;

    if(pcap_lookupnet(_PCAPNetworkDevice,
                      aLocalNetwork,
                      aSubnetMask,
                      tErrorBuffer) == -1)
    {
        throw std::runtime_error("pcap::NetworkDevice::lookUpNetwork failed.  "
                                 "Could not look up network from pcap "
                                 "interface.  Error: " + 
                                 std::string(tErrorBuffer));
    }
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

