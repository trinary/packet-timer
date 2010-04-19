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
#include<pcapp/timer/timeval.h>

// api includes

// tp includes

// std includes

// use own class's namespace
using namespace pcapp::timer;
using namespace pcapp;

//#############################################################################
/***************************** public interface ******************************/
//#############################################################################



//#############################################################################
Timeval::Timeval()
    :
    timeval()
{
    tv_sec = 0;
    tv_usec = 0;
}

//#############################################################################
Timeval::Timeval(const timeval & aTimeval)
    :
    timeval(aTimeval)
{
}

//#############################################################################
void
Timeval::clear()
{
    tv_sec = 0;
    tv_usec = 0;
}

//#############################################################################
std::string
Timeval::format()
{
    char timestr[64];
    snprintf(timestr,63,"%ld.%.6ld",tv_sec,(long)tv_usec);
    return std::string(timestr);
}

//#############################################################################
bool
Timeval::isSet()
{
    bool rSet = false;

    if(tv_sec != 0 || tv_usec != 0)
    {
        rSet = true;
    }

    return rSet;
}

//#############################################################################
Timeval
Timeval::operator-(const Timeval & aTime) const
{
    // since this operation modifies both the operand and operator we need
    // to copy them to be safe
    Timeval tOperator(aTime);
    Timeval rResult(*this);
    
    if (rResult.tv_usec < tOperator.tv_usec)
    {
        int nsec = (tOperator.tv_usec - rResult.tv_usec) / 1000000 + 1;
        tOperator.tv_usec -= 1000000 * nsec;
        tOperator.tv_sec += nsec;
    }
    if (rResult.tv_usec - tOperator.tv_usec > 1000000)
    {
        int nsec = (tOperator.tv_usec - rResult.tv_usec) / 1000000;
        tOperator.tv_usec += 1000000 * nsec;
        tOperator.tv_sec -= nsec;
    }
    
    // Compute the time remaining to wait.  tv_usec is certainly positive.
    rResult.tv_sec -= tOperator.tv_sec;
    rResult.tv_usec -= tOperator.tv_usec;

    return rResult;
}

//#############################################################################
/**************************** protected interface ****************************/
//#############################################################################

//#############################################################################
/***************************** private interface *****************************/
//#############################################################################

