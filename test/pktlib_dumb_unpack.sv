/*
Copyright (c) 2011, Sachin Gandhi
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// ----------------------------------------------------------------------
// Sample test for Pktlib. pack and upack hdrs
//
// ----------------------------------------------------------------------

`define NUM_PKTS 14

program my_test (); // {

  // include files
  `include "pktlib_class.sv"

  // local defines
  pktlib_class p;
  bit [7:0]    pkt [];
  int          i;

  initial
  begin // {
    for (i = 0; i < `NUM_PKTS; i++)
    begin // {
        // new pktlib
        p = new();
        
        // configure different hdrs for this packet
        case (i) // {
            0 : p.cfg_hdr ('{p.pth[0], p.eth[0],  p.data[0]});
            1 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.ipv4[0],  p.udp[0],  p.data[0]});
            2 : p.cfg_hdr ('{p.eth[0], p.ptl2[0], p.dot1q[0], p.ipv6[0], p.udp[0],  p.data[0]});
            3 : p.cfg_hdr ('{p.eth[0], p.snap[0], p.ipv4[0], p.ptip[0],  p.udp[0],  p.data[0]});
            4 : p.cfg_hdr ('{p.eth[0], p.mpls[0], p.ipv4[0],  p.udp[0],  p.data[0]});
            5 : p.cfg_hdr ('{p.eth[0], p.alt1q[0],p.mmpls[0], p.ipv6[0], p.udp[0],  p.data[0]});
            6 : p.cfg_hdr ('{p.pth[0], p.eth[0],  p.ptl2[0],  p.ptip[0], p.data[0]});
            7 : p.cfg_hdr ('{p.eth[0], p.ipv4[0], p.gre[0],   p.ipv4[1], p.udp[0], p.ptp[0], p.data[0]});
            8 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.mpls[0],  p.ipv4[0], p.udp[0],  p.data[0]});
            9 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.ptp[0],   p.data[0]});
            10: p.cfg_hdr ('{p.eth[0], p.ptp[0],  p.data[0]});
            11: p.cfg_hdr ('{p.eth[0], p.snap[0], p.ipv6[0],  p.udp[0], p.ptp[0], p.data[0]});
            12: p.cfg_hdr ('{p.eth[0], p.ipv4[0], p.udp[0],   p.ptp[0], p.data[0]});
            13: p.cfg_hdr ('{p.eth[0], p.ipv6[0], p.tcp[0],   p.data[0]});
        endcase // }
        
        // set max/min packet length
        p.toh.max_plen = 200;
        p.toh.min_plen = 32;
        if (p.dot1q[0].psnt)
            p.toh.pad_len  = 13;
        else
            p.toh.pad_len = 0;
        if  (~p.dot1q[0].psnt & p.ptp[0].psnt) 
            p.ptp[0].ptp_ver = 1'b0;
        else if  (p.ipv6[0].psnt & p.ptp[0].psnt) 
            p.ptp[0].ptp_ver = 1'b0;
        else
            p.ptp[0].ptp_ver = 1'b1;

        // randomize pktlib
        p.randomize with  
        {
          pth[0].psnt  -> pth[0].pt_len  == 5;
          ptl2[0].psnt -> ptl2[0].pt_len == 32;
          ptip[0].psnt -> ptip[0].pt_len == 15;
        };
        
        // pack all the hdrs to pkt
        p.pack_hdr (pkt);
        
        // display hdr content
        $display("%0t : INFO    : TEST      : Pack Pkt %0d", $time, i);
        p.display_cfg_hdr;
        p.display_hdr ();

        // display pkt content
        p.display_pkt (pkt);
         
        // new pktlib for unpack
        p = new();
        
        // configure different hdrs for this packet
        case (i) // {
            0 : p.cfg_hdr ('{p.pth[0], p.eth[0],  p.data[0]});
            1 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.ipv4[0],  p.udp[0],  p.data[0]});
            2 : p.cfg_hdr ('{p.eth[0], p.ptl2[0], p.dot1q[0], p.ipv6[0], p.udp[0],  p.data[0]});
            3 : p.cfg_hdr ('{p.eth[0], p.snap[0], p.ipv4[0], p.ptip[0],  p.udp[0],  p.data[0]});
            4 : p.cfg_hdr ('{p.eth[0], p.mpls[0], p.ipv4[0],  p.udp[0],  p.data[0]});
            5 : p.cfg_hdr ('{p.eth[0], p.alt1q[0],p.mmpls[0], p.ipv6[0], p.udp[0],  p.data[0]});
            6 : p.cfg_hdr ('{p.pth[0], p.eth[0],  p.ptl2[0],  p.ptip[0], p.data[0]});
            7 : p.cfg_hdr ('{p.eth[0], p.ipv4[0], p.gre[0],   p.ipv4[1], p.udp[0], p.ptp[0], p.data[0]});
            8 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.mpls[0],  p.ipv4[0], p.udp[0],  p.data[0]});
            9 : p.cfg_hdr ('{p.eth[0], p.dot1q[0],p.ptp[0],   p.data[0]});
            10: p.cfg_hdr ('{p.eth[0], p.ptp[0],  p.data[0]});
            11: p.cfg_hdr ('{p.eth[0], p.snap[0], p.ipv6[0],  p.udp[0], p.ptp[0], p.data[0]});
            12: p.cfg_hdr ('{p.eth[0], p.ipv4[0], p.udp[0],   p.ptp[0], p.data[0]});
            13: p.cfg_hdr ('{p.eth[0], p.ipv6[0], p.tcp[0],   p.data[0]});
        endcase // }
        
        // set few parameters 
        p.toh.max_plen    = 200;
        if (p.dot1q[0].psnt)
            p.toh.pad_len  = 13;
        else
            p.toh.pad_len = 0;

        if (p.pth[0].psnt ) p.pth[0].pt_len  = 5;
        if (p.ptl2[0].psnt) p.ptl2[0].pt_len = 32;
        if (p.ptip[0].psnt) p.ptip[0].pt_len = 15;

        // unpack 
        p.unpack_hdr (pkt);

        // display hdr content
        $display("%0t : INFO    : TEST      : Unpack Pkt %0d", $time, i);
        p.display_cfg_hdr;
        p.display_hdr ();

        // display pkt content
        p.display_pkt (pkt);
    end // }
    // end simulation
    $finish ();
  end // }

endprogram : my_test // }

