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
// This test 
// 1. pack_hdr    - Configures (cfg_hdr) 10 different types of headers
//                  and pack into array of pkt.
// 2. unpack_hdr  - Smartly Unpacks the pkt array into headers
// 3. copy_hdr    - Copies pktlib of each pkt to diffent pktlib
// 4. compare_pkt - From two arrays of pkts, it unpacks them and compares them.
//                  (Compare functionality doesn't work when we have 
//                   pth, ptl2, ptip in cfg_hdr)
//
// ----------------------------------------------------------------------

`define NUM_PKTS 10

program my_test (); // {

  // include files
  `include "pktlib_class.sv"

  // local defines
  pktlib_class p, p1;
  bit [7:0]    p_pkt [], u_pkt []; 
  int          i, err;

  initial
  begin // {
    for (i = 0; i < `NUM_PKTS; i++)
    begin // {
        // new pktlib
        p = new();
        
        // configure different hdrs for this packet
        case (i%10) // {
            0 : p.cfg_hdr ({p.eth[0], p.dot1q[0], p.dot1q[1], p.data[0]});
            1 : p.cfg_hdr ({p.eth[0], p.ipv4[0],  p.gre[0],   p.mpls[0], p.ipv6[0], p.tcp[0], p.data[0]});
            2 : p.cfg_hdr ({p.eth[0], p.dot1q[0], p.dot1q[1], p.ipv4[0], p.udp[0],  p.data[0]});
            3 : p.cfg_hdr ({p.eth[0], p.dot1q[0], p.ipv6[0],  p.gre[0],  p.data[0]});
            4 : p.cfg_hdr ({p.eth[0], p.itag[0],  p.eth[1],   p.ipv4[0], p.tcp[0],   p.data[0]});
            5 : p.cfg_hdr ({p.eth[0], p.mpls[0],  p.ipv4[0],  p.udp[0],  p.data[0]});
            6 : p.cfg_hdr ({p.eth[0], p.alt1q[0], p.mmpls[0], p.ipv6[0], p.udp[0],  p.data[0]});
            7 : p.cfg_hdr ({p.eth[0], p.mmpls[0], p.eth[1],   p.data[0]});
            8 : p.cfg_hdr ({p.eth[0], p.ipv4[0],  p.gre[0],   p.eth[1],  p.itag[0], p.eth[2], p.data[0]});
            9 : p.cfg_hdr ({p.eth[0], p.dot1q[0], p.mpls[0],  p.ipv4[0], p.udp[0],  p.data[0]});
        endcase // }
        
        // set max/min packet length
        p.toh.max_plen = 300;
        p.toh.min_plen = 32;

        // randomize pktlib
        p.randomize with  
        {
          data[0].data_len < 20;
        };
        
        // pack all the hdrs to pkt
        p.pack_hdr (p_pkt);
        
        // display hdr and pkt content
        $display("%0t : INFO    : TEST      : Pack Pkt %0d", $time, i+1);
        p.display_hdr_pkt (p_pkt);

	// new pktlib for unpack
        p = new();
        
        // unpack 
        p.unpack_hdr (p_pkt, SMART_UNPACK);

        // display hdr and pkt content
        $display("%0t : INFO    : TEST      : Unpack Pkt %0d", $time, i+1);
        p.display_hdr_pkt (p_pkt);

        // new pktlib for copy
        p1 = new ();

        // copy p to p1
        p1.cpy_hdr (p);

        // display hdr and pkt content
        $display("%0t : INFO    : TEST      : Copy Pkt %0d", $time, i+1);
        p1.display_hdr_pkt (p1.pkt);

	// new pktlib for compare
        p = new();
        u_pkt = new [p_pkt.size] (p_pkt);

        // corrupt few pkt to make sure Compare ctaches it
        if (i == 9)
        begin // {
            u_pkt[13] = $random;
        end // 
        if (i == 3)
        begin // {
            u_pkt[22] = $random;
        end // 

        $display("%0t : INFO    : TEST      : Compare Pkt %0d", $time, i+1);
        p.compare_pkt (p_pkt, u_pkt, err);
    end // }
    // end simulation
    $finish ();
  end // }

endprogram : my_test // }

