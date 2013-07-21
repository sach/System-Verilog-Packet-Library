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
// This test verifes pack and unpack for ROCE hdr 
// ----------------------------------------------------------------------

`define NUM_PKTS 1000

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
        p.cfg_hdr ('{p.eth[0], p.roce[0], p.grh[0], p.bth[0], p.data[0]});
        
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

    end // }
    // end simulation
    $finish ();
  end // }

endprogram : my_test // }

