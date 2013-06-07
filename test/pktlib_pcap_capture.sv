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
// Sample test to load pcap file and use pktlib to unpack it
// Run Command : scripts/pktlib_pcap_run <test_name>
//
// ----------------------------------------------------------------------


program my_test (); // {

  // include files
  `include "pktlib_class.sv"
  `include "../hdr_db/include/pcap/pcap_dpi.sv"

  // local defines
  int phandle, pkt_len;
  pktlib_class p;
  bit [7:0]    pkt [2000];
  bit [7:0]    p_pkt [];
  bit [63:0]   sm_time;
  int          i = 0;

  initial
  begin // {
    // register pcap handle
    pv_register ();

    // open pcap handle for reading
    pv_open (phandle, "pcap_log/sample-capture.pcap", 1);

    // get first pkt from phandle
    pv_get_pkt (phandle, pkt_len, pkt, sm_time);
    while (pkt_len != 0)
    begin // {
	// new pktlib for unpack
        p = new();
        p_pkt = new [pkt_len] (pkt);

        // unpack 
        p.unpack_hdr (p_pkt, SMART_UNPACK);

        // display hdr and pkt content
        $display("%0t : INFO    : TEST      : Unpack Pkt %0d", sm_time, i+1);
        p.display_hdr_pkt (p_pkt);
        i++;

        // get all pkt from phandle
        pv_get_pkt (phandle, pkt_len, pkt, sm_time);
    end // }
    // end simulation
    $finish ();
  end // }

endprogram : my_test // }

