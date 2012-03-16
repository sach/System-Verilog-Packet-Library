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
//  TCP defines/tasks/macros
// ----------------------------------------------------------------------

// ~~~~~~~~~~ Destination port defines ~~~~~~~~~~
`define STT_TCP_DST_PRT    16'hFFF // Not defined yet

// ~~~~~~~~~~ TCP Type fields ~~~~~~~~~~
  bit [15:0]  stt_tcp_dst_prt   = `STT_TCP_DST_PRT;

// ~~~~~~~~~~ define to copy TCP Type fields ~~~~~~~~~~
`define HDR_TCP_INCLUDE_CPY\
    this.stt_tcp_dst_prt   = cpy_cls.stt_tcp_dst_prt

// ~~~~~~~~~~ Constraints Macro for ethertype ~~~~~~~~~~
`define LEGAL_TCP_DST_PRT_CONSTRAINTS \
        (nxt_hdr.hid == STT_HID)  -> (dst_prt == stt_tcp_dst_prt) ;\
        (nxt_hdr.hid == DATA_HID) -> (dst_prt != stt_tcp_dst_prt)

// ~~~~~~~~~~ Function to get the name of Destination Port ~~~~~~~~~~
  function string get_tcp_dst_prt_name(bit [15:0] dst_prt); // {
     case (dst_prt) // {
         stt_tcp_dst_prt  : get_tcp_dst_prt_name = "STT";
         default          : get_tcp_dst_prt_name = "UNKNOWN";
     endcase // }
  endfunction : get_tcp_dst_prt_name // }

// ~~~~~~~~~~ Function to get the destination port ~~~~~~~~~~
  // function to get TCP dst_port based on hid
  function bit [15:0] get_tcp_dst_prt(int hid); // {
     case (hid) // {
        STT_HID           : get_tcp_dst_prt = stt_tcp_dst_prt;
        default           : get_tcp_dst_prt = $urandom ();
     endcase // }
  endfunction : get_tcp_dst_prt // }

// ~~~~~~~~~~ Function to get HID from the destination port ~~~~~~~~~~
  function int get_hid_from_tcp_dst_prt(bit [15:0] dst_prt); // {
     case (dst_prt) // {
         stt_tcp_dst_prt  : get_hid_from_tcp_dst_prt = STT_HID;
         default          : get_hid_from_tcp_dst_prt = DATA_HID;
     endcase // }
  endfunction : get_hid_from_tcp_dst_prt // }


// ~~~~~~~~~~ EOF ~~~~~~~~~~
