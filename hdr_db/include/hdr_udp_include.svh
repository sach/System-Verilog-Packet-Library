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
//  UDP defines/tasks/macros
// ----------------------------------------------------------------------

// ~~~~~~~~~~ UDP Destination port defines ~~~~~~~~~~
`define PTP_UDP_DST_PRT    16'h13F
`define NTP_UDP_DST_PRT    16'h07b
`define LISP_UDP_DST_PRT   16'd4341
`define OTV_UDP_DST_PRT    16'd9029
`define VXLAN_UDP_DST_PRT  16'd8472

// ~~~~~~~~~~ UDP destination ports fields ~~~~~~~~~~
  bit [15:0]  ptp_udp_dst_prt   = `PTP_UDP_DST_PRT;
  bit [15:0]  ntp_udp_dst_prt   = `NTP_UDP_DST_PRT;
  bit [15:0]  lisp_udp_dst_prt  = `LISP_UDP_DST_PRT;
  bit [15:0]  otv_udp_dst_prt   = `OTV_UDP_DST_PRT;
  bit [15:0]  vxlan_udp_dst_prt = `VXLAN_UDP_DST_PRT;

// ~~~~~~~~~~ define to copy UDP Type fields ~~~~~~~~~~
`define HDR_UDP_INCLUDE_CPY\
    this.ptp_udp_dst_prt   = cpy_cls.ptp_udp_dst_prt;\
    this.ntp_udp_dst_prt   = cpy_cls.ntp_udp_dst_prt;\
    this.lisp_udp_dst_prt  = cpy_cls.lisp_udp_dst_prt;\
    this.otv_udp_dst_prt   = cpy_cls.otv_udp_dst_prt;\
    this.vxlan_udp_dst_prt = cpy_cls.vxlan_udp_dst_prt

// ~~~~~~~~~~ Constraints Macro for UDP destination ~~~~~~~~~~
`define LEGAL_UDP_DST_PRT_CONSTRAINTS \
        (nxt_hdr.hid == PTP_HID)  -> (dst_prt == ptp_udp_dst_prt)   ;\
        (nxt_hdr.hid == NTP_HID)  -> (dst_prt == ntp_udp_dst_prt)   ;\
        (nxt_hdr.hid == LISP_HID) -> (dst_prt == lisp_udp_dst_prt)  ;\
        (nxt_hdr.hid == OTV_HID)  -> (dst_prt == otv_udp_dst_prt)   ;\
        (nxt_hdr.hid == VXLAN_HID)-> (dst_prt == vxlan_udp_dst_prt) ;\
        (nxt_hdr.hid == DATA_HID) -> (dst_prt != ptp_udp_dst_prt)   &\
                                     (dst_prt != ntp_udp_dst_prt)   &\
                                     (dst_prt != lisp_udp_dst_prt)  &\
                                     (dst_prt != otv_udp_dst_prt)   &\
                                     (dst_prt != vxlan_udp_dst_prt)

// ~~~~~~~~~~ Function to get the name of Destination Port ~~~~~~~~~~
  function string get_udp_dst_prt_name(bit [15:0] dst_prt); // {
     case (dst_prt) // {
         ptp_udp_dst_prt  : get_udp_dst_prt_name = "PTP";
         ntp_udp_dst_prt  : get_udp_dst_prt_name = "NTP";
         lisp_udp_dst_prt : get_udp_dst_prt_name = "LISP";
         otv_udp_dst_prt  : get_udp_dst_prt_name = "OTV";
         vxlan_udp_dst_prt: get_udp_dst_prt_name = "VXLAN";
         default          : get_udp_dst_prt_name = "UNKNOWN";
     endcase // }
  endfunction : get_udp_dst_prt_name // }

// ~~~~~~~~~~ Function to get the destination port ~~~~~~~~~~
  // function to get UDP dst_port based on hid
  function bit [15:0] get_udp_dst_prt(int hid); // {
     case (hid) // {
        PTP_HID           : get_udp_dst_prt = ptp_udp_dst_prt;
        NTP_HID           : get_udp_dst_prt = ntp_udp_dst_prt;
        LISP_HID          : get_udp_dst_prt = lisp_udp_dst_prt;
        OTV_HID           : get_udp_dst_prt = otv_udp_dst_prt;
        VXLAN_HID         : get_udp_dst_prt = vxlan_udp_dst_prt;
        default           : get_udp_dst_prt = $urandom ();
     endcase // }
  endfunction : get_udp_dst_prt // }

// ~~~~~~~~~~ Function to get HID from the destination port ~~~~~~~~~~
  function int get_hid_from_udp_dst_prt(bit [15:0] dst_prt); // {
     case (dst_prt) // {
         ptp_udp_dst_prt  : get_hid_from_udp_dst_prt = PTP_HID;
         ntp_udp_dst_prt  : get_hid_from_udp_dst_prt = NTP_HID;
         lisp_udp_dst_prt : get_hid_from_udp_dst_prt = LISP_HID;
         otv_udp_dst_prt  : get_hid_from_udp_dst_prt = OTV_HID;
         vxlan_udp_dst_prt: get_hid_from_udp_dst_prt = VXLAN_HID;
         default          : get_hid_from_udp_dst_prt = DATA_HID;
     endcase // }
  endfunction : get_hid_from_udp_dst_prt // }

// ~~~~~~~~~~ EOF ~~~~~~~~~~
