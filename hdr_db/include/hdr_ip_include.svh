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
//  L3/Protocol/Nxt Header defines/tasks/macros
// ----------------------------------------------------------------------

// ~~~~~~~~~~ Nxt_hdr/protocol defines ~~~~~~~~~~
`define IPV4_HDR_PROT       8'h04
`define IPV6_HDR_PROT       8'h29
`define IPSEC_HDR_PROT      8'h50
`define TCP_HDR_PROT        8'h06
`define UDP_HDR_PROT        8'h11
`define GRE_HDR_PROT        8'h2F
`define PTIP_HDR_PROT       8'hFF

// ~~~~~~~~~~ Nxt_hdr/protocol fields ~~~~~~~~~~
  bit [7:0]   ipv4_prot     = `IPV4_HDR_PROT;
  bit [7:0]   ipv6_prot     = `IPV6_HDR_PROT;
  bit [7:0]   ipsec_prot    = `IPSEC_HDR_PROT;
  bit [7:0]   tcp_prot      = `TCP_HDR_PROT;
  bit [7:0]   udp_prot      = `UDP_HDR_PROT;
  bit [7:0]   gre_prot      = `GRE_HDR_PROT;
  bit [7:0]   ptip_prot     = `PTIP_HDR_PROT;

// ~~~~~~~~~~ define to copy Nxt_hdr/protocol fields  ~~~~~~~~~~
`define HDR_IP_INCLUDE_CPY\
    this.ipv4_prot     = cpy_cls.ipv4_prot;\
    this.ipv6_prot     = cpy_cls.ipv6_prot;\
    this.ipsec_prot    = cpy_cls.ipsec_prot;\
    this.tcp_prot      = cpy_cls.tcp_prot;\
    this.udp_prot      = cpy_cls.udp_prot;\
    this.gre_prot      = cpy_cls.gre_prot;\
    this.ptip_prot     = cpy_cls.ptip_prot

// ~~~~~~~~~~ Constraints Macro for Next Protocol ~~~~~~~~~~
`define LEGAL_PROT_TYPE_CONSTRAINTS \
        (nxt_hdr.hid == IPV4_HID)  ->  (protocol == ipv4_prot)  ;\
        (nxt_hdr.hid == IPV6_HID)  ->  (protocol == ipv6_prot)  ;\
        (nxt_hdr.hid == IPSEC_HID) ->  (protocol == ipsec_prot) ;\
        (nxt_hdr.hid == TCP_HID)   ->  (protocol == tcp_prot)   ;\
        (nxt_hdr.hid == UDP_HID)   ->  (protocol == udp_prot)   ;\
        (nxt_hdr.hid == GRE_HID)   ->  (protocol == gre_prot)   ;\
        (nxt_hdr.hid == PTIP_HID)  ->  (protocol == ptip_prot)  ;\
        (nxt_hdr.hid == DATA_HID)  -> ((protocol != ipv4_prot)  &\
                                       (protocol != ipv6_prot)  &\
                                       (protocol != udp_prot)   &\
                                       (protocol != gre_prot)   &\
                                       (protocol != ptip_prot))



// ~~~~~~~~~~ Function to get the name of protocol ~~~~~~~~~~
  function string get_protocol_name(bit [7:0] protocol); // {
     case (protocol) // {
         ipv4_prot     : get_protocol_name = "IPV4";
         ipv6_prot     : get_protocol_name = "IPV6";
         ipsec_prot    : get_protocol_name = "IPSEC";
         tcp_prot      : get_protocol_name = "TCP";
         udp_prot      : get_protocol_name = "UDP";
         gre_prot      : get_protocol_name = "GRE";
         ptip_prot     : get_protocol_name = "PTIP";
         default       : get_protocol_name = "UNKNOWN";
     endcase // }
  endfunction : get_protocol_name // }

// ~~~~~~~~~~ Function to get the protocol from hid ~~~~~~~~~~
  function bit [7:0] get_prot(int hid); // {
     case (hid) // {
        IPV4_HID    : get_prot = ipv4_prot;
        IPV6_HID    : get_prot = ipv6_prot;
        IPSEC_HID   : get_prot = ipsec_prot;
        TCP_HID     : get_prot = tcp_prot;
        UDP_HID     : get_prot = udp_prot;
        GRE_HID     : get_prot = gre_prot;
        PTIP_HID    : get_prot = ptip_prot;
        default     : get_prot = $urandom ();
     endcase // }
  endfunction : get_prot // }

// ~~~~~~~~~~ Function to get the hid from protocol ~~~~~~~~~~
  function int get_hid_from_protocol(bit [7:0] protocol); // {
     case (protocol) // {
         ipv4_prot     : get_hid_from_protocol = IPV4_HID;
         ipv6_prot     : get_hid_from_protocol = IPV6_HID;
         ipsec_prot    : get_hid_from_protocol = IPSEC_HID;
         tcp_prot      : get_hid_from_protocol = TCP_HID;
         udp_prot      : get_hid_from_protocol = UDP_HID;
         gre_prot      : get_hid_from_protocol = GRE_HID;
         ptip_prot     : get_hid_from_protocol = PTIP_HID;
         default       : get_hid_from_protocol = DATA_HID;
     endcase // }
  endfunction : get_hid_from_protocol // }

// ~~~~~~~~~~ EOF ~~~~~~~~~~
