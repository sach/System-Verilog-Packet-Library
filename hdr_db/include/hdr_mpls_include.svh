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
//  MPLS defines/tasks/function
// ----------------------------------------------------------------------

`define MAX_MPLS_LBL          4

// ~~~~~~~~~~  MPLS Label defines ~~~~~~~~~~
`define MPLS_HDR_IPV4_NULL    20'h0
`define MPLS_HDR_ROUTER_ALERT 20'h1
`define MPLS_HDR_IPV6_NULL    20'h2
`define MPLS_HDR_ETH_NULL     20'h3
`define MPLS_HDR_IMPL_NULL    20'h4

// ~~~~~~~~~~ MPLS Label fields ~~~~~~~~~~
  bit [15:0]  ipv4_null_lbl    = `MPLS_HDR_IPV4_NULL;
  bit [15:0]  router_alert_lbl = `MPLS_HDR_ROUTER_ALERT;
  bit [15:0]  ipv6_null_lbl    = `MPLS_HDR_IPV6_NULL;
  bit [15:0]  eth_null_lbl     = `MPLS_HDR_ETH_NULL;
  bit [15:0]  impl_null_lbl    = `MPLS_HDR_IMPL_NULL;

// ~~~~~~~~~~ define to copy MPLS Label fields ~~~~~~~~~~
`define HDR_MPLS_INCLUDE_CPY\
    this.ipv4_null_lbl    = cpy_cls.ipv4_null_lbl;\
    this.router_alert_lbl = cpy_cls.router_alert_lbl;\
    this.ipv6_null_lbl    = cpy_cls.ipv6_null_lbl;\
    this.eth_null_lbl     = cpy_cls.eth_null_lbl;\
    this.impl_null_lbl    = cpy_cls.impl_null_lbl

// ~~~~~~~~~~ Function to get the name of mpls lbl ~~~~~~~~~~
  function string get_mpls_lbl_name(bit [19:0] lbl); // {
     case (lbl) // {
         ipv4_null_lbl    : get_mpls_lbl_name = "IPV4 Explicit Null";
         router_alert_lbl : get_mpls_lbl_name = "Router Alert";
         ipv6_null_lbl    : get_mpls_lbl_name = "IPV6 Explicit Null";
         eth_null_lbl     : get_mpls_lbl_name = "ETH Explicit Null";
         impl_null_lbl    : get_mpls_lbl_name = "Implicit Null";
         default          : get_mpls_lbl_name = "UNKNOWN";
     endcase // }
  endfunction : get_mpls_lbl_name // }

// ~~~~~~~~~~ EOF ~~~~~~~~~~
