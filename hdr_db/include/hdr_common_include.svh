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
//  Common declaration/tasks/functions/macros for hdrs
// ----------------------------------------------------------------------

  // ~~~~~~~~~~ hdr_class variables decelarations ~~~~~~~~~~
  rand   bit [15:0]             total_hdr_len;       // hdr length from this.hdr to end of pkt
  rand   bit [15:0]             hdr_len;             // length of this.hdr
         int                    hid;                 // header Id
         int                    inst_no = 0;         // hdr instance number
         int                    cfg_id  = 0;         // cfg_id number
         string                 hdr_name;
         bit [7:0]              hdr [];              // each hdr data in array
         bit [`VEC_SZ-1:0]      pack_vec;            // packing vector
  rand   hdr_class              nxt_hdr;             // object handle to nxt hdr in list
  rand   hdr_class              prv_hdr;             // object handle to prv hdr in list
  rand   hdr_class              all_hdr [$];         // all the hdr of list;
         bit                    psnt         = 1'b0; // this hdr_class is psnt
  rand   int                    start_off;           // starting offset of hdr
         bit [TOTAL_HID-1:0]    unpack_en    = {TOTAL_HID{1'b1}};
         pktlib_main_class      plib;
         pktlib_crc_chksm_class crc_chksm    = new ();
         pktlib_array_class     harray       = new ();

// ~~~~~~~~~~ Constraints Macro for total_hdr_len ~~~~~~~~~~~~~~~
`define LEGAL_TOTAL_HDR_LEN_CONSTRAINTS \
        total_hdr_len == hdr_len + super.nxt_hdr.total_hdr_len;\
        start_off     == all_hdr[0].total_hdr_len - total_hdr_len

//  ~~~~~~~~ task to update hdr db ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  task update_hdr_db (int hid, int inst_num); // {
      plib.hdr_db[hid][inst_num] = this;
  endtask : update_hdr_db // }

//  ~~~~~~~~ task to update nxt_hdr info (used by unpack task) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  task update_nxt_hdr_info (ref   hdr_class my_hdr,
                            ref   hdr_class hdr_q [$],
                            input int       nxt_hid); // {
    my_hdr.nxt_hdr = plib.hdr_db[nxt_hid][plib.inst_db[nxt_hid]];
    plib.inst_db[nxt_hid]++;
    hdr_q.push_back (my_hdr.nxt_hdr);
`ifdef DEBUG_UPDATE_NXT_HDR_INFO
    if (my_hdr.nxt_hdr == null) 
      $display("%m: my_hdr %s, nxt_hid %0d, my_hdr.nxt_hdr NULL", my_hdr.hdr_name, nxt_hid);
    else
      $display("%m: my_hdr %s, nxt_hid %0d, my_hdr.nxt_hdr %s", my_hdr.hdr_name, nxt_hid, my_hdr.nxt_hdr.hdr_name);
`endif
       my_hdr.nxt_hdr.all_hdr = hdr_q;
       my_hdr.nxt_hdr.prv_hdr = my_hdr;
       my_hdr.nxt_hdr.psnt    = 1'b1;
       my_hdr.nxt_hdr.cfg_id  = hdr_q.size-1;
  endtask : update_nxt_hdr_info // }

// ~~~~~~~~~~ define to copy all the fields of include files ~~~~~~~~~~~~~
`define HDR_INCLUDE_CPY \
    this.total_hdr_len       = cpy_cls.total_hdr_len;\
    this.hdr_len             = cpy_cls.hdr_len;\
    this.hid                 = cpy_cls.hid;\
    this.inst_no             = cpy_cls.inst_no;\
    this.cfg_id              = cpy_cls.cfg_id;\
    this.hdr_name            = cpy_cls.hdr_name;\
    this.hdr                 = cpy_cls.hdr;\
    this.pack_vec            = cpy_cls.pack_vec;\
    this.nxt_hdr             = cpy_cls.nxt_hdr;\
    this.prv_hdr             = cpy_cls.prv_hdr;\
    this.all_hdr             = cpy_cls.all_hdr;\
    this.psnt                = cpy_cls.psnt;\
    this.start_off           = cpy_cls.start_off;\
    this.plib                = cpy_cls.plib;\
    this.crc_chksm           = cpy_cls.crc_chksm;\
    this.harray              = cpy_cls.harray;\
    this.harray.data_pattern = cpy_cls.harray.data_pattern;\
    this.harray.start_byte   = cpy_cls.harray.start_byte;\
    `HDR_L2_INCLUDE_CPY;\
    `HDR_MACSEC_INCLUDE_CPY;\
    `HDR_PTP_INCLUDE_CPY;\
    `HDR_MPLS_INCLUDE_CPY;\
    `HDR_IP_INCLUDE_CPY;\
    `HDR_IPSEC_INCLUDE_CPY;\
    `HDR_UDP_INCLUDE_CPY;\
    `HDR_XXX_INCLUDE_CPY

// ~~~~~~~~~~ L2/Ether Type defines/tasks/macros ~~~~~~~~~~
`include "hdr_l2_include.svh"

// ~~~~~~~~~~ MACSEC defines/tasks/macros ~~~~~~~~~~
`include "hdr_macsec_include.svh"

// ~~~~~~~~~~ PTP defines/tasks/macros ~~~~~~~~~~
`include "hdr_ptp_include.svh"

// ~~~~~~~~~~ MPLS defines/tasks ~~~~~~~~~~
`include "hdr_mpls_include.svh"

// ~~~~~~~~~~ L3/Nxt hdr defines/tasks/macros ~~~~~~~~~~
`include "hdr_ip_include.svh"

// ~~~~~~~~~~ IPSEC defines/tasks/macros ~~~~~~~~~~
`include "hdr_ipsec_include.svh"

// ~~~~~~~~~~ UDP defines/tasks/macros ~~~~~~~~~~
`include "hdr_udp_include.svh"

// ~~~~~~~~~~ TCP defines/tasks/macros ~~~~~~~~~~
`include "hdr_tcp_include.svh"

// ~~~~~~~~~~ IGMP defines/tasks/macros ~~~~~~~~~~
`include "hdr_igmp_include.svh"

// ~~~~~~~~~~ XXX defines/tasks/macros ~~~~~~~~~~
`include "hdr_xxx_include.svh"

// ~~~~~~~~~~ EOF ~~~~~~~~~~
