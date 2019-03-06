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
         int                    pkt_format   = IEEE802; // Pkt format
  rand   bit [15:0]             total_hdr_len;          // hdr length from this.hdr to end of pkt
  rand   bit [15:0]             hdr_len;                // length of this.hdr 
  rand   bit [15:0]             trl_len;                // length of trailer, if present
         int                    hid;                    // header Id
         int                    inst_no = 0;            // hdr instance number
         int                    cfg_id  = 0;            // cfg_id number
         string                 hdr_name;
         bit [7:0]              hdr [];                 // each hdr data in array
         bit [`VEC_SZ-1:0]      pack_vec;               // packing vector
  rand   hdr_class              nxt_hdr;                // object handle to nxt hdr in list
  rand   hdr_class              prv_hdr;                // object handle to prv hdr in list
  rand   hdr_class              all_hdr [$];            // all the hdr of list;
         bit                    psnt           = 1'b0;  // this hdr_class is psnt
  rand   int                    start_off;              // starting offset of hdr
         bit [7:0]              null_a [];              // null array used in tasks as initial value
         bit [TOTAL_HID-1:0]    unpack_en      = {TOTAL_HID{1'b1}};
         pktlib_main_class      plib;
         pktlib_crc_chksm_class crc_chksm      = new ();
         pktlib_array_class     harray         = new ();

// ~~~~~~~~~~ Constraints Macro for total_hdr_len ~~~~~~~~~~~~~~~
`define LEGAL_TOTAL_HDR_LEN_CONSTRAINTS \
        total_hdr_len == hdr_len + trl_len + super.nxt_hdr.total_hdr_len;\
        start_off     == prv_hdr.start_off + prv_hdr.hdr_len

// ~~~~~~~~~~ Function to get the name of pkt_format ~~~~~~~~~~
  function string get_pkt_format_name(int pkt_format); // {
    case (pkt_format) // {
        IEEE802        : get_pkt_format_name = "IEEE802";
        FC             : get_pkt_format_name = "FC";
        MIPI_CSI2_DPHY : get_pkt_format_name = "MIPI-CSI2-DPHY";
        default        : get_pkt_format_name = "UNKNOWN";
    endcase // }
  endfunction : get_pkt_format_name // }

// ~~~~~~~~~~ Function to get crc_sz ~~~~~~~~~~
  function int get_crc_sz(); // {
    int got_crc_sz = 1'b0;
    get_crc_sz = 0;
    foreach (all_hdr[hdr_ls])
    begin // { 
        case (all_hdr[hdr_ls].hid) // {
            ETH_HID, FC_HID :
            begin // {
                 get_crc_sz = 4;
                 got_crc_sz = 1'b1;
            end // }
            DPHY_HID :
            begin // {
                 if (all_hdr[hdr_ls].dphy_spkt === 1'b0)
                     get_crc_sz = 2;
                 got_crc_sz = 1'b1;
            end // }
        endcase  // }
        if (got_crc_sz)
            break;
    end // }
  endfunction : get_crc_sz // }

//  ~~~~~~~~ task to update hdr db ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  function void update_hdr_db (int hid, int inst_num); // {
      plib.hdr_db[hid][inst_num] = this;
  endfunction : update_hdr_db // }

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

//  ~~~~~~~~ task to set some of the length(used by unpack task) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  task update_len (int        idx,
                   int        pkt_sz,
                   bit [15:0] hlen,
                   bit [15:0] tlen = 0); // {
    this.total_hdr_len = pkt_sz - idx - total_trl_len (this.cfg_id);
    this.start_off     = idx;
    this.hdr_len       = hlen;
    this.trl_len       = tlen; 
  endtask : update_len // }

//  ~~~~~~~~ function to get total_trl_len (used by unpack task) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  function bit[15:0] total_trl_len (int c_id); // {
    int i;
    for (i = 0; i < c_id; i++)
      total_trl_len += all_hdr[i].trl_len;
  endfunction : total_trl_len // } 

//  ~~~~~~~~ function to get HID from pkt_format(used by unpack task) ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  function int get_pformat_hid(int p_format); // {
    case (p_format) // {
        IEEE802        : get_pformat_hid = ETH_HID; 
        FC             : get_pformat_hid = FC_HID; 
        MIPI_CSI2_DPHY : get_pformat_hid = DPHY_HID; 
        default        : get_pformat_hid = ETH_HID; 
    endcase // }
  endfunction : get_pformat_hid // }

// ~~~~~~~~~~ task to display common hdr fields ~~~~~~~~~~~~~
 task display_common_hdr_flds (pktlib_display_class hdis, 
                               hdr_class            lcl,
                               int                  mode = DISPLAY); // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Local variables ~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "pkt_format",    pkt_format,    lcl.pkt_format, null_a, null_a, get_pkt_format_name(pkt_format));
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "total_hdr_len", total_hdr_len, lcl.total_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "hdr_len",       hdr_len,       lcl.hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "trl_len",       trl_len,       lcl.trl_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "hid",           hid,           lcl.hid);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "inst_no",       inst_no,       lcl.inst_no);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "cfg_id",        cfg_id,        lcl.cfg_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "start_off",     start_off,     lcl.start_off);
  endtask : display_common_hdr_flds // }

// ~~~~~~~~~~ define to copy all the fields of include files ~~~~~~~~~~~~~
`define HDR_INCLUDE_CPY \
    this.pkt_format          = cpy_cls.pkt_format;\
    this.total_hdr_len       = cpy_cls.total_hdr_len;\
    this.hdr_len             = cpy_cls.hdr_len;\
    this.trl_len             = cpy_cls.trl_len;\
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
    `HDR_DPHY_INCLUDE_CPY;\
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

// ~~~~~~~~~~ DPHY defines/tasks ~~~~~~~~~~
`include "hdr_dphy_include.svh"

// ~~~~~~~~~~ XXX defines/tasks/macros ~~~~~~~~~~
`include "hdr_xxx_include.svh"

// ~~~~~~~~~~ EOF ~~~~~~~~~~
