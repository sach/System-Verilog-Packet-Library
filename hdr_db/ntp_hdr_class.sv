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
//  This hdr_class generates the RFC 4330 - NTP version 4 header
//
//  NTP header Format
//  +---------------------+
//  | li           [1:0]  | 
//  +---------------------+
//  | vn           [2:0]  |
//  +---------------------+
//  | ntp_mode     [2:0]  |
//  +---------------------+
//  | stratum      [7:0]  |
//  +---------------------+
//  | poll         [7:0]  |
//  +---------------------+
//  | precision    [7:0]  |
//  +---------------------+
//  | root_delay   [31:0] |
//  +---------------------+
//  | root_disp    [31:0] | -> Root Dispersion
//  +---------------------+
//  | ref_ident    [31:0] | -> Reference Identifier
//  +---------------------+
//  | ref_timestamp[63:0] | -> Reference Timestamp
//  +---------------------+
//  | org_timestamp[63:0] | -> Originate Timestamp
//  +---------------------+
//  | rcv_timestamp[63:0] | -> Receive   Timestamp
//  +---------------------+
//  | xmt_timestamp[63:0] | -> Transmit  Timestamp
//  +---------------------+
//  | key_ident    [31:0] | -> Key Identifier (optional)
//  +---------------------+
//  | msg_digest   [127:0]| -> Message Digest (optional)
//  +---------------------+
//
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+-------------+----------------------------------------------+
//  | Width | Default | Variable    | Description                                  |
//  +-------+---------+-------------+----------------------------------------------+
//  | 1     | 1'b0    | auth_en     | If 1, key_ident and msg_digest exists in hdr |
//  |       |         |             | (authenticate process enable)                |
//  +-------+---------+-------------+----------------------------------------------+
//
// ----------------------------------------------------------------------

class ntp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand  bit [1:0]     li;
  rand  bit [2:0]     vn;
  rand  bit [2:0]     ntp_mode;
  rand  bit [7:0]     stratum;
  rand  bit [7:0]     poll;
  rand  bit [7:0]     precision;
  rand  bit [31:0]    root_delay;
  rand  bit [31:0]    root_disp;
  rand  bit [31:0]    ref_ident;
  rand  bit [63:0]    ref_timestamp;
  rand  bit [63:0]    org_timestamp;
  rand  bit [63:0]    rcv_timestamp;
  rand  bit [63:0]    xmt_timestamp;
  rand  bit [31:0]    key_ident;
  rand  bit [127:0]   msg_digest;   

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
        bit           auth_en            = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint ntp_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    (auth_en     == 1'b0) -> hdr_len == 48;
    (auth_en     == 1'b1) -> hdr_len == 68;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = NTP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "ntp[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void pre_randomize (); // {
    if (super) super.pre_randomize();
  endfunction : pre_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    if (auth_en)
        hdr = {>>{li, vn, ntp_mode, stratum, poll, precision, root_delay, root_disp, ref_ident, ref_timestamp, org_timestamp, rcv_timestamp, xmt_timestamp, key_ident, msg_digest}};
    else
        hdr = {>>{li, vn, ntp_mode, stratum, poll, precision, root_delay, root_disp, ref_ident, ref_timestamp, org_timestamp, rcv_timestamp, xmt_timestamp}};
    harray.pack_array_8 (hdr, pkt, index);
    // pack next hdr
    if (~last_pack)
        this.nxt_hdr.pack_hdr (pkt, index);
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    hdr_len   = (auth_en) ? 68 : 48;
    start_off = index;
    harray.copy_array (pkt, hdr, index, hdr_len);
    if (auth_en == 1'b1)
        {>>{li, vn, ntp_mode, stratum, poll, precision, root_delay, root_disp, ref_ident, ref_timestamp, org_timestamp, rcv_timestamp, xmt_timestamp, key_ident, msg_digest}} = hdr;
    else
        {>>{li, vn, ntp_mode, stratum, poll, precision, root_delay, root_disp, ref_ident, ref_timestamp, org_timestamp, rcv_timestamp, xmt_timestamp}} = hdr;
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[DATA_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
        else
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
    end // }
    // unpack next hdr
    if (~last_unpack)
        this.nxt_hdr.unpack_hdr (pkt, index, hdr_q, mode);
    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_unpack = 1'b0); // {
    ntp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.li               = lcl.li;
    this.vn               = lcl.vn;
    this.ntp_mode         = lcl.ntp_mode;
    this.stratum          = lcl.stratum;
    this.poll             = lcl.poll;
    this.precision        = lcl.precision;
    this.root_delay       = lcl.root_delay;
    this.root_disp        = lcl.root_disp;
    this.ref_ident        = lcl.ref_ident;
    this.ref_timestamp    = lcl.ref_timestamp;
    this.org_timestamp    = lcl.org_timestamp;
    this.rcv_timestamp    = lcl.rcv_timestamp;
    this.xmt_timestamp    = lcl.xmt_timestamp;
    this.key_ident        = lcl.key_ident;
    this.msg_digest       = lcl.msg_digest;   
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.auth_en          = lcl.auth_en;
    if (~last_unpack)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_unpack);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    ntp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, "li",             2, HEX, BIT_VEC, li,           lcl.li);           
    hdis.display_fld (mode, hdr_name, "vn",             3, HEX, BIT_VEC, vn,           lcl.vn);           
    hdis.display_fld (mode, hdr_name, "ntp_mode",       3, HEX, BIT_VEC, ntp_mode,     lcl.ntp_mode);         
    hdis.display_fld (mode, hdr_name, "stratum",        8, HEX, BIT_VEC, stratum,      lcl.stratum);      
    hdis.display_fld (mode, hdr_name, "poll",           8, HEX, BIT_VEC, poll,         lcl.poll);         
    hdis.display_fld (mode, hdr_name, "precision",      8, HEX, BIT_VEC, precision,    lcl.precision);    
    hdis.display_fld (mode, hdr_name, "root_delay",    32, HEX, BIT_VEC, root_delay,   lcl.root_delay);   
    hdis.display_fld (mode, hdr_name, "root_disp",     32, HEX, BIT_VEC, root_disp,    lcl.root_disp);    
    hdis.display_fld (mode, hdr_name, "ref_ident",     32, HEX, BIT_VEC, ref_ident,    lcl.ref_ident);    
    hdis.display_fld (mode, hdr_name, "ref_timestamp", 64, HEX, BIT_VEC, ref_timestamp,lcl.ref_timestamp);
    hdis.display_fld (mode, hdr_name, "org_timestamp", 64, HEX, BIT_VEC, org_timestamp,lcl.org_timestamp);
    hdis.display_fld (mode, hdr_name, "rcv_timestamp", 64, HEX, BIT_VEC, rcv_timestamp,lcl.rcv_timestamp);
    hdis.display_fld (mode, hdr_name, "xmt_timestamp", 64, HEX, BIT_VEC, xmt_timestamp,lcl.xmt_timestamp);
    if (auth_en)
    begin // {
    hdis.display_fld (mode, hdr_name, "key_ident",     32, HEX, BIT_VEC, key_ident,    lcl.key_ident);     
    hdis.display_fld (mode, hdr_name, "msg_digest",   128, HEX, BIT_VEC, msg_digest,   lcl.msg_digest);   
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : ntp_hdr_class // }
