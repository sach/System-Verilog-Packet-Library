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
//  This hdr_class generates Transport Interconnection for Lots of Links (TRILL) header
//  (RFC 6325)
//  TRILL header Format (6+B, No Trailer)
//  +--------------------+
//  | V[1:0]             | -> Version 
//  +--------------------+
//  | R[1:0]             | -> Reserved 
//  +--------------------+
//  | M                  | -> Multi-destination 
//  +--------------------+
//  | op_length[4:0]     | -> Options Length gives length of options in units of 4 octets
//  +--------------------+
//  | hop_count[5:0]     | -> Hop count
//  +--------------------+
//  | egr_rb_nname[15:0] | -> Egress RBridge Nickname
//  +--------------------+
//  | igr_rb_nname[15:0] | -> Ingress RBridge Nickname
//  +--------------------+
//  | options[124][7:0]  | -> present if op_length is non-zero
//  +--------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_trill_version     | If 1, corrupts trill version  |
//  |       |         |                           | (V != 2'h0)                   |
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class trill_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [1:0]     V;
  rand bit [1:0]     R;
  rand bit           M;
  rand bit [4:0]     op_length;
  rand bit [5:0]     hop_count;
  rand bit [15:0]    egr_rb_nname;
  rand bit [15:0]    igr_rb_nname;
  rand bit [7:0]     options[];

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           corrupt_trill_version = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint trill_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
   (op_length == 0) -> hdr_len == 6;
   (op_length != 0) -> hdr_len == (6 + options.size);
   trl_len == 0;
  }

  constraint legal_V
  {
    (corrupt_trill_version == 1'b0) -> (V == 2'h0);
    (corrupt_trill_version == 1'b1) -> (V != 2'h0);
  }

  constraint legal_R
  {
    R == 2'h0;
  }

  constraint legal_options_size
  {
   (op_length == 0) -> options.size == 0;
   (op_length != 0) -> options.size == (op_length*4);
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = TRILL_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "trill[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    int tmp_idx;
    pack_vec = {V, R, M, op_length, hop_count, egr_rb_nname, igr_rb_nname}; 
    harray.pack_bit (pkt, pack_vec, index, 48);
    if (op_length > 0)
    begin // {
        tmp_idx = index/8;
        harray.pack_array_8(options, pkt, tmp_idx);
        index = tmp_idx * 8;
    end // }
    `else
    if (op_length > 5'd0)
        hdr = {>>{V, R, M, op_length, hop_count, egr_rb_nname, igr_rb_nname, options}};
    else
        hdr = {>>{V, R, M, op_length, hop_count, egr_rb_nname, igr_rb_nname}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif
    // pack next hdr
    if (~last_pack)
    begin // {
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
        `endif
        this.nxt_hdr.pack_hdr (pkt, index);
    end // }
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    update_len (index, pkt.size, 6);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, 6);
    {V, R, M, op_length, hop_count, egr_rb_nname, igr_rb_nname} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, 6);
    {>>{V, R, M, op_length, hop_count, egr_rb_nname, igr_rb_nname}} = hdr;
    `endif
    hdr_len   = 6 + op_length*4;
    if (op_length > 5'd0)
        harray.copy_array (pkt, options, index, (hdr_len - 6));
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[ETH_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, ETH_HID);
        else
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
    end // } 
    // unpack next hdr
    if (~last_unpack)
    begin // {
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Unpacking %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
        `endif
        this.nxt_hdr.unpack_hdr (pkt, index, hdr_q, mode);
    end // }
    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    trill_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.V                         = lcl.V;
    this.R                         = lcl.R;
    this.M                         = lcl.M;
    this.op_length                 = lcl.op_length;
    this.hop_count                 = lcl.hop_count;
    this.egr_rb_nname              = lcl.egr_rb_nname;
    this.igr_rb_nname              = lcl.igr_rb_nname;
    this.options                   = lcl.options;      
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_trill_version     = lcl.corrupt_trill_version;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    trill_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 002, "V", V, lcl.V);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 002, "R", R, lcl.R);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "M", M, lcl.M);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 005, "op_length", op_length, lcl.op_length);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 006, "hop_count", hop_count, lcl.hop_count);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "egr_rb_nname", egr_rb_nname, lcl.egr_rb_nname);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "igr_rb_nname", igr_rb_nname, lcl.igr_rb_nname);
    if (options.size() !== 0)                           
    hdis.display_fld (mode, hdr_name, ARRAY,      DEF,  0, "options", 0, 0, options, lcl.options);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_trill_version", corrupt_trill_version, lcl.corrupt_trill_version);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : trill_hdr_class // }
