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
//  This hdr_class generates FCOE header.
//  FCOE header & trailer format (18B = 14B hdr + 4B trl)
//  FCOE header : (14B) (Timestamp format)
//  +-------------------+
//  | fcoe_ver[3:0]     | -> must be 0
//  +-------------------+
//  | fcoe_type[3:0]    | -> must be 0
//  +-------------------+
//  | sof [7:0]         | 
//  +-------------------+
//  | tv                | -> If 1, timestamp is vld else not 
//  +-------------------+
//  | rsvd0[30:0]       | 
//  +-------------------+
//  | timestamp[63:0]   | 
//  +-------------------+
//  FCOE header : (14B) (one more format)
//  +-------------------+
//  | fcoe_ver[3:0]     | -> must be 0
//  +-------------------+
//  | rsvd_0[99:0]      | 
//  +-------------------+
//  | sof [7:0]         | 
//  +-------------------+
//  FCOE trailer: (4B)
//  +-------------------+
//  | eof [7:0]         | 
//  +-------------------+
//  | rsvd1[23:0]       | 
//  +-------------------+
//
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+------------------+-----------------------------------+
//  | Width | Default | Variable         | Description                       |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_fcoe_ver | If 1, corrupts fcoe ver           |
//  |       |         |                  | (Version != 4'h0)                 |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_fcoe_type| If 1, corrupts fcoe type          |
//  |       |         |                  | (Type != 4'h0)                    |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_sof      | If 1,invalid SOF                  |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_eof      | If 1,invalid EOF                  |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | null_rsvd        | If 1, all rsvd fields set to 0    |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | timestamp_format | If 1, using timestamp_format      |
//  +-------+---------+------------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class fcoe_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [3:0]         fcoe_ver; 
  rand bit [3:0]         fcoe_type;
  rand bit [7:0]         sof;      
  rand bit               tv;       
  rand bit [30:0]        rsvd0;    
  rand bit [99:0]        rsvd_0;
  rand bit [63:0]        timestamp;
  rand bit [7:0]         eof;      
  rand bit [23:0]        rsvd1;            

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit               corrupt_fcoe_ver  = 1'b0;
       bit               corrupt_fcoe_type = 1'b0;
       bit               corrupt_sof       = 1'b0;
       bit               corrupt_eof       = 1'b0;
       bit               null_rsvd         = 1'b0;
       bit               timestamp_format  = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint fcoe_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == 14;
    trl_len == 4;
  }

  constraint legal_fcoe_ver
  {
    (corrupt_fcoe_ver == 1'b0) -> (fcoe_ver == 4'h0);
    (corrupt_fcoe_ver == 1'b1) -> (fcoe_ver != 4'h0);
  }

  constraint legal_fcoe_type
  {
    (corrupt_fcoe_type == 1'b0) -> (fcoe_type == 4'h0);
    (corrupt_fcoe_type == 1'b1) -> (fcoe_type != 4'h0);
  }

  constraint legal_sof
  {
   (corrupt_sof == 1'b0) ->  (sof inside {8'h28, 8'h2d, 8'h35, 8'h2e, 8'h36, 8'h29, 8'h31, 8'h39});
   (corrupt_sof == 1'b1) -> !(sof inside {8'h28, 8'h2d, 8'h35, 8'h2e, 8'h36, 8'h29, 8'h31, 8'h39});
  }

  constraint legal_eof
  {
   (corrupt_eof == 1'b0) ->  (eof inside {8'h41, 8'h42, 8'h49, 8'h50, 8'h46, 8'h4e, 8'h44, 8'h4f});
   (corrupt_eof == 1'b1) -> !(eof inside {8'h41, 8'h42, 8'h49, 8'h50, 8'h46, 8'h4e, 8'h44, 8'h4f});
  }

  constraint legal_rsvd
  {
    (null_rsvd) -> rsvd0  == 31'h0;
    (null_rsvd) -> rsvd1  == 24'h0;
    (null_rsvd) -> rsvd_0 == 100'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = FCOE_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "foce[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    if (timestamp_format)
        pack_vec = {fcoe_ver, fcoe_type, sof, tv, rsvd0, timestamp};
    else
        pack_vec = {fcoe_ver, rsvd_0, sof};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    if (timestamp_format)
        hdr = {>>{fcoe_ver, fcoe_type, sof, tv, rsvd0, timestamp}};
    else
        hdr = {>>{fcoe_ver, rsvd_0, sof}};
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
    start_off = index;
    // pack class members trailer
    `ifdef SVFNYI_0
    pack_vec = {eof, rsvd1};
    harray.pack_bit (pkt, pack_vec, index, trl_len*8);
    `else
    hdr = {>>{eof, rsvd1}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index); 
    `endif
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    update_len(index, pkt.size, 14, 4);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    if (timestamp_format)
        {fcoe_ver, fcoe_type, sof, tv, rsvd0, timestamp} = pack_vec;
    else
        {fcoe_ver, rsvd_0, sof} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    if (timestamp_format)
        {>>{fcoe_ver, fcoe_type, sof, tv, rsvd0, timestamp}} = hdr;
    else
        {>>{fcoe_ver, rsvd_0, sof}} = hdr;
    `endif
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[FC_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, FC_HID);
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
    // unpack class members
    start_off = index;
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, trl_len);
    {eof, rsvd1} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, trl_len);
    {>>{eof, rsvd1}} = hdr;
    `endif
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Unpacking %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index); 
    `endif
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    fcoe_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.fcoe_ver         = lcl.fcoe_ver; 
    this.fcoe_type        = lcl.fcoe_type;
    this.sof              = lcl.sof;      
    this.tv               = lcl.tv;       
    this.rsvd0            = lcl.rsvd0;    
    this.rsvd_0           = lcl.rsvd_0;    
    this.timestamp        = lcl.timestamp;
    this.eof              = lcl.eof;      
    this.rsvd1            = lcl.rsvd1;            
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_fcoe_ver = lcl.corrupt_fcoe_ver;
    this.corrupt_fcoe_type= lcl.corrupt_fcoe_type;
    this.corrupt_sof      = lcl.corrupt_sof;
    this.corrupt_eof      = lcl.corrupt_eof;
    this.null_rsvd        = lcl.null_rsvd;
    this.timestamp_format = lcl.timestamp_format;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    fcoe_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   4, "fcoe_ver", fcoe_ver, lcl.fcoe_ver);
    if (timestamp_format)
    begin // {
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   4, "fcoe_type", fcoe_type, lcl.fcoe_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "sof", sof, lcl.sof);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN,   1, "tv", tv, lcl.tv);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  31, "rsvd0", rsvd0, lcl.rsvd0);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "timestamp", timestamp, lcl.timestamp);
    end // }
    else
    begin // {
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 100, "rsvd_0", rsvd_0, lcl.rsvd_0);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "sof", sof, lcl.sof);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_fcoe_ver", corrupt_fcoe_ver, lcl.corrupt_fcoe_ver);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_fcoe_type", corrupt_fcoe_type, lcl.corrupt_fcoe_type);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_sof", corrupt_sof, lcl.corrupt_sof);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_eof", corrupt_eof, lcl.corrupt_eof);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "timestamp_format", timestamp_format, lcl.timestamp_format);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "eof", eof, lcl.eof);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "rsvd1", rsvd1, lcl.rsvd1);
  endtask : display_hdr // }

endclass : fcoe_hdr_class // }
