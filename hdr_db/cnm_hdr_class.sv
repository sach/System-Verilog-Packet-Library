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
//  This hdr_class generates Congestion Network Message (CNM) header. (IEEE 802.1Qau)
//  CNM header Format (24B, No trailer)
//  +----------------------+
//  | cnm_ver       [3:0]  |
//  +----------------------+
//  | rsvd          [5:0]  |
//  +----------------------+
//  | qfeedback     [5:0]  |     
//  +----------------------+
//  | cpid          [63:0] |
//  +----------------------+
//  | cnmqoffset    [15:0] |
//  +----------------------+
//  | cnmqdelta     [15:0] |
//  +----------------------+
//  | encap_priority[15:0] |
//  +----------------------+
//  | encap_da      [47:0] |
//  +----------------------+
//  | encap_len     [15:0] |
//  +----------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------------+----------------------------+
//  | Width | Default | Variable             | Description                |
//  +-------+---------+----------------------+----------------------------+
//  | 1     | 1'b0    | corrupt_cnm_ver      | If 1, corrupt CNM version  |
//  |       |         |                      | (cnm_ver != 4'h0           |
//  +-------+---------+----------------------+----------------------------+
//  | 1     | 1'b0    | null_rsvd            | If 1, rsvd  set to 0       |
//  +-------+---------+----------------------+----------------------------+
//  | 1     | 1'b1    | cal_encap_len        | If 1, calculates encap_len |
//  |       |         |                      | Otherwise it will be random|
//  +-------+---------+----------------------+----------------------------+
//  | 1     | 1'b0    | corrupt_encap_len    | If 1, corrupts encap_len   |
//  +-------+---------+----------------------+----------------------------+
//  | 16    | 16'h1   | corrupt_encap_len_by | Corrupts encap_len by value|
//  +-------+---------+----------------------+----------------------------+
//

//
// ----------------------------------------------------------------------

class cnm_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [3:0]     cnm_ver;
  rand bit [5:0]     rsvd;
  rand bit [5:0]     qfeedback;
  rand bit [63:0]    cpid;
  rand bit [15:0]    cnmqoffset;
  rand bit [15:0]    cnmqdelta;
  rand bit [15:0]    encap_priority;
  rand bit [47:0]    encap_da;
  rand bit [15:0]    encap_len;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           corrupt_cnm_ver      = 1'b0;
       bit           null_rsvd            = 1'b0;
       bit           cal_encap_len        = 1'b1;
       bit           corrupt_encap_len    = 1'b0;
       bit [15:0]    corrupt_encap_len_by = 16'h1;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint cnm_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
    hdr_len == 24; 
    trl_len == 0; 
  }

  constraint legal_cnm_ver
  {
    (corrupt_cnm_ver == 1'b0) -> (cnm_ver == 4'h0);
    (corrupt_cnm_ver == 1'b1) -> (cnm_ver != 4'h0);
  }

  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> rsvd == 6'h0;
  }

  constraint legal_encap_len
  {
    ( cal_encap_len & ~corrupt_encap_len) -> (encap_len == super.nxt_hdr.total_hdr_len);
    ( cal_encap_len &  corrupt_encap_len) -> (encap_len == super.nxt_hdr.total_hdr_len + corrupt_encap_len_by);
    (~cal_encap_len &  corrupt_encap_len) -> (encap_len == encap_len + corrupt_encap_len_by);
  }
  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = CNM_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "cnm[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {cnm_ver, rsvd, qfeedback, cpid, cnmqoffset, cnmqdelta, encap_priority, encap_da, encap_len};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{cnm_ver, rsvd, qfeedback, cpid, cnmqoffset, cnmqdelta, encap_priority, encap_da, encap_len}};
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
    hdr_class  lcl_class;
    // unpack class members
    update_len (index, pkt.size, 24);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {cnm_ver, rsvd, qfeedback, cpid, cnmqoffset, cnmqdelta, encap_priority, encap_da, encap_len} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{cnm_ver, rsvd, qfeedback, cpid, cnmqoffset, cnmqdelta, encap_priority, encap_da, encap_len}} = hdr;
    `endif
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
    cnm_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~~~~
    this.cnm_ver               = lcl.cnm_ver;
    this.rsvd                  = lcl.rsvd;
    this.qfeedback             = lcl.qfeedback;
    this.cpid                  = lcl.cpid;
    this.cnmqoffset            = lcl.cnmqoffset;
    this.cnmqdelta             = lcl.cnmqdelta;
    this.encap_priority        = lcl.encap_priority;
    this.encap_da              = lcl.encap_da;
    this.encap_len             = lcl.encap_len;
    // ~~~~~~~~~~ Local variables ~~~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_cnm_ver       = lcl.corrupt_cnm_ver;    
    this.null_rsvd             = lcl.null_rsvd;
    this.cal_encap_len         = lcl.cal_encap_len;
    this.corrupt_encap_len     = lcl.corrupt_encap_len;
    this.corrupt_encap_len_by  = lcl.corrupt_encap_len_by;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    cnm_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 004, "cnm_ver",        cnm_ver,        lcl.cnm_ver);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 006, "rsvd",           rsvd,           lcl.rsvd);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 006, "qfeedback",      qfeedback,      lcl.qfeedback);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 064, "cpid",           cpid,           lcl.cpid);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "cnmqoffset",     cnmqoffset,     lcl.cnmqoffset);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "cnmqdelta",      cnmqdelta,      lcl.cnmqdelta);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "encap_priority", encap_priority, lcl.encap_priority);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 048, "encap_da",       encap_da,       lcl.encap_da);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "encap_len",      encap_len,      lcl.encap_len);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_cnm_ver", corrupt_cnm_ver, lcl.corrupt_cnm_ver);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_encap_len", cal_encap_len, lcl.cal_encap_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_encap_len", corrupt_encap_len, lcl.corrupt_encap_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "corrupt_encap_len_by", corrupt_encap_len_by, lcl.corrupt_encap_len_by);
 
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : cnm_hdr_class // }
