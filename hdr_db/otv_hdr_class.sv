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
//  This hdr_class generates Overlay Transport Virtualization (OTV) header
//  (draft-ietf)
//  OTV header Format (8B, No trailer)
//  +---------+---+--------+
//  | R1[3:0] | I | R2[2:0]| -> R1, R2 - Reserved, If I = 1, instance_id is valid  
//  +---------+---+--------+
//  | overlay_id[23:0]     | 
//  +----------------------+
//  | instance_id[23:0]    | 
//  +----------------------+
//  | rsvd[7:0]            | 
//  +----------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+-----------------+---------------------------------+
//  | Width | Default | Variable        | Description                     |
//  +-------+---------+-----------------+---------------------------------+
//  | 1     | 1'b0    | null_rsvd        | If 1, all rsvd fields set to 0    |
//  +-------+---------+-----------------+---------------------------------+
//
// ----------------------------------------------------------------------

class otv_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [3:0]     R1;
  rand bit           I;
  rand bit [2:0]     R2;
  rand bit [23:0]    overlay_id;
  rand bit [23:0]    instance_id;
  rand bit [7:0]     rsvd;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit        null_rsvd         = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint otv_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
    hdr_len == 8; 
    trl_len == 0;
  }


  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> R1   == 3'h0;
    (null_rsvd == 1'b1) -> R2   == 2'h0;
    (null_rsvd == 1'b1) -> rsvd == 8'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = OTV_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "otv[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {R1, I, R2, overlay_id, instance_id, rsvd};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{R1, I, R2, overlay_id, instance_id, rsvd}};
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
    update_len (index, pkt.size, 8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {R1, I, R2, overlay_id, instance_id, rsvd} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{R1, I, R2, overlay_id, instance_id, rsvd}} = hdr;
    `endif
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
    otv_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~~~~
    this.R1                    = lcl.R1; 
    this.I                     = lcl.I; 
    this.R2                    = lcl.R2; 
    this.overlay_id            = lcl.overlay_id;
    this.instance_id           = lcl.instance_id;
    this.rsvd                  = lcl.rsvd;
    // ~~~~~~~~~~ Local variables ~~~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.null_rsvd        = lcl.null_rsvd;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    otv_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 004, "R1", R1, lcl.R1); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "I", I, lcl.I); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 003, "R2", R2, lcl.R2); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "overlay_id", overlay_id, lcl.overlay_id); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "instance_id", instance_id, lcl.instance_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "rsvd", rsvd, lcl.rsvd); 
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : otv_hdr_class // }
