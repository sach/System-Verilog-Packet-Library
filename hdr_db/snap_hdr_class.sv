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
//  This hdr_class generates IEEE 802.3 LLC/SNAP header
//  LLC/SNAP header format (8B, No trailer)
//  +-------------------+
//  | dsap [7:0] = 0xAA |
//  +-------------------+
//  | ssap [7:0] = 0xAA |
//  +-------------------+
//  | ctrl [7:0] = 0x3  |
//  +-------------------+
//  | oui  [23:0]       | 
//  +-------------------+
//  | etype [15:0]      |
//  +-------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+--------------+------------------------------------+
//  | Width | Default | Variable     | Description                        |
//  +-------+---------+--------------+------------------------------------+
//  | 1     | 1'b0    | corrupt_dsap | If 1, dsap != 0xAA                 |
//  +-------+---------+--------------+------------------------------------+
//  | 1     | 1'b0    | corrupt_ssap | If 1, ssap != 0xAA                 |
//  +-------+---------+--------------+------------------------------------+
//  | 1     | 1'b0    | corrupt_ctrl | If 1, ctrl != 0x3                  |
//  +-------+---------+--------------+------------------------------------+
// 
// ----------------------------------------------------------------------

class snap_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]  dsap;
  rand bit [7:0]  ssap;
  rand bit [7:0]  ctrl;
  rand bit [23:0] oui;
  rand bit [15:0] etype;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit        corrupt_dsap = 1'b0; 
       bit        corrupt_ssap = 1'b0; 
       bit        corrupt_ctrl = 1'b0; 

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint snap_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_etype
  {
    `LEGAL_ETH_TYPE_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == 8;
    trl_len == 0;
  }

  constraint legal_dsap
  {
    (corrupt_dsap == 1'b0) -> (dsap == 8'hAA);
    (corrupt_dsap == 1'b1) -> (dsap != 8'hAA);
  }

  constraint legal_ssap
  {
    (corrupt_ssap == 1'b0) -> (ssap == 8'hAA);
    (corrupt_ssap == 1'b1) -> (ssap != 8'hAA);
  }

  constraint legal_ctrl
  {
    (corrupt_ctrl == 1'b0) -> (ctrl == 8'h3);
    (corrupt_ctrl == 1'b1) -> (ctrl != 8'h3);
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = SNAP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "snap[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {dsap, ssap, ctrl, oui, etype};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{dsap, ssap, ctrl, oui, etype}};
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
    update_len (index, pkt.size, 8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {dsap, ssap, ctrl, oui, etype} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{dsap, ssap, ctrl, oui, etype}} = hdr;
    `endif
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[get_hid_from_etype(etype)] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_etype (etype));
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
    snap_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.dsap         = lcl.dsap;
    this.ssap         = lcl.ssap;
    this.ctrl         = lcl.ctrl;
    this.oui          = lcl.oui;
    this.etype        = lcl.etype;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_dsap = lcl.corrupt_dsap; 
    this.corrupt_ssap = lcl.corrupt_ssap; 
    this.corrupt_ctrl = lcl.corrupt_ctrl; 
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    snap_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "dsap", dsap, lcl.dsap);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "ssap", ssap, lcl.ssap);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "ctrl", ctrl, lcl.ctrl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "oui", oui, lcl.oui);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "etype", etype, lcl.etype, null_a, null_a, get_etype_name(etype));
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_dsap", corrupt_dsap, lcl.corrupt_dsap);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_ssap", corrupt_ssap, lcl.corrupt_ssap);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_ctrl", corrupt_ctrl, lcl.corrupt_ctrl);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display)
      if (cmp_cls.nxt_hdr.hid === nxt_hdr.hid)
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : snap_hdr_class // }
