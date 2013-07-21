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
//  This hdr_class generates the IEEE 802.1Qbh VNTag
//  802.1Qbh (*B, No trailer)
//  +---------------+
//  | d             | -> direction (0/1 - from adaptor/switch)
//  +---------------+ 
//  | p             | -> pointer (1-dst_vif points to a list)
//  +---------------+ 
//  | dst_vif[13:0] | -> destination vif (used only when d = 1)
//  +---------------+ 
//  | l             | -> looped (frame origniated at adapter)
//  +---------------+
//  + rsvd          | -> reserved
//  +---------------+
//  + ver[1:0]      | -> version
//  +---------------+
//  + src_vif[11:0] | -> source vif
//  +---------------+
//  | etype[15:0]   | 
//  +---------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_vntag_ver         | If 1, corrupts VNTag version  |
//  |       |         |                           | (Version != 2'h0)             |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | null_rsvd                 | If 1, all rsvd fields set to 0|
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class vntag_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit        d;      
  rand bit        p;      
  rand bit [13:0] dst_vif;
  rand bit        l;      
  rand bit        rsvd;   
  rand bit [1:0]  ver;    
  rand bit [11:0] src_vif;
  rand bit [15:0] etype;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
       bit        corrupt_vntag_ver = 1'b0;
       bit        null_rsvd         = 1'b0;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint vntag_hdr_user_constraint
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
    hdr_len == 6;
    trl_len == 0;
  }

  constraint legal_ver
  {
    (corrupt_vntag_ver == 1'b0) -> (ver == 2'h0);
    (corrupt_vntag_ver == 1'b1) -> (ver != 2'h0);
  }

  constraint legal_rsvd
  {
    (null_rsvd) -> rsvd == 1'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    this.inst_no = inst_no;
    hid      = VNTAG_HID;
    $sformat (hdr_name, "vntag[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr(ref   bit [7:0] pkt [],
                ref   int       index,
                input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {d, p, dst_vif, l, rsvd, ver, src_vif, etype};
    harray.pack_bit(pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{d, p, dst_vif, l, rsvd, ver, src_vif, etype}};
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
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {d, p, dst_vif, l, rsvd, ver, src_vif, etype} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{d, p, dst_vif, l, rsvd, ver, src_vif, etype}} = hdr;
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
    vntag_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.d                         = lcl.d;      
    this.p                         = lcl.p;      
    this.dst_vif                   = lcl.dst_vif;
    this.l                         = lcl.l;      
    this.rsvd                      = lcl.rsvd;   
    this.ver                       = lcl.ver;    
    this.src_vif                   = lcl.src_vif;
    this.etype                     = lcl.etype;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_vntag_ver         = lcl.corrupt_vntag_ver;
    this.null_rsvd                 = lcl.null_rsvd;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  // This task displays all the feilds of individual hdrs used
  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    vntag_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "d", d, lcl.d);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "p", p, lcl.p);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 014, "dst_vif", dst_vif, lcl.dst_vif);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "l", l, lcl.l);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "rsvd", rsvd, lcl.rsvd);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 002, "ver", ver, lcl.ver);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 012, "src_vif", src_vif, lcl.src_vif);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "etype", etype, lcl.etype, null_a, null_a, get_etype_name(etype));
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_vntag_ver", corrupt_vntag_ver, lcl.corrupt_vntag_ver);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : vntag_hdr_class // }
