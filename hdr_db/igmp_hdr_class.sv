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
//  This hdr_class generates Internet Group Managment Protocol (IGMP) header
//  Supports  the following RFC
//            - RFC 1112 (IGMP Version 1)
//            - RFC 2236 (IGMP Version 2) Updates  RFC 1112
//            - RFC 3376 (IGMP Version 2) Obsoltes RFC 2236
//  IGMP header Format (8B, No trailer)
//  +-------------------+
//  | igmp_type   [7:0] | 
//  +-------------------+
//  | max_res_code[7:0] | 
//  +-------------------+
//  | checksum   [15:0] | 
//  +-------------------+
//  | group_addr [31:0] | 
//  +-------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_igmp_chksm            | If 1,calculates igmp checksum |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_igmp_chksm        | If 1, corrupts igmp checksum  |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'hFFFF| corrupt_igmp_chksm_msk    | Msk used to corrupt igmp_chksm|
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class igmp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand  bit [7:0]     igmp_type;
  rand  bit [7:0]     max_res_code; 
  rand  bit [15:0]    checksum;
  rand  bit [31:0]    group_addr;   

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
        bit           cal_igmp_chksm         = 1'b1;
        bit           corrupt_igmp_chksm     = 1'b0;
        bit [15:0]    corrupt_igmp_chksm_msk = 16'hffff;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint igmp_hdr_user_constraint
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

  constraint legal_igmp_type
  {
    `LEGAL_IGMP_TYPE_CONSTRAINTS;
  }

  constraint legal_checksum
  {
    checksum == 16'h0;
  }


  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    this.hid     = IGMP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "igmp[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int       igmp_idx;
    // making sure checksum is 0, incase pack_hdr was called before radomization
    if (~last_pack & cal_igmp_chksm)
        checksum = 0;
    igmp_idx = index;
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {igmp_type, max_res_code, checksum, group_addr};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
     hdr = {>>{igmp_type, max_res_code, checksum, group_addr}};
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
    // checksum calulation
    if (~last_pack)
        post_pack (pkt, igmp_idx);
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
    {igmp_type, max_res_code, checksum, group_addr} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{igmp_type, max_res_code, checksum, group_addr}} = hdr;
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

  task post_pack (ref bit [7:0] pkt [],
                          int       igmp_idx); // {
    bit [7:0] chksm_data [];
    // Calulate igmp_chksm, corrupt it if asked
    if (cal_igmp_chksm)
    begin // {
        harray.copy_array(pkt, chksm_data, igmp_idx, (pkt.size - igmp_idx));
        checksum = crc_chksm.chksm16(chksm_data, chksm_data.size(), 0, corrupt_igmp_chksm, corrupt_igmp_chksm_msk);
        pack_hdr (pkt, igmp_idx, 1'b1);
    end // }
    else
    begin // {
        if (corrupt_igmp_chksm)
        begin // {
            checksum ^= corrupt_igmp_chksm_msk;
            pack_hdr (pkt, igmp_idx, 1'b1);
        end // }
    end // }
  endtask : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    igmp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.igmp_type              = lcl.igmp_type;             
    this.max_res_code           = lcl.max_res_code;             
    this.checksum               = lcl.checksum;
    this.group_addr             = lcl.group_addr;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_igmp_chksm         = lcl.cal_igmp_chksm;        
    this.corrupt_igmp_chksm     = lcl.corrupt_igmp_chksm;    
    this.corrupt_igmp_chksm_msk = lcl.corrupt_igmp_chksm_msk;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    igmp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "igmp_type", igmp_type, lcl.igmp_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "max_res_code", max_res_code, lcl.max_res_code);
    if (corrupt_igmp_chksm)                              
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum,null_a,null_a, "BAD");
    else                                                
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum,null_a,null_a, "GOOD");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "group_addr", group_addr, lcl.group_addr);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_igmp_chksm", cal_igmp_chksm, lcl.cal_igmp_chksm);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_igmp_chksm", corrupt_igmp_chksm, lcl.corrupt_igmp_chksm);    
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "corrupt_igmp_chksm_msk", corrupt_igmp_chksm_msk, lcl.corrupt_igmp_chksm_msk);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : igmp_hdr_class // }
