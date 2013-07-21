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
//  This hdr_class generates ROCE header.
//  1. ROCE header must follow by Infiniband Global routing header (GRH)
//  2. ROCE header must have Inner CRC (ICRC) 4B (Trailer)
//  Pkt with ROCE header looks like
//  +---+---+-----+----+---+
//  |Eth|GRH|BRH +|ICRC|CRC|
//  +---+---+-----+----+---+
//      ^              ^
//      |____ROCE______|
//
// ROCE header format (0B, 4B)
// Trailer - (4B)
//  +------------+
//  |icrc [31:0] |
//  +------------+

// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+------------------+-----------------------------------+
//  | Width | Default | Variable         | Description                       |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b1    | cal_n_add_icrc   | Calculate & add CRC to packet     |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_icrc     | If 1, corrupts CRC                |
//  +-------+---------+------------------+-----------------------------------+

// ----------------------------------------------------------------------

class roce_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [31:0] icrc;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
         bit               cal_n_add_icrc = 1'b1;
         bit               corrupt_icrc   = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint roce_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == 0;
    trl_len == 4;
  }


  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = ROCE_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "roce[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    bit [7:0] icrc_pkt [];
    // pack next hdr
    if (~last_pack)
    begin // {
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index); 
        `endif
        this.nxt_hdr.pack_hdr (pkt, index);
    end // }
    start_off = index;
    // calculate icrc
    if (cal_n_add_icrc)
    begin // {
        icrc_pkt = new[start_off] (pkt); 
        // GRH fields : flow_label, tclass, hoplmt and BTH rsvd0 are replaced with 1's for ICRC cal 
        if (nxt_hdr.hid === GRH_HID)
        begin // {
            icrc_pkt [nxt_hdr.start_off]     = {4'h0, 4'hF}; // tclass[7:4]
            icrc_pkt [nxt_hdr.start_off + 1] = 8'hFF;        // {tclass[3:0], flow_label[19:16]}
            icrc_pkt [nxt_hdr.start_off + 2] = 8'hFF;        // flow_label[15:8]
            icrc_pkt [nxt_hdr.start_off + 3] = 8'hFF;        // flow_label[7:0] 
            icrc_pkt [nxt_hdr.start_off + 7] = 8'hFF;        // hoplmt
            if (nxt_hdr.nxt_hdr.hid === BTH_HID)             // bth : rsvd0
                icrc_pkt [nxt_hdr.nxt_hdr.start_off + 4] = 8'hFF;
        end // }
        icrc = crc_chksm.crc32 (icrc_pkt, icrc_pkt.size, nxt_hdr.start_off, corrupt_icrc); 
    end // }
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = icrc;
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{icrc}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // get next hdr and update common nxt_hdr fields
    update_len (index, pkt.size, 0, 4);
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[GRH_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, GRH_HID);
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
    icrc = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, trl_len);
    {>>{icrc}} = hdr;
    `endif
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Unpacking %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index); 
    `endif
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    roce_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.icrc           = lcl.icrc;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_n_add_icrc = lcl.cal_n_add_icrc;   
    this.corrupt_icrc   = lcl.corrupt_icrc;     
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    roce_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_n_add_icrc", cal_n_add_icrc, lcl.cal_n_add_icrc);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_icrc", corrupt_icrc, lcl.corrupt_icrc);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
    if (cal_n_add_icrc)
    begin // {
    if (corrupt_icrc)
    hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "icrc", icrc, lcl.icrc, null_a, null_a, "BAD");
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "icrc", icrc, lcl.icrc, null_a, null_a, "GOOD");
    end // } 
  endtask : display_hdr // }

endclass : roce_hdr_class // }
