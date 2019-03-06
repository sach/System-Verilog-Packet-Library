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
//  hdr class to generate Fiber Channel(FC) header
//  FC header Format (28B = 24B hdr + 4B trl)
//  FC header (24B)
//  +-------------------+
//  | r_ctl[7:0]        |
//  +-------------------+
//  | d_id[23:0]        |
//  +-------------------+
//  | cs_ctl_pri[7:0]   |
//  +-------------------+
//  | s_id[23:0]        |
//  +-------------------+
//  | fc_type[7:0]      | 
//  +-------------------+
//  | f_ctl[23:0]       |
//  +-------------------+
//  | seq_id[7:0]       |
//  +-------------------+
//  | df_ctl[7:0]       |
//  +-------------------+
//  | seq_cnt[15:0]     |
//  +-------------------+
//  | ox_id[15:0]       |
//  +-------------------+
//  | rx_id[15:0]       |
//  +-------------------+
//  | parameter[31:0]   |
//  +-------------------+
//  FC Trailer (4B)
//  +-------------------+
//  | fcrc[31:0]        |
//  +-------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+------------------+---------------------------------+
//  | Width | Default | Variable         | Description                     |
//  +-------+---------+------------------+---------------------------------+
//  | 1     | 1'b1    | cal_n_add_fcrc   | Calculate & add CRC to packet   |
//  +-------+---------+------------------+---------------------------------+
//  | 1     | 1'b0    | corrupt_fcrc     | If 1, corrupts CRC              |
//  +-------+---------+------------------+---------------------------------+
//
// ----------------------------------------------------------------------

class fc_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]          r_ctl;
  rand bit [23:0]         d_id;
  rand bit [7:0]          cs_ctl_pri;
  rand bit [23:0]         s_id;
  rand bit [7:0]          fc_type;
  rand bit [23:0]         f_ctl;
  rand bit [7:0]          seq_id;
  rand bit [7:0]          df_ctl;
  rand bit [15:0]         seq_cnt;
  rand bit [15:0]         ox_id;
  rand bit [15:0]         rx_id;
  rand bit [31:0]         fc_parameter;
  rand bit [31:0]         fcrc;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit               cal_n_add_fcrc = 1'b1;
       bit               corrupt_fcrc   = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~
  constraint fc_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == 24;
    (pkt_format == FC) -> trl_len == 0;
    (pkt_format != FC) -> trl_len == 4;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = FC_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "fc[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {r_ctl, d_id, cs_ctl_pri, s_id, fc_type, f_ctl, seq_id, df_ctl, seq_cnt, ox_id, rx_id, fc_parameter};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{r_ctl, d_id, cs_ctl_pri, s_id, fc_type, f_ctl, seq_id, df_ctl, seq_cnt, ox_id, rx_id, fc_parameter}};
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
    // calculate fcrc
   if (trl_len != 0)
   begin // [
        if (cal_n_add_fcrc)
        begin // {
            fcrc = crc_chksm.crc32 (pkt, (total_hdr_len-trl_len), start_off, corrupt_fcrc); 
            // pack class members
            `ifdef SVFNYI_0
            pack_vec = fcrc;
            harray.pack_bit (pkt, pack_vec, index, trl_len*8);
            `else
            hdr = {>>{fcrc}};
            harray.pack_array_8 (hdr, pkt, index);
            `endif
            `ifdef DEBUG_PKTLIB
            $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
            `endif
       end // }
   end // }
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    if (pkt_format == FC) // trl_len = 0, as toh_class will take care of CRC
        update_len(index, pkt.size, 24);
    else
        update_len(index, pkt.size, 24, 4);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {r_ctl, d_id, cs_ctl_pri, s_id, fc_type, f_ctl, seq_id, df_ctl, seq_cnt, ox_id, rx_id, fc_parameter} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{r_ctl, d_id, cs_ctl_pri, s_id, fc_type, f_ctl, seq_id, df_ctl, seq_cnt, ox_id, rx_id, fc_parameter}} = hdr;
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
    // unpack class members - trailer
    if (trl_len != 0)
    begin // {
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, trl_len);
        fcrc = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, trl_len);
        {>>{fcrc}} = hdr;
        `endif
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Unpacking %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index); 
        `endif
    end // }
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    fc_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.r_ctl               = lcl.r_ctl;
    this.d_id                = lcl.d_id;
    this.cs_ctl_pri          = lcl.cs_ctl_pri;
    this.s_id                = lcl.s_id;
    this.fc_type             = lcl.fc_type;
    this.f_ctl               = lcl.f_ctl;
    this.seq_id              = lcl.seq_id;
    this.df_ctl              = lcl.df_ctl;
    this.seq_cnt             = lcl.seq_cnt;
    this.ox_id               = lcl.ox_id;
    this.rx_id               = lcl.rx_id;
    this.fc_parameter        = lcl.fc_parameter;
    this.fcrc                = lcl.fcrc;
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_n_add_fcrc = lcl.cal_n_add_fcrc;   
    this.corrupt_fcrc   = lcl.corrupt_fcrc;     
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    fc_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "r_ctl",        r_ctl       ,lcl.r_ctl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "d_id",         d_id        ,lcl.d_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "cs_ctl_pri",   cs_ctl_pri  ,lcl.cs_ctl_pri);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "s_id",         s_id        ,lcl.s_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "fc_type",      fc_type     ,lcl.fc_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "f_ctl",        f_ctl       ,lcl.f_ctl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "seq_id",       seq_id      ,lcl.seq_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "df_ctl",       df_ctl      ,lcl.df_ctl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  16, "seq_cnt",      seq_cnt     ,lcl.seq_cnt);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  16, "ox_id",        ox_id       ,lcl.ox_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  16, "rx_id",        rx_id       ,lcl.rx_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "fc_parameter", fc_parameter,lcl.fc_parameter);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_n_add_fcrc", cal_n_add_fcrc, lcl.cal_n_add_fcrc);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_fcrc", corrupt_fcrc, lcl.corrupt_fcrc);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
    if (pkt_format != FC)
    begin // {
        if (cal_n_add_fcrc)
        begin // {
            if (corrupt_fcrc)
                hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "fcrc", fcrc, lcl.fcrc, null_a, null_a, "BAD");
            else
                hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "fcrc", fcrc, lcl.fcrc, null_a, null_a, "GOOD");
        end // } 
    end // } 
  endtask : display_hdr // }

endclass : fc_hdr_class // }
