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
//  This hdr_class generates CSI-2 D-PHY header
//  D-PHY long pkt Format (hdr_len = 4B, trl_len = 2B (CRC16)
//  +-------------------+
//  |     di[7:0]       |
//  +-------------------+
//  |     wc[15:0]      |
//  +-------------------+
//  |     vcx[1:0]      |
//  +-------------------+
//  |     ecc[5:0]      | 
//  +-------------------+ -             
//  |     data[0]       |  |
//  +-------------------+  |             
//  |     ...           |  |- Payload
//  +-------------------+  |            
//  |     data[n]       |  |
//  +-------------------+ -
//  |     crc[15:0]     |  -> If present. Added in toh hdr and not in this class
//  +-------------------+ -
//  D-PHY short pkt Format (hdr_len = 4B, no Paylod, no crc, no tariler)
//  +-------------------+
//  |     di[7:0]       |
//  +-------------------+
//  |     sph[15:0]     | -> short packet data field instead of WC
//  +-------------------+
//  |     vcx[1:0]      |
//  +-------------------+
//  |     ecc[5:0]      |
//  +-------------------+ -
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_wc                    | If 1, calculates word count   |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_wc                | If 1, corrupts wc             |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'h1   | corrupt_wc_by             | corrupts wc value             |
//  +-------+---------+---------------------------+-------------------------------+
//  | 3     | 2'd0    | corrupt_bits              | 0 -> No corrupt,              |
//  |       |         |                           | 1 -> 1 bit  corruption        |
//  |       |         |                           | 2 -> 2 bits corruption        |
//  |       |         |                           | 3 -> (< 2) bits corruption    |
//  +-------+---------+---------------------------+-------------------------------+
//  | 32    | 32'd0   | corrupt_vector            | which bits to corrupt for ECC |
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class dphy_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]     di;
  rand bit [15:0]    wc;
  rand bit [15:0]    sph;
  rand bit [1:0]     vcx;    
  rand bit [5:0]     ecc;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           cal_wc           = 1'b1;
       bit           corrupt_wc       = 1'b0;
       bit [15:0]    corrupt_wc_by    = 16'h1;
       bit [2:0]     corrupt_bits     = 2'd0;
  rand bit [31:0]    corrupt_vector;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint dphy_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_di
  {
    `LEGAL_DI_TYPE_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
    hdr_len == 4; 
    trl_len == 0; 
  }

  constraint legal_wc
  {
    if (cal_wc)
    {
        (corrupt_wc == 1'b0) -> (wc == this.total_hdr_len - 4 );
        (corrupt_wc == 1'b1) -> (wc == this.total_hdr_len -4 + corrupt_wc_by);
    }
    else
        (corrupt_wc == 1'b1) -> (wc == wc + corrupt_wc_by);
  }

  // calculated in pack_hdr task 
  constraint legal_ecc
  {
    ecc == 0; 
  }

  // which bits to corrupt in case corrupt_bits != 0
  constraint unique_corrupt_vector
  {
    $countones(corrupt_vector) == corrupt_bits;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~
  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = DPHY_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "dphy[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    bit [15:0] tmp_wc;
    bit [25:0] ecc_data_in;
    // finf if it is DPHY Short pkt 
    cal_dphy_spkt;
    if (dphy_spkt)
        tmp_wc = sph;
    else
        tmp_wc = wc;
    // calculate ECC
    ecc_data_in = {vcx,tmp_wc,di};
    ecc = crc_chksm.ecc_32_26(ecc_data_in, corrupt_vector);
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {di,tmp_wc,vcx,ecc};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{di,tmp_wc,vcx,ecc}};
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
    bit [25:0] ecc_data_in;
    bit[5:0]   ecc_cal;
    // unpack class members
    update_len (index, pkt.size, 4);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {di,wc,vcx,ecc} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{di,wc,vcx,ecc}} = hdr;
    `endif
    sph            = wc;
    ecc_data_in    = {vcx,wc,di};
    ecc_cal        = crc_chksm.ecc_32_26(ecc_data_in);
    corrupt_vector = crc_chksm.ecc_32_26_check (ecc, ecc_cal);

    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (get_hid_from_di(di) == EOH_HID)
            super.update_nxt_hdr_info (lcl_class, hdr_q, EOH_HID);
        else if (unpack_en[get_hid_from_di(di)] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_di(di));
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
        cal_dphy_spkt;
    end // }

    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  // Calculate dphy_spkt
  task cal_dphy_spkt(); // {
    if (di inside {[8'h0 : sdphy_max_di]})
        dphy_spkt = 1'b1;
    else
        dphy_spkt = 1'b0;
  endtask : cal_dphy_spkt // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    dphy_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~~~~
    this.di                    = lcl.di;
    this.wc                    = lcl.wc;
    this.sph                   = lcl.sph;
    this.vcx                   = lcl.vcx;    
    this.ecc                   = lcl.ecc;
    // ~~~~~~~~~~ Local variables ~~~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_wc                = lcl.cal_wc;
    this.corrupt_wc            = lcl.corrupt_wc;
    this.corrupt_wc_by         = lcl.corrupt_wc_by;
    this.corrupt_bits          = lcl.corrupt_bits;
    this.corrupt_vector        = lcl.corrupt_vector;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    dphy_hdr_class lcl;
    string         ecc_string;
    int            bit_pos[$];
    $cast (lcl, cmp_cls);
    if (corrupt_vector == 26'h0)
        $sformat (ecc_string, "GOOD");
    else if (corrupt_vector == 26'hDEAD)
        $sformat (ecc_string, "Uncorrectbale ECC errors");
    else
    begin // {
        $sformat (ecc_string, "Corrupted Bit(s) :");
        crc_chksm.pos_1_0 (bit_pos, corrupt_vector);             
        foreach (bit_pos[b_ps])
        begin // {
        if (bit_pos[b_ps] < 26)
            $sformat (ecc_string, "%0s %0d", ecc_string, bit_pos[b_ps]);
        else
            $sformat (ecc_string, "%0s ECC[%0d] ", ecc_string, (bit_pos[b_ps] - 26));
        end // }
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "di",  di,  lcl.di, null_a, null_a, get_di_name(di));
    if (dphy_spkt)
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "sph", sph, lcl.sph);
    else
    begin // {
    if (corrupt_wc)
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "wc",  wc,  lcl.wc, null_a, null_a, "BAD");
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "wc",  wc,  lcl.wc, null_a,  null_a, "GOOD");
    end // }
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 002, "vcx", vcx, lcl.vcx);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 006, "ecc", ecc, lcl.ecc, null_a,  null_a, ecc_string);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_wc", cal_wc, lcl.cal_wc);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_wc",     corrupt_wc, lcl.corrupt_wc);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "corrupt_wc_by",  corrupt_wc_by, lcl.corrupt_wc_by);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 002, "corrupt_bits",   corrupt_bits,  lcl.corrupt_bits);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "corrupt_vector", corrupt_vector,lcl.corrupt_vector);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : dphy_hdr_class // }
