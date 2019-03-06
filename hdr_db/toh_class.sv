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
//  Top header class. This class is always present.
//  This class sets top level parameters like plen for the pkts
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+------------------+-----------------------------------+
//  | Width | Default | Variable         | Description                       |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | random  | plen             | Total  Packet length              |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 2048    | max_plen         | Maximum  Packet length            |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 0       | min_plen         | Miminum  Packet length            |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 1       | plen_multiple_of | Total plen should be multiple of  |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 0       | plen_residue     | Total plen remainder              |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 0       | chop_plen_to     | Chop the pkt to this length       |
//  |       |         |                  | If 0, don't chop the packet       |
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 1       | min_chop_len     | chop_plen_to = 0 | >= min_chop_len|
//  +-------+---------+------------------+-----------------------------------+
//  | 16    | 0       | pad_len          | Append Pad to the pkt             |
//  |       |         |                  | If 0, don't pad the packet        |
//  +-------+---------+------------------+-----------------------------------+
//  | 8 []  | -       | pad_data []      | Pad data                          |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b1    | cal_n_add_crc    | Calculate & add CRC to packet     |
//  +-------+---------+------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_crc      | If 1, corrupts CRC                |
//  +-------+---------+------------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class toh_class extends hdr_class; // {

  // ~~~~~~~~~~ Random variables ~~~~~~~~~~
  rand   bit [15:0]        plen;                         
  rand   bit [31:0]        crc32;       
  rand   bit [15:0]        crc16;
  rand   bit [15:0]        pad_len;
  rand   bit [7:0]         pad_data [];

  // ~~~~~~~~~~ Contol variables ~~~~~~~~~~
         bit               cal_n_add_crc    = 1'b1;
         bit               corrupt_crc      = 1'b0;
         bit [15:0]        max_plen         = `MAX_PLEN;
         bit [15:0]        min_plen         = `MIN_PLEN;
         bit [15:0]        plen_multiple_of = `PLEN_MULTI;
         bit [15:0]        plen_residue     = 0;
         int               chop_plen_to     = 0;
         int               min_chop_plen    = `MIN_CHOP_LEN;
         bit [15:0]        max_pad_len      = `MAX_PAD_LEN;
         bit [15:0]        usr_pad          = 0;                         
         bit               rnd_pad_en       = 1'b0;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  local  int               crc_sz          = 4;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint top_hdr_user_constraint
  {
  }

  constraint legal_plen
  {
    plen >= min_plen;
    plen <= max_plen;
    (plen % plen_multiple_of) == plen_residue;
    plen == nxt_hdr.total_hdr_len + pad_len;
    total_hdr_len == nxt_hdr.total_hdr_len;
    hdr_len  ==  0; 
    hdr_len  ==  0; 
    trl_len  ==  0; 
    start_off == 0;
  }

  constraint legal_rnd_pad
  {
     (rnd_pad_en   == 1'b1) -> pad_len inside { [16'd0 : max_pad_len] };
     (rnd_pad_en   == 1'b0) -> pad_len == usr_pad;
     pad_data.size == pad_len;
  }

  constraint legal_chop_plen
  {
    (chop_plen_to == 0) ||
    (chop_plen_to >= (min_chop_plen + crc_sz));
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib); // {
    super.new (plib);
    hid          = TOP_HID;
    this.inst_no = 0;
    $sformat (hdr_name, "toh");
    this.prv_hdr.rand_mode (0);
    this.harray.data_pattern = "FIX";
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int i; 
    `ifdef SVFNYI_0
    bit [`VEC_SZ-1:0] tmp_vec;
    `endif

    // pack all the hdrs to pkt
    pkt      = new[this.plen];
    index    = 0;
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
    `endif
    this.nxt_hdr.pack_hdr (pkt, index);

    // pad pkt
    if (pad_len != 0)
    begin // {
        if (harray.data_pattern != "RND")
            harray.fill_array(pad_data);
        harray.pack_array_8 (pad_data, pkt, index);
    end // }

    // CRC will get appended here. Get crc_sz if CRC need to be appended
    crc_sz = get_crc_sz;
    plen += crc_sz;
    pkt   = new [this.plen] (pkt);

    // chop pkt
    if ((chop_plen_to != 0) & (chop_plen_to < (plen - crc_sz)))
    begin // {
        pkt = new[chop_plen_to] (pkt);
        `ifdef SVFNYI_0
        index = (chop_plen_to - crc_sz) * 8;
        `else
        index = (chop_plen_to - crc_sz);
        `endif
    end // }

    // calculate and append crc
    if (cal_n_add_crc & (crc_sz != 0))
    begin // {
        for (i = crc_sz; i > 0; i--)
            pkt[pkt.size() - crc_sz] = 0;
        if (crc_sz == 4)
        begin // {
            crc32   = crc_chksm.crc32(pkt, pkt.size()-crc_sz, 0, corrupt_crc);
            `ifdef SVFNYI_0
            tmp_vec = crc32;
            this.nxt_hdr.harray.pack_bit(pkt, tmp_vec, index, crc_sz*8);
            `else
            hdr     = {>>{crc32}};
            this.nxt_hdr.harray.pack_array_8 (hdr, pkt, index);
            `endif
        end // }
        else
        begin // {
            crc16   = crc_chksm.crc32(pkt, pkt.size()-crc_sz, 0, corrupt_crc);
            `ifdef SVFNYI_0
            tmp_vec = crc16;
            this.nxt_hdr.harray.pack_bit(pkt, tmp_vec, index, crc_sz*8);
            `else
            hdr     = {>>{crc16}};
            this.nxt_hdr.harray.pack_array_8 (hdr, pkt, index);
            `endif
        end // }
    end // }
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Done Packing %s index %0d", hdr_name, index);
    `endif

  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    int        idx_eoh = 0;
    data_class lcl_data;

    update_len (index, plen, 0);
    plen    = pkt.size;

    // unpack all class members
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Unpacking %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
    `endif
    this.nxt_hdr.unpack_hdr (pkt, index, hdr_q, mode);
    idx_eoh = index;

    // If crc is present, extract crc
    if (cal_n_add_crc)
    begin // {
        crc_sz = get_crc_sz;
        crc32  = {pkt[pkt.size() - 4],
                  pkt[pkt.size() - 3],
                  pkt[pkt.size() - 2],
                  pkt[pkt.size() - 1]};
        crc16  = {pkt[pkt.size() - 2],
                  pkt[pkt.size() - 1]};
        index  = pkt.size - crc_sz;
    end // }

    // if pad_present, extract pad_data
    if (pad_len != 0)
    begin // {
        index = (pkt.size-pad_len);
        this.nxt_hdr.harray.copy_array (pkt, pad_data, index, pad_len);
        pkt   = new [pkt.size - pad_len] (pkt);
        index  = pkt.size;
    end // }

    // adjusting data[0].data_len due to CRC and pad
    if (idx_eoh > index)
    begin // {
        foreach (hdr_q[hdr_ls])
        begin // {
            if ((hdr_q[hdr_ls].hid == DATA_HID) & (hdr_q[hdr_ls].hdr_len > 0))
            begin // {
                lcl_data= new (plib, `MAX_NUM_INSTS+1);
                $cast (lcl_data, hdr_q[hdr_ls]);
                if (lcl_data.data_len > (idx_eoh - index))
                begin // {
                    lcl_data.data_len     -= (idx_eoh - index);
                    lcl_data.hdr_len       = lcl_data.data_len; 
                    lcl_data.total_hdr_len = lcl_data.data_len; 
                    lcl_data.data          = new [lcl_data.data_len] (lcl_data.data);
                end // }
            end // }
        end // }  
    end // }
    
    `ifdef DEBUG_PKTLIB
    $display ("    pkt_lib : Done Unpacking %s  index %0d", hdr_name, index);
    `endif

    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    toh_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Random variables ~~~~~~~~~~
    this.plen             = lcl.plen;
    this.crc32            = lcl.crc32;
    this.crc16            = lcl.crc16;
    this.pad_len          = lcl.pad_len;
    this.pad_data         = lcl.pad_data;
    // ~~~~~~~~~~ Contol variables ~~~~~~~~~~
    this.max_plen         = lcl.max_plen;        
    this.min_plen         = lcl.min_plen;        
    this.plen_multiple_of = lcl.plen_multiple_of;
    this.plen_residue     = lcl.plen_residue;    
    this.cal_n_add_crc    = lcl.cal_n_add_crc;   
    this.corrupt_crc      = lcl.corrupt_crc;     
    this.chop_plen_to     = lcl.chop_plen_to;    
    this.min_chop_plen    = lcl.min_chop_plen;   
    this.max_pad_len      = lcl.max_pad_len;     
    this.usr_pad          = lcl.usr_pad;         
    this.rnd_pad_en       = lcl.rnd_pad_en;      
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  // This task displays all the feilds of individual hdrs used
  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    string crc_string;
    toh_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Random Variables ~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "plen", plen, lcl.plen);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "chop_plen_to", chop_plen_to, lcl.chop_plen_to);
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "pad_len", pad_len, lcl.pad_len);
    if (pad_len != 0)
    hdis.display_fld (mode, hdr_name, ARRAY,      DEF, 000,  "pad_data", 0, 0, pad_data, lcl.pad_data);
    if (cal_n_add_crc)
    begin // {
    if (corrupt_crc)
        crc_string = "BAD"; 
    else
        crc_string = "GOOD"; 
    if (crc_sz == 4)
    hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "crc32", crc32, lcl.crc32, null_a, null_a, crc_string);
    else if (crc_sz == 2)
    hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 016, "crc16", crc16, lcl.crc16, null_a, null_a, crc_string);
    end // } 
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_n_add_crc", cal_n_add_crc, lcl.cal_n_add_crc);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_crc", corrupt_crc, lcl.corrupt_crc);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "max_plen", max_plen, lcl.max_plen);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "min_plen", min_plen, lcl.min_plen);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "plen_multiple_of", plen_multiple_of, lcl.plen_multiple_of);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "plen_residue", plen_residue, lcl.plen_residue);    
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "chop_plen_to", chop_plen_to, lcl.chop_plen_to);    
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "min_chop_plen", min_chop_plen, lcl.min_chop_plen);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "max_pad_len", max_pad_len, lcl.max_pad_len);     
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "usr_pad", usr_pad, lcl.usr_pad);                 
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "rnd_pad_en", rnd_pad_en, lcl.rnd_pad_en);      
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "crc_sz", crc_sz, lcl.crc_sz);
    end // }
  endtask : display_hdr // }

endclass : toh_class // }
