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
  rand   bit [31:0]        crc;
  rand   bit [15:0]        pad_len;
  rand   bit [7:0]         pad_data [];

  // ~~~~~~~~~~ Contol variables ~~~~~~~~~~
         bit [15:0]        max_plen         = `MAX_PLEN;
         bit [15:0]        min_plen         = `MIN_PLEN;
         bit [15:0]        plen_multiple_of = `PLEN_MULTI;
         bit [15:0]        plen_residue     = 0;
         bit               cal_n_add_crc    = 1'b1;
         bit               corrupt_crc      = 1'b0;
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
    plen == nxt_hdr.total_hdr_len + crc_sz + pad_len;
    total_hdr_len == nxt_hdr.total_hdr_len;
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

  function void pre_randomize (); // {
    if (super) super.pre_randomize();
    crc_sz = (cal_n_add_crc) ? 4 : 0;
  endfunction : pre_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack all the hdrs to pkt
    pkt      = new[this.plen];
    index    = 0;
    this.nxt_hdr.pack_hdr (pkt, index);

    // pad pkt
    if (pad_len != 0)
    begin // {
        if (harray.data_pattern != "RND")
            harray.fill_array(pad_data);
        harray.pack_array_8 (pad_data, pkt, index);
    end // }

    // chop pkt
    if ((chop_plen_to != 0) & (chop_plen_to < (plen - crc_sz)))
    begin // {
        pkt = new[chop_plen_to] (pkt);
        index = (chop_plen_to - crc_sz);
    end // }

    // calculate and append crc
    if (cal_n_add_crc)
    begin // {
        pkt[pkt.size() - 1] = 0;
        pkt[pkt.size() - 2] = 0;
        pkt[pkt.size() - 3] = 0;
        pkt[pkt.size() - 4] = 0;
        crc                 = crc_chksm.crc32(pkt, pkt.size()-4, 0, corrupt_crc);
        hdr                 = {>>{crc}};
        this.nxt_hdr.harray.pack_array_8 (hdr, pkt, index);
    end // }
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    plen      = pkt.size;
    start_off = index;
    // If crc is present, extract crc
    if (cal_n_add_crc)
    begin // {
        crc = {pkt[pkt.size() - 4],
               pkt[pkt.size() - 3],
               pkt[pkt.size() - 2],
               pkt[pkt.size() - 1]};
        pkt = new [pkt.size - 4] (pkt);
    end // }

    // if pad_present, extract pad_data
    if (pad_len != 0)
    begin // {
        index = (pkt.size-pad_len);
        this.nxt_hdr.harray.copy_array (pkt, pad_data, index, pad_len);
        pkt   = new [pkt.size - pad_len] (pkt);
        index = 0;
    end // }

    // unpack all class members
    this.nxt_hdr.unpack_hdr (pkt, index, hdr_q, mode);
    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_unpack = 1'b0); // {
    toh_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Random variables ~~~~~~~~~~
    this.plen             = lcl.plen;
    this.crc              = lcl.crc;
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
    if (~last_unpack)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_unpack);
  endtask : cpy_hdr // }

  // This task displays all the feilds of individual hdrs used
  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    toh_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, "plen",         32, DEF, BIT_VEC, plen, lcl.plen);
    hdis.display_fld (mode, hdr_name, "chop_plen_to", 32, DEF, BIT_VEC, chop_plen_to, lcl.chop_plen_to);
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
    hdis.display_fld (mode, hdr_name, "pad_len", 32, DEF, BIT_VEC,  pad_len, lcl.pad_len);
    if (pad_len != 0)
    hdis.display_fld (mode, hdr_name, "pad_data", 0, DEF, ARRAY, 0, 0, pad_data, lcl.pad_data);
    if (cal_n_add_crc)
    begin // {
    if (corrupt_crc)
    hdis.display_fld (mode, hdr_name, "crc", 32, HEX, BIT_VEC, crc, lcl.crc, '{}, '{}, "BAD");
    else
    hdis.display_fld (mode, hdr_name, "crc", 32, HEX, BIT_VEC, crc, lcl.crc, '{}, '{}, "GOOD");
    end // } 
  endtask : display_hdr // }

endclass : toh_class // }
