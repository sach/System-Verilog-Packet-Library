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
//  hdr class to generate IPv4 header (RFC 791)
//  IPv4 header Format (20B to 64B, No tariler)
//  +-----------------------+
//  | version[3:0]          | 
//  +-----------------------+
//  | ihl[3:0]              | 
//  +-----------------------+
//  | tos[7:0]              | 
//  +-----------------------+
//  | total_length[15:0]    |
//  +-----------------------+
//  | id[15:0]              | 
//  +----------+----+-------+
//  | reserved | mf | df    |   
//  +----------+----+-------+
//  | frag_offset[12:0]     |
//  +-----------------------+
//  |      ttl[7:0]         |     
//  +-----------------------+
//  | protocol[7:0]         |     
//  +-----------------------+
//  | checksum[15:0]        |
//  +-----------------------+
//  | ip_sa[31:0]           |
//  +-----------------------+
//  | ip_da[31:0]           |
//  +-----------------------+
//  | options[0:39][7:0]    | -> Optional.. depends on ihl
//  +-----------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_ip_version        | If 1, corrupts ip version     |
//  |       |         |                           | (Version != 4'h4)             |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_ihl               | If 1, corrupts ihl (ihl<4'h5) |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_total_length          | If 1, calculates total length |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_total_length      | If 1, corrupts total_length   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'h1   | corrupt_total_len_by      | corrupts total length by value|
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | null_rsvd                 | If 1, all rsvd fields set to 0|
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_mf_df             | If 1, corrupts mf-df mutually |
//  |       |         |                           | exclusive property            |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_frag_offset       | If 1, df-frag property        |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_frag_offset_range | If 1, frag_offset is beyond   |
//  |       |         |                           | legal range.                  |
//  |       |         |                           | (frag_offset<64k-total_length)|   
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_ip_chksm              | If 1, calculates ip checksum  |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_ip_chksm          | If 1, corrupts ip checksum    |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'hFFFF| corrupt_ip_chksm_msk      | Msk used to corrupt ip_chksm  |
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class ipv4_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [3:0]     version;
  rand bit [3:0]     ihl;
  rand bit [7:0]     tos;
  rand bit [15:0]    total_length;
  rand bit [15:0]    id;
  rand bit           reserved;
  rand bit           df;
  rand bit           mf;
  rand bit [12:0]    frag_offset; 
  rand bit [7:0]     ttl;
  rand bit [7:0]     protocol;
  rand bit [15:0]    checksum;
  rand bit [31:0]    ip_sa;
  rand bit [31:0]    ip_da;
  rand bit [7:0]     options[];

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  local bit [7:0]    chksm_data [];
  local int          chksm_idx;
  local bit [7:0]    pseudo_chksm_data [];
  local int          pseudo_chksm_idx;
        bit [15:0]   pseudo_chksm;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           corrupt_ip_version         = 1'b0;
       bit           corrupt_ihl                = 1'b0;
       bit           cal_total_length           = 1'b1;
       bit           corrupt_total_length       = 1'b0;
       bit [15:0]    corrupt_total_len_by       = 16'h1;
       bit           null_rsvd                  = 1'b0;
       bit           corrupt_mf_df              = 1'b0;
       bit           corrupt_frag_offset        = 1'b0;
       bit           corrupt_frag_offset_range  = 1'b0;
       bit           cal_ip_chksm               = 1'b1;
       bit           corrupt_ip_chksm           = 1'b0;
       bit [15:0]    corrupt_ip_chksm_msk       = 16'hffff;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint ipv4_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_protocol
  {
    `LEGAL_PROT_TYPE_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    (ihl inside {[5:15]}) -> hdr_len == ihl*4;
    (ihl < 4'h5)          -> hdr_len == 20;
    trl_len == 0;
  }

  constraint legal_verison
  {
    (corrupt_ip_version == 1'b0) -> (version == 4'h4);
    (corrupt_ip_version == 1'b1) -> (version != 4'h4);
  } 

  constraint legal_ihl
  {
    (corrupt_ihl == 1'b0) -> (ihl inside {[5:16]});
    (corrupt_ihl == 1'b1) ->  (ihl < 4'h5);
  } 
 
  constraint legal_total_length
  {
    if (cal_total_length)
    {
        (corrupt_total_length == 1'b0) -> (total_length == this.total_hdr_len);
        (corrupt_total_length == 1'b1) -> (total_length == this.total_hdr_len + corrupt_total_len_by);
    }
    else
        (corrupt_total_length == 1'b1) -> (total_length == total_length + corrupt_total_len_by);
  }

  constraint legal_reserved
  {
    (null_rsvd) -> reserved == 1'h0;
  }

  constraint legal_mf_df
  {
    (corrupt_mf_df == 1'b0) -> ((mf & df) == 1'b0);
    (corrupt_mf_df == 1'b1) -> ((mf & df) == 1'b1);
  } 

  constraint legal_frag_offset
  {
    if (~corrupt_frag_offset)
        (df == 1) -> (frag_offset == 0); 
    else
    {
        (df == 1);
        (frag_offset != 0);
    }
  } 

  constraint legal_frag_offset_range
  {
    (corrupt_frag_offset_range == 0) -> ((frag_offset >= 0) & (frag_offset < (65536 - total_length)));
  }
 
  constraint legal_checksum
  {
    checksum == 16'h0;
  }

  constraint legal_options_sz
  {
    (ihl inside {[5:15]}) -> (options.size == (ihl-5)*4);
    (ihl < 4'h5)          -> (options.size == 0);
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = IPV4_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "ipv4[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void post_randomize (); // {
    super.post_randomize();
    // Calculate options
    if (ihl > 5)
    begin // {
        if (harray.data_pattern != "RND")
            harray.fill_array(options);
    end // }
  endfunction : post_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    `ifdef SVFNYI_0
    int tmp_idx;
    `endif
    // Calulate ip_chksm, corrupt it if asked
    if (~last_pack)
    begin // {
        if (cal_ip_chksm)
        begin // {
            chksm_data = new[ihl*4];
            chksm_idx  = 0;
            checksum   = 0;
            pack_hdr (chksm_data, chksm_idx, 1'b1);
            checksum = crc_chksm.chksm16(chksm_data, chksm_data.size(), 0, corrupt_ip_chksm, corrupt_ip_chksm_msk);
        end // }
        else
        begin // {
            if (corrupt_ip_chksm)
                checksum ^= corrupt_ip_chksm_msk;
        end // }
    end // }
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {version, ihl, tos, total_length, id, reserved, df, mf,
                frag_offset, ttl, protocol, checksum, ip_sa, ip_da};
    harray.pack_bit (pkt, pack_vec, index, 160);
    if (ihl > 5)
    begin // {
        tmp_idx = index/8;
        harray.pack_array_8(options, pkt, tmp_idx);
        index = tmp_idx * 8;
    end // }
    `else
    if (ihl > 5)
        hdr = {>>{version, ihl, tos, total_length, id, reserved, df, mf,
                  frag_offset, ttl, protocol, checksum, ip_sa, ip_da, options}};
    else
        hdr = {>>{version, ihl, tos, total_length, id, reserved, df, mf,
                  frag_offset, ttl, protocol, checksum, ip_sa, ip_da}};
    harray.pack_array_8(hdr, pkt, index);
    `endif
    cal_pseudo_chksm ();
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
    update_len (index, pkt.size, 20);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, 20);
    {version, ihl, tos, total_length, id, reserved, df, mf,
     frag_offset, ttl, protocol, checksum, ip_sa, ip_da} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, 20);
    {>>{version, ihl, tos, total_length, id, reserved, df, mf,
        frag_offset, ttl, protocol, checksum, ip_sa, ip_da}} = hdr;
    `endif
    hdr_len = ihl * 4;
    if (ihl > 4'd5)
        harray.copy_array (pkt, options, index, (hdr_len - 20));
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[get_hid_from_protocol (protocol)] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_protocol (protocol));
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
    ipv4_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.version                   = lcl.version;
    this.ihl                       = lcl.ihl;
    this.tos                       = lcl.tos;
    this.total_length              = lcl.total_length;
    this.id                        = lcl.id;
    this.reserved                  = lcl.reserved;
    this.df                        = lcl.df;
    this.mf                        = lcl.mf;
    this.frag_offset               = lcl.frag_offset;
    this.ttl                       = lcl.ttl;
    this.protocol                  = lcl.protocol;
    this.checksum                  = lcl.checksum;
    this.ip_sa                     = lcl.ip_sa;
    this.ip_da                     = lcl.ip_da;
    this.options                   = lcl.options;            
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.chksm_data                = lcl.chksm_data;
    this.chksm_idx                 = lcl.chksm_idx;
    this.pseudo_chksm              = lcl.pseudo_chksm;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_ip_version        = lcl.corrupt_ip_version;       
    this.corrupt_ihl               = lcl.corrupt_ihl;              
    this.cal_total_length          = lcl.cal_total_length;         
    this.corrupt_total_length      = lcl.corrupt_total_length;     
    this.corrupt_total_len_by      = lcl.corrupt_total_len_by;     
    this.null_rsvd                 = lcl.null_rsvd;            
    this.corrupt_mf_df             = lcl.corrupt_mf_df;            
    this.corrupt_frag_offset       = lcl.corrupt_frag_offset;      
    this.corrupt_frag_offset_range = lcl.corrupt_frag_offset_range;
    this.cal_ip_chksm              = lcl.cal_ip_chksm;             
    this.corrupt_ip_chksm          = lcl.corrupt_ip_chksm;         
    this.corrupt_ip_chksm_msk      = lcl.corrupt_ip_chksm_msk;     
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    ipv4_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,    DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 004, "version", version, lcl.version);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 004, "ihl", ihl, lcl.ihl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 008, "tos", tos, lcl.tos);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 016, "total_length", total_length, lcl.total_length);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 016, "id", id, lcl.id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 001, "reserved", reserved, lcl.reserved);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 001, "df", df, lcl.df);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 001, "mf", mf, lcl.mf);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 013, "frag_offset", frag_offset, lcl.frag_offset);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 008, "ttl", ttl, lcl.ttl);            
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 008, "protocol", protocol, lcl.protocol, null_a, null_a, get_protocol_name(protocol));
    if (corrupt_ip_chksm)
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 016, "checksum", checksum, lcl.checksum, null_a, null_a, "BAD");
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 016, "checksum", checksum, lcl.checksum, null_a,  null_a, "GOOD");
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 032, "ip_sa", ip_sa, lcl.ip_sa);
    hdis.display_fld (mode, hdr_name, BIT_VEC,   HEX, 032, "ip_da", ip_da, lcl.ip_da);
    if (options.size() !== 0)
    hdis.display_fld (mode, hdr_name, ARRAY,     DEF, 000, "options", 0, 0, options, lcl.options);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {                                 
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_ip_version", corrupt_ip_version, lcl.corrupt_ip_version);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_ihl", corrupt_ihl, lcl.corrupt_ihl);               
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_total_length", cal_total_length, lcl.cal_total_length);          
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_total_length", corrupt_total_length, lcl.corrupt_total_length);      
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "corrupt_total_len_by", corrupt_total_len_by, lcl.corrupt_total_len_by);      
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);             
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_mf_df", corrupt_mf_df, lcl.corrupt_mf_df);             
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_frag_offset", corrupt_frag_offset, lcl.corrupt_frag_offset);       
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_frag_offset_range", corrupt_frag_offset_range, lcl.corrupt_frag_offset_range); 
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_ip_chksm", cal_ip_chksm, lcl.cal_ip_chksm);              
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_ip_chksm", corrupt_ip_chksm, lcl.corrupt_ip_chksm);          
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "corrupt_ip_chksm_msk", corrupt_ip_chksm_msk, lcl.corrupt_ip_chksm_msk);      
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF, 000, "chksm_data", 0, 0, chksm_data, lcl.chksm_data);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "chksm_idx", chksm_idx, lcl.chksm_idx);
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF, 000, "pseudo_chksm_data", 0, 0, pseudo_chksm_data, lcl.pseudo_chksm_data);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "pseudo_chksm_idx", pseudo_chksm_idx, lcl.pseudo_chksm_idx);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "pseudo_chksm", pseudo_chksm, lcl.pseudo_chksm);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

  // calculate pseudo ipv4 header checksum. It may be required for UDP or TCP
  task cal_pseudo_chksm; // {
    bit [15:0] ip_data_length;
    ip_data_length    = total_length - (ihl*4);
    pseudo_chksm_idx  = 0;
    pseudo_chksm      = 0;
    `ifdef SVFNYI_0
    pseudo_chksm_data = new[12];
    pack_vec          = {ip_data_length, {8'h0, protocol}, ip_sa, ip_da};
    harray.pack_bit (pseudo_chksm_data, pack_vec, pseudo_chksm_idx, 96);
    `else
    pseudo_chksm_data = {>>{ip_data_length, 8'h0, protocol, ip_sa, ip_da}}; 
    `endif
    pseudo_chksm      = crc_chksm.chksm16(pseudo_chksm_data, pseudo_chksm_data.size(), 0, 0, corrupt_ip_chksm_msk);
  endtask : cal_pseudo_chksm // }
endclass : ipv4_hdr_class // }
