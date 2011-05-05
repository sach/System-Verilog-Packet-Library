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
//  hdr class to generate GRE header
//  GRE header Format
//  +--------------------------------+
//  | C | R | K | S | s | recur[2:0] | -> C, R, K, s all are 0 for version = 1 
//  +---+---+---+---+---+------------+
//  | A | flags[3:0] | version[2:0]  | -> A is 0 for version = 0 
//  +---+------------+---------------+
//  | protocol[15:0] (etype)         | -> always 0x880B if version = 1 
//  +--------------------------------+
//  | cheksum/payload_length[15:0]   | -> version = 0 : checksum (optional),= 1 : payload_length
//  +--------------------------------+
//  | offset/call_id[15:0]           | -> version = 0 : offset (optional),  = 1 : call_id 
//  +--------------------------------+
//  | key[31:0]                      | -> version = 0 : (optional), version = 1 : not present  
//  +--------------------------------+
//  | sequence_number[31:0]          | -> optional
//  +--------------------------------+
//  | ack_number[31:0]               | -> version = 0 : not present,        = 1 : Acknowledge Number(optional)
//  +--------------------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | gre_4b                    | If 1, version = 0 & 4 byte hdr|
//  |       |         |                           | C, R, K, S, s, A all 0        |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | version_1                 | If 1, version = 1, otherwise 0|
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_version           | If 1, corrupts version        |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_payload_length        | If 1, calculates payload len  |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_payload_length    | If 1, corrupts payload_length |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'h1   | corrupt_payload_length_by | corrupts payload_length value |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_chksm                 | If 1, calculates checksum     |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_chksm             | If 1, corrupts checksum       |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'hFFFF| corrupt_chksm_msk         | Msk used to corrupt chksm     |
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class gre_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit           C;
  rand bit           R;
  rand bit           K;
  rand bit           S;
  rand bit           s;
  rand bit [2:0]     recur;
  rand bit           A;
  rand bit [3:0]     flags;
  rand bit [2:0]     version;
  rand bit [15:0]    etype;    // protocol
  rand bit [15:0]    checksum;
  rand bit [15:0]    payload_length;
  rand bit [15:0]    offset;      
  rand bit [15:0]    call_id;
  rand bit [31:0]    key;
  rand bit [31:0]    sequence_number;
  rand bit [31:0]    ack_number;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  rand  int          chkoff_len;
  rand  int          key_len;
  rand  int          seq_len;
  rand  int          ack_len;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           gre_4b                    = 1'b0;
       bit           version_1                 = 1'b0; 
       bit           corrupt_version           = 1'b0; 
       bit           cal_payload_length        = 1'b1; 
       bit           corrupt_payload_length    = 1'b0; 
       bit [15:0]    corrupt_payload_length_by = 16'h1;
       bit           cal_chksm                 = 1'b1; 
       bit           corrupt_chksm             = 1'b0; 
       bit [15:0]    corrupt_chksm_msk         = 16'hFFFF;             

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint gre_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    (C | R | version_1)  -> chkoff_len == 4;
    ~(C ^ R ^ version_1) -> chkoff_len == 0;
    (K)                  -> key_len    == 4;
    (~K)                 -> key_len    == 0;
    (S)                  -> seq_len    == 4;
    (~S)                 -> seq_len    == 0;
    (A)                  -> ack_len    == 4;
    (~A)                 -> ack_len    == 0;
    hdr_len == 4 + chkoff_len + key_len + seq_len + ack_len;
  }


  constraint legal_CRKSsArecurflags
  {
    (version_1 == 1'b0) -> A == 1'b0;
    (version_1 == 1'b1) -> ((C | R | K) == 1'b0); 
    (gre_4b    == 1'b1) -> ((C | R | K | S) == 1'b0); 
    s     == 0;
    recur == 0;
    flags == 0;
  }


  constraint legal_verison
  {
    if (version_1 & ~gre_4b)
    {
      (corrupt_version == 1'b0) -> (version == 3'h1);
      (corrupt_version == 1'b1) -> (version != 3'h1);
    }
    else
    {
      (corrupt_version == 1'b0) -> (version == 3'h0);
      (corrupt_version == 1'b1) -> (version != 3'h0);
    }
  } 

  constraint legal_protocol
  {
    `LEGAL_ETH_TYPE_CONSTRAINTS;
  }
 
  constraint legal_payload_length
  {
    if (cal_payload_length)
    {
        (corrupt_payload_length == 1'b0) -> (payload_length == super.nxt_hdr.total_hdr_len);
        (corrupt_payload_length == 1'b1) -> (payload_length == super.nxt_hdr.total_hdr_len + corrupt_payload_length_by);
    }
    else
        (corrupt_payload_length == 1'b1) -> (payload_length == payload_length + corrupt_payload_length_by);
  }

 
  constraint legal_checksum
  {
    checksum == 16'h0;
  }


  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = GRE_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "gre[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int gre_idx;
    gre_idx = index;
    // pack class members
    hdr = {>>{C, R, K, S, s, recur, A, flags, version, etype}};
    harray.pack_array_8 (hdr, pkt, index);
    if (C | R)
    begin // {
        hdr = {>>{checksum, offset}};
        harray.pack_array_8 (hdr, pkt, index);
    end // }
    if (version_1)
    begin // {
        hdr = {>>{payload_length, call_id}};
        harray.pack_array_8 (hdr, pkt, index);
    end // }
    if (K)
    begin // {
        hdr = {>>{key}};
        harray.pack_array_8 (hdr, pkt, index);
    end // }
    if (S)
    begin // {
        hdr = {>>{sequence_number}};
        harray.pack_array_8 (hdr, pkt, index);
    end // }
    if (A)
    begin // {
        hdr = {>>{ack_number}};
        harray.pack_array_8 (hdr, pkt, index);
    end // }
    // pack next hdr
    if (~last_pack)
        nxt_hdr.pack_hdr (pkt, index);
    if (~last_pack & (C | R))
        post_pack (pkt, gre_idx);
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    hdr_len    = 4;
    chkoff_len = 0;
    key_len    = 0;
    seq_len    = 0;
    ack_len    = 0;
    start_off  = index;
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{C, R, K, S, s, recur, A, flags, version, etype}} = hdr;
    if (C | R)
    begin // {
        chkoff_len = 4;
        harray.copy_array (pkt, hdr, index, chkoff_len);
        {>>{checksum, offset}} = hdr;
    end // }
    if (version == 1)
    begin // {
        chkoff_len = 4;
        harray.copy_array (pkt, hdr, index, chkoff_len);
        {>>{payload_length, call_id}} = hdr;
    end // }
    if (K)
    begin // {
        key_len = 4;
        harray.copy_array (pkt, hdr, index, key_len);
        {>>{key}} = hdr;
    end // }
    if (S)
    begin // {
        seq_len = 4;
        harray.copy_array (pkt, hdr, index, seq_len);
        {>>{sequence_number}} = hdr;
    end // }
    if (A)
    begin // {
        ack_len = 4;
        harray.copy_array (pkt, hdr, index, ack_len);
        {>>{ack_number}} = hdr;
    end // }
    hdr_len += chkoff_len + key_len + seq_len + ack_len;
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (pkt.size > index)
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_etype (etype));
        else
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
    end // }
    // unpack next hdr
    if (~last_unpack)
        this.nxt_hdr.unpack_hdr (pkt, index, hdr_q, mode);
    // update all hdr
    if (mode == SMART_UNPACK)
        super.all_hdr = hdr_q;
  endtask : unpack_hdr // }

  function post_pack (ref bit [7:0] pkt [],
                          int       gre_idx); // {
    bit [7:0] chksm_data [];
    int       idx;
    // Calulate udp_chksm, corrupt it if asked
    if (cal_chksm)
    begin // {
        idx = gre_idx;
        harray.copy_array(pkt, chksm_data, idx, (pkt.size - gre_idx));
        if (chksm_data.size/2 != 0)
        begin // {
            chksm_data                      = new [chksm_data.size + 1] (chksm_data);
            chksm_data [chksm_data.size -1] = 8'h00;
        end // }
        checksum = crc_chksm.chksm16(chksm_data, chksm_data.size(), 0, corrupt_chksm, corrupt_chksm_msk);
        pack_hdr (pkt, gre_idx, 1'b1);
    end // }
    else
    begin // {
        if (corrupt_chksm)
        begin // {
            checksum ^= corrupt_chksm_msk;
            pack_hdr (pkt, gre_idx, 1'b1);
        end // }
    end // }
  endfunction : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_unpack = 1'b0); // {
    gre_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.C                         = lcl.C;
    this.R                         = lcl.R;
    this.K                         = lcl.K;
    this.S                         = lcl.S;
    this.s                         = lcl.s;
    this.recur                     = lcl.recur;
    this.A                         = lcl.A;
    this.flags                     = lcl.flags;
    this.version                   = lcl.version;
    this.etype                     = lcl.etype;
    this.checksum                  = lcl.checksum;
    this.payload_length            = lcl.payload_length;
    this.offset                    = lcl.offset;
    this.call_id                   = lcl.call_id;
    this.key                       = lcl.key;
    this.sequence_number           = lcl.sequence_number;
    this.ack_number                = lcl.ack_number;                      
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.chkoff_len                = lcl.chkoff_len;
    this.key_len                   = lcl.key_len;
    this.seq_len                   = lcl.seq_len;
    this.ack_len                   = lcl.ack_len;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.gre_4b                    = lcl.gre_4b;                   
    this.version_1                 = lcl.version_1;                
    this.corrupt_version           = lcl.corrupt_version;          
    this.cal_payload_length        = lcl.cal_payload_length;       
    this.corrupt_payload_length    = lcl.corrupt_payload_length;   
    this.corrupt_payload_length_by = lcl.corrupt_payload_length_by;
    this.cal_chksm                 = lcl.cal_chksm;                
    this.corrupt_chksm             = lcl.corrupt_chksm;            
    this.corrupt_chksm_msk         = lcl.corrupt_chksm_msk;        
    if (~last_unpack)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_unpack);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    gre_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, "C",              01, BIN, BIT_VEC, C,              lcl.C);
    hdis.display_fld (mode, hdr_name, "R",              01, BIN, BIT_VEC, R,              lcl.R);
    hdis.display_fld (mode, hdr_name, "K",              01, BIN, BIT_VEC, K,              lcl.K);
    hdis.display_fld (mode, hdr_name, "S",              01, BIN, BIT_VEC, S,              lcl.S);
    hdis.display_fld (mode, hdr_name, "s",              01, BIN, BIT_VEC, s,              lcl.s);
    hdis.display_fld (mode, hdr_name, "recur",          03, HEX, BIT_VEC, recur,          lcl.recur);
    hdis.display_fld (mode, hdr_name, "A",              01, BIN, BIT_VEC, A,              lcl.A);
    hdis.display_fld (mode, hdr_name, "flags",          04, HEX, BIT_VEC, flags,          lcl.flags);
    hdis.display_fld (mode, hdr_name, "version",        03, HEX, BIT_VEC, version,        lcl.version);
    hdis.display_fld (mode, hdr_name, "protocol",       16, HEX, BIT_VEC, etype   ,       lcl.etype, '{}, '{}, get_etype_name(etype));
    if (C | R)
    begin // {
    if (corrupt_chksm)
    hdis.display_fld (mode, hdr_name, "checksum",       16, HEX, BIT_VEC, checksum,       lcl.checksum, '{}, '{}, "BAD");
    else
    hdis.display_fld (mode, hdr_name, "checksum",       16, HEX, BIT_VEC, checksum,       lcl.checksum, '{}, '{}, "GOOD");
    hdis.display_fld (mode, hdr_name, "offset",         16, HEX, BIT_VEC, offset,         lcl.offset);
    end // }
    if ((version == 1) | version_1)
    begin // {
    hdis.display_fld (mode, hdr_name, "payload_length", 16, HEX, BIT_VEC, payload_length, lcl.payload_length);
    hdis.display_fld (mode, hdr_name, "call_id",        16, HEX, BIT_VEC, call_id,        lcl.call_id);
    end // }
    if (K)
    hdis.display_fld (mode, hdr_name, "key",            32, HEX, BIT_VEC, key,            lcl.key);
    if (S)
    hdis.display_fld (mode, hdr_name, "sequence_number",32, HEX, BIT_VEC, sequence_number,lcl.sequence_number);
    if (A)
    hdis.display_fld (mode, hdr_name, "ack_number",     32, HEX, BIT_VEC, ack_number,     lcl.ack_number);
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : gre_hdr_class // }
