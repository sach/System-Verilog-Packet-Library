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
//  hdr class to generate GRE (Generic Routing Encapsulation) header.
//  Supports the following RFCs.
//            - RFC 1701 (GRE - Version = 0)
//            - RFC 2637 (Enhanced GRE - Version = 1)
//            - RFC 2784 (Many fields were deprecated from RFC 1701) - Default
//            - RFC 2890 (Key & Sequence number extension to GRE)    
//            - NVGRE Draft                                         
//  GRE header Format (4B to 20B, No trailer)
//  +--------------------------------+
//  |  C   |  R   |  K   |  S   |  s | -> {C, R, s} = 0, K = 1 for version = 1 
//  +------+------+------+------+----+ |  {R, K, S, s} = 0 for RFC 2784. {C, R, S, s} = 0, K = 1 for NVGRE
//  | recur[2:0]  |  A   | flags[3:0]| |  A = 0 for version = 0 (RFC 1701, 2784, 2890, NVGRE) 
//  +-------------+------+-----------+ -> recur & flags always 0. 
//  | version[2:0]                   | -> version = 1 for RFC 2637 else 0
//  +--------------------------------+
//  | protocol[15:0] (etype)         | -> always 0x880B if version = 1, 0x6558 if NVGRE 
//  +--------------------------------+
//  | cheksum[15:0]                  | -> checksum (present if (C | R) = 1) 
//  +--------------------------------+
//  | offset[15:0]                   | -> offset (present if (C | R) = 1). For RFC 2784, 2890 set to 0 
//  +--------------------------------+
//  | key[31:0]                  OR  | -> key (present if K = 1). RFC 1701, 2890  
//  +--------------------------------+
//  | tni[23:0]  | reserved[7:0] OR  | -> Tenenat Network ID(tni), reserved} (present k = 1). NVGRE
//  +--------------------------------+
//  | payload_length[15:0]           | 
//  | call_id[15:0]                  | -> {payload_length, call_id} (present if k = 1). Version = 1
//  +--------------------------------+
//  | sequence_number[31:0]          | -> sequence_number (present if S = 1)
//  +--------------------------------+
//  | ack_number[31:0]               | -> Acknowledge Number (present if A = 1)
//  +--------------------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+------------------------------------------+
//  | Width | Default | Variable                  | Description                              |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | implement_rfc2637         | If 1, GRE is implemneted as per RFC 2637 |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | implement_rfc2784         | If 1, GRE is implemneted as per RFC 2784 |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | implement_rfc2890         | If 1, GRE is implemneted as per RFC 2890 |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | implement_nvgre           | If 1, GRE is implemneted as per NVGRE    |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | corrupt_version           | If 1, corrupts version                   |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b1    | cal_payload_length        | If 1, calculates payload len else random |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | corrupt_payload_length    | If 1, corrupts payload_length            |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 16    | 16'h1   | corrupt_payload_length_by | corrupts payload_length value            |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b1    | cal_chksm                 | If 1, calculates checksum else its random|
//  +-------+---------+---------------------------+------------------------------------------+
//  | 1     | 1'b0    | corrupt_chksm             | If 1, corrupts checksum                  |
//  +-------+---------+---------------------------+------------------------------------------+
//  | 16    | 16'hFFFF| corrupt_chksm_msk         | Msk used to corrupt chksm                |
//  +-------+---------+---------------------------+------------------------------------------+
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
  rand bit [15:0]    offset;      
  rand bit [31:0]    key;
  rand bit [23:0]    tni;
  rand bit [7:0]     reserved;
  rand bit [15:0]    payload_length;
  rand bit [15:0]    call_id;
  rand bit [31:0]    sequence_number;
  rand bit [31:0]    ack_number;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  rand  int          chkoff_len;
  rand  int          key_len;
  rand  int          seq_len;
  rand  int          ack_len;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           implement_rfc2637         = 1'b0; 
       bit           implement_rfc2784         = 1'b0; 
       bit           implement_rfc2890         = 1'b0; 
       bit           implement_nvgre           = 1'b0; 
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
    (C | R ) -> chkoff_len == 4;
    ~(C | R) -> chkoff_len == 0;
    (K)      -> key_len    == 4;
    (~K)     -> key_len    == 0;
    (S)      -> seq_len    == 4;
    (~S)     -> seq_len    == 0;
    (A)      -> ack_len    == 4;
    (~A)     -> ack_len    == 0;
    hdr_len == 4 + chkoff_len + key_len + seq_len + ack_len;
    trl_len == 0;
  }


  constraint legal_CRKSsArecurflags
  {
    (~implement_rfc2637) -> (A == 1'b0);
    (implement_rfc2637 ) -> ((C | R | s) == 1'b0); 
    (implement_rfc2637 ) -> (K == 1'b1);
    (implement_rfc2784 ) -> ((R | K | S | s) == 1'b0); 
    (implement_rfc2890 ) -> ((R | s) == 1'b0); 
    (implement_nvgre   ) -> ((C | R | S | s) == 1'b0); 
    (implement_nvgre   ) -> (K == 1'b1);
    recur == 0;
    flags == 0;
  }


  constraint legal_verison
  {
    if (implement_rfc2637)
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

  constraint legal_offset   
  {
    (implement_rfc2784  | implement_rfc2890) -> (offset == 1'b0); 
  }

  constraint legal_reserved
  {
    reserved == 16'h0;
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

  function void pre_randomize (); // {
    super.pre_randomize();
    if (implement_rfc2637)
    begin // {
        implement_rfc2784 = 1'b0;
        implement_rfc2890 = 1'b0;
        implement_nvgre   = 1'b0;
    end // }
    else if (implement_rfc2784)
    begin // {
        implement_rfc2890 = 1'b0;
        implement_nvgre   = 1'b0;
    end // }
    else if (implement_nvgre)
    begin // {
        implement_rfc2890 = 1'b0;
    end // }
  endfunction : pre_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int gre_idx;
    gre_idx = index;
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {C, R, K, S, s, recur, A, flags, version, etype};
    harray.pack_bit (pkt, pack_vec, index, 32);
    `else
    hdr = {>>{C, R, K, S, s, recur, A, flags, version, etype}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif
    if (C | R)
    begin // {
        `ifdef SVFNYI_0
        pack_vec = {checksum, offset};
        harray.pack_bit (pkt, pack_vec, index, 32);
        `else
        hdr = {>>{checksum, offset}};
        harray.pack_array_8 (hdr, pkt, index);
        `endif
    end // }
    if (K)
    begin // {
        if ((version == 1) | implement_rfc2637)
        begin // {
            `ifdef SVFNYI_0
            pack_vec = {payload_length, call_id};
            harray.pack_bit (pkt, pack_vec, index, 32);
            `else
            hdr = {>>{payload_length, call_id}};
            harray.pack_array_8 (hdr, pkt, index);
            `endif
        end // }
        else if ((etype == eth_etype) | implement_nvgre)
        begin // {
            `ifdef SVFNYI_0
            pack_vec = {tni, reserved};
            harray.pack_bit (pkt, pack_vec, index, 32);
            `else
            hdr = {>>{tni, reserved}};
            harray.pack_array_8 (hdr, pkt, index);
            `endif
        end // }
        else
        begin // {
            `ifdef SVFNYI_0
            pack_vec = key;
            harray.pack_bit (pkt, pack_vec, index, 32);
            `else
            hdr = {>>{key}};
            harray.pack_array_8 (hdr, pkt, index);
            `endif
        end // }
    end // }
    if (S)
    begin // {
        `ifdef SVFNYI_0
        pack_vec = sequence_number;
        harray.pack_bit (pkt, pack_vec, index, 32);
        `else
        hdr = {>>{sequence_number}};
        harray.pack_array_8 (hdr, pkt, index);
        `endif
    end // }
    if (A)
    begin // {
        `ifdef SVFNYI_0
        pack_vec = ack_number;
        harray.pack_bit (pkt, pack_vec, index, 32);
        `else
        hdr = {>>{ack_number}};
        harray.pack_array_8 (hdr, pkt, index);
        `endif
    end // }
    // pack next hdr
    if (~last_pack)
    begin // {
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
        `endif
        this.nxt_hdr.pack_hdr (pkt, index);
    end // }
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
    update_len(index, pkt.size, 4);
    chkoff_len    = 0;
    key_len       = 0;
    seq_len       = 0;
    ack_len       = 0;
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, 4);
    {C, R, K, S, s, recur, A, flags, version, etype} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{C, R, K, S, s, recur, A, flags, version, etype}} = hdr;
    `endif
    if (C | R)
    begin // {
        chkoff_len = 4;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 4);
        {checksum, offset} = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, chkoff_len);
        {>>{checksum, offset}} = hdr;
        `endif
    end // }
    if (K)
    begin // {
        key_len = 4;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 4);
        if ((version == 1) | implement_rfc2637)
            {payload_length, call_id} = pack_vec;
        else if ((etype == eth_etype) | implement_nvgre)
            {tni, reserved} = pack_vec;
        else
            key = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, key_len);
        if ((version == 1) | implement_rfc2637)
            {>>{payload_length, call_id}} = hdr;
        else if ((etype == eth_etype) | implement_nvgre)
            {>>{tni, reserved}} = hdr;
        else
            {>>{key}} = hdr;
        `endif
    end // }
    if (S)
    begin // {
        seq_len = 4;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 4);
        sequence_number = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, seq_len);
        {>>{sequence_number}} = hdr;
        `endif
    end // }
    if (A)
    begin // {
        ack_len = 4;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 4);
        ack_number = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, ack_len);
        {>>{ack_number}} = hdr;
        `endif
    end // }
    hdr_len += chkoff_len + key_len + seq_len + ack_len;
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

  task post_pack (ref bit [7:0] pkt [],
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
  endtask : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
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
    this.implement_rfc2637         = lcl.implement_rfc2637;                
    this.implement_rfc2784         = lcl.implement_rfc2784;                
    this.implement_rfc2890         = lcl.implement_rfc2890;                
    this.implement_nvgre           = lcl.implement_nvgre;                   
    this.corrupt_version           = lcl.corrupt_version;          
    this.cal_payload_length        = lcl.cal_payload_length;       
    this.corrupt_payload_length    = lcl.corrupt_payload_length;   
    this.corrupt_payload_length_by = lcl.corrupt_payload_length_by;
    this.cal_chksm                 = lcl.cal_chksm;                
    this.corrupt_chksm             = lcl.corrupt_chksm;            
    this.corrupt_chksm_msk         = lcl.corrupt_chksm_msk;        
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    gre_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "C", C, lcl.C);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "R", R, lcl.R);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "K", K, lcl.K);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "S", S, lcl.S);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "s", s, lcl.s);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 003, "recur", recur, lcl.recur);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "A", A, lcl.A);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 004, "flags", flags, lcl.flags);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 003, "version", version, lcl.version);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "protocol", etype, lcl.etype, null_a, null_a, get_etype_name(etype));
    if (C | R)                                       
    begin // {                                       
    if (corrupt_chksm)                               
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum, null_a, null_a, "BAD");
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum, null_a, null_a, "GOOD");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "offset", offset, lcl.offset);
    end // }                                         
    if (K)                                           
    begin // {                                       
    if ((version == 1) | implement_rfc2637)
    begin // {                                       
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "payload_length", payload_length, lcl.payload_length);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "call_id", call_id, lcl.call_id);
    end // }                                         
    else if ((etype == eth_etype) | implement_nvgre)
    begin // {                                       
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "tni", tni, lcl.tni);            
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "reserved", reserved, lcl.reserved);
    end // }                                         
    else                                             
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "key", key, lcl.key);
    end // }                                         
    if (S)                                           
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "sequence_number", sequence_number, lcl.sequence_number);
    if (A)                                           
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "ack_number", ack_number, lcl.ack_number);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {                                       
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "implement_rfc2637", implement_rfc2637, lcl.implement_rfc2637);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "implement_rfc2784", implement_rfc2784, lcl.implement_rfc2784);       
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "implement_rfc2890", implement_rfc2890, lcl.implement_rfc2890);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "implement_nvgre", implement_nvgre, lcl.implement_nvgre);          
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_version", corrupt_version, lcl.corrupt_version);          
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_payload_length", cal_payload_length, lcl.cal_payload_length);       
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_payload_length", corrupt_payload_length, lcl.corrupt_payload_length);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "corrupt_payload_length_by", corrupt_payload_length_by,lcl.corrupt_payload_length_by);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_chksm", cal_chksm, lcl.cal_chksm);                
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_chksm", corrupt_chksm, lcl.corrupt_chksm);            
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "corrupt_chksm_msk", corrupt_chksm_msk, lcl.corrupt_chksm_msk);             
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "chkoff_len", chkoff_len, lcl.chkoff_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "key_len", key_len, lcl.key_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "seq_len", seq_len, lcl.seq_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "ack_len", ack_len, lcl.ack_len);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : gre_hdr_class // }
