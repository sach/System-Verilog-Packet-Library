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
//  This hdr_class generates the IPSEC header. (RFC 2406)
//  IPSEC header format (16B)
//   +-----------------------+
//   |  spi[31:0]            | 
//   +-----------------------+
//   |  seq_num[31:0]        | 
//   +-----------------------+
//   |  iv[63:0]             | 
//   +-----------------------+
//
//  IPSEC trailer format (ICV + (Pad Len + 2)B)
//   +-----------------------+
//   |  pad [0 to 3 Bytes]   | 
//   +-----------------------+
//   |  pad_len[7:0]         | 
//   +-----------------------+
//   |  protocol[7:0]        | 
//   +-----------------------+
//
// ----------------------------------------------------------------------
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+--------------------+-----------------------------------+
//  | Width | Default | Variable           | Description                       |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b1    | process_ae         | If 1, add ICV and optionally enc  |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b1    | enc_en             | If 1, encrypt the data            |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | null_rsvd          | If 1, all rsvd fields set to 0    |
//  +-------+---------+--------------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class ipsec_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [31:0]  spi;
  rand bit [31:0]  seq_num;
  rand bit [63:0]  iv;
  rand bit [7:0]   pad [];
  rand bit [7:0]   pad_len;
  rand bit [7:0]   protocol;
  rand bit [7:0]   icv [];
  rand bit [7:0]   rsvd;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  local int i;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit        process_ae          = 1'b1;
       bit        ipsec_type          = 1'b0;
       bit        enc_en              = 1'b1;
       bit        null_rsvd           = 1'b0;

  // ~~~~~~~~~~ IPsec Programming variables ~~~~~~~~~~
       bit [7:0]   auth_adjust        = 0; 
       bit [127:0] key                = 0;
       bit [31:0]  iv_offset          = 0;

  // ~~~~~~~~~~ Local IPSec related variables ~~~~~~~~~~
       int         auth_st            = 0;
       int         auth_sz            = 0;
       int         auth_only          = 0;
       int         enc_sz             = 0;
       int         sectag_sz          = 16;
  rand int         icv_sz             = 16;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint ipsec_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
    total_hdr_len % 4 == 0;
  }

  constraint legal_protocol
  {
    `LEGAL_PROT_TYPE_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
     process_ae -> icv_sz    == 16;
    ~process_ae -> icv_sz    == 0;
    pad_len inside {[0:max_ipsec_pad]};
    icv.size == icv_sz;
    trl_len  == 2 + pad_len + icv_sz;
    hdr_len  ==  sectag_sz;
  }

  constraint legal_iv
  {
    (ipsec_type == 1'b1) -> iv == {protocol, rsvd, seq_num};
  }

  constraint legal_pad
  {
    pad.size == pad_len;
    (pad_len > 0 ) -> {foreach (pad[pad_ls]) pad [pad_ls] == 8'h0;} 
  }

  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> rsvd == 8'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = IPSEC_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "ipsec[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void pre_randomize (); // {
    super.pre_randomize();
    `ifdef NO_PROCESS_AE
        process_ae  = 1'b0;
    `endif
  endfunction : pre_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int pkt_ptr;

    // pack class members
    pkt_ptr = index;
    `ifdef SVFNYI_0
    pack_vec = {spi, seq_num, iv};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{spi, seq_num, iv}};
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

    // pack trailer
    `ifdef SVFNYI_0
    pack_vec = {{pad_len*8{1'b0}}, pad_len, protocol};
    harray.pack_bit (pkt, pack_vec, index, (pad_len+2)*8);
    `else
    hdr = {>>{pad, pad_len, protocol}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif

    // post_pack task to encrypt and add ICV to packet
    if (process_ae)
    begin // {
        post_pack (pkt, pkt_ptr);
        `ifdef SVFNYI_0
        index += (icv_sz * 8);
        `else
        index += icv_sz;
        `endif
    end // }
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    int       pkt_ptr;
    // unpack class members
    pkt_ptr       = index;
    sectag_sz     = 16;
    update_len (index, pkt.size, 16);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, sectag_sz);
    {spi, seq_num, iv} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, sectag_sz);
    {>>{spi, seq_num, iv}} = hdr;
    `endif

    // decrypt pkt and remove icv from packet - trl_len is 0 as icv and trailer is removed
    if (process_ae)
    begin // {
        trl_len = 0;
        post_pack (pkt, pkt_ptr, 0);
    end // }
    else
    begin // {
        // Unpack IPSEC trailer from the packet
        protocol = pkt[pkt.size - 1];
        pad_len  = pkt[pkt.size - 2];
        trl_len  = pad_len + 2;
    end // }

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

  task post_pack (ref   bit [7:0] pkt [],
                  input int       index,
                  input int       enc_dcr = 1); // {
    bit [7:0]     out_pkt [];
    bit [31:0]    iv1;
    bit [31:0]    iv2;
    int           out_plen;
    int           avl_len;
    toh_class     lcl_toh;

    // copying original pkt
    if (enc_dcr == 1)
    begin // {
        super.plib.pkt_modified = 1'b1;
        super.plib.org_pkt      = pkt;
    end // }

    // setting up auth and enc related parameter
    auth_st     = index;
    auth_sz     = sectag_sz;
    if (enc_dcr == 1)
    begin // {
        avl_len = index + super.nxt_hdr.total_hdr_len;
        enc_sz  = super.nxt_hdr.total_hdr_len;
    end // }
    else
    begin // {
        avl_len = pkt.size - icv_sz;
        lcl_toh = new (super.plib);
        $cast (lcl_toh, super.all_hdr[i]);
        if (lcl_toh.cal_n_add_crc)
            avl_len = pkt.size - icv_sz - 4;
        else
            avl_len = pkt.size - icv_sz;
        enc_sz  = avl_len - index;

    end // }
    if ((auth_sz + auth_adjust) > (avl_len - auth_st))
        auth_sz = avl_len - auth_st;
    else
        auth_sz += auth_adjust;
    if (enc_sz > auth_adjust)
        enc_sz  -= auth_adjust;
    else
        enc_sz   = 0;
    auth_only   = !enc_en;

    // dpi call to enc/dec and authenticate pkt
    `ifndef NO_PROCESS_AE
    pkt     = new [avl_len] (pkt); 
    out_pkt = new [avl_len + icv_sz];
    iv1     = {iv_offset, iv[63:32]};
    iv2     = iv[31:0];
    gcm_crypt (key,
               iv1,
               iv2,
               auth_only,
               auth_st,
               auth_sz,
               enc_dcr,
               enc_sz,
               pkt,
               out_pkt,
               out_plen);
    `endif
    index = out_pkt.size - 16;
    if (enc_dcr == 1)
        pkt = new[super.plib.org_pkt.size] (out_pkt);
    else
    begin // {
        // Removing ICV from the packet 
        pkt = new[index] (out_pkt);
        // Removing IPSEC trailer from the packet
        protocol = pkt[out_pkt.size - 1];
        pad_len  = pkt[out_pkt.size - 2];
        index   -= (pad_len + 2); 
        pkt = new[index] (pkt);
    end // }
    harray.copy_array (out_pkt, icv, index, 16);
    out_pkt.delete();
  endtask : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    ipsec_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.spi         = lcl.spi;
    this.seq_num     = lcl.seq_num;
    this.iv          = lcl.iv;
    this.pad         = lcl.pad;
    this.pad_len     = lcl.pad_len;
    this.protocol    = lcl.protocol;
    this.icv         = lcl.icv;
    this.rsvd        = lcl.rsvd;    
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.i           = lcl.i;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.process_ae  = lcl.process_ae;
    this.ipsec_type  = lcl.ipsec_type;
    this.enc_en      = lcl.enc_en;
    this.null_rsvd   = lcl.null_rsvd;
    // ~~~~~~~~~~ IPsec Programming variables ~~~~~~~~~~
    this.auth_adjust = lcl.auth_adjust; 
    this.key         = lcl.key;         
    this.iv_offset   = lcl.iv_offset;   
    // ~~~~~~~~~~ Local IPSec related variables ~~~~~~~~~~
    this.auth_st     = lcl.auth_st;   
    this.auth_sz     = lcl.auth_sz;   
    this.auth_only   = lcl.auth_only; 
    this.enc_sz      = lcl.enc_sz;    
    this.sectag_sz   = lcl.sectag_sz; 
    this.icv_sz      = lcl.icv_sz;    
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    ipsec_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, STRING,     HEX,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ IPSEC Header ~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "spi", spi, lcl.spi);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "seq_num", seq_num, lcl.seq_num);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    DEC,  64, "iv", iv, lcl.iv);
    hdis.display_fld (mode, hdr_name, STRING,     HEX,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ IPSEC Trailer ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, ARRAY,      DEF,   0, "pad", 0, 0, pad, lcl.pad);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "pad_len", pad_len, lcl.pad_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "protocol", protocol, lcl.protocol);
    if (process_ae)
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     HEX,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Encryption Related ~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF,  32, "auth_st", auth_st, lcl.auth_st);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF,  32, "auth_sz", auth_sz, lcl.auth_sz);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEC,   8, "auth_adjust", auth_adjust, lcl.auth_adjust);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF,  32, "enc_en", enc_en, lcl.enc_en);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF,  32, "ipsec_type", ipsec_type, lcl.ipsec_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF,  32, "enc_sz", enc_sz, lcl.enc_sz);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX,  32, "iv_offset", iv_offset, lcl.iv_offset);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 128, "key", key, lcl.key);
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF,   0, "icv", 0, 0, icv, lcl.icv);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "process_ae", process_ae, lcl.process_ae);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd",  null_rsvd,  lcl.null_rsvd);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : ipsec_hdr_class // }
