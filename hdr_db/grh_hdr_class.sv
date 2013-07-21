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
//  hdr class to generate Infiniband Global Routing header (GRH) (InfiniBand Architecture Specification Volume 1 Release 1.2.1)
//  GRH header Format (40B, No trailer)
//  +-------------------+
//  | ipver[3:0]        |
//  +-------------------+
//  | tclass[7:0]       |
//  +-------------------+
//  | flow_label[19:0]  |
//  +-------------------+
//  | payload_len[15:0] |
//  +-------------------+
//  | protocol[7:0]     | 
//  +-------------------+
//  | hoplmt[7:0]       |
//  +-------------------+
//  | sgid[127:0]       |
//  +-------------------+
//  | dgid[127:0]       |
//  +-------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------------+---------------------------------+
//  | Width | Default | Variable             | Description                     |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b0    | corrupt_ipver        | If 1, corrupts ip ipver         |
//  |       |         |                      | (Version != 4'h6)               |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b1    | cal_payload_len      | If 1, calculates payload length |
//  |       |         |                      | Otherwise it will be random     |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b0    | corrupt_payload_len  | If 1, corrupts payload length   |
//  +-------+---------+----------------------+---------------------------------+
//  | 16    | 16'h1   | corrupt_pyld_len_by  | Corrupts paylaod length by value|
//  +-------+---------+----------------------+---------------------------------+
//
// ----------------------------------------------------------------------

class grh_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [3:0]          ipver;
  rand bit [7:0]          tclass;
  rand bit [19:0]         flow_label;
  rand bit [15:0]         payload_len;
  rand bit [7:0]          protocol;
  rand bit [7:0]          hoplmt;
  rand bit [127:0]        sgid;
  rand bit [127:0]        dgid;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  local bit [7:0]         chksm_data [];
  local int               chksm_idx;
  local bit [7:0]         pseudo_chksm_data [];
  local int               pseudo_chksm_idx;
        bit [15:0]        pseudo_chksm;
  rand  bit [15:0]        icrc_sz;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit                corrupt_ipver       = 1'b0;
       bit                cal_payload_len     = 1'b1;
       bit                corrupt_payload_len = 1'b0;
       bit [15:0]         corrupt_pyld_len_by = 16'h1;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~
  constraint grh_hdr_user_constraint
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
    hdr_len == 40;
    trl_len == 0;
  }

  constraint legal_verison
  {
    (corrupt_ipver == 1'b0) -> (ipver == 4'h6);
    (corrupt_ipver == 1'b1) -> (ipver != 4'h6);
  }

  constraint legal_payload_len
  {
    if (cal_payload_len)
    {
        (corrupt_payload_len == 1'b0) -> (payload_len == super.nxt_hdr.total_hdr_len + icrc_sz);
        (corrupt_payload_len == 1'b1) -> (payload_len == super.nxt_hdr.total_hdr_len + icrc_sz + corrupt_pyld_len_by);
    }
    else
        (corrupt_payload_len == 1'b1) -> (payload_len == payload_len + corrupt_pyld_len_by);
    if ((nxt_hdr.hid == BTH_HID) | (prv_hdr.hid == ROCE_HID))
        icrc_sz == 4; 
    else
        icrc_sz == 0; 
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = GRH_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "grh[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {ipver, tclass, flow_label, payload_len, protocol, hoplmt, sgid, dgid};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{ipver, tclass, flow_label, payload_len, protocol, hoplmt, sgid, dgid}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif
    cal_pseudo_chksm;
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
    update_len (index, pkt.size, 40);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {ipver, tclass, flow_label, payload_len, protocol, hoplmt, sgid, dgid} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{ipver, tclass, flow_label, payload_len, protocol, hoplmt, sgid, dgid}} = hdr;
    `endif
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
    grh_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.ipver               = lcl.ipver;
    this.tclass              = lcl.tclass;
    this.flow_label          = lcl.flow_label;
    this.payload_len         = lcl.payload_len;
    this.protocol            = lcl.protocol;
    this.hoplmt              = lcl.hoplmt;
    this.sgid                = lcl.sgid;
    this.dgid                = lcl.dgid;
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.chksm_data          = lcl.chksm_data;
    this.chksm_idx           = lcl.chksm_idx;
    this.pseudo_chksm        = lcl.pseudo_chksm;
    this.icrc_sz             = lcl.icrc_sz;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_ipver       = lcl.corrupt_ipver;
    this.cal_payload_len     = lcl.cal_payload_len;
    this.corrupt_payload_len = lcl.corrupt_payload_len;
    this.corrupt_pyld_len_by = lcl.corrupt_pyld_len_by;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    grh_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   4, "ipver", ipver, lcl.ipver);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "tclass", tclass, lcl.tclass);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  20, "flow_label", flow_label, lcl.flow_label);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  16, "payload_len", payload_len, lcl.payload_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "protocol", protocol, lcl.protocol, null_a, null_a, get_protocol_name(protocol));
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "hoplmt", hoplmt, lcl.hoplmt);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 128, "sgid", sgid, lcl.sgid);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 128, "dgid", dgid, lcl.dgid);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "corrupt_ipver",       corrupt_ipver,       lcl.corrupt_ipver);        
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "cal_payload_len",     cal_payload_len,     lcl.cal_payload_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "corrupt_payload_len", corrupt_payload_len, lcl.corrupt_payload_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    DEF, 016, "corrupt_pyld_len_by", corrupt_pyld_len_by, lcl.corrupt_pyld_len_by);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF, 000, "chksm_data", 0, 0, chksm_data, lcl.chksm_data);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "chksm_idx", chksm_idx, lcl.chksm_idx);
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF, 000, "pseudo_chksm_data", 0, 0, pseudo_chksm_data, lcl.pseudo_chksm_data);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "pseudo_chksm_idx", pseudo_chksm_idx, lcl.pseudo_chksm_idx);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "pseudo_chksm", pseudo_chksm, lcl.pseudo_chksm);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "icrc_sz", icrc_sz, lcl.icrc_sz);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

  // calculate pseudo ipv6 header checksum. It may be required for UDP or TCP
  task cal_pseudo_chksm (); // {
    pseudo_chksm_idx  = 0;
    pseudo_chksm      = 0;
    `ifdef SVFNYI_0
    pseudo_chksm_data = new[40];
    pack_vec          = {32'h0, {8'h0, protocol}, payload_len, sgid, dgid};
    harray.pack_bit(pseudo_chksm_data, pack_vec, pseudo_chksm_idx, 320);
    `else
    pseudo_chksm_data = {>>{32'h0, 8'h0, protocol, payload_len, sgid, dgid}}; 
    `endif
    pseudo_chksm      = crc_chksm.chksm16(pseudo_chksm_data, pseudo_chksm_data.size(), 0, 0, 16'hFFFF);
  endtask : cal_pseudo_chksm // }

endclass : grh_hdr_class // }
