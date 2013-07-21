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
//  This hdr_class generates Locator/ID Separation Protocol (LISP) header
//  (draft-ietf)
//  LISP header Format (8B, No trailer)
//  +------+------+------+------+----+------------+ 
//  |  N   |  L   |  E   |  V   |  I | flags[2:0] |  
//  +------+------+------+------+----+------------+
//  | nonce[23:0]                             OR  | 
//  +----------------------+----------------------+
//  | src_map_ver[11:0]    | dst_map_ver[15:0]    | -> When V = 1'b1
//  +----------------------+----------------------+
//  | lsb[31:0]                               OR  | -> Locator Status Bit 
//  +----------------------+----------------------+
//  | instance_id[23:0]    | lsb[7:0]             | -> When I = 1'b1 
//  +----------------------+----------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+-----------------+---------------------------------+
//  | Width | Default | Variable        | Description                     |
//  +-------+---------+-----------------+---------------------------------+
//  | 1     | 1'b0    | corrupt_N_V     | If 1, corrupts N & V property   |
//  |       |         |                 | i.e. N-V are mutually exclusive |
//  +-------+---------+-----------------+---------------------------------+
//
// ----------------------------------------------------------------------

class lisp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit           N;
  rand bit           L;
  rand bit           E;
  rand bit           V;
  rand bit           I;
  rand bit [2:0]     flags;
  rand bit [23:0]    nonce;
  rand bit [11:0]    src_map_ver;
  rand bit [11:0]    dst_map_ver;
  rand bit [31:0]    lsb;
  rand bit [23:0]    instance_id;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           corrupt_N_V = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint lisp_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
    hdr_len == 8; 
    trl_len == 0; 
  }

  // N & V are mutually exclusive
  constraint legal_N_V
  {
    ~corrupt_N_V -> (N & V) == 1'b0;
     corrupt_N_V -> (N & V) == 1'b1;
  }

  constraint legal_flags
  {
    flags == 3'h0;
  }

  constraint legal_lsb
  {
    (I & L) -> lsb[7:0] == 8'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = LISP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "lisp[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    bit [55:0] tmp_hdr;
    // pack class members
    if (~V)
    tmp_hdr[55:32] = nonce;
    else
    tmp_hdr[55:32] = {src_map_ver, dst_map_ver};
    if (I)
    tmp_hdr[31:0]  = {instance_id, lsb[7:0]};
    else
    tmp_hdr[31:0]  = lsb;
    `ifdef SVFNYI_0
    pack_vec = {N, L, E, V, I, flags, tmp_hdr};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{N, L, E, V, I, flags, tmp_hdr}};
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
    hdr_class  lcl_class;
    bit [7:0]  nxt_ip;
    
    // unpack class members
    update_len (index, pkt.size, 8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {N, L, E, V, I, flags, nonce, lsb} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{N, L, E, V, I, flags, nonce, lsb}} = hdr;
    `endif
    if (~V)
        {src_map_ver, dst_map_ver} = nonce;
    if (I)
        instance_id = lsb[31:8];
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (pkt.size >= index)
            nxt_ip = pkt[index];
        else
            nxt_ip = 0;
        if (unpack_en[IPV4_HID] & (pkt.size > index & (nxt_ip[7:4] == 4'h4)))
            super.update_nxt_hdr_info (lcl_class, hdr_q, IPV4_HID);
        else if (unpack_en[IPV6_HID] & (pkt.size > index & (nxt_ip[7:4] == 4'h6)))
            super.update_nxt_hdr_info (lcl_class, hdr_q, IPV6_HID);
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
    lisp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~~~~
    this.N                     = lcl.N; 
    this.L                     = lcl.L; 
    this.E                     = lcl.E; 
    this.V                     = lcl.V; 
    this.I                     = lcl.I; 
    this.flags                 = lcl.flags; 
    this.nonce                 = lcl.nonce; 
    this.src_map_ver           = lcl.src_map_ver;
    this.dst_map_ver           = lcl.dst_map_ver;
    this.lsb                   = lcl.lsb; 
    this.instance_id           = lcl.instance_id;
    // ~~~~~~~~~~ Local variables ~~~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_N_V           = lcl.corrupt_N_V;        
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    lisp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "N", N, lcl.N); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "L", L, lcl.L); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "E", E, lcl.E); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "V", V, lcl.V); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "I", I, lcl.I); 
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 003, "flags", flags, lcl.flags); 
    if (~V)
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "nonce", nonce, lcl.nonce); 
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 012, "src_map_ver", src_map_ver, lcl.src_map_ver);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 012, "dst_map_ver", dst_map_ver, lcl.dst_map_ver);
    if (I)
    begin // {
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 024, "instance_id", instance_id, lcl.instance_id);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "lsb", lsb[7:0], lcl.lsb[7:0]); 
    end // }
    else
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "lsb", lsb, lcl.lsb); 
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_N_V", corrupt_N_V, lcl.corrupt_N_V);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : lisp_hdr_class // }
