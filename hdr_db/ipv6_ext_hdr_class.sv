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
//  hdr class to generate IPv6 Extension headers (RFC 2460)
// No trailer support, if needed
// Suuports the following header
// - Hop-by-Hop Options
// - Routing (Type 0)
// - Fragment
// - Destination Options

//  IPv6 Hop-by-Hop and Destination options header Format ((hdr_ext_len+1)*8B)
//  +-------------------+
//  | protocol[7:0]     | -> nxt_hdr protocol 
//  +-------------------+
//  | hdr_ext_len[7:0]  |
//  +-------------------+
//  | options[7:0][]    | -> options.size = (hdr_ext_len*8) + 6;
//  +-------------------+
//
// Routing header Format  ((hdr_ext_len+1)*8B)
//  +-------------------+
//  | protocol[7:0]     | -> nxt_hdr protocol 
//  +-------------------+
//  | hdr_ext_len[7:0]  |
//  +-------------------+
//  | routing_type[7:0] |
//  +-------------------+
//  | seg_left[7:0]     |
//  +-------------------+
//  | options[7:0][]    | -> options.size = (hdr_ext_len*8) + 4;
//  +-------------------+
//
// Fragment header Format  ((hdr_ext_len+1)*8B)
//  +-------------------+
//  | protocol[7:0]     | -> nxt_hdr protocol
//  +-------------------+
//  | hdr_ext_len[7:0]  | -> == 0;
//  +-------------------+
//  | frag_offset[12:0] | 
//  +-------------------+
//  | frag_rsvd[1:0]    |
//  +-------------------+
//  | M                 | -> 1 = more fragments; 0 = last fragment.
//  +-------------------+
//  | options[7:0][]    | -> options.size = (hdr_ext_len*8) + 4;
//  +-------------------+
//
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------------+---------------------------------+
//  | Width | Default | Variable             | Description                     |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b0    | null_rsvd            | If 1, rsvd fields set to 0      |
//  +-------+---------+----------------------+---------------------------------+
//
// ----------------------------------------------------------------------

class ipv6_ext_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]          protocol;
  rand bit [7:0]          hdr_ext_len;
  rand bit [7:0]          options[];
  rand bit [7:0]          routing_type;
  rand bit [7:0]          seg_left;    
  rand bit [12:0]         frag_offset; 
  rand bit [1:0]          frag_rsvd;
  rand bit                M;
  rand bit [31:0]         identification;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit                null_rsvd = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~
  constraint ipv6_hdr_user_constraint
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
    hdr_len == (hdr_ext_len + 1) *8;
    trl_len == 0;
    (hid    == IPV6_FRAG_HID) -> hdr_ext_len == 0;
  }

  constraint legal_options
  {
    options.size == (hdr_ext_len*8) + 6;
    (hid ==  IPV6_FRAG_HID) -> {options[0], options[1], options[2], 
                                options[3], options[4], options[5]} == {frag_offset, frag_rsvd, M, identification};
    (hid ==  IPV6_ROUT_HID) -> {options[0], options[1]} == {routing_type, seg_left};
  }
 
  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> frag_rsvd == 2'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no,
                int               hid_ctrl = 0); // {
    super.new (plib);
    this.inst_no = inst_no;
    case (hid_ctrl) // {
      0 : 
      begin // {
          hid    = IPV6_HOPOPT_HID;
          $sformat (hdr_name, "ipv6_hopopts[%0d]",inst_no);
      end // }
      1 : 
      begin // {
          hid    = IPV6_ROUT_HID;
          $sformat (hdr_name, "ipv6_rout[%0d]",inst_no);
      end // }
      2 : 
      begin // {
          hid    = IPV6_FRAG_HID;
          $sformat (hdr_name, "ipv6_frag[%0d]",inst_no);
      end // }
      3 : 
      begin // {
          hid    = IPV6_OPTS_HID;
          $sformat (hdr_name, "ipv6_opts[%0d]",inst_no);
      end // }
    endcase // }
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    int tmp_idx;
    pack_vec = {protocol, hdr_ext_len};
    harray.pack_bit (pkt, pack_vec, index, 16);
    tmp_idx = index/8;
    harray.pack_array_8(options, pkt, tmp_idx);
    index = tmp_idx * 8;
    `else
    hdr = {>>{protocol, hdr_ext_len, options}};
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
    // unpack class members
    update_len (index, pkt.size, (pkt[index+1]+ 1) *8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, 2);
    {protocol, hdr_ext_len} = pack_vec;
    harray.copy_array (pkt, options, index, (hdr_len - 2));
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{protocol, hdr_ext_len, options}} = hdr;
    `endif
    {frag_offset, frag_rsvd, M, identification} = {options[0], options[1], options[2], options[3], options[4], options[5]};
    {routing_type, seg_left} = {options[0], options[1]};
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
    ipv6_ext_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.protocol            = lcl.protocol;
    this.hdr_ext_len         = lcl.hdr_ext_len;
    this.options             = lcl.options;
    this.routing_type        = lcl.routing_type;
    this.seg_left            = lcl.seg_left;    
    this.frag_offset         = lcl.frag_offset; 
    this.frag_rsvd           = lcl.frag_rsvd;
    this.M                   = lcl.M;
    this.identification      = lcl.identification;
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.null_rsvd           = lcl.null_rsvd;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    ipv6_ext_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "protocol", protocol, lcl.protocol, null_a, null_a, get_protocol_name(protocol));
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "hdr_ext_len", hdr_ext_len, lcl.hdr_ext_len);
    if (hid == IPV6_FRAG_HID)
    begin // {
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  13, "frag_offset", frag_offset, lcl.frag_offset);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   2, "frag_rsvd", frag_rsvd, lcl.frag_rsvd);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   1, "M", M, lcl.M);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "identification", identification, lcl.identification);
    end // }
    else if (hid == IPV6_ROUT_HID)
    begin // {
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "routing_type", routing_type, lcl.routing_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "seg_left", seg_left, lcl.seg_left);
    if (options.size() !== 0)
    hdis.display_fld (mode, hdr_name, ARRAY,      DEF, 000, "options", 0, 0, options, lcl.options);
    end // }
    else if (options.size() !== 0)
    hdis.display_fld (mode, hdr_name, ARRAY,      DEF, 000, "options", 0, 0, options, lcl.options);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);          
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : ipv6_ext_hdr_class // }
