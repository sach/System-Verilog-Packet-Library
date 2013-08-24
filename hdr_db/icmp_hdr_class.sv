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
//  This hdr_class generates Internet Control Message Protocol (ICMP for IPv4 and ICMPv6 for IPv6) header
//  Supports  the following RFC
//            - RFC  792 (Internet control message protocol)
//            - RFC 4443 (ICMPv6 for IPv6 specification)
//  ICMP/ICMPv6 header Format (8B, No trailer)
//  +-------------------+
//  | icmp_type   [7:0] | 
//  +-------------------+
//  | code        [7:0] | 
//  +-------------------+
//  | checksum   [15:0] | 
//  +-------------------+
//  | msg_body   [31:0] | -> Message body contents varies based on icmp_type/code 
//  +-------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_icmp_chksm            | If 1,calculates icmp checksum |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_icmp_chksm        | If 1, corrupts icmp checksum  |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'hFFFF| corrupt_icmp_chksm_msk    | Msk used to corrupt icmp_chksm|
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class icmp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand  bit [7:0]     icmp_type;
  rand  bit [7:0]     code; 
  rand  bit [15:0]    checksum;
  rand  bit [31:0]    msg_body;   

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
        bit           cal_icmp_chksm         = 1'b1;
        bit           corrupt_icmp_chksm     = 1'b0;
        bit [15:0]    corrupt_icmp_chksm_msk = 16'hffff;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint icmp_hdr_user_constraint
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

  constraint legal_checksum
  {
    checksum == 16'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no,
                int               hid_ctrl = 0); // {
    super.new (plib);
    this.inst_no = inst_no;
    case (hid_ctrl) // {
      1 : 
      begin // {
          hid      = ICMPV6_HID;
          $sformat (hdr_name, "icmpv6[%0d]",inst_no);
      end // }
      default : 
      begin // {
          hid      = ICMP_HID;
          $sformat (hdr_name, "icmp[%0d]",inst_no);
      end // }
    endcase // }
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    bit [7:0] cdata [];
    int       icmp_idx;
    // making sure checksum is 0, incase pack_hdr was called before radomization
    if (~last_pack)
    begin // {
        if (cal_icmp_chksm)
        begin // {
            checksum = 0;
            // calculate checksum if its ICMP
            if (hid === ICMP_HID)
            begin // {
                cdata    = new[hdr_len];
                icmp_idx = 0;
                pack_hdr (cdata, icmp_idx, 1'b1);
                checksum = crc_chksm.chksm16(cdata, cdata.size(), 0, corrupt_icmp_chksm, corrupt_icmp_chksm_msk);
            end // }
        end // }
        else if (hid === ICMP_HID)
        begin // {
            if (corrupt_icmp_chksm)
                checksum ^= corrupt_icmp_chksm_msk;
        end // }
    end // }
    icmp_idx = index;
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {icmp_type, code, checksum, msg_body};
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
     hdr = {>>{icmp_type, code, checksum, msg_body}};
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
    // checksum calulation
    if (~last_pack & (hid === ICMPV6_HID))
        post_pack (pkt, icmp_idx);
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    update_len (index, pkt.size, 8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {icmp_type, code, checksum, msg_body} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{icmp_type, code, checksum, msg_body}} = hdr;
    `endif
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[DATA_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
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
                      int       icmp_idx); // {
    bit [7:0]      chksm_data [];
    bit [15:0]     pseudo_chksm;
    int            i, idx;
    ipv4_hdr_class lcl_ip4;
    ipv6_hdr_class lcl_ip6;
    // Calulate icmp_chksm, corrupt it if asked
    if (cal_icmp_chksm)
    begin // {
        for (i = 0; i < this.cfg_id; i++)
        begin // {
            if (super.all_hdr[i].hid == IPV4_HID)
            begin // {
                lcl_ip4 = new (super.plib, `MAX_NUM_INSTS+1);
                $cast (lcl_ip4, super.all_hdr[i]);
                pseudo_chksm = lcl_ip4.pseudo_chksm;
            end // }
            if (super.all_hdr[i].hid == IPV6_HID)
            begin // {
                lcl_ip6 = new (super.plib, `MAX_NUM_INSTS+1);
                $cast (lcl_ip6, super.all_hdr[i]);
                pseudo_chksm = lcl_ip6.pseudo_chksm;
            end // }
        end // }
        `ifdef SVFNYI_0
        idx = icmp_idx/8;
        `else
        idx = icmp_idx;
        `endif
        harray.copy_array(pkt, chksm_data, idx, (pkt.size - icmp_idx));
        if (chksm_data.size%2 != 0)
        begin // {
            chksm_data                      = new [chksm_data.size + 1] (chksm_data);
            chksm_data [chksm_data.size -1] = 8'h00;
        end // }
        checksum = crc_chksm.chksm16(chksm_data, chksm_data.size(), 0, corrupt_icmp_chksm, corrupt_icmp_chksm_msk, pseudo_chksm);
        pack_hdr (pkt, icmp_idx, 1'b1);
    end // }
    else
    begin // {
        if (corrupt_icmp_chksm)
        begin // {
            checksum ^= corrupt_icmp_chksm_msk;
            pack_hdr (pkt, icmp_idx, 1'b1);
        end // }
    end // }
  endtask : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    icmp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.icmp_type              = lcl.icmp_type;             
    this.code                   = lcl.code;             
    this.checksum               = lcl.checksum;
    this.msg_body               = lcl.msg_body;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_icmp_chksm         = lcl.cal_icmp_chksm;        
    this.corrupt_icmp_chksm     = lcl.corrupt_icmp_chksm;    
    this.corrupt_icmp_chksm_msk = lcl.corrupt_icmp_chksm_msk;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    icmp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "icmp_type", icmp_type, lcl.icmp_type);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "code", code, lcl.code);
    if (corrupt_icmp_chksm)                              
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum,null_a,null_a, "BAD");
    else                                                
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "checksum", checksum, lcl.checksum,null_a,null_a, "GOOD");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "msg_body", msg_body, lcl.msg_body);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_icmp_chksm", cal_icmp_chksm, lcl.cal_icmp_chksm);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_icmp_chksm", corrupt_icmp_chksm, lcl.corrupt_icmp_chksm);    
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "corrupt_icmp_chksm_msk", corrupt_icmp_chksm_msk, lcl.corrupt_icmp_chksm_msk);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : icmp_hdr_class // }
