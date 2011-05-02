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
//  This hdr_class generates UDP header
//  UDP header Format
//  +-----------------+
//  | src_prt [15:0]  | 
//  +-----------------+
//  | dst_prt [15:0]  | 
//  +-----------------+
//  | length  [15:0]  | 
//  +-----------------+
//  | checksum[15:0]  |
//  +-----------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+---------------------------+-------------------------------+
//  | Width | Default | Variable                  | Description                   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_udp_chksm             | If 1, calculates udp checksum |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b1    | cal_length                | If 1, calculates length       |
//  |       |         |                           | Otherwise it will be random   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 1     | 1'b0    | corrupt_udp_chksm         | If 1, corrupts udp checksum   |
//  +-------+---------+---------------------------+-------------------------------+
//  | 16    | 16'hFFFF| corrupt_udp_chksm_msk     | Msk used to corrupt udp_chksm |
//  +-------+---------+---------------------------+-------------------------------+
//
// ----------------------------------------------------------------------

class udp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand  bit [15:0]    src_prt;
  rand  bit [15:0]    dst_prt;
  rand  bit [15:0]    length;
  rand  bit [15:0]    checksum;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
        bit           cal_length            = 1'b1;
        bit           cal_udp_chksm         = 1'b1;
        bit           corrupt_udp_chksm     = 1'b0;
        bit [15:0]    corrupt_udp_chksm_msk = 16'hffff;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint udp_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_length
  {
    if (cal_length)
    {
        length == this.total_hdr_len;
    }
  }

  constraint legal_hdr_len 
  {
    hdr_len == 8;
  }

  constraint legal_dst_prt
  {
    `LEGAL_UDP_DST_PRT_CONSTRAINTS;
  }

  constraint legal_checksum
  {
    checksum == 16'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = UDP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "udp[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int udp_idx;
    udp_idx = index;
    // making sure checksum is 0, incase pack_hdr was called before radomization
    if (cal_udp_chksm && ~last_pack)
        checksum = 0;
    // pack class members
    hdr = {>>{src_prt, dst_prt, length, checksum}};  
    harray.pack_array_8 (hdr, pkt, index);
    // pack next hdr
    if (~last_pack)
        nxt_hdr.pack_hdr (pkt, index);
    if (~last_pack)
        post_pack (pkt, udp_idx);
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // unpack class members
    hdr_len   = 8;
    start_off = index;
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{src_prt, dst_prt, length, checksum}} = hdr;
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (pkt.size > index)
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_udp_dst_prt (dst_prt));
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
                          int       udp_idx); // {
    bit [7:0]      chksm_data [];
    bit [15:0]     pseudo_chksm;
    int            i;
    ipv4_hdr_class lcl_ip4;
    ipv6_hdr_class lcl_ip6;
    // Calulate udp_chksm, corrupt it if asked
    if (cal_udp_chksm)
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
        harray.copy_array(pkt, chksm_data, udp_idx, (pkt.size - udp_idx));
        if (chksm_data.size%2 != 0)
        begin // {
            chksm_data                      = new [chksm_data.size + 1] (chksm_data);
            chksm_data [chksm_data.size -1] = 8'h00;
        end // }
        checksum = crc_chksm.chksm16(chksm_data, chksm_data.size(), 0, corrupt_udp_chksm, corrupt_udp_chksm_msk, pseudo_chksm);
        pack_hdr (pkt, udp_idx, 1'b1);
    end // }
    else
    begin // {
        if (corrupt_udp_chksm)
        begin // {
            checksum ^= corrupt_udp_chksm_msk;
            pack_hdr (pkt, udp_idx, 1'b1);
        end // }
    end // }
  endfunction : post_pack // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_unpack = 1'b0); // {
    udp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.src_prt               = lcl.src_prt;             
    this.dst_prt               = lcl.dst_prt;
    this.length                = lcl.length;
    this.checksum              = lcl.checksum;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.cal_length            = lcl.cal_length;        
    this.cal_udp_chksm         = lcl.cal_udp_chksm;        
    this.corrupt_udp_chksm     = lcl.corrupt_udp_chksm;    
    this.corrupt_udp_chksm_msk = lcl.corrupt_udp_chksm_msk;
    if (~last_unpack)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_unpack);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    udp_hdr_class lcl;
    $cast (lcl, cmp_cls);
`ifdef DEBUG_CHKSM
    hdis.display_fld (mode, hdr_name, "hdr_len",  16, HEX, BIT_VEC, hdr_len,   lcl.hdr_len);
    hdis.display_fld (mode, hdr_name, "total_hdr_len",  16, HEX, BIT_VEC, total_hdr_len,   lcl.total_hdr_len);
`endif
    hdis.display_fld (mode, hdr_name, "src_prt", 16, HEX, BIT_VEC, src_prt,  lcl.src_prt);
    hdis.display_fld (mode, hdr_name, "dst_prt", 16, HEX, BIT_VEC, dst_prt,  lcl.dst_prt, '{},'{}, get_udp_dst_prt_name(dst_prt));
    hdis.display_fld (mode, hdr_name, "length",  16, HEX, BIT_VEC, length,   lcl.length);
    if (corrupt_udp_chksm)
    hdis.display_fld (mode, hdr_name, "checksum",16, HEX, BIT_VEC, checksum, lcl.checksum,'{},'{}, "BAD");
    else
    hdis.display_fld (mode, hdr_name, "checksum",16, HEX, BIT_VEC, checksum, lcl.checksum,'{},'{}, "GOOD");
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : udp_hdr_class // }
