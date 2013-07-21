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
//  hdr class to generate ARP (Address Resolution Protocol) header.
//  Supports the following RFCs.
//            - RFC  826 (Ethernet Address Resolution Protocol)
//            - RFC  903 (Reversible Address Resolution Protocol) (Obsolete) 
//            - RFC 2390 (Inverse Address Resolution Protocol)
//  ARP, RARP, InvArp header format (hdr_len == 2(hlen + plen) + 8B), trl_len = 0)
//  (RARP has different ethertype)
//  +-------------+
//  | htype[15:0] | -> Hardware Type (Ethernet is 1) 
//  +-------------+
//  | ptype[15:0] | -> Protocol Type (for IPV4, 0x0800) 
//  +-------------+
//  | hlen[7:0]   | -> Hardware Address Length in Octets (6 if htype is 1)
//  +-------------+
//  | plen[7:0]   | -> Protocl Address Length in Octets (4 if ptype is IPV4)
//  +-------------+
//  | opcode[15:0]| 
//  +-------------+
//  | sha[][7:0]  | -> Source hardware address. Variable length based on hlen
//  +-------------+
//  | spa[][7:0]  | -> Source protocol address. Variable length based on plen
//  +-------------+
//  | dha[][7:0]  | -> Destination hardware address. Variable length based on hlen
//  +-------------+
//  | dpa[][7:0]  | -> Destination protocol address. Variable length based on plen
//  +-------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------+------------------------------------+
//  | Width | Default | Variable       | Description                        |
//  +-------+---------+----------------+------------------------------------+
//  | 1     | 1'b1    | arp_htype_eth  | If 1, htype is Ethernet            |
//  +-------+---------+----------------+------------------------------------+
//  | 1     | 1'b1    | arp_ptype_ipv4 | If 1, ptype is IPv4.               |
//  |       |         |                | (arp_htype_eth should be 1)        |
//  +-------+---------+----------------+------------------------------------+
// 
// ----------------------------------------------------------------------

class arp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [15:0]        htype;
  rand bit [15:0]        ptype;
  rand bit [7:0]         hlen;
  rand bit [7:0]         plen;
  rand bit [15:0]        opcode;
  rand bit [7:0]         sha[];
  rand bit [7:0]         spa[];
  rand bit [7:0]         dha[];
  rand bit [7:0]         dpa[];

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
                                                                               
  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit               arp_htype_eth  = 1'b1;
       bit               arp_ptype_ipv4 = 1'b1;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint arp_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == 8 + 2*hlen + 2*plen;
    trl_len == 0;
  }

  constraint legal_htype
  {
    (arp_htype_eth) -> htype == 16'h1;
  }
  
  constraint legal_ptype
  {
    (arp_htype_eth & arp_ptype_ipv4) -> ptype == ipv4_etype;
  }

  constraint legal_hlen 
  {
    (arp_htype_eth & arp_ptype_ipv4) -> hlen  == 8'h6;
  }

  constraint legal_plen 
  {
    (arp_htype_eth & arp_ptype_ipv4) -> plen  == 8'h4;
  }

  constraint legal_sha_dha
  {
    sha.size == hlen;
    dha.size == hlen;
  }

  constraint legal_spa_dpa
  {
    spa.size == plen;
    dpa.size == plen;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no,
                int               hid_ctrl = 0); // {
    super.new (plib);
    this.inst_no = inst_no;
    case (hid_ctrl) // {
      1 : // {
      begin // {
          hid      = RARP_HID;
          $sformat (hdr_name, "rarp[%0d]",inst_no);
      end // }
      default : // {
      begin // {
          hid      = ARP_HID;
          $sformat (hdr_name, "arp[%0d]",inst_no);
      end // }
    endcase // }
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr(ref   bit [7:0] pkt [],
                ref   int       index,
                input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    int tmp_idx;
    pack_vec = {htype, ptype, hlen, plen, opcode};
    harray.pack_bit(pkt, pack_vec, index, 64);
    tmp_idx = index/8;
    harray.pack_array_8(sha, pkt, tmp_idx);
    harray.pack_array_8(spa, pkt, tmp_idx);
    harray.pack_array_8(dha, pkt, tmp_idx);
    harray.pack_array_8(dpa, pkt, tmp_idx);
    index = tmp_idx * 8;
    `else
    hdr = {>>{htype, ptype, hlen, plen, opcode, sha, spa, dha, dpa}};
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
    update_len (index, pkt.size, 8);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {htype, ptype, hlen, plen, opcode} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{htype, ptype, hlen, plen, opcode}} = hdr;
    `endif
    harray.copy_array (pkt, sha, index, hlen);
    harray.copy_array (pkt, spa, index, plen);
    harray.copy_array (pkt, dha, index, hlen);
    harray.copy_array (pkt, dpa, index, plen);
    hdr_len += 2*(hlen + plen);
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

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    arp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.htype          = lcl.htype;
    this.ptype          = lcl.ptype;
    this.hlen           = lcl.hlen;
    this.plen           = lcl.plen;
    this.opcode         = lcl.opcode;
    this.sha            = lcl.sha;
    this.spa            = lcl.spa;
    this.dha            = lcl.dha;
    this.dpa            = lcl.dpa;    
    // ~~~~~~~~~~ Control Variables ~~~~~~~~~~
    this.arp_htype_eth  = lcl.arp_htype_eth;
    this.arp_ptype_ipv4 = lcl.arp_ptype_ipv4;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  // This task displays all the feilds of individual hdrs used
  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    int fld_idx                   = 0;
    bit [`VEC_SZ-1:0] sha_fld     = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] spa_fld     = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] dha_fld     = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] dpa_fld     = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] lcl_sha_fld = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] lcl_spa_fld = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] lcl_dha_fld = `VEC_SZ'h0;
    bit [`VEC_SZ-1:0] lcl_dpa_fld = `VEC_SZ'h0;
    arp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    harray.unpack_array (sha,     sha_fld,     fld_idx, hlen,     1'b1);
    harray.unpack_array (lcl.sha, lcl_sha_fld, fld_idx, lcl.hlen, 1'b1);
    harray.unpack_array (spa,     spa_fld,     fld_idx, plen,     1'b1);
    harray.unpack_array (lcl.spa, lcl_spa_fld, fld_idx, lcl.plen, 1'b1);
    harray.unpack_array (dha,     dha_fld,     fld_idx, hlen,     1'b1);
    harray.unpack_array (lcl.dha, lcl_dha_fld, fld_idx, lcl.hlen, 1'b1);
    harray.unpack_array (dpa,     dpa_fld,     fld_idx, plen,     1'b1);
    harray.unpack_array (lcl.dpa, lcl_dpa_fld, fld_idx, lcl.plen, 1'b1);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000,    "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016,    "htype",  htype,   lcl.htype);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016,    "ptype",  ptype,   lcl.ptype);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008,    "hlen",   hlen,    lcl.hlen);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008,    "plen",   plen,    lcl.plen);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016,    "opcode", opcode,  lcl.opcode);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, hlen*8, "sha",    sha_fld, lcl_sha_fld);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, plen*8, "spa",    spa_fld, lcl_spa_fld);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, hlen*8, "dha",    dha_fld, lcl_dha_fld);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, plen*8, "dpa",    dpa_fld, lcl_dpa_fld);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "arp_htype_eth", arp_htype_eth,  lcl.arp_htype_eth);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "arp_ptype_ipv4",arp_ptype_ipv4, lcl.arp_ptype_ipv4);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : arp_hdr_class // }
