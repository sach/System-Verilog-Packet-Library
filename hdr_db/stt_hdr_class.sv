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
//  This hdr_class generates Stateless Transport Tunneling Protocol (STT)
// ietf-draft
//  STT header Format (18B, No trailer)
//  +-----------------+
//  | version[7:0]    | 
//  +-----------------+
//  | flags[7:0]      | 
//  +-----------------+
//  | l4_offset[7:0]  | 
//  +-----------------+
//  | rsvd[7:0]       |
//  +-----------------+
//  | max_seg_sz[15:0]| 
//  +-----------------+
//  | PCP[2:0]        |
//  +---+-------------+
//  | V | vlan[11:0]  | -> If V == 1'b1, vlan is valid
//  +---+-------------+
//  | ctx_id[63:0]    |
//  +-----------------+
//  | pad[15:0]       | 
//  +-----------------+

// The flags field discription
// ----------------------------
// 0: CHKV : Checksum verified. Set if the checksum of the encapsulated
// packet has been verified by the sender.
// 1: CHKP : Checksum partial. Set if the checksum in the encapsulated
// packet has been computed only over the TCP/IP header. This bit
// MUST be set if TSO is used by the sender. Note that bit 0 and bit
// 1 cannot both be set in the same header.
// 2: IPPR : IP version. Set if the encapsulated packet is IPv4, not set if
// the packet is IPv6. See below for discussion of non-IP payloads.
// 3: TCPP : TCP payload.  Set if the encapsulated packet is TCP.
// 4-7: RSVD : Unused, MUST be zero on transmission and ignored on receipt.

// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------------+---------------------------------------+
//  | Width | Default | Variable             | Description                           |
//  +-------+---------+----------------------+---------------------------------------+
//  | 1     | 1'b0    | corrupt_stt_version  | If 1, version != 8'h0                 |
//  +-------+---------+----------------------+---------------------------------------+
//  | 1     | 1'b1    | cal_flag2            | If 1, calculate flags[2] else 0       |
//  +-------+---------+----------------------+---------------------------------------+
//  | 1     | 1'b1    | cal_flag3            | If 1, calculate flags[3] else 0       |
//  +-------+---------+----------------------+---------------------------------------+
//  | 1     | 1'b1    | cal_l4_offset        | If 1, calculate l4_offset else random |
//  +-------+---------+----------------------+---------------------------------------+
//  | 1     | 1'b0    | null_rsvd        | If 1, all rsvd fields set to 0    |
//  +-------+---------+------------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class stt_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]     version;
  rand bit [7:0]     flags;
  rand bit [7:0]     l4_offset;
  rand bit [7:0]     rsvd;
  rand bit [15:0]    max_seg_sz;
  rand bit [2:0]     PCP;
  rand bit           V;
  rand bit [11:0]    vlan;
  rand bit [63:0]    ctx_id;
  rand bit [15:0]    pad;           

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit           corrupt_stt_version = 1'b0;
       bit           cal_flag2           = 1'b1;
       bit           cal_flag3           = 1'b1;
       bit           cal_l4_offset       = 1'b1;
       bit           null_rsvd           = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint stt_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len 
  {
    hdr_len == 18; 
    trl_len == 0; 
  }

  constraint legal_version
  {
    (corrupt_stt_version == 1'b0) -> (version == 8'h0);
    (corrupt_stt_version == 1'b1) -> (version != 8'h0);
  }

  constraint legal_flags
  {
    (flags[0] & flags[1])    != 1'b1; 
    flags[7:2]               == 6'h0;
  }

  constraint legal_l4_offset
  {
    (cal_l4_offset) -> l4_offset == 8'h0;
  }

  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> rsvd == 8'h0;
  }

  constraint legal_pad
  {
    pad == 8'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = STT_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "stt[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void post_randomize (); // {
    bit ip_found;
    int i;
    super.post_randomize();
    ip_found  = 1'b0;
    for (i = this.cfg_id+1; i < super.all_hdr.size; i++)
    begin // {
        // Calculate flags[2] and l4_offset
        if (~ip_found & ((super.all_hdr[i].hid == IPV4_HID) | (super.all_hdr[i].hid == IPV6_HID)))
        begin // {
            ip_found = 1'b1;
            flags[2] = cal_flag2 & (super.all_hdr[i].hid == IPV4_HID);
            if (cal_l4_offset)
                l4_offset = this.nxt_hdr.total_hdr_len - super.all_hdr[i].nxt_hdr.total_hdr_len;
        end // }
        // Calculate flags[3]
        if (super.all_hdr[i].hid == TCP_HID)
        begin // {
            flags[3] = cal_flag3;
            break;
        end // }
    end // }
  endfunction : post_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    pack_vec = {version, flags, l4_offset, rsvd, max_seg_sz, PCP, V, vlan, ctx_id, pad};       
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    hdr = {>>{version, flags, l4_offset, rsvd, max_seg_sz, PCP, V, vlan, ctx_id, pad}};
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
    update_len (index, pkt.size, 18);
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    {version, flags, l4_offset, rsvd, max_seg_sz, PCP, V, vlan, ctx_id, pad} = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    {>>{version, flags, l4_offset, rsvd, max_seg_sz, PCP, V, vlan, ctx_id, pad}} = hdr;
    `endif
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[ETH_HID] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, ETH_HID);
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
    stt_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~~~~
    this.version               = lcl.version;
    this.flags                 = lcl.flags;
    this.l4_offset             = lcl.l4_offset;
    this.rsvd                  = lcl.rsvd;
    this.max_seg_sz            = lcl.max_seg_sz;
    this.PCP                   = lcl.PCP;
    this.V                     = lcl.V;
    this.vlan                  = lcl.vlan;
    this.ctx_id                = lcl.ctx_id;
    this.pad                   = lcl.pad;       
    // ~~~~~~~~~~ Local variables ~~~~~~~~~~~~
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_stt_version   = lcl.corrupt_stt_version; 
    this.cal_flag2             = lcl.cal_flag2;
    this.cal_flag3             = lcl.cal_flag3;
    this.cal_l4_offset         = lcl.cal_l4_offset;
    this.null_rsvd             = lcl.null_rsvd;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    string flags_brk;
    stt_hdr_class lcl;
    $cast (lcl, cmp_cls);
    $sformat(flags_brk, "=> RSVD %b TCPP %b IPPR %b CHKP %b CHKV %b", flags[7:4],flags[3],flags[2],flags[1],flags[0]); 
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "version",     version,    lcl.version);     
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "flags",       flags,      lcl.flags,null_a,null_a, flags_brk);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "l4_offset",   l4_offset,  lcl.l4_offset);   
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 008, "rsvd",        rsvd,       lcl.rsvd);        
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "max_seg_sz",  max_seg_sz, lcl.max_seg_sz);  
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 003, "PCP",         PCP,        lcl.PCP);         
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 001, "V",           V,          lcl.V);           
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 012, "vlan",        vlan,       lcl.vlan);        
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 064, "ctx_id",      ctx_id,     lcl.ctx_id);      
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "pad",         pad,        lcl.pad);         
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_stt_version", corrupt_stt_version, lcl.corrupt_stt_version);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_flag2", cal_flag2, lcl.cal_flag2);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_flag3", cal_flag3, lcl.cal_flag3);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "cal_l4_offset", cal_l4_offset, lcl.cal_l4_offset);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);     
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : stt_hdr_class // }
