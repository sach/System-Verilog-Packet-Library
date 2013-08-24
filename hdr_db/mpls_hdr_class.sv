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
//  This hdr_class generates MPLS header.
//  MPLS header format (4*Num of Lbls)B, No trailer
// +--------------+
// | label[19:0]  |
// +----------+---+
// | exp[2:0] | s |
// +----------+---+
// | ttl[7:0]     |
// +--------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+--------------+-----------------------------------+
//  | Width | Default | Variable     | Description                       |
//  +-------+---------+--------------+-----------------------------------+
//  | 32    | random  | num_mpls_lbl | Total number of MPLS label        |
//  +-------+---------+--------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class mpls_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [19:0] label [`MAX_MPLS_LBL];
  rand bit [2:0]  exp   [`MAX_MPLS_LBL];
  rand bit        s     [`MAX_MPLS_LBL];
  rand bit [7:0]  ttl   [`MAX_MPLS_LBL];
  rand bit [31:0] eth_ctrl;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
  rand int        num_mpls_lbl;
       bit        use_eth_null_lbl  = 1'b0;
       bit        use_ipv4_null_lbl = 1'b0;
       bit        use_ipv6_null_lbl = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint mpls_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    (nxt_hdr.hid == ETH_HID) & (label[0] != eth_null_lbl) -> hdr_len == (4 * num_mpls_lbl) + 4;
    (nxt_hdr.hid == ETH_HID) & (label[0] == eth_null_lbl) -> hdr_len == (4 * num_mpls_lbl);
    (nxt_hdr.hid != ETH_HID)                              -> hdr_len == (4 * num_mpls_lbl);
    trl_len == 0;
  }

  constraint legal_num_mpls_lbl
  {
    num_mpls_lbl inside {[1 : `MAX_MPLS_LBL]};
  }

  constraint legal_label
  {
    foreach (label[num_lbl])
    {
      nxt_hdr.hid != ETH_HID  -> label [num_lbl] != eth_null_lbl;
      nxt_hdr.hid != IPV6_HID -> label [num_lbl] != ipv6_null_lbl;
      nxt_hdr.hid != IPV4_HID -> label [num_lbl] != ipv4_null_lbl;
      // MPLS over Ethernet label
      (use_eth_null_lbl   & (nxt_hdr.hid == ETH_HID)  & (num_lbl == 0)) -> label [num_lbl] == eth_null_lbl;
      (~use_eth_null_lbl  & (nxt_hdr.hid == ETH_HID)  & (num_lbl == 0)) -> label [num_lbl] != eth_null_lbl;
      // IPV4 Explicit Null Label
      (use_ipv4_null_lbl  & (nxt_hdr.hid == IPV4_HID) & (num_lbl == (num_mpls_lbl - 1))) -> label [num_lbl] == ipv4_null_lbl;
      (~use_ipv4_null_lbl & (nxt_hdr.hid == IPV4_HID) & (num_lbl == (num_mpls_lbl - 1))) -> label [num_lbl] != ipv4_null_lbl;
      ((nxt_hdr.hid == IPV4_HID) & (num_lbl != (num_mpls_lbl - 1)) & (num_mpls_lbl > 1)) -> label [num_lbl] != ipv4_null_lbl;
      // IPV6 Explicit Null Label
      (use_ipv6_null_lbl  & (nxt_hdr.hid == IPV6_HID) & (num_lbl == (num_mpls_lbl - 1))) -> label [num_lbl] == ipv6_null_lbl;
      (~use_ipv6_null_lbl & (nxt_hdr.hid == IPV6_HID) & (num_lbl == (num_mpls_lbl - 1))) -> label [num_lbl] != ipv6_null_lbl;
      ((nxt_hdr.hid == IPV6_HID) & (num_lbl != (num_mpls_lbl - 1)) & (num_mpls_lbl > 1)) -> label [num_lbl] != ipv6_null_lbl;
      // Router Alert Label -> Not valid at the bottom stack
      num_lbl == (num_mpls_lbl - 1) -> label [num_lbl] != router_alert_lbl;
    }
  }

  constraint legal_s
  {
    foreach (s[num_lbl])
    {
      num_lbl == (num_mpls_lbl - 1) -> s [num_lbl] == 1'b1;
      num_lbl != (num_mpls_lbl - 1) -> s [num_lbl] == 1'b0;
    }
  }

  constraint legal_eth_ctrl
  {
      eth_ctrl[31:28] == 3'h0;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no,
                int               hid_ctrl = 0); // {
    super.new (plib);
    this.inst_no = inst_no;
    if (hid_ctrl === 1)
    begin // {
        hid      = MMPLS_HID;
        $sformat (hdr_name, "mmpls[%0d]",inst_no);
    end // }
    else
    begin // {
        hid      = MPLS_HID;
        $sformat (hdr_name, "mpls[%0d]",inst_no);
    end // }
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int i;
    // pack class members
    for (i = 0; i < num_mpls_lbl; i++)
    begin // {
        `ifdef SVFNYI_0
        pack_vec = {label[i], exp[i], s[i], ttl[i]};
        harray.pack_bit (pkt, pack_vec, index, 32);
        `else
        hdr = {>>{label[i], exp[i], s[i], ttl[i]}};
        harray.pack_array_8 (hdr, pkt, index);
        `endif
    end // }
    if ((nxt_hdr.hid == ETH_HID) & (label[0] !== eth_null_lbl))
    begin // {
        `ifdef SVFNYI_0
        pack_vec = eth_ctrl;
        harray.pack_bit (pkt, pack_vec, index, 32);
        `else
        hdr = {>>{eth_ctrl}};
        harray.pack_array_8 (hdr, pkt, index);
        `endif
    end // }
    // pack next hdr
    if (~last_pack && this.nxt_hdr != null)
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
    int       nxt_hid;
    bit [7:0] nxtB;
    bit       unpack_done;
    // unpack class members
    update_len (index, pkt.size, 4);
    unpack_done  = 0;
    num_mpls_lbl = 0;
    while (~unpack_done)
    begin // {
        if (pkt.size >= index)
        begin // {
            num_mpls_lbl++;
            if (num_mpls_lbl > `MAX_MPLS_LBL) 
            begin // {
               $display ("%t %m : ERROR : num_mpls_lbl %d > MAX_MPLS_LBL %d", $time, num_mpls_lbl, `MAX_MPLS_LBL);
               `ifdef STOP_ON_ERR
               $stop;
               `endif
               break;
            end // }
            `ifdef SVFNYI_0
            harray.unpack_array (pkt, pack_vec, index, 4);
            {label[num_mpls_lbl-1], exp[num_mpls_lbl-1], s[num_mpls_lbl-1], ttl[num_mpls_lbl-1]} = pack_vec;
            `else
            harray.copy_array (pkt, hdr, index, 4);
            {>>{label[num_mpls_lbl-1], exp[num_mpls_lbl-1], s[num_mpls_lbl-1], ttl[num_mpls_lbl-1]}} = hdr;
            `endif
            if (s[num_mpls_lbl-1] == 1'b1)
            begin // {
                unpack_done = 1;
            end // }
        end // }
        else
           break;
    end // }
    if (pkt.size >= index)
    begin // {
        nxtB = pkt[index];
    end // }
    else
        nxtB = 8'hAA;
    if ((label[0] != eth_null_lbl) & (nxtB[7:5] == 3'h0))
    begin // {
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 4);
        eth_ctrl =  pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, 4);
        {>>{eth_ctrl}} =  hdr;
        `endif
        hdr_len  = (num_mpls_lbl * 4) + 4;
    end // }
    else
        hdr_len  = num_mpls_lbl * 4;
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        nxt_hid = DATA_HID;
        if (pkt.size > index)
        begin // {
            if (label[num_mpls_lbl-1] == ipv4_null_lbl) 
                nxt_hid = IPV4_HID;
            if (label[num_mpls_lbl-1] == ipv6_null_lbl) 
                nxt_hid = IPV6_HID;
            if (label[0] == eth_null_lbl)
                nxt_hid = ETH_HID;
            if ((label[0] != eth_null_lbl) & (nxtB[7:5] == 3'h0))
                nxt_hid = ETH_HID;
            if ((label[num_mpls_lbl-1] != ipv4_null_lbl) & (nxtB[7:4] == 4'h4)) 
                nxt_hid = IPV4_HID;
            if ((label[num_mpls_lbl-1] != ipv6_null_lbl) & (nxtB[7:4] == 4'h6)) 
                nxt_hid = IPV6_HID;
        end // }
        if (~unpack_en[nxt_hid])
            nxt_hid = DATA_HID;
        $cast (lcl_class, this);
        super.update_nxt_hdr_info (lcl_class, hdr_q, nxt_hid);
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
    mpls_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.label             = lcl.label;
    this.exp               = lcl.exp;
    this.s                 = lcl.s;
    this.ttl               = lcl.ttl;
    this.eth_ctrl          = lcl.eth_ctrl;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.num_mpls_lbl      = lcl.num_mpls_lbl;
    this.use_eth_null_lbl  = lcl.use_eth_null_lbl ;
    this.use_ipv4_null_lbl = lcl.use_ipv4_null_lbl;
    this.use_ipv6_null_lbl = lcl.use_ipv6_null_lbl;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    int            i;
    string         fld_name;
    mpls_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin
       hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
       hdis.display_fld (mode, hdr_name, BIT_VEC, DEF, 032, "num_mpls_lbl", num_mpls_lbl, lcl.num_mpls_lbl);
    end
    for (i = 0; i < num_mpls_lbl; i++)
    begin // {
        $sformat(fld_name, "label[%0d]", i);
        hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 020, fld_name, label[i], lcl.label[i], null_a, null_a, get_mpls_lbl_name(label[i]));
        $sformat(fld_name, "exp[%0d]",   i);
        hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 003, fld_name, exp[i], lcl.exp[i]);
        $sformat(fld_name, "s[%0d]",     i);
        hdis.display_fld (mode, hdr_name, BIT_VEC, BIN, 001, fld_name, s[i], lcl.s[i]);
        $sformat(fld_name, "ttl[%0d]",   i);
        hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 008, fld_name, ttl[i], lcl.ttl[i]);
    end // }
    if (hdr_len > (num_mpls_lbl * 4))
        hdis.display_fld (mode, hdr_name, BIT_VEC, HEX, 032, "eth_ctrl", eth_ctrl, lcl.eth_ctrl);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a,"~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "num_mpls_lbl", num_mpls_lbl, lcl.num_mpls_lbl);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "use_eth_null_lbl", use_eth_null_lbl, lcl.use_eth_null_lbl);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "use_ipv4_null_lbl", use_ipv4_null_lbl, lcl.use_ipv4_null_lbl);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "use_ipv6_null_lbl", use_ipv6_null_lbl, lcl.use_ipv6_null_lbl);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : mpls_hdr_class // }
