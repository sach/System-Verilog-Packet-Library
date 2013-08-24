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
//  This hdr_class generates the data (payload) for the packet
//  Data format
//  +----------+
//  | data[0]  |
//  +----------+
//  | data[1]  |
//  +----------+
//  |  ...     |
//  +----------+
//  |  ...     |
//  +----------+
//  | data[n]  | -> where n is (data_len-1)
//  +----------+
// ----------------------------------------------------------------------

class data_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [7:0]  data [];
  rand bit [15:0] data_len;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit        mpls_chk_en = 1'b1; //  check to make sure first data nibble is not 0, 4 or 6
                                      //  if prev_hdr was mpls

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint data_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    hdr_len == data_len;
    trl_len == 0;
  }

  constraint legal_data_len
  {
    data_len inside { [16'd0 : `MAX_PLEN] }; // data_len can't be -ve
    data.size == data_len;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = DATA_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "data[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void post_randomize (); // {
    bit [7:0] tmp_data;
    super.post_randomize();
    if (harray.data_pattern != "RND")
        harray.fill_array (data);
    if (mpls_chk_en)
    begin // {
        if ((super.prv_hdr.hid === MPLS_HID) & (data_len > 0))
        begin // {
            tmp_data = data[0];
            if ((tmp_data[7:4] === 4'h0) | (tmp_data[7:4] === 4'h1) | (tmp_data[7:4] === 4'h4) | (tmp_data[7:4] === 4'h6))
                tmp_data[7:4] = $urandom_range(7, 15);
            data[0] = tmp_data;
        end // }
        if ((super.prv_hdr.hid === MMPLS_HID) & (data_len > 0))
        begin // {
            tmp_data = data[0];
            if ((tmp_data[7:4] === 4'h0) | (tmp_data[7:4] === 4'h1)| (tmp_data[7:4] === 4'h4) | (tmp_data[7:4] === 4'h6))
                tmp_data[7:4] = $urandom_range(7, 15);
            data[0] = tmp_data;
        end // }
    end // }
  endfunction : post_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    int tmp_idx;
    tmp_idx = index/8;
    harray.pack_array_8 (data, pkt, tmp_idx);
    index = tmp_idx * 8;
    `else
    harray.pack_array_8 (data, pkt, index);
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
    int        i;
    // unpack class members
    start_off     = index;
    trl_len       = 0;
    if (pkt.size  > (index + total_trl_len(cfg_id)))
        hdr_len   = (pkt.size - index - total_trl_len(cfg_id));
    else
        hdr_len   = 0;
    data_len      = hdr_len;
    total_hdr_len = hdr_len;
    harray.copy_array (pkt, data, index, hdr_len);
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        super.update_nxt_hdr_info (lcl_class, hdr_q, EOH_HID);
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
    data_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    this.data        = lcl.data;
    this.data_len    = lcl.data_len;
    this.mpls_chk_en = lcl.mpls_chk_en;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    string sample_data;
    data_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == COMPARE_FULL) | (mode == DISPLAY_FULL))
    begin // {
        hdis.display_fld (mode, hdr_name, STRING,  DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
        hdis.display_fld (mode, hdr_name, ARRAY,   DEF, 000, "data", 0, 0, data, lcl.data);
    end // }
    else
    begin // {
        if (data.size > 4)
            $sformat(sample_data, "data => %x %x %x %x ..", data[0], data[1], data[2], data[3]);
        else
        begin // {
            case (data.size) // {
              4 : $sformat(sample_data, "data => %x %x %x %x ", data[0], data[1], data[2], data[3]);
              3 : $sformat(sample_data, "data => %x %x %x", data[0], data[1], data[2]);
              2 : $sformat(sample_data, "data => %x %x", data[0], data[1]);
              1 : $sformat(sample_data, "data => %x", data[0]);
              0 : $sformat(sample_data, "data => EMPTY");
            endcase // }
        end // }
        hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "data_len", data.size, lcl.data.size, null_a, null_a, sample_data);
        hdis.index += hdr_len*8;
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "mpls_chk_en", mpls_chk_en, lcl.mpls_chk_en);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : data_class // }
