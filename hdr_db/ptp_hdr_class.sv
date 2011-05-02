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
//  This hdr_class generates the IEEE 1588 (PTP) header
//
//  PTPv1 header Format
//  +--------------------+
//  | ptp_ver     [15:0] | -> versionPTP
//  +--------------------+
//  | nw_ver      [15:0] | -> versionNetwork
//  +--------------------+
//  | subdomain   [127:0]|
//  +--------------------+
//  | msg_type    [7:0]  |
//  +--------------------+
//  | src_com_tech[7:0]  | -> sourceCommunicationTechnology
//  +--------------------+
//  | src_uid     [47:0] |
//  +--------------------+
//  | src_port_id [15:0] |
//  +--------------------+
//  | seq_id      [15:0] |
//  +--------------------+
//  | cntrl       [7:0]  |
//  +--------------------+
//  | rsvd0       [7:0]  |
//  +--------------------+
//  | flags       [15:0] |
//  +--------------------+
//  | rsvd1       [31:0] |
//  +--------------------+
//
//  PTPv2 header Format
//  +--------------------+
//  | trans_spec  [3:0]  |
//  +--------------------+
//  | msg_type    [3:0]  |
//  +--------------------+
//  | ptp_ver     [7:0]  |
//  +--------------------+
//  | msg_len     [15:0] |
//  +--------------------+
//  | domain_no   [7:0]  |
//  +--------------------+
//  | rsvd0       [7:0]  |
//  +--------------------+
//  | flags       [15:0] |
//  +--------------------+
//  | crct_fld    [63:0] | -> Correction field
//  +--------------------+
//  | rsvd1       [31:0] |
//  +--------------------+
//  | src_port_id [79:0] |
//  +--------------------+
//  | seq_id      [15:0] |
//  +--------------------+
//  | cntrl       [7:0]  |
//  +--------------------+
//  | logmsgintrl [7:0]  | -> Log Mean Message Interval
//  +--------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//
// ----------------------------------------------------------------------

class ptp_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand  bit [15:0]    v1_ptp_ver;
  rand  bit [15:0]    v1_nw_ver;
  rand  bit [127:0]   v1_subdomain;
  rand  bit [7:0]     v1_msg_type;
  rand  bit [7:0]     v1_src_com_tech;
  rand  bit [47:0]    v1_src_uid;
  rand  bit [15:0]    v1_src_port_id;
  rand  bit [15:0]    v1_seq_id;
  rand  bit [7:0]     v1_cntrl;
  rand  bit [7:0]     v1_rsvd0;
  rand  bit [15:0]    v1_flags;
  rand  bit [31:0]    v1_rsvd1;

  rand  bit [3:0]     v2_trans_spec;
  rand  bit [3:0]     v2_msg_type;
  rand  bit [7:0]     v2_ptp_ver;
  rand  bit [15:0]    v2_msg_len;
  rand  bit [7:0]     v2_domain_no;
  rand  bit [7:0]     v2_rsvd0;
  rand  bit [15:0]    v2_flags; 
  rand  bit [63:0]    v2_crct_fld;
  rand  bit [31:0]    v2_rsvd1;
  rand  bit [79:0]    v2_src_port_id;
  rand  bit [15:0]    v2_seq_id;
  rand  bit [7:0]     v2_cntrl;
  rand  bit [7:0]     v2_logmsgintrl;

  rand  bit [79:0]    v2_synctimestamp;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
  rand  int           sync_msg_hdr;
        bit           ptp_ver            = 1'b1; // 0 -> V1, 1-> V2
        bit           is_ptp             = 1'b1;
        bit           tspec_chk_dis      = 1'b1;
        bit [3:0]     usr_tspec          = 4'd0;
        bit           corrupt_ptp_ver    = 1'b0;
        bit           cal_msg_len        = 1'b0;
        bit           corrupt_msg_len    = 1'b0;
        bit [15:0]    corrupt_msg_len_by = 16'h1;
        bit           corrupt_syncts     = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  // ~~~~~~~~~~ Constraints common for v1/v2 ~~~~~~~~~~
  constraint ptp_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_hdr_len
  {
    (ptp_ver     == 1'b0) -> hdr_len == 40;
    (ptp_ver     == 1'b1) -> hdr_len == 34 + sync_msg_hdr;
    (v2_msg_type == 4'h0) -> sync_msg_hdr == 10;
    (v2_msg_type != 4'h0) -> sync_msg_hdr == 0;
  }

  // ~~~~~~~~~~ Constraints for v1 ~~~~~~~~~~
  constraint v1_ptp_hdr_user_constraint
  {
  }

  constraint legal_v1_ptp_ver
  {
    (~corrupt_ptp_ver) -> v1_ptp_ver == 16'h0001;
    ( corrupt_ptp_ver) -> v1_ptp_ver != 16'h0001;
  }

  constraint legal_v1_msg_type
  {
  }

  // ~~~~~~~~~~ Constraints for v2 ~~~~~~~~~~
  constraint v2_ptp_hdr_user_constraint
  {
  }

  constraint legal_v2_trans_spec
  {
    (~tspec_chk_dis) -> v2_trans_spec == usr_tspec;
  }

  constraint legal_v2_msg_type
  {
  }

  constraint legal_ptpv2_ver
  {
    (corrupt_ptp_ver == 1'b0) -> v2_ptp_ver == 8'h02;
    (corrupt_ptp_ver == 1'b1) -> v2_ptp_ver != 8'h02;
  }

  constraint legal_v2_msg_len
  {
    if (cal_msg_len)
    {
        (corrupt_msg_len == 1'b0) -> (v2_msg_len == this.total_hdr_len);
        (corrupt_msg_len == 1'b1) -> (v2_msg_len == this.total_hdr_len + corrupt_msg_len_by);
    }
    else
        (corrupt_msg_len == 1'b1) -> (v2_msg_len == v2_msg_len + corrupt_msg_len_by);
  }

  constraint legal_synctimestamp
  {
    (~corrupt_syncts) -> v2_synctimestamp[31:0] <= ptp_one_sec;
    ( corrupt_syncts) -> v2_synctimestamp[31:0] >  ptp_one_sec;
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = PTP_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "ptp[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
  endfunction : new // }

  function void pre_randomize (); // {
    if (super) super.pre_randomize();
    if (ptp_ver == 1'b1)
        $sformat (hdr_name, "ptpv2[%0d]",inst_no);
    else
        $sformat (hdr_name, "ptpv1[%0d]",inst_no);
  endfunction : pre_randomize // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    if (ptp_ver == 1'b1)
    begin // {
        if (v2_msg_type == 0)
            hdr = {>>{v2_trans_spec, v2_msg_type, v2_ptp_ver, v2_msg_len, v2_domain_no, v2_rsvd0, v2_flags, v2_crct_fld, v2_rsvd1, v2_src_port_id, v2_seq_id, v2_cntrl, v2_logmsgintrl, v2_synctimestamp}};
        else
            hdr = {>>{v2_trans_spec, v2_msg_type, v2_ptp_ver, v2_msg_len, v2_domain_no, v2_rsvd0, v2_flags, v2_crct_fld, v2_rsvd1, v2_src_port_id, v2_seq_id, v2_cntrl, v2_logmsgintrl}};
    end // }
    else
        hdr = {>>{v1_ptp_ver, v1_nw_ver, v1_subdomain, v1_msg_type, v1_src_com_tech, v1_src_uid, v1_src_port_id, v1_seq_id, v1_cntrl, v1_rsvd0, v1_flags, v1_rsvd1}};
    harray.pack_array_8 (pkt, hdr, index);
    // pack next hdr
    if (~last_pack)
        this.nxt_hdr.pack_hdr (pkt, index);
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    // find ptp_ver
    if ({pkt[index], pkt[index+1]} === 16'h0001)
        ptp_ver = 1'b0;
    else
        ptp_ver = 1'b1;
    if (ptp_ver == 1'b1)
        $sformat (hdr_name, "ptpv2[%0d]",inst_no);
    else
        $sformat (hdr_name, "ptpv1[%0d]",inst_no);
    // unpack class members
    hdr_len   = (ptp_ver) ? 34 : 40;
    start_off = index;
    harray.copy_array (pkt, hdr, index, hdr_len);
    if (ptp_ver == 1'b1)
        {>>{v2_trans_spec, v2_msg_type, v2_ptp_ver, v2_msg_len, v2_domain_no, v2_rsvd0, v2_flags, v2_crct_fld, v2_rsvd1, v2_src_port_id, v2_seq_id, v2_cntrl, v2_logmsgintrl}} = hdr;
    else
        {>>{v1_ptp_ver, v1_nw_ver, v1_subdomain, v1_msg_type, v1_src_com_tech, v1_src_uid, v1_src_port_id, v1_seq_id, v1_cntrl, v1_rsvd0, v1_flags, v1_rsvd1}} = hdr;
    if ((ptp_ver == 1'b1) && (v2_msg_type == 0))
    begin // {
        sync_msg_hdr     = 10;
        hdr_len         += sync_msg_hdr;
        harray.copy_array (pkt, hdr, index, sync_msg_hdr);
        {>>{v2_synctimestamp}} = hdr;
    end // }
    else 
        sync_msg_hdr = 0;
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (pkt.size > index)
            super.update_nxt_hdr_info (lcl_class, hdr_q, DATA_HID);
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

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_unpack = 1'b0); // {
    ptp_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.v1_ptp_ver         = lcl.v1_ptp_ver;
    this.v1_nw_ver          = lcl.v1_nw_ver;
    this.v1_subdomain       = lcl.v1_subdomain;
    this.v1_msg_type        = lcl.v1_msg_type;
    this.v1_src_com_tech    = lcl.v1_src_com_tech;
    this.v1_src_uid         = lcl.v1_src_uid;
    this.v1_src_port_id     = lcl.v1_src_port_id;
    this.v1_seq_id          = lcl.v1_seq_id;
    this.v1_cntrl           = lcl.v1_cntrl;
    this.v1_rsvd0           = lcl.v1_rsvd0;
    this.v1_flags           = lcl.v1_flags;
    this.v1_rsvd1           = lcl.v1_rsvd1;
    this.v2_trans_spec      = lcl.v2_trans_spec;
    this.v2_msg_type        = lcl.v2_msg_type;
    this.v2_ptp_ver         = lcl.v2_ptp_ver;
    this.v2_msg_len         = lcl.v2_msg_len;
    this.v2_domain_no       = lcl.v2_domain_no;
    this.v2_rsvd0           = lcl.v2_rsvd0;
    this.v2_flags           = lcl.v2_flags;
    this.v2_crct_fld        = lcl.v2_crct_fld;
    this.v2_rsvd1           = lcl.v2_rsvd1;
    this.v2_src_port_id     = lcl.v2_src_port_id;
    this.v2_seq_id          = lcl.v2_seq_id;
    this.v2_cntrl           = lcl.v2_cntrl;
    this.v2_logmsgintrl     = lcl.v2_logmsgintrl;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.ptp_ver            = lcl.ptp_ver;
    this.is_ptp             = lcl.is_ptp;            
    this.tspec_chk_dis      = lcl.tspec_chk_dis;     
    this.usr_tspec          = lcl.usr_tspec;         
    this.corrupt_ptp_ver    = lcl.corrupt_ptp_ver;   
    this.cal_msg_len        = lcl.cal_msg_len;       
    this.corrupt_msg_len    = lcl.corrupt_msg_len;   
    this.corrupt_msg_len_by = lcl.corrupt_msg_len_by;
    this.corrupt_syncts     = lcl.corrupt_syncts;
    if (~last_unpack)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_unpack);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    ptp_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if (ptp_ver == 1'b1)
    begin // {
`ifdef DEBUG_CHKSM
        hdis.display_fld (mode, hdr_name, "hdr_len",  16, HEX, BIT_VEC, hdr_len,   lcl.hdr_len);
        hdis.display_fld (mode, hdr_name, "total_hdr_len",  16, HEX, BIT_VEC, total_hdr_len,   lcl.total_hdr_len);
`endif
        hdis.display_fld (mode, hdr_name, "v2_trans_spec",     4, HEX, BIT_VEC, v2_trans_spec,    lcl.v2_trans_spec); 
        hdis.display_fld (mode, hdr_name, "v2_msg_type",       4, HEX, BIT_VEC, v2_msg_type,      lcl.v2_msg_type); 
        hdis.display_fld (mode, hdr_name, "v2_ptp_ver",        8, HEX, BIT_VEC, v2_ptp_ver,       lcl.v2_ptp_ver); 
        hdis.display_fld (mode, hdr_name, "v2_msg_len",       16, HEX, BIT_VEC, v2_msg_len,       lcl.v2_msg_len); 
        hdis.display_fld (mode, hdr_name, "v2_domain_no",     16, HEX, BIT_VEC, v2_domain_no,     lcl.v2_domain_no); 
        hdis.display_fld (mode, hdr_name, "v2_rsvd0",          8, HEX, BIT_VEC, v2_rsvd0,         lcl.v2_rsvd0); 
        hdis.display_fld (mode, hdr_name, "v2_flags",         16, HEX, BIT_VEC, v2_flags,         lcl.v2_flags);  
        hdis.display_fld (mode, hdr_name, "v2_crct_fld",      64, HEX, BIT_VEC, v2_crct_fld,      lcl.v2_crct_fld); 
        hdis.display_fld (mode, hdr_name, "v2_rsvd1",         32, HEX, BIT_VEC, v2_rsvd1,         lcl.v2_rsvd1); 
        hdis.display_fld (mode, hdr_name, "v2_src_port_id",   80, HEX, BIT_VEC, v2_src_port_id,   lcl.v2_src_port_id);  
        hdis.display_fld (mode, hdr_name, "v2_seq_id",        16, HEX, BIT_VEC, v2_seq_id,        lcl.v2_seq_id); 
        hdis.display_fld (mode, hdr_name, "v2_cntrl",          8, HEX, BIT_VEC, v2_cntrl,         lcl.v2_cntrl); 
        hdis.display_fld (mode, hdr_name, "v2_logmsgintrl",    8, HEX, BIT_VEC, v2_logmsgintrl,   lcl.v2_logmsgintrl);    
        if (v2_msg_type == 4'h0)
        hdis.display_fld (mode, hdr_name, "v2_synctimestamp", 80, HEX, BIT_VEC, v2_synctimestamp, lcl.v2_synctimestamp);    
    end // }
    else
    begin // {
`ifdef DEBUG_CHKSM
        hdis.display_fld (mode, hdr_name, "hdr_len",  16, HEX, BIT_VEC, hdr_len,   lcl.hdr_len);
        hdis.display_fld (mode, hdr_name, "total_hdr_len",  16, HEX, BIT_VEC, total_hdr_len,   lcl.total_hdr_len);
`endif
        hdis.display_fld (mode, hdr_name, "v1_ptp_ver",       16, HEX, BIT_VEC, v1_ptp_ver,       lcl.v1_ptp_ver);
        hdis.display_fld (mode, hdr_name, "v1_nw_ver",        16, HEX, BIT_VEC, v1_nw_ver,        lcl.v1_nw_ver);
        hdis.display_fld (mode, hdr_name, "v1_subdomain",    128, HEX, BIT_VEC, v1_subdomain,     lcl.v1_subdomain);
        hdis.display_fld (mode, hdr_name, "v1_msg_type",       8, HEX, BIT_VEC, v1_msg_type,      lcl.v1_msg_type);
        hdis.display_fld (mode, hdr_name, "v1_src_com_tech",   8, HEX, BIT_VEC, v1_src_com_tech,  lcl.v1_src_com_tech);
        hdis.display_fld (mode, hdr_name, "v1_src_uid",       48, HEX, BIT_VEC, v1_src_uid,       lcl.v1_src_uid);
        hdis.display_fld (mode, hdr_name, "v1_src_port_id",   16, HEX, BIT_VEC, v1_src_port_id,   lcl.v1_src_port_id);
        hdis.display_fld (mode, hdr_name, "v1_seq_id",        16, HEX, BIT_VEC, v1_seq_id,        lcl.v1_seq_id);
        hdis.display_fld (mode, hdr_name, "v1_cntrl",          8, HEX, BIT_VEC, v1_cntrl,         lcl.v1_cntrl);
        hdis.display_fld (mode, hdr_name, "v1_rsvd0",          8, HEX, BIT_VEC, v1_rsvd0,         lcl.v1_rsvd0);
        hdis.display_fld (mode, hdr_name, "v1_flags",         16, HEX, BIT_VEC, v1_flags,         lcl.v1_flags);
        hdis.display_fld (mode, hdr_name, "v1_rsvd1",         32, HEX, BIT_VEC, v1_rsvd1,         lcl.v1_rsvd1);        
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid === nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : ptp_hdr_class // }
