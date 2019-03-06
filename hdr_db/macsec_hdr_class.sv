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
//  This hdr_class generates the MACSEC(IEEE802.1AE) header.
//  MACSEC header format (8B or 16B + 16B of ICV)
//   +-----------------------+
//   |  tci[5:0]             | (Tag Control Information)
//   +-----------------------+
//   |  an[1:0]              | (Secure Association Number)
//   +-----------------------+
//   |  sl[7:0]              | (Short Length)
//   +-----------------------+
//   |  pn[31:0]             | (Packet Number)
//   +-----------------------+
//   |  sci[63:0] (optional) | (Secure Connection Identifier)
//   +-----------------------+
//   |  etype[15:0]          | 
//   +-----------------------+
//
//  tci[5:0] -> Tag Control Information fields
//   +-----------------------------+
//   | V=0 | ES | SC | SCB | E | C | 
//   +-----------------------------+
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+--------------------+-----------------------------------+
//  | Width | Default | Variable           | Description                       |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b1    | process_ae         | If 1, add ICV and optionally enc  |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_tci_ver    | If 1, corrupts tci version        |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_tci_es_sc  | If 1, corrupts tci ES-SC property |
//  |       |         |                    | i.e. ES-SC are mutually exclusive |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_tci_scb    | If 1, corrupts tci SCB            |
//  |       |         |                    | i.e. if (ES || SC) -> SCB = 0     |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_tci_e_c    | If 1, corrupts tci E-C property   |
//  |       |         |                    | i.e. EC are not mutually exclusive|
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | corrupt_sl         | If 1, corrupts SL. SL will be rnd |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b1    | enc_en             | If 1, encrypt the data            |
//  +-------+---------+--------------------+-----------------------------------+
//  | 1     | 1'b0    | ignore_ES_0        | If 1, ignore ES=0 for SCI cal     |
//  +-------+---------+--------------------+-----------------------------------+
//
// ----------------------------------------------------------------------

class macsec_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~
  rand bit [5:0]   tci;
  rand bit [1:0]   an;
  rand bit [7:0]   sl;
  rand bit [31:0]  pn;
  rand bit [63:0]  sci;
  rand bit [15:0]  etype;
  rand bit [7:0]   icv [];

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  local int i;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit        process_ae          = 1'b1;
       bit        corrupt_tci_ver     = 1'b0;
       bit        corrupt_tci_es_sc   = 1'b0;
       bit        corrupt_tci_scb     = 1'b0;
       bit        corrupt_tci_e_c     = 1'b0;
       bit        corrupt_sl          = 1'b0;
       bit        corrupt_icv         = 1'b0;
       bit        enc_en              = 1'b1;
       bit        ignore_ES_0         = 1'b0;

  // ~~~~~~~~~~ MACsec Programming variables ~~~~~~~~~~
       bit [7:0]   auth_adjust        = 0; 
       bit [127:0] key                = 0;
       bit [63:0]  implicit_sci       = 0;
       bit [15:0]  scb_port           = 0;
       bit [15:0]  default_port       = 16'h1;

  // ~~~~~~~~~~ Local MACsec related variables ~~~~~~~~~~
       bit [63:0]  final_sci          = 0;
       int         auth_st            = 0;
       int         auth_sz            = 0;
       int         auth_only          = 0;
       int         enc_sz             = 0;
  rand int         icv_sz             = 16;
  rand int         sectag_sz          = 16;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~

  constraint macsec_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
  }

  constraint legal_etype
  {
    `LEGAL_ETH_TYPE_CONSTRAINTS; 
  }

  // V(tci[5]) = 1'b0
  constraint legal_tci_ver
  {
    ~corrupt_tci_ver -> tci[5] ==  tci_ver;
     corrupt_tci_ver -> tci[5] == ~tci_ver;
  }

  // ES(tci[4]) and SC(tci[3]) are mutually exclusive 
  constraint legal_tci_es_sc
  {
    ~corrupt_tci_es_sc -> (tci[4] & tci[3]) == 0;
     corrupt_tci_es_sc -> (tci[4] & tci[3]) == 1;
  }

  // If SC(tci[3]) is 1, sci is present ==> MACSEC hdr is 16B
  constraint legal_hdr_len
  {
    ~tci[3]     -> sectag_sz == 8;
     tci[3]     -> sectag_sz == 16;
     process_ae -> icv_sz    == 16;
    ~process_ae -> icv_sz    == 0;
    icv.size == icv_sz;
    hdr_len  == sectag_sz;
    trl_len  == icv_sz;
  }

  // If SCB is set, SC is 0 
  constraint legal_tci_scb
  {
    if (~corrupt_tci_scb)
       (tci[2] == 1'b1) -> tci[3] == 0;    
  }

  // For encryption, E-C should be 2'b11
  // For auth only,  E-C should be 2'b00
  constraint legal_tci_e_c
  {
      (~corrupt_tci_e_c & enc_en)  -> (tci[1] & tci[0]) == 1'b1; 
      (~corrupt_tci_e_c & ~enc_en) -> (tci[1] | tci[0]) == 1'b0; 
      (corrupt_tci_e_c)            -> (tci[1] ^ tci[0]) == 1'b1; 
  }

  constraint legal_sl 
  {
    if (~corrupt_sl)
    {
       if (super.nxt_hdr.total_hdr_len <= (sl_sz - 3))
          sl == 2 + super.nxt_hdr.total_hdr_len;
       else
          sl == 0;
    }
    corrupt_sl -> sl inside { [8'd48 : 8'd255] };
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = MACSEC_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "macsec[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
    `ifdef NO_PROCESS_AE
        process_ae  = 1'b0;
    `endif
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    int pkt_ptr;

    // pack class members
    `ifdef SVFNYI_0
    pack_vec = (tci[3]) ? {tci, an, sl, pn, sci, etype} : {tci, an, sl, pn, etype};
    harray.pack_bit (pkt, pack_vec, index, sectag_sz*8);
    `else
    if (tci[3])
        hdr = {>>{tci, an, sl, pn, sci, etype}};
    else
        hdr = {>>{tci, an, sl, pn, etype}};
    harray.pack_array_8 (hdr, pkt, index);
    `endif

    // pack next hdr
    pkt_ptr = index;
    if (~last_pack)
    begin // {
        `ifdef DEBUG_PKTLIB
        $display ("    pkt_lib : Packing %s nxt_hdr %s index %0d", hdr_name, nxt_hdr.hdr_name, index);
        `endif
        this.nxt_hdr.pack_hdr (pkt, index);
    end // }

    // post_pack task to encrypt and add ICV to packet
    if (process_ae)
    begin // {
        post_pack (pkt, pkt_ptr);
        `ifdef SVFNYI_0
        index += (icv_sz * 8);
        `else
        index += icv_sz;
        `endif
    end // }
  endtask : pack_hdr // }

  task unpack_hdr (ref   bit [7:0] pkt   [],
                   ref   int       index,
                   ref   hdr_class hdr_q [$],
                   input int       mode        = DUMB_UNPACK,
                   input bit       last_unpack = 1'b0); // {
    hdr_class lcl_class;
    int       pkt_ptr;
    // unpack class members
    if (pkt[index] & 8'h20) // tci[3] = 1'b1
    begin // {
        sectag_sz = 16;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 14);
        {tci, an, sl, pn, sci} = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, 14);
        {>>{tci, an, sl, pn, sci}} = hdr;
        `endif
    end // }
    else
    begin // {
        sectag_sz = 8;
        `ifdef SVFNYI_0
        harray.unpack_array (pkt, pack_vec, index, 6);
        {tci, an, sl, pn} = pack_vec;
        `else
        harray.copy_array (pkt, hdr, index, 6);
        {>>{tci, an, sl, pn}} = hdr;
        `endif
    end // }
    icv_sz  = 16;
    update_len (index, pkt.size, sectag_sz);
    // decrypt pkt and remove icv from packet - trl_len stays 0 as ICV is removed
    if (process_ae)
    begin // {
        pkt_ptr = (index + 2);
        post_pack (pkt, pkt_ptr, 0);
    end // }
    //unpack etype
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, 2);
    etype = pack_vec;
    `else
    harray.copy_array (pkt, hdr, index, 2);
    {>>{etype}} = hdr;
    `endif
    // get next hdr and update common nxt_hdr fields
    if (mode == SMART_UNPACK)
    begin // {
        $cast (lcl_class, this);
        if (unpack_en[get_hid_from_etype(etype)] & (pkt.size > index))
            super.update_nxt_hdr_info (lcl_class, hdr_q, get_hid_from_etype (etype));
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

  task post_pack (ref   bit [7:0] pkt [],
                  input int       index,
                  input int       enc_dcr = 1); // {
    bit [7:0]     out_pkt [];
    int           out_plen;
    int           avl_len;
    toh_class     lcl_toh;

    // copying original pkt
    if (enc_dcr == 1)
    begin // {
        super.plib.pkt_modified = 1'b1;
        super.plib.org_pkt      = pkt;
    end // }

    // setting up auth and enc related parameter
    auth_st     = index - 14 - sectag_sz;
    auth_sz     = sectag_sz + 12;
    if (enc_dcr == 1)
    begin // {
        avl_len = index + super.nxt_hdr.total_hdr_len;
        enc_sz  = 2 + super.nxt_hdr.total_hdr_len;
    end // }
    else
    begin // {
        lcl_toh = new (super.plib);
        $cast (lcl_toh, super.all_hdr[i]);
        if (lcl_toh.cal_n_add_crc)
            avl_len = pkt.size - icv_sz - 4;
        else
            avl_len = pkt.size - icv_sz;
        enc_sz  = 2 + avl_len - index;
    end // }
    if ((auth_sz + auth_adjust) > (avl_len - auth_st))
        auth_sz = avl_len - auth_st;
    else
        auth_sz += auth_adjust;
    if (enc_sz > auth_adjust)
        enc_sz  -= auth_adjust;
    else
        enc_sz   = 0;
    auth_only   = !enc_en;

    // calculate final sci needed for enc/dec
    cal_final_sci;

    // dpi call to enc/dec and authenticate pkt
    `ifndef NO_PROCESS_AE
    pkt     = new [avl_len] (pkt); 
    out_pkt = new [avl_len + icv_sz];
    gcm_crypt (key,
               final_sci,
               pn,
               auth_only,
               auth_st,
               auth_sz,
               enc_dcr,
               enc_sz,
               pkt,
               out_pkt,
               out_plen);
    `endif
    index = out_pkt.size - 16;
    if (enc_dcr == 1)
    begin // {
        if (corrupt_icv)
            harray.pack_array_8 (icv, out_pkt, index, 1'b1);
        pkt = new[super.plib.org_pkt.size] (out_pkt);
    end // }
    else
        // Removing ICV from the packet 
        pkt = new[index] (out_pkt);
    harray.copy_array (out_pkt, icv, index, 16);
    out_pkt.delete();
  endtask : post_pack // }

  task cal_final_sci; // {
    eth_hdr_class lcl_eth;
    lcl_eth = new (super.plib, `MAX_NUM_INSTS+1);
    $cast (lcl_eth, super.prv_hdr);
    if (ignore_ES_0) 
    begin // {
        // final sci calculation 
        casex ({tci[3], tci[4], tci[2]})        // SC-ES-SCB {
            3'b1xx  : final_sci = sci;
            3'b0x1  : final_sci = {lcl_eth.sa, scb_port};
            3'b0x0  : final_sci = {lcl_eth.sa, default_port};   
            default : final_sci = implicit_sci; // Not possible.. Error case
        endcase // }
    end // }
    else
    begin // {
        // final sci calculation 
        casex ({tci[3], tci[4], tci[2]})        // SC-ES-SCB {
            3'b1xx  : final_sci = sci;
            3'b011  : final_sci = {lcl_eth.sa, scb_port};
            3'b010  : final_sci = {lcl_eth.sa, default_port};   
            3'b001  : final_sci = {implicit_sci[63:16], scb_port};
            3'b00x  : final_sci = implicit_sci;
            default : final_sci = implicit_sci; // Not possible.. Error case
        endcase // }
    end // }
  endtask : cal_final_sci // }

  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    macsec_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    this.tci               = lcl.tci;                 
    this.an                = lcl.an;
    this.sl                = lcl.sl;
    this.pn                = lcl.pn;
    this.sci               = lcl.sci;
    this.etype             = lcl.etype;
    this.icv               = lcl.icv;
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.i                 = lcl.i;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.process_ae        = lcl.process_ae;
    this.corrupt_tci_ver   = lcl.corrupt_tci_ver;
    this.corrupt_tci_es_sc = lcl.corrupt_tci_es_sc;
    this.corrupt_tci_scb   = lcl.corrupt_tci_scb;
    this.corrupt_tci_e_c   = lcl.corrupt_tci_e_c;
    this.corrupt_sl        = lcl.corrupt_sl;
    this.corrupt_icv       = lcl.corrupt_icv;
    this.enc_en            = lcl.enc_en;
    this.ignore_ES_0       = lcl.ignore_ES_0;
    // ~~~~~~~~~~ MACsec Programming variables ~~~~~~~~~~
    this.auth_adjust       = lcl.auth_adjust;
    this.key               = lcl.key;
    this.implicit_sci      = lcl.implicit_sci;
    this.scb_port          = lcl.scb_port;
    this.default_port      = lcl.default_port;
    // ~~~~~~~~~~ Local MACsec related variables ~~~~~~~~~~
    this.final_sci         = lcl.final_sci;
    this.auth_st           = lcl.auth_st;
    this.auth_sz           = lcl.auth_sz;
    this.auth_only         = lcl.auth_only;
    this.enc_sz            = lcl.enc_sz;
    this.icv_sz            = lcl.icv_sz;
    this.sectag_sz         = lcl.sectag_sz;
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    string tci_brk;
    macsec_hdr_class lcl;
    $cast (lcl, cmp_cls);
    $sformat(tci_brk, "=> V %b ES %b SC %b SCB %b E %b C %b", tci[5],tci[4],tci[3],tci[2],tci[1],tci[0]);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 006, "tci", tci, lcl.tci, null_a, null_a, tci_brk);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 002, "an", an, lcl.an);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    DEC, 008, "sl", sl, lcl.sl);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 032, "pn", pn, lcl.pn);
    if (tci[3] == 1'b1)
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 064, "sci", sci, lcl.sci);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX, 016, "etype", etype, lcl.etype, null_a, null_a, get_etype_name(etype));
    if (process_ae)
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     HEX, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Encryption Related ~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "auth_st", auth_st, lcl.auth_st);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "auth_sz", auth_sz, lcl.auth_sz);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEC, 008, "auth_adjust", auth_adjust, lcl.auth_adjust);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "enc_en", enc_en, lcl.enc_en);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "enc_sz", enc_sz, lcl.enc_sz);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 064, "implict_sci", implicit_sci, lcl.implicit_sci);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "scb_port", scb_port, lcl.scb_port);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 016, "default_port", default_port, lcl.default_port);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 128, "key", key, lcl.key);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 064, "final_sci", final_sci, lcl.final_sci);
    hdis.display_fld (mode, hdr_name, ARRAY_NH,   DEF, 000, "icv", 0, 0, icv, lcl.icv);
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "process_ae", process_ae, lcl.process_ae);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_tci_ver", corrupt_tci_ver, lcl.corrupt_tci_ver);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_tci_es_sc", corrupt_tci_es_sc, lcl.corrupt_tci_es_sc); 
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_tci_scb", corrupt_tci_scb, lcl.corrupt_tci_scb);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_tci_e_c", corrupt_tci_e_c, lcl.corrupt_tci_e_c);   
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_sl", corrupt_sl, lcl.corrupt_sl);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "corrupt_icv", corrupt_icv, lcl.corrupt_icv);        
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, BIN, 001, "ignore_ES_0", ignore_ES_0, lcl.ignore_ES_0);        
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode); 
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "icv_sz", icv_sz, lcl.icv_sz);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 032, "sectag_sz", sectag_sz, lcl.sectag_sz);
    end // }

    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

endclass : macsec_hdr_class // }
