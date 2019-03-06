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
//  Top Class of System Verilog Pkt Library
// ----------------------------------------------------------------------

`include "hdr_class.sv"
typedef class pktlib_class;

class pktlib_main_class extends pktlib_object_class; // {

  // ~~~~~~~~~~ Class/Contol variables ~~~~~~~~~~
         pktlib_display_class hdis;
         hdr_class            hdr_db  [TOTAL_HID] [`MAX_NUM_INSTS+1];
         int                  inst_db [TOTAL_HID]; // instance number database needed for unpack
  rand   hdr_class            first_hdr;
         hdr_class            hdr_q   [$];
         bit [7:0]            org_pkt [];            // original packet after build was done
         bit [7:0]            pkt     [];            // pkt after build was done
         bit                  pkt_modified  = 1'b0;  // indicates wether pkt got modified in post_pack
         string               cfg_hdr_list;
         int                  pkt_format    = IEEE802;

  // ~~~~~~~~~~ Contol variables for pkt driver ~~~~~~~~~~
         int                  pid          = 0;           // Packet Id
         int                  path         = EGR;
         int                  pnum         = 0;           // port num
         int                  add_ipg_by   = `ADD_IPG_BY; // increase IPG of pkt by
         int                  rate_limit   = 1;           // rate limit the pkt for Flow control
         int                  pkt_st_time  = 0;
         int                  pkt_end_time = 0;
         bit [31:0]           pkt_crc      = 0;
         bit [15:0]           drv_ctrl     = NO_ERR;      
         bit                  dsc_1        = 1'b0;
         bit [7:0]            dsc_8        = 8'h0;
         bit [15:0]           dsc_16       = 16'h0;
         bit [31:0]           dsc_32       = 32'h0;
         bit [63:0]           dsc_64       = 64'h0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~
  constraint user_constraint
  {
  }

  // ~~~~~~~~~~ Global Tasks ~~~~~~~~~~

  // This function news all the hdrs
  function new (); // {
  endfunction : new // }

  // This task configures and links all the hdrs used for the particular pkt
  // For E.g. -> cfg_hdr ({eth[0], dot1q[0], data[0]});
  function void cfg_hdr (hdr_class hdr [$]  = {},
                bit       push_top = 1'b1,
                bit       push_eoh = 1'b1,
                bit       clr_hdrq = 1'b1); // {
    int pkt_format_hid;
    foreach (hdr[hdr_ls])
        hdr_q.push_back (hdr[hdr_ls]);
    if (push_eoh)
        hdr_q.push_back  (hdr_db[EOH_HID][0]);
    if (push_top)
        hdr_q.push_front (hdr_db[TOP_HID][0]);
    if (hdr_q[1].hid == PTH_HID)
        pkt_format_hid = 2;
    else
        pkt_format_hid = 1;
    case (hdr_q[pkt_format_hid].hid) // {
       ETH_HID  : pkt_format = IEEE802;  
       FC_HID   : pkt_format = FC;  
       DPHY_HID : pkt_format = MIPI_CSI2_DPHY;  
       default  : pkt_format = IEEE802;  
    endcase // }
    foreach (hdr_q[cfg_ls])
    begin // {
        hdr_q[cfg_ls].prv_hdr     = hdr_q[cfg_ls-1];
        hdr_q[cfg_ls].nxt_hdr     = hdr_q[cfg_ls+1];
        hdr_q[cfg_ls].all_hdr     = hdr_q;
        hdr_q[cfg_ls].psnt        = 1'b1;
        hdr_q[cfg_ls].cfg_id      = cfg_ls;
        hdr_q[cfg_ls].pkt_format  = pkt_format;
    end // }
    first_hdr = hdr_q[0];
    if (clr_hdrq)
        hdr_q = {};
  endfunction : cfg_hdr // }

  //  This task adds hdr/hdrs to hdr_q statically until last_hdr = 1
  task add_hdr (hdr_class hdr [$]  = {},
                bit       last_hdr = 1'b0); // { 
    foreach (hdr[hdr_ls])
        hdr_q.push_back (hdr[hdr_ls]);
    if (last_hdr)
        cfg_hdr (); 
  endtask : add_hdr // }

  // This task insert hdr after input hid, assuming cfg_hdr is done
  task ins_hdr (hdr_class in_hdr,
                int       after_hid,
                int       after_inst = 0); // {
    hdr_class hdr[$];
    hdr_q = {};
    hdr   = first_hdr.all_hdr;
    foreach (hdr[hdr_ls])
    begin // {
        if ((hdr[hdr_ls].hid == after_hid) & (hdr[hdr_ls].inst_no == after_inst))
            hdr.insert(hdr[hdr_ls].cfg_id+1, in_hdr);
    end // }
    cfg_hdr (hdr, 1'b0, 1'b0);
  endtask : ins_hdr // }

  // This task remove hdr from the hdr_q, assuming cfg_hdr is done
  task rmv_hdr (int hid_rm,
                int inst_rm = 0); // {
    hdr_class hdr[$];
    hdr_q = {};
    hdr   = first_hdr.all_hdr;
    foreach (hdr[hdr_ls])
    begin // {
        if ((hdr[hdr_ls].hid == hid_rm) & (hdr[hdr_ls].inst_no == inst_rm))
            hdr.delete(hdr[hdr_ls].cfg_id);
    end // }
    cfg_hdr (hdr, 1'b0, 1'b0);
  endtask : rmv_hdr // }

  function void pre_randomize (); // {
  endfunction : pre_randomize // }

  function void post_randomize (); // {
  endfunction : post_randomize // }

  // This task packs all the fields of each configured hdr into byte array of pkt
  // this task is called after randomization
  task pack_hdr (ref    bit [7:0] ppkt []); // {
    int index;
    index = 0;
    this.first_hdr.pack_hdr (ppkt, index);
    pkt   = new [ppkt.size] (ppkt);
  endtask : pack_hdr // }

  // This task unpacks packs all the fields of each configured hdr
  task unpack_hdr (ref   bit [7:0] ppkt [],
                   input int       mode     = DUMB_UNPACK,
                   input hdr_class hdr [$]  = {},
                   input int       p_format = IEEE802); // {
    bit [7:0] copy_pkt [];
    int       index;
    index    = 0;
    copy_pkt = ppkt; 
    // clear instance database
    foreach (inst_db[db_ls])
        inst_db[db_ls] = 0;
    if (mode == SMART_UNPACK)
    begin // {
        hdr_q = {};
        if (hdr.size == 0)
        begin // {
            pkt_format = p_format;
            case (p_format) // { 
                IEEE802        : hdr_q.push_back (hdr_db[ETH_HID][0]);
                FC             : hdr_q.push_back (hdr_db[FC_HID][0]);
                MIPI_CSI2_DPHY : hdr_q.push_back (hdr_db[DPHY_HID][0]);
                default        : hdr_q.push_back (hdr_db[ETH_HID][0]);
            endcase // }
        end // }
        else
            hdr_q = hdr;
        cfg_hdr ({}, 1'b1, 1'b0, 1'b0); 
        foreach (hdr_q[db_ls])
           inst_db[hdr_q[db_ls].hid]++;  
    end // }
    this.first_hdr.unpack_hdr (copy_pkt, index, hdr_q, mode);
    hdr_q = {};
    pkt   = new [ppkt.size] (ppkt);
  endtask : unpack_hdr // }

  // This task copies all hdrs of the input class to this class 
  task cpy_hdr (pktlib_object_class cpy_cls,
                int                 mode = COPY_LITE); // {
    pktlib_main_class cpy_frm;
    pktlib_class      cp_2, cp_frm;
    $cast (cpy_frm, cpy_cls);
    this.hdis         = cpy_frm.hdis;
    this.hdr_db       = cpy_frm.hdr_db;
    this.inst_db      = cpy_frm.inst_db;
    this.first_hdr    = cpy_frm.first_hdr;
    this.hdr_q        = cpy_frm.hdr_q;  
    this.org_pkt      = cpy_frm.org_pkt;
    this.pkt          = cpy_frm.pkt;
    this.pkt_modified = cpy_frm.pkt_modified;
    this.cfg_hdr_list = cpy_frm.cfg_hdr_list;
    this.pkt_format   = cpy_frm.pkt_format;
    this.pid          = cpy_frm.pid;        
    this.path         = cpy_frm.path;        
    this.pnum         = cpy_frm.pnum;        
    this.add_ipg_by   = cpy_frm.add_ipg_by; 
    this.rate_limit   = cpy_frm.rate_limit;
    this.pkt_st_time  = cpy_frm.pkt_st_time;
    this.pkt_end_time = cpy_frm.pkt_end_time;
    this.drv_ctrl     = cpy_frm.drv_ctrl;   
    this.dsc_8        = cpy_frm.dsc_8;     
    this.dsc_16       = cpy_frm.dsc_16;   
    this.dsc_32       = cpy_frm.dsc_32;  
    this.dsc_64       = cpy_frm.dsc_64;                
    if (mode === COPY_LITE)
        this.first_hdr.cpy_hdr (cpy_frm.first_hdr);
    else
    begin // {
        $cast (cp_frm, cpy_cls);
        foreach (hdr_db[hdr_ls, inst_ls])
        begin // {
           cp_2 = new();
           if (cp_frm.hdr_db[hdr_ls][inst_ls] != null)
             cp_2.hdr_db[hdr_ls][inst_ls].cpy_hdr (cp_frm.hdr_db[hdr_ls][inst_ls], 1'b1);
        end // }
    end // }
  endtask : cpy_hdr // }

  // This task displays cfg_hdr
  task display_cfg_hdr (int mode        =  DISPLAY,
                        int min_hdrq_sz = 2); // {
    foreach (first_hdr.all_hdr[ls])
    begin // {
        if (ls == (first_hdr.all_hdr.size - 1))
            $sformat (cfg_hdr_list, "%0s} (%0s)", cfg_hdr_list, first_hdr.get_pkt_format_name(pkt_format));
        else if (ls == 0)
           $sformat (cfg_hdr_list,"{");
        else if (ls <  (first_hdr.all_hdr.size- 2)) 
            $sformat (cfg_hdr_list,"%0s%0s, ", cfg_hdr_list,first_hdr.all_hdr[ls].hdr_name);
         else
            $sformat (cfg_hdr_list,"%0s%0s", cfg_hdr_list,first_hdr.all_hdr[ls].hdr_name);
    end // }
    if (mode != NO_DISPLAY)
        $display ("    cfg_hdr : %0s", cfg_hdr_list);
  endtask : display_cfg_hdr // }

  // This task displays all the feilds of individual hdrs used
  task display_hdr (int    mode               = DISPLAY,
                    string path_name          = ""); // {
    hdis  = new (path_name);
    this.first_hdr.display_hdr (hdis, this.first_hdr, mode);
    $display("");
  endtask : display_hdr // }

  // This task display entire pkt
  task display_pkt (bit [7:0] pkt [],
                    string    path_name   = "",
                    string    hname       = "pkt_lib",
                    string    usr_comment = "NO",
                    int       mode        = DISPLAY); // {
    hdis = new (path_name);
    if (pkt_modified)
    begin // {
        pkt_modified = 1'b0;
        usr_comment  = "       ~~~~~~~ Original Packet as per cfg_hdr ~~~~~~~";
        hdis.display_array8 (org_pkt, hname, usr_comment, mode);
        org_pkt.delete();
        usr_comment  = "       ~~~~~~~ Pkt after Modification/Encryption ~~~~~";
        hdis.display_array8 (pkt, hname, usr_comment, mode);
    end // }
    else
        hdis.display_array8 (pkt, hname, usr_comment, mode);
  endtask : display_pkt // }

 // This task displays entire pkt with hdrs
 task display_hdr_pkt (bit [7:0] pkt [],
                       string    path_name   = "",
                       string    hname       = "pkt_lib",
                       string    usr_comment = "NO",
                       int       mode        = DISPLAY); // {
    display_cfg_hdr (mode);
    display_hdr (mode, path_name);
    display_pkt (pkt, path_name, hname, usr_comment, mode);
  endtask : display_hdr_pkt // }

  task compare_cfg_hdr (      pktlib_main_class cmp_cls,
                        ref   int               err,
                        input int               mode = COMPARE); // {
    bit display_on;
    display_cfg_hdr         (NO_DISPLAY);
    cmp_cls.display_cfg_hdr (NO_DISPLAY);
    if ((mode == NO_DISPLAY) | (mode == COMPARE_NO_DISPLAY))
        display_on = 1'b0;
    else
        display_on = 1'b1;
    if (cfg_hdr_list != cmp_cls.cfg_hdr_list)
    begin // {
        err++;
        if (display_on)
            $display ("    cmp_hdr : %0s != %0s (ERROR)", cfg_hdr_list, cmp_cls.cfg_hdr_list);
    end // }
    else if (display_on)
        $display ("    cmp_hdr : %0s", cfg_hdr_list);
  endtask : compare_cfg_hdr // }

  // This task compare all the feilds of individual hdrs with other class
  task compare_hdr (      pktlib_main_class cmp_cls,
                    ref   int               err,
                    input int               mode = COMPARE,
                    input string            path_name          = ""); // {
    int cfg_err;
    hdis    = new (path_name);
    cfg_err = 0;
    compare_cfg_hdr (cmp_cls, cfg_err, mode);
    this.first_hdr.display_hdr (hdis, cmp_cls.first_hdr, mode);
    if ((hdis.err + cfg_err) > 0)
        err++;
  endtask : compare_hdr // }

 // This task compare pkts and all the feilds of individual hdrs with other class
  task compare_pkt (      bit [7:0] p1 [],
                          bit [7:0] p2 [],
                    ref   int       err,
                    input hdr_class hdr [$]   = {},
                    input int       p_format  = IEEE802,
                    input int       mode      = COMPARE,
                    input string    path_name = "",
                    input string    hname     = "pkt_lib",
                    input string    cmp_type  = "Pkt",
                    input bit       crc_psnt  = 1'b1); // {
    pktlib_class p_cls;
    int          cfg_err;
    cfg_err = 0;
    hdis = new (path_name);
    hdis.compare_array8 (p1, p2, cfg_err, mode, hname,, cmp_type);
    if (cfg_err > 0)
    begin // {
        err++;
        p_cls = new ();
        p_cls.toh.cal_n_add_crc = crc_psnt;
        unpack_hdr       (p1, SMART_UNPACK, hdr, p_format);
        p_cls.unpack_hdr (p2, SMART_UNPACK, hdr, p_format);
        compare_hdr      (p_cls, cfg_err, mode, path_name);
    end // }
    $display("");
  endtask : compare_pkt // }

endclass : pktlib_main_class // }
