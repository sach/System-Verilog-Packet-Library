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
//  Top Class include file of System Verilog Pkt Library
// ----------------------------------------------------------------------

// ~~~~~~~~~~ Global defines ~~~~~~~~~~
`define MAX_PLEN            16383
`define MIN_PLEN            0
`define PLEN_MULTI          1
`define MAX_NUM_INSTS       20
`define MIN_CHOP_LEN        1
`define MAX_PAD_LEN         128
`define MAX_PT_LEN          32
`define VEC_SZ              1024
`define ADD_IPG_BY          0

// ~~~~~~~~~~ enum defination for pkt driver ctrl ~~~~~~~~~~~~~~~~~
  enum
  {
    NO_ERR,
    ERR_PKT,      // introduce error
    DROP_PKT,     // drop pkt
    DROP_ERR_PKT  // introduce error and drop pkt
  } drv_ctrl_mode;

// ~~~~~~~~~~ enum defination for copy hdr ~~~~~~~~~~~~~~~~~
  enum
  {
    COPY_LITE,
    COPY_DEEP
  } copy_mode;

// ~~~~~~~~~~ enum defination for path name ~~~~~~~~~~~~~~~~~
  enum
  {
    EGR,
    IGR,
    EGR_IGR
  } path_name;

// ~~~~~~~~~~ enum defination for feild value to display ~~~~~~~~~~~~~
  enum
  {
    HEX,
    DEC,
    BIN,
    DEF
  } fld_val;

// ~~~~~~~~~~ enum defination for feild type to display ~~~~~~~~~~~~~
  enum
  {
    BIT_VEC,
    BIT_VEC_NH,
    ARRAY,
    ARRAY_NH,
    STRING,
    STRING_NH // NH means its not a header field
  } fld_type;

// ~~~~~~~~~~ enum defination for path name ~~~~~~~~~~~~~~~~~
  enum
  {
    NO_DISPLAY,
    DISPLAY,
    DISPLAY_FULL,
    COMPARE_NO_DISPLAY,
    COMPARE,
    COMPARE_HDR,  // Only used for compare_pkt task eqal to COMPARE for others
    COMPARE_FULL,
    TOTAL_DISPLAY_MODE
  } display_mode;

// ~~~~~~~~~~ enum defination for unpack modes ~~~~~~~~~~~~~
  enum
  {
    SMART_UNPACK,
    DUMB_UNPACK
  } unpack_mode;

// ~~~~~~~~~~ enum defination for data type  ~~~~~~~~~~~~~
  enum
  {
    INCR,
    DECR,
    INVR,
    FIX,
    RND 
  } data_types;

// ~~~~~~~~~~ enum defination for all the headers ~~~~~~~~~~~~~
  enum
  {
    TOP_HID,                 // 0
    PTH_HID,                 // 1
    ETH_HID,                 // 2
    MACSEC_HID,              // 3
    ARP_HID,                 // 4
    RARP_HID,                // 5
    DOT1Q_HID,               // 6
    ALT1Q_HID,               // 7
    STAG_HID,                // 8
    ITAG_HID,                // 9
    ETAG_HID,                // 10
    VNTAG_HID,               // 11
    TRILL_HID,               // 12
    SNAP_HID,                // 13
    PTL2_HID,                // 14
    MPLS_HID,                // 15
    MMPLS_HID,               // 16
    IPV4_HID,                // 17
    IPV6_HID,                // 18
    PTIP_HID,                // 19
    IPSEC_HID,               // 20
    ICMP_HID,                // 21
    ICMPV6_HID,              // 22
    IGMP_HID,                // 23
    TCP_HID,                 // 24
    UDP_HID,                 // 25
    GRE_HID,                 // 26
    PTP_HID,                 // 27
    NTP_HID,                 // 28 
    LISP_HID,                // 29 
    OTV_HID,                 // 30 
    STT_HID,                 // 31 
    VXLAN_HID,               // 32
    DATA_HID,                // 33
    EOH_HID,                 // 34
//  XXX_HID,                 // 35
    TOTAL_HID                // 35
  } hdr_id;

  // ~~~~~~~~~~ typedef all the classes ~~~~~~~~~~
  typedef class hdr_class;
  typedef class pktlib_main_class;
  typedef class toh_class;
  typedef class pt_hdr_class;
  typedef class eth_hdr_class;
  typedef class macsec_hdr_class;
  typedef class arp_hdr_class;
  typedef class snap_hdr_class;
  typedef class dot1q_hdr_class;
  typedef class itag_hdr_class;
  typedef class etag_hdr_class;
  typedef class vntag_hdr_class;
  typedef class trill_hdr_class;
  typedef class ptl2_hdr_class;
  typedef class mpls_hdr_class;
  typedef class ipv4_hdr_class;
  typedef class ipv6_hdr_class;
  typedef class ptip_hdr_class;
  typedef class ipsec_hdr_class;
  typedef class icmp_hdr_class;
  typedef class igmp_hdr_class;
  typedef class ptp_hdr_class;
  typedef class ntp_hdr_class;
  typedef class tcp_hdr_class;
  typedef class udp_hdr_class;
  typedef class gre_hdr_class;
  typedef class lisp_hdr_class;
  typedef class otv_hdr_class;
  typedef class stt_hdr_class;
  typedef class vxlan_hdr_class;
  typedef class data_class;
//typedef class xxx_class;
  typedef class eoh_class;


  // ~~~~~~~~~~ include all the classes ~~~~~~~~~~
  `include "pktlib_object_class.sv"
  `include "pktlib_display_class.sv"
  `include "pktlib_array_class.sv"
  `include "pktlib_crc_chksm_class.sv"
  `include "pktlib_main_class.sv"

  // ~~~~~~~~~~ include all the hdr supported classes ~~~~~~~~~~
  `include "toh_class.sv"
  `include "pt_hdr_class.sv"
  `include "eth_hdr_class.sv"
  `include "macsec_hdr_class.sv"
  `include "arp_hdr_class.sv"
  `include "dot1q_hdr_class.sv"
  `include "itag_hdr_class.sv"
  `include "etag_hdr_class.sv"
  `include "vntag_hdr_class.sv"
  `include "trill_hdr_class.sv"
  `include "snap_hdr_class.sv"
  `include "ptl2_hdr_class.sv"
  `include "mpls_hdr_class.sv"
  `include "ipv4_hdr_class.sv"
  `include "ipv6_hdr_class.sv"
  `include "ptip_hdr_class.sv"
  `include "ipsec_hdr_class.sv"
  `include "icmp_hdr_class.sv"
  `include "igmp_hdr_class.sv"
  `include "tcp_hdr_class.sv"
  `include "udp_hdr_class.sv"
  `include "gre_hdr_class.sv"
  `include "ptp_hdr_class.sv"
  `include "ntp_hdr_class.sv"
  `include "lisp_hdr_class.sv"
  `include "otv_hdr_class.sv"
  `include "stt_hdr_class.sv"
  `include "vxlan_hdr_class.sv"
  `include "data_class.sv"
//`include "xxx_class.sv"
  `include "eoh_class.sv"

  // ~~~~~~~~~~ Declare All headers~~~~~~~~~~
`define HDR_DECLARATION \
  toh_class           toh;\
  pt_hdr_class        pth     [`MAX_NUM_INSTS];\
  eth_hdr_class       eth     [`MAX_NUM_INSTS];\
  macsec_hdr_class    macsec  [`MAX_NUM_INSTS];\
  arp_hdr_class       arp     [`MAX_NUM_INSTS];\
  arp_hdr_class       rarp    [`MAX_NUM_INSTS];\
  dot1q_hdr_class     dot1q   [`MAX_NUM_INSTS];\
  dot1q_hdr_class     alt1q   [`MAX_NUM_INSTS];\
  dot1q_hdr_class     stag    [`MAX_NUM_INSTS];\
  itag_hdr_class      itag    [`MAX_NUM_INSTS];\
  etag_hdr_class      etag    [`MAX_NUM_INSTS];\
  vntag_hdr_class     vntag   [`MAX_NUM_INSTS];\
  trill_hdr_class     trill   [`MAX_NUM_INSTS];\
  snap_hdr_class      snap    [`MAX_NUM_INSTS];\
  ptl2_hdr_class      ptl2    [`MAX_NUM_INSTS];\
  mpls_hdr_class      mpls    [`MAX_NUM_INSTS];\
  mpls_hdr_class      mmpls   [`MAX_NUM_INSTS];\
  ipv4_hdr_class      ipv4    [`MAX_NUM_INSTS];\
  ipv6_hdr_class      ipv6    [`MAX_NUM_INSTS];\
  ptip_hdr_class      ptip    [`MAX_NUM_INSTS];\
  ipsec_hdr_class     ipsec   [`MAX_NUM_INSTS];\
  icmp_hdr_class      icmp    [`MAX_NUM_INSTS];\
  icmp_hdr_class      icmpv6  [`MAX_NUM_INSTS];\
  igmp_hdr_class      igmp    [`MAX_NUM_INSTS];\
  tcp_hdr_class       tcp     [`MAX_NUM_INSTS];\
  udp_hdr_class       udp     [`MAX_NUM_INSTS];\
  gre_hdr_class       gre     [`MAX_NUM_INSTS];\
  ptp_hdr_class       ptp     [`MAX_NUM_INSTS];\
  ntp_hdr_class       ntp     [`MAX_NUM_INSTS];\
  lisp_hdr_class      lisp    [`MAX_NUM_INSTS];\
  otv_hdr_class       otv     [`MAX_NUM_INSTS];\
  stt_hdr_class       stt     [`MAX_NUM_INSTS];\
  vxlan_hdr_class     vxlan   [`MAX_NUM_INSTS];\
  data_class          data    [`MAX_NUM_INSTS];\
  eoh_class           eoh
  
  // ~~~~~~~~~~ New All headers~~~~~~~~~
`define NEW_HDR\
    for (i = 0; i < `MAX_NUM_INSTS; i++)\
    begin\
        pth    [i] = new (this, i);\
        eth    [i] = new (this, i);\
        macsec [i] = new (this, i);\
        arp    [i] = new (this, i);\
        rarp   [i] = new (this, i, 1);\
        dot1q  [i] = new (this, i);\
        alt1q  [i] = new (this, i, 1);\
        stag   [i] = new (this, i, 2);\
        itag   [i] = new (this, i);\
        etag   [i] = new (this, i);\
        vntag  [i] = new (this, i);\
        trill  [i] = new (this, i);\
        ptl2   [i] = new (this, i);\
        snap   [i] = new (this, i);\
        mpls   [i] = new (this, i);\
        mmpls  [i] = new (this, i, 1);\
        ipv4   [i] = new (this, i);\
        ipv6   [i] = new (this, i);\
        ptip   [i] = new (this, i);\
        ipsec  [i] = new (this, i);\
        icmp   [i] = new (this, i);\
        icmpv6 [i] = new (this, i, 1);\
        igmp   [i] = new (this, i);\
        tcp    [i] = new (this, i);\
        udp    [i] = new (this, i);\
        gre    [i] = new (this, i);\
        ptp    [i] = new (this, i);\
        ntp    [i] = new (this, i);\
        lisp   [i] = new (this, i);\
        otv    [i] = new (this, i);\
        stt    [i] = new (this, i);\
        vxlan  [i] = new (this, i);\
        data   [i] = new (this, i);\
    end\
    toh  = new (this);\
    eoh  = new (this)

  // ~~~~~~~~~~ EOF ~~~~~~~~~~~~~~~~
