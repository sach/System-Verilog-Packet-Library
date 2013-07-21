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
//  hdr class to generate Infiniband Base Transport Feild (BTH) header and other 
//  Extension Transport headers (InfiniBand Architecture Specification Volume 1 Release 1.2.1)
//
//  BTH header Format (12B)
//  +-------------------+
//  | opcode[7:0]       | -> indicates the IBA packet type. also specifies which extension headers follow BTH
//  +-------------------+
//  | S[0:0]            |
//  +-------------------+
//  | M[0:0]            |
//  +-------------------+
//  | padcnt[1:0]       |
//  +-------------------+
//  | tver[3:0]         | 
//  +-------------------+
//  | p_key[15:0]       |
//  +-------------------+
//  | rsvd0[7:0]        |
//  +-------------------+
//  | destQP[23:0]      |
//  +-------------------+
//  | A[0:0]            |
//  +-------------------+
//  | rsvd1[7:0]        |
//  +-------------------+
//  | psn[23:0]         |
//  +-------------------+
//
// Extension Transport Headers :
//
// RDETH(Reliable Datagram Extended Transport Header) Format (4B)
//  +-------------------+
//  | rsvd_rdeth[7:0]   |
//  +-------------------+
//  | EEcnxt[23:0]      |
//  +-------------------+
//
// DETH(Datagram Extended Transport Header) Format (8B)
//  +-------------------+
//  | q_key[31:0]       |
//  +-------------------+
//  | rsvd_eth[7:0]     |
//  +-------------------+
//  | srcQP[23:0]       |
//  +-------------------+
//
// RETH(RDMA Extended Transport Header) Format (16B)
//  +-------------------+
//  | va_reth[63:0]     |
//  +-------------------+
//  | r_key_reth[31:0]  |
//  +-------------------+
//  | dmalen[31:0]      |
//  +-------------------+
//
// ATOMICETH(Atomic Extended Transport Header) Format (28B)
//  +-------------------+
//  | va_aeth[63:0]     |
//  +-------------------+
//  | r_key_aeth[31:0]  |
//  +-------------------+
//  | swapdt[63:0]      |
//  +-------------------+
//  | cmprdt[63:0]      |
//  +-------------------+
//
// AETH(ACK Extended Transport Header Fields) (4B)
//  +-------------------+
//  | syndrom[7:0]      |
//  +-------------------+
//  | msn[23:0]         |
//  +-------------------+

// ATOMICACKETH(Atomic ACK Extended Transport Header) (8B)
//  +-----------------------+
//  | atomicacketh_hdr[63:0]| -> Original remote Date
//  +-----------------------+
//
// IMMDT(Immediate Extended Transport Header) (4B)
//  +-------------------+
//  | immdt_hdr[31:0]   |
//  +-------------------+
//
// IETH (Invalidate Extended Transport Header) (4B)
//  +-------------------+
//  | ieth_hdr [31:0]   |
//  +-------------------+
//
// No Trailer (trl_len = 0);
//
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +-------+---------+----------------------+---------------------------------+
//  | Width | Default | Variable             | Description                     |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b0    | corrupt_tver         | If 1, corrupts tver             |
//  |       |         |                      | (Version != 4'h0)               |
//  +-------+---------+----------------------+---------------------------------+
//  | 1     | 1'b0    | null_rsvd            | If 1, rsvd fields set to 0      |
//  +-------+---------+----------------------+---------------------------------+
//
// ----------------------------------------------------------------------

class bth_hdr_class extends hdr_class; // {

  // ~~~~~~~~~~ Class members ~~~~~~~~~~

  // BTH hdr 
  rand bit [7:0]          opcode; 
  rand bit                S;
  rand bit                M;
  rand bit [1:0]          padcnt;
  rand bit [3:0]          tver;  
  rand bit [15:0]         p_key; 
  rand bit [7:0]          rsvd0; 
  rand bit [23:0]         destQP;
  rand bit                A;     
  rand bit [6:0]          rsvd1; 
  rand bit [23:0]         psn;   

  // RDETH hdr
  rand bit [7:0]          rsvd_rdeth; 
  rand bit [23:0]         EEcnxt;

  // DETH hdr
  rand bit [31:0]         q_key; 
  rand bit [7:0]          rsvd_deth; 
  rand bit [23:0]         srcQP; 

  // RETH hdr
  rand bit [63:0]         va_reth;
  rand bit [31:0]         r_key_reth; 
  rand bit [31:0]         dmalen;

  // ATOMICETH hdr
  rand bit [63:0]         va_aeth;
  rand bit [31:0]         r_key_aeth; 
  rand bit [63:0]         swapdt; 
  rand bit [63:0]         cmprdt; 

  // AETH hdr
  rand bit [7:0]          syndrom;
  rand bit [23:0]         msn;

  // ATOMICACKETH hdr
  rand bit [63:0]         atomicacketh_hdr;

  // IMMDT hdr
  rand bit [31:0]         immdt_hdr;

  // IETH (Invalidate Extended Transport Header) (4B)
  rand bit [31:0]         ieth_hdr;

  // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
  rand bit [95:0]         bth_hdr;
  rand bit [31:0]         rdeth_hdr;
  rand bit [63:0]         deth_hdr;
  rand bit [127:0]        reth_hdr;
  rand bit [223:0]        atomiceth_hdr;
  rand bit [31:0]         aeth_hdr;
       bit [15:0]         bth_hdr_len;
       bit [15:0]         rdeth_hdr_len;
       bit [15:0]         deth_hdr_len;
       bit [15:0]         reth_hdr_len;
       bit [15:0]         atomiceth_hdr_len;
       bit [15:0]         aeth_hdr_len;
       bit [15:0]         atomicaeth_hdr_len;
       bit [15:0]         immdt_hdr_len;
       bit [15:0]         ieth_hdr_len;

  // ~~~~~~~~~~ Control variables ~~~~~~~~~~
       bit                corrupt_tver        = 1'b0;
       bit                null_rsvd           = 1'b0;

  // ~~~~~~~~~~ Constraints begins ~~~~~~~~~~
  constraint bth_hdr_user_constraint
  {
  }

  constraint legal_total_hdr_len
  {
    `LEGAL_TOTAL_HDR_LEN_CONSTRAINTS;
    total_hdr_len % 4 == 0;
  }

  constraint legal_hdr_len
  {
   (opcode == 8'b00000000) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00000001) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00000010) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00000011) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00000100) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00000101) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00000110) -> (hdr_len == bth_hdr_len + reth_hdr_len);
   (opcode == 8'b00000111) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00001000) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00001001) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00001010) -> (hdr_len == bth_hdr_len + reth_hdr_len);
   (opcode == 8'b00001011) -> (hdr_len == bth_hdr_len + reth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00001100) -> (hdr_len == bth_hdr_len + reth_hdr_len); // No pyld prsnt
   (opcode == 8'b00001101) -> (hdr_len == bth_hdr_len + aeth_hdr_len);
   (opcode == 8'b00001110) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00001111) -> (hdr_len == bth_hdr_len + aeth_hdr_len);
   (opcode == 8'b00010000) -> (hdr_len == bth_hdr_len + aeth_hdr_len);
   (opcode == 8'b00010001) -> (hdr_len == bth_hdr_len + aeth_hdr_len); // No pyld prsnt
   (opcode == 8'b00010010) -> (hdr_len == bth_hdr_len + aeth_hdr_len + atomicaeth_hdr_len);
   (opcode == 8'b00010011) -> (hdr_len == bth_hdr_len + atomiceth_hdr_len);
   (opcode == 8'b00010100) -> (hdr_len == bth_hdr_len + atomiceth_hdr_len);
   (opcode == 8'b00010101) -> (hdr_len == bth_hdr_len); // undefined -Reserved
   (opcode == 8'b00010110) -> (hdr_len == bth_hdr_len + ieth_hdr_len);
   (opcode == 8'b00010111) -> (hdr_len == bth_hdr_len + ieth_hdr_len);
   (opcode inside {[8'b00011000 : 8'b00011111]}) -> hdr_len == bth_hdr_len; // undefined -Reserved
   (opcode == 8'b00100000) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00100001) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00100010) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00100011) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00100100) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00100101) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00100110) -> (hdr_len == bth_hdr_len + reth_hdr_len);
   (opcode == 8'b00100111) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00101000) -> (hdr_len == bth_hdr_len);
   (opcode == 8'b00101001) -> (hdr_len == bth_hdr_len + immdt_hdr_len);
   (opcode == 8'b00101010) -> (hdr_len == bth_hdr_len + reth_hdr_len);
   (opcode == 8'b00101011) -> (hdr_len == bth_hdr_len + reth_hdr_len + immdt_hdr_len);
   (opcode inside {[8'b00101100 : 8'b00111111]}) -> hdr_len == bth_hdr_len; // undefined -Reserved
   (opcode == 8'b01000000) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01000001) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01000010) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01000011) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len);
   (opcode == 8'b01000100) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01000101) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len);
   (opcode == 8'b01000110) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len);
   (opcode == 8'b01000111) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01001000) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len);
   (opcode == 8'b01001001) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len);
   (opcode == 8'b01001010) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len);
   (opcode == 8'b01001011) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len  + reth_hdr_len + immdt_hdr_len);
   (opcode == 8'b01001100) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len); // No pyld psnt
   (opcode == 8'b01001101) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + aeth_hdr_len);
   (opcode == 8'b01001110) -> (hdr_len == bth_hdr_len + rdeth_hdr_len);
   (opcode == 8'b01001111) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + aeth_hdr_len);
   (opcode == 8'b01010000) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + aeth_hdr_len);
   (opcode == 8'b01010001) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + aeth_hdr_len); // No pyld psnt
   (opcode == 8'b01010010) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + aeth_hdr_len + atomicaeth_hdr_len); // No pyld psnt
   (opcode == 8'b01010011) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len); // No pyld psnt
   (opcode == 8'b01010100) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len); // No pyld psnt
   (opcode == 8'b01010101) -> (hdr_len == bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len); // No pyld psnt
   (opcode inside {[8'b01010110 : 8'b01100011]}) -> hdr_len == bth_hdr_len; // undefined -Reserved
   (opcode == 8'b01100100) -> (hdr_len == bth_hdr_len + deth_hdr_len);
   (opcode == 8'b01100101) -> (hdr_len == bth_hdr_len + deth_hdr_len + immdt_hdr_len);
   (opcode inside {[8'b01100110 : 8'b11111111]}) -> hdr_len == bth_hdr_len; // undefined -Reserved
   trl_len == 0;
  }

  constraint legal_tver
  {
    (corrupt_tver == 1'b0) -> (tver == 4'h0);
    (corrupt_tver == 1'b1) -> (tver != 4'h0);
  }

  constraint legal_rsvd
  {
    (null_rsvd == 1'b1) -> rsvd0      == 8'h0;
    (null_rsvd == 1'b1) -> rsvd1      == 7'h0;
    (null_rsvd == 1'b1) -> rsvd_rdeth == 8'h0;
    (null_rsvd == 1'b1) -> rsvd_deth  == 8'h0;
  }

  constraint legal_transport_hdr
  {
    bth_hdr           == {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn};
    rdeth_hdr         == {rsvd_rdeth, EEcnxt};
    deth_hdr          == {q_key, rsvd_deth, srcQP};
    reth_hdr          == {va_reth, r_key_reth, dmalen};
    atomiceth_hdr     == {va_aeth, r_key_aeth, swapdt, cmprdt};
    aeth_hdr          == {syndrom, msn};
  }

  // ~~~~~~~~~~ Task begins ~~~~~~~~~~

  function new (pktlib_main_class plib,
                int               inst_no); // {
    super.new (plib);
    hid          = BTH_HID;
    this.inst_no = inst_no;
    $sformat (hdr_name, "bth[%0d]",inst_no);
    super.update_hdr_db (hid, inst_no);
    bth_hdr_len        = 12;
    rdeth_hdr_len      = 4;
    deth_hdr_len       = 8;
    reth_hdr_len       = 16;
    atomiceth_hdr_len  = 28;
    aeth_hdr_len       = 4;
    atomicaeth_hdr_len = 8;
    immdt_hdr_len      = 4;
    ieth_hdr_len       = 4;
  endfunction : new // }

  task pack_hdr (ref   bit [7:0] pkt [],
                 ref   int       index,
                 input bit       last_pack = 1'b0); // {
    // pack class members
    `ifdef SVFNYI_0
    case (opcode) // { 
      8'b00000011 : pack_vec = {bth_hdr, immdt_hdr};
      8'b00000101 : pack_vec = {bth_hdr, immdt_hdr};
      8'b00000110 : pack_vec = {bth_hdr, reth_hdr};
      8'b00001001 : pack_vec = {bth_hdr, immdt_hdr}
      8'b00001010 : pack_vec = {bth_hdr, reth_hdr};
      8'b00001011 : pack_vec = {bth_hdr, reth_hdr, immdt_hdr};
      8'b00001100 : pack_vec = {bth_hdr, reth_hdr};
      8'b00001101 : pack_vec = {bth_hdr, aeth_hdr};
      8'b00001111 : pack_vec = {bth_hdr, aeth_hdr};
      8'b00010000 : pack_vec = {bth_hdr, aeth_hdr};
      8'b00010001 : pack_vec = {bth_hdr, aeth_hdr}; 
      8'b00010010 : pack_vec = {bth_hdr, aeth_hdr , atomicacketh_hdr};
      8'b00010011 : pack_vec = {bth_hdr, atomiceth_hdr};
      8'b00010100 : pack_vec = {bth_hdr, atomiceth_hdr};
      8'b00010110 : pack_vec = {bth_hdr, ieth_hdr};
      8'b00010111 : pack_vec = {bth_hdr, ieth_hdr};
      8'b00100011 : pack_vec = {bth_hdr, immdt_hdr};
      8'b00100101 : pack_vec = {bth_hdr, immdt_hdr};
      8'b00100110 : pack_vec = {bth_hdr, reth_hdr};
      8'b00101001 : pack_vec = {bth_hdr, immdt_hdr};
      8'b00101010 : pack_vec = {bth_hdr, reth_hdr};
      8'b00101011 : pack_vec = {bth_hdr, reth_hdr , immdt_hdr};
      8'b01000000 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01000001 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01000010 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01000011 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr , immdt_hdr};
      8'b01000100 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01000101 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, immdt_hdr};
      8'b01000110 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, reth_hdr};
      8'b01000111 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01001000 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr};
      8'b01001001 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, immdt_hdr};
      8'b01001010 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, reth_hdr};
      8'b01001011 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, reth_hdr , immdt_hdr};
      8'b01001100 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, reth_hdr}; 
      8'b01001101 : pack_vec = {bth_hdr, rdeth_hdr, aeth_hdr};
      8'b01001110 : pack_vec = {bth_hdr, rdeth_hdr};
      8'b01001111 : pack_vec = {bth_hdr, rdeth_hdr, aeth_hdr};
      8'b01010000 : pack_vec = {bth_hdr, rdeth_hdr, aeth_hdr};
      8'b01010001 : pack_vec = {bth_hdr, rdeth_hdr, aeth_hdr}; 
      8'b01010010 : pack_vec = {bth_hdr, rdeth_hdr, aeth_hdr, atomicacketh_hdr}; 
      8'b01010011 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}; 
      8'b01010100 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}; 
      8'b01010101 : pack_vec = {bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}; 
      8'b01100100 : pack_vec = {bth_hdr, deth_hdr};
      8'b01100101 : pack_vec = {bth_hdr, deth_hdr , immdt_hdr};
      8'b00010111 : pack_vec = {bth_hdr, ieth_hdr};
      default     : pack_vec = bth_hdr;
    endcase // }
    harray.pack_bit (pkt, pack_vec, index, hdr_len*8);
    `else
    case (opcode) // { 
      8'b00000011 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00000101 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00000110 : hdr = {>>{bth_hdr, reth_hdr}};
      8'b00001001 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00001010 : hdr = {>>{bth_hdr, reth_hdr}};
      8'b00001011 : hdr = {>>{bth_hdr, reth_hdr, immdt_hdr}};
      8'b00001100 : hdr = {>>{bth_hdr, reth_hdr}}; 
      8'b00001101 : hdr = {>>{bth_hdr, aeth_hdr}};
      8'b00001111 : hdr = {>>{bth_hdr, aeth_hdr}};
      8'b00010000 : hdr = {>>{bth_hdr, aeth_hdr}};
      8'b00010001 : hdr = {>>{bth_hdr, aeth_hdr}}; 
      8'b00010010 : hdr = {>>{bth_hdr, aeth_hdr , atomicacketh_hdr}};
      8'b00010011 : hdr = {>>{bth_hdr, atomiceth_hdr}};
      8'b00010100 : hdr = {>>{bth_hdr, atomiceth_hdr}};
      8'b00010110 : hdr = {>>{bth_hdr, ieth_hdr}};
      8'b00010111 : hdr = {>>{bth_hdr, ieth_hdr}};
      8'b00100011 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00100101 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00100110 : hdr = {>>{bth_hdr, reth_hdr}};
      8'b00101001 : hdr = {>>{bth_hdr, immdt_hdr}};
      8'b00101010 : hdr = {>>{bth_hdr, reth_hdr}};
      8'b00101011 : hdr = {>>{bth_hdr, reth_hdr , immdt_hdr}};
      8'b01000000 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01000001 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01000010 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01000011 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr , immdt_hdr}};
      8'b01000100 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01000101 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, immdt_hdr}};
      8'b01000110 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, reth_hdr}};
      8'b01000111 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01001000 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr}};
      8'b01001001 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, immdt_hdr}};
      8'b01001010 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, reth_hdr}};
      8'b01001011 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, reth_hdr , immdt_hdr}};
      8'b01001100 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, reth_hdr}}; 
      8'b01001101 : hdr = {>>{bth_hdr, rdeth_hdr, aeth_hdr}};
      8'b01001110 : hdr = {>>{bth_hdr, rdeth_hdr}};
      8'b01001111 : hdr = {>>{bth_hdr, rdeth_hdr, aeth_hdr}};
      8'b01010000 : hdr = {>>{bth_hdr, rdeth_hdr, aeth_hdr}};
      8'b01010001 : hdr = {>>{bth_hdr, rdeth_hdr, aeth_hdr}}; 
      8'b01010010 : hdr = {>>{bth_hdr, rdeth_hdr, aeth_hdr, atomicacketh_hdr}}; 
      8'b01010011 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}}; 
      8'b01010100 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}}; 
      8'b01010101 : hdr = {>>{bth_hdr, rdeth_hdr, deth_hdr, atomiceth_hdr}}; 
      8'b01100100 : hdr = {>>{bth_hdr, deth_hdr}};
      8'b01100101 : hdr = {>>{bth_hdr, deth_hdr , immdt_hdr}};
      8'b00010111 : hdr = {>>{bth_hdr, ieth_hdr}};
      default     : hdr = {>>{bth_hdr}};
    endcase // }
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
    bit [7:0]  op_code;
    update_len (index, pkt.size, bth_hdr_len);
    op_code = pkt[index];
    // commpute hdr_len
    case (op_code) // {
      8'b00000011 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00000101 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00000110 : hdr_len = bth_hdr_len + reth_hdr_len;
      8'b00001001 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00001010 : hdr_len = bth_hdr_len + reth_hdr_len;
      8'b00001011 : hdr_len = bth_hdr_len + reth_hdr_len + immdt_hdr_len;
      8'b00001100 : hdr_len = bth_hdr_len + reth_hdr_len; 
      8'b00001101 : hdr_len = bth_hdr_len + aeth_hdr_len;
      8'b00001111 : hdr_len = bth_hdr_len + aeth_hdr_len;
      8'b00010000 : hdr_len = bth_hdr_len + aeth_hdr_len;
      8'b00010001 : hdr_len = bth_hdr_len + aeth_hdr_len; 
      8'b00010010 : hdr_len = bth_hdr_len + aeth_hdr_len + atomicaeth_hdr_len;
      8'b00010011 : hdr_len = bth_hdr_len + atomiceth_hdr_len;
      8'b00010100 : hdr_len = bth_hdr_len + atomiceth_hdr_len;
      8'b00010110 : hdr_len = bth_hdr_len + ieth_hdr_len;
      8'b00010111 : hdr_len = bth_hdr_len + ieth_hdr_len;
      8'b00100011 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00100101 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00100110 : hdr_len = bth_hdr_len + reth_hdr_len;
      8'b00101001 : hdr_len = bth_hdr_len + immdt_hdr_len;
      8'b00101010 : hdr_len = bth_hdr_len + reth_hdr_len;
      8'b00101011 : hdr_len = bth_hdr_len + reth_hdr_len + immdt_hdr_len;
      8'b01000000 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01000001 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01000010 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01000011 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len;
      8'b01000100 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01000101 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len;
      8'b01000110 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len;
      8'b01000111 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01001000 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len;
      8'b01001001 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + immdt_hdr_len;
      8'b01001010 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len;
      8'b01001011 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len  + reth_hdr_len + immdt_hdr_len;
      8'b01001100 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + reth_hdr_len; 
      8'b01001101 : hdr_len = bth_hdr_len + rdeth_hdr_len + aeth_hdr_len;
      8'b01001110 : hdr_len = bth_hdr_len + rdeth_hdr_len;
      8'b01001111 : hdr_len = bth_hdr_len + rdeth_hdr_len + aeth_hdr_len;
      8'b01010000 : hdr_len = bth_hdr_len + rdeth_hdr_len + aeth_hdr_len;
      8'b01010001 : hdr_len = bth_hdr_len + rdeth_hdr_len + aeth_hdr_len; 
      8'b01010010 : hdr_len = bth_hdr_len + rdeth_hdr_len + aeth_hdr_len + atomicaeth_hdr_len; 
      8'b01010011 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len; 
      8'b01010100 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len; 
      8'b01010101 : hdr_len = bth_hdr_len + rdeth_hdr_len + deth_hdr_len + atomiceth_hdr_len; 
      8'b01100100 : hdr_len = bth_hdr_len + deth_hdr_len;
      8'b01100101 : hdr_len = bth_hdr_len + deth_hdr_len + immdt_hdr_len;
      default     : hdr_len = bth_hdr_len; 
    endcase // }
    // unpack class members
    `ifdef SVFNYI_0
    harray.unpack_array (pkt, pack_vec, index, hdr_len);
    case (op_code) // { 
      8'b00000011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00000101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00000110 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b00001001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00001010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b00001011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen, immdt_hdr} = pack_vec;
      8'b00001100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen} = pack_vec; 
      8'b00001101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn} = pack_vec;
      8'b00001111 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn} = pack_vec;
      8'b00010000 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn} = pack_vec;
      8'b00010001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn} = pack_vec; 
      8'b00010010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn , atomicacketh_hdr} = pack_vec;
      8'b00010011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_aeth, r_key_aeth, swapdt, cmprdt} = pack_vec;
      8'b00010100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_aeth, r_key_aeth, swapdt, cmprdt} = pack_vec;
      8'b00010110 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr} = pack_vec;
      8'b00010111 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr} = pack_vec;
      8'b00100011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00100101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00100110 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b00101001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr} = pack_vec;
      8'b00101010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b00101011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen , immdt_hdr} = pack_vec;
      8'b01000000 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01000001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01000010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01000011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP , immdt_hdr} = pack_vec;
      8'b01000100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01000101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, immdt_hdr} = pack_vec;
      8'b01000110 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b01000111 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01001000 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01001001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, immdt_hdr} = pack_vec;
      8'b01001010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen} = pack_vec;
      8'b01001011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen , immdt_hdr} = pack_vec;
      8'b01001100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen} = pack_vec; 
      8'b01001101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn} = pack_vec;
      8'b01001110 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt} = pack_vec;
      8'b01001111 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn} = pack_vec;
      8'b01010000 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn} = pack_vec;
      8'b01010001 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn} = pack_vec; 
      8'b01010010 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn, atomicacketh_hdr} = pack_vec; 
      8'b01010011 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt} = pack_vec; 
      8'b01010100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt} = pack_vec; 
      8'b01010101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt} = pack_vec; 
      8'b01100100 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, q_key, rsvd_deth, srcQP} = pack_vec;
      8'b01100101 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, q_key, rsvd_deth, srcQP , immdt_hdr} = pack_vec;
      8'b00010111 : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr} = pack_vec;
      default     : {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn} = pack_vec;
    endcase // } 
    `else
    harray.copy_array (pkt, hdr, index, hdr_len);
    case (op_code) // { 
      8'b00000011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00000101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00000110 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen}} = hdr;
      8'b00001001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00001010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen}} = hdr;
      8'b00001011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen, immdt_hdr}} = hdr;
      8'b00001100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen}} = hdr; 
      8'b00001101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn}} = hdr;
      8'b00001111 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn}} = hdr;
      8'b00010000 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn}} = hdr;
      8'b00010001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn}} = hdr; 
      8'b00010010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, syndrom, msn , atomicacketh_hdr}} = hdr;
      8'b00010011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_aeth, r_key_aeth, swapdt, cmprdt}} = hdr;
      8'b00010100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_aeth, r_key_aeth, swapdt, cmprdt}} = hdr;
      8'b00010110 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr}} = hdr;
      8'b00010111 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr}} = hdr;
      8'b00100011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00100101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00100110 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen}} = hdr;
      8'b00101001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, immdt_hdr}} = hdr;
      8'b00101010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen}} = hdr;
      8'b00101011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, va_reth, r_key_reth, dmalen , immdt_hdr}} = hdr;
      8'b01000000 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01000001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01000010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01000011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP , immdt_hdr}} = hdr;
      8'b01000100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01000101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, immdt_hdr}} = hdr;
      8'b01000110 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen}} = hdr;
      8'b01000111 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01001000 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01001001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, immdt_hdr}} = hdr;
      8'b01001010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen}} = hdr;
      8'b01001011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen , immdt_hdr}} = hdr;
      8'b01001100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_reth, r_key_reth, dmalen}} = hdr; 
      8'b01001101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn}} = hdr;
      8'b01001110 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt}} = hdr;
      8'b01001111 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn}} = hdr;
      8'b01010000 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn}} = hdr;
      8'b01010001 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn}} = hdr; 
      8'b01010010 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, syndrom, msn, atomicacketh_hdr}} = hdr; 
      8'b01010011 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt}} = hdr; 
      8'b01010100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt}} = hdr; 
      8'b01010101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, rsvd_rdeth, EEcnxt, q_key, rsvd_deth, srcQP, va_aeth, r_key_aeth, swapdt, cmprdt}} = hdr; 
      8'b01100100 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, q_key, rsvd_deth, srcQP}} = hdr;
      8'b01100101 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, q_key, rsvd_deth, srcQP , immdt_hdr}} = hdr;
      8'b00010111 : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn, ieth_hdr}} = hdr;
      default     : {>>{opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn}} = hdr;
    endcase // } 
    `endif
    bth_hdr       = {opcode, S, M, padcnt, tver, p_key, rsvd0, destQP, A, rsvd1, psn};
    rdeth_hdr     = {rsvd_rdeth, EEcnxt};
    deth_hdr      = {q_key, rsvd_deth, srcQP};
    reth_hdr      = {va_reth, r_key_reth, dmalen};
    atomiceth_hdr = {va_aeth, r_key_aeth, swapdt, cmprdt};
    aeth_hdr      = {syndrom, msn};
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
    bth_hdr_class lcl;
    super.cpy_hdr (cpy_cls);
    $cast (lcl, cpy_cls);
    // ~~~~~~~~~~ Class members ~~~~~~~~~~
    // BTH hdr
    this.opcode               = lcl.opcode; 
    this.S                    = lcl.S;
    this.M                    = lcl.M;
    this.padcnt               = lcl.padcnt;
    this.tver                 = lcl.tver;  
    this.p_key                = lcl.p_key; 
    this.rsvd0                = lcl.rsvd0; 
    this.destQP               = lcl.destQP;
    this.A                    = lcl.A;     
    this.rsvd1                = lcl.rsvd1; 
    this.psn                  = lcl.psn;   
    // RDETH hdr 
    this.rsvd_rdeth           = lcl.rsvd_rdeth;
    this.EEcnxt               = lcl.EEcnxt;
    // DETH hdr 
    this.q_key                = lcl.q_key; 
    this.rsvd_deth            = lcl.rsvd_deth;
    this.srcQP                = lcl.srcQP; 
    // RETH hdr 
    this.va_reth              = lcl.va_reth;
    this.r_key_reth           = lcl.r_key_reth;
    this.dmalen               = lcl.dmalen; 
    // ATOMICETH hdr 
    this.va_aeth              = lcl.va_aeth;
    this.r_key_aeth           = lcl.r_key_aeth;
    this.swapdt               = lcl.swapdt; 
    this.cmprdt               = lcl.cmprdt; 
    // AETH hdr 
    this.syndrom              = lcl.syndrom;
    this.msn                  = lcl.msn;
    // ATOMICACKETH hdr 
    this.atomicacketh_hdr     = lcl.atomicacketh_hdr;
    // IMMDT hdr
    this.immdt_hdr            = lcl.immdt_hdr;
    // IETH hdr 
    this.ieth_hdr             = lcl.ieth_hdr;
    // ~~~~~~~~~~ Local Variables ~~~~~~~~~~
    this.bth_hdr              = lcl.bth_hdr;
    this.rdeth_hdr            = lcl.rdeth_hdr;
    this.deth_hdr             = lcl.deth_hdr;
    this.reth_hdr             = lcl.reth_hdr;
    this.atomiceth_hdr        = lcl.atomiceth_hdr;
    this.aeth_hdr             = lcl.aeth_hdr;
    this.bth_hdr_len          = lcl.bth_hdr_len;
    this.rdeth_hdr_len        = lcl.rdeth_hdr_len;
    this.deth_hdr_len         = lcl.deth_hdr_len;
    this.reth_hdr_len         = lcl.reth_hdr_len;
    this.atomiceth_hdr_len    = lcl.atomiceth_hdr_len;
    this.aeth_hdr_len         = lcl.aeth_hdr_len;
    this.atomicaeth_hdr_len   = lcl.atomicaeth_hdr_len;
    this.immdt_hdr_len        = lcl.immdt_hdr_len;
    this.ieth_hdr_len         = lcl.ieth_hdr_len;
    // ~~~~~~~~~~ Control variables ~~~~~~~~~~
    this.corrupt_tver         = lcl.corrupt_tver;
    this.null_rsvd            = lcl.null_rsvd;   
    if (~last_cpy)
        this.nxt_hdr.cpy_hdr (cpy_cls.nxt_hdr, last_cpy);
  endtask : cpy_hdr // }

  task display_hdr (pktlib_display_class hdis,
                    hdr_class            cmp_cls,
                    int                  mode         = DISPLAY,
                    bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Class members ~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN,   8, "opcode", opcode, lcl.opcode);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN,   1, "S", S, lcl.S);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN,   1, "M", M, lcl.M);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   2, "padcnt", padcnt, lcl.padcnt);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   4, "tver", tver, lcl.tver);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  16, "p_key", p_key, lcl.p_key);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "rsvd0", rsvd0, lcl.rsvd0);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "destQP", destQP, lcl.destQP);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN,   1, "A", A, lcl.A);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   7, "rsvd1", rsvd1, lcl.rsvd1);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "psn", psn, lcl.psn);
    case (opcode) // { 
      8'b00000011 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00000101 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00000110 : display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00001001 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00001010 : display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00001011 : 
      begin // {
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b00001100 : display_reth_hdr        (hdis, cmp_cls, mode, last_display); 
      8'b00001101 : display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00001111 : display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00010000 : display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00010001 : display_aeth_hdr        (hdis, cmp_cls, mode, last_display); 
      8'b00010010 : 
      begin // {
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_atomicacketh_hdr(hdis, cmp_cls, mode, last_display);
      end // }
      8'b00010011 : display_atomiceth_hdr   (hdis, cmp_cls, mode, last_display);
      8'b00010100 : display_atomiceth_hdr   (hdis, cmp_cls, mode, last_display);
      8'b00010110 : display_ieth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00010111 : display_ieth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00100011 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00100101 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00100110 : display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00101001 : display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      8'b00101010 : display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      8'b00101011 : 
      begin // {
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);  
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000000 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000001 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000010 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000011 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000100 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000101 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000110 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01000111 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001000 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001001 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001010 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001011 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display); 
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001100 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_reth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001101 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01001110 : display_rdeth_hdr(hdis, cmp_cls, mode, last_display);
      8'b01001111 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01010000 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01010001 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01010010 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_atomicacketh_hdr(hdis, cmp_cls, mode, last_display);
                    
      end // }
      8'b01010011 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_aeth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_atomiceth_hdr   (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01010100 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_atomiceth_hdr   (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01010101 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_deth_hdr        (hdis, cmp_cls, mode, last_display);
                    display_atomiceth_hdr   (hdis, cmp_cls, mode, last_display);
      end // }
      8'b01100100 : display_deth_hdr(hdis, cmp_cls, mode, last_display);
      8'b01100101 : 
      begin // {
                    display_rdeth_hdr       (hdis, cmp_cls, mode, last_display);
                    display_immdt_hdr       (hdis, cmp_cls, mode, last_display);
      end // }
      8'b00010111 : display_ieth_hdr        (hdis, cmp_cls, mode, last_display);
      default     : hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ No Extension Transport Header ~~~~~");
    endcase // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    hdis.display_fld (mode, hdr_name, STRING,     DEF, 000, "", 0, 0, null_a, null_a, "~~~~~~~~~~ Control variables ~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "corrupt_tver", corrupt_tver, lcl.corrupt_tver);        
    hdis.display_fld (mode, hdr_name, BIT_VEC,    BIN, 001, "null_rsvd", null_rsvd, lcl.null_rsvd);        
    end // }
    if ((mode == DISPLAY_FULL) | (mode == COMPARE_FULL))
    begin // {
    display_common_hdr_flds (hdis, lcl, mode);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 096, "bth_hdr", bth_hdr, lcl.bth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 032, "rdeth_hdr", rdeth_hdr, lcl.rdeth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 064, "deth_hdr", deth_hdr, lcl.deth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 128, "reth_hdr", reth_hdr, lcl.reth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 224, "atomiceth_hdr", atomiceth_hdr, lcl.atomiceth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, HEX, 032, "aeth_hdr", aeth_hdr, lcl.aeth_hdr);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "bth_hdr_len", bth_hdr_len, lcl.bth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "rdeth_hdr_len", rdeth_hdr_len, lcl.rdeth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "deth_hdr_len", deth_hdr_len, lcl.deth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "reth_hdr_len", reth_hdr_len, lcl.reth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "atomiceth_hdr_len", atomiceth_hdr_len, lcl.atomiceth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "aeth_hdr_len", aeth_hdr_len, lcl.aeth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "atomicaeth_hdr_len", atomicaeth_hdr_len, lcl.atomicaeth_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "immdt_hdr_len", immdt_hdr_len, lcl.immdt_hdr_len);
    hdis.display_fld (mode, hdr_name, BIT_VEC_NH, DEF, 016, "ieth_hdr_len", ieth_hdr_len, lcl.ieth_hdr_len);
    end // }
    if (~last_display & (cmp_cls.nxt_hdr.hid == nxt_hdr.hid))
        this.nxt_hdr.display_hdr (hdis, cmp_cls.nxt_hdr, mode);
  endtask : display_hdr // }

  task display_rdeth_hdr (pktlib_display_class hdis,
                          hdr_class            cmp_cls,
                          int                  mode         = DISPLAY,
                          bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ RDETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "rsvd_rdeth", rsvd_rdeth, lcl.rsvd_rdeth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "EEcnxt", EEcnxt, lcl.EEcnxt);
  endtask : display_rdeth_hdr // }

  task display_deth_hdr (pktlib_display_class hdis,
                         hdr_class            cmp_cls,
                         int                  mode         = DISPLAY,
                         bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ DETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "q_key", q_key, lcl.q_key);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "rsvd_deth", rsvd_deth, lcl.rsvd_deth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "srcQP", srcQP, lcl.srcQP);
  endtask : display_deth_hdr // }

  task display_reth_hdr (pktlib_display_class hdis,
                         hdr_class            cmp_cls,
                         int                  mode         = DISPLAY,
                         bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ RETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "va_reth", va_reth, lcl.va_reth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "r_key_reth", r_key_reth, lcl.r_key_reth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "dmalen", dmalen, lcl.dmalen);
  endtask : display_reth_hdr // }

 task display_atomiceth_hdr (pktlib_display_class hdis,
                             hdr_class            cmp_cls,
                             int                  mode         = DISPLAY,
                             bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ ATOMICETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "va_aeth", va_aeth, lcl.va_aeth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "r_key_aeth", r_key_aeth, lcl.r_key_aeth);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "swapdt", swapdt, lcl.swapdt);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "cmprdt", cmprdt, lcl.cmprdt);
  endtask : display_atomiceth_hdr // }

 task display_aeth_hdr (pktlib_display_class hdis,
                        hdr_class            cmp_cls,
                        int                  mode         = DISPLAY,
                        bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ AETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,   8, "syndrom", syndrom, lcl.syndrom);
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  24, "msn", msn, lcl.msn);
  endtask : display_aeth_hdr // }

 task display_atomicacketh_hdr (pktlib_display_class hdis,
                                hdr_class            cmp_cls,
                                int                  mode         = DISPLAY,
                                bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ ATOMICACKETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  64, "atomicacketh_hdr", atomicacketh_hdr, lcl.atomicacketh_hdr);
  endtask : display_atomicacketh_hdr // }

 task display_immdt_hdr (pktlib_display_class hdis,
                         hdr_class            cmp_cls,
                         int                  mode         = DISPLAY,
                         bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ IMMDT hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "immdt_hdr", immdt_hdr, lcl.immdt_hdr);
  endtask : display_immdt_hdr // }

 task display_ieth_hdr (pktlib_display_class hdis,
                        hdr_class            cmp_cls,
                        int                  mode         = DISPLAY,
                        bit                  last_display = 1'b0); // {
    bth_hdr_class lcl;
    $cast (lcl, cmp_cls);
    hdis.display_fld (mode, hdr_name, STRING,     DEF,   0, "", 0, 0, null_a, null_a, "~~~~~~~~~~ IETH hdr ~~~~~~~~~~~~~~");
    hdis.display_fld (mode, hdr_name, BIT_VEC,    HEX,  32, "ieth_hdr", ieth_hdr, lcl.ieth_hdr);
  endtask : display_ieth_hdr // }

endclass : bth_hdr_class // }
