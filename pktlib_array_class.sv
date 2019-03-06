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
//  Header array realted classed
// ----------------------------------------------------------------------
//  Control Variables :
//  ==================
//  +--------+---------+---------------+----------------------------------+
//  | Width  | Default | Variable      | Description                      |
//  +--------+---------+---------------+----------------------------------+
//  | 8      | 8'h0    | start_byte    | Starting pattern of data         |
//  +--------+---------+---------------+----------------------------------+
//  | string | "RND"   | data_pattern  | Data patterns supported :        |
//  |        |         |               | "INC" -> Incrementing data       |
//  |        |         |               | "DEC" -> Decrementing data       |
//  |        |         |               | "INV" -> Inverting data pattern  |
//  |        |         |               |          i.e. {start_byte,       |
//  |        |         |               |                ~start_byte, ...} |
//  |        |         |               | "FIX" -> Fix start_byte data     |
//  |        |         |               | "RND" -> Random data             |
//  +--------+---------+---------------+----------------------------------+
//
// ----------------------------------------------------------------------

class pktlib_array_class;

  // ~~~~~~~~~~ control variables ~~~~~~~~~~
    string     data_pattern = "RND";
    bit [7:0]  start_byte   = 8'h00;

  function new (input string     data_pattern = "RND",
                input bit [7:0]  start_byte   = 8'h00); // {
    this.data_pattern = data_pattern;
    this.start_byte   = start_byte;
  endfunction : new // }

  // this task converts bit vector into pkt array of 8 bit
  task pack_bit (ref   bit [7:0]         pkt [],         // Output array
                 input bit [`VEC_SZ-1:0] bit_vec,        // bit vector to pack 
                 ref   int               start_offset,   // starting offset in bits
                 input int               length,         // how much data to unpack 
                 input bit               no_icr = 1'b0); // don't increment start_offset if 1 {
    bit [7:0] hold_reg;
    int       i;
    for (i = start_offset/8; i < (start_offset+length)/8; i++)
    begin // {
        hold_reg = bit_vec  >> (length - (i - start_offset/8 + 1) * 8);
        pkt[i]  |= hold_reg << (start_offset % 8);
        if (start_offset % 8 != 0)
            pkt[i+1] |= hold_reg >> (8 - start_offset % 8);
    end // }
    if (i*8 < (start_offset + length))
    begin // {
        hold_reg = bit_vec;
        pkt[i]  |= hold_reg << (start_offset % 8);
    end // }
    if (~no_icr)
        start_offset += length;
  endtask : pack_bit // }

  // this tasks replaces bytes of pkt array from start offset with array_8
  task pack_array_8 (input bit [7:0] array_8 [],
                     ref   bit [7:0] pkt     [],
                     ref   int       start_offset,   // starting offset in bytes 
                     input bit       no_icr = 1'b0); // don't increment start_offset if 1 {
    foreach (array_8[a_ls])
        pkt [start_offset + a_ls] = array_8[a_ls];
    if (~no_icr)
        start_offset += array_8.size;
  endtask : pack_array_8 // }

  // this tasks converts 8 byte array into unpack vector
  task unpack_array (input bit [7:0]         array_8 [],
                     ref   bit [`VEC_SZ-1:0] unpack_vec,
                     ref   int               start_offset,
                     input int               length,         // how much data to unpack 
                     input bit               no_icr = 1'b0); // don't increment start_offset if 1 {
    int i;
    for (i = start_offset; i < start_offset+length; i++)
    begin // {
        unpack_vec = unpack_vec << 8;
        if (i < array_8.size)
        begin // {
            unpack_vec[7:0] = array_8[i];
        end // }
        else
        begin // {
            unpack_vec[7:0] = 8'h0;
        end // }
    end // }
    if (~no_icr)
        start_offset += length; 
  endtask : unpack_array // }

  // this function copies m to n bytes of an array into new array
  function void copy_array (input bit [7:0] copy_from [],
                            ref   bit [7:0] copy_to   [],
                            ref   int       start_offset,
                            input int       length,    
                            input bit       no_icr = 1'b0); // {
    if (length > 0)
    begin // {
        copy_to = new [length];
        foreach (copy_to[c_to])
        begin // {
            if (copy_from.size >= (start_offset + c_to))
                copy_to [c_to] = copy_from [start_offset + c_to];
        end // }
    end // }
    if (~no_icr)
        start_offset += length; 
  endfunction : copy_array // }

  // function to fill data array
  function  void fill_array (ref   bit [7:0]  data []); // {
    bit [7:0] fill_byte;
    int       cnt;
    fill_byte  = start_byte;
    for (cnt = 0; cnt < data.size(); cnt++)
    begin // {
         case (data_pattern) // {
              "INC"   :
              begin // {
                  data[cnt] = fill_byte;
                  fill_byte = fill_byte + 1;
              end // }
              "DEC"   :
              begin // {
                  data[cnt] = fill_byte;
                  fill_byte = fill_byte - 1;
              end // }
              "INV"   :
              begin // {
                  data[cnt] = fill_byte;
                  fill_byte = ~fill_byte;
              end // }
              "FIX"   : data[cnt] = start_byte;
              default : data[cnt] = $urandom();
         endcase // }
    end // }
  endfunction : fill_array // }
    
endclass : pktlib_array_class // }
