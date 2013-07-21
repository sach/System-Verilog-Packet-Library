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
//  This class is the template class for all the headers
//  All hdrs extend this class and inherit its properties.
// ----------------------------------------------------------------------

virtual class hdr_class extends pktlib_object_class; // {
 
  // all the variable decelaration and common tasks for all the hdrs
  `include "hdr_common_include.svh"

  function new (pktlib_main_class plib); // {
    super.new ();
    null_a = new [0];
    this.plib = plib;
  endfunction : new // }

  // pack all the fields of this hdr to input pkt array
  virtual task pack_hdr (ref   bit [7:0] pkt [], 
                         ref   int       index,
                         input bit       last_pack = 1'b0); // {
  endtask : pack_hdr // }

  // unpack all the fields of this hdr from input pkt array
  virtual task unpack_hdr (ref   bit [7:0] pkt   [],
                           ref   int       index,
                           ref   hdr_class hdr_q [$],
                           input int       mode        = DUMB_UNPACK,
                           input bit       last_unpack = 1'b0); // {
  endtask : unpack_hdr // }

  // display all this hdr fields
  virtual task display_hdr (pktlib_display_class hdis,
                            hdr_class            cmp_cls,
                            int                  mode         = DISPLAY,
                            bit                  last_display = 1'b0); // {
  endtask : display_hdr // }

  // copy all the fields
  task cpy_hdr (hdr_class cpy_cls,
                bit       last_cpy = 1'b0); // {
    `HDR_INCLUDE_CPY;
  endtask : cpy_hdr // }

endclass : hdr_class // }
