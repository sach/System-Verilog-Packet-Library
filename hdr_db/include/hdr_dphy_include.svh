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
//   di (data_id)defines/tasks/macros
// ----------------------------------------------------------------------

// ~~~~~~~~~~ di defines ~~~~~~~~~~
`define SDPHY_MAX_DI       8'h1F // Upper limit of DI for DPHY short packet header

// ~~~~~~~~~~ di fields ~~~~~~~~~~
   bit [7:0]   sdphy_max_di = `SDPHY_MAX_DI;
   bit         dphy_spkt    = 1'b0;      // Control variable set when its DPHY short packet header

// ~~~~~~~~~~ define to copy DI fields  ~~~~~~~~~~
`define HDR_DPHY_INCLUDE_CPY\
    this.sdphy_max_di = cpy_cls.sdphy_max_di;\
    this.dphy_spkt    = cpy_cls.dphy_spkt

// ~~~~~~~~~~ Constraints Macro for DI ~~~~~~~~~~
`define LEGAL_DI_TYPE_CONSTRAINTS \
    (nxt_hdr.hid == EOH_HID)            -> (di inside {[8'h0 : sdphy_max_di]});\
    (nxt_hdr.hid == DATA_HID)           -> (di > sdphy_max_di)

// ~~~~~~~~~~ Function to get the name of di ~~~~~~~~~~
  function string get_di_name(bit [7:0] di); // {
     if (di inside {[8'h0 : sdphy_max_di]})
         get_di_name = "DPHY Short Pkt Header";
     else 
     begin // {
         case (di) // {
             default : get_di_name = "UNKNOWN";
         endcase // }
     end // }
  endfunction : get_di_name // }

// ~~~~~~~~~~ Function to get the di from hid ~~~~~~~~~~
  function bit [7:0] get_di(int hid); // {
     case (hid) // {
        EOH_HID      : get_di = $urandom_range(8'h00, sdphy_max_di);
        default      : get_di = $urandom ();
     endcase // }
  endfunction : get_di // }

// ~~~~~~~~~~ Function to get the hid from di ~~~~~~~~~~
  function int get_hid_from_di(bit [7:0] di); // {
     if (di inside {[8'h0 : sdphy_max_di]})
         get_hid_from_di = EOH_HID;
     else
     begin // {
         case (di) // {
             default     : get_hid_from_di = DATA_HID;
         endcase // }
     end // }
  endfunction : get_hid_from_di // }

// ~~~~~~~~~~ EOF ~~~~~~~~~~
