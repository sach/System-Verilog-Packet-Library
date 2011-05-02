/*
Copyright (c) 2011, Sachin Gandhi
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// -----------------------------------------------------------------
//  GCM_AES DPI calls
// -----------------------------------------------------------------

  int c_error = 0;
  int c_warn = 0;
  
  // Encrypt and Auth the packet
  import "DPI" function void gcm_crypt (
               input  bit [127:0] key,       // 128 bit Key
               input  bit [63:0]  sci,       // 64  bit Sci 
               input  bit [31:0]  pn,        // 32  bit Pn 
               input  int         auth_only, // 1 -> Auth_only, no encrypt/decrypt
               input  int         auth_st,   // Auth Start
               input  int         auth_sz,   // Auth Size
               input  int         enc,       // 1 -> encrypt, 0 -> decrypt
               input  int         enc_sz,    // Encrypt/decrypt Size
               input  bit [7:0]   in_pkt[],  // Original Pkt (without auth tag)
               output bit [7:0]   out_pkt[], // Output Pkt (Encrypt/decrypt + Auth Tag)
               output int         out_plen); // Output Pkt Len                        

  // Hkey calculation
  import "DPI" function void aes_hkey(input  bit [127:0] key,
                                      input  bit [127:0] in,
                                      output bit [7:0]   out[]);

  // Print c-file messages
  export "DPI" function print_c_msg;

  function void print_c_msg (input int    msg_type,
                             input string msg);
`ifdef C_DISPLAY_ON
    case (msg_type)
        1       : 
        begin // {
            $write("%0t :        : C-FILE    : ",$time);
            $write("%0s",msg);
        end // }
        2       : 
        begin // {
            $write("%0t : INFO   : C-FILE    : ",$time);
            $write("%0s",msg);
        end // }
        3       : 
        begin // {
            `ifndef NO_REF_DEBUG
            $write("%0t : DEBUG  : C-FILE    : ",$time);
            $write("%0s",msg);
            `endif
        end // }
        4       : 
        begin // {
            $write("%0t : WARNING: C-FILE    : ",$time);
            $write("%0s",msg);
            c_warn++;
        end // }
        5       : 
        begin // {
            $write("%0t : ERROR  : REF_MODEL : ",$time);
            $write("%0s",msg);
            c_error++;
        end // }
        default : $write("%0s",msg); 
    endcase // }
`endif
  endfunction // }
