/*Copyright (c) 2011, Sachin Gandhi
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// ---------------------------------------------------------------------
//  GCM-AES DPI Calls
// ---------------------------------------------------------------------

#include <stdio.h>
#include <svdpi.h>
#include "gfvec.h"
#include "gcm.h"
#include "gcm_dpi.h"

#define NO_TYPE       0
#define NULL_TYPE     1
#define INFO          2
#define DEBUG         3
#define WARNING       4
#define ERROR         5

  char c_msg[5000];
  svScope g_scope;


  void print_msg (int   msg_type, char* msg, int msg_len)
  {
    if (msg_len > 0)
    {
      // Commenting out as xrun gives error
//    g_scope = svGetScopeFromName("$unit");
//    svSetScope(g_scope);
//    ::print_c_msg (msg_type, msg);
    }
  }

  // function to encrypt/decrypt and auth
  extern "C" void gcm_crypt (svBitVec32        *t_key,    // 128 bit Key
                             svBitVec32        *t_sci,    // 64  bit Sci 
                             uint32_t          t_pn,      // 32  bit Pn 
                             int               auth_only, // 1 -> auth _only , no encrypt/decrypt
                             int               auth_st,   // Auth Start
                             int               auth_sz,   // Auth Size
                             int               enc,       // 1 -> encrypt, 0 -> decrypt 
                             int               enc_sz,    // Encrypt/decrypt Size
                             svOpenArrayHandle in_pkt,    // Original Pkt (without auth tag)
                             svOpenArrayHandle out_pkt,   // Output Pkt (Encrypt/decrypt + Auth Tag)
                             int               *out_plen) // Output Pkt Len                           `
  {
    uint8_t    key[16]; 
    uint64_t   sci;
    uint32_t   pn;
    int        i, ii, j, shift, wc, auth_rg;
    gcm        g_inst;
    gfvec      k, ptxt, ctxt;
    svBitVec32 *in_pkt_ptr;
    svBitVec32 *out_pkt_ptr;

    in_pkt_ptr  = (svBitVec32*) svGetArrayPtr(in_pkt);
    out_pkt_ptr = (svBitVec32*) svGetArrayPtr(out_pkt);

    // copy key
    j = 0;
    for (i = 0; i < 16; i++)
    {
        shift       = (i%4) * 8;
        key[15 - i] = (uint8_t) ((t_key[j] >> shift) & 0xFF);
        if (shift == 24)
            j++;
    }

    // copy sci
    sci =  ((uint64_t) t_sci[0]) | ((uint64_t) t_sci[1]) << 32;

    // copy pn
    pn  = (uint32_t) t_pn;

    //  Set key to use for encryption
    k.copy (key);
    g_inst.set_key (k);

    // Initialize engine with nonce values
    g_inst.packet_init (sci, pn);

    if (auth_only == 1)
        auth_rg = auth_st + auth_sz + enc_sz;
    else
        auth_rg = auth_st + auth_sz;

//  print_msg(INFO, c_msg, sprintf(c_msg, "auth_only %0d auth_st %0d auth_sz %0d auth_rg %0d enc %0d enc_sz %0d \n", 
//                         auth_only, auth_st, auth_sz, auth_rg, enc, enc_sz));
    // authentication
    for (i = 0; i < auth_rg; i++)
    {
        if (i >= auth_st)
            g_inst.add_auth (in_pkt_ptr[i]);
        out_pkt_ptr[i] = in_pkt_ptr[i];
//      print_msg(INFO, c_msg, sprintf(c_msg, "i %0d in_pkt_ptr %x out pkt_ptr  %x  AUTH_LOOP\n", 
//                             i, in_pkt_ptr[i], out_pkt_ptr[i]));
    }
    wc = 0;
    ii = auth_rg;

    // Encryption
    if (auth_only == 0)
    {
        for (i = 0; i < enc_sz; i++)
        {
            ptxt.d[wc] = in_pkt_ptr[auth_rg + i]; 
            wc++;
            // if we've reached a full 16 count, encrypt/decrypt the word, then copy out of
            // gfvec into the out packet array.
            if (wc == 16) 
            {
                if (enc)
                    g_inst.encrypt (ptxt, ctxt, 16);
                else
                    g_inst.decrypt (ptxt, ctxt, 16);
                for (j = 0; j < 16; j++)
                {
                    out_pkt_ptr[j + ii] = ctxt.d[j];
//                print_msg(INFO, c_msg, sprintf(c_msg, "i %0d j+ii %0d in_pkt_ptr %x out pkt_ptr  %x  ENC_LOOP\n", 
//                                         j+ii, in_pkt_ptr[j+ii], out_pkt_ptr[j+ii]));
                }
                wc = 0;
                ii += 16;
            }
        }
    
        // check to see if anything is left over to encrypt/decrypt.  If so, encrypt/decrypt with
        // the remainder amount and
        // copy the result into the packet.
        if (wc != 0) 
        {
          if (enc)
              g_inst.encrypt (ptxt, ctxt, wc);
          else
              g_inst.decrypt (ptxt, ctxt, wc);
          for (j = 0; j < wc; j++)
          {
              out_pkt_ptr[j + ii] = ctxt.d[j];
//          print_msg(INFO, c_msg, sprintf(c_msg, "i %0d in_pkt_ptr %x out pkt_ptr  %x ENC_LOOP1 \n", 
//                                   j+ii, in_pkt_ptr[j+ii], out_pkt_ptr[j+ii]));
          }
          ii += wc; 
        }
    }

    // insert the auth tag 
    g_inst.get_tag (ctxt);
    for (i = 0; i < 16; i++)
    {
        out_pkt_ptr[i + ii] = ctxt.d[i];
//    print_msg(INFO, c_msg, sprintf(c_msg, "i %0d in_pkt_ptr %x out pkt_ptr  %x \n", 
//                             i+ii, in_pkt_ptr[i+ii], out_pkt_ptr[i+ii]));
    }
    ii += 16;
    out_plen[0] = ii;
  }

  // h-key calculation needed by API calls
  extern "C" void aes_hkey (svBitVec32        *t_key, // 127:0
                            svBitVec32        *t_in, // 127 :0
                            svOpenArrayHandle t_out)
  {
    svBitVec32 *tmp_out;
    uint8_t    key[16], in[16], out[16];
    int        i, j, shift;
    tmp_out = (svBitVec32*) svGetArrayPtr(t_out);
    aes_encrypt_ctx acx[1];
    j = 0;
    for (i = 0; i < 16; i++)
    {
        shift = (i%4) * 8;
        key[15-i] = (uint8_t) ((t_key[j] >> shift) & 0xFF);
        in [15-i] = (uint8_t) ((t_in [j] >> shift) & 0xFF);
        if (shift == 24)
            j++;
    }
    aes_encrypt_key (key, 16, acx);
    aes_encrypt (in, out, acx);
    for (int i = 0; i < 16; i++)
    {
        tmp_out[15-i] = out[i];
        //print_msg(INFO, c_msg, sprintf(c_msg, "i %0d key %x in %x out %x tmp_out %x \n", i, key[i], in[i], out[i], tmp_out[i]));
    }
  }

