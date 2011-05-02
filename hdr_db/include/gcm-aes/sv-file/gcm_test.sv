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
//  Example test to enc/dec pkt
// ----------------------------------------------------------------------

program gcm_test (); // { 

  // include file
  `include "gcm_dpi.sv"

  // Local Variables 
  bit [7:0]   pkt  [];
  bit [7:0]   epkt [];
  bit [7:0]   dpkt [];
  bit [7:0]   npkt [];
  bit [31:0]  pn;
  bit [63:0]  sci;
  bit [127:0] key;
  bit         pkt_err;
  bit         auth_err;
  int         plen;
  int         out_plen;
  int         auth_only;
  int         auth_st;
  int         auth_sz;
  int         enc;
  int         enc_sz;
  int         crc_sz;
  int         icv_sz;
  int         i;

  initial
  begin // {
    // setting values
    plen      = 64;                       // pkt_len
    pkt       = new[plen];                // pkt to encrypt
    epkt      = new[plen + 16];           // Output pkt after enc 
                                          // (encrypted pkt + 16B auth tag)
    key       = 128'habcdabcdabcdfffffff; // key from table lookup 
    sci       = 64'ha5a5a5a5a5a5a5a5;     // sci from table lookup
    pn        = 32'hdeadbeef;             // pn from table lookup
    auth_only = 0;                        // 0 => Encrypt and auth, 1 -> only auth no encryption
    auth_st   = 0;                        // Authentication start
    auth_sz   = 20;                       // Total bytes to auth_only 
                                          // For eg. DA + SA + MAcsecHdr
                                          // This part of the pkt is never encrypted
    enc       = 1;                        // 1 -> Encrypt, 0 -> decrypt the pkt
    enc_sz    = plen - auth_sz - auth_st; // total bytes to Encrypt or decrypt. 
                                          // Encryption starts after auth_sz
    for (i = 0; i < plen; i++)
        pkt[i] = i[7:0];

    // DPI call to encrypt the pkt
    // This call will output epkt which is encrypted data + 16B of auth_tag
    // Auth tag is always last 16B
    gcm_crypt (key,
               sci,
               pn,
               auth_only,
               auth_st,
               auth_sz,
               enc,
               enc_sz,
               pkt,
               epkt,
               out_plen);

    // display
    $write ("gcm_test:        ~~~~~~~~~~~~~ Pkt before Encryption ~~~~~~~~~~~~~~\n");
    dump(pkt);
    $write ("gcm_test:        ~~~~~~~~~~~~~ Pkt after Encryption ~~~~~~~~~~~~~~\n");
    dump(epkt);
    
    // remove auth tag from epkt
    npkt = new[plen];
    for (i = 0; i < plen; i++)
        npkt[i] = epkt[i];

    // DPI call to decrypt the pkt
    // This call will output dpkt which is decrypted data + 16B of auth_tag
    // Auth tag is always last 16B
    // decrypt data should match with original pkt
    // Last 16B which is auth tag should match with auth tag of encrypted pkt
    enc = 0;
    dpkt      = new[plen + 16];  
    gcm_crypt (key,
               sci,
               pn,
               auth_only,
               auth_st,
               auth_sz,
               enc,
               enc_sz,
               npkt,
               dpkt,
               out_plen);
    $write ("gcm_test:        ~~~~~~~~~~~~~ Pkt after decryption ~~~~~~~~~~~~~~\n");
    dump(dpkt);

    // Pkt and auth tag Comparison
    pkt_err  = 1'b0;
    auth_err = 1'b0;
    for (i = 0; i < plen ; i++)
    begin // {
        if (pkt[i] !== dpkt[i])
            pkt_err = 1'b1;
    end // }
    if (pkt_err)
         $display("%0t : ERROR  : GCM_TEST  :  Pkt Mismatch", $time);

    for (i = plen; i < (plen + 16) ; i++)
    begin // {
        if (epkt[i] !== dpkt[i])
            auth_err = 1'b1;
    end // }
    if (auth_err)
        $display("%0t : ERROR  : GCM_TEST  :  Auth Fail", $time);

    if (pkt_err | auth_err)
        $display("%0t : ~~~~~~~  Test FAIL :(- ~~~~~~~",$time);
    else
        $display("%0t : ~~~~~~~  Test PASS :)- ~~~~~~~",$time);
  end // }

  // This task display entire pkt
  task dump (bit [7:0] data []); // {
    int pkt_len = 0;
    int i;
    pkt_len = data.size ();
    for (i = 0; i < 16 ; i++)
    begin // {
        if (i % 16 == 0)
            $write ("gcm_test:       %2d ", i);
        else if (i % 16 == 7)
            $write ("%3d |", i);
        else if (i % 16 == 15)
            $write ("%3d\n", i);
        else
            $write ("%3d", i);
    end // }
    $write ("gcm_test:        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~\n");
    for (i = 0; i < pkt_len; i++)
    begin
        if (i % 16 == 0)
            $write ("gcm_test: %4d : ", i);
        $write ("%x ", data[i]);
        if (i % 16 == 7)
            $write ("| ");
        if (i % 16 == 15)
            $write ("\n");
    end
    $write ("\n\n");
  endtask : dump // }

endprogram : gcm_test // }
