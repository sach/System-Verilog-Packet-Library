/*
Copyright (c) 2011, Sachin Gandhi
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

//----------------------------------------------------------------------
//  GCM Encryption and Decryption
//----------------------------------------------------------------------

#ifndef _GCM_H
#define _GCM_H
#include <stdint.h>
#include <stdio.h>
#include "gfvec.h"
#include "aes.h"
#include "gcm_dpi.h"

// define for print message
#define NO_TYPE       0
#define NULL_TYPE     1
#define INFO          2
#define DEBUG         3
#define WARNING       4
#define ERROR         5

/*! \brief GCM encrypt/decrypt class
 *
 * Basic class to provide a GCM encrypt/decrypt engine, and associated
 * context.  Emphasizes simplicity over speed.  Requires the gfvec classes
 * for input and output, as these allow certain vector math to be performed
 * on 128-bit sequences.
 *
 * Engine needs to be initialized once per key with set_key(), and once
 * per packet with packet_init().  auth_finalize() is optional, and will
 * automatically be called at the first encrypt() call.
 *
 * Engine operation is by calling add_auth() once for each byte of the
 * authorized material, and encrypt() once for each 16-byte word of the
 * encrypted material.  The size parameter allows the engine to be called
 * with less than 16 bytes on the last word.  The engine will automatically
 * pad the remainder data with 0.
 *
 * Once auth and encrypt are complete, the result can be retrieved with
 * get_tag().
 */
class gcm {
private:
  aes_encrypt_ctx acx[1];
  gfvec counter;
  gfvec h, eky0;
  gfvec xi;
  int auth_ind;
  gfvec auth_acc;
  bool auth_done;
  int alen, plen;
public:
  bool debug;

  gcm () { debug = false; };

  void set_key (gfvec &key);
  void packet_init (uint64_t sci, uint32_t pn);
  void add_auth (uint8_t adata);
  void auth_finalize();
  void encrypt (gfvec &p, gfvec &c, int size);
  void decrypt (gfvec &c, gfvec &p, int size);
  void get_tag (gfvec &tag);
  char ref_msg [5000];
};

#endif
