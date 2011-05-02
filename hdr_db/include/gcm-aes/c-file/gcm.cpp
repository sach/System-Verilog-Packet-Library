/*Copyright (c) 2011, Sachin Gandhi
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

#include "gcm.h"

/*! \brief Set key to use for encryption
 */
void gcm::set_key (gfvec &key) {
  uint8_t zero[16];

  for (int i=0; i<16; i++) zero[i] = 0;

  aes_encrypt_key (key.ptr(), 16, acx);
  aes_encrypt (zero, h.ptr(), acx);

  print_msg(INFO, ref_msg, sprintf(ref_msg, "GCM : Key      = ")); key.print();
  print_msg(INFO, ref_msg, sprintf(ref_msg, "GCM : H        = ")); h.print();
}

/*! \brief Initialize engine with nonce values
 *
 * Called once per packet, initializes the engine with the 96-bit
 * nonce of SCI and packet number, and initializes the internal 
 * 32-bit word counter to 0.
 */
void gcm::packet_init (uint64_t sci, uint32_t pn) {
  for (int i=0; i<8; i++)
    counter.d[i] = sci >> (8*(7-i));
  for (int i=0; i<4; i++) {
    counter.d[i+8] = pn >> (8*(3-i));
    counter.d[i+12] = 0;
  }
  counter.add(1);
  aes_encrypt (counter.ptr(), eky0.ptr(), acx);
  print_msg(INFO, ref_msg, sprintf(ref_msg, "GCM : SCI      = %llx\n", sci));
  print_msg(INFO, ref_msg, sprintf(ref_msg, "GCM : PN       = %x\n", pn)); 
  #ifndef NO_REF_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : EK0      = ")); eky0.print();
  #endif

  // initialize the authorization index/buf
  auth_ind = 0;
  xi.init(0);
  auth_acc.init(0);
  auth_done = false;

  // initialize length counters
  alen = 0; plen = 0;
}

/*! \brief Add single byte of authorized material
 */
void gcm::add_auth (uint8_t adata) {
  auth_acc.d[auth_ind++] = adata;

  if (auth_ind == 16) {
#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_GH = ")); xi.print();
#endif
    xi = xi + auth_acc;
#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_ACC = ")); auth_acc.print();
#endif
    xi = xi * h;
    auth_ind = 0;
#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_MUL = ")); xi.print();
#endif
  }
  alen++;
}

/*! \brief Explict call to end auth region (optional)
 */
void gcm::auth_finalize() {
  if (auth_ind) {
    while (auth_ind < 16)
      auth_acc.d[auth_ind++] = 0;

#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_GH = ")); xi.print();
#endif
    xi = xi + auth_acc;
#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_ACC = ")); auth_acc.print();
#endif
    xi = xi * h;   
#ifdef AUTH_DEBUG
    print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_MUL = ")); xi.print();
#endif
  }
  auth_done = true;
}

/*! \brief Encrypt a single word
 *
 * "p" refers to plaintext, and "c" to ciphertext (input and output,
 * respectively).  Size is the number of bytes of valid data in the
 * p-vector, and should be 16 for all words except the last one.
 */
void gcm::encrypt (gfvec &p, gfvec &c, int size) {
  gfvec eki, cauth;

  if (!auth_done) auth_finalize();

  counter.add (1);
  aes_encrypt (counter.ptr(), eki.ptr(), acx);
  #ifndef NO_REF_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : AES ctr  = ")); counter.print();
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : AES outi = ")); eki.print();
  #endif 

  c = p + eki;
  cauth = c;
  if (size != 16)
    for (int i=size; i<16; i++) cauth.d[i] = 0;

#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_GH = ")); xi.print();
#endif
  xi = xi + cauth;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_ACC = ")); cauth.print();
#endif
  xi = xi * h;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RE_HASH_MUL = ")); xi.print();
#endif

  plen += size;
}

/*! \brief Decrypt a single word
 *
 * "c" refers to ciphertext, "p" to plaintext (input and output,
 * respectively).  Size is number of valid bytes, as per encrypt.
 */
void gcm::decrypt (gfvec &c, gfvec &p, int size) {
  gfvec eki, cauth;

  if (!auth_done) auth_finalize();

  counter.add (1);
  aes_encrypt (counter.ptr(), eki.ptr(), acx);
  p = c + eki;
  cauth = c;
  if (size != 16)
    for (int i=size; i<16; i++) cauth.d[i] = 0;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_GH = ")); xi.print();
#endif
  xi = xi + cauth;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_ACC = ")); cauth.print();
#endif
  xi = xi * h;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RE_HASH_MUL = ")); xi.print();
#endif

  plen += size;
}

/*! \brief Retrieve the authorization tag
 *
 * 
 */
void gcm::get_tag (gfvec &tag) {
  gfvec length(0);

  if (!auth_done) auth_finalize();

  // convert values from bytes to bits and stuff values into
  // length vector
  plen *= 8;
  alen *= 8;
  for (int i=0; i<4; i++) {
    length.d[i+4] = alen >> (8*(3-i));
    length.d[i+12] = plen >> (8*(3-i));
  }

  // multiply length value into ghash
  // add E(K,Y0) to get final tag value
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RA_HASH_ACC = ")); length.print();
#endif
  xi = xi + length;
  xi = xi * h;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RE_HASH_MUL = ")); xi.print();
#endif
  tag = xi + eky0;
#ifdef AUTH_DEBUG
  print_msg(DEBUG, ref_msg, sprintf(ref_msg, "GCM : RE_HASH_FIN = ")); tag.print();
#endif
}
