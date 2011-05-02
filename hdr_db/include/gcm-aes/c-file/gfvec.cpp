/*
Copyright (c) 2011, Sachin Gandhi
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// ---------------------------------------------------------------------
//  gfvec class 
// ---------------------------------------------------------------------

#include "gfvec.h"

// bit index operator
// bit 0 is MSB, bit 127 is LSB (IBM numbering)
uint8_t gfvec::operator[](unsigned index) {
  return (d[index/8] >> (7 - (index % 8))) & 0x01;
}

gfvec::gfvec (const gfvec &init) {
  for (int i=0; i<16; i++)
    d[i] = init.d[i];
}

void gfvec::print () {
  for (int i=0; i<16; i++)
    print_msg(NO_TYPE, ref_msg, sprintf(ref_msg, "%02x", d[i]));
  print_msg(NO_TYPE, ref_msg, sprintf(ref_msg, "\n"));
}

void gfvec::add (uint32_t amount) {
  uint32_t tmp = 0;

  for (int i=0; i<4; i++)
    tmp += d[15-i] << (8*i);
  tmp += amount;
  for (int i=0; i<4; i++)
    d[15-i] = (tmp >> (8*i)) & 0xFF;
}

void gfvec::rightshift () {
  uint8_t carry, tmp;

  carry = 0;
  for (int i=0; i<16; i++) {
    tmp = (d[i] >> 1) | (carry << 7);
    carry = d[i] & 0x01;
    d[i] = tmp;
  }
}

gfvec gfvec::operator+ (const gfvec &y) {
  gfvec z;

  for (int i=0; i<16; i++)
    z.d[i] = d[i] ^ y.d[i];

  return z;
}

gfvec gfvec::operator* (gfvec &y) {
  gfvec z(0),r(0);
  uint8_t tmp;
  gfvec v;

  for (int i=0; i<16; i++)
    v.d[i] = d[i];

  r.d[0] = 0xE1;

  for (int i=0; i<128; i++) {
    if (y[i])
      z = z + v;

    tmp = v[127];
    v.rightshift();
    if (tmp)
      v = v + r;
  }

  return z;
}
