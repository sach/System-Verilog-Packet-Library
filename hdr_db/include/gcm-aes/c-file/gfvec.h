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

#ifndef _GFVEC_H
#define _GFVEC_H
#include <stdint.h>
#include <stdio.h>
#include <deque>
#include <exception>
#include <string>
#include "gcm_dpi.h"

// define for print message
#define NO_TYPE       0
#define NULL_TYPE     1
#define INFO          2
#define DEBUG         3
#define WARNING       4
#define ERROR         5

class gfvec {
  public:
    uint8_t d[16];
    gfvec () {};
    gfvec (uint8_t c) { for (int i=0; i<16; i++) d[i]=c; };
    gfvec (const gfvec &init);
    uint8_t operator[](unsigned index);
    gfvec operator+ (const gfvec &y);
    gfvec operator* (gfvec &y);
    void init (const uint8_t c) { for (int i=0; i<16; i++) d[i]=c; };
    void copy (const uint8_t c[]) { for (int i=0; i<16; i++) d[i]=c[i]; };
    uint8_t *ptr () { return d; };
    void print ();
    void print (char *t) { printf(t); print(); }
    void rightshift ();
    void add (uint32_t amount);
    char ref_msg [5000];
};
#endif
