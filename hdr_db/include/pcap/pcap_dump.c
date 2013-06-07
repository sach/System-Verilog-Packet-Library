/* Copyright (c) 2011, Guy Hutchison
   All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include "pcap_dump.h"
#include <assert.h>

void pcap_add_pkt (pcap_dumper_t *dump, packet_info_t *p) 
{
  struct pcap_pkthdr hdr;
  hdr.ts.tv_sec = p->sec;
  hdr.ts.tv_usec = p->usec;
  hdr.caplen = p->length;
  hdr.len = p->length;
  pcap_dump ((u_char *) dump, &hdr, p->pdata);
}

void pcap_get_pkt (pcap_t *ctx, packet_info_t *p) 
{
  struct pcap_pkthdr hdr;
  p->pdata  = (uint8_t *) pcap_next (ctx, &hdr);
  if (p->pdata != NULL)
  {
  	p->sec    = hdr.ts.tv_sec;
  	p->usec   = hdr.ts.tv_usec;
  	p->length = hdr.caplen;
  }
}

pcap_handle_t pcap_open (char *filename, int bufsize, int open_type)
{
  pcap_handle_t h;

  h.ctx = NULL; h.dump = NULL;

  if (open_type == PCAP_DUMP_WRITE)
  {
    h.ctx = pcap_open_dead (DLT_EN10MB, bufsize);
    h.dump = pcap_dump_open (h.ctx, filename);
  }
  else {
    h.ctx =  pcap_open_offline (filename, errbuf);
    h.dump = NULL;
  }
  return h;
}

void pcap_shutdown (pcap_handle_t *h) 
{
  if (h->dump != NULL)
    pcap_dump_close (h->dump);
  pcap_close (h->ctx);
}
