/*! \file pcap_dump.h
 * Defines the pcap_vpi data structures and function calls.   Proper sequence of calls is
 * to first call pcap_open() to create a dumper, repeatedly call
 * pcap_add_pkt() to add packets to the dumper, then call 
 * pcap_shutdown() when finished.
 */

/* Copyright (c) 2011, Guy Hutchison
   All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PCAP_DUMP_H_
#define PCAP_DUMP_H_
#include <stdint.h>
#include <pcap.h>

#define PCAP_DUMP_READ  1
#define PCAP_DUMP_WRITE 0

#if defined(__cplusplus)
extern "C"
{
#endif

/*! Dumper context
 * 
 * Contains the pcap context used to start up as well as the
 * dumper file containing packets.
 */
typedef struct {
  pcap_t *ctx;
  pcap_dumper_t *dump;
} pcap_handle_t;

/*! Packet information structure
 *
 * Contains the packet data and length, as well as the transmission
 * time of the packet
 */
typedef struct {
  /// packet length
  int length;    
  /// packet data
  uint8_t *pdata;
  /// tx time in seconds
  uint32_t sec;
  /// tx time in microseconds
  uint32_t usec; 
} packet_info_t;

char errbuf[PCAP_ERRBUF_SIZE];

/*! \brief Open up a dumper
 * \return pcap_handle_t structure containing context and dumper
 */
pcap_handle_t pcap_open (char *filename, int bufsize, int open_type);
/*! \brief Add a packet to an active dumper
 */
void pcap_add_pkt (pcap_dumper_t *dump, packet_info_t *p);
/*! \brief Get a packet to an active dumper
 */
void pcap_get_pkt (pcap_t *ctx, packet_info_t *p);
/*! \brief Shut down a dumper and close the pcap file
 */
void pcap_shutdown (pcap_handle_t *h);

#if defined(__cplusplus)
}
#endif
#endif /*PCAP_DUMP_H_*/
