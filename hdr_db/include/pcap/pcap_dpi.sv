/*! \file pcap_dpi.sv
 * Contains the DPI-C routines used to allocate pcap dumpers, dump individual
 * packets to a dumpfile, and shutdown afterwards.  Default has a maximum
 * of 32 open dumpfiles for a simulation.
 */
/* Copyright (c) 2011, Sachin Gandhi
   All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

  // Regitser DPI-C routines
  import "DPI-C" function void pv_register ();

  //  Create a new dumper (port)
  import "DPI-C" function void pv_open (
               output int         phandle,   // handler or port number of new dumper
               input  string      pcap_file, // filename  
               input  int         pcap_type = 0);// 0 -> writting, 1 -> reading

  //  Dump a packet to an active dumper
  import "DPI-C" function void pv_dump_pkt (
               input  int         phandle,   // active handler (port) to dump pkt
               input  int         pkt_len,   // length of packet
               input  bit [7:0]   in_pkt[],  // Packet array
               input  bit [63:0]  nstime);   // simulation time in ns

  //  Dump a packet to an active dumper
  import "DPI-C" function void pv_get_pkt (
               input  int         phandle,   // active handler (port) to dump pkt
               output int         pkt_len,   // length of packet
               output bit [7:0]   in_pkt[],  // Packet array
               output bit [63:0]  nstime);   // simulation time in ns

  //  Shutdown a dumper after use
  import "DPI-C" function void pv_shutdown (
               input  int         phandle);  // active handler (port) to shutdown 
