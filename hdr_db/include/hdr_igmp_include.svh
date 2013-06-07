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
//  IGMP defines/tasks/macros
// ----------------------------------------------------------------------

// ~~~~~~~~~~ IGMP type defines ~~~~~~~~~~
`define IGMP_MEMBERSHIP_QUERY     8'h11
`define IGMPV1_MEMBERSHIP_REPORT  8'h12
`define IGMPV2_MEMBERSHIP_REPORT  8'h16
`define IGMPV2_LEAVE_GROUP        8'h17
`define IGMPV3_MEMBERSHIP_REPORT  8'h22

// ~~~~~~~~~~ IGMP Type fields ~~~~~~~~~~
  bit [7:0] igmp_query         = `IGMP_MEMBERSHIP_QUERY;
  bit [7:0] igmpv1_report      = `IGMPV1_MEMBERSHIP_REPORT;
  bit [7:0] igmpv2_report      = `IGMPV2_MEMBERSHIP_REPORT;
  bit [7:0] igmpv2_leave_group = `IGMPV2_LEAVE_GROUP;
  bit [7:0] igmpv3_report      = `IGMPV3_MEMBERSHIP_REPORT;

// ~~~~~~~~~~ define to copy IGMP fields ~~~~~~~~~~
`define HDR_IGMP_INCLUDE_CPY\
    this.igmp_query         = cpy_cls.igmp_query;\
    this.igmpv1_report      = cpy_cls.igmpv1_report;\
    this.igmpv2_report      = cpy_cls.igmpv2_report;\
    this.igmpv2_leave_group = cpy_cls.igmpv2_leave_group;\
    this.igmpv3_report      = cpy_cls.igmpv3_report

// ~~~~~~~~~~ Constraints Macro for IGMP type ~~~~~~~~~~
`define LEGAL_IGMP_TYPE_CONSTRAINTS\
    igmp_type inside {igmp_query,igmpv1_report,igmpv2_report,igmpv2_leave_group,igmpv3_report}

// ~~~~~~~~~~ Function to get the name of IGMP type ~~~~~~~~~~
  function string get_igmp_type_name(bit [7:0] igmp_type); // {
     case (igmp_type) // {
         igmp_query        : get_igmp_type_name = "QUERY";
         igmpv1_report     : get_igmp_type_name = "V1REPORT";
         igmpv2_report     : get_igmp_type_name = "V2REPORT";
         igmpv2_leave_group: get_igmp_type_name = "LEAVE_GROUP";
         igmpv3_report     : get_igmp_type_name = "V3REPORT";
         default           : get_igmp_type_name = "UNKNOWN";
     endcase // }
  endfunction : get_igmp_type_name // }

// ~~~~~~~~~~ EOF ~~~~~~~~~~
