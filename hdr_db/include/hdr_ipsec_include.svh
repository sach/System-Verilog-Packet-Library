// ----------------------------------------------------------------------
//
//  Copyright (c) 2009-2010 SiGeeks
//  All Rights Reserved
// ----------------------------------------------------------------------
//  IPSEC releated defines
// ----------------------------------------------------------------------

// ~~~~~~~~~~ IPSEC releated defines ~~~~~~~~~~
`define MAX_IPSEC_PAD       8'd3

// ~~~~~~~~~~ IPSEC releated fields ~~~~~~~~~~
  bit [7:0]   max_ipsec_pad = `MAX_IPSEC_PAD;

//  ~~~~~~~~~~ define to copy IPSEC releated fields ~~~~~~~~~~
`define HDR_IPSEC_INCLUDE_CPY\
    this.max_ipsec_pad = cpy_cls.max_ipsec_pad

// ~~~~~~~~~~ EOF ~~~~~~~~~~
