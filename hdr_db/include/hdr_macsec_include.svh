// ----------------------------------------------------------------------
//
//  Copyright (c) 2009-2010 SiGeeks
//  All Rights Reserved
// ----------------------------------------------------------------------
//  MACSEC releated defines
// ----------------------------------------------------------------------

// ~~~~~~~~~~ MACSEC releated defines ~~~~~~~~~~
`define TCI_VER             1'b0
`define SL_SZ               8'd48

// ~~~~~~~~~~ MACSEC releated fields ~~~~~~~~~~
  bit         tci_ver       = `TCI_VER;
  bit [7:0]   sl_sz         = `SL_SZ;

// ~~~~~~~~~~ define to copy MACSEC releated fields ~~~~~~~~~~
`define HDR_MACSEC_INCLUDE_CPY\
    this.tci_ver = cpy_cls.tci_ver;\
    this.sl_sz   = cpy_cls.sl_sz

// ~~~~~~~~~~ EOF ~~~~~~~~~~
