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
//  class to compute crc and checksum
// ----------------------------------------------------------------------

class pktlib_crc_chksm_class; // {

   function new (); // {
   endfunction : new // }

  // function to compute crc32
  function bit [31:0] crc32 (bit [7:0]  pkt [],
                             bit [31:0] len     = 0, 
                             bit [31:0] offset  = 0, 
                             bit        corrupt = 0); // {
    int        corrupt_bit;
    bit [31:0] crc = 32'hffffffff;
    bit [31:0] crc32_array [256];
    crc32_array[255] = 32'h2d02ef8d;
    crc32_array[254] = 32'h5a05df1b;
    crc32_array[253] = 32'hc30c8ea1;
    crc32_array[252] = 32'hb40bbe37;
    crc32_array[251] = 32'h2a6f2b94;
    crc32_array[250] = 32'h5d681b02;
    crc32_array[249] = 32'hc4614ab8;
    crc32_array[248] = 32'hb3667a2e;
    crc32_array[247] = 32'h23d967bf;
    crc32_array[246] = 32'h54de5729;
    crc32_array[245] = 32'hcdd70693;
    crc32_array[244] = 32'hbad03605;
    crc32_array[243] = 32'h24b4a3a6;
    crc32_array[242] = 32'h53b39330;
    crc32_array[241] = 32'hcabac28a;
    crc32_array[240] = 32'hbdbdf21c;
    crc32_array[239] = 32'h30b5ffe9;
    crc32_array[238] = 32'h47b2cf7f;
    crc32_array[237] = 32'hdebb9ec5;
    crc32_array[236] = 32'ha9bcae53;
    crc32_array[235] = 32'h37d83bf0;
    crc32_array[234] = 32'h40df0b66;
    crc32_array[233] = 32'hd9d65adc;
    crc32_array[232] = 32'haed16a4a;
    crc32_array[231] = 32'h3e6e77db;
    crc32_array[230] = 32'h4969474d;
    crc32_array[229] = 32'hd06016f7;
    crc32_array[228] = 32'ha7672661;
    crc32_array[227] = 32'h3903b3c2;
    crc32_array[226] = 32'h4e048354;
    crc32_array[225] = 32'hd70dd2ee;
    crc32_array[224] = 32'ha00ae278;
    crc32_array[223] = 32'h166ccf45;
    crc32_array[222] = 32'h616bffd3;
    crc32_array[221] = 32'hf862ae69;
    crc32_array[220] = 32'h8f659eff;
    crc32_array[219] = 32'h11010b5c;
    crc32_array[218] = 32'h66063bca;
    crc32_array[217] = 32'hff0f6a70;
    crc32_array[216] = 32'h88085ae6;
    crc32_array[215] = 32'h18b74777;
    crc32_array[214] = 32'h6fb077e1;
    crc32_array[213] = 32'hf6b9265b;
    crc32_array[212] = 32'h81be16cd;
    crc32_array[211] = 32'h1fda836e;
    crc32_array[210] = 32'h68ddb3f8;
    crc32_array[209] = 32'hf1d4e242;
    crc32_array[208] = 32'h86d3d2d4;
    crc32_array[207] = 32'h0bdbdf21;
    crc32_array[206] = 32'h7cdcefb7;
    crc32_array[205] = 32'he5d5be0d;
    crc32_array[204] = 32'h92d28e9b;
    crc32_array[203] = 32'h0cb61b38;
    crc32_array[202] = 32'h7bb12bae;
    crc32_array[201] = 32'he2b87a14;
    crc32_array[200] = 32'h95bf4a82;
    crc32_array[199] = 32'h05005713;
    crc32_array[198] = 32'h72076785;
    crc32_array[197] = 32'heb0e363f;
    crc32_array[196] = 32'h9c0906a9;
    crc32_array[195] = 32'h026d930a;
    crc32_array[194] = 32'h756aa39c;
    crc32_array[193] = 32'hec63f226;
    crc32_array[192] = 32'h9b64c2b0;
    crc32_array[191] = 32'h5bdeae1d;
    crc32_array[190] = 32'h2cd99e8b;
    crc32_array[189] = 32'hb5d0cf31;
    crc32_array[188] = 32'hc2d7ffa7;
    crc32_array[187] = 32'h5cb36a04;
    crc32_array[186] = 32'h2bb45a92;
    crc32_array[185] = 32'hb2bd0b28;
    crc32_array[184] = 32'hc5ba3bbe;
    crc32_array[183] = 32'h5505262f;
    crc32_array[182] = 32'h220216b9;
    crc32_array[181] = 32'hbb0b4703;
    crc32_array[180] = 32'hcc0c7795;
    crc32_array[179] = 32'h5268e236;
    crc32_array[178] = 32'h256fd2a0;
    crc32_array[177] = 32'hbc66831a;
    crc32_array[176] = 32'hcb61b38c;
    crc32_array[175] = 32'h4669be79;
    crc32_array[174] = 32'h316e8eef;
    crc32_array[173] = 32'ha867df55;
    crc32_array[172] = 32'hdf60efc3;
    crc32_array[171] = 32'h41047a60;
    crc32_array[170] = 32'h36034af6;
    crc32_array[169] = 32'haf0a1b4c;
    crc32_array[168] = 32'hd80d2bda;
    crc32_array[167] = 32'h48b2364b;
    crc32_array[166] = 32'h3fb506dd;
    crc32_array[165] = 32'ha6bc5767;
    crc32_array[164] = 32'hd1bb67f1;
    crc32_array[163] = 32'h4fdff252;
    crc32_array[162] = 32'h38d8c2c4;
    crc32_array[161] = 32'ha1d1937e;
    crc32_array[160] = 32'hd6d6a3e8;
    crc32_array[159] = 32'h60b08ed5;
    crc32_array[158] = 32'h17b7be43;
    crc32_array[157] = 32'h8ebeeff9;
    crc32_array[156] = 32'hf9b9df6f;
    crc32_array[155] = 32'h67dd4acc;
    crc32_array[154] = 32'h10da7a5a;
    crc32_array[153] = 32'h89d32be0;
    crc32_array[152] = 32'hfed41b76;
    crc32_array[151] = 32'h6e6b06e7;
    crc32_array[150] = 32'h196c3671;
    crc32_array[149] = 32'h806567cb;
    crc32_array[148] = 32'hf762575d;
    crc32_array[147] = 32'h6906c2fe;
    crc32_array[146] = 32'h1e01f268;
    crc32_array[145] = 32'h8708a3d2;
    crc32_array[144] = 32'hf00f9344;
    crc32_array[143] = 32'h7d079eb1;
    crc32_array[142] = 32'h0a00ae27;
    crc32_array[141] = 32'h9309ff9d;
    crc32_array[140] = 32'he40ecf0b;
    crc32_array[139] = 32'h7a6a5aa8;
    crc32_array[138] = 32'h0d6d6a3e;
    crc32_array[137] = 32'h94643b84;
    crc32_array[136] = 32'he3630b12;
    crc32_array[135] = 32'h73dc1683;
    crc32_array[134] = 32'h04db2615;
    crc32_array[133] = 32'h9dd277af;
    crc32_array[132] = 32'head54739;
    crc32_array[131] = 32'h74b1d29a;
    crc32_array[130] = 32'h03b6e20c;
    crc32_array[129] = 32'h9abfb3b6;
    crc32_array[128] = 32'hedb88320;
    crc32_array[127] = 32'hc0ba6cad;
    crc32_array[126] = 32'hb7bd5c3b;
    crc32_array[125] = 32'h2eb40d81;
    crc32_array[124] = 32'h59b33d17;
    crc32_array[123] = 32'hc7d7a8b4;
    crc32_array[122] = 32'hb0d09822;
    crc32_array[121] = 32'h29d9c998;
    crc32_array[120] = 32'h5edef90e;
    crc32_array[119] = 32'hce61e49f;
    crc32_array[118] = 32'hb966d409;
    crc32_array[117] = 32'h206f85b3;
    crc32_array[116] = 32'h5768b525;
    crc32_array[115] = 32'hc90c2086;
    crc32_array[114] = 32'hbe0b1010;
    crc32_array[113] = 32'h270241aa;
    crc32_array[112] = 32'h5005713c;
    crc32_array[111] = 32'hdd0d7cc9;
    crc32_array[110] = 32'haa0a4c5f;
    crc32_array[109] = 32'h33031de5;
    crc32_array[108] = 32'h44042d73;
    crc32_array[107] = 32'hda60b8d0;
    crc32_array[106] = 32'had678846;
    crc32_array[105] = 32'h346ed9fc;
    crc32_array[104] = 32'h4369e96a;
    crc32_array[103] = 32'hd3d6f4fb;
    crc32_array[102] = 32'ha4d1c46d;
    crc32_array[101] = 32'h3dd895d7;
    crc32_array[100] = 32'h4adfa541;
    crc32_array[ 99] = 32'hd4bb30e2;
    crc32_array[ 98] = 32'ha3bc0074;
    crc32_array[ 97] = 32'h3ab551ce;
    crc32_array[ 96] = 32'h4db26158;
    crc32_array[ 95] = 32'hfbd44c65;
    crc32_array[ 94] = 32'h8cd37cf3;
    crc32_array[ 93] = 32'h15da2d49;
    crc32_array[ 92] = 32'h62dd1ddf;
    crc32_array[ 91] = 32'hfcb9887c;
    crc32_array[ 90] = 32'h8bbeb8ea;
    crc32_array[ 89] = 32'h12b7e950;
    crc32_array[ 88] = 32'h65b0d9c6;
    crc32_array[ 87] = 32'hf50fc457;
    crc32_array[ 86] = 32'h8208f4c1;
    crc32_array[ 85] = 32'h1b01a57b;
    crc32_array[ 84] = 32'h6c0695ed;
    crc32_array[ 83] = 32'hf262004e;
    crc32_array[ 82] = 32'h856530d8;
    crc32_array[ 81] = 32'h1c6c6162;
    crc32_array[ 80] = 32'h6b6b51f4;
    crc32_array[ 79] = 32'he6635c01;
    crc32_array[ 78] = 32'h91646c97;
    crc32_array[ 77] = 32'h086d3d2d;
    crc32_array[ 76] = 32'h7f6a0dbb;
    crc32_array[ 75] = 32'he10e9818;
    crc32_array[ 74] = 32'h9609a88e;
    crc32_array[ 73] = 32'h0f00f934;
    crc32_array[ 72] = 32'h7807c9a2;
    crc32_array[ 71] = 32'he8b8d433;
    crc32_array[ 70] = 32'h9fbfe4a5;
    crc32_array[ 69] = 32'h06b6b51f;
    crc32_array[ 68] = 32'h71b18589;
    crc32_array[ 67] = 32'hefd5102a;
    crc32_array[ 66] = 32'h98d220bc;
    crc32_array[ 65] = 32'h01db7106;
    crc32_array[ 64] = 32'h76dc4190;
    crc32_array[ 63] = 32'hb6662d3d;
    crc32_array[ 62] = 32'hc1611dab;
    crc32_array[ 61] = 32'h58684c11;
    crc32_array[ 60] = 32'h2f6f7c87;
    crc32_array[ 59] = 32'hb10be924;
    crc32_array[ 58] = 32'hc60cd9b2;
    crc32_array[ 57] = 32'h5f058808;
    crc32_array[ 56] = 32'h2802b89e;
    crc32_array[ 55] = 32'hb8bda50f;
    crc32_array[ 54] = 32'hcfba9599;
    crc32_array[ 53] = 32'h56b3c423;
    crc32_array[ 52] = 32'h21b4f4b5;
    crc32_array[ 51] = 32'hbfd06116;
    crc32_array[ 50] = 32'hc8d75180;
    crc32_array[ 49] = 32'h51de003a;
    crc32_array[ 48] = 32'h26d930ac;
    crc32_array[ 47] = 32'habd13d59;
    crc32_array[ 46] = 32'hdcd60dcf;
    crc32_array[ 45] = 32'h45df5c75;
    crc32_array[ 44] = 32'h32d86ce3;
    crc32_array[ 43] = 32'hacbcf940;
    crc32_array[ 42] = 32'hdbbbc9d6;
    crc32_array[ 41] = 32'h42b2986c;
    crc32_array[ 40] = 32'h35b5a8fa;
    crc32_array[ 39] = 32'ha50ab56b;
    crc32_array[ 38] = 32'hd20d85fd;
    crc32_array[ 37] = 32'h4b04d447;
    crc32_array[ 36] = 32'h3c03e4d1;
    crc32_array[ 35] = 32'ha2677172;
    crc32_array[ 34] = 32'hd56041e4;
    crc32_array[ 33] = 32'h4c69105e;
    crc32_array[ 32] = 32'h3b6e20c8;
    crc32_array[ 31] = 32'h8d080df5;
    crc32_array[ 30] = 32'hfa0f3d63;
    crc32_array[ 29] = 32'h63066cd9;
    crc32_array[ 28] = 32'h14015c4f;
    crc32_array[ 27] = 32'h8a65c9ec;
    crc32_array[ 26] = 32'hfd62f97a;
    crc32_array[ 25] = 32'h646ba8c0;
    crc32_array[ 24] = 32'h136c9856;
    crc32_array[ 23] = 32'h83d385c7;
    crc32_array[ 22] = 32'hf4d4b551;
    crc32_array[ 21] = 32'h6ddde4eb;
    crc32_array[ 20] = 32'h1adad47d;
    crc32_array[ 19] = 32'h84be41de;
    crc32_array[ 18] = 32'hf3b97148;
    crc32_array[ 17] = 32'h6ab020f2;
    crc32_array[ 16] = 32'h1db71064;
    crc32_array[ 15] = 32'h90bf1d91;
    crc32_array[ 14] = 32'he7b82d07;
    crc32_array[ 13] = 32'h7eb17cbd;
    crc32_array[ 12] = 32'h09b64c2b;
    crc32_array[ 11] = 32'h97d2d988;
    crc32_array[ 10] = 32'he0d5e91e;
    crc32_array[  9] = 32'h79dcb8a4;
    crc32_array[  8] = 32'h0edb8832;
    crc32_array[  7] = 32'h9e6495a3;
    crc32_array[  6] = 32'he963a535;
    crc32_array[  5] = 32'h706af48f;
    crc32_array[  4] = 32'h076dc419;
    crc32_array[  3] = 32'h990951ba;
    crc32_array[  2] = 32'hee0e612c;
    crc32_array[  1] = 32'h77073096;
    crc32_array[  0] = 32'h00000000;
    while (len--)
    begin // {
        crc  = (((crc) >> 8) ^ crc32_array[((crc) ^ (pkt[offset])) & 8'hff]);
        offset++;
    end // }
    crc32 = {~crc [7:0], ~crc [15:8], ~crc [23:16], ~crc [31:24]};
    if (corrupt)
    begin // {
        corrupt_bit        = $urandom_range(0,31);
        crc32[corrupt_bit] = ~crc32[corrupt_bit];
    end // }
endfunction : crc32 // }

  // function to compute crc16
  function bit [15:0] crc16 (bit [7:0]  pkt [],
                             bit [31:0] len     = 0, 
                             bit [31:0] offset  = 0, 
                             bit        corrupt = 0); // {
    int        corrupt_bit;
    bit [15:0] crc = 16'hffff;
    bit [7:0]  local_reg;
    bit [15:0] crc16_array [256];
    crc16_array[255] = 16'h4040;
    crc16_array[254] = 16'h8081;
    crc16_array[253] = 16'h81c1;
    crc16_array[252] = 16'h4100;
    crc16_array[251] = 16'h8341;
    crc16_array[250] = 16'h4380;
    crc16_array[249] = 16'h42c0;
    crc16_array[248] = 16'h8201;
    crc16_array[247] = 16'h8641;
    crc16_array[246] = 16'h4680;
    crc16_array[245] = 16'h47c0;
    crc16_array[244] = 16'h8701;
    crc16_array[243] = 16'h4540;
    crc16_array[242] = 16'h8581;
    crc16_array[241] = 16'h84c1;
    crc16_array[240] = 16'h4400;
    crc16_array[239] = 16'h8c41;
    crc16_array[238] = 16'h4c80;
    crc16_array[237] = 16'h4dc0;
    crc16_array[236] = 16'h8d01;
    crc16_array[235] = 16'h4f40;
    crc16_array[234] = 16'h8f81;
    crc16_array[233] = 16'h8ec1;
    crc16_array[232] = 16'h4e00;
    crc16_array[231] = 16'h4a40;
    crc16_array[230] = 16'h8a81;
    crc16_array[229] = 16'h8bc1;
    crc16_array[228] = 16'h4b00;
    crc16_array[227] = 16'h8941;
    crc16_array[226] = 16'h4980;
    crc16_array[225] = 16'h48c0;
    crc16_array[224] = 16'h8801;
    crc16_array[223] = 16'h9841;
    crc16_array[222] = 16'h5880;
    crc16_array[221] = 16'h59c0;
    crc16_array[220] = 16'h9901;
    crc16_array[219] = 16'h5b40;
    crc16_array[218] = 16'h9b81;
    crc16_array[217] = 16'h9ac1;
    crc16_array[216] = 16'h5a00;
    crc16_array[215] = 16'h5e40;
    crc16_array[214] = 16'h9e81;
    crc16_array[213] = 16'h9fc1;
    crc16_array[212] = 16'h5f00;
    crc16_array[211] = 16'h9d41;
    crc16_array[210] = 16'h5d80;
    crc16_array[209] = 16'h5cc0;
    crc16_array[208] = 16'h9c01;
    crc16_array[207] = 16'h5440;
    crc16_array[206] = 16'h9481;
    crc16_array[205] = 16'h95c1;
    crc16_array[204] = 16'h5500;
    crc16_array[203] = 16'h9741;
    crc16_array[202] = 16'h5780;
    crc16_array[201] = 16'h56c0;
    crc16_array[200] = 16'h9601;
    crc16_array[199] = 16'h9241;
    crc16_array[198] = 16'h5280;
    crc16_array[197] = 16'h53c0;
    crc16_array[196] = 16'h9301;
    crc16_array[195] = 16'h5140;
    crc16_array[194] = 16'h9181;
    crc16_array[193] = 16'h90c1;
    crc16_array[192] = 16'h5000;
    crc16_array[191] = 16'hb041;
    crc16_array[190] = 16'h7080;
    crc16_array[189] = 16'h71c0;
    crc16_array[188] = 16'hb101;
    crc16_array[187] = 16'h7340;
    crc16_array[186] = 16'hb381;
    crc16_array[185] = 16'hb2c1;
    crc16_array[184] = 16'h7200;
    crc16_array[183] = 16'h7640;
    crc16_array[182] = 16'hb681;
    crc16_array[181] = 16'hb7c1;
    crc16_array[180] = 16'h7700;
    crc16_array[179] = 16'hb541;
    crc16_array[178] = 16'h7580;
    crc16_array[177] = 16'h74c0;
    crc16_array[176] = 16'hb401;
    crc16_array[175] = 16'h7c40;
    crc16_array[174] = 16'hbc81;
    crc16_array[173] = 16'hbdc1;
    crc16_array[172] = 16'h7d00;
    crc16_array[171] = 16'hbf41;
    crc16_array[170] = 16'h7f80;
    crc16_array[169] = 16'h7ec0;
    crc16_array[168] = 16'hbe01;
    crc16_array[167] = 16'hba41;
    crc16_array[166] = 16'h7a80;
    crc16_array[165] = 16'h7bc0;
    crc16_array[164] = 16'hbb01;
    crc16_array[163] = 16'h7940;
    crc16_array[162] = 16'hb981;
    crc16_array[161] = 16'hb8c1;
    crc16_array[160] = 16'h7800;
    crc16_array[159] = 16'h6840;
    crc16_array[158] = 16'ha881;
    crc16_array[157] = 16'ha9c1;
    crc16_array[156] = 16'h6900;
    crc16_array[155] = 16'hab41;
    crc16_array[154] = 16'h6b80;
    crc16_array[153] = 16'h6ac0;
    crc16_array[152] = 16'haa01;
    crc16_array[151] = 16'hae41;
    crc16_array[150] = 16'h6e80;
    crc16_array[149] = 16'h6fc0;
    crc16_array[148] = 16'haf01;
    crc16_array[147] = 16'h6d40;
    crc16_array[146] = 16'had81;
    crc16_array[145] = 16'hacc1;
    crc16_array[144] = 16'h6c00;
    crc16_array[143] = 16'ha441;
    crc16_array[142] = 16'h6480;
    crc16_array[141] = 16'h65c0;
    crc16_array[140] = 16'ha501;
    crc16_array[139] = 16'h6740;
    crc16_array[138] = 16'ha781;
    crc16_array[137] = 16'ha6c1;
    crc16_array[136] = 16'h6600;
    crc16_array[135] = 16'h6240;
    crc16_array[134] = 16'ha281;
    crc16_array[133] = 16'ha3c1;
    crc16_array[132] = 16'h6300;
    crc16_array[131] = 16'ha141;
    crc16_array[130] = 16'h6180;
    crc16_array[129] = 16'h60c0;
    crc16_array[128] = 16'ha001;
    crc16_array[127] = 16'he041;
    crc16_array[126] = 16'h2080;
    crc16_array[125] = 16'h21c0;
    crc16_array[124] = 16'he101;
    crc16_array[123] = 16'h2340;
    crc16_array[122] = 16'he381;
    crc16_array[121] = 16'he2c1;
    crc16_array[120] = 16'h2200;
    crc16_array[119] = 16'h2640;
    crc16_array[118] = 16'he681;
    crc16_array[117] = 16'he7c1;
    crc16_array[116] = 16'h2700;
    crc16_array[115] = 16'he541;
    crc16_array[114] = 16'h2580;
    crc16_array[113] = 16'h24c0;
    crc16_array[112] = 16'he401;
    crc16_array[111] = 16'h2c40;
    crc16_array[110] = 16'hec81;
    crc16_array[109] = 16'hedc1;
    crc16_array[108] = 16'h2d00;
    crc16_array[107] = 16'hef41;
    crc16_array[106] = 16'h2f80;
    crc16_array[105] = 16'h2ec0;
    crc16_array[104] = 16'hee01;
    crc16_array[103] = 16'hea41;
    crc16_array[102] = 16'h2a80;
    crc16_array[101] = 16'h2bc0;
    crc16_array[100] = 16'heb01;
    crc16_array[ 99] = 16'h2940;
    crc16_array[ 98] = 16'he981;
    crc16_array[ 97] = 16'he8c1;
    crc16_array[ 96] = 16'h2800;
    crc16_array[ 95] = 16'h3840;
    crc16_array[ 94] = 16'hf881;
    crc16_array[ 93] = 16'hf9c1;
    crc16_array[ 92] = 16'h3900;
    crc16_array[ 91] = 16'hfb41;
    crc16_array[ 90] = 16'h3b80;
    crc16_array[ 89] = 16'h3ac0;
    crc16_array[ 88] = 16'hfa01;
    crc16_array[ 87] = 16'hfe41;
    crc16_array[ 86] = 16'h3e80;
    crc16_array[ 85] = 16'h3fc0;
    crc16_array[ 84] = 16'hff01;
    crc16_array[ 83] = 16'h3d40;
    crc16_array[ 82] = 16'hfd81;
    crc16_array[ 81] = 16'hfcc1;
    crc16_array[ 80] = 16'h3c00;
    crc16_array[ 79] = 16'hf441;
    crc16_array[ 78] = 16'h3480;
    crc16_array[ 77] = 16'h35c0;
    crc16_array[ 76] = 16'hf501;
    crc16_array[ 75] = 16'h3740;
    crc16_array[ 74] = 16'hf781;
    crc16_array[ 73] = 16'hf6c1;
    crc16_array[ 72] = 16'h3600;
    crc16_array[ 71] = 16'h3240;
    crc16_array[ 70] = 16'hf281;
    crc16_array[ 69] = 16'hf3c1;
    crc16_array[ 68] = 16'h3300;
    crc16_array[ 67] = 16'hf141;
    crc16_array[ 66] = 16'h3180;
    crc16_array[ 65] = 16'h30c0;
    crc16_array[ 64] = 16'hf001;
    crc16_array[ 63] = 16'h1040;
    crc16_array[ 62] = 16'hd081;
    crc16_array[ 61] = 16'hd1c1;
    crc16_array[ 60] = 16'h1100;
    crc16_array[ 59] = 16'hd341;
    crc16_array[ 58] = 16'h1380;
    crc16_array[ 57] = 16'h12c0;
    crc16_array[ 56] = 16'hd201;
    crc16_array[ 55] = 16'hd641;
    crc16_array[ 54] = 16'h1680;
    crc16_array[ 53] = 16'h17c0;
    crc16_array[ 52] = 16'hd701;
    crc16_array[ 51] = 16'h1540;
    crc16_array[ 50] = 16'hd581;
    crc16_array[ 49] = 16'hd4c1;
    crc16_array[ 48] = 16'h1400;
    crc16_array[ 47] = 16'hdc41;
    crc16_array[ 46] = 16'h1c80;
    crc16_array[ 45] = 16'h1dc0;
    crc16_array[ 44] = 16'hdd01;
    crc16_array[ 43] = 16'h1f40;
    crc16_array[ 42] = 16'hdf81;
    crc16_array[ 41] = 16'hdec1;
    crc16_array[ 40] = 16'h1e00;
    crc16_array[ 39] = 16'h1a40;
    crc16_array[ 38] = 16'hda81;
    crc16_array[ 37] = 16'hdbc1;
    crc16_array[ 36] = 16'h1b00;
    crc16_array[ 35] = 16'hd941;
    crc16_array[ 34] = 16'h1980;
    crc16_array[ 33] = 16'h18c0;
    crc16_array[ 32] = 16'hd801;
    crc16_array[ 31] = 16'hc841;
    crc16_array[ 30] = 16'h0880;
    crc16_array[ 29] = 16'h09c0;
    crc16_array[ 28] = 16'hc901;
    crc16_array[ 27] = 16'h0b40;
    crc16_array[ 26] = 16'hcb81;
    crc16_array[ 25] = 16'hcac1;
    crc16_array[ 24] = 16'h0a00;
    crc16_array[ 23] = 16'h0e40;
    crc16_array[ 22] = 16'hce81;
    crc16_array[ 21] = 16'hcfc1;
    crc16_array[ 20] = 16'h0f00;
    crc16_array[ 19] = 16'hcd41;
    crc16_array[ 18] = 16'h0d80;
    crc16_array[ 17] = 16'h0cc0;
    crc16_array[ 16] = 16'hcc01;
    crc16_array[ 15] = 16'h0440;
    crc16_array[ 14] = 16'hc481;
    crc16_array[ 13] = 16'hc5c1;
    crc16_array[ 12] = 16'h0500;
    crc16_array[ 11] = 16'hc741;
    crc16_array[ 10] = 16'h0780;
    crc16_array[  9] = 16'h06c0;
    crc16_array[  8] = 16'hc601;
    crc16_array[  7] = 16'hc241;
    crc16_array[  6] = 16'h0280;
    crc16_array[  5] = 16'h03c0;
    crc16_array[  4] = 16'hc301;
    crc16_array[  3] = 16'h0140;
    crc16_array[  2] = 16'hc181;
    crc16_array[  1] = 16'hc0c1;
    crc16_array[  0] = 16'h0000;
    while (len--)
    begin // {
       local_reg = reflect (pkt[offset], 8);
       crc       = (crc >> 8) ^ crc16_array[(crc ^ local_reg) & 8'hff];
       offset++;
    end // }
    crc = reflect (crc, 16);
    crc16 = (crc);
    if (corrupt)
    begin // {
        corrupt_bit        = $urandom_range(0,15);
        crc16[corrupt_bit] = ~crc16[corrupt_bit];
    end // }
  endfunction : crc16 // }

  // function to compute checksum16
  function bit [15:0] chksm16 (bit [7:0]  pkt [],
                               bit [31:0] len         = 0, 
                               bit [31:0] offset      = 0, 
                               bit        corrupt     = 0,
                               bit [15:0] corrupt_msk = 16'hffff,
                               bit [31:0] chksm       = 32'h00000000); // {
    bit [15:0] local_reg;
    bit [31:0] local_chksm;
    // get the one's complement of orig checksum, if it is nonzero
    if (chksm != 32'h00000000) 
        local_chksm = (~chksm) & 16'hffff;
    else
        local_chksm = 32'h00000000;
`ifdef DEBUG_CHKSM
    $display("%m : Calculating checksum: len %d corrupt %d corrupt_msk 0x%x orig chksm 0x%x local_chksm 0x%x", len, corrupt, corrupt_msk, chksm, local_chksm);
`endif    
    while (len > 1)                                                            
    begin // {                                                                       
        local_reg    = {pkt[offset], pkt[offset+1]};
        offset       = offset + 2;
        len          = len - 2;
        local_chksm += local_reg;
    end // }
    if (len > 0 )
      local_chksm += pkt[offset];
    while (local_chksm >> 16)                                             
      local_chksm = (local_chksm & 16'hffff) + (local_chksm >> 16);
    if (corrupt)
        chksm16   = (~local_chksm) ^ corrupt_msk;
    else
        chksm16   = (~local_chksm);
`ifdef DEBUG_CHKSM
    $display("%m : orig chksm 0x%x final chksm16 0x%x", chksm, chksm16);
`endif    
  endfunction : chksm16 // }

  // function to compute checksum8
  function bit [7:0] chksm8 (bit [7:0]  pkt [],
                             bit [31:0] len         = 0, 
                             bit [31:0] offset      = 0, 
                             bit        corrupt     = 0, 
                             bit [07:0] corrupt_msk = 8'hff); // {
    bit [15:0] chksm = 16'h0000;
    bit [07:0] local_reg;
    while (len-- )
    begin // {
      chksm += pkt[offset];
      offset = offset + 1;
    end // }
    while (chksm >> 8)
      chksm  = (chksm & 8'hff) + (chksm >> 8);
    if (corrupt)
      chksm8 = (~chksm) ^ corrupt_msk;
    else
      chksm8 = (~chksm);
  endfunction : chksm8 // }

  function bit [31:0] reflect (bit [31:0] v, int b); // {
    int        i;
    bit [31:0] t = v;
    for (i = 0; i < b; i++)
    begin // {
        if (t & 1)                                                               
          v |= 1 << ((b-1)-i);
        else
          v &= ~(1 << ((b-1)-i));
        t   >>=1;
    end // }
    reflect = v;
  endfunction : reflect // }

  // function to commpute ECC(32,26) -- Need to paramterized
  function bit [5:0] ecc_32_26 (bit [25:0] Din,
                                bit [31:0] corrupt_vector = 32'h0); // {
      // Flip Din if the vector bit is set
      for (int i1 =0; i1 < 26; i1++)
          if (corrupt_vector[i1])
              Din[i1] = ~Din[i1];
      ecc_32_26 = {Din[10]^Din[11]^Din[12]^Din[13]^Din[14]^Din[15]^Din[16]^Din[17]^Din[18]^Din[19]^Din[21]^Din[22]^Din[23]^Din[24]^Din[25], // P5
                   Din[04]^Din[05]^Din[06]^Din[07]^Din[08]^Din[09]^Din[16]^Din[17]^Din[18]^Din[19]^Din[20]^Din[22]^Din[23]^Din[24]^Din[25], // P4
                   Din[01]^Din[02]^Din[03]^Din[07]^Din[08]^Din[09]^Din[13]^Din[14]^Din[15]^Din[19]^Din[20]^Din[21]^Din[23]^Din[24]^Din[25], // P3
                   Din[00]^Din[02]^Din[03]^Din[05]^Din[06]^Din[09]^Din[11]^Din[12]^Din[15]^Din[18]^Din[20]^Din[21]^Din[22]^Din[24]^Din[25], // P2
                   Din[00]^Din[01]^Din[03]^Din[04]^Din[06]^Din[08]^Din[10]^Din[12]^Din[14]^Din[17]^Din[20]^Din[21]^Din[22]^Din[23]^Din[25], // P2
                   Din[00]^Din[01]^Din[02]^Din[04]^Din[05]^Din[07]^Din[10]^Din[11]^Din[13]^Din[16]^Din[20]^Din[21]^Din[22]^Din[23]^Din[24]};// P0
      // Flip ECC bit if the vector bit is set
      for (int i1 =0; i1 < 6; i1++)
          if (corrupt_vector[i1+26])
              ecc_32_26[i1] = ~ecc_32_26[i1];
  endfunction : ecc_32_26 // }

  // function to check ECC(32,26) -- Need to paramterized
  function bit [31:0] ecc_32_26_check (bit [5:0] ecc_snd,
                                       bit [5:0] ecc_rcv); // {
    bit [5:0]  ecc_sd [26];
    bit [5:0]  ecc_syndrome;
    int        err_pos [$]; 
    ecc_32_26_check  = 26'd0;
    ecc_sd[00] = 6'h07;
    ecc_sd[01] = 6'h0B;
    ecc_sd[02] = 6'h0D;
    ecc_sd[03] = 6'h0E;
    ecc_sd[04] = 6'h13;
    ecc_sd[05] = 6'h15;
    ecc_sd[06] = 6'h16;
    ecc_sd[07] = 6'h19;
    ecc_sd[08] = 6'h1A;
    ecc_sd[09] = 6'h1C;
    ecc_sd[10] = 6'h23;
    ecc_sd[11] = 6'h25;
    ecc_sd[12] = 6'h26;
    ecc_sd[13] = 6'h29;
    ecc_sd[14] = 6'h2A;
    ecc_sd[15] = 6'h2C;
    ecc_sd[16] = 6'h31;
    ecc_sd[17] = 6'h32;
    ecc_sd[18] = 6'h34;
    ecc_sd[19] = 6'h38;
    ecc_sd[20] = 6'h1F;
    ecc_sd[21] = 6'h2F;
    ecc_sd[22] = 6'h37;
    ecc_sd[23] = 6'h3B;
    ecc_sd[24] = 6'h3D;
    ecc_sd[25] = 6'h3E;
    ecc_syndrome = ecc_snd ^ ecc_rcv;
    // 1. If the syndrome is 0, no errors are present - ecc_32_26_check == 26'd0;
    if (ecc_syndrome == 6'd0)
        ecc_32_26_check = 26'd0;
    // 2. If the syndrome has only one bit set, 
    //    then a single bit error has occurred at the parity bit located at syndrome bit position - ecc_32_26_check[26+ecc_syndrom[onehot]] = 1'b1
    else if ($countones(ecc_syndrome) === 1)
    begin // {
        pos_1_0 (err_pos, ecc_syndrome, 6);
        ecc_32_26_check[26 + err_pos[0]] = 1'b1;
    end // }
    else 
    begin // {
        err_pos = ecc_sd.find_first_index with (item == ecc_syndrome); 
        // 3. If the syndrome matches one of the ecc_sd value, 
        //    then a single bit error has occurred at that position - ecc_32_26_check[bit_pos] = 1'b1; 
        if (err_pos.size != 0)
            ecc_32_26_check[err_pos[0]] = 1'b1;
        // 4. If the syndrome does not fit any of the other outcomes, 
        //    then an uncorrectable error has occurred - ecc_32_26_check = 26'hDEAD
        else
            ecc_32_26_check = 26'hDEAD;
    end // }
  endfunction : ecc_32_26_check // }

  // function find positions of number of 1/0 in a vector
  function void pos_1_0 (ref   int               idx_1_0 [$],  // output array to strore position
                         input bit [`VEC_SZ-1:0] bit_vec,      // bit vector to check
                         input int               vec_sz = 32,  // number of bits in vector
                         input bit               f1_0 = 1'b1); // find for 1 or 0 {
    for (int i1 =0; i1 < vec_sz; i1++)
         if (bit_vec[i1] === f1_0)
              idx_1_0.push_back(i1);
  endfunction : pos_1_0 // }

endclass : pktlib_crc_chksm_class // }
