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
//  Common display class for all the hdrs
// ----------------------------------------------------------------------

class pktlib_display_class; // {

  // ~~~~~~~~~~ Class variables ~~~~~~~~~~
        string       cls_name;
        int          err;
        int          index;
        bit [7:0]    null_a [];

  function new (string cls_name = ""); // {
    this.cls_name = cls_name;
    this.err      = 0;
    this.index    = 0;
    this.null_a   = new [0];
  endfunction : new // }

  // This task displays the feild of individual hdr
  task display_fld (int               mode        = DISPLAY, // display or compare
                    string            hname,                 // string literals
                    int               fltype,                // Field type - BIT_VEC, ARRAY or STRING(for comments)
                    int               flval,                 // Field value - DEC, BIN, HEX, etc..
                    int               flsz,                  // Field size
                    string            flname,                // Field name - string literals
                    bit [`VEC_SZ-1:0] flvec,
                    bit [`VEC_SZ-1:0] flvec2      = `VEC_SZ'h0,
                    bit [7:0]         flarray  [] = null_a,
                    bit [7:0]         flarray2 [] = null_a,
                    string            flcomment   = "NO");   // comments if field type is STRING {
    $sformat (hname, "%16s", hname);
    $sformat (flname,"%32s",flname);
    if ((mode == NO_DISPLAY) |(mode == COMPARE_NO_DISPLAY))
    begin // {
        if ((fltype == BIT_VEC) | (fltype == BIT_VEC_NH))
        begin // {
            if (flvec != flvec2)
                err++;
        end // }
        if ((mode == COMPARE_NO_DISPLAY) && (fltype == ARRAY))
            compare_array8 (flarray, flarray2, err, mode, hname, flname, "pkt_lib");
    end // }
    else 
    begin // {
        if (fltype == STRING)
            $display ("%0s%s : %s", cls_name, hname, flcomment);
        if ((fltype == BIT_VEC) | (fltype == BIT_VEC_NH))
        begin // { 
            if (fltype == BIT_VEC)
                $write("%0s%s : [%4d : %4d] : %3d : %s : ", cls_name, hname, index, index+flsz-1, index/8, flname);
            else
                $write("%0s%s :                       %s : ", cls_name, hname, flname);
            case (flval) // {
                HEX     : $write ("%0d'h%0x ", flsz, flvec);
                BIN     : $write ("%0d'b%0b ", flsz, flvec);
                DEC     : $write ("%0d'd%0d ", flsz, flvec);
                DEF     : $write ("%0d ",      flvec);
                default : $write ("%0d ",      flvec);
            endcase // }
            if (((mode === COMPARE) | (mode === COMPARE_FULL)) & (flvec != flvec2))
            begin // {
                err++;
                case (flval) // {
                HEX     : $write ("!= %0d'h%0x (ERROR) ", flsz, flvec2);
                BIN     : $write ("!= %0d'b%0b (ERROR) ", flsz, flvec2);
                DEC     : $write ("!= %0d'd%0d (ERROR) ", flsz, flvec2);
                DEF     : $write ("!= %0d (ERROR) ",      flvec2);
                default : $write ("!= %0d (ERROR) ",      flvec2);
            endcase // }
            end // }
            if (flcomment != "NO")
                $write   ("(%s)", flcomment);
            $write("\n");
        end // }
        if ((fltype == ARRAY) | (fltype == ARRAY_NH))
        begin // {
             if ((mode === COMPARE) | (mode === COMPARE_FULL))
                 compare_array8 (flarray, flarray2, err, mode, hname, flname, "pkt_lib");
             else
             begin // {
                 if (fltype == ARRAY)
                     $write("%0s%s :               : %3d : %s : ", cls_name, hname, index/8, flname);
                 else
                     $write("%0s%s :                       %s : ", cls_name, hname, flname);
                 if (flarray.size != 0)
                 begin // {
                     $write ("(Total Len  = %0d)\n", flarray.size());
                     display_array8 (flarray, hname, "NO", 0, 0);
                 end // }
                 else
                     $write ("(EMPTY)\n");
             end // }
        end // }
    end // }
    if (fltype == BIT_VEC)
        index += flsz;
    if (fltype == ARRAY)
        index += flarray.size*8;
  endtask : display_fld // }

  // This task displays each byte of array entire pkt
  task display_array8 (bit [7:0]        data [],
                       string           hname       = "pkt_lib", // string literals
                       string           usr_comment = "NO",
                       int              mode        = 0,
                       int              n_atend     = 1); // {
    $sformat (hname, "%16s", hname);
    if (usr_comment != "NO")
        $write ("%0s%s : %s\n",cls_name, hname, usr_comment);  
    for (int i = 0; i < 16 ; i++)
    begin // {
        if (i % 16 == 0)
            $write ("%0s%s :       %2d ", cls_name, hname, i);
        else if (i % 16 == 7)
            $write ("%3d |", i);
        else if (i % 16 == 15)
            $write ("%3d\n", i);
        else
            $write ("%3d", i);
    end // }
    $write ("%0s%s :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~\n", cls_name, hname);
    for (int i = 0; i < data.size(); i++)
    begin
        if (i % 16 == 0)
            $write ("%0s%s : %4d : ", cls_name, hname, i);
        $write ("%x ", data[i]);
        if (i % 16 == 7)
            $write ("| ");
        if (i % 16 == 15)
            $write ("\n");
    end
    if (data.size() % 16 !== 0)
        $write ("\n");
    $write ("%0s%s :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~\n", cls_name, hname);
    if (mode)
        $write ("%s%s : (Total Len  = %0d)\n", cls_name, hname, data.size());
    repeat (n_atend)
       $write ("\n");
  endtask : display_array8 // }

 task compare_array8 (       bit [7:0]        rcv [],
                             bit [7:0]        exp [],
                       ref   int              cmp_err,
                       input int              mode           = COMPARE,
                       input string           hname          = "pkt_lib", // string literals
                       input string           flname         = "",        // string literals
                       input string           cmp_type       = "Pkt",
                       input string           err_type       = "ERROR",   // string literals
                       input string           info_type      = "INFO",
                       input int              nochkcnt       = 0); // {
    int rcv_len, exp_len, cmp_len;
    int i, off, err;
    bit always_display;
    bit [7:0] tmp;
    $sformat (hname, "%16s", hname);
    $sformat (flname,"%32s",flname);
    err = 0;
    rcv_len = rcv.size;
    exp_len = exp.size;
    if (rcv_len > exp_len)
        cmp_len = rcv_len;
    else
        cmp_len = exp_len;
    if (rcv_len != exp_len)
        err++;
    else if (nochkcnt > rcv_len)
        err++;
    else
    begin  // {
      for (i = 0; i < rcv_len-nochkcnt; i++)
      begin  // {
          if (rcv[i] != exp[i])
              err++;
      end // }
    end // }
    if (mode !== COMPARE_NO_DISPLAY)
    begin // {
      if (mode == COMPARE_FULL)
          always_display = 1'b1;
      if (cmp_type == "pkt_lib")
      begin // {
          if (err !== 0)
              $write ("%0s%s : %s : Mismatch (ERROR) :-( Length Rcv => %0d Exp => %0d\n",cls_name, hname, flname, rcv_len, exp_len);  
          else
              $write ("%0s%s : %s : Matched :-) Length Rcv => %0d Exp => %0d\n",cls_name, hname, flname, rcv_len, exp_len);  
      end // }
      else
      begin // {
          if (err)
              $display("%0t : %s : %0s%s : %s Miscompares :-( Length Rcv => %0d Exp => %0d",
                        $time, err_type, cls_name, hname, cmp_type, rcv_len, exp_len);
          else
              $display("%0t : %s : %0s%s : %s Compares :-) Length Rcv => %0d Exp => %0d",
                        $time, info_type, cls_name, hname, cmp_type, rcv_len, exp_len);
      end // }
      off = 0;
      if (err | always_display | (nochkcnt > 0))
      begin // {
        $write ("%0s%s :        ~~~~~~~~~ RCV ~~~~~~~~~~|~~~~~~~~~ EXP ~~~~~~~~~~\n", cls_name, hname);
        for (i = 0; i < 16 ; i++)
        begin // {
            if (i % 16 == 0)
                $write ("%0s%s :       %2d ", cls_name, hname, i%8);
            else if (i % 16 == 7)
                $write ("%3d |", i%8);
            else if (i % 16 == 15)
                $write ("%3d\n", i%8);
            else
                $write ("%3d", i%8);
        end // }
        $write ("%0s%s :        ~~~~~~~~~~~~~~~~~~~~~~~~|~~~~~~~~~~~~~~~~~~~~~~~~\n", cls_name, hname);
        while (off < cmp_len)
        begin // {
           for (i = 0; i < 8; i++)
           begin // {
               if ((off + i) < rcv_len)
               begin // {
                   if (i == 0)
                       $write ("%0s%s : %4d : %h ", cls_name, hname, off, rcv[off + i]);
                   else
                       $write ("%h ", rcv[off + i]);
               end // }
               else if ((off + i) < cmp_len)
               begin // {
                   if (i == 0)
                       $write ("%0s%s : %4d : ?? ", cls_name, hname, off);
                   else
                       $write ("?? ");
               end // }
               else
                   $write ("   ");
           end // }
           $write ("| ");
           for (i = 0; i < 8; i++)
           begin // {
               if ((off + i) < exp_len)
               begin // {
                   tmp = exp[off + i];
                   if ((off + i) >= rcv_len)
                       $write ("%h ", tmp[7:0]);
                   else if (tmp == rcv[off + i])
                       $write (".. ");
                   else
                       $write ("%h ", tmp[7:0]);
               end // }
               else if ((off + i) < cmp_len)
                   $write ("?? ");
           end // }
           $write ("\n");
           off = off + 8;
        end // }
      end // }
    end // }
    if (err != 0)
        cmp_err++;
  endtask  : compare_array8 // }

  // This task displays each byte of array entire pkt
  task display_array16 (bit [15:0]        data [],
                        string           hname       = "pkt_lib", // string literals
                        string           usr_comment = "NO",
                        int              mode        = 0,
                        int              n_atend     = 1); // {
    $sformat (hname, "%16s", hname);
    if (usr_comment != "NO")
        $write ("%0s%s : %s\n",cls_name, hname, usr_comment);
    for (int i = 0; i < 8 ; i++)
    begin // {
        if (i % 8 == 0)
            $write ("%0s%s :       %2d ", cls_name, hname, i);
        else if (i % 8 == 7)
            $write ("%5d\n", i);
        else
            $write ("%5d", i);
    end // }
    $write ("%0s%s :        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", cls_name, hname);
    for (int i = 0; i < data.size(); i++)
    begin
        if (i % 8 == 0)
            $write ("%0s%s : %4d : ", cls_name, hname, i);
        $write ("%x ", data[i]);
        if (i % 8 == 7)
            $write ("\n");
    end
    if (data.size() % 8 !== 0)
        $write ("\n");
    $write ("%0s%s :        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", cls_name, hname);
   
    if (mode)
        $write ("%s%s : (Total Len  = %0d)\n", cls_name, hname, data.size());
    repeat (n_atend)
       $write ("\n");
  endtask : display_array16 // }

endclass : pktlib_display_class // }
