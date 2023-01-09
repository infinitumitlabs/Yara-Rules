/*
   YARA Rule Set
   Author: InfinitumIT
   Date: 2023-01-09
  
*/

/* Rule Set ----------------------------------------------------------------- */

rule Agent_tesla {
   meta:
      description = "12 - file vbc.bin"
      author = "InfinitumIT"
      date = "2023-01-09"
      hash1 = "11291730451790d28b936bd60eec223ab8e690367402e5c5ab746b2adeb858fa"
   strings:
      $s3 = "PmNK.uQ+qP+i8`1" fullword ascii
      $s4 = "LyNv.exe" fullword wide
      $s7 = "4C556E6E3572" wide /* hex encoded string 'LUnn5r' */
      $s11 = "LyNv.pdb" fullword ascii
      $s12 = "RS55Q74D7H7GH" wide
      $s19 = "Cortez.Properties" fullword ascii
      $s20 = ")O71ODAOPQOPYOPaOPiOPqOPyOP" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      7 of them
}

