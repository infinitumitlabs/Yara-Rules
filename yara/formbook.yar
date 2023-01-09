import "pe"

/*
   Yara Rule Set
   Author: Sefa
   Date: 2022-12-29
   Identifier: Formbook
*/

/* Rule Set ----------------------------------------------------------------- */

rule Loader {
   meta:
      description = "Detects Formbookloader"
      author = "Sefa"
      date = "2022-12-29"
      hash1 = "4c3d925669944dbdec6649638901b8ccb110c2ff971d8cf558ef05f9980ecf69"
   strings:
      $hex1 = { 41 00 65 00 65 00 65 00 65 }
      $hex2 = { 55 00 5A 00 71 00 74 }
      $hex3 = { 70 A2 25 17 72 BE 38 00 70 A2 25 18 72 CC 38 00 70 A2 7D }
      $x1 = "dPZf.exe" ascii
      $x2 = "BipuniBitan" wide
   condition:
      uint16(0) == 0x5a4d and (
         pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" or
         1 of them
      )
}

rule Formbook {
   meta:
      description = "Detects Formbook"
      author = "Sefa"
      date = "2022-12-29"
      hash1 = "ce5e55a7733010dde02c988d50b0385c0347156e2d2e1892b740100dfafdf913"
   strings:
      $hex1 = { 3C 41 72 35 3C 7A 77 31 3C 5A }
      $hex2 = { 4D 5A 45 52 }
      
   condition:
      uint16(0) == 0x5a4d and filesize < 190KB and (
         all of them
      )
}