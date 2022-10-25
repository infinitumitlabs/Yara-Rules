import "pe"

/*
   Yara Rule Set
   Author: Arda Büyükkaya
   Date: 2022-10-25
   Identifier: Kasper Agent
*/

/* Rule Set ----------------------------------------------------------------- */

rule KasperBackdoor {
   meta:
      description = "Detects Kasper Agent"
      author = "Arda Büyükkaya"
      date = "2022-10-25"
      hash1 = "608960a8120276c9b5dbdc71cd3094be339ac5be0120d78b3eb6bf9359ed5e0f"
   strings:
      $hex3 = { 5C 6B 61 73 70 65 72 5C 52 65 6C 65 61 73 65 5C 6B 61 73 70 65 72 2E 70 64 62 }
      $hex1 = { 43 00 3A 00 5C 00 53 00 70 00 6F 00 6F 00 6C 00 65 00 72 00 5C 00 76 00 69 00 73 00 61 00 66 00 6F 00 72 00 6D 00 2E 00 64 00 6F 00 63 }
      $hex2 = { 43 00 3A 00 5C 00 53 00 70 00 6F 00 6F 00 6C 00 65 00 72 00 5C 00 72 00 75 00 6E 00 74 00 69 00 6D 00 65 00 2E 00 65 00 78 00 65 }
      $x1 = "\\Release\\Loader.pdb" ascii
      $x2 = "C:\\D@oc@um@en@ts a@nd Set@tings\\Al@l Users" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and (
         pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" or
         1 of them
      )
}
