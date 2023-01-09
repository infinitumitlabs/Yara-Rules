import "pe"
/*
   Yara Rule Set
   Author: Sefa
   Date: 2022-11-10
   Identifier: Monti
*/
rule Monti {
	meta:
		description = "Detects Monti"
		author = "SEFA"
		date = "2022-11-10"	
	strings:
	$hex_encyrpt = {20 19 57 65 03 62 D0 AE F4 D1 68}
      $hexenc1 = {30 58 33 46 34 50 34 5D 34}
      $hexenc2 = {39 38 39 3E 39 50 39 63 39}
	$hex2 = {2E 00 50 00 55 00 55 00 55 00 4B }
	condition:
		  uint16(0) == 0x5a4d and filesize < 230KB and (
			 pe.imphash() == "5036747c069c42a5e12c38d94db67fad" or
			 all of them
		  )
}
