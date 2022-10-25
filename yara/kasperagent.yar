rule kasperagent {
meta:
author = "Sefa"
description = "kasperagent rule"
strings:
$hex3 = { 5C 6B 61 73 70 65 72 5C 52 65 6C 65 61 73 65 5C 6B 61 73 70 65 72 2E 70 64 62 }
$hex1 = { 43 00 3A 00 5C 00 53 00 70 00 6F 00 6F 00 6C 00 65 00 72 00 5C 00 76 00 69 00 73 00 61 00 66 00 6F 00 72 00 6D 00 2E 00 64 00 6F 00 63 }
$hex2 = { 43 00 3A 00 5C 00 53 00 70 00 6F 00 6F 00 6C 00 65 00 72 00 5C 00 72 00 75 00 6E 00 74 00 69 00 6D 00 65 00 2E 00 65 00 78 00 65 }
condition:
all of them
}

