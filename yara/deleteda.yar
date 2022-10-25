rule deleteda {
meta:
author = "Sefa"
description = "deleteda rule"
strings:
$string1 = "rvi3t4esijl.dll"
$string2 = "DeleteDateConnectionPosition"
$string3 = "DrawFillBlink"
condition:
all of them
}