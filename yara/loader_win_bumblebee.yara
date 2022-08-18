rule loader_win_bumblebee {
   meta:
      malware = "BumbleBee Loader"
      reference = ""
      source = "Infinitum IT"
      classification = "TLP:WHITE"

   strings:
      $str0 = { 5a 00 3a 00 5c 00 68 00 6f 00 6f 00 6b 00 65 00 72 00 32 00 5c 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 5c 00 6d 00 64 00 35 00 2e 00 63 00 70 00 70 00 } // Z:\hooker2\Common\md5.cpp
      $str1 = "/gates" ascii
      $str2 = "3C29FEA2-6FE8-4BF9-B98A-0E3442115F67" wide

   condition:
      uint16be(0) == 0x4d5a and all of them
}

rule malw_ISO{
    meta:
      malware = "Identifies execution artefacts in ISO files"
      reference = ""
      source = "Infinitum IT"
      classification = "TLP:WHITE"
strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}

rule Windows_Trojan_Bumblebee{
    strings:
        $a1 = "Checking Virtual PC processes %s " wide fullword
        $a2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii fullword
        $a3 = "Injection-Date" ascii fullword
        $a4 = " -Command \"Wait-Process -Id " ascii fullword
        $a5 = "%WINDIR%\\System32\\wscript.exe" wide fullword
        $a6 = "objShell.Run \"rundll32.exe my_application_path"
        $a7 = "Checking reg key HARDWARE\\Description\\System - %s is set to %s" wide fullword
    condition:
        5 of them
}
