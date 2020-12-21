
rule Generic_Strings_Hacktools_1
{	
    strings:
        $s1a = {55 73 61 67 65 3A 20 73 73 70 2E 65 78 65 20 50 41 43 4B 41 47 45 5F 50 41 54 48}
        $s1b = {41 64 64 53 65 63 75 72 69 74 79 50 61 63 6B 61 67 65 20 52 61 77 20 52 50 43 20 45 78 61 6D 70 6C 65}
        $s1c = { 62 79 20 40 5F 78 70 6E 5F }
		$s1d = {42 75 69 6C 64 69 6E 67 20 52 50 43 20 70 61 63 6B 65 74}
		$s1e = {6C 73 61 73 73 70 69 72 70 63 ?? ?? ?? ?? ?? ?? 6E 63 61 6C 72 70 63 }
		$s1f = {43 6F 6E 6E 65 63 74 69 6E 67 20 74 6F 20 6C 73 61 73 73 70 69 72 70 63 20 52 50 43 20 73 65 72 76 69 63 65}
		$s1u = {53 65 6E 64 69 6E 67 20 53 73 70 69 72 43 6F 6E 6E 65 63 74 52 70 63 20 63 61 6C 6C}
		$s1v = {5B 2A 5D 20 53 65 6E 64 69 6E 67 20 53 73 70 69 72 43 61 6C 6C 52 70 63 20 63 61 6C 6C}
		$s1x = {45 72 72 6F 72 20 63 6F 64 65 20 30 78 36 63 36 20 72 65 74 75 72 6E 65 64 2C 20 77 68 69 63 68 20 69 73 20 65 78 70 65 63 74 65 64 20 69 66 20 44 4C 4C 20 6C 6F 61 64 20 72 65 74 75 72 6E 73 20 46 41 4C 53 45}
		
    condition:
        filesize < 1000KB and
        (
            any of ($s*)       
        )
}

rule Generic_Strings_Hacktools_2
{
    strings:
        $s1a = {6D 31 6D 69 6B 61 74 7A 2E 64 6C 6C 00 6D 61 69 6E}

		
    condition:
        filesize < 1000KB and
        (
            any of them
        )
}

rule Generic_Strings_Hacktools
{		
    condition:
		Generic_Strings_Hacktools_1 or Generic_Strings_Hacktools_2	
}