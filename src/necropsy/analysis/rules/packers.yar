/*
   Packer and protector identification.

   Detection content only: these rules recognise commodity packers by their
   own artefacts. Nothing here helps produce or reconfigure a packer.
*/

rule NECROPSY_Packer_UPX
{
    meta:
        author = "necropsy"
        description = "UPX-packed executable"
        severity = "medium"
        attack = "T1027.002"
        kill_chain = "installation"
        confidence = "0.9"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
        $s4 = "$Info: This file is packed with the UPX" ascii
    condition:
        uint16(0) == 0x5A4D and (2 of ($s1, $s2, $s3) or $s4)
}

rule NECROPSY_Packer_Themida_WinLicense
{
    meta:
        author = "necropsy"
        description = "Themida / WinLicense protector"
        severity = "medium"
        attack = "T1027.002,T1622"
        kill_chain = "installation"
        confidence = "0.85"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".winlice" ascii
        $s3 = "Themida" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule NECROPSY_Packer_VMProtect
{
    meta:
        author = "necropsy"
        description = "VMProtect virtualising protector"
        severity = "medium"
        attack = "T1027.002"
        kill_chain = "installation"
        confidence = "0.85"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule NECROPSY_Packer_Common_Section_Names
{
    meta:
        author = "necropsy"
        description = "Section names associated with commodity packers"
        severity = "low"
        attack = "T1027.002"
        kill_chain = "installation"
        confidence = "0.6"
    strings:
        $aspack  = ".aspack" ascii
        $mpress  = ".MPRESS1" ascii
        $petite  = ".petite" ascii
        $nspack  = ".nsp0" ascii
        $enigma  = ".enigma1" ascii
        $pklstb  = "PKLITE" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
