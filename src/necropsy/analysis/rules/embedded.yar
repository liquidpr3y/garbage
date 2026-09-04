/*
   Embedded and encoded payload indicators.
*/

rule NECROPSY_Embedded_PE
{
    meta:
        author = "necropsy"
        description = "A second PE image is embedded in this file"
        severity = "medium"
        attack = "T1027.009"
        kill_chain = "delivery"
        confidence = "0.7"
    strings:
        $mz_dos = "This program cannot be run in DOS mode" ascii
    condition:
        uint16(0) == 0x5A4D and #mz_dos > 1
}

rule NECROPSY_Encoded_PowerShell
{
    meta:
        author = "necropsy"
        description = "Base64-encoded PowerShell invocation"
        severity = "high"
        attack = "T1059.001,T1027"
        kill_chain = "exploitation"
        confidence = "0.8"
    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "FromBase64String" ascii wide nocase
        $hid  = "-w hidden" ascii wide nocase
        $nop  = "-nop" ascii wide nocase
    condition:
        2 of them
}

rule NECROPSY_Reflective_Loading
{
    meta:
        author = "necropsy"
        description = "In-memory assembly or module loading"
        severity = "high"
        attack = "T1620"
        kill_chain = "exploitation"
        confidence = "0.75"
    strings:
        $a = "[Reflection.Assembly]::Load" ascii wide nocase
        $b = "System.Reflection.Assembly" ascii wide
        $c = "ReflectiveLoader" ascii
        $d = "VirtualAlloc" ascii
        $e = "memoryModule" ascii nocase
    condition:
        $c or $e or (2 of ($a, $b, $d))
}
