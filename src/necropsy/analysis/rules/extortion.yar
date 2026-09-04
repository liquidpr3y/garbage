/*
   Extortion and destruction indicators. Detection content -- recognising a
   ransom note, not writing one.
*/

rule NECROPSY_Ransom_Note_Language
{
    meta:
        author = "necropsy"
        description = "Extortion language typical of a ransom note"
        severity = "critical"
        attack = "T1486"
        kill_chain = "actions_on_objectives"
        confidence = "0.8"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "all your files are encrypted" ascii wide nocase
        $c = "to decrypt your files" ascii wide nocase
        $d = "pay the ransom" ascii wide nocase
        $e = "decryption key" ascii wide nocase
        $f = ".onion" ascii wide nocase
        $g = "bitcoin" ascii wide nocase
    condition:
        2 of them
}

rule NECROPSY_Recovery_Destruction
{
    meta:
        author = "necropsy"
        description = "Deletes shadow copies or disables Windows recovery"
        severity = "critical"
        attack = "T1490"
        kill_chain = "actions_on_objectives"
        confidence = "0.9"
    strings:
        $a = "vssadmin" ascii wide nocase
        $b = "delete shadows" ascii wide nocase
        $c = "recoveryenabled no" ascii wide nocase
        $d = "bcdedit" ascii wide nocase
        $e = "wbadmin delete catalog" ascii wide nocase
        $f = "Win32_ShadowCopy" ascii wide nocase
    condition:
        2 of them
}
