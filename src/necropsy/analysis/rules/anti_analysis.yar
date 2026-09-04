/*
   Anti-analysis artefacts. Directly relevant to this lab: a sample that
   detects virtualisation and goes dormant looks identical to a benign one
   in the sandbox timeline.
*/

rule NECROPSY_VM_Artefact_Strings
{
    meta:
        author = "necropsy"
        description = "References hypervisor or analysis-tool artefacts"
        severity = "high"
        attack = "T1497.001"
        kill_chain = "installation"
        confidence = "0.75"
    strings:
        $a = "VBoxService" ascii wide nocase
        $b = "vmtoolsd" ascii wide nocase
        $c = "VMwareService" ascii wide nocase
        $d = "SbieDll.dll" ascii wide nocase
        $e = "VIRTUAL HD" ascii wide nocase
        $f = "QEMU" ascii wide
        $g = "VBOX__" ascii wide
        $h = "cuckoomon" ascii wide nocase
    condition:
        2 of them
}

rule NECROPSY_Debugger_Evasion
{
    meta:
        author = "necropsy"
        description = "Debugger detection and evasion primitives"
        severity = "medium"
        attack = "T1622"
        kill_chain = "installation"
        confidence = "0.7"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
        $c = "NtQueryInformationProcess" ascii
        $d = "NtSetInformationThread" ascii
        $e = "OutputDebugString" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}
