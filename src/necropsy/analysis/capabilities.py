"""Capability detection: imports and strings -> what the sample can do.

This is the analytic core of static triage, and the point at which findings
acquire ATT&CK technique IDs. Tagging at the producer rather than in a later
pass is deliberate: the evidence for "this calls VirtualAllocEx,
WriteProcessMemory and CreateRemoteThread" is right here, and a mapping layer
that re-derives it from a finding title would be guessing. Phase 4 aggregates
these into the per-case heatmap and adds the behavioural (Sysmon/Sigma) side;
it does not need to re-do this.

Two honesty constraints:

* Capability is not intent. A binary that can take a screenshot may be a
  remote support tool. Findings say what the code is equipped to do, and
  severity/confidence are set accordingly -- never "this is malware".
* Import-based detection collapses on packed samples, whose import tables are
  a stub. `detection_quality` reports that explicitly so a thin result is read
  as "we cannot see" rather than "there is nothing here".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from necropsy.enums import KillChainPhase, Severity

KCP = KillChainPhase


@dataclass(frozen=True)
class Capability:
    id: str
    title: str
    description: str
    severity: Severity
    kill_chain_phase: KillChainPhase
    attack: tuple[str, ...]
    imports: frozenset[str] = frozenset()
    strings: tuple[str, ...] = ()
    # Distinct indicators required before this is reported. Set higher for
    # capabilities whose individual APIs are common in benign software.
    min_hits: int = 2


def _c(**kw: Any) -> Capability:
    kw["imports"] = frozenset(n.lower() for n in kw.get("imports", ()))
    kw["strings"] = tuple(s.lower() for s in kw.get("strings", ()))
    return Capability(**kw)


CATALOGUE: tuple[Capability, ...] = (
    _c(
        id="process_injection",
        title="Process injection primitives",
        description=(
            "Allocates and writes memory in another process and starts execution there. "
            "The canonical remote-injection sequence."
        ),
        severity=Severity.HIGH,
        kill_chain_phase=KCP.EXPLOITATION,
        attack=("T1055", "T1055.002"),
        imports=(
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtWriteVirtualMemory", "NtCreateThreadEx", "RtlCreateUserThread",
            "QueueUserAPC", "NtQueueApcThread", "OpenProcess", "VirtualProtectEx",
        ),
        min_hits=3,
    ),
    _c(
        id="process_hollowing",
        title="Process hollowing primitives",
        description="Unmaps a suspended process image and replaces it with its own.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.EXPLOITATION,
        attack=("T1055.012",),
        imports=(
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
            "GetThreadContext", "ResumeThread", "CreateProcessInternalW",
        ),
        min_hits=3,
    ),
    _c(
        id="dynamic_api_resolution",
        title="Resolves APIs at runtime",
        description=(
            "Looks up functions dynamically instead of importing them. Ordinary in "
            "plugin hosts; in a small binary with a thin import table it usually means "
            "the real capability is hidden from static import analysis."
        ),
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1027.007",),
        imports=("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress",
                 "LdrLoadDll", "LdrGetProcedureAddress"),
        min_hits=2,
    ),
    _c(
        id="registry_run_persistence",
        title="Registry autorun persistence",
        description="Writes to a Run/RunOnce key so the payload survives reboot.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1547.001",),
        imports=("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"),
        strings=(r"currentversion\run", r"currentversion\runonce", "userinit", "shell folders"),
        min_hits=2,
    ),
    _c(
        id="service_persistence",
        title="Windows service installation",
        description="Creates or reconfigures a service, giving SYSTEM-level persistence.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1543.003",),
        imports=("OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
                 "StartServiceA", "ChangeServiceConfigA", "ChangeServiceConfigW"),
        strings=("sc create", "sc config"),
        min_hits=2,
    ),
    _c(
        id="scheduled_task_persistence",
        title="Scheduled task persistence",
        description="Registers a scheduled task for persistence or delayed execution.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1053.005",),
        strings=("schtasks", "/create /tn", "taskschd.dll", "itaskservice",
                 "\\microsoft\\windows\\", "register-scheduledtask"),
        min_hits=2,
    ),
    _c(
        id="credential_access_lsass",
        title="LSASS / credential store access",
        description="Reaches for the credential store or LSASS memory.",
        severity=Severity.CRITICAL,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1003", "T1003.001"),
        imports=("LsaOpenPolicy", "LsaRetrievePrivateData", "CredEnumerateA",
                 "CredEnumerateW", "CredReadA", "MiniDumpWriteDump", "SamConnect"),
        strings=("lsass.exe", "sekurlsa", "\\sam", "\\security\\policy\\secrets"),
        min_hits=2,
    ),
    _c(
        id="browser_credential_theft",
        title="Browser credential and cookie theft",
        description="Reads browser credential stores or cookie databases.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1555.003", "T1539"),
        imports=("CryptUnprotectData",),
        strings=("login data", "cookies.sqlite", "logins.json", "web data",
                 r"\google\chrome\user data", "key4.db", "places.sqlite"),
        min_hits=2,
    ),
    _c(
        id="keylogging",
        title="Keystroke capture",
        description="Installs a keyboard hook or polls key state.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1056.001",),
        imports=("SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                 "GetKeyboardState", "RegisterRawInputDevices", "GetKeyState"),
        min_hits=2,
    ),
    _c(
        id="screen_capture",
        title="Screen capture",
        description="Grabs the screen via GDI bit-block transfer.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1113",),
        imports=("BitBlt", "GetDC", "CreateCompatibleBitmap", "CreateCompatibleDC",
                 "GetDIBits", "PrintWindow"),
        min_hits=3,
    ),
    _c(
        id="clipboard_capture",
        title="Clipboard monitoring",
        description="Reads clipboard contents -- commonly used for crypto address swapping.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1115",),
        imports=("OpenClipboard", "GetClipboardData", "SetClipboardData",
                 "AddClipboardFormatListener"),
        min_hits=2,
    ),
    _c(
        id="http_c2",
        title="HTTP client capability",
        description="Speaks HTTP(S) outbound -- the most common C2 channel.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.COMMAND_AND_CONTROL,
        attack=("T1071.001",),
        imports=("InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
                 "HttpSendRequestA", "InternetReadFile", "WinHttpOpen", "WinHttpConnect",
                 "WinHttpSendRequest", "URLDownloadToFileA", "URLDownloadToFileW"),
        min_hits=2,
    ),
    _c(
        id="raw_socket_c2",
        title="Raw socket networking",
        description="Opens sockets directly rather than through an HTTP stack.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.COMMAND_AND_CONTROL,
        attack=("T1095",),
        imports=("WSAStartup", "socket", "connect", "send", "recv", "WSASocketA", "bind",
                 "listen", "accept"),
        min_hits=3,
    ),
    _c(
        id="dns_c2",
        title="Direct DNS querying",
        description="Issues DNS queries directly, which can carry a covert channel.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.COMMAND_AND_CONTROL,
        attack=("T1071.004",),
        imports=("DnsQuery_A", "DnsQuery_W", "DnsQueryEx"),
        min_hits=1,
    ),
    _c(
        id="anti_debug",
        title="Anti-debugging checks",
        description="Detects a debugger and can alter behaviour when analysed.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1622",),
        imports=("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                 "NtQueryInformationProcess", "OutputDebugStringA", "NtSetInformationThread"),
        min_hits=2,
    ),
    _c(
        id="sandbox_evasion",
        title="Virtualisation / sandbox detection",
        description=(
            "Looks for hypervisor and analysis artefacts. Directly relevant to this lab: "
            "a sample that detects emulation and goes dormant is indistinguishable from "
            "a benign one in the sandbox timeline."
        ),
        severity=Severity.HIGH,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1497", "T1497.001"),
        strings=("vboxservice", "vmtoolsd", "vmware", "virtualbox", "qemu", "sbiedll",
                 "vboxtray", "wine_get_unix_file_name", "sandboxie", "cuckoomon",
                 "hgfs", "vbox guest additions"),
        min_hits=2,
    ),
    _c(
        id="defence_evasion_tampering",
        title="Security product tampering",
        description="Attempts to disable AV/EDR, the firewall, or event logging.",
        severity=Severity.CRITICAL,
        kill_chain_phase=KCP.INSTALLATION,
        attack=("T1685", "T1686"),
        strings=("netsh advfirewall set", "set-mppreference", "add-mppreference",
                 "-exclusionpath", "windefend", "wevtutil cl", "stop-service",
                 "taskkill /f /im", "sc stop"),
        min_hits=1,
    ),
    _c(
        id="shadow_copy_destruction",
        title="Backup and shadow copy destruction",
        description=(
            "Deletes volume shadow copies or disables recovery. Near-diagnostic of "
            "ransomware pre-encryption staging."
        ),
        severity=Severity.CRITICAL,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1490",),
        strings=("vssadmin", "delete shadows", "win32_shadowcopy", "bcdedit",
                 "recoveryenabled no", "wbadmin delete", "resize shadowstorage"),
        min_hits=1,
    ),
    _c(
        id="file_encryption",
        title="Bulk file encryption capability",
        description="Cryptographic primitives combined with filesystem enumeration.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1486",),
        imports=("CryptAcquireContextA", "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
                 "BCryptGenerateSymmetricKey", "FindFirstFileA", "FindNextFileA",
                 "FindFirstFileW", "FindNextFileW"),
        min_hits=3,
    ),
    _c(
        id="lolbin_execution",
        title="Living-off-the-land binary invocation",
        description="Invokes signed Windows binaries to proxy execution.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.EXPLOITATION,
        attack=("T1218", "T1059.001"),
        strings=("rundll32", "regsvr32", "mshta", "certutil -decode", "bitsadmin",
                 "wmic process call create", "powershell -enc", "powershell -e ",
                 "-nop -w hidden", "cscript", "wscript", "installutil", "msiexec /i http"),
        min_hits=1,
    ),
    _c(
        id="uac_bypass",
        title="UAC bypass indicators",
        description="Known auto-elevation hijack paths.",
        severity=Severity.HIGH,
        kill_chain_phase=KCP.EXPLOITATION,
        attack=("T1548.002",),
        strings=("fodhelper", "eventvwr", "computerdefaults", "sdclt",
                 r"\shell\open\command", "ms-settings\\shell", "slui.exe"),
        min_hits=1,
    ),
    _c(
        id="host_discovery",
        title="Host and domain reconnaissance",
        description="Enumerates host, user, domain and network configuration.",
        severity=Severity.LOW,
        kill_chain_phase=KCP.RECONNAISSANCE,
        attack=("T1082", "T1033", "T1016"),
        imports=("GetComputerNameA", "GetComputerNameW", "GetUserNameA", "GetUserNameW",
                 "GetSystemInfo", "GetAdaptersInfo", "GetVolumeInformationA",
                 "NetWkstaGetInfo", "GetNativeSystemInfo"),
        strings=("whoami", "systeminfo", "net group \"domain admins\"", "nltest"),
        min_hits=3,
    ),
    _c(
        id="staging_archive",
        title="Collection staging via archiving",
        description="Compresses collected data prior to exfiltration.",
        severity=Severity.MEDIUM,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1560.001",),
        strings=("rar.exe a -", "7z.exe a ", "-hp", "compress-archive", ".zip\" -password"),
        min_hits=1,
    ),
    _c(
        id="ransom_note",
        title="Ransom note or extortion text",
        description="Extortion language or a payment channel embedded in the binary.",
        severity=Severity.CRITICAL,
        kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
        attack=("T1486",),
        strings=("your files have been encrypted", "all your files", "decrypt",
                 ".onion", "tox id", "readme.txt", "how to restore", "ransom"),
        min_hits=2,
    ),
)

CATALOGUE_BY_ID = {c.id: c for c in CATALOGUE}

_SUFFIXED = re.compile(r"(?:[AW]|Ex[AW]?)$")


@dataclass
class CapabilityHit:
    capability: Capability
    matched_imports: list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)

    @property
    def hit_count(self) -> int:
        return len(self.matched_imports) + len(self.matched_strings)

    @property
    def confidence(self) -> float:
        """More distinct indicators, more confidence -- capped short of certainty.

        Static capability detection can be defeated by packing and faked by
        unreachable code, so this never reaches 1.0.
        """
        surplus = self.hit_count - self.capability.min_hits
        return round(min(0.9, 0.45 + 0.1 * max(0, surplus) + 0.05 * self.capability.min_hits), 2)

    def evidence(self) -> dict[str, Any]:
        return {
            "capability": self.capability.id,
            "matched_imports": sorted(self.matched_imports)[:40],
            "matched_strings": sorted(self.matched_strings)[:40],
            "hit_count": self.hit_count,
            "attack": list(self.capability.attack),
        }


def _import_forms(name: str) -> set[str]:
    lowered = name.lower()
    forms = {lowered}
    stripped = _SUFFIXED.sub("", name).lower()
    if stripped:
        forms.add(stripped)
    return forms


def detect(imports: list[str], strings: list[str]) -> list[CapabilityHit]:
    import_forms: dict[str, str] = {}
    for name in imports:
        for form in _import_forms(name):
            import_forms.setdefault(form, name)

    haystack = "\n".join(s.lower() for s in strings)

    hits: list[CapabilityHit] = []
    for capability in CATALOGUE:
        matched_imports = sorted(
            {import_forms[f] for f in capability.imports if f in import_forms}
        )
        matched_strings = [s for s in capability.strings if s in haystack]
        hit = CapabilityHit(capability, matched_imports, matched_strings)
        if hit.hit_count >= capability.min_hits:
            hits.append(hit)

    hits.sort(key=lambda h: (-_SEVERITY_ORDER[h.capability.severity], -h.hit_count))
    return hits


_SEVERITY_ORDER = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}


def detection_quality(import_count: int, string_count: int, packed: bool) -> dict[str, Any]:
    """Say how much the absence of findings is worth.

    A packed sample with eleven imports has not been shown to be harmless; it
    has not been shown at all. Reporting that distinction is the difference
    between triage and false reassurance.
    """
    degraded = packed or import_count < 12 or string_count < 40
    if not degraded:
        note = "Import table and strings are intact; static capability coverage is good."
    elif packed:
        note = (
            "Sample is packed. The import table and strings visible here belong to the "
            "unpacking stub, not the payload. Absence of a capability below is not "
            "evidence the payload lacks it -- unpack first."
        )
    else:
        note = (
            f"Thin static surface ({import_count} imports, {string_count} strings). "
            "Capability coverage is limited; treat absence as unknown, not negative."
        )
    return {"degraded": degraded, "import_count": import_count,
            "string_count": string_count, "packed": packed, "note": note}
