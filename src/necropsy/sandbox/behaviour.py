"""Sysmon telemetry -> behavioural findings.

The static side answers "what is this equipped to do". This answers "what did
it do", which is a different and stronger claim -- so the ATT&CK mappings here
carry higher confidence than their static counterparts. An import of
`RegSetValueEx` is a capability; a registry write to a Run key is an act.

The most important output is not a behaviour at all. It is the verdict on
whether the run is readable: a sample that produced almost no telemetry has
not been shown to be harmless, and on an emulated pairing that silence is the
expected result of the sample failing to run rather than choosing not to act.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from necropsy.enums import KillChainPhase, Severity
from necropsy.sandbox.targets.base import EmulationFidelity

KCP = KillChainPhase

# Below this, the run tells you nothing. Booting Windows and launching a
# process generates telemetry on its own, so a near-empty window means the
# sample never really ran.
DORMANCY_EVENT_THRESHOLD = 8

LOLBINS = {
    "rundll32.exe": ("T1218.011", "Proxied execution via rundll32"),
    "regsvr32.exe": ("T1218.010", "Proxied execution via regsvr32"),
    "mshta.exe": ("T1218.005", "Proxied execution via mshta"),
    "certutil.exe": ("T1140", "certutil used for encoding or download"),
    "bitsadmin.exe": ("T1197", "BITS job created"),
    "installutil.exe": ("T1218.004", "Proxied execution via InstallUtil"),
    "msbuild.exe": ("T1127.001", "Proxied execution via MSBuild"),
    "wmic.exe": ("T1047", "WMI used for execution"),
    "cscript.exe": ("T1059.005", "Script host execution"),
    "wscript.exe": ("T1059.005", "Script host execution"),
    "powershell.exe": ("T1059.001", "PowerShell execution"),
    "pwsh.exe": ("T1059.001", "PowerShell execution"),
    "cmd.exe": ("T1059.003", "Command shell execution"),
    "schtasks.exe": ("T1053.005", "Scheduled task created"),
    "sc.exe": ("T1543.003", "Service created or modified"),
    "vssadmin.exe": ("T1490", "Shadow copy administration"),
    "wbadmin.exe": ("T1490", "Backup catalog administration"),
    "bcdedit.exe": ("T1490", "Boot configuration modified"),
    "net.exe": ("T1087", "Account or share enumeration"),
    "nltest.exe": ("T1482", "Domain trust discovery"),
    "whoami.exe": ("T1033", "User discovery"),
}

RUN_KEY = re.compile(r"currentversion\\+run(once)?\\+", re.I)
SERVICES_KEY = re.compile(r"\\+services\\+", re.I)
DEFENCE_TAMPER = re.compile(
    r"(netsh\s+advfirewall|set-mppreference|add-mppreference|-exclusionpath|"
    r"wevtutil\s+cl|taskkill\s+/f|stop-service\s+windefend)", re.I
)
DESTRUCTIVE = re.compile(
    r"(vssadmin.{0,20}delete\s+shadows|wbadmin\s+delete|bcdedit.{0,40}recoveryenabled\s+no|"
    r"win32_shadowcopy)", re.I
)
STAGING_DIR = re.compile(r"\\+(appdata|temp|programdata|users\\+public)\\+", re.I)


@dataclass
class Behaviour:
    id: str
    title: str
    description: str
    severity: Severity
    kill_chain_phase: KillChainPhase
    attack: list[str]
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviourReport:
    event_count: int = 0
    events_by_code: dict[str, int] = field(default_factory=dict)
    process_tree: list[dict[str, Any]] = field(default_factory=list)
    contacted_ips: list[str] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    behaviours: list[Behaviour] = field(default_factory=list)
    readable: bool = True
    verdict_note: str = ""

    def summary(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "events_by_code": self.events_by_code,
            "behaviours": [b.id for b in self.behaviours],
            "attack_techniques": sorted({t for b in self.behaviours for t in b.attack}),
            "contacted_ips": self.contacted_ips[:50],
            "dns_queries": self.dns_queries[:50],
            "readable": self.readable,
            "verdict_note": self.verdict_note,
        }


def analyse(
    events: list[dict[str, Any]],
    *,
    fidelity: EmulationFidelity,
    sample_image: str | None = None,
) -> BehaviourReport:
    report = BehaviourReport(event_count=len(events))
    report.events_by_code = dict(
        Counter(str(_get(e, "event.code") or "?") for e in events).most_common()
    )

    children: dict[str, list[str]] = defaultdict(list)
    ips: Counter[str] = Counter()
    dns: Counter[str] = Counter()
    lolbin_hits: dict[str, list[str]] = defaultdict(list)
    autoruns: list[str] = []
    service_writes: list[str] = []
    remote_threads = 0
    pipes: list[str] = []
    tampering: list[str] = []
    destructive: list[str] = []
    staged_files: list[str] = []

    for event in events:
        code = str(_get(event, "event.code") or "")
        name = (_get(event, "process.name") or "").lower()
        parent = (_get(event, "process.parent.name") or "").lower()
        cmdline = _get(event, "process.command_line") or ""

        if code == "1":
            if parent:
                children[parent].append(name)
            if name in LOLBINS:
                lolbin_hits[name].append(cmdline[:400])
            if DEFENCE_TAMPER.search(cmdline):
                tampering.append(cmdline[:400])
            if DESTRUCTIVE.search(cmdline):
                destructive.append(cmdline[:400])

        elif code == "3":
            destination = _get(event, "destination.ip")
            if destination and _is_external(destination):
                ips[destination] += 1

        elif code == "22":
            question = _get(event, "dns.question.name")
            if question:
                dns[question] += 1

        elif code in ("12", "13", "14"):
            path = _get(event, "registry.path") or ""
            if RUN_KEY.search(path):
                autoruns.append(path[:400])
            elif SERVICES_KEY.search(path):
                service_writes.append(path[:400])

        elif code == "8":
            remote_threads += 1

        elif code == "17":
            pipe = _get(event, "file.name") or _get(event, "file.path") or ""
            if pipe:
                pipes.append(pipe[:200])

        elif code == "11":
            path = _get(event, "file.path") or ""
            if STAGING_DIR.search(path):
                staged_files.append(path[:400])

        elif code == "25":
            remote_threads += 1

    report.process_tree = [
        {"parent": parent, "children": sorted(set(kids))} for parent, kids in children.items()
    ]
    report.contacted_ips = [ip for ip, _ in ips.most_common()]
    report.dns_queries = [q for q, _ in dns.most_common()]

    _add = report.behaviours.append

    if autoruns:
        _add(Behaviour(
            id="autorun_persistence", title="Wrote an autorun registry value",
            description="The sample established persistence via a Run/RunOnce key.",
            severity=Severity.HIGH, kill_chain_phase=KCP.INSTALLATION,
            attack=["T1547.001"], confidence=0.95, evidence={"paths": autoruns[:10]},
        ))
    if service_writes:
        _add(Behaviour(
            id="service_persistence", title="Modified service configuration",
            description="Service registry keys were written -- SYSTEM-level persistence.",
            severity=Severity.HIGH, kill_chain_phase=KCP.INSTALLATION,
            attack=["T1543.003"], confidence=0.85, evidence={"paths": service_writes[:10]},
        ))
    if remote_threads:
        _add(Behaviour(
            id="remote_thread_injection", title="Created a thread in another process",
            description=(
                "Sysmon recorded cross-process thread creation. Unlike the static "
                "capability finding, this is the act rather than the ability."
            ),
            severity=Severity.CRITICAL, kill_chain_phase=KCP.EXPLOITATION,
            attack=["T1055"], confidence=0.95, evidence={"count": remote_threads},
        ))
    for binary, cmdlines in lolbin_hits.items():
        technique, label = LOLBINS[binary]
        _add(Behaviour(
            id=f"lolbin_{binary.replace('.exe', '')}", title=f"{label} ({binary})",
            description=f"The sample invoked {binary}.",
            severity=Severity.MEDIUM, kill_chain_phase=KCP.EXPLOITATION,
            attack=[technique], confidence=0.9, evidence={"command_lines": cmdlines[:5]},
        ))
    if destructive:
        _add(Behaviour(
            id="recovery_destruction", title="Destroyed backups or recovery data",
            description="Shadow copies or recovery configuration were targeted.",
            severity=Severity.CRITICAL, kill_chain_phase=KCP.ACTIONS_ON_OBJECTIVES,
            attack=["T1490"], confidence=0.95, evidence={"command_lines": destructive[:5]},
        ))
    if tampering:
        _add(Behaviour(
            id="defence_tampering", title="Tampered with security controls",
            description="Firewall, AV or event logging was modified.",
            severity=Severity.CRITICAL, kill_chain_phase=KCP.INSTALLATION,
            attack=["T1685"], confidence=0.9, evidence={"command_lines": tampering[:5]},
        ))
    if report.contacted_ips or report.dns_queries:
        _add(Behaviour(
            id="network_activity", title="Contacted external network infrastructure",
            description=(
                "Outbound connections observed during detonation. These are live "
                "indicators: hunt them across the estate before closing the case."
            ),
            severity=Severity.HIGH, kill_chain_phase=KCP.COMMAND_AND_CONTROL,
            attack=["T1071"], confidence=0.9,
            evidence={"ips": report.contacted_ips[:30], "dns": report.dns_queries[:30]},
        ))
    if pipes:
        _add(Behaviour(
            id="named_pipe", title="Created a named pipe",
            description="Named pipes are used for both IPC and C2 channels.",
            severity=Severity.LOW, kill_chain_phase=KCP.COMMAND_AND_CONTROL,
            attack=["T1090.001"], confidence=0.6, evidence={"pipes": pipes[:10]},
        ))
    if staged_files:
        _add(Behaviour(
            id="staging_writes", title="Wrote files to a staging directory",
            description="Files written to AppData/Temp/ProgramData -- typical payload staging.",
            severity=Severity.MEDIUM, kill_chain_phase=KCP.INSTALLATION,
            attack=["T1074.001"], confidence=0.7, evidence={"paths": staged_files[:20]},
        ))

    report.readable, report.verdict_note = _verdict(report, fidelity, sample_image)
    return report


def _verdict(
    report: BehaviourReport, fidelity: EmulationFidelity, sample_image: str | None
) -> tuple[bool, str]:
    """Decide whether this run supports any conclusion at all."""
    quiet = report.event_count < DORMANCY_EVENT_THRESHOLD

    if not quiet and report.behaviours:
        return True, (
            f"{report.event_count} events observed with "
            f"{len(report.behaviours)} behaviour(s) identified."
        )
    if not quiet:
        return True, (
            f"{report.event_count} events observed and no known-malicious behaviour "
            "matched. The run is readable; the sample may be benign, may be waiting on "
            "a trigger it did not receive, or may act outside the observation window."
        )

    if fidelity is EmulationFidelity.EMULATED:
        return False, (
            f"INCONCLUSIVE: only {report.event_count} events. This sample ran under "
            "architecture emulation, where failing to start and choosing not to act "
            "look identical. Do not record this as benign -- re-run it on a native "
            "target before drawing any conclusion."
        )
    if fidelity is EmulationFidelity.UNSUPPORTED:
        return False, (
            "INCONCLUSIVE: the target cannot execute this architecture at all. "
            "Nothing about the sample's behaviour was tested."
        )
    return False, (
        f"INCONCLUSIVE: only {report.event_count} events on a natively-capable target. "
        "Either the sample detected the sandbox, requires a trigger it did not get "
        "(arguments, a C2 response, a specific date), or failed to launch. Check the "
        "screenshot and the static sandbox-evasion findings before re-running."
    )


def _get(event: dict[str, Any], dotted: str) -> Any:
    """ECS documents arrive both nested and flattened depending on the pipeline."""
    if dotted in event:
        return event[dotted]
    node: Any = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _is_external(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
