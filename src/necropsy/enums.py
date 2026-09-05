"""Shared vocabulary used by both the ORM models and the API schemas."""

from __future__ import annotations

from enum import Enum


class CaseStatus(str, Enum):
    OPEN = "open"
    ANALYSING = "analysing"
    CONTAINED = "contained"
    CLOSED = "closed"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    OFFICE = "office"
    SCRIPT = "script"
    ARCHIVE = "archive"
    PDF = "pdf"
    SHORTCUT = "shortcut"
    UNKNOWN = "unknown"


class Arch(str, Enum):
    """Recorded at intake because it gates Phase 3 target matching.

    An x86 sample on an ARM64-only lab produces unreliable behavioural
    verdicts, and dormancy under emulation is indistinguishable from
    benignity -- so this needs to be known before a detonation is offered,
    not after. See docs/ARCHITECTURE.md S5.
    """

    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIXED = "mixed"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class StorageState(str, Enum):
    VAULTED = "vaulted"
    QUARANTINED = "quarantined"
    PURGED = "purged"


class SampleSource(str, Enum):
    UPLOAD = "upload"
    PATH = "path"
    URL = "url"
    SANDBOX_DROP = "sandbox_drop"


class JobKind(str, Enum):
    IDENTIFY = "identify"
    HASH_PIVOT = "hash_pivot"
    # Registered but not implemented until the phase named in registry.py.
    STATIC_TRIAGE = "static_triage"
    YARA_SCAN = "yara_scan"
    GHIDRA_DECOMPILE = "ghidra_decompile"
    DETONATE = "detonate"
    SIGMA_SWEEP = "sigma_sweep"
    AI_SUMMARISE = "ai_summarise"
    AI_REPORT = "ai_report"
    AI_YARA = "ai_yara"


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class KillChainPhase(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONISATION = "weaponisation"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class Producer(str, Enum):
    INTAKE = "intake"
    STRINGS = "strings"
    CAPABILITY = "capability"
    PE = "pe"
    YARA = "yara"
    RIZIN = "rizin"
    GHIDRA = "ghidra"
    SYSMON = "sysmon"
    ZEEK = "zeek"
    SANDBOX = "sandbox"
    AI = "ai"
    CORRELATION = "correlation"


class ActionState(str, Enum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXECUTED = "executed"
    EXPIRED = "expired"


class ArtifactKind(str, Enum):
    STRINGS = "strings"
    STATIC_REPORT = "static_report"
    DECOMPILATION = "decompilation"
    TELEMETRY = "telemetry"
    UNPACKED = "unpacked"
    PCAP = "pcap"
    MEMDUMP = "memdump"
    GHIDRA_PROJECT = "ghidra_project"
    SCREENSHOT = "screenshot"
    REPORT = "report"
    YARA_RULE = "yara_rule"
    OTHER = "other"
