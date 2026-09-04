"""String extraction and IOC harvesting.

Pure Python, no native dependency, because strings are the single highest
yield-per-second artefact in triage and must always be available. On a packed
sample the yield collapses, which is itself a finding rather than a failure.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MIN_LENGTH = 4
MAX_STRINGS = 20000
READ_CAP = 32 * 1024 * 1024

_ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LENGTH)
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LENGTH)

# Deliberately conservative. A triage tool that cries wolf on every dotted
# token trains the operator to ignore it.
IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\)]{4,300}", re.I),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "email": re.compile(r"\b[\w.+-]{1,64}@(?:[\w-]{1,63}\.){1,4}[a-z]{2,24}\b", re.I),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,4}"
        r"(?:com|net|org|ru|cn|info|biz|xyz|top|io|co|onion|su|tk|pw)\b",
        re.I,
    ),
    "registry_key": re.compile(
        r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\\\?[\w\\\\ .-]{4,200}", re.I
    ),
    "windows_path": re.compile(r"\b[A-Za-z]:\\\\?[\w\\\\ .$@()-]{3,200}"),
    "env_path": re.compile(r"%(?:APPDATA|TEMP|PROGRAMDATA|SYSTEMROOT|USERPROFILE|LOCALAPPDATA)%[\w\\\\.-]{0,200}", re.I),
    "unc_path": re.compile(r"\\\\\\\\[\w.-]{2,64}\\[\w$.-]{1,200}"),
    "user_agent": re.compile(r"Mozilla/[45]\.0[^\r\n\"]{5,200}"),
    "pipe": re.compile(r"\\\\\\\\\.\\pipe\\[\w.-]{1,100}", re.I),
    "base64_blob": re.compile(r"\b(?:[A-Za-z0-9+/]{4}){12,}={0,2}"),
    "bitcoin": re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}

# Hostnames that are noise in almost every sample.
DOMAIN_NOISE = frozenset(
    {
        "microsoft.com", "windows.com", "msftncsi.com", "verisign.com", "digicert.com",
        "globalsign.com", "symantec.com", "thawte.com", "entrust.net", "sectigo.com",
        "comodoca.com", "godaddy.com", "example.com", "w3.org", "schemas.microsoft.com",
    }
)

IP_NOISE = frozenset({"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"})

VERSION_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class StringHarvest:
    ascii_count: int = 0
    utf16_count: int = 0
    total_unique: int = 0
    strings: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False

    @property
    def ioc_count(self) -> int:
        return sum(len(v) for v in self.iocs.values())

    def summary(self) -> dict[str, Any]:
        return {
            "ascii_count": self.ascii_count,
            "utf16_count": self.utf16_count,
            "total_unique": self.total_unique,
            "truncated": self.truncated,
            "ioc_counts": {k: len(v) for k, v in self.iocs.items()},
        }


def harvest(path: Path, *, max_strings: int = MAX_STRINGS) -> StringHarvest:
    data = path.read_bytes()[:READ_CAP]
    result = StringHarvest()

    ascii_hits = [m.group().decode("latin-1") for m in _ASCII.finditer(data)]
    utf16_hits = [
        m.group().decode("utf-16-le", errors="ignore") for m in _UTF16.finditer(data)
    ]
    result.ascii_count = len(ascii_hits)
    result.utf16_count = len(utf16_hits)

    seen: dict[str, None] = {}
    for value in ascii_hits + utf16_hits:
        value = value.strip()
        if len(value) >= MIN_LENGTH:
            seen.setdefault(value, None)
    unique = list(seen)
    result.total_unique = len(unique)
    if len(unique) > max_strings:
        result.truncated = True
        unique = unique[:max_strings]
    result.strings = unique
    result.iocs = extract_iocs(unique)
    return result


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    found: dict[str, Counter[str]] = {name: Counter() for name in IOC_PATTERNS}
    for value in strings:
        for name, pattern in IOC_PATTERNS.items():
            for match in pattern.findall(value):
                token = match if isinstance(match, str) else match[0]
                if _is_noise(name, token):
                    continue
                found[name][token] += 1
    return {
        name: [token for token, _ in counter.most_common(200)]
        for name, counter in found.items()
        if counter
    }


def _is_noise(name: str, token: str) -> bool:
    lowered = token.lower()
    if name == "domain":
        return any(lowered == n or lowered.endswith("." + n) for n in DOMAIN_NOISE)
    if name == "ipv4":
        # Version strings look exactly like dotted quads and are far more common.
        return token in IP_NOISE or bool(VERSION_LIKE.match(token) and _looks_like_version(token))
    if name == "base64_blob":
        return len(token) < 48
    return False


def _looks_like_version(token: str) -> bool:
    parts = [int(p) for p in token.split(".")]
    return all(p < 40 for p in parts)
