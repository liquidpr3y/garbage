"""Synthetic benign controls for false-positive testing.

A drafted YARA rule has to be tested against something that is *not* the
sample, or "it matches" means nothing. Operators can point
NECROPSY_AI_GOODWARE_DIR at real known-good binaries, and should. Absent that,
these generated controls at least catch a rule that keys on generic PE
structure, common imports or compiler boilerplate -- the most common way a
drafted rule goes wrong.

These are generated files, not samples: a valid PE header over inert filler,
carrying the kind of ordinary imports and strings a benign Windows binary has.
"""

from __future__ import annotations

import struct
from pathlib import Path

COMMON_IMPORTS = [
    "GetLastError", "CloseHandle", "Sleep", "CreateFileW", "ReadFile", "WriteFile",
    "GetModuleHandleW", "GetProcAddress", "LoadLibraryW", "HeapAlloc", "HeapFree",
    "LocalFree", "GetCommandLineW", "ExitProcess", "VirtualAlloc", "VirtualFree",
    "RegOpenKeyExW", "RegQueryValueExW", "WSAStartup", "InternetOpenA",
]

COMMON_STRINGS = [
    "This program cannot be run in DOS mode.",
    "Microsoft Visual C++ Runtime Library",
    "mscoree.dll", "KERNEL32.dll", "USER32.dll", "ADVAPI32.dll",
    "Software\\Microsoft\\Windows\\CurrentVersion",
    "C:\\Program Files\\Vendor\\Product\\product.exe",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "https://update.vendor.example.com/check",
    "Runtime Error!", "Assertion failed", "invalid argument",
]


def _minimal_pe(strings: list[str], import_names: list[str]) -> bytes:
    """A structurally valid PE32+ with an entry point that returns immediately."""
    e_lfanew = 0x80
    size_opt = 240
    headers = 0x400

    blob = bytearray(b"\x00" * headers)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, e_lfanew)
    blob[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", blob, e_lfanew + 4, 0x8664, 2, 0x60000000, 0, 0, size_opt, 0x0022)

    opt = e_lfanew + 24
    struct.pack_into("<H", blob, opt, 0x20B)
    struct.pack_into("<I", blob, opt + 16, 0x1000)
    struct.pack_into("<II", blob, opt + 32, 0x1000, 0x200)
    struct.pack_into("<I", blob, opt + 108, 16)

    sections = opt + size_opt
    for index, name in ((0, b".text"), (1, b".rdata")):
        offset = sections + 40 * index
        blob[offset : offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", blob, offset + 8, 0x200, 0x1000 * (index + 1), 0x200,
                         headers + 0x200 * index)
        struct.pack_into("<I", blob, offset + 36, 0x40000000)

    text = b"\xc3" + b"\x90" * 0x1FF
    payload = b"\x00".join(s.encode() for s in strings + import_names) + b"\x00"
    rdata = payload.ljust(0x200, b"\x00")
    return bytes(blob) + text + rdata


def write_controls(directory: Path) -> list[Path]:
    """Write the synthetic benign corpus into `directory`."""
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    variants = {
        "control_generic.bin": (COMMON_STRINGS, COMMON_IMPORTS),
        "control_networking.bin": (
            COMMON_STRINGS + ["POST /api/v1/telemetry HTTP/1.1", "User-Agent: Updater/2.0"],
            COMMON_IMPORTS + ["HttpSendRequestA", "InternetConnectA", "InternetReadFile"],
        ),
        "control_installer.bin": (
            COMMON_STRINGS
            + [
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "%APPDATA%\\Vendor\\updater.exe",
                "Installing components...",
            ],
            COMMON_IMPORTS + ["RegSetValueExW", "CreateServiceW", "OpenSCManagerW",
                              "SHGetFolderPathW", "CopyFileW"],
        ),
    }
    for name, (strings, imports) in variants.items():
        path = directory / name
        path.write_bytes(_minimal_pe(strings, imports))
        written.append(path)
    return written
