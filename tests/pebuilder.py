"""A minimal, inert PE32+ writer for test fixtures.

Phase 2 answers questions about imports, section flags, TLS callbacks, debug
paths and overlays, so the fixtures have to actually contain those structures.
Building them here rather than checking in real binaries keeps the rule in
docs/SAFETY.md intact: no samples in the repository, ever -- not even benign
ones, because "it was only a test fixture" is exactly how a repo becomes
un-publishable.

Nothing produced here executes anything: the entry point is a single `ret`,
and no imported function is ever called. It is a shape, not a program.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x140000000

MACHINE_AMD64 = 0x8664
MACHINE_I386 = 0x014C

# Section characteristics
CODE = 0x00000020
INITIALIZED = 0x00000040
EXECUTE = 0x20000000
READ = 0x40000000
WRITE = 0x80000000

DIR_IMPORT = 1
DIR_DEBUG = 6
DIR_TLS = 9
DIR_CERT = 4


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int
    rva: int = 0
    raw_ptr: int = 0


@dataclass
class PESpec:
    machine: int = MACHINE_AMD64
    imports: dict[str, list[str]] = field(default_factory=dict)
    entry_section: str = ".text"
    add_wx_section: bool = False
    tls_callbacks: int = 0
    pdb_path: str | None = None
    overlay: bytes = b""
    text_filler: bytes | None = None
    extra_rdata_strings: list[str] = field(default_factory=list)
    is_dll: bool = False


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _build_import_blob(imports: dict[str, list[str]], base_rva: int) -> tuple[bytes, int]:
    """Import descriptors + ILT/IAT + names, as one contiguous blob."""
    n = len(imports)
    desc_size = 20 * (n + 1)

    thunk_sizes = [8 * (len(fns) + 1) for fns in imports.values()]
    ilt_off = desc_size
    iat_off = ilt_off + sum(thunk_sizes)
    names_off = iat_off + sum(thunk_sizes)

    name_blob = bytearray()
    dll_name_rvas: list[int] = []
    func_name_rvas: list[list[int]] = []

    for dll, funcs in imports.items():
        dll_name_rvas.append(base_rva + names_off + len(name_blob))
        name_blob += dll.encode() + b"\x00"
        if len(name_blob) % 2:
            name_blob += b"\x00"
        rvas = []
        for fn in funcs:
            rvas.append(base_rva + names_off + len(name_blob))
            name_blob += struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(name_blob) % 2:
                name_blob += b"\x00"
        func_name_rvas.append(rvas)

    blob = bytearray(names_off + len(name_blob))

    ilt_cursor, iat_cursor = ilt_off, iat_off
    for i, (_dll, funcs) in enumerate(imports.items()):
        struct.pack_into(
            "<IIIII", blob, 20 * i,
            base_rva + ilt_cursor,   # OriginalFirstThunk
            0, 0,
            dll_name_rvas[i],        # Name
            base_rva + iat_cursor,   # FirstThunk
        )
        for j, _fn in enumerate(funcs):
            entry = func_name_rvas[i][j]
            struct.pack_into("<Q", blob, ilt_cursor + 8 * j, entry)
            struct.pack_into("<Q", blob, iat_cursor + 8 * j, entry)
        ilt_cursor += 8 * (len(funcs) + 1)
        iat_cursor += 8 * (len(funcs) + 1)

    blob[names_off : names_off + len(name_blob)] = name_blob
    return bytes(blob), desc_size


def build(path: Path, spec: PESpec | None = None) -> Path:
    spec = spec or PESpec()

    text = spec.text_filler if spec.text_filler is not None else b"\xc3" + b"\x90" * 0x1FF
    sections = [Section(".text", text, CODE | EXECUTE | READ)]

    # Lay out .rdata: imports, then TLS/debug structures, then filler strings.
    rdata_rva = _align(SECT_ALIGN, SECT_ALIGN) * 2  # placeholder; fixed up below
    rdata = bytearray()
    import_dir = (0, 0)
    tls_dir = (0, 0)
    debug_dir = (0, 0)

    # First pass needs the final .rdata RVA, which depends only on .text size.
    rdata_rva = SECT_ALIGN + _align(len(text), SECT_ALIGN)

    if spec.imports:
        blob, desc_size = _build_import_blob(spec.imports, rdata_rva)
        import_dir = (rdata_rva, desc_size)
        rdata += blob
        if len(rdata) % 8:
            rdata += b"\x00" * (8 - len(rdata) % 8)

    if spec.tls_callbacks:
        cb_array_rva = rdata_rva + len(rdata)
        cb_array = b"".join(
            struct.pack("<Q", IMAGE_BASE + SECT_ALIGN + 0x10 * (i + 1))
            for i in range(spec.tls_callbacks)
        ) + struct.pack("<Q", 0)
        rdata += cb_array
        tls_struct_rva = rdata_rva + len(rdata)
        rdata += struct.pack(
            "<QQQQII",
            IMAGE_BASE + cb_array_rva, IMAGE_BASE + cb_array_rva,
            0, IMAGE_BASE + cb_array_rva, 0, 0,
        )
        tls_dir = (tls_struct_rva, 40)

    if spec.pdb_path:
        cv = b"RSDS" + bytes(range(16)) + struct.pack("<I", 1) + spec.pdb_path.encode() + b"\x00"
        cv_rva = rdata_rva + len(rdata)
        rdata += cv
        if len(rdata) % 4:
            rdata += b"\x00" * (4 - len(rdata) % 4)
        dbg_rva = rdata_rva + len(rdata)
        # AddressOfRawData/PointerToRawData are patched once raw offsets are known.
        rdata += struct.pack("<IIHHIIII", 0, 0, 0, 0, 2, len(cv), cv_rva, 0)
        debug_dir = (dbg_rva, 28)
        cv_rva_marker = cv_rva
    else:
        cv_rva_marker = None

    for extra in spec.extra_rdata_strings:
        rdata += extra.encode() + b"\x00"

    if rdata:
        sections.append(Section(".rdata", bytes(rdata), INITIALIZED | READ))

    sections.append(Section(".data", b"\x00" * 0x100, INITIALIZED | READ | WRITE))
    if spec.add_wx_section:
        # Writable *and* executable: the classic unpacking stub shape.
        sections.append(Section(".packed", b"\xcc" * 0x400, INITIALIZED | EXECUTE | READ | WRITE))

    n_sections = len(sections)
    e_lfanew = 0x80
    size_opt = 240
    headers_size = e_lfanew + 4 + 20 + size_opt + 40 * n_sections
    headers_size = _align(headers_size, FILE_ALIGN)

    rva = SECT_ALIGN
    raw = headers_size
    for section in sections:
        section.rva = rva
        section.raw_ptr = raw
        rva += _align(len(section.data), SECT_ALIGN)
        raw += _align(len(section.data), FILE_ALIGN)

    image_size = rva
    total_raw = raw

    out = bytearray(total_raw)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, e_lfanew)
    out[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    coff = e_lfanew + 4
    characteristics = 0x0022 | (0x2000 if spec.is_dll else 0)
    struct.pack_into(
        "<HHIIIHH", out, coff,
        spec.machine, n_sections, 0x60000000, 0, 0, size_opt, characteristics,
    )

    entry = next(s for s in sections if s.name == spec.entry_section)
    opt = coff + 20
    struct.pack_into("<HBB", out, opt, 0x20B, 14, 0)  # PE32+ magic, linker version
    struct.pack_into("<I", out, opt + 16, entry.rva)  # AddressOfEntryPoint
    struct.pack_into("<Q", out, opt + 24, IMAGE_BASE)
    struct.pack_into("<II", out, opt + 32, SECT_ALIGN, FILE_ALIGN)
    struct.pack_into("<HH", out, opt + 40, 6, 0)  # OS version
    struct.pack_into("<HH", out, opt + 48, 6, 0)  # Subsystem version
    struct.pack_into("<II", out, opt + 56, image_size, headers_size)
    struct.pack_into("<H", out, opt + 68, 3)  # Subsystem: console
    struct.pack_into("<H", out, opt + 70, 0x8160)  # DllCharacteristics
    struct.pack_into("<I", out, opt + 108, 16)  # NumberOfRvaAndSizes

    dirs = opt + 112
    for index, (dir_rva, dir_size) in (
        (DIR_IMPORT, import_dir), (DIR_TLS, tls_dir), (DIR_DEBUG, debug_dir)
    ):
        if dir_size:
            struct.pack_into("<II", out, dirs + 8 * index, dir_rva, dir_size)

    sect_table = opt + size_opt
    for i, section in enumerate(sections):
        off = sect_table + 40 * i
        out[off : off + 8] = section.name.encode().ljust(8, b"\x00")
        struct.pack_into(
            "<IIII", out, off + 8,
            len(section.data), section.rva,
            _align(len(section.data), FILE_ALIGN), section.raw_ptr,
        )
        struct.pack_into("<I", out, off + 36, section.characteristics)
        out[section.raw_ptr : section.raw_ptr + len(section.data)] = section.data

    if cv_rva_marker is not None:
        rdata_section = next(s for s in sections if s.name == ".rdata")
        cv_raw = rdata_section.raw_ptr + (cv_rva_marker - rdata_section.rva)
        dbg_raw = rdata_section.raw_ptr + (debug_dir[0] - rdata_section.rva)
        struct.pack_into("<I", out, dbg_raw + 24, cv_raw)  # PointerToRawData

    data = bytes(out) + spec.overlay
    path.write_bytes(data)
    return path
