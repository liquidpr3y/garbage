# Phase 2 — Static triage

**Goal:** an operator accepts the "Static triage" proposal from Phase 1 and gets a full
offline picture of a sample — PE structure, strings and IOCs, capability detection mapped
to ATT&CK, YARA hits — then optionally pays for a Ghidra decompile that sees past what the
import table shows. Nothing executes the sample.

**Status: built.** 131 tests pass with no network, no Redis, no lab and no external
analyser installed. The Ghidra path was verified against a real Ghidra 11.4.2 headless run,
not stubbed.

---

## 1. What produces findings now

| Producer | Module | Emits |
|---|---|---|
| `pe` | `analysis/pe.py` | W+X sections, high-entropy sections, entry point outside code, TLS callbacks, debug/PDB path, overlay |
| `capability` | `analysis/capabilities.py` | 24 capabilities, each ATT&CK-tagged, from imports + strings |
| `yara` | `analysis/yara_rules.py` | Rule hits, severity/technique/phase read from rule metadata |
| `strings` | `analysis/strings.py` | Network IOCs (URL, IP, domain, UA) with noise filtering |
| `ghidra` | `analysis/ghidra.py` | Capabilities visible only after decompilation; function inventory |

All of them land in the single normalised `Finding` model built in Phase 1. No new finding
pipeline, which was the point of that design.

## 2. ATT&CK tagging happens here, not in Phase 4

Findings now populate `attack_technique_ids` and `kill_chain_phase`. This is a deliberate
departure from the original phase split, and worth being explicit about.

The evidence for a technique mapping exists at the producer and nowhere else. "This binary
imports `VirtualAllocEx`, `WriteProcessMemory` and `CreateRemoteThread`" *is* the argument
for T1055 — a later layer reading only the finding title would be re-deriving a conclusion
from a summary of itself. So the catalogue carries the mapping, the finding carries the
evidence, and Phase 4 aggregates rather than infers.

Phase 4 is unchanged in scope and still has to build: the per-case technique heatmap, the
behavioural (Sysmon → Sigma) side of the mapping, and the Elastic mirror. It just starts
from tagged findings instead of untagged ones.

## 3. Capability detection, and the honesty constraint

`analysis/capabilities.py` matches 24 capabilities across the kill chain — injection,
hollowing, runtime API resolution, four persistence mechanisms, credential and browser
theft, keylogging, screen and clipboard capture, three C2 channel types, anti-debug,
sandbox evasion, security-product tampering, shadow copy destruction, bulk encryption,
LOLBin proxying, UAC bypass, discovery, staging, extortion text.

Three rules keep it from becoming a random-finding generator:

- **`min_hits` per capability.** `OpenProcess` alone is ordinary Windows programming; the
  allocate-write-execute sequence is not. Capabilities whose individual APIs are common
  require more distinct indicators.
- **Confidence never reaches 1.0.** Static capability detection is defeated by packing and
  faked by unreachable code. The number says so, and it is separate from severity, so a
  high-severity low-confidence result cannot be mistaken for a YARA hit.
- **Capability is not intent.** A binary that can capture the screen may be a remote
  support tool. Findings state what the code is equipped to do.

There is a true-negative test: an ordinary PE importing `GetLastError`, `CloseHandle` and
`Sleep` must produce zero capability findings and zero high-severity findings. A triage
tool that flags everything trains the operator to ignore it.

### The degraded-coverage finding

The most important output when a sample is packed is `capability_coverage_degraded`:

> Sample is packed. The import table and strings visible here belong to the unpacking stub,
> not the payload. Absence of a capability below is not evidence the payload lacks it —
> unpack first.

Without this, a packed sample produces a short finding list that reads like a clean bill of
health. This is the static-analysis equivalent of the Phase 1 arch-mismatch warning: the
failure mode is a confident negative, and the fix is to say what you could not see.

## 4. Why a decompile is worth eight minutes

`ghidra_decompile` re-runs capability detection over the decompiled C and the call graph,
and reports anything found **only** there:

```
Process injection primitives (visible only after decompilation)
  This was not visible in the import table, which means the sample resolves it at
  runtime. Static import analysis alone would have missed it.
```

`GetProcAddress("CreateRemoteThread")` is invisible to import-table analysis and plain in
the decompilation. That difference is the concrete argument for the cost, and the job
states it rather than leaving the operator to infer it.

Functions are stored as rows (`functions` table, migration `0002_functions`) rather than
only inside the export blob, so the GUI can page and search them and Phase 5 has somewhere
to hang a per-function AI summary. Each carries `code_sha256` — the whitespace-normalised
hash of its decompiled body — because identical function bodies across samples are shared
code, a far more specific clustering signal than a whole-file fuzzy hash and one hash per
function to compute.

## 5. External tooling: degrade, never gate

| Tool | Licence stance | Absent behaviour |
|---|---|---|
| LIEF | Apache-2.0, imported | Phase 1's own PE parser still answers arch and signature |
| yara-python | BSD-3, imported | Triage runs, `yara_available: false` in the result |
| TLSH | Apache-2.0, imported | No fuzzy hash; everything else unaffected |
| rizin | LGPL-3, **subprocess** | Reported unavailable; enrichment only, never gated a finding |
| Ghidra | Apache-2.0, subprocess | Proposal shows "Ghidra not installed; set NECROPSY_GHIDRA_HOME" |
| ssdeep | GPL-2, **subprocess** | Optional |

`test_degraded.py` runs the whole triage pipeline with LIEF, YARA, TLSH, libmagic and rizin
all removed, and asserts it still emits IOC and string-based capability findings plus the
degraded-coverage note. An analyst on a bare laptop gets a worse answer, not an error.

Unavailable tooling surfaces on the *proposal*, so the GUI greys out a decompile the
machine cannot run rather than offering a button that fails. `necropsy doctor` prints the
same information as a checklist — every "no" is a class of finding this machine will
silently not produce.

## 6. Ghidra integration specifics

Driven through `support/analyzeHeadless` into a throwaway project, with
`ghidra_scripts/necropsy_export.py` as a post-script exporting functions and decompiled C
as JSON. Read-only throughout: Ghidra never executes the sample and the emulator is not
enabled.

**Script language.** The export script is written in the subset of Python valid under both
Jython 2.7 (how Ghidra runs `.py` GhidraScripts today) and CPython 3 (how PyGhidra will).
No f-strings, no `print` statement, explicit encoding on write. Jython is deprecated
upstream, so that one file is the entire migration surface when it goes.

**Verified, not assumed.** A real headless run against a fixture with genuine x86-64 code
returns `x86:LE:64:default`, one internal function, and decompiled C containing `0x2b` —
that is 42 + 1, so the decompilation is correct rather than merely present. The test is
marked `slow` and skipped unless `GHIDRA_HOME` is set.

**One bug found by running it.** `getFunctionCount()` includes external (import) functions
that `getFunctions(True)` does not iterate, so the first version reported "exported 1 of 4"
and would have flagged truncation on every binary. Fixed by counting the same iterator the
export walks.

## 7. Test fixtures: a PE writer, not a checked-in binary

`tests/pebuilder.py` writes structurally valid, inert PE32+ files with real import tables,
configurable section flags, TLS callbacks, CODEVIEW debug paths and overlays. LIEF parses
them, computes a real imphash, and reads the PDB path back.

This exists because the alternative is checking a binary into the repository, and "it was
only a benign test fixture" is exactly how a repo becomes one you cannot make public. The
generated files contain no executable payload: the entry point is a single `ret` and no
imported function is ever called.

## 8. Scope check

Everything here is analysis. The YARA rules are detection content — they recognise
commodity packers, extortion language and VM-detection artefacts. The capability catalogue
describes what code can do so a defender can hunt it. Nothing in Phase 2 packs, obfuscates,
or tests a sample against defences; the line and its examples are in
[SAFETY.md](SAFETY.md).

## 9. What Phase 3 inherits

- `Sample.arch` and the ARM-fidelity warning already gate detonation proposals.
- `sandbox_evasion` capability findings now tell the operator *before* detonating that a
  quiet run will be unreadable — which on an ARM-only lab is the difference between a
  wasted run and a misread one.
- Network IOCs are extracted and flagged with "hunt these in the SIEM before detonating:
  an existing hit changes the case from analysis to incident response."
- `artifacts` storage, the vault `put_bytes` path and the shared proposal publisher all
  exist, so PCAPs and Sysmon captures are new producers rather than new plumbing.
