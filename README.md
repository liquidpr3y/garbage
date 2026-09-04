# Necropsy

Malware analysis and reverse engineering platform for SOC research, built as a **module of
the existing macOS pentest GUI**, not a separate application. Findings are organised around
the Cyber Kill Chain and MITRE ATT&CK.

**Status: proof of concept. Not for distribution.**

## Docs

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Plug-in structure, data flow, module layout, licensing constraints |
| [PHASE1.md](docs/PHASE1.md) | Concrete build plan: data model, vault, file list, API, acceptance criteria |
| [HOST_INTEGRATION.md](docs/HOST_INTEGRATION.md) | The contract the pentest backend must satisfy |
| [SAFETY.md](docs/SAFETY.md) | Handling invariants, scope boundary, repo hygiene |

## Roadmap

1. **Cases data model + intake** — extend the existing backend/GUI shell ← *planned, not started*
2. Static triage: rizin pre-triage, Ghidra headless, YARA, PE parsing
3. Dynamic sandbox on the VMware Fusion lab (ARM-only for the POC); Sysmon → Elastic SIEM
4. ATT&CK mapping layer, per-case technique heatmap, findings mirrored back into Elastic
5. Claude API summarisation + auto-drafted YARA
6. Full merge into the single-pane GUI alongside the pentest tooling

## Non-negotiables

- Samples are never executed on the host Mac — enforced structurally, see SAFETY.md
- Nothing detonates without a human accepting a risk-scored proposal
- No samples, lab topology, or credentials in this repository
