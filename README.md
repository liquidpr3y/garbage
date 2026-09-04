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

1. **Cases data model + intake** — cases, vault, identification, findings, risk-scored proposals ← **built**
2. Static triage: rizin pre-triage, Ghidra headless, YARA, PE parsing
3. Dynamic sandbox on the VMware Fusion lab (ARM-only for the POC); Sysmon → Elastic SIEM
4. ATT&CK mapping layer, per-case technique heatmap, findings mirrored back into Elastic
5. Claude API summarisation + auto-drafted YARA
6. Full merge into the single-pane GUI alongside the pentest tooling

## Running it

```bash
pip install -e ".[analysis,dev]"     # analysis extras are optional; see `necropsy doctor`
cp .env.example .env                 # then edit -- never commit it
necropsy init-db
necropsy doctor                      # reports what this install can actually do

CASE=$(necropsy case new "Invoice phish - Sept" --tag phishing)
necropsy ingest ./sample.bin --case "$CASE"
necropsy serve                       # http://127.0.0.1:8010/api/v1/necropsy
necropsy worker                      # needs Redis; or set NECROPSY_JOB_RUNNER=inline
```

`pytest` runs the whole suite with no network, no Redis and no lab.

## Non-negotiables

- Samples are never executed on the host Mac — enforced structurally, see SAFETY.md
- Nothing detonates without a human accepting a risk-scored proposal
- No samples, lab topology, or credentials in this repository
