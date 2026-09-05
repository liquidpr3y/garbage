# Necropsy

Malware analysis and reverse engineering platform for SOC research, built as a **module of
the existing macOS pentest GUI**, not a separate application. Findings are organised around
the Cyber Kill Chain and MITRE ATT&CK.

**Status: proof of concept. Not for distribution.**

## Docs

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Plug-in structure, data flow, module layout, licensing constraints |
| [PHASE1.md](docs/PHASE1.md) | Cases, vault, intake, findings, risk-scored proposals |
| [PHASE2.md](docs/PHASE2.md) | Static triage: capabilities, YARA, Ghidra, and where ATT&CK tagging happens |
| [PHASE3.md](docs/PHASE3.md) | Dynamic sandbox: detonation invariants, the readability verdict, telemetry |
| [PHASE4.md](docs/PHASE4.md) | ATT&CK heatmap, detection gaps, Sigma, and the Elastic findings mirror |
| [HOST_INTEGRATION.md](docs/HOST_INTEGRATION.md) | The contract the pentest backend must satisfy |
| [SAFETY.md](docs/SAFETY.md) | Handling invariants, scope boundary, repo hygiene |

## Roadmap

1. **Cases data model + intake** — cases, vault, identification, findings, risk-scored proposals ← **built**
2. **Static triage** — PE structure, strings/IOCs, ATT&CK-mapped capabilities, YARA, Ghidra decompilation ← **built**
3. **Dynamic sandbox** — vmrun detonation, host-side PCAP, Sysmon read back from Elastic, behavioural ATT&CK mapping ← **built**
4. **ATT&CK mapping layer** — bundled ATT&CK v19.2, per-case heatmap with evidence grades, detection-gap analysis, Sigma sweeps, findings mirrored into Elastic ← **built**
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
necropsy triage <sha256> --case "$CASE"   # PE, strings, capabilities, YARA
necropsy actions --case "$CASE"           # risk-scored next steps
necropsy accept <action-id>               # authorise one (the only route to detonation)
necropsy attack --case "$CASE"            # ATT&CK matrix + detection gaps
necropsy serve                       # http://127.0.0.1:8010/api/v1/necropsy
necropsy worker                      # needs Redis; or set NECROPSY_JOB_RUNNER=inline
```

`pytest` runs the whole suite with no network, no Redis and no lab.

## Non-negotiables

- Samples are never executed on the host Mac — enforced structurally, see SAFETY.md
- Nothing detonates without a human accepting a risk-scored proposal — there is deliberately no `necropsy detonate`
- A quiet run is never reported as a clean one; see the readability verdict in PHASE3.md
- Absence of evidence is reported as a visibility gap, never as a clean result
- No samples, lab topology, or credentials in this repository
