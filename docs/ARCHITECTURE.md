# Necropsy — Malware Analysis & RE Platform

> Working package name: `necropsy`. Trivially renameable — it appears in one place
> (`src/necropsy/`) plus the entry-point string in `pyproject.toml`.

Status: **proof of concept**. Not for distribution. See [SAFETY.md](SAFETY.md) for the
handling invariants and the scope boundary (this platform *analyses* malware; it does not
generate, weaponise or improve it).

---

## 1. The core structural decision: extension, not fork

The existing macOS pentest GUI already owns the shell, the orchestration loop and the
risk-scoring UX. Necropsy must not re-implement any of that. It is packaged as a
**separate Python distribution that the host backend discovers and mounts**, and a
**new panel in the host GUI that talks to the mounted REST/WS surface**.

Three seams, and nothing else crosses:

| Seam | Direction | Mechanism |
|---|---|---|
| **Mount** | host → module | Host imports `necropsy.plugin:MODULE` and calls `MODULE.mount(app, host_services)` |
| **Services** | module → host | `HostServices` Protocol: Redis conn, event publisher, artifact root, actor identity, engagement/case ref resolver |
| **UI** | GUI → module | OpenAPI schema + `/ws/cases/{id}` event stream. No shared Swift code, only shared design tokens |

Discovery is via a packaging entry point so the host never hardcodes an import:

```toml
# pyproject.toml
[project.entry-points."pentestgui.modules"]
necropsy = "necropsy.plugin:MODULE"
```

The host does `importlib.metadata.entry_points(group="pentestgui.modules")` at boot,
mounts whatever it finds under `/api/v1/{module.slug}`. Adding Necropsy is then
`pip install -e ../necropsy` and a restart. Removing it is `pip uninstall`.

### Standalone mode is mandatory, not a nicety

`necropsy.standalone.app` is a dev-only FastAPI app that mounts the same router with a
`StandaloneHost` implementation of `HostServices`. Without this you cannot develop,
test or CI the module without booting the whole macOS app, and the two projects will
silently fuse. Every `HostServices` method gets a local fallback:

| HostServices | Host impl | StandaloneHost impl |
|---|---|---|
| `redis()` | host's pool | local `redis://localhost:6379/1` |
| `publish(channel, event)` | host event bus | Redis pub/sub |
| `actor()` | logged-in operator | `"local"` |
| `artifact_root()` | host vault path | `~/.necropsy/vault` |
| `resolve_engagement(ref)` | host engagement store | returns `None` |
| `risk_policy()` | host thresholds | packaged defaults |

If a feature can only work when the host provides it, it is behind a capability check
(`host.has("engagements")`), never an import-time dependency.

---

## 2. Orchestration parity — the thing that makes it feel like one product

The pentest GUI's pattern is: *a stage completes → results push into the next stage →
the human chooses what happens next → when several options exist, each carries a risk
score so blast radius is visible before the click.*

Necropsy adopts this literally by making **`NextAction` a first-class row in the data
model from Phase 1**, not a Phase 4 afterthought. Every analysis stage terminates by
emitting zero or more proposals:

```
static_triage completes on 3f9a…c1
  ├─ Finding: packed (high entropy .text, imports stub only)   T1027.002
  ├─ Finding: 4 YARA hits (Themida, anti-VM string set)        T1497
  └─ NextAction proposals:
       • Full Ghidra decompile pass          risk 1   cost ~8 min
       • Detonate: isolated snapshot         risk 6   [packed, anti-VM, unknown C2]
       • Detonate: snapshot + egress allowed risk 9   [live C2 contact, attributable IP]
       • Hunt hash across Elastic (30d)      risk 1
```

The risk score is computed by a **local scorer that consumes the same `RiskFactor`
vocabulary the pentest module uses** (`contracts/risk.py`), so the GUI renders both
module's proposals with one component and one colour scale. This is the single highest
leverage piece of shared surface — get it right in Phase 1 and Phases 3–6 mostly become
new producers of `Finding` and `NextAction` rows.

**Nothing auto-detonates.** Detonation is always a proposal the operator accepts. The
`NextAction` row records `decided_by` / `decided_at` — that is also your chain of custody.

---

## 3. Everything reduces to `Finding`

One normalised finding type, many producers. A YARA hit, a PE anomaly, a Sysmon process
tree, a Zeek DNS anomaly and a Claude-authored summary all land in the same table with:

- `producer` (`yara`, `pe`, `ghidra`, `sysmon`, `zeek`, `ai`)
- `severity` + `confidence` (kept separate — a high-severity low-confidence AI inference
  must not read like a YARA hit)
- `attack_technique_ids: list[str]` and `kill_chain_phase`
- `evidence: dict` (producer-specific, schema-free)
- `dedupe_key` (so re-running a job doesn't multiply findings)

**Phase 1 creates the ATT&CK columns even though nothing populates them yet.** Phase 4's
technique heatmap then becomes a `GROUP BY` over findings rather than a second pipeline,
and the Cyber Kill Chain view is a second projection of the same rows. Retrofitting these
columns after three phases of findings have accumulated is the expensive version.

---

## 4. Repository / module layout

```
necropsy/
├── pyproject.toml               # deps, entry point, ruff/pytest config
├── .gitignore                   # hard-blocks samples, vaults, *.bin/exe/dll, .env
├── .env.example                 # no real lab values — see SAFETY.md
├── alembic.ini
├── migrations/                  # render_as_batch=True (SQLite ALTER)
├── docs/
│   ├── ARCHITECTURE.md          # this file
│   ├── PHASE1.md                # concrete build plan
│   ├── HOST_INTEGRATION.md      # the contract the pentest backend must satisfy
│   └── SAFETY.md                # handling invariants + scope boundary
├── src/necropsy/
│   ├── plugin.py                # MODULE descriptor: slug, router, mount(), migrations
│   ├── config.py                # pydantic-settings, env-prefixed NECROPSY_
│   ├── contracts/               # ── the plug-in seam, no business logic ──
│   │   ├── host.py              #    HostServices Protocol + capability flags
│   │   ├── events.py            #    event envelope shared with the pentest module
│   │   └── risk.py              #    RiskFactor / RiskScore / ActionProposal
│   ├── db/
│   │   ├── session.py           # engine, WAL, busy_timeout, session factory
│   │   ├── models/              # case, sample, artifact, job, finding, next_action, audit
│   │   └── repos/               # thin data access; keeps route handlers dumb
│   ├── schemas/                 # pydantic request/response models (the GUI contract)
│   ├── intake/                  # ── Phase 1 ──
│   │   ├── vault.py             # content-addressed encrypted sample store
│   │   ├── hashing.py           # sha256/sha1/md5 + TLSH (+ optional ssdeep)
│   │   ├── identify.py          # magic/mime, container format, arch, entropy
│   │   └── service.py           # ingest orchestration, dedupe, audit
│   ├── cases/service.py
│   ├── jobs/
│   │   ├── queue.py             # RQ queues: triage (fast) / heavy (Ghidra) / detonate
│   │   ├── registry.py          # job kind -> callable, params schema, idempotency key
│   │   └── tasks/               # one module per job kind
│   ├── analysis/                # ── Phase 2 ──
│   │   ├── rizin.py             # rzpipe pre-triage (shell-out)
│   │   ├── ghidra.py            # analyzeHeadless driver + scripts/
│   │   ├── yara_rules.py
│   │   └── pe.py                # LIEF/pefile
│   ├── sandbox/                 # ── Phase 3 ──
│   │   ├── targets/base.py      # DetonationTarget ABC — no localhost impl, ever
│   │   ├── targets/vmware.py    # vmrun snapshot→detonate→revert
│   │   ├── targets/remote.py    # x86 host over the wire (placeholder, same ABC)
│   │   └── collectors/          # sysmon, pcap
│   ├── attack/                  # ── Phase 4 ── sigma→elastic, technique rollups
│   ├── ai/                      # ── Phase 5 ── Claude API: summaries, YARA drafts
│   ├── api/
│   │   ├── router.py            # aggregate APIRouter the host mounts
│   │   ├── routes/              # cases, samples, jobs, findings, actions
│   │   └── ws.py                # Redis pub/sub -> WebSocket fan-out
│   ├── standalone/app.py        # dev/CI harness
│   └── cli.py                   # typer: serve, worker, case, ingest
└── tests/
```

### Why a separate SQLite file

Necropsy owns `necropsy.db`; it does **not** write to the pentest backend's database.

1. SQLite is single-writer. RQ workers writing job/finding rows during a Ghidra pass would
   contend with the pentest module's own writes and produce `database is locked` under the
   exact conditions (long analysis + live UI) you care about.
2. Independent Alembic history. Two modules sharing one migration chain is a fork by
   another name.
3. Droppable: `pip uninstall` leaves no orphan tables in the host schema.

The link between the two worlds is a nullable `Case.host_engagement_ref` string. When the
host has an engagements capability, the GUI can show "3 malware cases attached to this
engagement" without either side owning the other's schema. WAL mode + `busy_timeout=5000`
on our own DB regardless.

### Why RQ, and how workers reach the GUI

RQ over Redis, three queues (`triage`, `heavy`, `detonate`) so an 8-minute Ghidra pass
never starves an intake. `detonate` runs at concurrency 1 — the VM lab has one set of
snapshots.

Workers cannot hold WebSocket connections. The flow is:

```
worker → redis.publish("necropsy:case:{id}", event) → API process subscriber → WS fan-out → GUI panel
```

This is worth building in Phase 1 with a single event type, because it's the difference
between a live sandbox timeline in Phase 3 and a polling rewrite.

---

## 5. Host-agnostic detonation (the Apple Silicon problem)

M5 Pro + VMware Fusion means Windows-on-ARM. Most samples are x86 and will either fail
under Windows' x86 emulation or behave unrepresentatively — and, importantly, a sample
that *detects* emulation and goes dormant looks identical to a benign sample in your
telemetry. That's an analysis-correctness problem, not just a compatibility one.

The architecture does not solve this in Phase 1; it just refuses to foreclose it:

```python
class DetonationTarget(ABC):
    caps: TargetCapabilities   # arch={x86,x64,arm64}, os, has_sysmon, egress_policy
    async def snapshot_restore(self, name: str) -> None: ...
    async def push(self, local: Path, guest: PurePath) -> None: ...
    async def execute(self, guest: PurePath, args, timeout_s) -> ExecResult: ...
    async def collect(self, dest: Path) -> list[Artifact]: ...
    async def revert(self) -> None: ...
```

Rules that keep the later x86 host cheap:

- **There is no `LocalhostTarget`.** Not commented out — never written. The only way to
  execute a sample is through a target that is definitionally a separate machine.
- Sample `arch` is recorded at intake (Phase 1) and matched against `target.caps.arch`
  before a detonation proposal is even offered. A mismatch produces a *warning finding*
  ("x86 sample on ARM64 target — emulation artefacts likely, dormancy is not evidence of
  benignity"), which is exactly the ATT&CK T1497 confusion you want surfaced, not hidden.
- Transport is abstracted from the start: `vmware.py` uses `vmrun` locally, `remote.py`
  is the same ABC over a network transport. Adding an Intel NUC or a cloud x86 VM later
  is one class, not a rewrite.
- Detonation results carry `target_fingerprint` so you can tell later which findings came
  from an emulated run.

---

## 6. Integration points that must not be duplicated

- **Elastic SIEM** — the lab's existing Basic-tier cluster is the telemetry sink. Necropsy
  ships Sysmon/Zeek data to it via the in-guest Elastic Agent and *queries it back* for
  correlation. It does not stand up its own logging stack, and does not store raw event
  volume in SQLite — only derived `Finding` rows plus the query that produced them, so a
  finding is always re-verifiable in Kibana.
- **pySigma** — Sigma rules compile to Elastic queries at runtime. Rules live in
  `attack/sigma/`, sourced from the public Sysmon-to-ATT&CK corpora rather than authored
  from zero.
- **The red/blue agent lab** — Necropsy detonates into it and reads its telemetry. The
  red-team agent stays out of this platform entirely; conflating "analyse this sample" with
  "an agent that acts" is the line in SAFETY.md.

## 7. Licensing notes that shape dependency choices

Your Nmap instinct generalises. Treat anything GPL as a subprocess, never a linked import,
so a future distributable stays clean:

| Component | Licence | Treatment |
|---|---|---|
| Ghidra | Apache-2.0 | Safe to automate/bundle; driven via `analyzeHeadless` anyway |
| YARA / yara-python | BSD-3-Clause | Import freely |
| LIEF | Apache-2.0 | Import freely |
| pefile | MIT | Import freely |
| TLSH | Apache-2.0 | **Primary fuzzy hash** |
| ssdeep / libfuzzy | GPL-2.0 (verify) | Optional, shell-out to the `ssdeep` binary — not the Python bindings |
| rizin / radare2 | LGPL-3.0 | Shell-out via `rzpipe` / `r2pipe` |
| Nmap | GPL-2.0 (w/ NPSL terms) | Subprocess only, as you already do |
| Sysmon | Microsoft EULA | **Not redistributable** — operator installs in-guest |
| Elastic Basic | Elastic Licence 2.0 | Free for internal use, not OSS; external service |

One correction worth making before it reaches `pyproject.toml`: `r2pipe` is radare2's
binding, `rzpipe` is rizin's. Pick one fork. Recommendation: **rizin + rzpipe** — cleaner
API surface, and its analysis JSON is more stable across versions, which matters when
you're parsing it as a pre-triage gate. Either way it's a subprocess, so the choice is
reversible.
