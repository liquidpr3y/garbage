# Phase 1 — Cases data model + intake

**Goal:** an operator can create a case, submit a sample, and see it appear in a new GUI
panel with hashes, identified file type, and a first set of risk-scored next actions —
with the sample stored safely and a complete audit trail. No disassembly, no detonation.

**Deliberately deferred:** Ghidra, rizin, YARA, sandbox, ATT&CK mapping, Claude API.
Phase 1 exists to make Phases 2–5 additive rather than structural.

**Status: built.** Implemented on `claude/malware-analysis-platform-vopeqt`; 77 tests pass
with no network, no Redis and no lab. Section 6 records what was verified, and section 7
the places the build departed from this plan.

---

## 1. Data model

Seven tables. SQLAlchemy 2.0 declarative, Alembic with `render_as_batch=True`.

### `cases`
| column | type | notes |
|---|---|---|
| `id` | uuid pk | |
| `name` | str | |
| `status` | enum | `open` / `analysing` / `contained` / `closed` |
| `severity` | enum | `info`/`low`/`medium`/`high`/`critical`, operator-set, overridable by findings |
| `summary` | text | AI-written from Phase 5 |
| `tags` | json list | |
| `host_engagement_ref` | str, null | link to a pentest-module engagement, if any |
| `ai_disclosure_allowed` | bool, default **false** | gate for Phase 5 — see §5 |
| `created_at` / `updated_at` | ts | |

### `samples` — global, content-addressed, deduped across cases
`id` (uuid), `sha256` (unique idx), `sha1`, `md5`, `tlsh`, `ssdeep` (null), `size`,
`mime`, `magic`, `file_type` (enum: `pe`/`elf`/`macho`/`office`/`script`/`archive`/`pdf`/`unknown`),
`arch` (enum: `x86`/`x86_64`/`arm64`/`unknown` — **feeds Phase 3 target matching**),
`entropy`, `storage_state` (enum: `vaulted`/`quarantined`/`purged`), `vault_uri`,
`first_seen_at`.

### `case_samples` — join, carries per-case observation context
`case_id`, `sample_id`, `observed_filename`, `source` (enum: `upload`/`path`/`url`/`sandbox_drop`),
`submitted_by`, `note`, `added_at`. Unique on `(case_id, sample_id)`.

> The split matters: the same sample seen in two cases is one vault object and one hash
> record, but two observation contexts. Collapsing these means re-storing samples and
> losing cross-case pivots — which is the whole point of TLSH clustering in Phase 2.

### `artifacts` — anything *derived* (unpacked blobs, PCAP, memdump, Ghidra project, screenshots)
`id`, `sample_id`, `job_id`, `kind`, `sha256`, `vault_uri`, `size`, `meta` json, `created_at`.
Same vault, same rules. Present in Phase 1 with no producers yet; Phase 2/3 fill it.

### `analysis_jobs`
`id`, `case_id`, `sample_id`, `kind` (enum, Phase 1 ships only `identify`), `state`
(`queued`/`running`/`succeeded`/`failed`/`cancelled`), `rq_job_id`, `params` json,
`idempotency_key` (unique — `sha256(case_id + sample_sha256 + kind + canonical(params))`),
`result_summary` json, `error`, `queued_at`/`started_at`/`finished_at`, `worker`.

> The key is scoped to the case as well as the bytes. That was a correction made during the
> build: keyed on bytes alone, the same sample arriving in a second case reused the first
> case's completed job and the second case got no findings at all. Cross-case reuse of
> *expensive derived output* (a Ghidra decompilation of identical bytes) belongs in the
> artifacts table keyed by sha256, not in suppressing the job that produces the findings.

### `findings`
`id`, `case_id`, `sample_id` (null), `job_id` (null), `producer`, `type`, `title`,
`description`, `severity`, `confidence` (float 0–1), **`attack_technique_ids` json list**,
**`kill_chain_phase`** (enum: recon/weaponisation/delivery/exploitation/installation/c2/actions),
`evidence` json, `dedupe_key` (unique per case), `created_at`,
`elastic_doc_id` (null), `mirrored_at` (null).

The two `elastic_*` columns support the decided bidirectional Elastic design: findings are
mirrored into a `necropsy-findings-*` ECS data stream so they're pivotable in Kibana next to
raw lab telemetry. Phase 1 only ships the `FindingSink` interface with a `NullSink` default
— SQLite stays the system of record, the mirror is best-effort and replayable, and CI never
needs a cluster. The columns exist now so Phase 4 is a new sink implementation plus a
`necropsy reindex` backfill, not a migration against live case data.

Phase 1 emits a handful: `pe_no_signature`, `high_entropy`, `arch_mismatch_risk`,
`known_sample_reappearance` (sample already seen in another case). Enough to prove the
pipeline end to end. The ATT&CK columns stay null until Phase 4 — **but they exist now.**

### `next_actions`
`id`, `case_id`, `origin_job_id`, `kind`, `title`, `rationale`, `risk_score` (0–10),
`risk_factors` json list, `estimated_cost_s`, `params` json, `state`
(`proposed`/`accepted`/`rejected`/`executed`/`expired`), `decided_by`, `decided_at`.

### `audit_events` — append-only, no update/delete path in the repo layer
`id`, `case_id`, `actor`, `action`, `object_type`, `object_id`, `detail` json, `at`.
Written for: case create/close, sample ingest, vault read, action accept/reject, job launch,
export. This is chain of custody; treat it as evidentiary from day one because
retrofitting it later means the early cases have none.

---

## 2. The vault (`intake/vault.py`)

The one piece of Phase 1 that is genuinely easy to get wrong on macOS.

**Layout:** `{vault_root}/{sha256[0:2]}/{sha256[2:4]}/{sha256}.bin`

**Rules:**
1. Written mode `0o400`, owned by the running user. Never `+x`, never the original extension.
2. **Encrypted at rest** (AES-GCM, key from Keychain or `NECROPSY_VAULT_KEY`). This is not
   about confidentiality — it is because XProtect/Gatekeeper on Apple Silicon will happily
   quarantine or delete a recognised sample out from under you, and a corrupted case is
   worse than a locked one. Encryption also stops accidental double-click execution and
   keeps Spotlight out. Decryption happens only into a `DetonationTarget` (Phase 3) or a
   temp file inside an analysis job's own scratch dir, deleted in a `finally`.
3. Vault root defaults to `~/.necropsy/vault`, **and the installer should exclude it from
   Time Machine and Spotlight** (`tmutil addexclusion`, `.metadata_never_index`). Document
   this; don't silently do it.
4. `vault.read()` writes an `audit_event`. Every time.
5. Alternative if encryption proves annoying in dev: password-protected ZIP with the
   industry-standard `infected` password. Weaker, but survives XProtect and is portable to
   other analysts. Pick one in Phase 1; don't support both.

---

## 3. Files to create

```
pyproject.toml                              deps + entry point + ruff/pytest
.gitignore                                  samples, vault, *.bin/exe/dll/dmg, .env, ghidra_projects
.env.example                                placeholders only — no lab values
alembic.ini
migrations/env.py + versions/0001_initial.py

src/necropsy/__init__.py
src/necropsy/plugin.py                      MODULE descriptor: slug, router, mount(), migration head
src/necropsy/config.py                      pydantic-settings, NECROPSY_ prefix
src/necropsy/enums.py                       vocabulary shared by models and schemas
src/necropsy/runtime.py                     per-process host handle (RQ cannot serialise one)

src/necropsy/contracts/host.py              HostServices Protocol + capability flags
src/necropsy/contracts/events.py            Event envelope: {type, case_id, at, payload}
src/necropsy/contracts/risk.py              RiskFactor, RiskScore, ActionProposal

src/necropsy/db/session.py                  engine, WAL, busy_timeout, sessionmaker
src/necropsy/db/models/__init__.py          + case.py sample.py artifact.py job.py
                                              finding.py next_action.py audit.py
src/necropsy/db/repos/cases.py              CRUD + list filters
src/necropsy/db/repos/samples.py            get_or_create_by_sha256, cross-case lookup
src/necropsy/db/repos/jobs.py               idempotent enqueue-or-return
src/necropsy/db/repos/findings.py           upsert on dedupe_key
src/necropsy/db/repos/actions.py
src/necropsy/db/repos/audit.py              append-only

src/necropsy/schemas/case.py sample.py job.py finding.py action.py   pydantic I/O
src/necropsy/intake/hashing.py              sha256/sha1/md5 streaming + TLSH
src/necropsy/intake/identify.py             magic/mime, file_type, arch (LIEF), entropy
src/necropsy/intake/vault.py                content-addressed encrypted store
src/necropsy/intake/service.py              ingest_file(): hash -> dedupe -> vault ->
                                              case_sample -> audit -> enqueue identify job

src/necropsy/cases/service.py               create/close, case timeline assembly
src/necropsy/sinks/base.py                  FindingSink protocol + NullSink default
                                              (Elastic impl lands in Phase 4)
src/necropsy/scoring/rules.py               Phase-1 risk scorer over RiskFactor vocabulary
src/necropsy/scoring/proposals.py           post-job proposal generation

src/necropsy/jobs/queue.py                  RQ worker bootstrap
src/necropsy/jobs/runner.py                 JobRunner: RQ in the lab, inline in CI/on a laptop
src/necropsy/jobs/registry.py               kind -> callable + params schema
src/necropsy/jobs/tasks/identify.py         Phase-1 job: deep identify, emit findings + proposals
src/necropsy/jobs/publish.py                worker-side redis.publish of case events

src/necropsy/api/router.py                  aggregate APIRouter
src/necropsy/api/routes/cases.py samples.py jobs.py findings.py actions.py
src/necropsy/api/ws.py                      pub/sub subscriber -> WS fan-out
src/necropsy/api/deps.py                    session + host services injection

src/necropsy/standalone/app.py              primary app for Phases 1-5
src/necropsy/standalone/host.py             StandaloneHost: local impl of every HostServices call
src/necropsy/cli.py                         typer: serve / worker / case new / ingest / reindex

tests/conftest.py                           tmp vault, tmp sqlite, fake host, synthetic PEs
tests/test_vault.py                         crypto round-trip, perms, tamper/truncation, audit
tests/test_intake.py                        dedupe across cases, re-vaulting, refusals
tests/test_identify.py                      PE/ELF/OOXML/LNK, arch, signature, entropy
tests/test_jobs.py                          pipeline end to end, findings, proposals, failure
tests/test_idempotency.py                   double-enqueue, case scoping, param canonicalisation
tests/test_api.py                           end-to-end through the router the GUI binds to
tests/test_mount.py                         the sidecar-to-mounted seam stays honest
tests/test_risk.py                          shared risk vocabulary
tests/test_migrations.py                    Alembic and the models do not drift
tests/test_degraded.py                      full pipeline with no native optional deps
```

## 4. API surface (what the GUI panel binds to)

```
POST   /cases                          create
GET    /cases?status=&tag=             list
GET    /cases/{id}                     detail + counts
GET    /cases/{id}/timeline            merged jobs+findings+actions+audit, time-ordered
POST   /cases/{id}/samples             multipart upload OR {path: "..."} → ingest
GET    /cases/{id}/samples
GET    /samples/{sha256}               incl. other_cases[] for cross-case pivot
GET    /cases/{id}/findings
GET    /cases/{id}/actions             proposals awaiting a human
POST   /actions/{id}/accept            → enqueues the job; records decided_by
POST   /actions/{id}/reject            {reason}
GET    /jobs/{id}
WS     /ws/cases/{id}                  {job.*, finding.created, action.proposed} events
```

Upload cap and streaming-to-vault (never buffer a sample fully in memory), plus a
`X-Necropsy-Confirm-Malware: true` header requirement on ingest — a small friction that
makes accidental ingest of the wrong file harder.

## 5. Two flags worth setting now, not later

- **`Case.ai_disclosure_allowed`** (default false, confirmed). Phase 5 sends decompiled functions and
  strings to the Claude API. Some samples will come from client engagements where that is
  a contractual problem. A per-case boolean checked at the top of every `ai/` call, set
  once at case creation, is trivial now and awkward to retrofit after the AI layer exists.
- **`Sample.arch`** at intake. It's the input to Phase 3's target-capability matching and
  to the "x86 sample on an ARM64 target" warning. Costs one LIEF call now.

## 6. Acceptance criteria — verified

| # | Criterion | Status |
|---|---|---|
| 1 | `necropsy serve` / `necropsy worker` run with no host app present | **met** — server boots, `/health` and the full OpenAPI surface respond; the mount seam is covered by `test_mount.py` rather than left theoretical |
| 2 | `necropsy ingest` stores encrypted at `0o400`, dedupes, audits both | **met** — `test_vault.py`, `test_intake.py` |
| 3 | Same sample in a second case → one vault object, two `case_samples`, a reappearance finding | **met** — `test_intake.py::test_same_sample_in_two_cases_is_one_vault_object`, `test_jobs.py::test_second_case_gets_a_reappearance_finding` |
| 4 | Identify job emits findings and ≥2 risk-scored proposals, streamed live | **met** — a packed x86 PE yields 3 findings and 6 proposals; `test_jobs.py::test_events_reach_subscribers` asserts the event stream |
| 5 | Accepting a proposal records `decided_by`/`decided_at` and enqueues its job | **met** — `test_api.py`; an accepted proposal also flips to `executed` once its job lands |
| 6 | `pytest` green with no network and no Redis | **met** — 77 tests, no broker, no lab; `test_degraded.py` additionally runs the whole pipeline with TLSH and libmagic removed |
| 7 | GUI panel lists cases and opens a timeline | **backend met** — `/cases` and `/cases/{id}/timeline` serve it; the Swift panel is yours to build against the schema |

Sample output from a live run against a synthetic packed x86 PE, which is the shape the
GUI panel renders:

```
FINDINGS
  [medium conf=0.95] arch_mismatch_risk    x86 sample, lab targets are arm64
  [low    conf=0.9 ] pe_no_signature       PE has no Authenticode signature
  [medium conf=0.6 ] high_entropy          High entropy (7.85) -- likely packed or encrypted

NEXT ACTIONS (operator decides; nothing runs on its own)
  risk 10.0 severe    detonate          Detonate in sandbox (egress permitted)   [Phase 3]
          +1.2 Packed or encrypted contents (high entropy)
          +0.5 No Authenticode signature
          +3.0 Live network egress: C2 contact is attributable to your lab
          +1.5 x86 sample against arm64 target: emulated execution, dormancy is
               not evidence of benignity
  risk  7.2 high      detonate          Detonate in sandbox (isolated)           [Phase 3]
  risk  5.7 moderate  ai_summarise      AI summary of decompiled functions       [Phase 5]
  risk  2.7 low       static_triage     Static triage (rizin, PE parsing, YARA)  [Phase 2]
  risk  2.7 low       ghidra_decompile  Full Ghidra decompile pass               [Phase 2]
  risk  0.3 minimal   hash_pivot        Pivot on hashes across all cases
```

---

## 7. Where the build departed from this plan

1. **Idempotency is case-scoped.** See the note in §1 — keyed on bytes alone, a second case
   silently received no analysis.
2. **`jobs/runner.py` was added.** A `JobRunner` seam (RQ in the lab, inline in CI or on a
   laptop with no Redis) instead of calling RQ directly. Submission happens *after* the
   caller commits, because a worker opening its own session cannot see an uncommitted row.
3. **`runtime.py` was added.** RQ serialises job arguments, so a worker cannot be handed a
   live `HostServices`; each process establishes its host once and tasks resolve it there.
4. **Identification moved out of ingest into the job.** Ingest only hashes, vaults, attaches
   and audits. Everything analytical happens in the identify job, which reads back *out of
   the vault* — so the vault read path and its audit trail are exercised on every sample
   rather than first being tried in Phase 3.
5. **`hash_pivot` was added as a second implemented job kind.** Cross-case exact and TLSH
   matching. It made criterion 5 testable against real work rather than a stub, and it is
   genuinely the cheapest useful thing to run after intake.
6. **Policy is checked before capability.** Accepting `ai_summarise` on a case without
   disclosure consent returns 403, not "not implemented until Phase 5" — the policy answer
   will not change when Phase 5 lands, and the other ordering would send an operator away
   expecting it to work later.
7. **Vault encryption is chunked AES-GCM, not one-shot.** A 512MB installer must not have to
   fit in memory. Each chunk is authenticated with its index, and a terminator chunk makes
   truncation detectable — so XProtect half-eating a vault object is an error, not silent
   corruption.
8. **Optional native deps degrade rather than gate.** Architecture and Authenticode presence
   are parsed by ~150 lines of our own PE/ELF/Mach-O code, because those two answers drive
   Phase 3 target matching and a real finding. libmagic and LIEF add description on top;
   TLSH and ssdeep are optional. `necropsy doctor` reports what an install can actually do.
