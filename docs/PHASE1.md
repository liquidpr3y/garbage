# Phase 1 — Cases data model + intake

**Goal:** an operator can create a case, submit a sample, and see it appear in a new GUI
panel with hashes, identified file type, and a first set of risk-scored next actions —
with the sample stored safely and a complete audit trail. No disassembly, no detonation.

**Deliberately deferred:** Ghidra, rizin, YARA, sandbox, ATT&CK mapping, Claude API.
Phase 1 exists to make Phases 2–5 additive rather than structural.

**Rough size:** ~1,400 lines across ~30 files. Two sittings.

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
`idempotency_key` (unique — `sha256(sample_sha256 + kind + canonical(params))`),
`result_summary` json, `error`, `queued_at`/`started_at`/`finished_at`, `worker`.

### `findings`
`id`, `case_id`, `sample_id` (null), `job_id` (null), `producer`, `type`, `title`,
`description`, `severity`, `confidence` (float 0–1), **`attack_technique_ids` json list**,
**`kill_chain_phase`** (enum: recon/weaponisation/delivery/exploitation/installation/c2/actions),
`evidence` json, `dedupe_key` (unique per case), `created_at`.

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
src/necropsy/scoring/rules.py               Phase-1 risk scorer over RiskFactor vocabulary
src/necropsy/scoring/proposals.py           post-job proposal generation

src/necropsy/jobs/queue.py                  RQ queues triage/heavy/detonate
src/necropsy/jobs/registry.py               kind -> callable + params schema
src/necropsy/jobs/tasks/identify.py         Phase-1 job: deep identify, emit findings + proposals
src/necropsy/jobs/publish.py                worker-side redis.publish of case events

src/necropsy/api/router.py                  aggregate APIRouter
src/necropsy/api/routes/cases.py samples.py jobs.py findings.py actions.py
src/necropsy/api/ws.py                      pub/sub subscriber -> WS fan-out
src/necropsy/api/deps.py                    session + host services injection

src/necropsy/standalone/app.py              dev harness w/ StandaloneHost
src/necropsy/cli.py                         typer: serve / worker / case new / ingest

tests/conftest.py                           tmp vault, in-memory-ish sqlite, fake host
tests/test_vault.py                         round-trip, perms, no-exec-bit, audit on read
tests/test_intake.py                        dedupe across cases, hash correctness
tests/test_idempotency.py                   double-enqueue returns one job
tests/test_api_cases.py                     end-to-end ingest via TestClient
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

- **`Case.ai_disclosure_allowed`** (default false). Phase 5 sends decompiled functions and
  strings to the Claude API. Some samples will come from client engagements where that is
  a contractual problem. A per-case boolean checked at the top of every `ai/` call, set
  once at case creation, is trivial now and awkward to retrofit after the AI layer exists.
- **`Sample.arch`** at intake. It's the input to Phase 3's target-capability matching and
  to the "x86 sample on an ARM64 target" warning. Costs one LIEF call now.

## 6. Acceptance criteria

1. `necropsy serve` + `necropsy worker` run standalone with no host app present.
2. `necropsy ingest --case <id> ./sample.bin` stores the sample encrypted at 0o400,
   dedupes on second ingest, and writes audit rows for both.
3. The same sample added to a second case produces one vault object, two `case_samples`,
   and a `known_sample_reappearance` finding on the second case.
4. The identify job emits at least one finding and at least two risk-scored `NextAction`
   proposals, and the WS stream delivers all of them live.
5. Accepting a proposal records `decided_by`/`decided_at` and enqueues its job.
6. `pytest` green with no network and no Redis (fakeredis) — CI must not need the lab.
7. The GUI panel lists cases and opens a case timeline against the standalone server.
