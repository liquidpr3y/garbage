# Phase 4 — ATT&CK mapping layer and technique heatmap

**Goal:** everything the previous phases produced, laid out on the ATT&CK matrix per case;
Sigma rules run against detonation telemetry; findings mirrored back into Elastic so a
hunter can pivot in Kibana.

**Status: built.** 250 tests pass with no Elastic and no lab; 264 with a live
Elasticsearch. The Sigma queries, the ECS mapping and the findings mirror were all
verified against a real Elasticsearch 8.15.3 — for reasons §3 makes concrete.

---

## 1. The taxonomy is real, bundled, and current

`attack/data/enterprise.json` (187 KB) is generated from MITRE's `enterprise-attack` STIX
release: **697 techniques, 15 tactics, ATT&CK v19.2**, plus 149 revocation mappings and,
per technique, the log sources and Sysmon event codes MITRE associates with detecting it.
Bundled rather than fetched, so analysis never depends on network access. Attribution is
in `attack/data/ATTRIBUTION.md`.

Two things fell out of using the real data that would not have surfaced from a hand-written
mapping table:

**ATT&CK v19 renamed TA0005 "Defense Evasion" to "Stealth"** and added TA0112 "Defense
Impairment". Every Sigma rule, blog post and existing mapping in the world still says
`defense-evasion`, so the catalogue aliases the old name onto the new tactic.

**ATT&CK v19 revoked the entire T1562 "Impair Defenses" family** — T1562.001 became T1685,
T1562.004 became T1686, and so on. Necropsy's own Phase 2/3 code was emitting `T1562.001`,
which as of v19 resolves to nothing; a test now fails the build if any producer emits a
revoked ID. For *other people's* rules — SigmaHQ is full of `attack.t1562.001` — the
catalogue follows the revocation chain so those rules still land on the matrix instead of
rendering as unknown.

## 2. The heatmap makes one distinction above all others

A cell is `observed`, `observed_emulated`, or `inferred`, and carries the caveat in words:

| Grade | Meaning | Caveat shown |
|---|---|---|
| `observed` | Seen in a native-fidelity detonation | none |
| `observed_emulated` | Seen, but only under architecture emulation | "the run's negative space proves nothing" |
| `inferred` | Static analysis only | "the sample is equipped to do this. Not evidence that it did." |

A heatmap that renders a decompiled import table the same colour as an observed registry
write flattens the most important distinction in the case. One solid run clears an earlier
emulation caveat; nothing downgrades a solid observation.

Sub-techniques roll into their parent so the matrix stays readable, with the specific IDs
kept on the cell. Techniques appear in every tactic they belong to (process injection is
both Stealth and Privilege Escalation), and the kill chain view picks each technique's
*earliest* tactic so a sample does not appear to skip stages it passed through.

The Cyber Kill Chain view ships alongside, with an explicit note that ATT&CK tactics and
the kill chain are different models and this mapping is a presentation convenience, not a
MITRE-published equivalence.

## 3. Detection gaps: turning "we saw nothing" into a work item

For every technique in a case that was *not* observed, MITRE names the Sysmon event codes
that detect it. Comparing that against what the lab actually collects produces:

```
Detection gaps (Sysmon events this lab does not collect)
  T1055       Process Injection                        missing 10

! 1 technique(s) in this case need Sysmon events the lab does not collect (10).
  Absence of behavioural evidence for those is a visibility gap, not a negative result.
```

Sysmon event 10 is ProcessAccess, and Necropsy's query set does not include it. That is a
concrete Sysmon configuration change, derived from MITRE's own detection data rather than
from anyone's opinion. Gaps are suppressed for techniques the sandbox caught anyway — if
you saw it, the missing log source is academic.

## 4. Sigma, and the silent-zero problem

Sigma rules carry `attack.tXXXX` tags, so a hit becomes a technique-tagged finding with no
mapping table of ours. Eight rules ship packaged; point `NECROPSY_SIGMA_RULE_PATHS` at a
SigmaHQ checkout for the corpus. Each file compiles independently, so one malformed rule
costs that file.

The engineering that matters is field translation. SigmaHQ rules are written against
Sysmon field names (`TargetObject`, `Image`); the lab's telemetry is ECS
(`registry.path`, `process.executable`). pySigma's sysmon + ecs_windows pipelines do that,
and running against a real cluster surfaced two failures a test double would have accepted:

- **`.caseless` multi-fields.** pySigma maps `Image` to `process.executable.caseless`, a
  multi-field the *winlogbeat* ECS module defines and a modern Elastic Agent integration
  may not. A Lucene query naming an absent field matches nothing and raises nothing.
  Necropsy probes the index and strips the suffix when it is absent — and says so,
  including the consequence: matching becomes case-sensitive, so a rule keyed on
  `\winword.exe` will miss a process logged as `WINWORD.EXE`.
- **text vs keyword mappings.** `process.executable:*\\vssadmin.exe` matches on a `keyword`
  field and silently returns zero on a `text` one.

Neither can be fixed automatically in general, so the sweep refuses to call a null result
clean: **if no rule fired but the window contained events, the run is marked
`inconclusive`** with a note naming the likely cause. Same principle as the Phase 3
detonation verdict — never report blindness as absence.

## 5. The findings mirror

`ElasticFindingSink` writes findings into a `necropsy-findings-*` data stream as ECS, with
its own index template. SQLite stays the system of record: every write is best-effort, a
failure leaves `mirrored_at` null, and `necropsy reindex` retries. A SIEM outage costs the
mirror, never the finding.

One correctness fix landed here: `threat.tactic.name` had been carrying our kill chain
phase. ECS `threat.*` is ATT&CK's namespace, so it now carries real ATT&CK tactic names and
TA-IDs resolved from the technique, with the kill chain phase moved to
`necropsy.kill_chain_phase`. The wrong version looked right and would have broken every
Kibana ATT&CK view reading that field. Verified live: pivots by
`threat.technique.id`, `threat.tactic.name` and `necropsy.case_id` all work.

## 6. Regenerating the ATT&CK data

```bash
curl -sSL -o /tmp/attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python tools/build_attack_catalogue.py /tmp/attack.json src/necropsy/attack/data/enterprise.json
pytest tests/test_attack_catalogue.py
```

The test suite fails if any producer emits a technique ID the new release revoked, which
is the intended way to find out that a bump changed something underneath you.

## 7. What Phase 5 inherits

- Findings across four producers, all ATT&CK-tagged, with evidence grades — the input an
  AI summary should be reasoning over, rather than raw strings.
- `Case.ai_disclosure_allowed`, enforced at the point of decision since Phase 1.
- `functions` rows with a per-function `ai_summary` column already waiting.
- The heatmap and detection gaps give a report generator something to say beyond a list of
  findings: what was observed, what was only inferred, and what the lab could not have seen.

## 8. What is not verified here

- **A real SigmaHQ corpus.** The packaged eight rules are ours. Pointing at a few thousand
  community rules will surface rules whose logsource categories the pipeline does not map;
  those appear as per-file compile errors rather than silent misses, but the first run
  against a real corpus deserves a look at `necropsy doctor`.
- **The lab's actual ECS field shapes.** The queries are verified against ECS-shaped
  mappings; whether your Elastic Agent integration provides `.caseless`, and how it maps
  `host.name`, is checked at runtime rather than assumed — but worth confirming once.
