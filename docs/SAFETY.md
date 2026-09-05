# Handling invariants and scope boundary

## Scope: analysis, not weaponisation

This platform observes and explains malware that already exists. It does not create,
modify, obfuscate, pack, or improve it, and it does not test payloads against defences to
find what evades them.

Everything currently on the roadmap sits on the analysis side of that line, including the
Phase 5 auto-drafted YARA rules — those are *detection content* derived from observed
sample behaviour, which is the defensive output of the pipeline.

Requests that would cross the line, so they're recognisable if they come up later:

| On the roadmap (fine) | Would cross the line |
|---|---|
| Unpack a sample to read its real code | Repack a sample to change its signature |
| Draft a YARA rule from observed traits | Iterate a sample until the YARA rule stops firing |
| Detonate an existing sample in an isolated VM | Generate a new payload to detonate |
| Summarise a decompiled C2 routine | Produce working C2 client/server code from it |
| Map behaviour to ATT&CK techniques | Build tooling that executes those techniques |

The red-team agent in the VMware lab is a separate system with its own authorisation; it
is deliberately not integrated into this platform, and Necropsy exposes no interface it
could drive.

## Execution invariants

1. **A sample is never executed on the host Mac.** Enforced structurally: there is no
   `LocalhostTarget` implementation of `DetonationTarget` and none may be added. Execution
   is only reachable through a target that is definitionally a separate machine.
2. **Nothing detonates without a human accepting a `NextAction`.** No auto-escalation from
   static triage to dynamic analysis, regardless of score.
3. **Vault objects are stored encrypted, `0o400`, never with an executable bit or the
   original extension.** Decryption happens only into an analysis job's scratch dir or a
   detonation target, and is always deleted in a `finally`.
4. **Every vault read writes an audit event.** Chain of custody is not optional.
5. **Detonation defaults to no egress.** Egress-permitted runs are a separate, higher-risk
   proposal with the attribution consequence stated in its `rationale` — your lab IP is
   attributable, and live C2 contact tells the operator you exist.
6. **`revert` runs in a `finally`.** A failed detonation must never leave a dirty snapshot
   that the next sample inherits.
7. **One detonation at a time.** The lab has one set of snapshots, so a filesystem lock
   holds them for the whole run. Two samples sharing them would cross-contaminate
   telemetry and a mid-run revert would destroy both.
8. **A failed run still leaves a record.** The detonation row is committed before the run
   and its failure committed before the error propagates. A run that pushed a live sample
   into a guest must be in the record whatever happened next.
9. **Egress is never silently downgraded.** Asking for a live-network run when no egress
   snapshot is configured is an error, not an isolated run — an operator who expected C2
   contact would read the resulting silence as the sample doing nothing.

These are enforced by `tests/test_sandbox_safety.py`, which fails the build if a
host-executing target appears, if `revert()` leaves the `finally`, or if the guest
password becomes loggable.

## Repository hygiene

`liquidpr3y/garbage` is currently **public**. Regardless of visibility:

- **No samples, ever** — not as test fixtures, not zipped, not base64'd. Test fixtures are
  synthesised benign binaries or EICAR.
- **No lab topology** — no VM names, IPs, hostnames, Elastic URLs, index names, API keys,
  or snapshot names in tracked files. All of it lives in `.env`, which is gitignored;
  `.env.example` carries placeholders only.
- **No client or engagement data** in case names used as examples.
- `.gitignore` blocks `*.bin *.exe *.dll *.dmg *.vmdk vault/ samples/ .env ghidra_projects/`
  as a backstop, not as the primary control.

Consider making the repo private before Phase 3, when lab-shaped configuration and Sigma
tuning start landing.
