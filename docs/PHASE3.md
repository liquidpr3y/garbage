# Phase 3 — Dynamic sandbox

**Goal:** an operator accepts a risk-scored detonation proposal and gets an observed run —
snapshot revert, detonate, telemetry, revert — with Sysmon read back from the lab's
existing Elastic cluster, packets captured host-side, and behaviours mapped to ATT&CK.

**Status: built.** 198 tests pass with no VMware, no Elastic and no lab; 204 with
Elasticsearch and Ghidra available. The Elastic query DSL was verified against a real
Elasticsearch 8.15.3, not a test double — for reasons in §5.

---

## 1. The invariant, restated in code

There is no way to execute a sample on the host. `DetonationTarget` has no localhost
implementation, and `tests/test_sandbox_safety.py` walks the AST of every module in
`sandbox/` and fails the build if a class name suggests one appears. A second test asserts
that any module using `subprocess` invokes only a known lab-control tool (`vmrun`,
`tcpdump`) — the sample reaches a subprocess only as an *argument* to a tool that copies
it into a guest.

Four more invariants are enforced rather than documented:

| Invariant | How it is enforced |
|---|---|
| `revert()` runs on every path | A test parses the AST of `detonate.run` and asserts `revert` appears in a `finally` body |
| `revert()` never raises | Teardown must not mask the real error; tested with a target that throws on every command |
| One detonation at a time | `fcntl.flock` on a lock file, not just RQ's queue concurrency — an inline run or a second worker would bypass the queue |
| The guest password never reaches a log | `_redact()` on argv, tested |

## 2. Nothing detonates without a named human

Detonation is reachable only by accepting a proposal. That is why there is no
`necropsy detonate` command: the acceptance row (`decided_by`, `decided_at`, the risk
score and factors the operator saw) is the record that a person authorised running live
malware, and a direct command would bypass it. The CLI gets `necropsy actions` and
`necropsy accept` instead, which route through the same `necropsy/actions/service.py` the
API uses — one implementation of the policy, so the CLI cannot reach a laxer version.

Accepting also re-checks *live* whether this install can actually run the job. A proposal
written before Ghidra was installed becomes acceptable once it is; a detonation proposal
on a machine with no sandbox is refused with the setting to fix, rather than enqueueing a
job that fails.

## 3. Egress is never silently downgraded

VMware networking is host-level configuration, not something `vmrun` can flip per run. A
tool that claimed to control it and quietly failed would produce an isolated run reported
as an egress run — and the operator would read the silence as the sample not calling home.

So an egress run requires its own configured snapshot (`NECROPSY_SANDBOX_SNAPSHOT_EGRESS`)
whose VM sits on a network that genuinely has egress. Asking for egress without one raises
`EgressUnavailable`. Refusing is the honest failure.

## 4. The verdict is the product, not the event list

`sandbox/behaviour.py` maps Sysmon telemetry to behaviours — autorun persistence, service
creation, remote-thread injection, LOLBin proxying, recovery destruction, defence
tampering, staging writes, network activity — each carrying ATT&CK techniques at *higher*
confidence than their static counterparts, because doing a thing is a stronger claim than
being able to do it.

But the most important output is `readable`, and it can be false:

> **INCONCLUSIVE:** only 2 events. This sample ran under architecture emulation, where
> failing to start and choosing not to act look identical. Do not record this as benign —
> re-run it on a native target before drawing any conclusion.

This is the ARM decision arriving where it actually bites. Booting Windows and launching a
process generates telemetry on its own, so a near-empty window means the sample never
really ran. On an emulated pairing that is the *expected* outcome, and reporting it as a
clean run would be the single worst thing this pipeline could say. The verdict distinguishes
four cases: busy with behaviours, busy without (readable, sample may be waiting on a
trigger), quiet under emulation (inconclusive, re-run natively), and quiet on a native
target (sandbox detection, missing trigger, or failed launch — check the screenshot).

Every finding carries the `fidelity` of the run that produced it, and the `detonations`
row stores target, arch, snapshot and egress. Six months later "the sample did nothing" is
only interpretable if you know what it ran on.

## 5. Telemetry: reading, and knowing when you cannot see

The guest ships Sysmon through the Elastic Agent that is already in the lab; Necropsy
queries it back. No parallel logging stack, no EVTX parsing — normalisation happens once,
in Elastic.

**Why this was verified against a real cluster.** A `term` query against a `text`-mapped
field matches nothing and raises nothing. Against ES 8.15.3 the failure is silent and
total: zero hits, no error, which in this pipeline reads as "the sample did nothing". The
Elastic Agent integration maps `host.name` as `keyword` so a plain `term` is correct
there — but a hand-rolled or dynamically-mapped index is not. `host_filter()` therefore
matches `term`, `.keyword` and `match_phrase` across four host fields. A test double would
have accepted the broken version happily.

When the host-filtered query returns nothing, a **coverage probe** runs the same window
with no host filter:

- Other hosts reporting → *the filter is wrong, not the sample.* The run is reported as
  uncollected, naming `NECROPSY_SANDBOX_GUEST_HOSTNAME` as the thing to fix.
- Nothing at all → the Agent or Sysmon is not running, or the index pattern is wrong.
  Also uncollected, not quiet.

The probe samples documents rather than aggregating on `host.name`, because aggregation
needs fielddata and text mappings refuse it — a probe that errors on the exact case it
exists to diagnose is no probe at all. (Found by running it.)

## 6. Packet capture, host-side

`tcpdump` on a host-only vmnet, so the sample can neither see nor suppress the capture.
The parser is ~200 lines of pure Python over classic pcap and pulls out what triage
actually reads: conversations, contacted IPs, DNS query names and **TLS SNI**. SNI is
worth the 30 lines because for most modern C2 it is the only readable destination name in
an otherwise encrypted flow. Ethernet, VLAN-tagged, raw-IP and Linux SLL link types are
handled, both endiannesses, and a truncated trailing packet is flagged rather than thrown.

## 7. What Phase 4 inherits

- `Finding` rows now arrive from three producers (static, decompilation, sandbox), all
  ATT&CK-tagged, all in one table. The heatmap is a `GROUP BY`.
- `Detonation` rows carry the fidelity caveat, so the heatmap can distinguish a technique
  observed natively from one inferred from an emulated run.
- `ElasticClient.bulk_index()` and `ensure_index_template()` already exist and are tested
  against a live cluster; the Phase 4 finding mirror is a `FindingSink` implementation over
  them plus the ECS mapping already written in `sinks/base.py`.
- pySigma is still to come. The behavioural rules in `sandbox/behaviour.py` are hand-written
  and deliberately few; Phase 4 should source the bulk from the public Sysmon-to-ATT&CK
  Sigma corpora rather than growing that table by hand.

## 8. What is not verified here

- **VMware Fusion.** No Fusion in CI, ever. The target is driven through a stub `vmrun`
  that records argv, which covers command construction, ordering, the boot wait, teardown
  and redaction — everything that is ours. Fusion's own behaviour, and the guest having
  VMware Tools and Sysmon, need one live run on the analysis Mac before this is trusted
  with a real sample.
- **The Elastic Agent's exact field shapes** for your integration version. The queries are
  verified; the assumption that your pipeline emits `event.code` as a string and
  `host.name` matching `NECROPSY_SANDBOX_GUEST_HOSTNAME` is worth one check. Both
  flattened and nested ECS documents are handled.
- **rizin**, still stub-tested from Phase 2.
