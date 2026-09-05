# Phase 6 — Merge into the single-pane GUI

**Goal:** Necropsy stops being a separate thing you run and becomes panels inside the
pentest GUI, sharing its window, its navigation and its risk vocabulary.

**Status: built, with one honest gap.** 299 Python tests pass with no external services (313 with Ghidra and Elasticsearch), and 27 Swift tests pass. The
mount seam, the module self-description, the GUI contract and the whole `NecropsyKit`
client are verified. The SwiftUI views are written and parse, but only Xcode type-checks
them — SwiftUI does not exist on Linux. See §6.

---

## 1. The merge is a config change, as designed

`examples/host_app.py` is the ~40 lines the pentest backend needs. It enumerates the
`pentestgui.modules` entry point group, hands each module a `HostServices`, and mounts its
router:

```python
for entry_point in importlib.metadata.entry_points(group="pentestgui.modules"):
    module = entry_point.load()
    prefix = module.mount(app, host)
```

There is no `import necropsy` anywhere in that file, and a test parses its AST to keep it
that way. `pip install -e ../necropsy` plus a restart adds the panels; `pip uninstall`
removes them. The seam built in Phase 1 held: nothing about moving from sidecar to mounted
required touching a route, a job, or a model.

## 2. The module describes itself

The shell cannot hardcode Necropsy's panels without coupling itself to this module's
release cycle, so `GET /meta/module` returns them — id, title, SF Symbol, path, stream,
and **whether each is usable on this host**:

```
[enabled ] cases      Cases          /cases
[enabled ] sample     Sample         /samples/{sha256}/static
[disabled] decompile  Decompilation  (Ghidra not installed on this host)
[disabled] sandbox    Sandbox        (Dynamic analysis is disabled. Set NECROPSY_SANDBOX_ENABLED=true…)
[enabled ] attack     ATT&CK         /cases/{case_id}/attack
[disabled] report     AI Report      (no Anthropic credentials on this host)
```

`enabled` comes from the same probes `necropsy doctor` uses. A panel whose backing tool is
missing renders greyed out with the reason, rather than looking available and failing on
click — the same principle the proposals have followed since Phase 1.

## 3. Two contracts, because one language cannot check the other

A backend change that passes every Python test and silently breaks the panel is the
failure mode this phase had to guard against. Two checks, catching different halves:

**`contract/surface.json`** — every route by method and path, plus the top-level response
field names and any required headers. Committed and diffed on every test run. Renaming a
field or dropping a route fails the build; rewording a description does not. Re-bless a
deliberate change with `necropsy contract --bless`.

**`gui/Fixtures/*.json`** — 21 real responses captured from the running Python API by
`tools/generate_gui_fixtures.py`, decoded in Swift by the models that will consume them.
The surface check catches the Python side changing; this catches the Swift side drifting
from it.

## 4. What the cross-language test found immediately

The fixtures failed to decode on the first run, and the bug was in the backend, not Swift.

FastAPI was emitting `2026-09-05T13:26:11.419758` — **no timezone**. SQLite does not store
tzinfo, so a value written as aware comes back naive, and pydantic serialises it without an
offset. Every consumer then has to guess, and a browser guesses *local time*: silently
wrong by up to twelve hours on a case timeline, with no error anywhere.

Fixed at the source with a `UTCDateTime` type decorator registered on the declarative base,
so it applies to every `Mapped[datetime]` column without touching a model. SQLite stores
the same string either way, so no migration was needed. Timestamps are now
`2026-09-05T13:34:55.454819Z`, and a Python test asserts the offset is present on the wire.

That bug was invisible to 287 passing Python tests. It took a consumer in another language
to surface it.

## 5. The panels, and the decisions they carry

`NecropsyKit` is Foundation-only (so it builds and tests anywhere); `NecropsyPanel` is the
SwiftUI layer. The views exist to render decisions the backend already made, and three
carry real weight:

**Proposals show blast radius before the click.** Risk factors are expanded inline, not
hidden behind a disclosure, with mitigating factors rendered in the same list carrying
their sign — so "isolated" visibly earns its lower score than "egress permitted". A
proposal at high or severe gets a destructive-styled confirmation.

**The ATT&CK matrix never renders inferred as observed.** An observed cell gets a solid
fill and border; an inferred one is washed out and dashed. `observed_emulated` gets its own
icon. The caveat text is one hover away. A flat heatmap would erase the difference between
"imports VirtualAllocEx" and "created a remote thread", which is the most important
distinction in a case.

**An unreadable detonation is a warning, not an empty list.** The verdict leads and the
event count follows, because a blank timeline and "the sample did nothing" look identical
and only one is true.

Everything a model wrote carries an `AIBadge` with its confidence. `NecropsyTheme` maps the
shared vocabulary onto semantic colours in one place, so the host's design tokens replace
it without touching a view.

## 6. What is not verified

**SwiftUI type-checking.** `#if canImport(SwiftUI)` means those files compile to nothing on
Linux. CI proves they *parse* — a missing `#endif` was caught exactly that way — but the
first `swift build` on your Mac may surface type errors. The client layer underneath them
is fully tested, so any breakage should be local to view code.

**Your design language.** I have never seen the pentest GUI. `NecropsyTheme` is a
placeholder shaped to be replaced; the panels assume a `NavigationSplitView` shell that the
host owns.

**Fixture freshness.** The Swift tests decode committed fixtures, so a backend change plus
stale fixtures would pass there — which is what the Python-side surface check is for.
Regenerate after any API change:

```bash
python tools/generate_gui_fixtures.py gui/Fixtures
cd gui && swift test
```

## 7. Where the platform stands

All six phases are built. What remains is not code I can write from here — it is the five
things only your Mac and lab can confirm:

| | |
|---|---|
| VMware Fusion | One live detonation. The vmrun layer is stub-tested; Fusion's own behaviour is not |
| Anthropic | One live call. No credentials here, and spending on your account is your decision |
| Elastic | Whether your Agent integration provides `.caseless`, and how it maps `host.name` |
| rizin | Its JSON key shapes, which have moved between releases |
| Xcode | `swift build` against the real SwiftUI |
