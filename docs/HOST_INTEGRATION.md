# What the pentest backend must provide

Necropsy mounts into the existing macOS pentest GUI backend. This is the whole contract —
if the host satisfies it, `pip install -e ../necropsy` plus a restart is the integration.

## 1. Discovery and mount

```python
# host backend, at startup
for ep in importlib.metadata.entry_points(group="pentestgui.modules"):
    module = ep.load()                      # necropsy.plugin:MODULE
    module.mount(app, host_services)        # adds APIRouter under /api/v1/<module.slug>
```

`MODULE` exposes: `slug`, `title`, `router`, `mount(app, host)`, `migration_head`,
`required_capabilities: set[str]`, `healthcheck()`.

## 2. `HostServices` (Protocol in `necropsy/contracts/host.py`)

```python
class HostServices(Protocol):
    def redis(self) -> Redis: ...
    def publish(self, channel: str, event: Event) -> None: ...
    def actor(self) -> str: ...                       # operator identity for audit rows
    def artifact_root(self) -> Path: ...
    def risk_policy(self) -> RiskPolicy: ...          # shared thresholds/colour bands
    def resolve_engagement(self, ref: str) -> Engagement | None: ...
    def has(self, capability: str) -> bool: ...
```

Only `redis`, `publish`, `actor` and `artifact_root` are required. `resolve_engagement`
and `risk_policy` sit behind `has()` checks and fall back to packaged defaults, so a host
that hasn't grown engagements yet still mounts the module cleanly.

## 3. Shared vocabulary, not shared code

The two modules must agree on three small types so the GUI renders both with one
component set:

- **`RiskFactor`** — `{code, label, weight, direction}`. The pentest module's
  "credentialed scan against production" and Necropsy's "egress-permitted detonation"
  should be the same shape and the same colour band.
- **`ActionProposal`** — `{kind, title, rationale, risk_score, risk_factors,
  estimated_cost_s, params}`. This is what drives the "results push to the next stage,
  human chooses" loop in both modules.
- **`Event`** — `{type, case_id, at, payload}` on a Redis channel, fanned out over WS.

These live in `necropsy/contracts/` for now. Once the pentest module needs them too,
promote the three files into a tiny shared `pentestgui-contracts` package that both depend
on — that is the correct moment to extract, not before.

## 4. What the GUI panel needs

No shared Swift. The panel binds to the OpenAPI schema plus `/ws/cases/{id}`, and reuses
the host's existing design tokens and its risk-score component. Five views, all backed by
endpoints listed in PHASE1.md §4: case list, case timeline, sample/disassembly view
(Phase 2), sandbox timeline (Phase 3), ATT&CK heatmap (Phase 4), AI summary pane (Phase 5).

Phase 1 only needs the first two.
