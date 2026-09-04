# Integrating with the pentest GUI backend

**Decided:** the pentest backend is an early prototype, not a settled FastAPI+ORM service.
That reverses the usual direction of this document. Necropsy does not adapt to the host's
current shape; **Necropsy's `contracts/` package is the reference definition, and the host
grows into it.** The upside is that Phases 1–5 don't block on the other project. The risk
is drift, so the seam is built and tested from day one even though it isn't used yet.

## 1. Deployment now vs. later

**Now (Phases 1–5): sidecar.** Necropsy runs as its own uvicorn process on a local port.
The macOS GUI treats it as a second base URL alongside the pentest backend and renders the
new panel against its OpenAPI schema. Nothing is shared but the design language and the
risk-score component.

```
macOS GUI ─┬─→ pentest backend   :8000
           └─→ necropsy          :8010   ← new panel binds here
```

**Later (Phase 6): in-process mount.** When the host backend is mature, it discovers and
mounts Necropsy through a packaging entry point and the GUI collapses to one base URL:

```python
for ep in importlib.metadata.entry_points(group="pentestgui.modules"):
    module = ep.load()                      # necropsy.plugin:MODULE
    module.mount(app, host_services)        # APIRouter under /api/v1/<module.slug>
```

`MODULE` exposes `slug`, `title`, `router`, `mount(app, host)`, `migration_head`,
`required_capabilities: set[str]`, `healthcheck()`. Moving from sidecar to mounted is a
config change and a base-URL change in the GUI — not a port — **provided the router never
assumes it owns the app**: no `@app.on_event` handlers outside `mount()`, no root-path
routes, no global middleware, all paths relative to the router prefix. Enforce that with a
test that mounts the router into a bare `FastAPI()` under a non-default prefix and hits
three endpoints.

## 2. `HostServices` (Protocol in `necropsy/contracts/host.py`)

```python
class HostServices(Protocol):
    def redis(self) -> Redis: ...
    def publish(self, channel: str, event: Event) -> None: ...
    def actor(self) -> str: ...                       # operator identity for audit rows
    def artifact_root(self) -> Path: ...
    def risk_policy(self) -> RiskPolicy: ...          # shared thresholds / colour bands
    def resolve_engagement(self, ref: str) -> Engagement | None: ...
    def has(self, capability: str) -> bool: ...
```

While the host is a prototype, `StandaloneHost` implements all of it locally: its own Redis
DB index, Redis pub/sub for events, `NECROPSY_OPERATOR` for actor identity,
`~/.necropsy/vault` for artifacts, packaged risk thresholds, and `resolve_engagement`
returning `None` behind a `has("engagements")` check. Only `redis`, `publish`, `actor` and
`artifact_root` are ever required; everything else must degrade.

## 3. Shared vocabulary — the part worth agreeing on early

Three small types, defined here, adopted by the host when it's ready. They're the reason
both modules' output can render through one GUI component set:

- **`RiskFactor`** — `{code, label, weight, direction}`. The pentest module's "credentialed
  scan against production" and Necropsy's "egress-permitted detonation" should be the same
  shape and land in the same colour band.
- **`ActionProposal`** — `{kind, title, rationale, risk_score, risk_factors,
  estimated_cost_s, params}`. This drives the "results push to the next stage, human chooses
  what happens next" loop in both modules.
- **`Event`** — `{type, case_id, at, payload}`, published to Redis by workers, fanned out
  over WebSocket by the API process.

Keep `contracts/` dependency-free (stdlib + pydantic only) so the pentest backend can depend
on it without inheriting SQLAlchemy, RQ, LIEF or anything else in Necropsy. When the host
does adopt them, extract those three files into a `pentestgui-contracts` distribution that
both depend on — **that** is the right moment to extract, not before.

## 4. What the GUI panel needs

No shared Swift. The panel binds to the OpenAPI schema plus `/ws/cases/{id}`, and reuses the
host's existing design tokens and its risk-score component. Five views, all backed by
endpoints in PHASE1.md §4: case list, case timeline, sample/disassembly view (Phase 2),
sandbox timeline (Phase 3), ATT&CK heatmap (Phase 4), AI summary pane (Phase 5).

Phase 1 only needs the first two.
