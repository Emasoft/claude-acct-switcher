# TRDD-c30609ab-77b0-41e0-bb4c-59f3a93aff47 — Three-port split: daemon (3333) + proxy (3334) + UI (4444), all configurable

**TRDD ID:** `c30609ab-77b0-41e0-bb4c-59f3a93aff47`
**Filename:** `design/tasks/TRDD-c30609ab-three-port-split.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)
**Status:** Not started — supersedes TRDD-ffc4e8e2 (which proposed the inverse — moving hooks to the proxy port). The UI-on-its-own-port approach is structurally simpler because install-hooks.sh keeps writing 3333 and old installs keep working unchanged.

## Background

Phase 1.5 (`vdm dashboard start --no-ui`) was blocked at the pre-commit
gate by Opus F-001 MAJOR: setting `CSW_DISABLE_UI=1` skipped
`server.listen(PORT)` for port 3333, but `install-hooks.sh` resolves all
16 hook URLs against `CSW_PORT` (3333). Daemon-only mode therefore broke
hook-driven token tracking (session-start, session-stop, session-end,
PreCompact, PostToolBatch, Subagent*, Worktree*, Task*, Notification, the
git commit-msg trailer) — curl's `|| true` swallowed the ECONNREFUSED so
the breakage was silent.

**Original plan (TRDD-ffc4e8e2):** move hook endpoints from the dashboard
server (3333) to the proxy server (3334), update install-hooks.sh to
write 3334. Required a coordinated install-hooks rev and a migration
block.

**New plan (this TRDD):** keep hook endpoints exactly where they are
(3333), and instead move the **UI** onto its own new port (default 4444).
Stopping the dashboard means closing the UI port; 3333 stays bound for
hooks; 3334 stays bound for the proxy. install-hooks.sh is untouched —
old installs continue to POST to 3333 and keep working unchanged. No
migration block, no coordinated rev.

## Architectural shape

Three HTTP servers, three ports, three independent stop/start lifecycles:

| Port | Default | Role | Stoppable? | What lives there |
|------|---------|------|------------|------------------|
| `CSW_PORT` | 3333 | Daemon (hooks + hook-adjacent reads) | NO — always-on | All 16 Claude Code hook POST endpoints + the 2 dual-use reads (`GET /api/settings`, `GET /api/token-usage`) used by the git commit-msg trailer |
| `CSW_PROXY_PORT` | 3334 | Proxy (Anthropic forwarding + Phase 1.0 control) | NO — always-on | The Anthropic-forwarding handler, `/health`, Phase 1.0 control endpoints (`/api/dashboard/ui-listener/{status,stop,start}`) |
| `CSW_UI_PORT` | 4444 | UI (HTML + UI-only API) | YES — `vdm dashboard stop` closes it | `GET /` (HTML), `GET /api/profiles`, `GET /api/proxy-status`, `POST /api/switch`, `POST /api/remove`, `POST /api/refresh`, `GET /api/activity`, `GET+POST /api/account-prefs`, `GET+POST /api/cleanup-plaintext`, `GET /api/logs/stream`, `POST /api/settings`, `GET+POST /api/viewer-state`, `GET /api/sessions`, `GET /api/token-usage/by-tool`, `POST /api/token-usage/flush`, `GET /api/token-usage-tree`, `GET /api/otel-events` |

The dual-use reads (`GET /api/settings`, `GET /api/token-usage`) live on
3333 because the git trailer hook reads them. The UI's settings tab also
reads them, but the UI runs same-origin on 4444 — it could either
duplicate-register them on 4444 (cleaner: same-origin, no CORS) or fetch
them cross-origin from 3333 (introduces preflight + Access-Control
headers). **Decision:** duplicate-register on both. Read-only endpoints
are safe to mirror; the small body size means the duplicate handler is
identical code with no shared state to keep in sync.

### What "configurable" means

Each port is resolvable via THREE sources, in this precedence order:

1. **Env var** (highest priority)
   - `CSW_PORT` → daemon
   - `CSW_PROXY_PORT` → proxy
   - `CSW_UI_PORT` → UI
2. **`config.json`** (in `~/.vdm/`)
   - `daemonPort`
   - `proxyPort`
   - `uiPort`
3. **Compile-time default** (lowest)
   - 3333, 3334, 4444 respectively

Port resolution is shared between `vdm` (bash) and `dashboard.mjs`
(Node). The bash side already has `_resolve_vdm_port` in `lib-install.sh`
+ `install-hooks.sh`; that becomes a generic `_resolve_vdm_port_for KIND`
helper where `KIND` is `daemon` / `proxy` / `ui`. The Node side reads
`process.env.CSW_*` first, falls back to the parsed `config.json`.

Each value is range-validated `1..65535`, with the same
isinstance-with-bool-discriminator used by the existing port code (see
the 5 sites in `vdm` and `lib-install.sh` that reject `bool`-as-int).

### What "stoppable" means

`vdm dashboard stop` (Phase 1.0 endpoint `POST /api/dashboard/ui-listener/stop`)
closes only the UI server. The daemon and proxy stay listening. Hooks
keep firing into 3333. Token tracking, account rotation, OAuth refresh
all continue uninterrupted.

`vdm dashboard start [--no-ui]` (Phase 1.5):
- Without `--no-ui`: bind UI on 4444 + open browser.
- With `--no-ui`: skip the UI bind. Daemon + proxy come up; UI stays
  closed. The user can later open the UI via the Phase 1.0
  `POST /api/dashboard/ui-listener/start` endpoint without a process
  restart.

### CSRF and same-origin notes

- Daemon (3333) hook endpoints: no `Origin` header from curl. Skip
  `_isOriginAllowed` for hook paths.
- UI (4444) endpoints: same-origin with the HTML at 4444. Existing
  `_isOriginAllowed` checks remain — just extend the allow-list to
  include `http://localhost:<CSW_UI_PORT>`.
- Proxy (3334) Phase 1.0 control endpoints: same-origin with the UI
  HTML at 4444. Already has `_isOriginAllowed`. Extend the allow-list
  to include `http://localhost:<CSW_UI_PORT>`.
- The dual-use read endpoints on 3333 (`/api/settings GET`,
  `/api/token-usage GET`) are read-only. CSRF doesn't apply (no state
  change). Skip the Origin check; ensure no secret material leaks in
  the response body (already audited).

## Migration plan

The user-facing migration path is **invisible**: existing installs run
`install.sh` again (or `vdm upgrade`), pick up the new code, and the
new UI port (4444) starts being bound on next dashboard start. Hook
URLs in `~/.claude/settings.json` keep pointing at 3333 (no change)
and continue to work because 3333 still hosts hook endpoints.

The only externally visible change for an existing user is: opening
http://localhost:3333/ in a browser no longer shows the dashboard UI
(it shows a small placeholder pointing at 4444). The new dashboard URL
is http://localhost:4444/.

### Stages

**Stage A — port configurability (additive, no behavior change):**
1. Add `_resolve_vdm_port_for KIND` to `lib-install.sh` (parametric over
   `daemon` / `proxy` / `ui`). Existing `_resolve_vdm_port` becomes a
   thin wrapper for `KIND=daemon`.
2. Read `daemonPort` / `proxyPort` / `uiPort` from `~/.vdm/config.json`
   if present, with the env-var override and the
   isinstance-without-bool discriminator.
3. Document the three keys in `CLAUDE.md`'s runtime-state table and in
   `vdm config --help`.
4. No new server is bound yet — this stage is purely the resolver
   plumbing.

**Stage B — split the UI server:**
1. Inventory the 16 UI-only endpoints + the 2 dual-use reads (already
   done above). Save the list as a comment block at the top of the new
   `uiServer` request handler.
2. Extract each UI-only handler body into a named function. The handler
   receives `(req, res, body, url)` so it can be invoked from either
   server's request callback (currently inline-inside-the-callback).
3. Create `uiServer = createServer(...)` whose request handler dispatches
   to the named UI handlers. `daemonServer` (the renamed `server`)
   keeps the hook handlers + the dual-use read endpoints (which also
   register on `uiServer` for same-origin convenience).
4. Bind `uiServer` on `CSW_UI_PORT` (default 4444). Add the same
   `127.0.0.1`-only bind as the daemon. Add the same `_serverWritable`
   draining behavior as the daemon for graceful stop.
5. Phase 1.5's `CSW_DISABLE_UI=1` becomes "skip `uiServer.listen()`"
   instead of "skip `server.listen(PORT)`". Same `setImmediate(autoDiscover + self-test)`
   block, just gating a different listener.
6. Phase 1.0 endpoint `POST /api/dashboard/ui-listener/{status,stop,start}`
   moves to controlling `uiServer` instead of the daemon server. The
   endpoint URL stays the same; the listener it controls changes.

**Stage C — vdm CLI updates:**
1. `vdm dashboard status`: report all three ports.
2. `vdm dashboard start [--no-ui]`: report the UI port in the success
   message + open browser at `http://localhost:<CSW_UI_PORT>`.
3. `vdm dashboard stop`: unchanged user-facing semantics; under the
   hood it still POSTs to the Phase 1.0 endpoint, which now closes
   `uiServer`.
4. `vdm config <key> <value>`: extend to accept `daemonPort`,
   `proxyPort`, `uiPort` and round-trip through `config.json`.
5. The rc-snippet `~/.zshrc` block keeps `export ANTHROPIC_BASE_URL=http://localhost:<CSW_PROXY_PORT>`
   exactly as it does today — only the proxy port matters for that env
   var. The auto-start command in the rc-snippet is also unchanged
   because nohup + node + dashboard.mjs is the same entry point.

**Stage D — CLAUDE.md updates:**
1. Update the "Architecture" section to describe three servers, not
   two.
2. Update the "Runtime state files" table — config.json now stores
   three ports.
3. Document the precedence order (env > config > default) in one
   paragraph.
4. Update the Phase G "What disables vdm" section to mention port
   conflicts as a new failure mode (already implicit, but worth being
   explicit).

## Test scenarios

- Default install, default ports (3333/3334/4444): hooks fire on 3333,
  proxy forwards on 3334, UI loads on 4444.
- Custom UI port via env: `CSW_UI_PORT=5555 vdm dashboard start`
  binds UI on 5555. Browser opens 5555. `vdm dashboard status` reports
  5555.
- Custom UI port via config.json: `vdm config uiPort 5555` writes
  config.json. Next `vdm dashboard start` reads it and binds 5555.
- Port conflict: another process listening on 4444. Dashboard start
  fails fast with a clear error pointing at how to change the port.
- `vdm dashboard stop`: UI closes (4444 unbound). Hooks on 3333 keep
  working — verified by triggering a session-start hook from a
  separate Claude Code session and checking `token-usage.json` updates.
- `vdm dashboard start --no-ui`: daemon + proxy come up. UI stays
  closed. Browser does NOT open. `curl http://localhost:4444/`
  fails. `curl http://localhost:3333/api/session-start` works.
- Upgrade from a pre-three-port install: existing hook URLs in
  `~/.claude/settings.json` (pointing at 3333) keep working. Browser
  opening of 3333 shows a small placeholder pointing at 4444. User's
  bookmark to 3333 is updated lazily by the placeholder's auto-redirect
  link.
- Bool-as-int rejection: setting `daemonPort: true` in config.json is
  rejected with a clear error (same isinstance-without-bool
  discriminator already in use for the existing port code).

## Security considerations

- All three servers bind to `127.0.0.1` only. No network exposure.
- The `READ_BODY_MAX = 1 MiB` cap from `readBody` applies to all three
  servers' POST handlers. Reuse the helper.
- `_isOriginAllowed` allow-list extends to include the UI port. The
  current allow-list assumes localhost:3333; updating to include
  `localhost:<CSW_UI_PORT>` is mechanical.
- Daemon (3333) hook endpoints have no browser counterpart — keep
  `_isOriginAllowed` SKIPPED for hook paths so curl POSTs continue to
  work. Document this skip explicitly (Phase 1.0 had the same property).
- Resource sharing across servers: `accountStateManager`, the per-account
  lock, the activity log, the utilization history, the probe tracker,
  and the token-usage state are all module-scope singletons. Both
  servers' handlers will mutate them. The existing per-account lock
  (`createPerAccountLock` in `lib.mjs`) protects mutations; no new
  cross-server locking needed.
- Port conflicts are noisy not silent: the new port resolver fails
  fast on EADDRINUSE with the suggested override.

## File list

- `dashboard.mjs` — biggest change. Split request handler into UI vs
  daemon handlers. Bind two servers (plus the proxy server already
  there). Move the Phase 1.0 ui-listener control endpoints to control
  the UI server. Add the third self-test gate (UI HTML + UI script
  parse) for the UI server's startup.
- `lib.mjs` — no logic change expected. May need to expose `vdm-ui`
  port helper if any pure function reads it (currently none do).
- `vdm` — extend `cmd_dashboard_status`, `cmd_dashboard_start`,
  `cmd_config`, the rc-snippet, the help block.
- `lib-install.sh` — generalize `_resolve_vdm_port` to
  `_resolve_vdm_port_for KIND`. Existing single-port helper becomes a
  shim.
- `install-hooks.sh` — UNCHANGED. Hook URLs continue to write
  `CSW_PORT` (3333). This is a deliberate simplification.
- `install.sh` — extend the rc-snippet's auto-start block to also
  pick up `CSW_UI_PORT` if set in env (the dashboard reads it itself,
  but exporting in the rc-snippet means the user's interactive shells
  also see it for `vdm` invocations).
- `test/lib.test.mjs` — port resolver tests, isinstance-bool tests for
  the new keys.
- `test/api.test.mjs` — integration test that the UI server and daemon
  server both work, that `dashboard stop` only closes the UI, and that
  hook endpoints keep firing through the close.
- `CLAUDE.md` — Architecture, Runtime state files, Phase G sections.

## Status field

- Not started: 2026-05-06 — TRDD created, supersedes TRDD-ffc4e8e2.
- In progress: TBD.
- Done: TBD. Mark Done when (a) all four stages have shipped, (b) the
  Phase 1.5 WIP commit on branch `phase-1.5-blocked-on-f001` has been
  cherry-picked onto main with comment-block updates reflecting the new
  architecture, (c) `vdm dashboard stop` is verified to leave hooks
  working via integration test.

## Phase 1.5 work parked on branch `phase-1.5-blocked-on-f001`

Same as TRDD-ffc4e8e2 — the WIP commit is preserved on the local
branch. After this TRDD lands, the cherry-pick will require:

- Re-naming `CSW_DISABLE_UI` to gate the UI server (not the dashboard
  server). The env var name itself is fine; only the listener it
  guards changes.
- Updating the daemon-only block's comments to mention the daemon and
  proxy stay up — UI alone is gated.
- The TDZ-safe `_proxy_port_for_log` log line stays the same; the
  daemon port for the same log can be inlined identically.

Recovery: `git checkout main && git cherry-pick phase-1.5-blocked-on-f001`,
then patch the comment blocks, then `git commit --amend` and re-run
through the gate.
