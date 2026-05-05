# TRDD-ffc4e8e2-6c88-470f-8dcd-6c8f9e6dddb6 — Move hook endpoints from dashboard server (3333) to proxy server (3334)

**TRDD ID:** `ffc4e8e2-6c88-470f-8dcd-6c8f9e6dddb6`
**Filename:** `design/tasks/TRDD-ffc4e8e2-hooks-on-proxy-port.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)
**Status:** SUPERSEDED on 2026-05-06 by [TRDD-c30609ab](TRDD-c30609ab-three-port-split.md), which inverts the approach: instead of moving hooks from the dashboard server (3333) to the proxy server (3334), the new plan keeps hooks where they are and instead moves the UI to its own new port (4444 default, configurable). Same total scope, but install-hooks.sh stays untouched and existing installs upgrade invisibly. Body retained below for historical context only — DO NOT IMPLEMENT this approach.

(Original status: Not started — blocked Phase 1.5 commit on 2026-05-06; Phase 1.5 work parked on local branch `phase-1.5-blocked-on-f001` (see "Phase 1.5 work parked" section below for recovery instructions).)

## Background — what discovered the issue

While running the pre-commit gate on Phase 1.5 ("`vdm dashboard start --no-ui`"
daemon-only mode), the Opus reviewer flagged **F-001 MAJOR**: setting
`CSW_DISABLE_UI=1` skips `server.listen(PORT)` for port 3333, but
`install-hooks.sh` resolves every hook URL against `CSW_PORT` (3333) — so
all hook-driven token tracking (session-start, session-stop, session-end,
PreCompact, PostToolBatch, Subagent*, Worktree*, Task*, Notification, the
git commit-msg trailer, etc.) silently fails with `ECONNREFUSED` (curl's
`|| true` swallows the error). Daemon-only mode therefore breaks the
documented "token tracking + account rotation always on" contract.

**Phase 1.0** has the same bug structurally: `POST /api/dashboard/ui-listener/stop`
also closes 3333. Phase 1.0 was committed via `[no-verify]` (commit
ce7e9cd), so the bug is already in `main` — it's just easier to hit via
Phase 1.5's `--no-ui` flag.

The root cause is architectural: the dashboard server (port 3333) hosts
both the HTML UI **and** the API endpoints that hooks POST to. The proxy
server (port 3334) only handles the upstream-Anthropic forwarding. Closing
3333 for "UI off" purposes inadvertently closes hook endpoints too.

## Architectural inventory (as of 2026-05-06, pre-fix)

Survey of `dashboard.mjs` API endpoints by server:

**Dashboard server (port 3333) — 36 endpoints, all on `server` instance:**

Hook endpoints (must stay reachable when hooks fire):
- `/api/session-start`           POST  (UserPromptSubmit hook)
- `/api/session-stop`            POST  (Stop / StopFailure / SubagentStop hooks)
- `/api/session-end`             POST  (SessionEnd hook)
- `/api/subagent-start`          POST  (SubagentStart hook)
- `/api/pre-compact`             POST  (PreCompact hook)
- `/api/post-compact`            POST  (PostCompact hook)
- `/api/cwd-changed`             POST  (CwdChanged hook)
- `/api/post-tool-batch`         POST  (PostToolBatch hook, gated)
- `/api/worktree-create`         POST  (WorktreeCreate hook)
- `/api/worktree-remove`         POST  (WorktreeRemove hook)
- `/api/task-created`            POST  (TaskCreated hook)
- `/api/task-completed`          POST  (TaskCompleted hook)
- `/api/teammate-idle`           POST  (TeammateIdle hook)
- `/api/notification`            POST  (Notification hook)
- `/api/config-change`           POST  (ConfigChange hook)
- `/api/user-prompt-expansion`   POST  (UserPromptExpansion hook)

Hook-adjacent (read by the git commit-msg trailer in install-hooks.sh):
- `/api/settings`                GET   (read by trailer to check `commitTokenUsage`)
- `/api/token-usage`             GET   (read by trailer for the per-branch usage)

UI-only endpoints (genuinely UI; can stay on dashboard server):
- `/`                            GET   (renderHTML)
- `/api/profiles`                GET   (UI account list)
- `/api/proxy-status`            GET   (UI status pill)
- `/api/switch`                  POST  (UI Switch button)
- `/api/remove`                  POST  (UI Remove button)
- `/api/refresh`                 POST  (UI Refresh button)
- `/api/activity`                GET   (UI activity feed)
- `/api/account-prefs`           GET/POST (UI per-account toggle)
- `/api/cleanup-plaintext`       GET/POST (recovery endpoint)
- `/api/logs/stream`             GET   (UI SSE log stream)
- `/api/settings`                POST  (UI settings form save)
- `/api/viewer-state`            GET/POST (UI scrubber persistence)
- `/api/token-usage/by-tool`     GET   (UI tool breakdown)
- `/api/token-usage/flush`       POST  (UI flush button)
- `/api/token-usage-tree`        GET   (UI Tokens tab tree)
- `/api/otel-events`             GET   (UI OTLP debug tab, opt-in)

**Proxy server (port 3334):**
- The Anthropic-forwarding handler (always-on)
- Phase 1.0 control endpoints: `/api/dashboard/ui-listener/{status,stop,start}`
- `/health`

The split between "hook-relevant" and "UI-only" is the unit of separation
that needs to happen.

## Proposal

Two endpoint surfaces:

1. **Dashboard server (3333)** — pure UI. HTML, the SSE log stream, the
   user-action endpoints driven by buttons in the browser. Stoppable.
2. **Proxy server (3334)** — proxy + token-tracking + state-of-the-world
   reads. Always-on. Hosts:
   - The Anthropic-forwarding proxy (already there).
   - Phase 1.0 ui-listener control endpoints (already there).
   - All 16 hook POST endpoints listed above.
   - `GET /api/settings` (read-only, used by the git trailer).
   - `GET /api/token-usage` (read-only, used by the git trailer).
   - The `cleanup-plaintext` GET/POST recovery endpoint (no UI required).

Migration plan:

1. Extract every hook handler body into a named function (e.g.
   `handleSessionStart(req, res, body)`). Today the handlers are inline
   inside the server's request callback. Inline → named function refactor
   is mechanical and reviewable in isolation.
2. Register the named functions on **both** servers, gated by the same
   path/method match. Initially this means hook traffic to either port
   works — useful for migration safety.
3. Update `install-hooks.sh` to write `CSW_PROXY_PORT` (3334) into hook
   URLs instead of `CSW_PORT` (3333). New installs will bind hooks to the
   proxy directly.
4. Bump the install-hooks Phase counter (currently Phase I → Phase J) and
   make the migration block in `install-hooks.sh` rewrite legacy 3333 hook
   entries to 3334 idempotently. Pre-existing installs upgrade cleanly on
   the next `vdm` invocation (the migration runs at the top of the bash
   dispatch block).
5. Once the install-hooks migration has had a release cycle to roll out,
   remove the duplicate handlers from the dashboard server. The proxy
   server becomes the sole owner of hook endpoints.

CSRF / Origin allow-list: the proxy server already has `_isOriginAllowed`
applied to its Phase 1.0 control endpoints. Hook endpoints are POSTed by
local CLI/curl — they don't need browser-origin CSRF (curl doesn't send
Origin), but they DO need the same `READ_BODY_MAX` 1 MiB cap and the same
JSON-only body parsing. Easiest path: copy the existing
`/api/dashboard/ui-listener/*` plumbing for the body cap, skip
`_isOriginAllowed` for hook endpoints (they have no browser counterpart),
and document the difference in CLAUDE.md.

## Why we're doing this AS deferred work, not right now

Three reasons:

1. **Scope.** 16 hook endpoints + 2 hook-adjacent reads = 18 handlers to
   move. Each one currently has 50–200 lines of inline body. Mechanical
   but lengthy.
2. **Test surface.** Hook handlers feed `account-state.json`,
   `token-usage.json`, `session-history.json`, `activity-log.json`, the
   probe tracker, the per-account lock, and the utilization history.
   Moving them without breaking attribution requires new integration tests
   that don't exist yet (the current `test/api.test.mjs` only exercises
   OAuth refresh).
3. **Coordinated install-hooks rev.** Changing the URL hooks POST to
   needs a coordinated bump in `install-hooks.sh`'s phase counter and a
   migration block. Old installs that haven't run the new install yet
   would still POST to 3333; the new code needs to keep listening there
   for a release cycle before we can remove the duplication.

## File list for the future implementation

- `dashboard.mjs` — extract hook handler bodies to named functions; register
  on `proxyServer` in addition to `server`.
- `install-hooks.sh` — change hook URL templates from `CSW_PORT` (3333) to
  `CSW_PROXY_PORT` (3334); bump phase counter; add migration block that
  rewrites legacy entries.
- `lib-install.sh` — `_resolve_vdm_port` already exists; clone for
  `_resolve_vdm_proxy_port` if not already there.
- `test/api.test.mjs` — add integration tests for hook endpoints on the
  proxy server (mock OAuth pattern from existing tests).
- `CLAUDE.md` — update the "Hooks installed into the user's machine"
  section to point at port 3334; document the dashboard/hook port split.

## Test scenarios

- New install: hooks POST to 3334; daemon-only mode (`--no-ui`) keeps
  token tracking working.
- Upgrade install: existing 3333 hook entries get rewritten to 3334 on
  first `vdm` invocation post-migration. Re-running migration is a no-op.
- Mixed-state install (partial upgrade interrupted): new install runs
  migration, sees both 3333 and 3334 entries, merges them sanely.
- `vdm dashboard stop` with hooks active: token tracking continues
  uninterrupted (verified by checking `token-usage.json` updates after
  stop).
- `vdm dashboard start --no-ui`: same — hooks land on 3334, attribution
  continues.
- Old vdm version (still posting to 3333) against new dashboard: still
  works for one release cycle (duplicate registration on both servers).

## Security considerations

- The proxy server today is bound to 127.0.0.1 only. Adding hook
  endpoints does not change the bind surface.
- Hook payloads are 1 MiB-capped via `readBody` already. Reuse the helper
  on the proxy server.
- The git commit-msg trailer reads `/api/settings` and `/api/token-usage`
  — these become GET-on-proxy. They MUST NOT leak credentials in their
  responses. Re-audit the response shapes when moving them.
- `Origin` header is absent from curl POSTs but present from browser
  POSTs. Today `_isOriginAllowed` enforces same-origin for browser
  state-changing requests. For hook endpoints, no browser counterpart
  exists — `_isOriginAllowed` should be SKIPPED for hook paths, NOT
  enforced (browser → hook endpoint would be a misconfiguration anyway).

## Status field

- Not started: 2026-05-06 — TRDD created.
- In progress: TBD.
- Done: TBD. Mark Done when (a) all 18 handlers are on the proxy, (b)
  install-hooks.sh writes 3334, (c) at least one release cycle has
  elapsed with the duplicate registration, (d) the dashboard-side
  duplicates are removed.

## Phase 1.5 work parked on branch `phase-1.5-blocked-on-f001`

The `vdm dashboard start --no-ui` flag plumbing + the `dashboard.mjs`
gate (CSW_DISABLE_UI env, daemon-only setImmediate block with the
mirrored renderHTML self-test, the TDZ-safe local _proxy_port_for_log)
is preserved as a single WIP commit on the local branch
`phase-1.5-blocked-on-f001`. Stash refs were considered but rejected —
they shift on every new push (`stash@{0}` → `stash@{1}` …) and the
reference goes silently stale.

Recovering Phase 1.5 once this TRDD is implemented and hooks live on
3334:

```bash
git checkout main
git cherry-pick phase-1.5-blocked-on-f001
# Review the remaining comment-block updates — the F-001 commentary
# in the WIP commit references the pre-fix architecture. Rephrase to
# reflect the post-fix state where hooks live on 3334.
# Re-run through the pre-commit gate.
```

The branch is local-only by design (no `git push`) — it is a parking
spot, not a publication. If the branch is at risk of being lost (laptop
reset, `git gc` after a long pause), publish it under
`refs/wip/phase-1.5-blocked-on-f001` on the user's fork to make it
durable.
