# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project: Van Damme-o-Matic (vdm)

Multi-account credential switcher for Claude Code on macOS. Auto-rotates OAuth accounts to dodge rate limits and refreshes expiring tokens in the background. The README is the user-facing pitch; this file is the developer-facing one.

## Common commands

```bash
# Run the test suite (Node's built-in runner — no test framework)
node --test 'test/*.test.mjs'

# Run a single test file
node --test test/lib.test.mjs

# Run the dashboard + proxy directly from the repo (skips install)
node dashboard.mjs                                  # ports 3333 (UI) and 3334 (proxy)
CSW_PORT=4444 CSW_PROXY_PORT=4445 node dashboard.mjs

# Local dev install — copies dashboard.mjs/lib.mjs/vdm to ~/.claude/account-switcher/
# and writes a `# BEGIN claude-account-switcher` block into ~/.zshrc.
./install.sh

# Reverse the install
./uninstall.sh

# CLI (after install, or run `./vdm <cmd>` from the repo)
vdm list | switch | remove | status | config | dashboard | logs | tokens | prefs | upgrade
```

There is **no build step, no bundler, no package.json, no lockfile, no linter**. The whole project is plain Node.js using only built-in modules plus bash. Don't add dependencies — that's a deliberate constraint (see Architecture below).

Requires Node 18+, macOS (uses Keychain), and `python3` (used by `vdm` and `install-hooks.sh` for JSON munging).

## Architecture

Four source files do all the work. Understand these and you understand the whole project:

- **`vdm`** (bash, ~2300 lines) — user-facing CLI. Dispatches to `cmd_*` functions; talks to the macOS Keychain via `security(1)` and to the dashboard's HTTP API for anything stateful. The `case` block at the bottom of the file is the command map.
- **`dashboard.mjs`** (Node, ~11,700 lines) — runs **two HTTP servers in one process**: the web dashboard (default port 3333, all the `/api/*` routes plus the embedded HTML in `renderHTML()`) and the API proxy (default port 3334, `handleProxyRequest`). Holds all I/O, timers, and global state. The HTML/CSS/JS for the UI is a single template string returned by `renderHTML()` — there is no separate frontend.
- **`lib.mjs`** (Node, ~2200 lines) — pure functions only, zero side effects. Anything testable lives here: fingerprinting, header rewriting (`buildForwardHeaders`/`stripHopByHopHeaders`), the `createAccountStateManager`/`createUtilizationHistory`/`createProbeTracker`/`createPerAccountLock` factories, rotation-strategy logic (`pickByStrategy` and friends — see **Per-account `excludeFromAuto`** below), OAuth-refresh helpers, `parseRetryAfter` (RFC 7231 §7.1.3 — handles both delta-seconds and HTTP-date forms; capped at `PARSE_RETRY_AFTER_MAX = 86400s`), the SSE token usage extractor (`createUsageExtractor`), and the serialization queue factory (`createSerializationQueue`). **When adding logic that can be expressed as a pure function, put it in `lib.mjs` and unit-test it in `test/lib.test.mjs`** — that's how the existing code is structured.
- **`lib-install.sh`** (bash, ~770 lines) — shared install/uninstall helpers sourced by `install.sh`, `uninstall.sh`, and `install-hooks.sh`. Atomic file ops (`_atomic_replace`, `_atomic_remove_block`), signal-safe cleanup stack (`_register_cleanup`/`_run_cleanup`), BSD/GNU portability shims (`_bsd_chmod_match`), env detectors, the `_kill_running_vdm` shutdown helper, and JSON readers (`_json_get_int`). NOT a runtime library — it's only loaded during install/uninstall lifecycles. The atomic helpers MUST be used for any file write outside `~/.claude/account-switcher/` because partial writes to user-controlled paths (rc files, hooks dirs) have outsized blast radius.

### How a Claude Code request flows through this

```
claude CLI ──ANTHROPIC_BASE_URL=http://localhost:3334──▶ dashboard.mjs proxy
                                                              │
                                                              │ readKeychain() → active token
                                                              │ buildForwardHeaders() (lib.mjs)
                                                              ▼
                                                        api.anthropic.com
                                                              │
                                            ◀──── 200 / 429 / 401 / 5xx ────
                                                              │
                                                              ▼
                                  on 429: pickByStrategy() picks another account,
                                          writeKeychain() swaps it, retry the request
                                  on 401: refresh token via OAUTH_TOKEN_URL,
                                          retry; if refresh fails → mark expired, switch
                                  on 200: parse `anthropic-ratelimit-*` headers,
                                          update accountStateManager + utilizationHistory
```

The shell `install.sh` writes `export ANTHROPIC_BASE_URL=http://localhost:3334` into the user's rc file and auto-starts `dashboard.mjs` on every new shell. That env var is the entire integration point with Claude Code — there is no plugin, no SDK hook on the request path.

### Credential storage — the load-bearing detail

Active credentials live in **a single macOS Keychain entry**: service `Claude Code-credentials`, account `$USER`, value is the JSON blob Claude Code itself writes (`{ claudeAiOauth: { accessToken, refreshToken, expiresAt, ... } }`).

**Saved-but-inactive accounts ALSO live in the keychain**, as separate generic-password entries: service `vdm-account-<name>`, account `$USER`, value is the same `claudeAiOauth` JSON shape. The `vdmAccountServiceName(name)` helper in `lib.mjs` builds the service name and is the canonical place to enforce the allowed-character rule (`[a-zA-Z0-9._@-]`, no reserved name `"index"`). Display labels (email or human-readable name) still live as plaintext sibling files `accounts/<name>.label` because they carry no secret material. **Switching accounts means: read `vdm-account-<name>` from the keychain → `security add-generic-password -U` writing the new blob to `Claude Code-credentials`.** Because Claude Code re-reads the keychain on each request, every running session sees the swap immediately. There is no IPC; the keychain *is* the IPC.

**Migration**: Older installs stored saved accounts as plaintext `accounts/<name>.json` files. Both `dashboard.mjs` (`migrateAccountsToKeychain` runs right after `loadPersistedState()` at startup) and `vdm` (the same step at the top of the dispatch block in the bash script) idempotently read each `*.json` file, write it to the matching `vdm-account-<name>` entry, and only delete the file on successful keychain write. `*.label` files stay where they are. Re-running migration on an already-migrated install is a no-op.

`detectKeychainService()` (in both `vdm` and `dashboard.mjs`) exists because the service name has changed across Claude Code releases — don't hardcode `Claude Code-credentials`, always go through that helper.

### Runtime state files (gitignored, live next to dashboard.mjs)

| File | Written by | Holds |
|---|---|---|
| `config.json` | `saveSettings()` | user settings (rotation strategy, autoSwitch, proxyEnabled, intervals) |
| `accounts/*.label` | rename + auto-discover | per-account human label (email/display name — no secrets) |
| `account-state.json` | proxy on rate-limit responses | per-token rate-limit state (5h/7d resets, utilization) |
| `activity-log.json` | `logActivity()` | rolling 500-event ring buffer (UI feed) |
| `utilization-history.json` | `saveHistoryToDisk()` | 24h + 7d utilization series for trend graphs |
| `probe-log.json` | `recordProbe()` | rolling 7-day count of HEAD probes (so the cost of probing is itself observable) |
| `token-usage.json` | `/api/session-start` + `/api/session-stop` hooks | per-session token counters used by the git commit-message trailer |
| `session-history.json` | `persistCompletedSession` (debounced 750ms) | rolling history of completed monitored sessions; debounced via `_flushSessionHistory` to avoid blocking the event loop on burst completions |
| `account-prefs.json` | `setAccountPref` | per-account user prefs (`excludeFromAuto`, `priority`); single JSON map, atomic-written on change. The picker layer reads this via `getAccountPrefs(name)` in `loadAllAccountTokens`, so a successful POST to `/api/account-prefs` takes effect on the next pick. **`/api/remove` MUST drop the matching entry** — recreating an account with the same name later otherwise revives stale flags. |
| `viewer-state.json` | `saveViewerState()` (`/api/viewer-state` POST) | persisted token-usage scrubber state (`{start, end, tierFilter}`). Single JSON object, atomic-written. Was added in Phase C without being added to the runtime-state table or `.gitignore` — exactly the regression `session-history.json` had. |
| `.dashboard.pid` | `vdm dashboard start` | PID file for the foreground-launched dashboard |

Account credentials no longer live as plaintext JSON files — they're keychain entries (see "Credential storage" above). The remaining files in `accounts/` are just `*.label` text files. These all use atomic-rename writes in the helpers; don't write directly with `writeFileSync` from new code — copy the existing pattern.

**Gitignore invariant for this table.** Every filename listed above is gitignored in `.gitignore`. When adding a new runtime state file, add it to `.gitignore` in the same commit — historical drift between this table and `.gitignore` (e.g. `session-history.json` and `account-prefs.json` were documented as runtime state but missing from gitignore until commit a867229) is the bug that lets per-install state leak into PRs. A quick `grep -c '<filename>' .gitignore` before merging is enough.

### OAuth refresh

`OAUTH_TOKEN_URL` defaults to `https://console.anthropic.com/v1/oauth/token` (Anthropic retired the older `platform.claude.com` host during the platform→console migration; the old URL silently 404s and refreshes against it never recover), `OAUTH_CLIENT_ID` defaults to a hardcoded UUID. Both are overridable via env var — that's the only way the integration tests in `test/api.test.mjs` work (they spin up a `createMockOAuthServer` on a random port and point `OAUTH_TOKEN_URL` at it). The refresh is a JSON POST (not form-encoded — that was a bug fix, see commit 815bd66). `REFRESH_BUFFER_MS = 1 hour` controls proactive refresh; `REFRESH_MAX_RETRIES = 3` controls retry loops. `createPerAccountLock()` from `lib.mjs` serialises refreshes per account so two concurrent requests can't double-spend a refresh token.

### Rotation strategies

Defined in `lib.mjs` as `ROTATION_STRATEGIES` and implemented by `pickByStrategy()`: `sticky` (only on 429/401), `conserve` (drain already-active windows first, leave dormant accounts dormant — this is the default in `DEFAULT_SETTINGS`), `round-robin` (every N minutes), `spread` (always lowest utilization), `drain-first` (highest 5h utilization first). When you add or change a strategy, update both `ROTATION_STRATEGIES` (the metadata) and `pickByStrategy` (the dispatch) and the UI's strategy dropdown in `renderHTML()`.

#### Per-account `excludeFromAuto`

Every picker function in `lib.mjs` (`pickBestAccount`, `pickConserve`, `pickDrainFirst`, `pickAnyUntried`) routes through the `_isPickable(a, excludeTokens, stateManager)` helper which filters out accounts where `a.excludeFromAuto === true`. The flag flows from `account-prefs.json` → `getAccountPrefs(name)` → `loadAllAccountTokens()` (attaches the field on each account object) → picker layer.

Two important semantics that aren't obvious from the field name:

1. **"Exclude from auto-PICK", not "force-rotate-away"**. `pickByStrategy` has a guard right after the unavailable-fallback branch: if the current account is excluded BUT still available, return `{account: null, rotated: false}` regardless of strategy. Otherwise every poll would force-rotate-away (because the picker filters the current account out of candidates → returns a different account → `rotated: true`). The flag is meant to mean "don't auto-PICK me next time", not "force-rotate me out NOW."
2. **Recovery rotation still wins.** When the current account is rate-limited or expired, `pickBestAccount(accounts, stateManager, excludeTokens)` is called UNCONDITIONALLY before the excluded-sticky guard. If it returns a non-excluded candidate, we rotate; if every candidate is excluded too, we return null and the proxy surfaces the failure — no force-rotation onto an excluded account ever happens.

Manual switches via `/api/switch` and `vdm switch <name>` bypass these helpers entirely, so excluded accounts can still be reached on demand.

When you add a new picker variant, route it through `_isPickable` (don't reimplement the filter) and add a test that asserts excluded accounts are skipped — `test/lib.test.mjs` has the pattern under `describe('pickXxx — excludeFromAuto', ...)`.

### Hooks installed into the user's machine

`install-hooks.sh` is sourced by `install.sh`/`uninstall.sh` and on every `vdm` startup (the migration block at the top of `vdm` re-installs hooks if they're missing). It installs:

1. **Claude Code hooks** into `~/.claude/settings.json`, posting to the dashboard's session-tracking endpoints via curl. **Hooks are `type: "command"`, NOT `type: "http"`** — that distinction is load-bearing (see "Why command hooks, not HTTP hooks" below). Each command embeds the dashboard URL plus the literal sentinel marker `# __VDM_HOOK__` (a shell comment, ignored at runtime) so install/uninstall can identify "this entry belongs to vdm" regardless of port changes or command-string drift. The Python rewriter in `install-hooks.sh` recognises BOTH the legacy http-type entries (pre-Phase-I) AND the new command-type entries when deduping/uninstalling, so a mixed-state install (partial upgrade interrupted) cleans up fully on the next run. The full subscription set is:
   - `UserPromptSubmit` — anchor a session and stamp the active git repo + branch on every prompt. (NOTE: `SessionStart` is intentionally NOT subscribed via HTTP — the spec only allows `type: "command"` or `type: "mcp_tool"` for SessionStart, so HTTP entries are silently rejected. UserPromptSubmit covers the same signal with at most one prompt of latency.)
   - `Stop` / `StopFailure` / `SubagentStop` / `SessionEnd` — close out a turn (or sub-agent fan-out) so the input/output token totals are flushed before the next turn starts.
   - `SubagentStart` — pairs with `SubagentStop` so parallel sub-agent fan-outs get their tokens attributed to the right repo+branch instead of being silently dropped. The spec carries `agent_id` (per-instance ID) and `transcript_path`; **no `parent_session_id` is in the payload** — parent attribution is best-effort via cwd matching at handler time, or via tail-reading the `transcript_path` JSONL.
   - `PreCompact` / `PostCompact` — record context-compaction boundaries so the running input-token math doesn't double-count messages that Claude Code has just collapsed. Note: the spec payload does NOT carry `preTokens` / `postTokens` (those come from the subagent transcript JSONL `compactMetadata` block); parsers tolerate them missing.
   - `CwdChanged` — re-resolves the active branch when a session `cd`s between turns, keeping branch attribution fresh in long-lived sessions.
   - `PostToolBatch` (gated) — opt-in per-tool token attribution; enable by setting `perToolAttribution: true` in `config.json` (or the equivalent UI toggle). Off by default because it materially increases the size of `token-usage.json`. **Spec field is `tool_calls`**, not `tools` — vdm reads both for forward-compat.
   - **Phase E additions:** `WorktreeCreate` / `WorktreeRemove` (worktree-aware token attribution), `TaskCreated` / `TaskCompleted` (task-tracker integration), `TeammateIdle` (parallel sub-agent fan-out coverage).
   - **Phase G additions:** `Notification` (auth_success → invalidate keychain caches; other types → activity feed), `ConfigChange` (detects external rewrites of settings.json), `UserPromptExpansion` (logs `/skill-name` and `@`-mention expansion in the activity feed).
2. **Global git `prepare-commit-msg` hook** in `git config --global core.hooksPath` (created at `~/.config/git/hooks/` if not already set). It chains to any pre-existing repo-local or global hook, then queries `/api/token-usage` and appends a `Token-Usage:` trailer. Look for `_VDM_HOOKS_MARKER` and `_VDM_HOOKS_PATH_MARKER` to see how it tracks ownership for clean uninstall.

#### Why command hooks, not HTTP hooks (Phase I)

Pre-Phase-I, vdm shipped 18 `type: "http"` hooks. CC's HTTP-hook implementation logs `ECONNREFUSED` loudly on every event when the dashboard is not responding, with no way to silence it. That meant:
- Any time the dashboard wasn't up (not started yet, crashed, port collision, mid-restart), every CC session globally spammed `Stop hook error: ECONNREFUSED` and `UserPromptSubmit hook error: ECONNREFUSED` on every prompt, every stop, every event — across every running session, until those shells restarted and the rc snippet's auto-start kicked in.
- The non-atomic install made this guaranteed on first install: hooks landed in `~/.claude/settings.json` (read instantly by every CC session) before the dashboard was started (only happens on new shells via the rc snippet). Existing CC sessions broke immediately.

Phase I switches to `type: "command"` hooks built like:
```bash
curl -sS --connect-timeout 1 --max-time 3 -X POST -H 'Content-Type: application/json' --data-binary @- http://localhost:$VDM_PORT/api/session-start >/dev/null 2>&1 || true  # __VDM_HOOK__
```
The `>/dev/null 2>&1 || true` swallows curl's exit code AND its stderr — CC sees a successful exit and logs nothing. Token tracking degrades gracefully when the dashboard is unreachable instead of spamming errors. Tradeoff: each event spawns sh+curl (~20-50ms vs the previous ~1-5ms HTTP-direct), but hooks are not on the request hot path, so this is acceptable.

Phase I also makes `install.sh` **atomic**: it starts the dashboard in the background and polls `http://localhost:$port/health` (added to BOTH the dashboard server and the proxy server) for up to 10 seconds before calling `install_hooks`. If the dashboard fails to come up, the orphan PID is killed and the install aborts WITHOUT touching `settings.json` — there is no longer any window where hooks exist while the dashboard does not.

If you change the hook payload format, update both ends in lock-step: the writer in `install-hooks.sh` and the reader in the `/api/session-*` handlers and `cmd_tokens` in `vdm`. If you ever revisit the http-vs-command choice, **re-read the section above first** — the choice is deliberate and the failure mode is severe.

## Testing

Tests use Node's built-in `node:test` and `node:assert/strict` — no Jest, no mocha, no test config. Two files:

- `test/lib.test.mjs` — unit tests against the pure functions in `lib.mjs`. Add tests here when you add a function to `lib.mjs`.
- `test/api.test.mjs` — integration tests for the OAuth refresh flow against an in-process mock OAuth server (`createMockOAuthServer`). The pattern is: spin up the mock on `127.0.0.1:0` (random port), point `OAUTH_TOKEN_URL` at it via env, run the flow, assert. Use this pattern for any new test that exercises an outbound HTTP call — never let tests touch the real Anthropic or `console.anthropic.com` endpoints.

There is currently no integration test that exercises the full proxy server end-to-end; the proxy is only covered indirectly through `lib.mjs` units. If you find yourself testing proxy logic, first check whether the logic can be extracted to `lib.mjs` as a pure function.

## Conventions worth knowing

- **Zero dependencies is a hard rule.** No `package.json`, no `node_modules/`. If you need something, write it (the project ships its own activity-log ring buffer, utilization-history with sampling, per-account mutex, etc. for this reason).
- **Two parallel implementations of the same helpers** exist in `vdm` (bash + python3 one-liners) and `dashboard.mjs` (Node) — `detectKeychainService`, `getFingerprint`, `read/writeKeychain`, etc. They MUST stay in sync; if you change behaviour in one, change the other.
- **The dashboard HTML is in `renderHTML()` in `dashboard.mjs`** as a template string. There is no build step or framework — vanilla JS, fetch calls to `/api/*`. UI changes go directly in that function.
- **Accounts are auto-discovered**, not manually added. `autoDiscoverAccount()` runs on every proxy request (and on hooks) — it reads the active keychain entry (`Claude Code-credentials`), hashes the access token to a fingerprint, and creates a new `vdm-account-auto-N` keychain entry if no saved account matches. The `vdm add` command is mostly a fallback for headless/CI flows. Don't add a manual-add UI without understanding why discovery is the primary path.
- **Slash commands** ship in `commands/` (e.g. `commands/vdm-switch.md`). `install.sh` copies every `commands/*.md` to `~/.claude/commands/` so they're invokable as `/vdm-switch`. `uninstall.sh` removes only the `.md` files we own (matched by source-dir basename). When adding a new slash command, drop the file in `commands/` — install.sh's copy step picks it up automatically.
- **Ports are configurable via `CSW_PORT` (dashboard) and `CSW_PROXY_PORT` (proxy)** — always read them from env, don't hardcode 3333/3334 in new code. Both `vdm` and `dashboard.mjs` honour these.
- **Proxy queue + timeout knobs (Phase F) are env-var configurable** — read once at `dashboard.mjs` startup. Defaults reflect lessons from the Phase F audit (the 45 s deadline + per-account permit released at headers were causing false rate-limits and "Anthropic unresponsive" reports). Tunable via:
  - `CSW_PROXY_TIMEOUT_MS` — idle socket timeout per upstream call (default 900000 = 15 min). Bump if Opus 4 extended-thinking phases produce SSE gaps wider than this.
  - `CSW_REQUEST_DEADLINE_MS` — wall-clock cap on a single `handleProxyRequest` (incl. retries) (default 600000 = 10 min). Only checked at retry boundaries, NOT during a successful first-attempt stream.
  - `CSW_MAX_INFLIGHT_PER_ACCOUNT` — concurrent streams per bearer token (default 8). Now actually enforced for stream lifetime — `forwardToAnthropic` holds the per-account permit until `end`/`error`/`close` fires on the response, not just until headers arrive. Pre-Phase-F this cap was silently bypassed for streams (which is 100% of CC traffic).
  - `CSW_MIN_INTERVAL_PER_ACCOUNT_MS` — minimum gap between successive dispatches against one bearer (default 100 ms ≈ 10 RPS).
  - `CSW_MAX_PERMIT_WAIT_MS` — how long a queued request waits for a permit before failing (default 300000 = 5 min). Combined with `CSW_REQUEST_DEADLINE_MS`, this means high-load queueing no longer manufactures false 504s.
  - `CSW_QUEUE_TIMEOUT_MS` — how long a request waits in the settings-level serialization queue before being rejected with `queue_timeout` 503 (default = `CSW_REQUEST_DEADLINE_MS + 60_000` = 660 s). MUST be ≥ `CSW_REQUEST_DEADLINE_MS`, otherwise queued requests get rejected before the deadline guard fires (re-introduces the audit B1/G1 regression — token tracking silently breaks because rejected requests never reach `forwardToAnthropic`/`recordUsage`). Setting it to 0 enables instant rejection (test mode); the dashboard logs a warn at startup if the configured value is below the deadline. Honored by `createSerializationQueue` in `lib.mjs` via the `??` operator so an explicit 0 is preserved.
- **Serialize-mode auto-safeguards (`createSlidingWindowCounter` in `lib.mjs`).** Three independent breakers watch for the failure modes serialize mode produces in production. All read live settings on every check; `settings.serializeAutoDisableEnabled` (default `true`) is the master switch — set to `false` if the user explicitly wants serialize on through hell or high water (alerts still fire, but the auto-toggle won't).
  - **Breaker A — `queue_timeout` 503 burst:** counts queue-rejection 503s in a sliding window. Default trip = 5 within 10 min (`queueTimeoutBreakerThreshold`, `queueTimeoutBreakerWindowMs`). On trip, sets `settings.serializeRequests = false`, drains the queue, and emits `serialize-auto-disabled` activity event with `reason='queue_timeout breaker tripped'`. Wired at the queue_timeout catch handler (line ~10330).
  - **Breaker B — sustained queue depth alert:** informational only, NEVER auto-disables. Polls `getQueueStats().queued` every 5s; when it stays above `queueDepthAlertThreshold` (default 50) for `queueDepthAlertSustainMs` (default 60s), emits `queue-depth-alert` activity event + log warn. Doesn't auto-disable because legitimate burst traffic produces deep queues without indicating a problem.
  - **Breaker C — all-accounts-429 burst:** tracks 429s by account fingerprint over a sliding window. When EVERY known account fingerprint has been seen 429-ing within `all429BreakerWindowMs` (default 60s) AND serialize is on, auto-disables serialize. Single-account installs cannot trip this (it would just mean "the only account is rate-limited", not a serialize symptom). Wired at the 429-handling branch (line ~10708).
  - **Debounce:** `_autoDisableSerialize` debounces at 30s — two rapid trips (queue_timeout + all-429 in close succession) emit only the first event. Counter state is reset on trip so a re-enable doesn't immediately re-trip on the same recorded events.
  - **Source-grep XSS regression** in `test/lib.test.mjs` covers the new `serialize-auto-disabled` and `queue-depth-alert` evtMsg cases (every dynamic field routed through `h(...)`).
- **Settings-level serialization queue is a SEPARATE layer from the per-account permits above.** The per-account permits (`CSW_MAX_INFLIGHT_PER_ACCOUNT`) cap concurrent streams *per bearer token*. The settings-level queue is the user-toggleable `serializeRequests` setting — it caps concurrent in-flight requests *globally across all accounts* via `serializeMaxConcurrent` (default 1 = strict serialization). Backed by `createSerializationQueue()` in `lib.mjs`. The earlier in-file implementation in `dashboard.mjs` had an `inflight === 0` early-return bypass that broke under sustained load: with 15+ concurrent CC clients, every time the queue's 200 ms dispatch timer was waiting to fire, a fresh request whose inflight counter was momentarily 0 would bypass the queue and run alongside the queue's own pending dispatch. Steady-state symptom was the user observing 18 inflight + 54 queued in the dashboard's queue-stats display — `inflight` was supposed to be 1 but bypass requests piled up. The factory removes the bypass entirely: when `serializeRequests` is on, every request goes through the queue and inflight is HARD-CAPPED at `serializeMaxConcurrent`. UI exposes both the delay (`serializeDelayMs`, 0–2000 ms) and the cap (`serializeMaxConcurrent`, 1–16). Strict default = 1 because most vdm users are running multiple CC clients on a single bearer; pipelining is opt-in only when you have multiple accounts. Use `vdm dashboard` → Settings tab → "Request Serialization" to tune, or `vdm config serialize-max-concurrent N` from the CLI (note: CLI changes don't propagate to a running dashboard until restart — same caveat as every other `vdm config` key).
- **Phase H — OTLP/HTTP/JSON receiver (opt-in)** for cross-checking vdm's hook-derived counts against Claude Code's first-party telemetry. Off by default. Enabled via:
  - `CSW_OTEL_ENABLED=1` — opens a third HTTP listener on `CSW_OTLP_PORT` (default 3335) accepting `POST /v1/logs` and `POST /v1/metrics` (OTLP/HTTP/JSON only — protobuf is rejected with 415 because vdm refuses to add a protobuf dependency). The user must additionally configure Claude Code to push telemetry there: `CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_LOGS_EXPORTER=otlp`, `OTEL_METRICS_EXPORTER=otlp`, `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3335`. vdm does NOT auto-mutate `~/.claude/settings.json` to enable this — telemetry has privacy implications (the `claude_code.user_prompt` event carries prompt text when `OTEL_LOG_USER_PROMPTS=1`).
  - `CSW_OTLP_PORT` (default 3335).
  - `CSW_OTEL_BUFFER_MAX` (default 5000) — ring-buffer cap for both logs and metrics. In-memory only; not persisted to disk.
  - Query API: `GET /api/otel-events?kind=logs|metrics|both&name=<filter>&since=<ms>&limit=<N>`. Returns `{enabled, stats, logs[], metrics[]}`.
  - Parsers (`parseOtlpLogs`, `parseOtlpMetrics`, `unwrapOtlpValue`, `otlpAttrsToObject`) live in `lib.mjs` for unit-testability.
- **Proxy-internal errors return 503 + `x-vdm-proxy: true` + `[vdm proxy]` message prefix**, NOT 504 + `timeout_error`. The old 504/timeout_error shape made Claude Code interpret the proxy's own queue/deadline failures as upstream Anthropic problems ("Anthropic unresponsive", "rate limited"). The 503 + `overloaded_error` shape signals "transient backpressure, retry after N seconds" — which is what the proxy actually means.
- **Activity log is a ring buffer** capped at 500 entries / 7 days (`ACTIVITY_MAX_ENTRIES`, `ACTIVITY_MAX_AGE`). Don't log per-request — log state transitions (switch, rate-limit, refresh, settings change). The set of allowed event types is the `case` list in `renderHTML()` around the activity feed renderer.
- **Hop-by-hop header rules are explicit.** `HOP_BY_HOP` in `lib.mjs` lists the headers that get stripped on forward. `accept-encoding` is stripped intentionally so the proxy can read uncompressed error bodies — don't "fix" that.
- **The `.janitor/` directory at the repo root is not a project source folder** — it's runtime state for the `ai-maestro-janitor` plugin used in this user's Claude Code setup, unrelated to vdm's own code. Leave it alone.
- **`_runGitCached` is the hot-path git wrapper** (30s TTL on success, 5s on error, FIFO eviction at 200 entries). Every UserPromptSubmit / SSE response / periodic timer fires through it. Never call `_runGit` directly from a hot path — the cache is what keeps `git rev-parse` from blocking the event loop on every poll. The wrapper rejects non-absolute or `>4096`-char `cwd` values so a hostile `/api/session-start` payload can't churn the cache by spamming unique strings. When mutating worktree state from inside the dashboard, call `_invalidateRunGitCache(cwd)` (or pass `null` for a full clear) so subsequent reads see fresh state — see the `/api/worktree-remove` handler for the pattern.
- **XSS-escaping discipline inside `renderHTML()`**. The dashboard binds to localhost only, but the `renderHTML` template builds HTML strings via `+` concatenation, and several fields are user-controlled (account labels from `vdm label` or auto-discover's `organization_name`, error strings from refresh-failed events, etc.). Two helpers exist:
  - `escHtml(s)` — full HTML entity escape for any field rendered with `<span>...` style interpolation.
  - `displayNameJs` — single-quote-as-JS-string escape, used INSIDE `onclick="doSwitch('...','...')"` so the toast still shows readable apostrophes.
  - `evtMsg` defines a local `h(...)` alias and routes every dynamic field through it.
  Source-level regression tests in `test/lib.test.mjs` (`describe('XSS regression — ...')`) read `dashboard.mjs` and grep for the dangerous shape `+ e.<field>` outside an `h(...)` wrap. New event types or new card fields that interpolate user data MUST go through `escHtml` / `h` or those tests fail.
- **Backtick-in-comment trap inside the `renderHTML` template literal.** `renderHTML()` returns a SINGLE backtick-quoted template string from line ~2446 to ~6500. Any `` ` `` inside that range — even inside a `// JS comment` — terminates the template literal early and produces cascading parse errors. Don't use markdown-style backticks for inline code in comments inside `renderHTML`. Use plain-text wording (`the prev* variables`, `on the API endpoint`) or HTML entities (`&#39;`) instead. There's a regression grep — `awk 'NR>=2446 && NR<=6900 && /\/\/.*\`/'` — that should run zero hits.
- **`readBody(req, maxBytes = READ_BODY_MAX)` caps every POST body at 1 MiB.** Tracks bytes during `req.on('data')`, destroys the socket with a tagged `Error.code = 'E_BODY_TOO_LARGE'` when exceeded. Without this, a same-origin browser tab could DoS the dashboard by POSTing multi-MB JSON to any `/api/*` endpoint. If you ever need a larger body for a specific endpoint, pass an explicit `maxBytes` — don't bump the global default.
- **`_resolveBinary(name)` pins absolute paths for `osascript` and `notify-send` at startup** to defend against PATH-hijack (`~/.local/bin/notify-send` could otherwise intercept account labels and error strings on every rotation event). On macOS, `/usr/bin/osascript` is hardcoded first; Linux uses `/usr/bin/which` (or `/bin/which`) to capture the path once. Never re-resolve at notification time, never call `execFile('osascript', ...)` with a bare name.
- **Per-card hash diffing in `renderAccounts`.** `_renderedCardCache` (a `Map<safeName, hash>`) tracks the previously-rendered card hashes; on each refresh, only cards whose hash changed get rewritten via `outerHTML`. The set of names + their order is also compared — if either changes, full `innerHTML` replacement falls back. The OUTER `quickHash(profiles)` gate (line ~5057 in the refresh loop) skips the entire `renderAccounts` call when nothing visible changed.
- **`quickHash` schema-detects on the first array entry.** If it has `inputTokens` / `outputTokens` / `cacheReadInputTokens` / `cacheCreationInputTokens` (token-usage row shape), it uses the FNV-1a 32-bit fast path. Otherwise it falls back to `JSON.stringify(obj)` — required for profile arrays whose discriminating fields don't match the usage-row schema. **Never make the FNV-1a path field-set narrower without verifying every caller's data shape**; the previous regression silently broke `_lastProfilesHash` checks because profile fields didn't include any of the FNV folds.

## What disables vdm (Phase G research findings)

These are external conditions vdm CANNOT override — only detect and warn:

- **`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_OAUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_OAUTH_REFRESH_TOKEN`** — any one of these in the user's shell makes Claude Code read its token from the env, NOT the keychain. vdm's whole credential-rotation model becomes a no-op (the proxy still forwards traffic, but every request uses the env-supplied token regardless of which "active account" vdm picks). `install.sh` warns at install time.
- **`CLAUDE_CODE_USE_BEDROCK` / `USE_VERTEX` / `USE_FOUNDRY` / `USE_MANTLE`** — routes Claude Code to a non-Anthropic backend. The proxy is bypassed entirely, vdm has zero visibility. `install.sh` warns.
- **`auto` permission mode** — unavailable when `ANTHROPIC_BASE_URL` is non-default. Per the spec: "Provider: Anthropic API only. Not available on Custom API endpoints via ANTHROPIC_BASE_URL." vdm users get the "auto unavailable" message; there's no recovery path while the proxy is active. Use `default` / `acceptEdits` / `plan` / `bypassPermissions` instead.
- **`claude --bare` / `CLAUDE_CODE_SIMPLE=1`** — bare mode skips ALL hook auto-discovery, ALL CLAUDE.md loading, and reads only `ANTHROPIC_API_KEY` / `apiKeyHelper` (NOT the keychain). vdm hooks don't fire; the proxy may still see traffic if the env var is set, but token attribution is silently absent for bare-mode turns.
- **`allowManagedHooksOnly: true`** in managed settings (`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS) — every user-level hook is silently dropped. vdm hooks stop firing; the proxy still works. `install-hooks.sh` warns at install time. Can be unblocked by an admin adding `"allowedHttpHookUrls": ["http://localhost:3333/*"]` to managed settings.
- **`disableAllHooks: true`** in managed settings — same effect, blanket disable.
- **Server-managed settings are bypassed** as a side effect of vdm setting `ANTHROPIC_BASE_URL` (per the spec). Enterprise users running on managed devices should know that vdm subverts their managed-settings policy — this is architectural, not a bug.

### Spec compliance notes (Phase G)

- **Hook payload schema drift fixed in Phase G:** `parsePostToolBatchPayload` now reads `data.tool_calls` (spec field), not `data.tools` (vdm-internal name); `parseSubagentStartPayload` exposes `agent_id`; `parseTaskEventPayload` exposes `task_title` / `task_description`; `parseTeammateIdlePayload` exposes `agent_id` / `agent_type`. All parsers keep legacy field-name fallbacks so old test fixtures still pass.
- **Pricing table covers `claude-opus-4-7`, `claude-sonnet-4-7`, `claude-haiku-4-6`** plus the 4-5/4-6 generations. Cache token rates (`cacheRead`, `cacheCreation`) follow Anthropic's published 1.25x (creation) / 0.10x (read) ratios. Unknown-model hits log to the activity feed on first occurrence so the rate table can be kept current. Verify rates against `https://claude.com/pricing` when bumping versions.
- **macOS Keychain credential storage is NOT documented in the public spec.** The service name `Claude Code-credentials` is an undocumented implementation detail that has changed before. `detectKeychainService()` (in both `vdm` and `lib.mjs`/`dashboard.mjs`) is the canonical fallback pattern; never hardcode the service name in new code.
- **Claude Code's keychain-cache TTL is 30 seconds** (raised from 5s in v2.1.86). After `vdm switch`, the new account may not be visible to a running Claude Code session for up to 30s. Document in `vdm switch` output if users hit this.

### `/api/account-prefs` — per-account preferences endpoint

GET returns `{ ok: true, prefs: <map> }` where `<map>` is the full `_accountPrefs` object (small JSON, bounded by account count).

POST accepts `{ name, key, value }` and persists via `setAccountPref(name, key, value)`. Validation rules (enforced in both the handler and the helper):

- `name` must match `/^[a-zA-Z0-9._@-]+$/` and not equal the reserved `"index"` — same allow-list as `vdmAccountServiceName` so we can't be tricked into mutating an unrelated key.
- `key` must be exactly `excludeFromAuto` (boolean) or `priority` (finite number). Anything else throws.
- A successful POST calls `invalidateAccountsCache()` so the next picker call sees the new flag without waiting for the cache TTL.

CSRF protection: the global Origin allow-list at `dashboard.mjs:~6960` rejects mutating requests from foreign origins. The endpoint also relies on the `readBody` 1 MiB cap (see `READ_BODY_MAX` above).

The corresponding CLI is `vdm prefs [name [key val]]` — fetches the same endpoint via `curl` and renders a small Python-formatted listing. CLI requires the dashboard to be running because the prefs file is owned by the dashboard process to avoid write conflicts (vdm could in theory read the file directly, but writing it would race the dashboard's atomic-rename pattern).
