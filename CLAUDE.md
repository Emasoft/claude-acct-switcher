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
vdm list | switch | remove | status | config | dashboard | logs | tokens | upgrade
```

There is **no build step, no bundler, no package.json, no lockfile, no linter**. The whole project is plain Node.js using only built-in modules plus bash. Don't add dependencies — that's a deliberate constraint (see Architecture below).

Requires Node 18+, macOS (uses Keychain), and `python3` (used by `vdm` and `install-hooks.sh` for JSON munging).

## Architecture

Three source files do all the work. Understand these and you understand the whole project:

- **`vdm`** (bash, ~1150 lines) — user-facing CLI. Dispatches to `cmd_*` functions; talks to the macOS Keychain via `security(1)` and to the dashboard's HTTP API for anything stateful. The `case` block at the bottom of the file is the command map.
- **`dashboard.mjs`** (Node, ~4360 lines) — runs **two HTTP servers in one process**: the web dashboard (default port 3333, all the `/api/*` routes plus the embedded HTML in `renderHTML()`) and the API proxy (default port 3334, `handleProxyRequest`). Holds all I/O, timers, and global state. The HTML/CSS/JS for the UI is a single template string returned by `renderHTML()` — there is no separate frontend.
- **`lib.mjs`** (Node, ~560 lines) — pure functions only, zero side effects. Anything testable lives here: fingerprinting, header rewriting (`buildForwardHeaders`/`stripHopByHopHeaders`), the `createAccountStateManager`/`createUtilizationHistory`/`createProbeTracker`/`createPerAccountLock` factories, rotation-strategy logic (`pickByStrategy` and friends), and OAuth-refresh helpers. **When adding logic that can be expressed as a pure function, put it in `lib.mjs` and unit-test it in `test/lib.test.mjs`** — that's how the existing code is structured.

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
| `.dashboard.pid` | `vdm dashboard start` | PID file for the foreground-launched dashboard |

Account credentials no longer live as plaintext JSON files — they're keychain entries (see "Credential storage" above). The remaining files in `accounts/` are just `*.label` text files. These all use atomic-rename writes in the helpers; don't write directly with `writeFileSync` from new code — copy the existing pattern.

### OAuth refresh

`OAUTH_TOKEN_URL` defaults to `https://console.anthropic.com/v1/oauth/token` (Anthropic retired the older `platform.claude.com` host during the platform→console migration; the old URL silently 404s and refreshes against it never recover), `OAUTH_CLIENT_ID` defaults to a hardcoded UUID. Both are overridable via env var — that's the only way the integration tests in `test/api.test.mjs` work (they spin up a `createMockOAuthServer` on a random port and point `OAUTH_TOKEN_URL` at it). The refresh is a JSON POST (not form-encoded — that was a bug fix, see commit 815bd66). `REFRESH_BUFFER_MS = 1 hour` controls proactive refresh; `REFRESH_MAX_RETRIES = 3` controls retry loops. `createPerAccountLock()` from `lib.mjs` serialises refreshes per account so two concurrent requests can't double-spend a refresh token.

### Rotation strategies

Defined in `lib.mjs` as `ROTATION_STRATEGIES` and implemented by `pickByStrategy()`: `sticky` (only on 429/401), `conserve` (drain already-active windows first, leave dormant accounts dormant — this is the default in `DEFAULT_SETTINGS`), `round-robin` (every N minutes), `spread` (always lowest utilization), `drain-first` (highest 5h utilization first). When you add or change a strategy, update both `ROTATION_STRATEGIES` (the metadata) and `pickByStrategy` (the dispatch) and the UI's strategy dropdown in `renderHTML()`.

### Hooks installed into the user's machine

`install-hooks.sh` is sourced by `install.sh`/`uninstall.sh` and on every `vdm` startup (the migration block at the top of `vdm` re-installs hooks if they're missing). It installs:

1. **Claude Code hooks** into `~/.claude/settings.json`, pointing at the dashboard's session-tracking endpoints. Hook entries are matched by URL marker so re-install is idempotent. The full subscription set is:
   - `UserPromptSubmit` — anchor a session and stamp the active git repo + branch on every prompt. (NOTE: `SessionStart` is intentionally NOT subscribed via HTTP — the spec only allows `type: "command"` or `type: "mcp_tool"` for SessionStart, so HTTP entries are silently rejected. UserPromptSubmit covers the same signal with at most one prompt of latency.)
   - `Stop` / `StopFailure` / `SubagentStop` / `SessionEnd` — close out a turn (or sub-agent fan-out) so the input/output token totals are flushed before the next turn starts.
   - `SubagentStart` — pairs with `SubagentStop` so parallel sub-agent fan-outs get their tokens attributed to the right repo+branch instead of being silently dropped. The spec carries `agent_id` (per-instance ID) and `transcript_path`; **no `parent_session_id` is in the payload** — parent attribution is best-effort via cwd matching at handler time, or via tail-reading the `transcript_path` JSONL.
   - `PreCompact` / `PostCompact` — record context-compaction boundaries so the running input-token math doesn't double-count messages that Claude Code has just collapsed. Note: the spec payload does NOT carry `preTokens` / `postTokens` (those come from the subagent transcript JSONL `compactMetadata` block); parsers tolerate them missing.
   - `CwdChanged` — re-resolves the active branch when a session `cd`s between turns, keeping branch attribution fresh in long-lived sessions.
   - `PostToolBatch` (gated) — opt-in per-tool token attribution; enable by setting `perToolAttribution: true` in `config.json` (or the equivalent UI toggle). Off by default because it materially increases the size of `token-usage.json`. **Spec field is `tool_calls`**, not `tools` — vdm reads both for forward-compat.
   - **Phase E additions:** `WorktreeCreate` / `WorktreeRemove` (worktree-aware token attribution), `TaskCreated` / `TaskCompleted` (task-tracker integration), `TeammateIdle` (parallel sub-agent fan-out coverage).
   - **Phase G additions:** `Notification` (auth_success → invalidate keychain caches; other types → activity feed), `ConfigChange` (detects external rewrites of settings.json), `UserPromptExpansion` (logs `/skill-name` and `@`-mention expansion in the activity feed).
2. **Global git `prepare-commit-msg` hook** in `git config --global core.hooksPath` (created at `~/.config/git/hooks/` if not already set). It chains to any pre-existing repo-local or global hook, then queries `/api/token-usage` and appends a `Token-Usage:` trailer. Look for `_VDM_HOOKS_MARKER` and `_VDM_HOOKS_PATH_MARKER` to see how it tracks ownership for clean uninstall.

If you change the hook payload format, update both ends in lock-step: the writer in `install-hooks.sh` and the reader in the `/api/session-*` handlers and `cmd_tokens` in `vdm`.

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
