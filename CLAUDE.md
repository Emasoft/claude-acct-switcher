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
| `.dashboard.lock` | dashboard startup singleton mutex (Phase I+) | PID of the canonical running dashboard. Two-instance startups detect a live PID via `process.kill(pid, 0)` and exit cleanly before clobbering state files. Stale PIDs (process gone) are reaped via the ESRCH branch. |
| `events.jsonl` | `logForensicEvent()` (Phase I+) | Append-only JSON Lines forensic log. One line per incident: rate_limit, auth_failure, server_error, client_disconnect, queue_saturation, inflight_escalation, dashboard_start, etc. Each entry carries a stable schema (ts + category + typed payload) so jq / awk / grep work without parsing. Mode 0o600. Daily rotation: snapshots are `events.jsonl.YYYY-MM-DD.gz`; retention is `EVENTS_RETENTION_DAYS = 7`. Rotated at startup + every 6h timer. |
| `startup.log` | `nohup node dashboard.mjs >>$f` (rc-snippet auto-start + install.sh atomic-block) | Captured stdout/stderr from the dashboard process. Same daily-rotate / 7-day-retention policy as `events.jsonl` (snapshots `startup.log.YYYY-MM-DD.gz`). Rotation truncates the active file via `writeFileSync(STARTUP_LOG_FILE, '', { mode: 0o600 })` so the open-fd append stream from `nohup` writes to the new active file (the renamed snapshot keeps the historical bytes). |

Account credentials no longer live as plaintext JSON files — they're keychain entries (see "Credential storage" above). The remaining files in `accounts/` are just `*.label` text files. These all use atomic-rename writes in the helpers; don't write directly with `writeFileSync` from new code — copy the existing pattern.

**Gitignore invariant for this table.** Every filename listed above is gitignored in `.gitignore`. When adding a new runtime state file, add it to `.gitignore` in the same commit — historical drift between this table and `.gitignore` (e.g. `session-history.json` and `account-prefs.json` were documented as runtime state but missing from gitignore until commit a867229) is the bug that lets per-install state leak into PRs. A quick `grep -c '<filename>' .gitignore` before merging is enough.

### TRDD-1645134b — usage tree, cache-miss detection, wasted-spend chart

A 4-level hierarchical breakdown of the Tokens tab plus a heuristic for cache-miss reasons and a wasted-spend chart. All implementation lives in lib.mjs (pure functions) + dashboard.mjs (endpoint + UI).

**Endpoint:** `GET /api/token-usage-tree`. Three response shapes share one URL via query params:
  - **Default JSON:** `{ ok, totals, tree }` — the 4-level tree (`repo → branch/worktree → component → tool`) computed by `aggregateUsageTree`.
  - **JSON with cache info:** add `?includeMisses=1` to also get `misses` (flat per-row miss list), `missSessions` (per-session aggregate with hit-rate), and `wastedSpend` (cache-miss cost time series).
  - **CSV:** add `?format=csv` to stream a tree-aggregated CSV (one row per `(repo, branch, component, tool)` bucket with USD cost). Anchored download via Content-Disposition; filename is sanitised to `[A-Za-z0-9_-]` only.

  Common filters (all optional, all also accepted in the JSON branch): `from`, `to`, `since` (alias for `from`), `repo`, `account`, `model`, `minMissInput`. Rejected: `from > to`, negative numeric values. The `from`/`to` time-range filter when used with `includeMisses=1` preserves rows of `type === 'compact_boundary'` (those drive Phase 5 reason classification — see below).

**`MODEL_PRICING` table** lives in `lib.mjs` and mirrors `TOK_PRICING` in `dashboard.mjs`. **MUST stay in sync** — both list the same 8 generations (opus/sonnet/haiku 4-5..4-7) with the same per-1M-token rates. Cache rates follow Anthropic's 1.25x (creation) / 0.10x (read) ratios; the regression test asserts that ratio so single-column hand-edits trip. Unknown models fall back to `MODEL_PRICING_DEFAULT` (Sonnet rates) which is "median", NOT "conservative" — it under-prices Opus and over-prices Haiku, so add new model entries promptly when Anthropic ships them.

**Cache-miss heuristic** in `buildCacheMissReport`: groups by `sessionId`, classifies each miss into one of four reasons in this priority order:
  1. `compact-boundary` — a `compact_boundary` row preceded the miss in the same session. **The production type-string is `compact_boundary` (NOT `compact`)** — that's what `buildCompactBoundaryEntry` writes to `token-usage.json`. An earlier draft used `'compact'` and the classifier was dead code (see audit SR-OP-001 in `reports/audit/`).
  2. `model-changed` — the prior cache-creating row was on a different model (caches are model-scoped).
  3. `TTL-likely` — gap exceeds `CACHE_TTL_LIKELY_MS` (5 min, matching Anthropic's documented prompt-cache TTL). Configurable via `opts.cacheTtlMs`.
  4. `unknown` — could be `/clear`, OAuth-rotation gap, or a real prefix change. Heuristic admits ignorance.

`summarizeCacheMissesBySession` builds the per-session UI aggregate (hits/misses/hit-rate). It drops sessions with neither hits nor misses (denominator-symmetric: a hit requires `cacheRead > 0 && input >= minInput`, mirroring the miss threshold). Both functions accept `opts._precomputedMisses` so the endpoint can call `buildCacheMissReport` once and feed all three downstream consumers from the same flat list (perf — see audit CC-DASH-016).

**Wasted-spend chart** (`buildWastedSpendSeries` + `renderWastedSpendChart`): per-miss series with `costUSD` (gross input price) AND `wastedUSD` (savable differential = costUSD − cacheReadCost). Bar heights track `wastedUSD` because that's the actionable metric. Chart honours the same dropdown filters as the rest of the Tokens tab (model/account/repo/branch + scrubber + tier) — without those, the chart would silently disagree with adjacent charts when filters are active (see audit SR-OP-004).

**Two CSV exports** coexist:
  - **Flat** (`exportUsageCsv` button) — one row per API request, raw fields, computed client-side from `_tokensRawData`. Maximum-certainty audit trail. **Body must NOT change** without explicit user approval (power users diff their CSVs week over week).
  - **Tree-aggregated** (`exportUsageTreeCsv` button) — one row per `(repo, branch, component, tool)` bucket with summed `totalCostUSD`, computed server-side. Streams via anchor-download. Falls back to the `tok-time` selector window when the scrubber hasn't been touched.

**Chart-scoped project multi-select** at the top-right of the carousel card: independent of the existing `tok-repo` single-select. localStorage key `vdm.chartProjectFilter` persists the selection (bounded: max 200 items × 1024 chars × 256 KB total to defend against quota poisoning). When the single-select narrows to one repo, the multi-select is disabled with an explanatory hint to prevent the "both filters narrow to disjoint sets → every chart empty" UX trap.

**CSV formula-injection guard:** `csvField` prefixes user-string cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote (CWE-1236, OWASP A03). Numeric cells are NOT prefixed (`-1.5` stays a numeric cell). Sub-agent / skill / repo names from third-party plugins are user-controlled and a hostile name like `=cmd|'/c calc'!A0` would otherwise execute when the operator opens the CSV in Excel.

**Lazy-loading deferred:** the TRDD spec calls for lazy-loading deeper tree levels on `<details>` toggle. Current implementation eager-renders the full tree (acceptable at the current scale where the aggregated tree is well under 1 MB rendered HTML). Re-evaluate if a single user reports >100 repos × 10 worktrees in their data.

**Round-2 audit defenses** (commit on top of the Phase 6 series):
- Tree-refresh hash uses a custom `_treeHash` FNV-1a structural fingerprint instead of `quickHash` (which fell through to `JSON.stringify` on the entire tree because tree nodes lack the FNV schema-marker fields — that allocated multi-MB strings every 5s poll).
- `refreshUsageTree` checks `data.totals` shape before dereferencing `.requests`, so a malformed but `ok:true` response surfaces "missing totals" instead of a cryptic TypeError.
- `chartCarouselGo` defensively clamps `_chartCarouselIdx` against `btns.length` so a shrinking dot count never leaves the carousel with no active dot.
- `parsePostToolBatchPayload` rejects tool names containing `\r`, `\n`, `\x00`, or longer than 256 chars — defense-in-depth against hostile sub-agent metadata that would round-trip through `token-usage.json` into naive line-splitting consumers.
- The endpoint returns `400 Bad Request` for negative `from`/`to` and reversed ranges instead of silently widening the result set.
- `exportUsageTreeCsv` treats either-end-null in the scrubber as both-null (uses the `tok-time` window for both bounds) so the export window matches what the user is currently viewing.
- The multi-select dropdown's stale-prune now also kicks `refreshUsageTree` so the wasted-spend chart's `_wastedSpendRaw` data source gets purged of the gone repo, not just the dropdown options.
- Disabled multi-select labels carry `cpf-item-disabled` class + `aria-disabled="true"` so the locked state is visible (not just behavioural).
- Single-select repo not in the current dataset shows zero rows + an explanatory "no recent data" hint.
- `populateProjectFilterOptions` failure surfaces "Filter unavailable" on the toggle button for 2s (was console.error only).
- `applyChartProjectFilter` and `renderWastedSpendChart` defer to single-select tok-repo when set — without this, a saved multi-select selection that doesn't include the single-select repo silently zeros every chart.
- `buildCacheMissReport` and `buildWastedSpendSeries` propagate `account` through their output rows so the wasted-spend chart's account-filter actually filters (it was a dead predicate before — the field was never produced).
- `csvField` formula-injection trigger set extended to include `\n` (newer LibreOffice/Sheets evaluate cells starting with bare `\n` as formulas in some import paths).
- `classifyUsageComponent` length-caps tool names at 256 chars before regex (CWE-1333 hardening — the regex is linear-time but a pathological 1MB tool name would still consume CPU).
- `renderCacheMisses` derives the reason CSS class via a strict allow-list (`KNOWN_MISS_REASONS`) instead of a regex strip — closes the "fragile by design" XSS sink that would have opened if a future refactor broadened the reason set.
- The `Skill( )` whitespace-only edge case correctly falls through to the mcpServer/`unknown` fallback instead of emitting `skill:` (empty label).

**A11y batch 2 invariants** (UX-X3 / UX-CPF3 / UX-S2):
- Any clickable `<div>` (currently `tok-repo-header` and `session-header`) MUST carry `role="button"`, `tabindex="0"`, and `aria-expanded` reflecting the open/collapsed state. The single capture-phase keydown delegate near `_wireRovingArrowKeys` synthesises a `.click()` on Enter or Space for every `[role="button"][tabindex]` non-`<button>` element. Adding a new clickable div without that attribute set silently locks out keyboard-only users.
- The chart project filter is a WAI-ARIA listbox: `<div id="cpf-list" role="listbox" aria-multiselectable="true">`, each `<label class="cpf-item" role="option" aria-selected="…">`. `toggleProjectInFilter` and `projectFilterSelectAll` MUST update `aria-selected` on the label whenever they flip the inner checkbox — otherwise screen readers announce the previous state. `_wireListboxArrowKeys('#cpf-list', 'input[type="checkbox"]:not(:disabled)')` provides Up/Down/Home/End nav over the items; Tab + Space still own activation natively.
- Chevron CSS rules: `.tok-repo-chevron` and `.session-collapse-indicator` both list `transition: transform 0.15s, color 0.15s` (the `color` part is load-bearing — the hover rules `.{tok-repo,session}-header:{hover,focus-visible} .{tok-repo-chevron,session-collapse-indicator} { color: var(--foreground); }` would otherwise snap instead of fade). Keep colour in the transition list when adding new chevron animations.
- The "no backticks in JS comments inside renderHTML template literal" regression test resolves the template range dynamically (anchored on `function renderHTML()` and `</html>\`;`) instead of hardcoding line numbers — earlier the window silently shrank as renderHTML grew, letting traps slip through past the old upper bound. Don't reintroduce the numeric window.

**UX batch B invariants** (UX-X8 / UX-X9 — time + token-count formatters):
- `lib.mjs` exports `fmtTokenCount(n)` and `fmtDuration(ms)` — BOTH return `{short, exact}` (compact display + full hover-exact form). Defensive: null/undefined/NaN/negative/Infinity all collapse to a safe fallback. Floating-point token counts are floored.
- The `formatNum` and `sessionDuration` legacy helpers in `dashboard.mjs` are now thin wrappers over `fmtTokenCountShort` / `fmtDurationShort` — DO NOT reintroduce parallel formatting logic. The browser-side `fmtTokenCountShort` / `fmtTokenCountExact` / `fmtDurationShort` / `fmtDurationExact` helpers inside the renderHTML template literal MUST stay algorithm-locked to the lib.mjs versions (they're duplicated because the template ships as a string to the browser and can't `import`). The "no drift" regression tests assert delegation.
- Every numeric token-count or duration cell rendered into HTML that uses the compact form ("1.2M", "5m 12s") MUST also carry a `title=` attribute with the exact unabbreviated value (e.g. `title="1,234,567"` / `title="5 minutes 12 seconds"`). Without this, the user can never recover the exact figure that the compact form rounds away. The `tickCountdowns` timer refreshes both `textContent` and `title=` together — keep them in lockstep when adding new live-updating displays.
- Token-count `short` form extends to "B" for billions (long-running sessions cross the 1B boundary). Duration `short` is capped at TWO segments (`3d 5h`, never `3d 5h 17m`) — three-segment renders make the dashboard feel like a stopwatch app.

**UX batch D invariants** (UX-X7 / UX-VS2 — sparklines + scrubber):
- `renderSparkline` MUST scale heights against `Math.max(maxObserved, 1.0)` — partial utilization renders as partial fill, not a full bar. The `1.0` floor is load-bearing: without it a flat-30% history would visually equal a flat-100% history because both would scale to fill.
- The sparkline SVG MUST carry both a `<title>` child element AND `role="img" aria-label` with the same `'Min N% / Max M% over the window'` content (empty-data path: `'No data in window'`). Hover tooltips and screen readers must not diverge.
- Two on-chart `<text>` overlays at `y=6` (peak%) and `y=padT+chartH` (literal `0%`) are always-visible — do NOT gate them on data availability; the `'--'` placeholder for empty data IS the always-visible state.
- Custom scrubber `.vs-thumb` width/height MUST be ≥ 24px (28px shipped). `margin-left` MUST equal `-Math.floor(width/2)` so the thumb stays centred on its track point. `.vs-track-wrap` height MUST be ≥ thumb-diameter + 2× focus-ring width (currently 28+2×3=34, bumped to 44 for headroom).
- BOTH `input[type="range"]::-webkit-slider-thumb` AND `input[type="range"]::-moz-range-thumb` MUST be sized to match `.vs-thumb` so a future stray native range slider can't regress to OS-default 16px. Firefox prefix is the one most likely to be forgotten.

**UX batch E invariants** (UX-L2 / UX-AC1 — Logs/Activity filter UIs):
- Both filter implementations MUST hide non-matching entries via the CSS class toggle (`.evt-hidden` / `.log-line-hidden`), NOT DOM removal. Clearing the filter restores visibility without a re-fetch. The class names are part of the public regression-test contract — don't rename without updating the source-grep.
- User input goes into a `RegExp(...)` constructor when the regex toggle is on — `_vdmCompileFilterRegex` MUST wrap that in try/catch, return `null` on throw, and the renderer MUST show "Invalid regex" inline (with `.error` class for red) AND show all lines so the user isn't staring at an empty pane.
- 256-char hard cap is enforced at THREE levels: `maxlength="256"` on the `<input>`, `.slice(0, 256)` in the input handler, `.slice(0, 256)` in the compile/persist helpers. Defense-in-depth against ReDoS-class patterns + localStorage quota poisoning. The `_VDM_FILTER_MAX_LEN = 256` constant must appear in at least 3 use-sites (regression test enforces this).
- The user pattern lives in `input.value` (DOM-escaped by the browser), is read via `.value`, and is ONLY passed to `RegExp(...)` / `String.indexOf` / `.toLowerCase()`. NEVER concatenate the pattern into `innerHTML`. The count badge writes via `textContent` (not innerHTML). Source-grep regression test enforces no `innerHTML = ... + _vdmFilterLogsPattern` style sinks.
- For SSE-streamed log lines: the `connectLogStream` `onmessage` handler MUST check the active filter against `line.textContent` BEFORE appending the new `<div>` — otherwise the user sees a flicker where the line briefly appears then hides. Filter-on-append, not filter-after-append.
- `_vdmWireFilterControls` MUST check `dataset.vdmWired` so repeated calls (from `switchTab` → `connectLogStream`, from each `renderActivity`) don't double-bind handlers. Without this, every typed character would fire 2× / 3× / N× as the function gets called again.

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
- **Serialize-mode auto-safeguards (`createSlidingWindowCounter` in `lib.mjs`).** Four independent breakers watch the failure modes serialize mode produces in production — three that disable it (A, B alert-only, C) and one that ENABLES it on burst (D). All read live settings on every check; `settings.serializeAutoDisableEnabled` (default `true`) is the master switch covering ALL FOUR — set to `false` if the user explicitly wants full manual control over serialize state (alerts still fire, but the auto-toggle won't). The two "I want auto-X but not auto-Y" toggles are `settings.serializeAutoEnableEnabled` (default `true`, controls Safeguard D only) and the global master switch above.
  - **Breaker A — `queue_timeout` 503 burst:** counts queue-rejection 503s in a sliding window. Default trip = 5 within 10 min (`queueTimeoutBreakerThreshold`, `queueTimeoutBreakerWindowMs`). On trip, sets `settings.serializeRequests = false`, drains the queue, and emits `serialize-auto-disabled` activity event with `reason='queue_timeout breaker tripped'`. Wired at the queue_timeout catch handler (line ~10330).
  - **Breaker B — sustained queue depth alert:** informational only, NEVER auto-disables. Polls `getQueueStats().queued` every 5s; when it stays above `queueDepthAlertThreshold` (default 50) for `queueDepthAlertSustainMs` (default 60s), emits `queue-depth-alert` activity event + log warn. Doesn't auto-disable because legitimate burst traffic produces deep queues without indicating a problem.
  - **Breaker C — all-accounts-429 burst:** tracks 429s by account fingerprint over a sliding window. When EVERY known account fingerprint has been seen 429-ing within `all429BreakerWindowMs` (default 60s) AND serialize is on, auto-disables serialize. Single-account installs cannot trip this (it would just mean "the only account is rate-limited", not a serialize symptom). Wired at the 429-handling branch (line ~10708).
  - **Safeguard D — burst-429 from a SINGLE account → auto-ENABLE serialize.** This is the inverse of A/C: instead of disabling serialize when it's misbehaving, it ENABLES serialize when it should have been on already. Motivation: when multiple Claude Code instances share an account and burst-fire huge payloads in parallel, the account hits 429 within seconds. The naive response (rotate to the next account) just bombards THAT account too, and Anthropic 5h-bans (5000-9000s) cascade across the whole pool. Detection: 3+ 429s on the SAME account within 30s (`_BURST_429_WINDOW_MS = 30_000`, `_BURST_429_THRESHOLD = 3`, both hardcoded — these are emergency-response defaults, not user-tunable). On trip, sets `serializeRequests=true`, ensures `serializeMaxConcurrent ≥ 1`, bumps `serializeDelayMs` to ≥250ms, and emits `serialize-auto-enabled` activity + `serialize_auto_enabled` forensic event + `circuitBreaker` notify (HIGH_PRIORITY → fires regardless of throttle). Skipped if (a) master switch off, (b) serialize already on (don't fight whoever turned it on, especially the user), (c) `serializeAutoEnableEnabled` is false. Wired at the 429-handling branch alongside Breaker C (line ~11586).
  - **Auto-revert for Safeguard D:** `_maybeAutoRevertSerialize` runs on a 60s `setInterval` (unref'd). When `_serializeAutoEnabledAt > 0` (vdm owns the state) AND there's been NO 429 from any account for `_SERIALIZE_AUTO_REVERT_MS` (30 min, hardcoded), it sets `serializeRequests=false`, clears `_burst429ByFingerprint`, drains the queue, and emits `serialize-auto-reverted` activity + `serialize_auto_reverted` forensic. Critical: if the user (or Breaker A/C) turned serialize off while we owned it, the timer detects this and clears `_serializeAutoEnabledAt` instead of fighting them — vdm never re-enables what someone else just disabled. No notification on revert (good news, no action needed).
  - **Debounce:** `_autoDisableSerialize` debounces at 30s — two rapid trips (queue_timeout + all-429 in close succession) emit only the first event. Counter state is reset on trip so a re-enable doesn't immediately re-trip on the same recorded events. Safeguard D doesn't need its own debounce because it can only fire ONCE per quiet-window cycle (the next trip requires both another 3-429 burst AND `serializeRequests` to be off, which only happens after auto-revert).
  - **Source-grep XSS regression** in `test/lib.test.mjs` covers `serialize-auto-disabled`, `serialize-auto-enabled`, `serialize-auto-reverted`, and `queue-depth-alert` evtMsg cases (every dynamic field routed through `h(...)`).
- **Settings-level serialization queue is a SEPARATE layer from the per-account permits above.** The per-account permits (`CSW_MAX_INFLIGHT_PER_ACCOUNT`) cap concurrent streams *per bearer token*. The settings-level queue is the user-toggleable `serializeRequests` setting — it caps concurrent in-flight requests *globally across all accounts* via `serializeMaxConcurrent` (default 1 = strict serialization). Backed by `createSerializationQueue()` in `lib.mjs`. The earlier in-file implementation in `dashboard.mjs` had an `inflight === 0` early-return bypass that broke under sustained load: with 15+ concurrent CC clients, every time the queue's 200 ms dispatch timer was waiting to fire, a fresh request whose inflight counter was momentarily 0 would bypass the queue and run alongside the queue's own pending dispatch. Steady-state symptom was the user observing 18 inflight + 54 queued in the dashboard's queue-stats display — `inflight` was supposed to be 1 but bypass requests piled up. The factory removes the bypass entirely: when `serializeRequests` is on, every request goes through the queue and inflight is HARD-CAPPED at `serializeMaxConcurrent`. UI exposes both the delay (`serializeDelayMs`, 0–2000 ms) and the cap (`serializeMaxConcurrent`, 1–16). Strict default = 1 because most vdm users are running multiple CC clients on a single bearer; pipelining is opt-in only when you have multiple accounts. Use `vdm dashboard` → Settings tab → "Request Serialization" to tune, or `vdm config serialize-max-concurrent N` from the CLI (note: CLI changes don't propagate to a running dashboard until restart — same caveat as every other `vdm config` key).
- **Progressive drain on serialize-disable (`drainProgressively` in `lib.mjs`).** Every "serialize is turning OFF" callsite — user toggle off, Breakers A/C auto-disable, Safeguard D auto-revert — uses `progressivelyDrainSerializationQueue(reason)` instead of an instant `.drain()` flush. Without progressive drain, a backlog of pending payloads (e.g. 100 queued mid-incident) hits Anthropic in the same millisecond the user flips serialize off, guaranteeing an immediate rate-limit cascade across whichever account is active. Cadence defaults to `max(250 ms, serializeDelayMs)` so the user's chosen rate is the upper bound on drain speed. The drain is cancellable via the controller object returned from `drainProgressively`, and `_activeProgressiveDrain` is single-tracked — starting a new drain mid-flight cancels the prior one (otherwise two drains would race and double the dispatch rate). Activity events `serialize-progressive-drain-start` and `serialize-progressive-drain-end` surface drain progress in the dashboard feed; both routed through `h(...)` for XSS-safety.
- **OAuth bypass mode — all-accounts-revoked passthrough.** When `settings.oauthBypassEnabled` is true (default ON) AND every saved account has a permanently-revoked refresh token, the proxy stops trying to rotate or refresh and just forwards requests transparently. Detection is per RFC 6749 §5.2: an account counts as "permanently revoked" when 3+ refresh attempts spread over at least 1 hour all returned `invalid_grant` / `unauthorized_client` / `invalid_client` / `access_denied` (`isOAuthRevocationError` in `lib.mjs` is the classifier). Other failures (5xx, 429, network timeouts) NEVER count as strikes — a brief OAuth-server outage cannot trip bypass. An account is "alive" if any of: not permanently revoked, future 5h/7d-reset window, OR a 200 response in the last 24h (`areAllAccountsTerminallyDead` in `lib.mjs` is the all-accounts checker). Bypass mode auto-exits on any 200 response from any account (the keychain may have a fresh token after `claude login` — `autoDiscoverAccount` picks it up, the new account starts with no revocation flags, the next request gets a 200, bypass exits). A 5-minute background probe (`_probeBypassRecovery`) attempts refresh on each revoked account while bypassed, in case a transient platform issue resolves. Bypass-mode entry fires a HIGH_PRIORITY notification ("Run `claude login`") that bypasses the 10s notify throttle. Passthrough goes through `_smartPassthrough` (same code path as `proxyEnabled=false` and circuit-breaker-open) — the serialize queue STILL applies because it wraps `handleProxyRequest` from the createServer layer. Activity events: `oauth-bypass-enabled` / `oauth-bypass-disabled`. Forensic events: `oauth_bypass_enabled` / `oauth_bypass_disabled` (events.jsonl). Tracking fields on each `accountState` entry: `permanentlyRevoked` (boolean), `permanentRefreshFailureCount`, `firstPermanentFailureAtMs`, `lastPermanentFailureAtMs`, `lastSuccessAtMs`. All cleared by `clearPermanentRevocation` on any successful refresh OR 200 response.
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
