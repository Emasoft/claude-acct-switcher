# Changelog

All notable changes to vdm (Van Damme-o-Matic) are recorded here.

The project follows the spirit of [Keep a Changelog](https://keepachangelog.com/) and [SemVer](https://semver.org/) — but versions are git tags, not npm releases. The "version" of an install is the commit SHA it was cloned at; `vdm upgrade` re-clones from `origin` (or `$VDM_UPGRADE_URL` override).

## Unreleased — Phase I+ (competitor-audit response)

This window covers four parallel adversarial audits + the prior install-time security hardening. Treat it as the security-and-reliability baseline release.

### Security (P0)

- **DNS-rebind defense (CVE-tier).** All three HTTP servers (dashboard 3333, proxy 3334, OTLP 3335) now reject any request whose `Host:` header isn't `localhost:PORT` / `127.0.0.1:PORT` / `[::1]:PORT`. The previous Origin allow-list only fired on mutating requests, leaving every GET (`/api/profiles` returns emails+fingerprints, `/api/sessions` returns prompt excerpts, `/api/logs/stream` is a live SSE feed) exposed to a malicious local web page that DNS-rebound `attacker.example` → 127.0.0.1.
- **State files are mode 0o600.** `atomicWriteFileSync` now writes with the explicit mode option at file CREATION (no TOCTOU window). Files under `~/.claude/account-switcher/` (activity log, account-state, token-usage, session-history, accounts/*.label) used to inherit the user's umask — typically 644, world-readable on multi-user macOS. Pre-existing files from older installs keep their old mode; chmod once after upgrade if you want them tightened.
- **No more `console.log` email leaks.** All three call sites in `_autoDiscoverAccountImpl` now route through `log()` (which feeds `_redactForLog`). The email-redaction regex was being bypassed three lines after it was written, leaking emails into mode-644 startup.log.
- **`atomicWriteFileSync` cleans up `.tmp` on disk-full / EIO.** Without this, a chronically-failing write accumulated leftover `.tmp` files in the install dir.
- **Shell-injection guard on `$CSW_PORT` / `$CSW_PROXY_PORT`** (closed in the prior install audit, see commit history). Validated against `^[1-9][0-9]{0,4}$` + IANA range before reaching any URL or `command:` field.
- **`_validate_port` promoted to `lib-install.sh`.** Single source of truth for port-shape validation across install.sh, install-hooks.sh, uninstall.sh, and `vdm`.
- **Atomic install lifecycle.** `install.sh` now starts the dashboard + proxy in the background, polls BOTH `/health` endpoints, verifies the body marker `"server":"dashboard"` (anti-squatter), AND only THEN writes hooks to `~/.claude/settings.json`. Abort + cleanup if anything fails. The pre-Phase-I non-atomic order caused every existing CC session globally to spam `ECONNREFUSED` on every prompt the moment hooks landed but the dashboard hadn't yet started.
- **Hooks are `type: "command"`, not `type: "http"`.** Each command runs `curl ... 2>/dev/null || true # __VDM_HOOK_v1_DO_NOT_EDIT__`. CC's HTTP-hook implementation logs `ECONNREFUSED` loudly when the dashboard is down; command-type hooks swallow the failure silently. Token tracking now degrades gracefully on dashboard restart instead of error-spamming every CC session.
- **Drop Google Fonts.** Dashboard now uses the OS system-ui stack (`-apple-system, BlinkMacSystemFont, ...`). Was leaking visit metadata to Google's edge on every page load AND breaking the dashboard for users behind captive portals.

### Reliability (P1)

- **Breaker C now actually trips.** The all-accounts-429 auto-disable safeguard documented in CLAUDE.md was reading `a.accessToken` from objects whose top-level field is `a.token`. Since the field never exists, `knownFps` was always `[]`, and the documented breaker had never been able to fire in production.
- **Account-state migration propagates `expired` flag.** `accountState.update()` always writes `expired: false` (no header signal); without an explicit `markExpired` after migration, a 401-expired token had its flag silently dropped during refresh-migration. The picker would re-select the (still-expired) token, get another 401, and loop until the circuit breaker opened.
- **`refreshSweep` parallelizes via `Promise.allSettled`.** Was serial `for await`. With N expired tokens × ~17s OAuth retry budget each, the serial form blocked Claude Code for N×17s after wake-from-sleep. `_refreshSem` (cap 3) still bounds upstream concurrency.
- **Serialize-mode auto-safeguards** (Breaker A `queue_timeout` burst, Breaker B sustained queue depth alert, Breaker C all-accounts-429 burst). All three are debounced and read live settings every check.

### UX / CLI (P3)

- **Atomic install closing message** uses the resolved ports (`_DASH_PORT_DEFAULT`, `_PROXY_PORT_DEFAULT`) instead of hardcoded 3333/3334. Custom-port installs no longer end with a dead link.
- **Install "Next steps"** rewritten to match README + `vdm help`. Now mentions the macOS Keychain prompt explicitly. Was telling users to `vdm add account-1` (manual save) when README and `vdm help` both say accounts are auto-discovered.
- **macOS-only check now happens BEFORE the install lock acquisition.** Prevents leaking a lock-dir on a Linux user's first attempt.
- **`vdm upgrade` URL is no longer hardcoded** to upstream `loekj/`. New priority: `$VDM_UPGRADE_URL` → `git remote get-url origin` of the install dir → fallback to `Emasoft/claude-acct-switcher.git`. The hardcoded upstream URL silently rolled active-fork users back to upstream on every upgrade.
- **`vdm config <unknown>`** prints a one-per-line settings table instead of jamming 14 names into one comma-separated wrapping line.
- **`vdm remove <active>`** now refuses with the same safety check as the dashboard's `/api/remove` (was bricking auto-switch silently).
- **`vdm remove`** drops matching `account-prefs.json` entry so a re-added account doesn't inherit stale `excludeFromAuto` / `priority` flags.
- **Migration error noise** is rate-limited to once per 24h via a marker file. Was firing on every `vdm <anything>` call after the first transient failure (locked keychain on user's first interaction with laptop, etc.) → hours of error-banner spam.
- **`vdm tokens`** error message now matches `vdm logs` ("Dashboard is not running. Start it with: vdm dashboard").
- **`vdm prefs`** help text warns about the dashboard requirement.
- **`vdm hooks`** added to `vdm help` (was dispatchable but missing from help).
- **Dashboard "no accounts" empty-state typo fixed** (was "Code  - accounts" with double space + ambiguous `/login`).
- **Remove confirm dialog text** updated. Was "deletes the saved credentials FILE" (3 versions out-of-date).
- **`/health` endpoint added to UI server**, accepts GET and HEAD.

### Documentation (P2)

- **README** points at `Emasoft/claude-acct-switcher` (active fork). Was pointing at upstream `loekj/`.
- **Default rotation strategy** in README is now "Conserve" (matches code default at `dashboard.mjs:112`). Was "Sticky".
- **macOS Keychain prompt** documented in Install section.
- **`ANTHROPIC_BASE_URL` blast radius warning** added — the env var redirects every Anthropic SDK in every language through vdm.
- **Replaced unverifiable "~37s sleep recovery" claim** with description matching the actual code.
- **Removed `--remote-control` references** in the opening pitch (the term doesn't exist anywhere in vdm's source).
- **Ports table** lists OTLP receiver on port 3335.
- **Tuning Knobs table** lists `CSW_OTEL_ENABLED` / `CSW_OTLP_PORT` / `CSW_OTEL_BUFFER_MAX`.
- **CLI table** adds `vdm hooks` and `vdm add` (with caveat about being a fallback for headless flows).
- **CLAUDE.md line counts** updated to reality (drift had grown to 31% on lib-install.sh).

### Tests

- **372 unit tests, 0 fail.** Was 339 before Phase I. New tests cover: shell-injection guard, sentinel marker shape (versioned + single-source-of-truth), atomic-install invariants, `_validate_port`, `/health` endpoint, `atomicWriteFileSync` mode + cleanup, console.log absence in auto-discover, three Host-check call sites, no Google Fonts, no "credentials FILE" copy, no double-space-dash empty-state, Breaker C uses `a.token`, `migrateAccountState` propagates `expired`, `refreshSweep` uses `Promise.allSettled`.

### Audit reports (gitignored under `reports/`)

- `reports/install-audit/20260501_101247+0200-phase-i-adversarial-audit.md` — install-time security audit (all findings closed in commit `10c7855`).
- `reports/competitor-audit/20260501_104909+0200-master-takedown-synthesis.md` — multi-angle competitor audit synthesis (4 sub-reports).

## Earlier history

See `git log` for the pre-Changelog commit timeline. The project does not yet ship signed releases; consider any pre-`Phase I+` SHA equivalent to "0.x" maturity.
