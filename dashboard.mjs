#!/usr/bin/env node
// Van Damme-o-Matic  - Dashboard
// Zero dependencies, uses Node.js built-in modules only.

import { createServer } from 'node:http';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { execSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { existsSync, writeFileSync, mkdirSync, readdirSync, readFileSync, unlinkSync, renameSync } from 'node:fs';
import { pipeline as _streamPipeline } from 'node:stream';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Prevent EIO/EPIPE on stdout/stderr from crashing the process when
// running as a background daemon (terminal closed, pipe broken).
process.stdout?.on?.('error', () => {});
process.stderr?.on?.('error', () => {});

const PORT = parseInt(process.env.CSW_PORT || '3333', 10);
const ACCOUNTS_DIR = join(__dirname, 'accounts');
const STATS_CACHE = join(process.env.HOME, '.claude', 'stats-cache.json');
const CONFIG_FILE = join(__dirname, 'config.json');
const STATE_FILE = join(__dirname, 'account-state.json');
const TOKEN_USAGE_FILE = join(__dirname, 'token-usage.json');
const SESSION_HISTORY_FILE = join(__dirname, 'session-history.json');
// Per-account user preferences. Schema: { "<account-name>": { excludeFromAuto: bool, priority: number } }.
// Atomic file (tmp + rename) like every other state file. Preferred over
// per-account sidecar files because (a) prefs change rarely so a single
// JSON read is cheaper than N stat calls, (b) it's natural to enumerate
// "all accounts with prefs" without listdir.
const ACCOUNT_PREFS_FILE = join(__dirname, 'account-prefs.json');
// Phase C — date-range scrubber persistence. Kept next to the other state
// files so it shares the same atomic-write contract and per-install scope.
// Schema: { start: ms_epoch, end: ms_epoch, tierFilter: string[] }.
const VIEWER_STATE_FILE = join(__dirname, 'viewer-state.json');
const KEYCHAIN_ACCOUNT = process.env.USER || execSync('whoami').toString().trim();

// Detect installed Claude Code version for User-Agent mimicry
function detectClaudeCodeVersion() {
  try {
    const out = execSync('claude --version 2>/dev/null', { encoding: 'utf8', timeout: 3000 }).trim();
    const match = out.match(/^([\d.]+)/);
    if (match) return match[1];
  } catch {}
  // Fallback: read symlink target which contains the version
  try {
    const target = execSync('readlink ~/.local/bin/claude 2>/dev/null || readlink /usr/local/bin/claude 2>/dev/null', { encoding: 'utf8', timeout: 2000 }).trim();
    const match = target.match(/versions\/([\d.]+)/);
    if (match) return match[1];
  } catch {}
  return '2.1.0'; // safe default
}
const CLAUDE_CODE_VERSION = detectClaudeCodeVersion();

// Project version — read from .version file (written by vdm upgrade), fall back to git tag
function detectProjectVersion() {
  const versionFile = join(__dirname, '.version');
  try {
    const v = readFileSync(versionFile, 'utf8').trim();
    if (v) return v;
  } catch {}
  try {
    return execSync('git describe --tags --abbrev=0 2>/dev/null', { encoding: 'utf8', cwd: __dirname, timeout: 3000 }).trim();
  } catch {}
  return 'dev';
}
const PROJECT_VERSION = detectProjectVersion();

// Auto-detect keychain service name for robustness against Claude Code updates.
//
// Phase 6: deterministic preference order. The Claude Code CLI has shipped
// the keychain entry under three different service names across releases.
// We try a stable, ordered list of known names first — only falling back to
// `dump-keychain` (sorted, head -1) when none of them exist. This mirrors
// vdm's bash detect_keychain_service() byte-for-byte so the two
// implementations can never diverge on which entry they pick.
function detectKeychainService() {
  const candidates = ['Claude Code-credentials', 'Claude-Code-credentials', 'claude.ai-credentials'];
  for (const candidate of candidates) {
    try {
      execFileSync('security', ['find-generic-password', '-a', KEYCHAIN_ACCOUNT, '-s', candidate, '-w'],
                   { stdio: ['ignore', 'pipe', 'ignore'] });
      return candidate;
    } catch { /* try next */ }
  }
  // Deterministic dump-keychain fallback: LC_ALL=C sort -u | head -1 ensures
  // multiple Claude entries (e.g. dev + stable installs) always resolve to
  // the same service, instead of whichever the keychain happened to list
  // first this boot.
  try {
    const dump = execSync(
      `security dump-keychain 2>/dev/null | grep -A4 '"svce"' | grep -i claude | sed -n 's/.*"svce"<blob>="\\([^"]*\\)".*/\\1/p' | LC_ALL=C sort -u | head -1`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    if (dump) return dump;
  } catch { /* ignore */ }
  return 'Claude Code-credentials';
}

const KEYCHAIN_SERVICE = detectKeychainService();

// ─────────────────────────────────────────────────
// Settings (persisted to config.json)
// ─────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  autoSwitch: true,
  proxyEnabled: true,
  rotationStrategy: 'conserve',
  rotationIntervalMin: 60,
  notifications: true,
  serializeRequests: false,
  serializeDelayMs: 200,
  // Hard cap on concurrent in-flight requests when serialization is on.
  // Default 1 = strict serialization (the bug-fix-justified default for
  // users running many CC clients on a single bearer token). Settable
  // 1..16 via /api/settings — users with many accounts can dial up.
  serializeMaxConcurrent: 1,
  commitTokenUsage: false,
  sessionMonitor: false,
  // Phase D — gate per-tool attribution behind a setting. When false, the
  // /api/post-tool-batch endpoint replies 404 (so the install-hooks.sh
  // SubagentStart-style installer can detect and skip subscribing). When
  // true, PostToolBatch payloads tag the next appendTokenUsage() row with
  // `tool` (and `mcpServer` if applicable) — see Refinement 1 in the
  // contract.
  perToolAttribution: false,
  // Retention defaults — vdm config and /api/settings accept these and the
  // _tokenUsageMaxEntries / _activityMaxEntries / _tokenUsageMaxAgeMs helpers
  // read them, but the values were missing from DEFAULT_SETTINGS. On a fresh
  // install they fell through to 0 (= "unlimited"), while vdm `cmd_config`
  // displayed defaults like "90 days" / "500 entries" — drift between what
  // the user was told and what the dashboard actually used.
  activityMaxEntries: 500,
  tokenUsageMaxEntries: 50000,
  tokenUsageMaxAgeDays: 90,
  // ── Serialize-mode auto-safeguards ──
  // Master switch for the breakers + alerts that auto-disable serialize
  // when it's making things worse. The user can disable the auto-toggle
  // (set this to false) if they prefer to debug failures manually
  // without serialize getting flipped under them.
  serializeAutoDisableEnabled: true,
  // Safeguard D — auto-ENABLE serialize when a single account hits
  // 3+ rate-limits within 30s. Avoids the "burst payload bombards
  // every account in turn → all banned" failure mode by switching to
  // queue mode + small inter-request delay BEFORE rotating to the next
  // account. Auto-reverts to non-serialize after 30 min of no 429s.
  // Default ON. Set false to disable JUST this safeguard while still
  // keeping the auto-disable safeguards above active.
  serializeAutoEnableEnabled: true,
  // OAuth bypass mode — when ALL saved accounts have permanently
  // revoked refresh tokens (3+ invalid_grant/etc. failures spread over
  // 1h), stop trying to rotate and just forward requests transparently
  // with whatever the keychain currently has. Notifies the user once
  // with HIGH_PRIORITY ("Run `claude login`"). Auto-exits the moment
  // any account responds 200. Default ON. Set false ONLY if you want
  // vdm to keep churning rotation attempts even when nothing works.
  oauthBypassEnabled: true,
  // Breaker A — N queue_timeout 503s within window → auto-disable.
  // Defaults: 5 trips within 10 min. Conservative — a healthy serialize
  // run won't hit any queue_timeout 503 (the queue timeout default of
  // REQUEST_DEADLINE_MS + 60s = 660s is well above any normal request).
  // 5 in 10 min means something is genuinely sustained-broken.
  queueTimeoutBreakerThreshold: 5,
  queueTimeoutBreakerWindowMs: 600000,
  // Alert B — sustained queue depth above threshold for sustainMs.
  // Informational only — emits an activity event and a log warn but
  // does NOT auto-disable, because a transient burst of legitimate
  // traffic can produce a deep queue without indicating a problem.
  // Defaults: 50 queued for 60s straight.
  queueDepthAlertThreshold: 50,
  queueDepthAlertSustainMs: 60000,
  // Breaker C — every account hit 429 within window AND serialize is on.
  // The original symptom that motivated this work: serialize made every
  // request line up behind the slowest account, so when one account
  // started returning 429 the whole queue piled up and OTHER accounts
  // also exhausted. Auto-disabling serialize lets the queue drain in
  // parallel and the rotation logic find a healthy account again.
  // Defaults: every-account-429 within 60s.
  all429BreakerWindowMs: 60000,
};

function loadSettings() {
  try {
    if (existsSync(CONFIG_FILE)) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch { /* corrupt file  - use defaults */ }
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(settings) {
  // Hoist atomicWriteFileSync usage: defined later in the file but JS hoists
  // function declarations. This call only runs after module init completes.
  atomicWriteFileSync(CONFIG_FILE, JSON.stringify(settings, null, 2));
}

let settings = loadSettings();
let lastRotationTime = 0; // tracks when proactive rotation last happened
let _consecutive400s = 0;  // global: consecutive 400 errors across requests (reset on success)
// Global byte counter for the streaming-phase body buffers. Caps the
// aggregate memory dedicated to incoming request body accumulation so a
// burst of large concurrent uploads cannot OOM the dashboard.
let _bufferedBytes = 0;
let _consecutive400sAt = 0;  // timestamp of last 400 (for time-based decay)
const _lastWarnPct = new Map(); // acctName → last logged percentage (dedup 90%+ warnings)

// ── Circuit breaker ──
// When the proxy fails repeatedly (all recovery strategies exhausted), it
// auto-disables into passthrough mode so Claude Code can still reach the API
// with its own token / trigger re-auth.  Resets after a cooldown.
let _circuitOpen = false;
let _circuitOpenAt = 0;
let _circuitClosedAt = 0; // PROXY-6: track close time so the "post-close 400 grace window" works
let _consecutiveExhausted = 0; // count of requests where ALL recovery strategies failed
const CIRCUIT_COOLDOWN_MS = 2 * 60 * 1000; // 2 minutes
const CIRCUIT_OPEN_THRESHOLD = 3;           // open after N consecutive exhausted requests
const CIRCUIT_400_THRESHOLD = 10;           // open circuit after N consecutive 400s across requests
const CIRCUIT_POST_CLOSE_GRACE_MS = 5000;   // PROXY-6: don't count 400s for 5s after close

function _isCircuitOpen() {
  if (!_circuitOpen) return false;
  if (Date.now() - _circuitOpenAt > CIRCUIT_COOLDOWN_MS) {
    _circuitOpen = false;
    _circuitClosedAt = Date.now();
    _consecutiveExhausted = 0;
    _consecutive400s = 0;
    log('circuit', 'Circuit breaker closed — retrying proxy mode');
    return false;
  }
  return true;
}

// PROXY-6: returns true if we're still inside the post-close grace
// window. Callers use this to decide whether a fresh 400 should count
// toward the threshold OR be silently absorbed (because 10 in-flight
// CC sessions all hit a stale-token 400 the instant the breaker
// closes, racing the increment, can re-open it within seconds for
// hours of bounce). 5s is enough for the recovery strategy to drain
// the queued bad-token requests without re-tripping.
function _inCircuitPostCloseGrace() {
  return _circuitClosedAt > 0 && (Date.now() - _circuitClosedAt) < CIRCUIT_POST_CLOSE_GRACE_MS;
}

function _openCircuit(reason) {
  if (_circuitOpen) return;
  _circuitOpen = true;
  _circuitOpenAt = Date.now();
  log('circuit', `Circuit breaker OPEN (${reason}) — passthrough for ${CIRCUIT_COOLDOWN_MS / 1000}s`);
  notify('Proxy Bypassed', `${reason} — passthrough mode for ${CIRCUIT_COOLDOWN_MS / 60000}min`, 'circuitBreaker');
}

// ─────────────────────────────────────────────────
// Keychain helpers
// ─────────────────────────────────────────────────

// KC-1: rate-limit the user-deny notification so a denied permission
// doesn't notify-spam every 5s as the proxy retries reading. One alert
// per 10-min window is enough to surface the issue.
let _lastKeychainDenyNotifyAt = 0;
function readKeychain() {
  try {
    // execFileSync with argv[] — no shell, no interpolation injection vector.
    const raw = execFileSync(
      'security',
      ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }
    ).trim();
    return JSON.parse(raw);
  } catch (e) {
    log('error', `Keychain read failed: ${e.message}`);
    // KC-1: macOS `security` exits with status 51 (SecAuthFailed) when
    // the user clicked "Deny" on the keychain prompt. Without surfacing
    // this, every proxy request returns a generic "no active token" 502
    // and the user has no idea why. Notify once per 10 min so the
    // dashboard activity feed + a desktop alert make the cause obvious.
    const isUserDeny = e.status === 51 || /SecAuthFailed|user.{0,10}deni|interaction is not allowed/i.test(String(e.message || ''));
    if (isUserDeny) {
      const now = Date.now();
      if (now - _lastKeychainDenyNotifyAt > 10 * 60 * 1000) {
        _lastKeychainDenyNotifyAt = now;
        try {
          notify(
            'vdm — Keychain access denied',
            `Open Keychain Access, find "${KEYCHAIN_SERVICE}", and re-grant access (or click Always Allow next time).`,
            'keychain-deny',
          );
        } catch {}
        try { logActivity('keychain-access-denied', { service: KEYCHAIN_SERVICE }); } catch {}
      }
    }
    return null;
  }
}

// Tracks the last successful keychain write so autoDiscoverAccount can
// safely skip the brief race window where the on-disk account file has
// been refreshed but the keychain has not yet been updated. Without this,
// an inbound proxy request landing between those two writes would
// trigger an email-match overwrite of the just-refreshed disk file with
// the stale (pre-refresh) keychain creds — audit Concern 03.C7.
let _lastKeychainWriteAt = 0;
// Global counter incremented while ANY refresh is in flight. Covers the
// PRE-keychain-write half of the race that `_lastKeychainWriteAt` cannot:
// the refresh writes disk first, THEN keychain. Between those two
// writes the keychain still holds the OLD token while the disk file has
// the NEW token. autoDiscoverAccount running in that window would
// match by email and overwrite the just-refreshed file with stale
// keychain creds. The counter goes up before atomicWriteAccountFile and
// drops after writeKeychain returns; autoDiscoverAccount short-circuits
// while > 0.
let _refreshesInProgress = 0;

// Saved-accounts cache. Declared up here (rather than next to
// loadAllAccountTokens further down the file) because the startup
// sequence in this same module calls rehydrateAccountStateFromPersisted
// → loadAllAccountTokens before the bottom of the file is evaluated, and
// `let` is in TDZ until its declaration line runs. Declaring here keeps
// the cache state next to the other module-level keychain bookkeeping
// and side-steps the temporal-dead-zone fault.
let _accountsCache = null;
let _accountsCacheAt = 0;
const ACCOUNTS_CACHE_TTL = 5000; // 5s — covers hot path without stale data

function writeKeychain(creds) {
  // Atomic: `add-generic-password -U` updates in place if the entry exists,
  // creates it otherwise. Single syscall — no delete-then-add window where
  // concurrent readers see null. argv[] form — no shell, no interpolation.
  const json = JSON.stringify(creds);
  execFileSync(
    'security',
    ['add-generic-password', '-U', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w', json],
    { stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }
  );
  _lastKeychainWriteAt = Date.now();
}

// ── Phase J — per-account keychain ops ──
// Each saved account's OAuth blob lives at service `vdm-account-<name>`
// instead of `<INSTALL_DIR>/accounts/<name>.json`. Pre-Phase-J the JSON
// files were world-readable on default umask, leaking refresh tokens to
// anyone with $HOME read access. The keychain enforces per-user ACLs
// AND prompts on first read from a new binary, so even a process running
// as the user must have been granted access (which `security` provides
// transparently to subprocesses started by the original installer).
//
// Why per-account services rather than one combined JSON-array entry:
//   - keeps each account independently revocable (`security delete-...`)
//   - no critical section across N accounts on read/write (would need a
//     mutex — keychain has no built-in transactions)
//   - uninstall enumeration via `dump-keychain | grep` works
//   - swap-in is just `vdm-account-<name>` → `KEYCHAIN_SERVICE` (one read,
//     one write, no merge logic)

function readAccountKeychain(name) {
  const svc = vdmAccountServiceName(name);
  try {
    const out = execFileSync(
      'security',
      ['find-generic-password', '-s', svc, '-a', KEYCHAIN_ACCOUNT, '-w'],
      { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return JSON.parse(out.trim());
  } catch (e) {
    // exit 44 = SecKeychainItemNotFound. Treat as "no account by this name".
    if (e && e.status === 44) return null;
    // Anything else: log + return null (don't crash the dashboard).
    log('warn', `readAccountKeychain(${name}) failed: ${e.message}`);
    return null;
  }
}

function writeAccountKeychain(name, creds) {
  const svc = vdmAccountServiceName(name);
  const json = JSON.stringify(creds);
  execFileSync(
    'security',
    ['add-generic-password', '-U', '-s', svc, '-a', KEYCHAIN_ACCOUNT, '-w', json],
    { stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }
  );
}

function deleteAccountKeychain(name) {
  const svc = vdmAccountServiceName(name);
  try {
    execFileSync(
      'security',
      ['delete-generic-password', '-s', svc, '-a', KEYCHAIN_ACCOUNT],
      { stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }
    );
  } catch (e) {
    // Already gone (status 44) is fine — uninstall path may double-call.
    if (e && e.status === 44) return;
    log('warn', `deleteAccountKeychain(${name}) failed: ${e.message}`);
  }
}

/**
 * Phase J — enumerate vdm account keychain entries.
 *
 * macOS `security` CLI has no native "list entries by service-prefix" verb,
 * so we shell out to `security dump-keychain` and grep the SecAttr blocks.
 * The dump format is line-noisy; we look for `"svce"<blob>="vdm-account-..."`
 * lines and parse the service name out. This works across all macOS
 * versions vdm targets (14+).
 *
 * For typical use (1-10 accounts) this is plenty fast. If a user ever has
 * thousands of accounts, dump-keychain is O(n) on the whole keychain — we
 * can revisit with a sidecar index file then.
 */
function listVdmAccountKeychainEntries() {
  try {
    const out = execFileSync(
      'sh',
      ['-c', `security dump-keychain 2>/dev/null | grep -oE '"svce"<blob>="${VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX}[^"]+"' | sed -E 's/.*"(${VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX}[^"]+)".*/\\1/' | LC_ALL=C sort -u`],
      { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'ignore'] }
    );
    return out.split('\n')
      .map(s => s.trim())
      .map(vdmAccountNameFromService)
      .filter(n => typeof n === 'string' && n.length > 0);
  } catch (e) {
    log('warn', `listVdmAccountKeychainEntries failed: ${e.message}`);
    return [];
  }
}

/**
 * Phase J — Migrate plaintext accounts/<name>.json files to keychain.
 *
 * Idempotent — runs every dashboard startup. For each `.json` file:
 *   1. Parse it. If it has an accessToken, write to keychain under
 *      `vdm-account-<name>`.
 *   2. Only after the keychain write succeeds, delete the file.
 *
 * Order matters — write-first-then-delete-file means an interrupted
 * migration leaves data on BOTH sides (file + keychain), which next run
 * will reconcile harmlessly (keychain write is idempotent via -U). The
 * reverse order would risk losing tokens to a SIGKILL.
 *
 * The .label sidecars are not touched (labels are not secrets).
 */
function migrateAccountsToKeychain() {
  if (!existsSync(ACCOUNTS_DIR)) return 0;
  let migrated = 0;
  let files;
  try { files = readdirSync(ACCOUNTS_DIR); }
  catch { return 0; }
  for (const f of files) {
    if (!f.endsWith('.json')) continue;
    const name = basename(f, '.json');
    let valid = true;
    try { vdmAccountServiceName(name); } catch { valid = false; }
    if (!valid) {
      log('warn', `Migration skipped: invalid account name "${name}"`);
      continue;
    }
    const filePath = join(ACCOUNTS_DIR, f);
    let creds;
    try {
      const raw = readFileSync(filePath, 'utf8');
      creds = JSON.parse(raw);
    } catch (e) {
      log('warn', `Migration skipped ${f}: parse error: ${e.message}`);
      continue;
    }
    if (!creds?.claudeAiOauth?.accessToken) {
      // No token in the file — just delete it; nothing to migrate.
      try { unlinkSync(filePath); } catch { /* ignore */ }
      continue;
    }
    try {
      writeAccountKeychain(name, creds);
    } catch (e) {
      log('error', `Migration FAILED for ${name} (file kept, retry next run): ${e.message}`);
      continue;
    }
    // Keychain write succeeded — safe to delete the file.
    try {
      unlinkSync(filePath);
      migrated++;
    } catch (e) {
      // Keychain has the data; file delete failed (permissions?). The
      // file still holds plaintext tokens.
      // SEC-10: previously this log line included the absolute filePath,
      // which then landed in mode-644 startup.log + the in-memory
      // _logBuffer (visible to /api/logs/stream). That was a roadmap
      // for any local attacker reading startup.log to find the
      // plaintext token. Now we (a) print to stderr only — bypasses
      // log() entirely, so no SSE / disk leak — AND (b) stamp a
      // sticky activity event so the dashboard UI surfaces it.
      // The activity event uses ONLY the account name, never the path.
      try {
        process.stderr.write(`[vdm migration WARNING] Account "${name}": keychain write OK but plaintext-file delete failed (${e.code || e.message}). The file still contains plaintext OAuth tokens. Open the dashboard for the recovery command.\n`);
      } catch {}
      try {
        // Activity-log entry carries only the account name + reason —
        // the dashboard's UI can resolve the path back from
        // _accountNameToPlaintextFile() at render time without ever
        // putting the path into the persisted log.
        logActivity('keychain-migration-partial-failure', { account: name, reason: e.code || 'unlink-failed' });
      } catch {}
    }
  }
  if (migrated > 0) {
    log('info', `Phase J migration: moved ${migrated} OAuth token(s) from plaintext files to Keychain (service "${VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX}<name>")`);
    try { logActivity('keychain-migration', `Migrated ${migrated} account(s) from plaintext files to Keychain`); }
    catch { /* logActivity not yet defined at startup — best-effort */ }
  }
  return migrated;
}

// Atomic file write: write to .tmp, then rename over the target. POSIX
// rename(2) is atomic on the same filesystem, so a SIGKILL/OOM/power-loss
// between the truncate and the final byte never leaves a half-written
// state file. Used for every state file whose corruption would lose data.
function atomicWriteFileSync(filePath, content) {
  const tmpPath = filePath + '.tmp';
  // SECURITY: state files under ~/.claude/account-switcher/ contain
  // absolute paths, session IDs, account labels, fingerprints, and
  // (for token-usage / activity-log) prompt-derived metadata. Default
  // umask-derived 644 leaves them world-readable on multi-user macOS.
  // Force 0o600 so other local users cannot harvest the metadata. Mode
  // is applied at file CREATION via writeFileSync's mode option to avoid
  // a TOCTOU window between create and chmod.
  // Note: a 2nd-process race writing the same file is NOT defended here
  // (Node sync writes don't yield to the event loop, so a single-process
  // race is impossible; cross-process races require a file lock — see
  // the dashboard-startup mutex). Cleanup the .tmp on disk-full / EIO.
  try {
    writeFileSync(tmpPath, content, { mode: 0o600 });
    renameSync(tmpPath, filePath);
  } catch (e) {
    try { unlinkSync(tmpPath); } catch {}
    throw e;
  }
}

// ─────────────────────────────────────────────────
// Forensic event log (events.jsonl) + log rotation
// ─────────────────────────────────────────────────
//
// Per the Phase I+ user request: detailed enough to reconstruct rate
// limits, bans, server errors, disconnects, queue saturation, and
// inflight escalation events without ambiguity. Append-only JSON Lines
// so jq / awk / grep / cut all work directly. One line per event;
// each event carries a `category` plus a typed payload.
//
// File: ~/.claude/account-switcher/events.jsonl
// Rotation: daily, keep 7 days. Active file is `events.jsonl`; daily
// snapshots are `events.jsonl.YYYY-MM-DD.gz` (compressed at rotate
// time). `events.jsonl` itself is mode 0o600 — same rationale as
// every other state file (paths, fingerprints, error excerpts).
//
// Categories vdm currently emits:
//   - rate_limit       — 429 from upstream (fingerprint + reset-at + retry-after)
//   - auth_failure     — 401 from upstream (token expired / revoked)
//   - server_error     — 5xx from upstream (status + error_type + body excerpt)
//   - client_disconnect — SSE client closed mid-stream (bytes + duration)
//   - queue_saturation — settings queue rejected request with queue_timeout
//   - inflight_escalation — per-account inflight cap reached (queueing started)
//   - circuit_open / circuit_close
//   - refresh_success / refresh_failure
//   - token_rotation   — keychain swap from one account to another
const EVENTS_FILE = join(__dirname, 'events.jsonl');
const EVENTS_RETENTION_DAYS = 7;
const EVENTS_MAX_BYTES = 32 * 1024 * 1024; // 32 MiB rotate threshold (catches runaway days)

// Lazy-initialised at first use so the file path is always relative
// to the current __dirname even if the test harness moves it.
let _eventsRotationTimer = null;

function logForensicEvent(category, details) {
  // Best-effort: a forensic logger that throws would defeat its
  // purpose. Swallow every failure and continue.
  try {
    const entry = {
      ts: new Date().toISOString(),
      category,
      ...(details && typeof details === 'object' ? details : { detail: details }),
    };
    // appendFileSync with mode option creates the file with 0o600 if
    // it doesn't exist. Existing file's mode is preserved.
    let _appendFileSync;
    try { _appendFileSync = require('node:fs').appendFileSync; } catch {}
    if (_appendFileSync) {
      try { _appendFileSync(EVENTS_FILE, JSON.stringify(entry) + '\n', { mode: 0o600 }); } catch {}
    } else {
      // ESM path — use the import we already have.
      try { writeFileSync(EVENTS_FILE, JSON.stringify(entry) + '\n', { flag: 'a', mode: 0o600 }); } catch {}
    }
  } catch {}
}

// Daily rotation: any day older than EVENTS_RETENTION_DAYS is deleted.
// Run at startup AND on a daily timer. Best-effort; never throws.
function _rotateForensicLog() {
  try {
    if (!existsSync(EVENTS_FILE)) return;
    const st = require('node:fs').statSync(EVENTS_FILE);
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const fileMtimeDay = st.mtime.toISOString().slice(0, 10);
    const sizeOver = st.size >= EVENTS_MAX_BYTES;
    // Rotate when:
    //   (a) the active file is from a different day, OR
    //   (b) it has exceeded the size budget for any single day.
    if (fileMtimeDay !== today || sizeOver) {
      const dayTag = sizeOver ? `${fileMtimeDay}-${process.pid}` : fileMtimeDay;
      const rotated = `${EVENTS_FILE}.${dayTag}`;
      try { renameSync(EVENTS_FILE, rotated); } catch {}
      // Try to gzip the rotated file so old days don't bloat the
      // install dir. Best-effort: if gzip is missing or busy, leave
      // the plain .jsonl in place — still gets retention-pruned.
      try {
        execFileSync('gzip', ['-q', '-9', rotated], { timeout: 30_000, stdio: 'ignore' });
      } catch {}
    }
  } catch {}
  // Retention: remove files older than EVENTS_RETENTION_DAYS days.
  try {
    const dirEntries = readdirSync(__dirname);
    const cutoff = Date.now() - EVENTS_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    for (const f of dirEntries) {
      // Match events.jsonl.YYYY-MM-DD(.gz)? or startup.log.YYYY-MM-DD(.gz)?
      if (!/^(events\.jsonl|startup\.log)\.\d{4}-\d{2}-\d{2}/.test(f)) continue;
      const fp = join(__dirname, f);
      try {
        const st = require('node:fs').statSync(fp);
        if (st.mtimeMs < cutoff) {
          try { unlinkSync(fp); } catch {}
        }
      } catch {}
    }
  } catch {}
}

// Same rotation policy applied to startup.log so it doesn't grow
// unbounded across uptime weeks. Active file is appended-to by the
// nohup line that starts the dashboard; we just rotate-and-prune the
// historical snapshots here.
const STARTUP_LOG_FILE = join(__dirname, 'startup.log');
function _rotateStartupLog() {
  try {
    if (!existsSync(STARTUP_LOG_FILE)) return;
    const st = require('node:fs').statSync(STARTUP_LOG_FILE);
    const today = new Date().toISOString().slice(0, 10);
    const fileMtimeDay = st.mtime.toISOString().slice(0, 10);
    const sizeOver = st.size >= EVENTS_MAX_BYTES;
    if (fileMtimeDay !== today || sizeOver) {
      const dayTag = sizeOver ? `${fileMtimeDay}-${process.pid}` : fileMtimeDay;
      const rotated = `${STARTUP_LOG_FILE}.${dayTag}`;
      try { renameSync(STARTUP_LOG_FILE, rotated); } catch {}
      try {
        execFileSync('gzip', ['-q', '-9', rotated], { timeout: 30_000, stdio: 'ignore' });
      } catch {}
      // Touch a fresh empty file so the next nohup append writes to
      // the new active file (not the renamed one — Linux/macOS keep
      // the open fd alive on rename, so the old logs would still
      // accumulate if we didn't truncate).
      try { writeFileSync(STARTUP_LOG_FILE, '', { mode: 0o600 }); } catch {}
    }
  } catch {}
}

// Schedule rotation at startup + every 6 hours. The 6h cadence catches
// both "day boundary" rotations and any sudden-burst size-exceed cases.
function _startLogRotationTimer() {
  _rotateForensicLog();
  _rotateStartupLog();
  if (_eventsRotationTimer) clearInterval(_eventsRotationTimer);
  _eventsRotationTimer = setInterval(() => {
    try { _rotateForensicLog(); } catch {}
    try { _rotateStartupLog(); } catch {}
  }, 6 * 60 * 60 * 1000);
  if (_eventsRotationTimer.unref) _eventsRotationTimer.unref();
}

// Run a `git -C <cwd> ...` command without invoking a shell. cwd is passed
// as a separate argv element, so any character in it (including ;, |, &,
// `, $, ", newline, single-quote, glob) is treated as a literal directory
// path by git itself — it is impossible for a hostile cwd from a /api/*
// payload to inject extra commands. stderr is discarded the way the
// previous `2>/dev/null` shell redirect did. Throws (like execSync) if
// git exits non-zero or if cwd is not a non-empty string; callers wrap
// in try/catch.
function _runGit(cwd, args, timeout = 3000) {
  if (typeof cwd !== 'string' || cwd.length === 0) {
    throw new Error('git: cwd must be a non-empty string');
  }
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    timeout,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
}

// `git rev-parse` is invoked on every UserPromptSubmit, every CwdChanged,
// every periodic timer (auto-claim/worktree sweep), and every proxy
// streaming response that hits updateSessionTimeline. execFileSync forks a
// child process, blocks the event loop for 5–50 ms, and the answer almost
// never changes within a 30s window (branch / commit hash / repo root are
// quasi-static during a Claude turn). Cache by `cwd + args` and re-use.
//
// Errors are cached too, but with a SHORTER TTL — a transient `not a git
// repository` failure (cwd that's been `rm`-ed) should be re-checked sooner
// than a successful answer that's worth keeping fresh. FIFO eviction at
// _RUNGIT_CACHE_MAX so a long-running dashboard hitting hundreds of
// throwaway scratch dirs doesn't accumulate forever.
const _runGitCache = new Map();
const _RUNGIT_CACHE_TTL_MS = 30_000;
const _RUNGIT_ERROR_CACHE_TTL_MS = 5_000;
const _RUNGIT_CACHE_MAX = 200;

function _runGitCached(cwd, args, timeout = 3000) {
  if (typeof cwd !== 'string' || cwd.length === 0) {
    throw new Error('git: cwd must be a non-empty string');
  }
  // Reject obviously-bogus cwds before they pollute the cache. A
  // hostile /api/session-start payload could otherwise spam unique
  // cwd strings to evict every legitimate cache entry (cap is 200
  // FIFO). Two cheap checks:
  //   1. Must be an absolute path — git itself rejects relative cwd
  //      with `fatal: not a git repository`, but only AFTER forking,
  //      and the cache then stores the error. By rejecting up front
  //      we save the fork on every poll for the same bad cwd.
  //   2. Length cap: paths > 4096 chars are pathological on every
  //      filesystem we support and almost always mean attack input.
  // We do NOT existsSync(cwd) here — adding a stat call to a hot path
  // is exactly the kind of thing _runGitCached exists to avoid; the
  // git fork below will fail cheaply for non-existent paths and the
  // 5-second error cache absorbs the cost.
  if (cwd.length > 4096 || !cwd.startsWith('/')) {
    const e = new Error('git: cwd must be an absolute path under 4096 chars');
    throw e;
  }
  const key = cwd + '\0' + args.join('\0');
  const now = Date.now();
  const hit = _runGitCache.get(key);
  if (hit) {
    const ttl = hit.error ? _RUNGIT_ERROR_CACHE_TTL_MS : _RUNGIT_CACHE_TTL_MS;
    if (now - hit.ts < ttl) {
      if (hit.error) throw hit.error;
      return hit.value;
    }
  }
  if (_runGitCache.size >= _RUNGIT_CACHE_MAX) {
    const firstKey = _runGitCache.keys().next().value;
    if (firstKey !== undefined) _runGitCache.delete(firstKey);
  }
  try {
    const value = _runGit(cwd, args, timeout);
    _runGitCache.set(key, { value, ts: now });
    return value;
  } catch (e) {
    _runGitCache.set(key, { error: e, ts: now });
    throw e;
  }
}

// Drop cache entries for one cwd (or all cwds when omitted). Call this
// when the proxy KNOWS git state under that path is now invalid — e.g.
// after a worktree-removed hook, or when the user explicitly asks for a
// fresh re-resolution from the UI.
function _invalidateRunGitCache(cwd) {
  if (!cwd || typeof cwd !== 'string') {
    _runGitCache.clear();
    return;
  }
  // The boundary between cwd and args in the cache key is `\0` (NUL byte
  // — see _runGitCached `key = cwd + '\0' + args.join('\0')`). Including
  // the NUL in the prefix is what makes startsWith path-segment-safe:
  // invalidating `/tmp/foo` MUST NOT also evict `/tmp/foobar` keys, and
  // it does not because no valid filesystem path contains `\0`. If the
  // key construction in _runGitCached ever changes to a different
  // separator (e.g. `/`), this prefix check would silently turn into a
  // path-prefix bug — the regression test in lib.test.mjs pins both
  // sides of the contract.
  const prefix = cwd + '\0';
  for (const k of _runGitCache.keys()) {
    if (k.startsWith(prefix)) _runGitCache.delete(k);
  }
}

import https from 'node:https';
import { execFile } from 'node:child_process';
import http from 'node:http';
import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders as _buildForwardHeaders,
  stripHopByHopHeaders,
  createAccountStateManager,
  isAccountAvailable as _isAccountAvailable,
  pickBestAccount as _pickBestAccount,
  pickDrainFirst as _pickDrainFirst,
  pickConserve as _pickConserve,
  pickAnyUntried as _pickAnyUntried,
  getEarliestReset as _getEarliestReset,
  pickByStrategy as _pickByStrategy,
  createProbeTracker,
  createUtilizationHistory,
  buildRefreshRequestBody,
  parseRefreshResponse,
  parseRetryAfter,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  createPerAccountLock,
  createSemaphore,
  createSerializationQueue,
  createSlidingWindowCounter,
  gcAccountSlots,
  createUsageExtractor as _createUsageExtractor,
  ROTATION_STRATEGIES,
  ROTATION_INTERVALS,
  clampViewerState,
  // Phase D — hook payload parsers and helpers
  parseCompactPayload,
  parseSubagentStartPayload,
  parseCwdChangedPayload,
  parsePostToolBatchPayload,
  isUsageRow,
  buildCompactBoundaryEntry,
  mergeSessionAttribution,
  // Phase E — additional hook parsers + breakdown helper
  parseWorktreeEventPayload,
  parseTaskEventPayload,
  parseTeammateIdlePayload,
  aggregateByTool,
  // Phase H — OTLP/HTTP/JSON parsers (CSW_OTEL_ENABLED=1)
  parseOtlpLogs,
  parseOtlpMetrics,
  // Phase J — keychain-based account storage
  vdmAccountServiceName,
  vdmAccountNameFromService,
  VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX,
  // Phase I+ — bypass mode (all accounts revoked → transparent forward)
  isOAuthRevocationError,
  isPostRefreshTrulyExpired,
  areAllAccountsTerminallyDead,
  // Phase I+ — guard against attributing tokens to system / cache dirs
  isNonProjectCwd,
  // TRDD-1645134b — usage tree aggregation + cache-miss heuristic
  aggregateUsageTree,
  buildCacheMissReport,
  // TRDD-1645134b Phase 4 — tree-aggregated CSV export
  aggregateUsageForCsvExport,
  renderUsageTreeCsv,
  // TRDD-1645134b Phase 5 — per-session cache-miss aggregate
  summarizeCacheMissesBySession,
  // Phase 6 — wasted-spend (cache-miss cost) time series
  buildWastedSpendSeries,
} from './lib.mjs';

// Fetch email from Anthropic roles API using OAuth token. This is an
// authenticated call against api.anthropic.com and consumes the user's
// unified rate-limit budget on every cache miss — track it as a probe
// so the cost is visible in `/api/probe-stats` and shape the request to
// match a real Claude Code session (User-Agent + oauth beta) so it
// can't be heuristically distinguished by the upstream.
function fetchAccountEmail(token) {
  return new Promise((resolve) => {
    try { recordProbe(); } catch (e) {
      log('warn', `fetchAccountEmail: recordProbe failed: ${e && e.message}`);
    }
    const req = https.get('https://api.anthropic.com/api/oauth/claude_cli/roles', {
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': `claude-code/${CLAUDE_CODE_VERSION}`,
        'anthropic-beta': 'oauth-2025-04-20',
      },
      timeout: 3000,
    }, (res) => {
      // Connect-level deadline: `timeout: 3000` only fires on socket
      // idle, not on slow connect. Wrap in an outer setTimeout so a
      // hung TLS handshake doesn't keep the request open past 6s.
      const _connectDeadline = setTimeout(() => {
        try { req.destroy(new Error('connect deadline')); } catch {}
        resolve('');
      }, 6000);
      _connectDeadline.unref?.();
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        clearTimeout(_connectDeadline);
        try {
          const d = JSON.parse(data);
          const name = d.organization_name || '';
          const match = name.match(/^(.+?)(?:'s Organization| Organization)$/);
          resolve(match ? match[1] : name || '');
        } catch (e) {
          // Surface JSON parse failures so transient API issues are
          // not silently masked. The body is redacted (NOT truncated)
          // so the parser-failure point and structure stay visible
          // for diagnosis while emails / tokens / UUIDs are scrubbed.
          // Cap at 4 KiB to bound log volume on a runaway response.
          const safeBody = _redactForLog((data || '').slice(0, 4096));
          log('warn', `fetchAccountEmail: JSON parse failed (status=${res.statusCode}, len=${(data || '').length}, body=${safeBody}): ${e.message}`);
          resolve('');
        }
      });
      // Drain the socket on response error so it can be GC'd.
      res.on('error', () => { try { res.resume(); } catch {} });
    });
    req.on('error', (e) => {
      log('warn', `fetchAccountEmail: request error: ${e && e.message}`);
      resolve('');
    });
    req.on('timeout', () => { req.destroy(); resolve(''); });
  });
}

// Cache-prune helpers. Several Maps in this file used to grow without
// bound — token rotation orphans old fingerprint keys, repo discovery
// adds entries forever, etc. The two helpers below give every cache a
// shape: either a hard size cap (LRU-ish: drop first key when over)
// or a TTL prune (walk + delete entries older than X). A periodic
// timer at startup runs the TTL prune across the caches that need it.
//
// Insert helper: cap a Map by inserting AFTER deleting old entries
// when the size is already at the limit. Insertion order is preserved
// in JS Map semantics (V8 implementation), so the first key is the
// oldest. NOT strict-LRU (no on-read move-to-end) but good enough for
// the access patterns here, where reads are bursty and dominated by
// fingerprint lifetimes.
function _capMapInsert(map, key, value, maxSize) {
  if (map.has(key)) {
    map.set(key, value);
    return;
  }
  while (map.size >= maxSize) {
    const oldest = map.keys().next().value;
    if (oldest === undefined) break;
    map.delete(oldest);
  }
  map.set(key, value);
}

// TTL prune: walk a Map and delete entries whose `getTs(entry)` is
// older than `now - ttlMs`. Returns the count of dropped entries.
// Safe to call from a setInterval — bounded by map size.
function _pruneMapByTtl(map, getTs, ttlMs, now = Date.now()) {
  if (!ttlMs || ttlMs <= 0) return 0;
  const cutoff = now - ttlMs;
  let dropped = 0;
  for (const [k, v] of map) {
    const ts = getTs(v);
    if (typeof ts === 'number' && ts < cutoff) {
      map.delete(k);
      dropped++;
    }
  }
  return dropped;
}

// Cache emails so we don't hit the API on every 5s refresh.
// Capped at 500 fingerprint entries — a single user almost never has
// more than 10, but token rotation creates new fingerprints for each
// refresh and the old ones used to leak forever.
const emailCache = new Map(); // fingerprint -> { email, fetchedAt }
const EMAIL_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const EMAIL_CACHE_MAX = 500;

async function getEmailForToken(token, fp) {
  const cached = emailCache.get(fp);
  if (cached && Date.now() - cached.fetchedAt < EMAIL_CACHE_TTL) {
    return cached.email;
  }
  const email = await fetchAccountEmail(token);
  if (email) _capMapInsert(emailCache, fp, { email, fetchedAt: Date.now() }, EMAIL_CACHE_MAX);
  return email;
}

// ─────────────────────────────────────────────────
// Auto-discover: detect unknown keychain tokens and
// auto-save them as new accounts.
// ─────────────────────────────────────────────────

const ACTIVITY_LOG_FILE = join(__dirname, 'activity-log.json');
const ACTIVITY_MAX_ENTRIES = 500;
// Resolve the activity-log cap from settings (overrides the const default).
// Mirrors _tokenUsageMaxEntries — was missing, so vdm config and /api/settings
// accepted activityMaxEntries but the cap reads ignored it (silent no-op).
function _activityMaxEntries() {
  const v = (typeof settings !== 'undefined' && settings && Number.isFinite(settings.activityMaxEntries))
    ? settings.activityMaxEntries
    : 0;
  return v > 0 ? v : ACTIVITY_MAX_ENTRIES;
}
const ACTIVITY_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// Load persisted activity log on startup (prune stale entries)
let activityLog = [];
try {
  if (existsSync(ACTIVITY_LOG_FILE)) {
    const raw = JSON.parse(readFileSync(ACTIVITY_LOG_FILE, 'utf8'));
    const cutoff = Date.now() - ACTIVITY_MAX_AGE;
    activityLog = raw.filter(e => e.ts >= cutoff).slice(0, _activityMaxEntries());
  }
} catch { activityLog = []; }

function logActivity(type, detail = {}) {
  // C4 fix — coerce string `detail` to {msg: detail}. Eleven call sites in
  // earlier code passed a string here; the previous `{ ts, type, ...detail }`
  // spread on a string spreads each character into numeric-keyed properties,
  // ballooning activity-log.json with garbage like {"0":"W","1":"o",...} and
  // hiding the actual message. evtMsg's `default: h(e.msg||e.type)` fallthrough
  // now picks up the rescued .msg field.
  if (typeof detail === 'string') detail = { msg: detail };
  else if (!detail || typeof detail !== 'object' || Array.isArray(detail)) detail = {};
  const entry = { ts: Date.now(), type, ...detail };
  activityLog.unshift(entry);
  // Prune by age + cap
  const cutoff = Date.now() - ACTIVITY_MAX_AGE;
  while (activityLog.length > 0 && activityLog[activityLog.length - 1].ts < cutoff) activityLog.pop();
  const cap = _activityMaxEntries();
  if (activityLog.length > cap) activityLog.length = cap;
  // C5 fix — atomicWriteFileSync replaces the previous temp+rename async
  // write that had no per-file mutex. Two concurrent calls both targeted the
  // same `<file>.tmp`, raced the rename, and could leave partial bytes.
  // The activity log is small (capped at ACTIVITY_MAX_ENTRIES) so the sync
  // cost is negligible. atomicWriteFileSync is the canonical helper used
  // for every other state file.
  try {
    atomicWriteFileSync(ACTIVITY_LOG_FILE, JSON.stringify(activityLog));
  } catch { /* persistence is best-effort */ }
}

// ─────────────────────────────────────────────────
// Session Monitor — constants & data
// ─────────────────────────────────────────────────

const SESSION_INACTIVITY_MS = 10 * 60 * 1000; // 10 min → session considered completed
const SESSION_HISTORY_MAX = 200;               // max entries on disk
const SESSION_MAX_ACTIVE = 30;                 // max concurrent tracked sessions
const SESSION_TIMELINE_MAX = 50;               // max timeline entries per session
const SESSION_FILES_MAX = 100;                 // max filesModified per session
const SESSION_BODY_MAX = 2 * 1024 * 1024;      // 2 MB — skip parsing larger bodies
const HAIKU_TIMEOUT = 5000;                    // 5s timeout on Haiku calls
const HAIKU_BACKOFF_MS = 2 * 60 * 1000;        // 2 min backoff after 3 consecutive failures
const SESSION_AWAITING_THRESHOLD = 120000;     // 2 min idle → "awaiting input"

const monitoredSessions = new Map();           // sessionId → session object
let _summarizerOverhead = { inputTokens: 0, outputTokens: 0 };
let _haikuFailCount = 0;
let _haikuBackoffUntil = 0;

// Load persisted session history on startup
let sessionHistory = [];
try {
  if (existsSync(SESSION_HISTORY_FILE)) {
    sessionHistory = JSON.parse(readFileSync(SESSION_HISTORY_FILE, 'utf8'));
    if (!Array.isArray(sessionHistory)) sessionHistory = [];
    sessionHistory = sessionHistory.slice(0, SESSION_HISTORY_MAX);
  }
} catch { sessionHistory = []; }

// Per-account preferences.
//   excludeFromAuto: true  → pickByStrategy / pickBestAccount / pickConserve
//                            etc. all skip this account when picking the
//                            next active. The user can still manually
//                            switch to it via the dashboard or vdm CLI.
//   priority:        number → reserved for future use; not yet honoured
//                             by the picker.
// File is loaded once at startup and held in memory; mutations go through
// setAccountPref which atomically rewrites the whole map. Account names
// in the keychain are restricted to [a-zA-Z0-9._@-] so JSON-key safety
// is automatic.
let _accountPrefs = {};
try {
  if (existsSync(ACCOUNT_PREFS_FILE)) {
    const raw = JSON.parse(readFileSync(ACCOUNT_PREFS_FILE, 'utf8'));
    if (raw && typeof raw === 'object' && !Array.isArray(raw)) _accountPrefs = raw;
  }
} catch { _accountPrefs = {}; }

function getAccountPrefs(name) {
  if (!name) return { excludeFromAuto: false };
  const p = _accountPrefs[name] || {};
  return {
    excludeFromAuto: p.excludeFromAuto === true,
    priority: typeof p.priority === 'number' ? p.priority : 0,
  };
}

function setAccountPref(name, key, value) {
  if (!name || typeof name !== 'string') throw new Error('setAccountPref: name required');
  if (key !== 'excludeFromAuto' && key !== 'priority') {
    throw new Error('setAccountPref: only excludeFromAuto and priority are settable');
  }
  // Validate value shape per key. Reject anything else with a clear
  // error so callers can't accidentally persist garbage that breaks the
  // picker filter.
  if (key === 'excludeFromAuto' && typeof value !== 'boolean') {
    throw new Error('excludeFromAuto must be a boolean');
  }
  if (key === 'priority') {
    // SEC-17: clamp priority to [-100, 100]. The field is unused TODAY
    // (picker doesn't honour it) but the validation contract IS the
    // persistence contract — a future picker change that multiplies or
    // compares priorities is one PR away from a Number.MAX_VALUE
    // overflow / Infinity / NaN bug. Lock the range now.
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new Error('priority must be a finite number');
    }
    if (value < -100 || value > 100) {
      throw new Error('priority must be between -100 and 100 (inclusive)');
    }
  }
  if (!_accountPrefs[name]) _accountPrefs[name] = {};
  _accountPrefs[name][key] = value;
  // Drop empty prefs objects so the file doesn't accumulate cruft after
  // a user un-toggles their last flag for a given account.
  if (
    (_accountPrefs[name].excludeFromAuto === false || _accountPrefs[name].excludeFromAuto == null) &&
    (_accountPrefs[name].priority === 0           || _accountPrefs[name].priority           == null)
  ) {
    delete _accountPrefs[name];
  }
  try {
    atomicWriteFileSync(ACCOUNT_PREFS_FILE, JSON.stringify(_accountPrefs, null, 2));
  } catch (e) {
    log('warn', `Failed to persist account-prefs.json: ${e.message}`);
    throw e;
  }
  // Bust the loadAllAccountTokens cache so the next picker call sees
  // the new excludeFromAuto flag immediately instead of waiting for
  // the cache TTL.
  invalidateAccountsCache();
}

// Check if the current keychain creds match a saved profile.
// If not, auto-save them as a new account.
// Per-process mutex for autoDiscoverAccount. Multiple proxy requests
// arriving within the 750ms keychain-write quiescence window could
// each pass the early returns and race to write the same auto-N
// keychain entry. Once one is in flight we drop subsequent calls.
let _autoDiscoverInFlight = false;

async function autoDiscoverAccount() {
  // Skip while ANY refresh is in flight (pre- AND post-keychain-write
  // halves of the race) and for a short window after the most recent
  // keychain write (covers the tiny gap between the refresh hook
  // dropping the counter and the keychain becoming "stable").
  if (_refreshesInProgress > 0) return;
  if (Date.now() - _lastKeychainWriteAt < 750) return;
  if (_autoDiscoverInFlight) return;
  _autoDiscoverInFlight = true;
  try {
    return await _autoDiscoverAccountImpl();
  } finally {
    _autoDiscoverInFlight = false;
  }
}

async function _autoDiscoverAccountImpl() {
  const creds = readKeychain();
  if (!creds?.claudeAiOauth?.accessToken) return;
  const fp = getFingerprint(creds);

  // Enumerate saved profiles from the keychain (vdm-account-* entries)
  const savedNames = listVdmAccountKeychainEntries();

  // Resolve email for the new token so we can deduplicate by identity
  const token = creds.claudeAiOauth.accessToken;
  const email = await fetchAccountEmail(token);

  for (const savedName of savedNames) {
    try {
      const saved = readAccountKeychain(savedName);
      if (!saved) continue;
      if (getFingerprint(saved) === fp) return; // exact same token already saved

      // Same refresh token = same underlying account, even when email fetch failed
      const savedRefresh = saved.claudeAiOauth?.refreshToken;
      const currentRefresh = creds.claudeAiOauth.refreshToken;
      if (savedRefresh && currentRefresh && savedRefresh === currentRefresh) {
        writeAccountKeychain(savedName, creds);
        const oldFp = getFingerprint(saved);
        migrateAccountState(saved.claudeAiOauth?.accessToken, token, oldFp, fp, savedName);
        // log() routes through _redactForLog (line 7508); console.log
        // bypasses the redactor and leaks dynamic content (savedName,
        // email, etc.) into mode-644 startup.log. Keep all dynamic fields
        // out of console.log forever.
        log('info', `[auto-discover] Updated "${savedName}" with refreshed token (same refreshToken)`);
        if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
        invalidateTokenCache();
        return;
      }

      // Same email = same account with a refreshed token  - update in place
      if (email) {
        let savedEmail = '';
        try { savedEmail = (await readFile(join(ACCOUNTS_DIR, `${savedName}.label`), 'utf8')).trim(); } catch {}
        if (savedEmail === email) {
          writeAccountKeychain(savedName, creds);
          // Migrate persisted state / history from old fingerprint to new
          const oldFp = getFingerprint(saved);
          migrateAccountState(saved.claudeAiOauth?.accessToken, token, oldFp, fp, savedName);
          log('info', `[auto-discover] Updated "${savedName}" with refreshed token (${email})`);
          if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
          invalidateTokenCache(); // ensure getActiveToken() sees the updated token
          return;
        }
      }
    } catch { /* skip */ }
  }

  // Truly new account  - save it. Pick the lowest free auto-N slot,
  // checking both the keychain (the new home) and the leftover label
  // files in ACCOUNTS_DIR (pre-migration label files outlive the move).
  const usedNames = new Set(savedNames);
  let idx = 1;
  while (
    usedNames.has(`auto-${idx}`) ||
    existsSync(join(ACCOUNTS_DIR, `auto-${idx}.label`))
  ) idx++;

  // Cap auto-discovered accounts to prevent runaway creation during error spirals
  const MAX_AUTO_ACCOUNTS = 5;
  if (idx > MAX_AUTO_ACCOUNTS) {
    log('info', `[auto-discover] Skipping — already ${idx - 1} auto accounts (max ${MAX_AUTO_ACCOUNTS})`);
    return;
  }

  const name = `auto-${idx}`;

  writeAccountKeychain(name, creds);

  if (email) {
    try { mkdirSync(ACCOUNTS_DIR, { recursive: true }); } catch {}
    atomicWriteFileSync(join(ACCOUNTS_DIR, `${name}.label`), email);
  }

  const displayName = email || name;
  logActivity('account-discovered', { name, label: displayName });
  log('info', `[auto-discover] New account saved as "${name}" (${displayName})`);

  // Invalidate caches so the proxy picks it up
  if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
}

// Auto-discover runs on proxy requests (see handleProxyRequest),
// not on a timer  - no wasted work when idle.

// ─────────────────────────────────────────────────
// Rate limit fetcher  - uses a minimal haiku call
// to read back the rate-limit response headers.
// ─────────────────────────────────────────────────
const rateLimitCache = new Map(); // fingerprint -> { data, fetchedAt }
const RATE_LIMIT_CACHE_TTL = 5 * 60 * 1000; // 5 min  - proxy state fills the gap between probes
const RATE_LIMIT_CACHE_MAX = 500;          // cap to prevent fp leak

// ── Probe cost tracking (uses lib.mjs) ──
const probeTracker = createProbeTracker();
const PROBE_LOG_FILE = join(__dirname, 'probe-log.json');

// Load persisted probe log on startup
try {
  if (existsSync(PROBE_LOG_FILE)) {
    const raw = readFileSync(PROBE_LOG_FILE, 'utf8');
    probeTracker.load(JSON.parse(raw));
  }
} catch { /* corrupt file - start fresh */ }

function saveProbeLogToDisk() {
  try { atomicWriteFileSync(PROBE_LOG_FILE, JSON.stringify(probeTracker.toJSON())); } catch {}
}

function recordProbe() { probeTracker.record(); saveProbeLogToDisk(); }
function getProbeStats() { return probeTracker.getStats(); }

const utilizationHistory = createUtilizationHistory(); // 24h window, ~2 min intervals
const weeklyHistory = createUtilizationHistory(7 * 24 * 60 * 60 * 1000, 15 * 60 * 1000); // 7d window, ~15 min intervals

const HISTORY_FILE = join(__dirname, 'utilization-history.json');

function loadHistoryFromDisk() {
  try {
    const raw = readFileSync(HISTORY_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data.fiveH) {
      for (const [fp, entries] of Object.entries(data.fiveH)) {
        utilizationHistory.load(fp, entries);
      }
    }
    if (data.weekly) {
      for (const [fp, entries] of Object.entries(data.weekly)) {
        weeklyHistory.load(fp, entries);
      }
    }
  } catch {}
}

function saveHistoryToDisk() {
  try {
    atomicWriteFileSync(HISTORY_FILE, JSON.stringify({ fiveH: utilizationHistory.toJSON(), weekly: weeklyHistory.toJSON() }));
  } catch {}
}

loadHistoryFromDisk();

// ── macOS desktop notifications ──
// `settings.notifications` is intentionally polymorphic — both shapes
// are first-class public APIs, NOT legacy:
//   1. boolean — what the dashboard's UI checkbox writes
//      (toggleSetting('notifications', true|false)). The whole UI is one
//      single global gate by design; per-event toggles would clutter it
//      for the 99% of users who just want "on/off".
//   2. object  — per-event-type flags written by the CLI / API for the
//      power-user case ("turn off the switch beep but keep the rate-
//      limit alarm"):
//        { switch: true, exhausted: true, refreshFailed: true,
//          circuitBreaker: true, expired: true, _default: true }
// Code paths that emit a notification pass an `eventType` so the per-
// event flag (or `_default` if missing) decides whether to show. When
// settings.notifications is a boolean, every event evaluates to that
// boolean. The dual shape is what lets the UI stay simple while the
// API stays granular — keep both.
//
// Throttling is also per-event-type: a "switch" + "all-exhausted"
// arriving within the global window used to drop the second (more
// important) one. Now each event-type has its own last-fired timestamp,
// AND high-priority events (exhausted, expired, circuitBreaker,
// refreshFailed) bypass the throttle entirely so a critical follow-up
// is never silently dropped.

const NOTIFY_THROTTLE_MS = 10_000;          // default throttle (per type)
const NOTIFY_HIGH_PRIORITY = new Set([      // bypass throttling
  'exhausted', 'expired', 'circuitBreaker', 'refreshFailed',
]);
// Notification policy (Phase I+ heuristic re-tightening):
//   - SUPPRESS_ALWAYS: events that fire constantly during normal
//     operation. Activity feed still records them; OS desktop alert
//     stays silent. The user opted in to vdm; they don't need a toast
//     every refresh / circuit-close / discovery-after-the-first.
//   - COALESCE_WINDOW: events that ARE worth notifying about but only
//     once per N seconds. e.g. account-switch in burst rate-limit
//     storms — instead of N toasts, get one summary toast.
//   - HIGH_PRIORITY (above): always fire, no coalescing.
//
// Goal: a typical user who installs vdm and uses it normally for a
// week should see at most a handful of OS notifications — not one per
// proxy event.
const NOTIFY_SUPPRESS_ALWAYS = new Set([
  'refresh',                  // routine background refresh — silent
  'refresh-success',
  'circuitClose',             // good news, no action needed
  'config_change',            // user just toggled it themselves
  'queue-depth-alert',        // already surfaced in activity feed + UI badge
  'serialize-auto-disabled',  // surfaces in dashboard banner
  'all429-burst',
  'account-discovered-again', // only the FIRST discovery is worth a toast
]);
// COALESCE: type → { window_ms, max_in_window } — when more than
// max_in_window OS-notifications of this type would fire within
// window_ms, collapse into a single "(N more switches in last 5m)"
// summary at the END of the window.
const NOTIFY_COALESCE = {
  switch: { windowMs: 300_000, maxInWindow: 1 },           // 1 toast per 5 min
  '400-recovery': { windowMs: 600_000, maxInWindow: 1 },   // 1 per 10 min
  worktree: { windowMs: 60_000, maxInWindow: 0 },          // never (activity-only)
};
const _lastNotifyAtByType = Object.create(null);
const _coalesceState = Object.create(null);  // type → { count, firstAt, timer }

function _isNotifyEnabled(eventType) {
  const n = settings.notifications;
  if (n === undefined || n === null) return false;
  if (typeof n === 'boolean') return n;
  if (typeof n !== 'object') return false;
  if (eventType && Object.prototype.hasOwnProperty.call(n, eventType)) {
    return !!n[eventType];
  }
  return n._default !== false; // default ON unless explicitly disabled
}

// _decideNotifyPolicy(eventType) → 'fire' | 'suppress' | 'coalesce'
// Pure function (besides reading the always-suppress set). Lets us
// unit-test the heuristic without booting any OS-notification backend.
function _decideNotifyPolicy(eventType) {
  if (NOTIFY_SUPPRESS_ALWAYS.has(eventType)) return 'suppress';
  if (NOTIFY_HIGH_PRIORITY.has(eventType)) return 'fire';
  if (NOTIFY_COALESCE[eventType]) return 'coalesce';
  return 'fire';
}

// Detect available notification backends ONCE at startup so we don't
// fork osascript / notify-send / which on every notify() call. Result is
// the FIRST working channel for the current platform; falls back to
// 'log-only' (write to activity feed and stderr but no GUI popup) when
// neither macOS nor Linux libnotify is available.
//
// Order:
//   1. macOS              → osascript (JXA) — the project's primary platform
//   2. Linux + libnotify  → notify-send  (gracefully degrades for WSL2 / dev VMs)
//   3. anything else      → log-only — at least the activity feed + stderr show it
// Resolve the absolute path to a binary using the user's PATH at startup,
// then HARDCODE that path for every subsequent execFile. PATH-hijack
// defense: a malicious binary named `notify-send` or `osascript` placed
// earlier in PATH (e.g. ~/.local/bin/) would otherwise receive every
// notify() call's payload (account labels, error strings) on every
// rotation event. Resolving once at startup means we'd have to be
// hijacked AT module-load time, which requires file-system write
// access the dashboard process never grants to other users.
//
// Returns null if the binary isn't on PATH.
function _resolveBinary(name) {
  // /usr/bin/which is itself in a fixed system location, so it can't be
  // hijacked by a user-PATH manipulation. Avoid `command -v` because
  // that's shell-builtin and execFileSync('command', …) doesn't work.
  // execFileSync without shell — argv-only, no injection vector.
  for (const which of ['/usr/bin/which', '/bin/which']) {
    try {
      const out = execFileSync(which, [name], {
        encoding: 'utf8', timeout: 1500, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (out && out.startsWith('/')) return out;
    } catch { /* try next which */ }
  }
  return null;
}

function _detectNotifyChannel() {
  if (process.platform === 'darwin') {
    // osascript ships with macOS in /usr/bin/osascript — hardcoded
    // path means a malicious ~/.local/bin/osascript can't intercept.
    // We still verify the canonical path exists in case of a stripped
    // / sandboxed environment.
    if (existsSync('/usr/bin/osascript')) return { kind: 'osascript', path: '/usr/bin/osascript' };
    // Fallback: PATH lookup but pinned at startup. Worst case is a
    // hijacked ~/.local/bin BEFORE the dashboard starts, which is a
    // pre-existing supervisor-level compromise, not a notify-channel
    // problem.
    const resolved = _resolveBinary('osascript');
    return resolved ? { kind: 'osascript', path: resolved } : { kind: 'log-only', path: null };
  }
  if (process.platform === 'linux') {
    // Probe notify-send via `which` so we capture an absolute path AND
    // also confirm it's installed in one go. Skip the previous
    // `notify-send --version` probe — a hijacked notify-send earlier
    // in PATH would have answered just to mask itself.
    const resolved = _resolveBinary('notify-send');
    if (resolved) return { kind: 'notify-send', path: resolved };
  }
  return { kind: 'log-only', path: null };
}
const _NOTIFY_CHANNEL_INFO = _detectNotifyChannel();
const _NOTIFY_CHANNEL = _NOTIFY_CHANNEL_INFO.kind;
const _NOTIFY_BINARY = _NOTIFY_CHANNEL_INFO.path;

function notify(title, message, eventType = '') {
  if (!_isNotifyEnabled(eventType)) return;
  const now = Date.now();
  // Policy decision: fire / suppress / coalesce. The activity-log entry
  // ALWAYS happens (so the dashboard feed remains canonical); only the
  // OS-level desktop alert is filtered.
  try { log('info', `[notify:${eventType || '?'}] ${title} — ${message}`); } catch {}

  const policy = _decideNotifyPolicy(eventType);
  if (policy === 'suppress') return;
  if (policy === 'coalesce') {
    const cfg = NOTIFY_COALESCE[eventType] || { windowMs: 300_000, maxInWindow: 1 };
    let s = _coalesceState[eventType];
    if (!s || (now - s.firstAt) > cfg.windowMs) {
      // Window started: fire this notification, count subsequent ones.
      s = _coalesceState[eventType] = { count: 1, firstAt: now, timer: null };
      // Schedule a flush at end-of-window so any coalesced count gets
      // a follow-up summary toast.
      s.timer = setTimeout(() => {
        const cur = _coalesceState[eventType];
        if (cur && cur.count > 1) {
          const dropped = cur.count - cfg.maxInWindow;
          // Re-enter notify() with a synthetic title; the
          // _coalesceState is cleared FIRST so this call doesn't
          // re-coalesce itself.
          delete _coalesceState[eventType];
          if (dropped > 0) {
            notify('vdm — burst summary', `${dropped} more "${eventType}" event(s) in the last ${Math.round(cfg.windowMs/60000)}min (see dashboard activity feed for detail)`, '_summary');
          }
        } else {
          delete _coalesceState[eventType];
        }
      }, cfg.windowMs);
      if (s.timer.unref) s.timer.unref();
      // Fall through to actually fire this first one.
    } else {
      s.count++;
      // Only the first cfg.maxInWindow fires; subsequent are silenced.
      if (s.count > cfg.maxInWindow) return;
    }
  }
  // Default 10s throttle still applies as a backstop for fire/coalesce.
  if (!NOTIFY_HIGH_PRIORITY.has(eventType)) {
    const last = _lastNotifyAtByType[eventType || '_'] || 0;
    if (now - last < NOTIFY_THROTTLE_MS) return;
  }
  _lastNotifyAtByType[eventType || '_'] = now;

  if (_NOTIFY_CHANNEL === 'osascript' && _NOTIFY_BINARY) {
    try {
      // JXA (JavaScript for Automation) + JSON.stringify encodes every
      // character — backslash, newline, CR, quote — so account names
      // containing those bytes cannot break out of the string and inject
      // `do shell script`. The previous AppleScript form only escaped `"`
      // and was an RCE path through user-controlled account labels.
      const script =
        'var app = Application.currentApplication(); ' +
        'app.includeStandardAdditions = true; ' +
        'app.displayNotification(' + JSON.stringify(String(message)) +
        ', {withTitle: ' + JSON.stringify(String(title)) +
        ', soundName: "Blow"});';
      execFile(_NOTIFY_BINARY, ['-l', 'JavaScript', '-e', script], { timeout: 3000 }, (err) => {
        if (err) log('warn', `osascript notify failed: ${err.message}`);
      });
    } catch (e) {
      log('warn', `notify (osascript) threw: ${e && e.message}`);
    }
    return;
  }

  if (_NOTIFY_CHANNEL === 'notify-send' && _NOTIFY_BINARY) {
    try {
      // notify-send takes positional args: <summary> <body>. Both are
      // passed through argv (no shell), so newlines / quotes / metas
      // in the strings cannot inject. -u low avoids stealing focus on
      // GNOME / KDE.
      execFile(
        _NOTIFY_BINARY,
        ['-u', 'low', String(title), String(message)],
        { timeout: 3000 },
        (err) => {
          if (err) log('warn', `notify-send failed: ${err.message}`);
        },
      );
    } catch (e) {
      log('warn', `notify (notify-send) threw: ${e && e.message}`);
    }
    return;
  }

  // 'log-only' — already logged above. Nothing more to do.
}

function fetchRateLimits(token) {
  return new Promise((resolve) => {
    // Mimic the Anthropic TypeScript SDK request shape to look identical
    // to a real Claude Code session. Uses haiku (cheapest) with max_tokens:1.
    const body = JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1,
      messages: [{ role: 'user', content: '.' }],
    });

    // The Promise-resolution must happen exactly once, even if `error` /
    // `timeout` / `end` race against each other (which they can — `end`
    // fires after the body buffer is flushed; `error` can come from the
    // socket layer slightly later). Without this guard, a quick error +
    // late `end` produced a "resolve called twice" no-op the first time
    // and silently dropped the second resolution — the first one wins,
    // but the bug is real if the order ever flips for the worse.
    let _settled = false;
    const settle = (v) => { if (_settled) return; _settled = true; resolve(v); };
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${token}`,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'oauth-2025-04-20',
        'User-Agent': `claude-code/${CLAUDE_CODE_VERSION}`,
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        // Read rate limit headers from both 200 and 429 responses
        if (res.statusCode !== 200 && res.statusCode !== 429) {
          settle(null);
          return;
        }
        const h = res.headers;
        settle({
          status: h['anthropic-ratelimit-unified-status'] || (res.statusCode === 429 ? 'limited' : 'unknown'),
          fiveH: {
            status: h['anthropic-ratelimit-unified-5h-status'] || 'unknown',
            reset: Number(h['anthropic-ratelimit-unified-5h-reset'] || 0),
            utilization: parseFloat(h['anthropic-ratelimit-unified-5h-utilization'] || '0'),
          },
          sevenD: {
            status: h['anthropic-ratelimit-unified-7d-status'] || 'unknown',
            reset: Number(h['anthropic-ratelimit-unified-7d-reset'] || 0),
            utilization: parseFloat(h['anthropic-ratelimit-unified-7d-utilization'] || '0'),
          },
          fallbackPct: parseFloat(h['anthropic-ratelimit-unified-fallback-percentage'] || '0'),
          overageStatus: h['anthropic-ratelimit-unified-overage-status'] || 'unknown',
          overageDisabledReason: h['anthropic-ratelimit-unified-overage-disabled-reason'] || '',
          fetchedAt: Date.now(),
        });
      });
      // Response-stream errors (socket reset mid-body, malformed chunked
      // encoding, etc.) fire on `res` not `req`. Without this listener,
      // an upstream that aborts after headers but before `end` would
      // hang the Promise until req.timeout (10s) eventually fires —
      // burning the entire timeout budget on a determined error.
      res.on('error', () => { try { res.resume(); } catch {} settle(null); });
    });
    req.on('error', () => settle(null));
    req.on('timeout', () => { try { req.destroy(); } catch {} settle(null); });
    req.write(body);
    req.end();
  });
}

async function getRateLimitsForToken(token, fp, { allowProbe = true } = {}) {
  // 1. Check probe cache
  const cached = rateLimitCache.get(fp);
  if (cached && Date.now() - cached.fetchedAt < RATE_LIMIT_CACHE_TTL) {
    return cached.data;
  }

  // 2. Check proxy-tracked state (populated from real traffic  - no extra API calls)
  if (typeof accountState !== 'undefined') {
    const proxyState = accountState.get(token);
    if (proxyState && proxyState.updatedAt && Date.now() - proxyState.updatedAt < RATE_LIMIT_CACHE_TTL) {
      return {
        status: proxyState.limited ? 'limited' : 'ok',
        fiveH: {
          status: proxyState.limited ? 'limited' : 'ok',
          reset: proxyState.resetAt || 0,
          utilization: proxyState.utilization5h || 0,
        },
        sevenD: {
          status: 'ok',
          reset: proxyState.resetAt7d || 0,
          utilization: proxyState.utilization7d || 0,
        },
        fetchedAt: proxyState.updatedAt,
      };
    }
  }

  // 3. Check persisted state (survives restarts)
  const persisted = persistedState[fp];
  let fromPersisted = null;
  if (persisted && persisted.updatedAt) {
    // Pass through last-known values as-is. Don't zero out when the window
    // epoch has passed — that causes the UI to flash "0% / rolling window"
    // between data sources. The staleness indicator communicates the age.
    fromPersisted = {
      status: 'ok',
      fiveH: { status: 'ok', reset: persisted.resetAt || 0, utilization: persisted.utilization5h || 0 },
      sevenD: { status: 'ok', reset: persisted.resetAt7d || 0, utilization: persisted.utilization7d || 0 },
      fetchedAt: persisted.updatedAt,
    };
    // If probe suppressed, return persisted state (with reset-aware values)
    if (!allowProbe) return fromPersisted;
    // If persisted state is recent enough, use it
    if (Date.now() - persisted.updatedAt < RATE_LIMIT_CACHE_TTL) return fromPersisted;
  }

  // 4. Fall back to API probe  - but NOT if probing is suppressed
  //    (conserve strategy: probing a dormant account activates its rate limit window)
  if (!allowProbe) return null;

  recordProbe();
  const data = await fetchRateLimits(token);
  if (data) {
    _capMapInsert(rateLimitCache, fp, { data, fetchedAt: Date.now() }, RATE_LIMIT_CACHE_MAX);
    // Route probe data through the canonical observation pipeline. The
    // previous code wrote ONLY to persistedState, so the probe path was
    // invisible to utilizationHistory / weeklyHistory and was the root
    // cause for several user-visible prediction bugs (audit findings F2,
    // C2, C6): velocity slope was computed only from real proxy traffic
    // and the reset detector silently misfired after a probe poisoned
    // its `prevReset5h` baseline. By calling updateAccountState we fold
    // probes into the same machinery as proxy responses.
    const acctMatch = loadAllAccountTokens().find(a => getFingerprintFromToken(a.token) === fp);
    const acctName = acctMatch ? acctMatch.name : '(probe)';
    updateAccountState(token, acctName, {
      'anthropic-ratelimit-unified-status': data.status === 'limited' ? 'limited' : 'ok',
      'anthropic-ratelimit-unified-5h-utilization': String(data.fiveH.utilization || 0),
      'anthropic-ratelimit-unified-7d-utilization': String(data.sevenD.utilization || 0),
      'anthropic-ratelimit-unified-5h-reset': String(data.fiveH.reset || 0),
      'anthropic-ratelimit-unified-7d-reset': String(data.sevenD.reset || 0),
    }, fp);
    return data;
  }

  // 5. Probe failed  - fall back to stale persisted data instead of null
  if (fromPersisted) {
    fromPersisted.staleAt = fromPersisted.fetchedAt;
    return fromPersisted;
  }
  return null;
}

// ─────────────────────────────────────────────────
// Data loaders
// ─────────────────────────────────────────────────

async function loadProfiles() {
  const activeCreds = readKeychain();
  const activeFp = activeCreds ? getFingerprint(activeCreds) : '';

  // Account credentials live in the keychain (vdm-account-* services).
  // Display labels (email addresses) still live as plaintext .label files
  // alongside ACCOUNTS_DIR — those carry no secrets, just human names.
  const accountNames = listVdmAccountKeychainEntries();

  const profiles = [];
  for (const name of accountNames) {
    try {
      const creds = readAccountKeychain(name);
      if (!creds) continue;
      const oauth = creds.claudeAiOauth || {};
      const fp = getFingerprint(creds);

      // Resolve display name: try live API, then persisted .label file, then account name
      let email = '';
      if (oauth.accessToken) {
        email = await getEmailForToken(oauth.accessToken, fp);
      }
      if (!email) {
        try { email = (await readFile(join(ACCOUNTS_DIR, `${name}.label`), 'utf8')).trim(); } catch {}
      }

      const isActive = fp === activeFp;

      // Rate limit fetching strategy:
      // - Active account: always get fresh data (from probe cache or proxy state)
      // - Has persisted state with usage: use proxy state (updated from traffic), no probe needed
      // - Has persisted state at 0%: truly dormant in conserve mode, skip probe
      // - No state at all: probe ONCE to discover actual state, then persist
      let rateLimits = null;
      let dormant = false;
      if (oauth.accessToken) {
        const persisted = persistedState[fp];
        const hasProxyState = !!(accountState.get(oauth.accessToken)?.updatedAt);
        const conserveMode = settings.rotationStrategy === 'conserve';

        let allowProbe = true;
        if (conserveMode && !isActive) {
          if (hasProxyState) {
            // Proxy traffic is keeping it updated  - no probe needed
            allowProbe = false;
          } else if (persisted) {
            // Check reset-aware utilization (if window reset since we saved, it's now 0)
            const nowSec = Math.floor(Date.now() / 1000);
            const eff5h = (persisted.resetAt && persisted.resetAt < nowSec) ? 0 : (persisted.utilization5h || 0);
            const eff7d = (persisted.resetAt7d && persisted.resetAt7d < nowSec) ? 0 : (persisted.utilization7d || 0);
            if (eff5h === 0 && eff7d === 0) {
              allowProbe = false;
              dormant = true;
            }
            // else: has usage  - probe to refresh
          }
          // else: no state at all  - probe once to discover
        }

        rateLimits = await getRateLimitsForToken(oauth.accessToken, fp, { allowProbe });
      }

      // Clear stale refresh failures only if the token fingerprint has actually
      // changed since the failure was recorded (meaning a real refresh happened,
      // e.g. user ran `claude login`). Previously this cleared on expiresAt > now,
      // which hid failures when tokens had future expiry but were already rejected.
      const expiresAt = oauth.expiresAt || 0;
      const failureEntry = refreshFailures.get(name);
      if (failureEntry && failureEntry.fp && failureEntry.fp !== fp) {
        refreshFailures.delete(name);
      }

      // Check if the proxy has marked this account as expired (e.g. via 401)
      const proxyExpired = !!(accountState.get(oauth.accessToken)?.expired);

      // For the active account, prefer the live keychain's subscription/tier data
      // over stale stored files (which may predate Claude Code populating these fields).
      const activeOauth = activeCreds?.claudeAiOauth || {};
      const subType = (isActive && activeOauth.subscriptionType) ? activeOauth.subscriptionType
        : (oauth.subscriptionType || 'unknown');
      const rlTier = (isActive && activeOauth.rateLimitTier) ? activeOauth.rateLimitTier
        : (oauth.rateLimitTier || 'unknown');

      // Backfill: if the stored entry has stale/missing tier data but keychain
      // has it, update the saved entry so the data persists even when this
      // account is inactive. The keychain ops use security(1) `add -U` which
      // is itself atomic, so there's no half-written-blob window.
      if (isActive && activeOauth.rateLimitTier && activeOauth.rateLimitTier !== oauth.rateLimitTier) {
        try {
          const updatedCreds = { ...creds, claudeAiOauth: { ...oauth, subscriptionType: subType, rateLimitTier: rlTier } };
          writeAccountKeychain(name, updatedCreds);
        } catch { /* non-critical */ }
      }

      profiles.push({
        name,
        label: email || name,
        subscriptionType: subType,
        rateLimitTier: rlTier,
        expiresAt,
        isActive,
        fingerprint: fp,
        rateLimits,
        dormant,
        expired: proxyExpired,
        refreshFailed: refreshFailures.get(name) || null,
      });
    } catch {
      // skip corrupt files
    }
  }

  // Dedup pass: if two profiles resolved to the same email, keep the one with
  // the newest expiresAt and remove the other from disk. This handles duplicates
  // created when autoDiscover ran while email fetch was failing.
  const seen = new Map(); // email → profile index
  const toRemove = [];
  for (let i = 0; i < profiles.length; i++) {
    const p = profiles[i];
    // Only dedup by real email labels (skip bare account names like "auto-1")
    if (!p.label || p.label === p.name) continue;
    const prev = seen.get(p.label);
    if (prev !== undefined) {
      const prevP = profiles[prev];
      // Keep the one with the newer expiresAt; on tie, keep the active one
      const keepNew = (p.expiresAt > prevP.expiresAt) || (p.expiresAt === prevP.expiresAt && p.isActive);
      const loserIdx = keepNew ? prev : i;
      const loser = profiles[loserIdx];
      toRemove.push(loserIdx);
      try {
        deleteAccountKeychain(loser.name);
        try { unlinkSync(join(ACCOUNTS_DIR, `${loser.name}.label`)); } catch {}
        log('dedup', `Removed duplicate account "${loser.name}" (same email as "${keepNew ? p.name : prevP.name}")`);
      } catch (e) {
        log('warn', `Failed to remove duplicate account "${loser.name}": ${e.message}`);
      }
      if (keepNew) seen.set(p.label, i);
    } else {
      seen.set(p.label, i);
    }
  }
  if (toRemove.length > 0) {
    invalidateAccountsCache();
    // Return profiles with duplicates removed
    const removeSet = new Set(toRemove);
    return profiles.filter((_, i) => !removeSet.has(i));
  }

  return profiles;
}

async function loadStats() {
  try {
    const raw = await readFile(STATS_CACHE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────
// API handlers
// ─────────────────────────────────────────────────

async function handleAPI(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/api/profiles' && req.method === 'GET') {
    const profiles = await loadProfiles();
    // Attach utilization history + velocity to each profile
    for (const p of profiles) {
      p.utilizationHistory = utilizationHistory.getHistory(p.fingerprint);
      p.weeklyHistory = weeklyHistory.getHistory(p.fingerprint);
      p.velocity5h = utilizationHistory.getVelocity(p.fingerprint);
      p.velocity7d = weeklyHistory.getVelocity(p.fingerprint);
      // Pass the reset epoch so each prediction is clamped against its
      // own window. Without the clamp, a small positive velocity at 95%
      // utilization can produce "Est. 6h to limit" even when the rolling
      // window will reset in 30 minutes — the audit's "wrong estimation
      // at end of cycle" failure mode. predictMinutesToLimit returns null
      // when the projected limit is past the next reset, so the UI hides
      // the badge.  Both windows are emitted so the dashboard's 7d/30d
      // panels (the user's "30-day cycle wrong estimation" concern) get
      // the same treatment as the 5h badge — the previous code only
      // predicted the 5h window and the 7d ETA was effectively missing.
      const resetAt5h = (p.rateLimits && p.rateLimits.fiveH && p.rateLimits.fiveH.reset) || 0;
      const resetAt7d = (p.rateLimits && p.rateLimits.sevenD && p.rateLimits.sevenD.reset) || 0;
      p.minutesToLimit = utilizationHistory.predictMinutesToLimit(p.fingerprint, resetAt5h);
      p.minutesToLimit7d = weeklyHistory.predictMinutesToLimit(p.fingerprint, resetAt7d);
      // Per-account preferences. The UI shows an "Exclude from auto" toggle
      // on each card; the user can opt accounts out of rotation without
      // removing them entirely.
      const _prefs = getAccountPrefs(p.name);
      p.excludeFromAuto = _prefs.excludeFromAuto;
      p.priority        = _prefs.priority;
    }
    const stats = await loadStats();
    const probeStats = getProbeStats();
    // Check if all accounts are exhausted
    const allAccounts = loadAllAccountTokens();
    const allExhausted = allAccounts.length > 0 &&
      allAccounts.every(a => !isAccountAvailable(a.token, a.expiresAt));
    const earliestReset = allExhausted ? getEarliestReset() : null;
    json(res, { profiles, stats, probeStats, allExhausted, earliestReset, rotationStrategy: settings.rotationStrategy, queueStats: getQueueStats() });
    return true;
  }

  if (url.pathname === '/api/proxy-status' && req.method === 'GET') {
    json(res, typeof getProxyStatus === 'function' ? getProxyStatus() : {});
    return true;
  }

  if (url.pathname === '/api/switch' && req.method === 'POST') {
    const body = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(body || '{}'); } catch { parsed = {}; }
    const auto = url.searchParams.get('auto') === 'true' || parsed.auto === true;
    let { name } = parsed;
    try {
      // --auto: pick the next available account using the current rotation
      // strategy. Bypasses the interactive name lookup so it can be wired
      // into a slash command (/vdm-switch) without a UI prompt.
      if (auto) {
        const all = loadAllAccountTokens();
        if (all.length === 0) {
          json(res, { ok: false, error: 'No accounts available' }, 400);
          return true;
        }
        const activeCredsNow = readKeychain();
        const activeFp = activeCredsNow ? getFingerprint(activeCredsNow) : '';
        // Exclude the currently-active token so --auto truly switches
        const excludeTokens = new Set();
        if (activeCredsNow?.claudeAiOauth?.accessToken) {
          excludeTokens.add(activeCredsNow.claudeAiOauth.accessToken);
        }
        const picked = pickBestAccount(excludeTokens) || pickAnyUntried(excludeTokens);
        if (!picked) {
          json(res, { ok: false, error: 'No alternative account available' }, 400);
          return true;
        }
        // Sanity: don't switch to the same fingerprint we already have
        if (activeFp && getFingerprintFromToken(picked.token) === activeFp) {
          json(res, { ok: false, error: 'Only one account configured' }, 400);
          return true;
        }
        name = picked.name;
      }
      if (!name) {
        json(res, { ok: false, error: 'name required (or pass auto=true)' }, 400);
        return true;
      }
      const creds = readAccountKeychain(name);
      if (!creds) {
        json(res, { ok: false, error: `account "${name}" not found` }, 404);
        return true;
      }
      // Serialize manual switches against proxy-side rotations. Without
      // this, a UI click + an in-flight 429-driven swap can interleave
      // and leave the keychain pointing at the proxy's choice, not the
      // user's. (Concern 6 in the OAuth/keychain audit.)
      await withSwitchLock(() => {
        writeKeychain(creds);
        invalidateTokenCache();
      });
      // Log the manual switch
      let label = '';
      try { label = (await readFile(join(ACCOUNTS_DIR, `${name}.label`), 'utf8')).trim(); } catch {}
      // The user clicked Switch on a non-sticky/round-robin strategy.
      // Previously we PERMANENTLY set rotationStrategy='sticky' here,
      // which destroyed their chosen strategy across the whole session
      // (and persisted to config.json so it survived restarts). Now we
      // remember the previous strategy in `settings.previousStrategy`
      // and apply 'sticky' only as the EFFECTIVE strategy until the
      // next time the user explicitly changes settings; rotation logic
      // honours `previousStrategy` if present at next save. This way:
      //   - auto-switch on 429 still rotates as the user configured.
      //   - the explicit click sticks until the user touches settings.
      // Set `respectPreviousStrategy: false` in the body to preserve
      // the legacy "always overwrite" behaviour.
      let strategyChanged = false;
      const prevStrategy = settings.rotationStrategy;
      const respectPrev = parsed.respectPreviousStrategy !== false;
      if (prevStrategy !== 'sticky' && prevStrategy !== 'round-robin') {
        if (respectPrev && !settings.previousStrategy) {
          settings.previousStrategy = prevStrategy;
        }
        settings.rotationStrategy = 'sticky';
        saveSettings(settings);
        strategyChanged = true;
        logActivity('settings-changed', {
          autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
          rotationStrategy: 'sticky', rotationIntervalMin: settings.rotationIntervalMin,
          previousStrategy: settings.previousStrategy || null,
          reason: auto ? 'auto-switch' : 'manual-switch',
        });
      }
      lastRotationTime = Date.now();
      logActivity(auto ? 'auto-switch' : 'manual-switch', { to: label || name });
      json(res, {
        ok: true, switched: name, label: label || name,
        strategyChanged, strategy: settings.rotationStrategy,
        previousStrategy: settings.previousStrategy || null,
        auto,
      });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 400);
    }
    return true;
  }

  if (url.pathname === '/api/remove' && req.method === 'POST') {
    const body = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(body); } catch {
      json(res, { ok: false, error: 'invalid JSON' }, 400);
      return true;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      json(res, { ok: false, error: 'body must be a JSON object' }, 400);
      return true;
    }
    const { name } = parsed;
    if (!name) {
      json(res, { ok: false, error: 'name required' }, 400);
      return true;
    }
    try {
      // Verify the account exists in the keychain
      const creds = readAccountKeychain(name);
      if (!creds) {
        json(res, { ok: false, error: `account "${name}" not found` }, 404);
        return true;
      }
      // Prevent removing the active account
      const activeCreds = readKeychain();
      if (activeCreds && getFingerprint(creds) === getFingerprint(activeCreds)) {
        json(res, { ok: false, error: 'Cannot remove the active account. Switch to another account first.' }, 400);
        return true;
      }
      // Delete keychain entry + label file (label file lives outside the
      // keychain because it carries no secret)
      deleteAccountKeychain(name);
      try { await unlink(join(ACCOUNTS_DIR, `${name}.label`)); } catch {}
      // Drop any per-account preferences. Without this, removing an
      // account and later re-creating one with the same name would
      // silently revive the old excludeFromAuto / priority flags —
      // surprising behaviour that could lock someone out of their
      // own newly-created account from the auto-switch pool.
      if (_accountPrefs[name]) {
        delete _accountPrefs[name];
        try {
          atomicWriteFileSync(ACCOUNT_PREFS_FILE, JSON.stringify(_accountPrefs, null, 2));
        } catch (e) {
          log('warn', `Failed to persist account-prefs.json after remove: ${e.message}`);
        }
      }
      // LEAK-1: drop _lastWarnPct entry too. Without this, a removed
      // account's name pinned a 90%+ warn-percentage tracker entry
      // forever (small leak per account, but unbounded over a year of
      // auto-N churn).
      try { _lastWarnPct.delete(name); } catch {}
      logActivity('account-removed', { name });
      if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 400);
    }
    return true;
  }

  if (url.pathname === '/api/refresh' && req.method === 'POST') {
    const body = await readBody(req);
    let parsed;
    try { parsed = JSON.parse(body); } catch {
      json(res, { ok: false, error: 'invalid JSON' }, 400);
      return true;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      json(res, { ok: false, error: 'body must be a JSON object' }, 400);
      return true;
    }
    const { name } = parsed;
    if (!name) {
      json(res, { ok: false, error: 'name required' }, 400);
      return true;
    }
    try {
      refreshFailures.delete(name);
      const result = await refreshAccountToken(name, { force: true });
      json(res, result, result.ok ? 200 : 500);
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/activity' && req.method === 'GET') {
    json(res, { log: activityLog.slice(0, 100) });
    return true;
  }

  // Per-account preferences. GET returns the full prefs map (small JSON,
  // bounded by account count). POST validates {name, key, value} and
  // persists. The picker layer reads these via getAccountPrefs() in
  // loadAllAccountTokens, so a successful POST takes effect on the next
  // pick (we also bust the accounts cache from setAccountPref).
  if (url.pathname === '/api/account-prefs' && req.method === 'GET') {
    json(res, { ok: true, prefs: _accountPrefs });
    return true;
  }
  if (url.pathname === '/api/account-prefs' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const { name, key, value } = data || {};
      if (!name || typeof name !== 'string') {
        json(res, { ok: false, error: 'name required' }, 400);
        return true;
      }
      // Same allowed-character set as the keychain service-name validator
      // (vdmAccountServiceName) so we can't be tricked into mutating
      // some unrelated key by smuggling slashes / null bytes / etc.
      if (!/^[a-zA-Z0-9._@-]+$/.test(name) || name === 'index') {
        json(res, { ok: false, error: 'invalid account name' }, 400);
        return true;
      }
      try {
        setAccountPref(name, key, value);
      } catch (e) {
        json(res, { ok: false, error: e.message }, 400);
        return true;
      }
      logActivity('account-prefs-changed', `${name}: ${key}=${value}`);
      json(res, { ok: true, prefs: _accountPrefs[name] || null });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // SSE endpoint: stream proxy logs in real-time (used by `vdm logs`)
  if (url.pathname === '/api/logs/stream' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    // H8 fix — cap concurrent subscribers and reject 503 beyond cap. Without
    // this, a malicious tab opening N subscribers turns each log line into N
    // writes against dead sockets that never get GC'd until the OS sends RST.
    // 16 subscribers is far more than any legitimate vdm/dashboard workflow.
    const MAX_LOG_SUBSCRIBERS = 16;
    if (_logSubscribers.size >= MAX_LOG_SUBSCRIBERS) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'too many log subscribers' }));
      return true;
    }
    res.write(`data: ${JSON.stringify({ tag: 'system', msg: 'Connected to log stream', line: '--- Connected to Van Damme-o-Matic log stream ---' })}\n\n`);
    // Replay buffered history so new clients see recent logs immediately
    for (const entry of _logBuffer) {
      res.write(`data: ${JSON.stringify(entry)}\n\n`);
    }
    _logSubscribers.add(res);
    // H8 fix — also remove on 'error'. The previous close-only listener missed
    // async errors (ECONNRESET, EPIPE) that fire on the response stream after
    // the socket dies; without this the entry leaks until something else
    // triggers the synchronous-throw catch-and-delete in log().
    req.on('close', () => _logSubscribers.delete(res));
    res.on('error', () => _logSubscribers.delete(res));
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'GET') {
    json(res, settings);
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'POST') {
    const body = await readBody(req);
    let patch;
    try { patch = JSON.parse(body); } catch {
      json(res, { ok: false, error: 'invalid JSON' }, 400);
      return true;
    }
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
      json(res, { ok: false, error: 'body must be a JSON object' }, 400);
      return true;
    }
    if (typeof patch.autoSwitch === 'boolean') settings.autoSwitch = patch.autoSwitch;
    if (typeof patch.proxyEnabled === 'boolean') {
      const wasEnabled = settings.proxyEnabled;
      settings.proxyEnabled = patch.proxyEnabled;
      if (wasEnabled !== patch.proxyEnabled) {
        // Reset error state on proxy toggle for a clean slate
        _consecutive400s = 0;
        _consecutive400sAt = 0;
        _circuitOpen = false;
        _consecutiveExhausted = 0;
        if (patch.proxyEnabled) {
          log('info', 'Proxy re-enabled — clean state');
        } else {
          log('info', 'Proxy disabled — error state reset');
        }
      }
    }
    // L7 — settings.notifications is intentionally polymorphic: the
    // dashboard UI writes a boolean (one global gate), the CLI / API
    // writes a per-event-type object (granular control). NOT a legacy
    // shim — see the comment above _isNotifyEnabled. Validate the
    // object shape so a typo can't sneak an unknown key into
    // config.json.
    if (typeof patch.notifications === 'boolean') {
      settings.notifications = patch.notifications;
    } else if (patch.notifications && typeof patch.notifications === 'object') {
      const known = ['switch', 'exhausted', 'expired', 'circuitBreaker', 'refreshFailed', '_default'];
      const filtered = {};
      for (const k of known) {
        if (typeof patch.notifications[k] === 'boolean') filtered[k] = patch.notifications[k];
      }
      // Merge with existing — partial patches don't reset other channels.
      const cur = (typeof settings.notifications === 'object' && settings.notifications) ? settings.notifications : {};
      settings.notifications = { ...cur, ...filtered };
    }
    if (typeof patch.rotationStrategy === 'string' && ROTATION_STRATEGIES[patch.rotationStrategy]) {
      settings.rotationStrategy = patch.rotationStrategy;
      // User explicitly changed the strategy via Settings — clear the
      // sticky-after-manual-switch shadow so the previous-strategy
      // bookkeeping doesn't leak into the next manual switch.
      delete settings.previousStrategy;
      lastRotationTime = Date.now(); // reset timer on strategy change
    }
    if (typeof patch.rotationIntervalMin === 'number' && ROTATION_INTERVALS.includes(patch.rotationIntervalMin)) {
      settings.rotationIntervalMin = patch.rotationIntervalMin;
      lastRotationTime = Date.now(); // reset timer on interval change
    }
    if (typeof patch.serializeRequests === 'boolean') {
      settings.serializeRequests = patch.serializeRequests;
      // If turning off, drain queued requests progressively so a
      // backlog doesn't flood Anthropic in one millisecond and trip
      // an immediate rate-limit cascade. Cadence defaults to the
      // user's configured serializeDelayMs (≥250ms floor).
      if (!patch.serializeRequests) progressivelyDrainSerializationQueue('user-toggle-off');
    }
    if (typeof patch.serializeDelayMs === 'number' && patch.serializeDelayMs >= 0 && patch.serializeDelayMs <= 2000) {
      settings.serializeDelayMs = patch.serializeDelayMs;
    }
    if (Number.isFinite(patch.serializeMaxConcurrent) && patch.serializeMaxConcurrent >= 1 && patch.serializeMaxConcurrent <= 16) {
      settings.serializeMaxConcurrent = Math.floor(patch.serializeMaxConcurrent);
    }
    // Serialize-mode auto-safeguard tunables. All three breakers respect
    // serializeAutoDisableEnabled at trip time; setting that to false
    // turns off the auto-toggle without removing the safeguards (alerts
    // still log + emit activity events).
    if (typeof patch.serializeAutoDisableEnabled === 'boolean') {
      settings.serializeAutoDisableEnabled = patch.serializeAutoDisableEnabled;
    }
    if (Number.isFinite(patch.queueTimeoutBreakerThreshold) && patch.queueTimeoutBreakerThreshold >= 1 && patch.queueTimeoutBreakerThreshold <= 1000) {
      settings.queueTimeoutBreakerThreshold = Math.floor(patch.queueTimeoutBreakerThreshold);
    }
    if (Number.isFinite(patch.queueTimeoutBreakerWindowMs) && patch.queueTimeoutBreakerWindowMs >= 1000 && patch.queueTimeoutBreakerWindowMs <= 86_400_000) {
      settings.queueTimeoutBreakerWindowMs = Math.floor(patch.queueTimeoutBreakerWindowMs);
    }
    if (Number.isFinite(patch.queueDepthAlertThreshold) && patch.queueDepthAlertThreshold >= 1 && patch.queueDepthAlertThreshold <= 100_000) {
      settings.queueDepthAlertThreshold = Math.floor(patch.queueDepthAlertThreshold);
    }
    if (Number.isFinite(patch.queueDepthAlertSustainMs) && patch.queueDepthAlertSustainMs >= 1000 && patch.queueDepthAlertSustainMs <= 86_400_000) {
      settings.queueDepthAlertSustainMs = Math.floor(patch.queueDepthAlertSustainMs);
    }
    if (Number.isFinite(patch.all429BreakerWindowMs) && patch.all429BreakerWindowMs >= 1000 && patch.all429BreakerWindowMs <= 86_400_000) {
      settings.all429BreakerWindowMs = Math.floor(patch.all429BreakerWindowMs);
    }
    if (typeof patch.commitTokenUsage === 'boolean') settings.commitTokenUsage = patch.commitTokenUsage;
    if (typeof patch.sessionMonitor === 'boolean') settings.sessionMonitor = patch.sessionMonitor;
    if (typeof patch.perToolAttribution === 'boolean') settings.perToolAttribution = patch.perToolAttribution;
    // Retention knobs — user-tunable trade-off between fidelity and
    // disk. Cap each at sensible bounds so a typo can't request a 1B
    // entry buffer. Numbers are days for *_MAX_AGE_DAYS, count for
    // *_MAX_ENTRIES. Validation: positive integers within range; null
    // / undefined leaves the existing value alone.
    // L6 — single canonical name across CLI, API, config.json, and
    // DEFAULT_SETTINGS: tokenUsageMaxAgeDays. The API previously
    // accepted `tokenUsageMaxAge` (without the Days suffix) and mapped
    // it to `tokenUsageMaxAgeDays` on disk — that asymmetry made the
    // CLI need a custom alias and the field appeared under two names
    // in user-facing output. Per CLAUDE.md "no backward compatibility
    // code", the short name is removed; vdm config now sends the full
    // name.
    if (Number.isFinite(patch.tokenUsageMaxAgeDays) && patch.tokenUsageMaxAgeDays > 0 && patch.tokenUsageMaxAgeDays <= 365) {
      settings.tokenUsageMaxAgeDays = Math.floor(patch.tokenUsageMaxAgeDays);
    }
    if (Number.isFinite(patch.tokenUsageMaxEntries) && patch.tokenUsageMaxEntries > 0 && patch.tokenUsageMaxEntries <= 500_000) {
      settings.tokenUsageMaxEntries = Math.floor(patch.tokenUsageMaxEntries);
    }
    if (Number.isFinite(patch.activityMaxEntries) && patch.activityMaxEntries > 0 && patch.activityMaxEntries <= 5000) {
      settings.activityMaxEntries = Math.floor(patch.activityMaxEntries);
    }
    saveSettings(settings);
    logActivity('settings-changed', {
      autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
      rotationStrategy: settings.rotationStrategy, rotationIntervalMin: settings.rotationIntervalMin,
    });
    json(res, settings);
    return true;
  }

  // ── Phase C — viewer-state (date-range scrubber + tier filter) ──
  // GET returns the persisted window plus a freshly-computed live data
  // range so the client can clamp before render. POST validates and
  // persists. Both endpoints reject malformed input with 400 instead of
  // silently coercing — the client controls the values via drag/preset
  // and a malformed POST signals a bug, not a user error to recover from.

  if (url.pathname === '/api/viewer-state' && req.method === 'GET') {
    const persisted = loadViewerState();
    const dataRange = computeDataRange(); // null if no data
    let start, end, tierFilter;
    if (persisted && Number.isFinite(persisted.start) && Number.isFinite(persisted.end)) {
      start = persisted.start;
      end = persisted.end;
      tierFilter = Array.isArray(persisted.tierFilter) ? persisted.tierFilter : ['all'];
    } else if (dataRange) {
      // Fresh install — no persisted state. Default to the full live
      // window so every chart renders all available data on first load.
      start = dataRange.oldest;
      end = dataRange.newest;
      tierFilter = ['all'];
    } else {
      // No data AND no persisted state: collapse to "now" and let the
      // client hide the scrubber.
      const now = Date.now();
      start = now; end = now;
      tierFilter = ['all'];
    }
    // Server-side clamp: if persisted values fell outside the live data
    // range (e.g. data aged out), clampViewerState produces a sane
    // window. We only apply the clamp when dataRange exists — collapsed
    // [now,now] fallbacks already match the helper's output.
    //
    // knownTiers is left empty here on purpose: the server doesn't keep
    // a live tier list (rateLimitTier lives in account JSON files and
    // gets refreshed by /api/profiles). Empty knownTiers tells
    // clampViewerState to pass tier entries through unchanged; the
    // client revalidates against /api/profiles right after this GET.
    if (dataRange) {
      const clamped = clampViewerState({ start, end, tierFilter, dataRange, knownTiers: [] });
      start = clamped.start;
      end = clamped.end;
      tierFilter = clamped.tierFilter;
    }
    json(res, { start, end, tierFilter, dataRange });
    return true;
  }

  if (url.pathname === '/api/viewer-state' && req.method === 'POST') {
    let body;
    try {
      body = JSON.parse(await readBody(req));
    } catch {
      json(res, { ok: false, error: 'invalid JSON body' }, 400);
      return true;
    }
    if (!body || typeof body !== 'object') {
      json(res, { ok: false, error: 'body must be a JSON object' }, 400);
      return true;
    }
    // Validate ms-epoch integers. Number.isFinite + Number.isInteger
    // together reject NaN, Infinity, fractions, and non-numeric inputs.
    // The MIN_WINDOW_MS check is delegated to the client UI (which
    // clamps on drag) — we accept any valid window here and trust the
    // clamp helper at read time to enforce sanity for stale persisted
    // data. The one server-side invariant we DO enforce is start ≤ end,
    // because saving start>end could break clients that don't run their
    // own clamp.
    const start = Number(body.start);
    const end = Number(body.end);
    if (!Number.isFinite(start) || !Number.isInteger(start) || start < 0) {
      json(res, { ok: false, error: 'start must be a non-negative integer (ms epoch)' }, 400);
      return true;
    }
    if (!Number.isFinite(end) || !Number.isInteger(end) || end < 0) {
      json(res, { ok: false, error: 'end must be a non-negative integer (ms epoch)' }, 400);
      return true;
    }
    if (start > end) {
      json(res, { ok: false, error: 'start must be ≤ end' }, 400);
      return true;
    }
    let tierFilter = body.tierFilter;
    if (tierFilter == null) {
      tierFilter = ['all'];
    } else if (!Array.isArray(tierFilter) || tierFilter.some(t => typeof t !== 'string')) {
      json(res, { ok: false, error: 'tierFilter must be an array of strings' }, 400);
      return true;
    }
    saveViewerState({ start, end, tierFilter });
    json(res, { ok: true });
    return true;
  }

  // ── Session tracking for token usage ──

  if (url.pathname === '/api/session-start' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const data = JSON.parse(body);
      const sessionId = data.session_id;
      const cwd = data.cwd;
      if (!sessionId || !cwd) {
        json(res, { ok: false, error: 'session_id and cwd required' }, 400);
        return true;
      }
      // Only register new sessions — don't overwrite startedAt on subsequent
      // UserPromptSubmit hooks (otherwise we'd lose usage from earlier prompts)
      if (!pendingSessions.has(sessionId)) {
        // Sentinel for non-git cwd. Without this every throwaway scratch
        // directory (`/tmp/foo/bar`, `~/Desktop/notes`) ended up in the
        // project dropdown as a separate "project" — polluting the list
        // and making aggregate token-usage useless. (Concern 02.C2.)
        // Phase 6: branch keeps its `'(no git)'` sentinel for backwards
        // compatibility with the UI's grouping logic; appendTokenUsage
        // sites coerce to null when persisting so the on-disk schema
        // matches the spec (branchAtWriteTime: string|null).
        let repo = '(non-git)', branch = '(no git)', commitHash = '';
        // Skip git lookup for system/cache cwds. Without this, a CC
        // session that happens to fire its first prompt while cwd is
        // inside ~/.claude/plugins/cache/<plugin>/ (which is itself a
        // git checkout) attributes ALL of its tokens to that plugin —
        // even though dozens of unrelated sessions share the same
        // plugin dir. The (non-project) sentinel keeps usage bucketed
        // separately from real projects.
        if (isNonProjectCwd(cwd)) {
          repo = '(non-project)';
          log('tokens', `Session ${sessionId.slice(0, 8)}… cwd=${cwd} is non-project — using (non-project) sentinel`);
        } else {
          try {
            // Use --git-common-dir to resolve to main repo root (not worktree directory)
            // so worktree sessions group with the parent repo in the dashboard.
            // _runGitCached: session-start fires on every UserPromptSubmit, so
            // without TTL cache these four execFileSync calls would block the
            // event loop on every prompt.
            try {
              repo = _runGitCached(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']).trim().replace(/\/\.git\/?$/, '');
            } catch {
              repo = _runGitCached(cwd, ['rev-parse', '--show-toplevel']).trim();
            }
            branch = _resolveWorktreeBranch(cwd, _runGitCached(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
            commitHash = _runGitCached(cwd, ['rev-parse', '--short', 'HEAD']).trim();
            // Defense-in-depth: even if cwd looks like a real project,
            // the resolved repo path itself may be inside a system dir
            // (e.g. cwd=/Users/me/projects, but a sibling worktree
            // points back to ~/.claude/plugins/...). Apply the same
            // guard to the resolved path.
            if (repo && isNonProjectCwd(repo)) {
              log('tokens', `Session ${sessionId.slice(0, 8)}… resolved repo=${repo} is non-project — using sentinel`);
              repo = '(non-project)';
            }
          } catch { /* not a git repo — keep sentinel `repo` */ }
        }
        pendingSessions.set(sessionId, { repo, branch, commitHash, cwd, startedAt: Date.now() });
        // Fire-and-forget — async (file IO under the `_hookedRepoPaths`
        // gate). Errors are logged inside the function; awaiting would
        // serialise session-start handling behind disk latency for no
        // user-visible benefit.
        ensureLocalCommitHook(cwd).catch(e => log('warn', `ensureLocalCommitHook: ${e.message}`));
        log('tokens', `Session started: ${sessionId.slice(0, 8)}… (${basename(repo)}/${branch})`);
      } else {
        // Re-read branch on subsequent prompts (handles worktree branch switches)
        const session = pendingSessions.get(sessionId);
        // Keep cwd up to date so periodic persist and auto-claim use the latest directory
        if (cwd && cwd !== session.cwd) session.cwd = cwd;
        try {
          // _runGitCached: 30s TTL means a branch switch within a single 30s
          // window is detected on the *next* prompt after the cache expires —
          // accepted trade-off vs. blocking the event loop on every prompt.
          const newBranch = _resolveWorktreeBranch(cwd, _runGitCached(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
          if (newBranch && newBranch !== session.branch) {
            log('tokens', `Session ${sessionId.slice(0, 8)}… branch updated: ${session.branch} → ${newBranch}`);
            session.branch = newBranch;
            session.commitHash = _runGitCached(cwd, ['rev-parse', '--short', 'HEAD']).trim();
          }
        } catch { /* ignore */ }
      }
      // Prune stale sessions (>24h — sessions can be long-lived)
      const staleThreshold = Date.now() - 24 * 60 * 60 * 1000;
      for (const [id, s] of pendingSessions) {
        if (s.startedAt < staleThreshold) {
          // Auto-persist before pruning so data isn't lost
          _autoClaimSession(id, s);
          pendingSessions.delete(id);
        }
      }
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/session-stop' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const data = JSON.parse(body);
      const sessionId = data.session_id;
      if (!sessionId) {
        json(res, { ok: false, error: 'session_id required' }, 400);
        return true;
      }
      const result = _claimAndPersistForSession(sessionId, data, 'stop');
      json(res, { ok: true, claimed: result.claimed });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase 6 (Item 8h): /api/session-end — mirrors /api/session-stop but is
  // wired to Claude Code's `SessionEnd` hook, which fires once when the
  // user quits Claude Code (Cmd-Q, terminal close, /exit). Stop /
  // StopFailure don't fire when the user quits mid-turn, so without
  // SessionEnd that turn's usage would only be recovered by the 24h
  // auto-claim sweep — and even then, attribution would be stale.
  // Idempotent: an unknown sessionId is treated as already-claimed.
  if (url.pathname === '/api/session-end' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const data = JSON.parse(body);
      const sessionId = data.session_id;
      if (!sessionId) {
        json(res, { ok: false, error: 'session_id required' }, 400);
        return true;
      }
      const result = _claimAndPersistForSession(sessionId, data, 'end');
      json(res, { ok: true, claimed: result.claimed });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase D — /api/subagent-start: SubagentStart hook fires when Claude
  // Code spawns a sub-agent. Without this endpoint, SubagentStop's
  // session_id is unknown to the dashboard and usage gets either dropped
  // or attributed to the parent via the CL-3 fallback (correct repo, wrong
  // sessionId/agentType). Pre-registering here means SubagentStop fires
  // with a known session_id and the row inherits parentSessionId/agentType
  // automatically via _attachSessionAttribution.
  if (url.pathname === '/api/subagent-start' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseSubagentStartPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, parentSessionId, agentType, cwd } = parsed;
      // Idempotent: if we've already registered this sub-agent (e.g. the
      // hook fired twice — Claude Code retries on transport failure), just
      // refresh the branch via the cached git wrapper and return success.
      if (pendingSessions.has(sessionId)) {
        const existing = pendingSessions.get(sessionId);
        if (cwd && cwd !== existing.cwd) existing.cwd = cwd;
        if (existing.cwd) {
          try {
            const newBranch = _resolveWorktreeBranch(existing.cwd, _runGitCached(existing.cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
            if (newBranch && newBranch !== existing.branch) existing.branch = newBranch;
          } catch { /* ignore */ }
        }
        json(res, { ok: true, registered: 'subagent', idempotent: true });
        return true;
      }
      // Locate the parent session. Three paths in priority order:
      //   (a) parentSessionId is provided AND in pendingSessions → inherit
      //       repo/branch/commitHash (the user's PR attribution stays with
      //       the orchestrator's session).
      //   (b) parentSessionId not provided OR not in pendingSessions, but
      //       there IS an active main session whose cwd is an ANCESTOR of
      //       the subagent's cwd → inherit from that. Catches the worktree
      //       case where the subagent runs in /tmp/cc-worktree-xyz spawned
      //       from /Users/.../my-project (no exact-cwd match).
      //   (c) Still no match → use the most-recently-active main session
      //       (no parentSessionId) as the inferred parent. Catches subagents
      //       spawned with totally unrelated cwds (plugin caches, etc.).
      //   (d) Last resort: compute repo from subagent's own cwd, with the
      //       isNonProjectCwd guard so plugin/system paths fall through to
      //       a sentinel rather than polluting the project list.
      let repo = '(non-git)', branch = '(no git)', commitHash = '';
      let parent = parentSessionId ? pendingSessions.get(parentSessionId) : null;
      let parentResolution = parent ? 'explicit' : null;

      // Path (b): ancestor-cwd matching across active main sessions.
      if (!parent && cwd) {
        let bestMatch = null;
        let bestStart = -Infinity;
        for (const [, s] of pendingSessions) {
          if (s.parentSessionId) continue; // skip subagents — only main sessions can be parents
          if (!s.cwd) continue;
          // Subagent's cwd is inside the main session's cwd?
          const subPath = cwd.replace(/\/+$/, '');
          const mainPath = s.cwd.replace(/\/+$/, '');
          if (subPath === mainPath || subPath.startsWith(mainPath + '/')) {
            if (s.startedAt > bestStart) { bestStart = s.startedAt; bestMatch = s; }
          }
        }
        if (bestMatch) { parent = bestMatch; parentResolution = 'ancestor-cwd'; }
      }

      // Path (c): most-recently-active main session, regardless of cwd.
      // Only fires when cwd is non-project (plugin cache / temp / system) —
      // otherwise we'd risk attributing a legitimate orphan subagent to the
      // wrong main session. For non-project cwds, "wrong main session" is
      // strictly better than "the plugin that hosts the script".
      if (!parent && cwd && isNonProjectCwd(cwd)) {
        let bestMatch = null;
        let bestStart = -Infinity;
        for (const [, s] of pendingSessions) {
          if (s.parentSessionId) continue;
          if (s.startedAt > bestStart) { bestStart = s.startedAt; bestMatch = s; }
        }
        if (bestMatch) { parent = bestMatch; parentResolution = 'most-recent-main'; }
      }

      if (parent) {
        // Inherit parent's repo/branch but record the sub-agent's own cwd
        // (a sub-agent in a worktree has a distinct cwd; the dashboard
        // already rolls worktrees back to the parent repo via
        // --git-common-dir).
        repo = parent.repo;
        branch = parent.branch;
        commitHash = parent.commitHash;
      } else if (cwd) {
        // Path (d): resolve from subagent's own cwd. Apply the non-project
        // guard so plugin caches / system dirs fall through to sentinel.
        if (isNonProjectCwd(cwd)) {
          repo = '(non-project)';
          log('tokens', `Subagent ${sessionId.slice(0, 8)}… cwd=${cwd} is non-project AND no parent resolvable — using (non-project) sentinel`);
        } else {
          try {
            try {
              repo = _runGitCached(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']).trim().replace(/\/\.git\/?$/, '');
            } catch {
              repo = _runGitCached(cwd, ['rev-parse', '--show-toplevel']).trim();
            }
            if (repo && isNonProjectCwd(repo)) {
              repo = '(non-project)';
            }
            branch = _resolveWorktreeBranch(cwd, _runGitCached(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
            commitHash = _runGitCached(cwd, ['rev-parse', '--short', 'HEAD']).trim();
          } catch { /* not a git repo — keep sentinel `repo` */ }
        }
      }
      if (parentResolution) {
        log('tokens', `Subagent ${sessionId.slice(0, 8)}… parent resolved via ${parentResolution} → repo=${repo}`);
      }
      pendingSessions.set(sessionId, {
        repo,
        branch,
        commitHash,
        cwd: cwd || (parent ? parent.cwd : null),
        startedAt: Date.now(),
        // Phase D — sub-agent attribution
        parentSessionId: parentSessionId || null,
        agentType: agentType || null,
      });
      log('tokens', `Sub-agent started: ${sessionId.slice(0, 8)}… (parent ${(parentSessionId || 'unknown').slice(0, 8)}, type ${agentType || 'unknown'})`);
      json(res, { ok: true, registered: 'subagent' });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase D — /api/pre-compact: PreCompact hook fires before context
  // compaction. We append a compact_boundary marker row to token-usage.json
  // so the dashboard can render a "compaction" tick at the right ts.
  // Aggregation readers skip type !== 'usage' rows so the marker doesn't
  // get summed as input/output tokens (see isUsageRow in lib.mjs).
  if (url.pathname === '/api/pre-compact' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseCompactPayload(data, 'pre');
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, trigger, preTokens } = parsed;
      const session = pendingSessions.get(sessionId);
      appendCompactBoundary({
        sessionId,
        repo: session ? session.repo : '(non-git)',
        branch: session ? (session.branch ?? null) : null,
        commitHash: session ? session.commitHash : '',
        trigger,
        preTokens,
        postTokens: null,
        account: null,
      });
      log('tokens', `Pre-compact: ${sessionId.slice(0, 8)}… (trigger=${trigger}, preTokens=${preTokens})`);
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase D — /api/post-compact: PostCompact hook fires after compaction
  // completes. We append a second compact_boundary marker (with postTokens)
  // and clear the session's lastBatchToolNames so the next per-tool
  // attribution claim doesn't double-count cache tokens that were already
  // discarded during compaction. (Per the contract §3: "PostCompact also
  // clears any in-flight cache-creation tracking for that session so the
  // next claim doesn't double-count cache tokens.")
  if (url.pathname === '/api/post-compact' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseCompactPayload(data, 'post');
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, trigger, preTokens, postTokens } = parsed;
      const session = pendingSessions.get(sessionId);
      appendCompactBoundary({
        sessionId,
        repo: session ? session.repo : '(non-git)',
        branch: session ? (session.branch ?? null) : null,
        commitHash: session ? session.commitHash : '',
        trigger,
        preTokens,
        postTokens,
        account: null,
      });
      // Clear in-flight per-tool tracking — compaction discards the cache
      // and we MUST NOT attribute the next round-trip's cache_creation
      // tokens to the tool that triggered compaction.
      if (session) {
        session.lastBatchToolNames = [];
      }
      log('tokens', `Post-compact: ${sessionId.slice(0, 8)}… (trigger=${trigger}, ${preTokens}→${postTokens})`);
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase D — /api/cwd-changed: CwdChanged hook fires when Claude Code's
  // working directory changes (e.g. `cd` between prompts). We re-resolve
  // the session's branch so subsequent appendTokenUsage calls record the
  // post-cd branch. Already-buffered usage retains the old branch (good —
  // it WAS emitted while in the old cwd).
  if (url.pathname === '/api/cwd-changed' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseCwdChangedPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, cwd } = parsed;
      const session = pendingSessions.get(sessionId);
      if (session) {
        session.cwd = cwd;
        try {
          // _runGitCached: first call for `cwd` after `cd` is naturally fresh
          // (no prior cache entry under this key). Subsequent CwdChanged
          // events for the same cwd within 30s will hit cache — that's fine,
          // the branch under a stable cwd doesn't change between two
          // back-to-back hooks.
          const newBranch = _resolveWorktreeBranch(cwd, _runGitCached(cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
          if (newBranch && newBranch !== session.branch) {
            log('tokens', `Cwd-changed: session ${sessionId.slice(0, 8)}… branch updated: ${session.branch} → ${newBranch}`);
            session.branch = newBranch;
            session.commitHash = _runGitCached(cwd, ['rev-parse', '--short', 'HEAD']).trim();
          }
        } catch { /* not a git repo — keep prior branch */ }
      }
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase D — /api/post-tool-batch (gated): PostToolBatch hook fires after
  // a batch of parallel tool calls resolves. Only registered when
  // settings.perToolAttribution === true. Per the contract §3 (Refinement
  // 1), we attach the batch's tool names to the session's
  // lastBatchToolNames — `_attachSessionAttribution` then tags the next
  // appendTokenUsage row with `tool` (comma-joined) and `mcpServer`
  // (derived from the first mcp__ tool in the batch).
  if (url.pathname === '/api/post-tool-batch' && req.method === 'POST') {
    if (!settings.perToolAttribution) {
      // Endpoint disabled when the gate is off — return 404 so the hook
      // installer can detect "this endpoint isn't accepting events" and
      // skip subscribing on the next install/uninstall cycle.
      json(res, { ok: false, error: 'per-tool attribution disabled' }, 404);
      return true;
    }
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parsePostToolBatchPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, tools } = parsed;
      const session = pendingSessions.get(sessionId);
      let recorded = 0;
      if (session && tools.length > 0) {
        // Per the contract: "the simpler choice is to attach a
        // lastBatchToolNames: string[] array on the pendingSession at
        // PostToolBatch time, and then when the next appendTokenUsage for
        // that session fires, set tool: lastBatchToolNames.join(',') and
        // mcpServer: <derived>. This avoids 10x row inflation."
        // M10 fix — cap to 32 unique tool names. A pathological PostToolBatch
        // with 1000 entries would otherwise produce a 1000-string array that
        // gets `join(',')`-stringified and persisted on every appendTokenUsage
        // row until the next batch arrives. 32 is well above any realistic
        // single-batch tool count and bounds the per-row payload.
        const _seen = new Set();
        const _names = [];
        for (const t of tools) {
          if (_names.length >= 32) break;
          if (!t || typeof t.toolName !== 'string' || _seen.has(t.toolName)) continue;
          _seen.add(t.toolName);
          _names.push(t.toolName);
        }
        session.lastBatchToolNames = _names;
        recorded = tools.length;
      }
      json(res, { ok: true, recorded });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase E — /api/worktree-create: WorktreeCreate hook fires when Claude
  // Code (or a sub-agent) creates a new git worktree. We log the event to
  // the activity feed but DON'T mutate the session's branch — Claude Code
  // doesn't `cd` into the new worktree on creation, only on a subsequent
  // CwdChanged. This is mostly here for completeness so the event isn't
  // silently dropped, and so the activity feed can correlate worktree
  // lifecycle with token-attribution shifts.
  if (url.pathname === '/api/worktree-create' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseWorktreeEventPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, worktreePath, branch } = parsed;
      logActivity('worktree_create', `Worktree created at ${worktreePath}${branch ? ` (branch ${branch})` : ''}`);
      log('tokens', `Worktree created: ${sessionId.slice(0, 8)}… → ${worktreePath}${branch ? ` (${branch})` : ''}`);
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase E — /api/worktree-remove: WorktreeRemove hook fires when a git
  // worktree is removed. The critical case: a session was attributed to
  // that worktree's branch and continues running. Without this event, the
  // session keeps writing token rows tagged with the now-deleted branch.
  // We re-resolve the session's branch from its current cwd (if the cwd
  // still exists post-removal — a session in the removed worktree's own
  // dir will fail and fall back to '(no git)' which is the truthful
  // outcome).
  if (url.pathname === '/api/worktree-remove' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseWorktreeEventPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, worktreePath, branch } = parsed;
      const session = pendingSessions.get(sessionId);
      let rebranched = false;
      // Worktree removal invalidates ANY cached git answer for paths under
      // it — drop them so the re-resolve below + future hot-path calls see
      // fresh state. Also drop cached entries for the session's own cwd
      // when it's not the same as worktreePath.
      _invalidateRunGitCache(worktreePath);
      if (session && session.cwd) {
        _invalidateRunGitCache(session.cwd);
        // If the session's cwd is INSIDE the removed worktree, _runGit will
        // throw — that's the correct signal that the branch is now invalid.
        // Use the uncached _runGit here: the cache was just cleared, but we
        // also explicitly want the freshest possible answer for the rebranch
        // decision.
        try {
          const newBranch = _resolveWorktreeBranch(session.cwd, _runGit(session.cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
          if (newBranch && newBranch !== session.branch) {
            session.branch = newBranch;
            try {
              session.commitHash = _runGit(session.cwd, ['rev-parse', '--short', 'HEAD']).trim();
            } catch { /* ignore */ }
            rebranched = true;
          }
        } catch {
          // cwd is gone — mark branch as unresolvable; future appendTokenUsage
          // calls will record null branch (worktree-aware aggregation handles
          // this correctly).
          if (session.branch !== '(no git)') {
            session.branch = '(no git)';
            session.commitHash = '';
            rebranched = true;
          }
        }
      }
      logActivity('worktree_remove', `Worktree removed: ${worktreePath}${branch ? ` (was ${branch})` : ''}`);
      log('tokens', `Worktree removed: ${sessionId.slice(0, 8)}… → ${worktreePath}${rebranched ? ` (rebranched)` : ''}`);
      json(res, { ok: true, rebranched });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase E — /api/task-created and /api/task-completed: agent-team task
  // lifecycle events. These complement SubagentStart/Stop with task-level
  // metadata (the Task tool's description, status). When the parent session
  // is in pendingSessions we link the taskId so SubagentStop can include
  // task context in its log line; otherwise the event is recorded for the
  // activity feed only.
  if ((url.pathname === '/api/task-created' || url.pathname === '/api/task-completed') && req.method === 'POST') {
    const kind = url.pathname === '/api/task-created' ? 'created' : 'completed';
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseTaskEventPayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, taskId, parentSessionId, agentType, status, description } = parsed;
      // Link the task to the parent session so SubagentStart/Stop log lines
      // can reference it. We DO NOT register the task as a separate session
      // — sub-agent events are still the source of truth for token
      // attribution; tasks are pure metadata.
      const parent = parentSessionId ? pendingSessions.get(parentSessionId) : null;
      if (parent) {
        if (!parent.activeTaskIds) parent.activeTaskIds = new Set();
        if (kind === 'created') {
          parent.activeTaskIds.add(taskId);
        } else {
          parent.activeTaskIds.delete(taskId);
        }
      }
      const detail = description ? ` — ${description.slice(0, 80)}${description.length > 80 ? '…' : ''}` : '';
      logActivity(`task_${kind}`, `Task ${kind}: ${taskId.slice(0, 12)}…${agentType ? ` [${agentType}]` : ''}${status ? ` (${status})` : ''}${detail}`);
      log('tokens', `Task ${kind}: ${taskId.slice(0, 12)}… session=${sessionId.slice(0, 8)}…${parent ? ' (parent linked)' : ''}`);
      json(res, { ok: true, linked: !!parent });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase E — /api/teammate-idle: TeammateIdle hook fires when an
  // agent-teams teammate goes idle. Purely informational — we log it to
  // the activity feed so users can correlate idle gaps with the timeline,
  // but it doesn't affect token attribution.
  if (url.pathname === '/api/teammate-idle' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const parsed = parseTeammateIdlePayload(data);
      if (!parsed.ok) {
        json(res, { ok: false, error: parsed.error }, 400);
        return true;
      }
      const { sessionId, teammateId } = parsed;
      logActivity('teammate_idle', `Teammate idle${teammateId ? ` (${teammateId})` : ''} session=${sessionId.slice(0, 8)}…`);
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase G — /api/notification: Notification hook fires for permission
  // prompts, idle prompts, auth-success, and elicitation dialogs. The
  // load-bearing case is `auth_success` — when a user runs /login, this
  // hook fires immediately and lets vdm invalidate its keychain cache so
  // the next proxy request reads the freshly-rotated token instead of
  // the stale one. (Without this, the user has to wait up to 30 seconds
  // for Claude Code's own keychain cache + vdm's KC_CACHE_TTL to expire.)
  if (url.pathname === '/api/notification' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      if (!data || typeof data !== 'object') {
        json(res, { ok: false, error: 'payload must be an object' }, 400);
        return true;
      }
      const sessionId = typeof data.session_id === 'string' ? data.session_id : null;
      const notifType = typeof data.notification_type === 'string' ? data.notification_type : 'unknown';
      const notifMsg = typeof data.notification_message === 'string'
        ? data.notification_message.slice(0, 200)
        : '';
      // auth_success: invalidate caches so vdm picks up new keychain state.
      // Other types are activity-feed only.
      if (notifType === 'auth_success') {
        invalidateTokenCache();
        invalidateAccountsCache();
        log('tokens', `Auth success — keychain caches invalidated (session ${sessionId ? sessionId.slice(0, 8) + '…' : 'unknown'})`);
        logActivity('auth_success', `User authenticated${notifMsg ? ': ' + notifMsg : ''}`);
      } else {
        logActivity(`notification_${notifType}`, notifMsg || `Notification: ${notifType}`);
      }
      json(res, { ok: true, type: notifType });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase G — /api/config-change: ConfigChange hook fires when settings.json
  // changes mid-session. Useful because vdm itself rewrites the file when
  // toggling per-tool-attribution.flag — we use this to detect when an
  // EXTERNAL tool (devcontainer rebuild, Husky, another plugin install) has
  // stomped on settings and may have removed vdm's hook block. The activity
  // feed entry tells the user "your hooks may need re-installing".
  if (url.pathname === '/api/config-change' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const settingsKey = (data && typeof data.setting_key === 'string') ? data.setting_key : '';
      const filePath = (data && typeof data.file_path === 'string') ? data.file_path : '';
      const detail = settingsKey
        ? `key=${settingsKey}${filePath ? ' (' + filePath + ')' : ''}`
        : filePath || 'unknown change';
      logActivity('config_change', `Settings changed: ${detail}`);
      log('tokens', `ConfigChange: ${detail}`);
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase G — /api/user-prompt-expansion: UserPromptExpansion fires after
  // /skill-name or @-mention expansion. We log the expanded skill / mention
  // to the activity feed so users can see what skill ran for a given turn.
  // Per-skill token attribution (binding the next Stop's token deltas to
  // this skill name) is a Phase H follow-up — would require a per-session
  // state machine to remember "the next Stop fires for skill X".
  if (url.pathname === '/api/user-prompt-expansion' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      let data;
      try { data = JSON.parse(body); }
      catch { json(res, { ok: false, error: 'invalid JSON' }, 400); return true; }
      const expansionType = (data && typeof data.expansion_type === 'string') ? data.expansion_type : 'unknown';
      const commandName = (data && typeof data.command_name === 'string') ? data.command_name : '';
      const commandSource = (data && typeof data.command_source === 'string') ? data.command_source : '';
      const sessionId = (data && typeof data.session_id === 'string') ? data.session_id : '';
      const detail = commandName
        ? `${expansionType}:${commandName}${commandSource ? ' (' + commandSource + ')' : ''}`
        : expansionType;
      logActivity('user_prompt_expansion', `Expansion: ${detail}`);
      if (sessionId && commandName) {
        log('tokens', `UserPromptExpansion: ${sessionId.slice(0, 8)}… ran ${detail}`);
      }
      json(res, { ok: true, type: expansionType });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase H — /api/otel-events: query the in-memory OTel ring buffers.
  // Read-only; activates when CSW_OTEL_ENABLED=1 (returns empty otherwise).
  // Query params:
  //   kind=logs|metrics|both (default: both)
  //   name=<event-name>      filter by event body (logs) or metric name (metrics)
  //   limit=<N>              cap result count (default 500, max OTEL_BUFFER_MAX)
  //   since=<ts-ms>          only entries with ts >= since
  if (url.pathname === '/api/otel-events' && req.method === 'GET') {
    try {
      const kind = url.searchParams.get('kind') || 'both';
      const nameFilter = url.searchParams.get('name') || '';
      const sinceStr = url.searchParams.get('since');
      const limitStr = url.searchParams.get('limit');
      const since = sinceStr ? Number(sinceStr) : 0;
      const limit = Math.min(limitStr ? Number(limitStr) : 500, OTEL_BUFFER_MAX);
      const filter = (rec, isLog) => {
        if (since && rec.ts < since) return false;
        if (nameFilter) {
          const cmp = isLog ? (typeof rec.body === 'string' ? rec.body : '') : rec.name;
          if (cmp !== nameFilter) return false;
        }
        return true;
      };
      const out = { ok: true, enabled: OTEL_ENABLED, stats: _otelStats };
      if (kind === 'logs' || kind === 'both') {
        out.logs = _otelLogs.filter(r => filter(r, true)).slice(-limit);
      }
      if (kind === 'metrics' || kind === 'both') {
        out.metrics = _otelMetrics.filter(r => filter(r, false)).slice(-limit);
      }
      json(res, out);
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // Phase E — /api/token-usage/by-tool: aggregate token usage by tool name
  // (with mcpServer disambiguation) for the dashboard's Tool Breakdown
  // panel. Range is parsed from query string (start, end as ms-since-epoch);
  // both are optional. Skips compact_boundary rows via aggregateByTool's
  // built-in isUsageRow filter.
  if (url.pathname === '/api/token-usage/by-tool' && req.method === 'GET') {
    try {
      const rows = loadTokenUsage();
      const startStr = url.searchParams.get('start');
      const endStr = url.searchParams.get('end');
      const range = (startStr || endStr) ? {
        start: startStr ? Number(startStr) : null,
        end: endStr ? Number(endStr) : null,
      } : null;
      const buckets = aggregateByTool(rows, range);
      json(res, { ok: true, buckets });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/token-usage/flush' && req.method === 'POST') {
    // Force all active sessions to claim and persist unclaimed usage now.
    // Same logic as the periodic timer, but triggered on demand (used by commit hooks).
    try {
      let flushed = 0;
      for (const [sessionId, session] of pendingSessions) {
        const now = Date.now();
        if (session.cwd) {
          try {
            const cur = _resolveWorktreeBranch(session.cwd, _runGitCached(session.cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
            if (cur && cur !== session.branch) {
              session.branch = cur;
              session.commitHash = _runGitCached(session.cwd, ['rev-parse', '--short', 'HEAD']).trim();
            }
          } catch { /* ignore */ }
        }
        const claimed = claimUsageInRange(session.startedAt, now);
        for (const entry of claimed) {
          appendTokenUsage(_attachSessionAttribution(sessionId, session, {
            ts: entry.ts, repo: session.repo,
            // Phase 6: branchAtWriteTime null-safe.
            branch: session.branch ?? null,
            commitHash: session.commitHash, model: entry.model,
            inputTokens: entry.inputTokens, outputTokens: entry.outputTokens,
            cacheReadInputTokens: entry.cacheReadInputTokens || 0,
            cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
            messageId: entry.messageId ?? null,
            account: entry.account,
          }));
        }
        if (claimed.length > 0) {
          session.startedAt = now;
          flushed += claimed.length;
        }
      }
      if (flushed > 0) log('tokens', `Flush: persisted ${flushed} entries on demand`);
      json(res, { ok: true, flushed });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/token-usage' && req.method === 'GET') {
    try {
      const usage = loadTokenUsage();
      // Phase D — aggregation default: filter out compact_boundary rows so
      // existing clients that sum inputTokens/outputTokens don't accidentally
      // include marker rows. Clients that want compaction markers can pass
      // ?includeMarkers=1 to get the full stream back.
      const includeMarkers = url.searchParams.get('includeMarkers') === '1';
      let filtered = includeMarkers ? usage : usage.filter(isUsageRow);
      const repo = url.searchParams.get('repo');
      const branch = url.searchParams.get('branch');
      const since = url.searchParams.get('since');
      const limit = parseInt(url.searchParams.get('limit') || '0', 10);
      if (repo) filtered = filtered.filter(e => e.repo === repo);
      if (branch) filtered = filtered.filter(e => e.branch === branch);
      if (since) filtered = filtered.filter(e => e.ts >= Number(since));
      if (limit > 0) filtered = filtered.slice(-limit);
      json(res, filtered);
    } catch (e) {
      json(res, [], 500);
    }
    return true;
  }

  // TRDD-1645134b Phase 2 — /api/token-usage-tree
  // Returns the 4-level tree (repo → branch/worktree → component → tool)
  // computed by aggregateUsageTree, plus optionally the cache-miss
  // report. Mirrors /api/token-usage's query-param contract:
  //   repo=<path>          — single-repo filter
  //   account=<name>       — single-account filter
  //   model=<id>           — single-model filter
  //   from=<ms>            — earliest ts (epoch ms)
  //   to=<ms>              — latest ts (epoch ms)
  //   since=<ms>           — alias for from (matches existing endpoint)
  //   includeMisses=1      — include cache-miss report (default: off)
  //   minMissInput=<n>     — override the cache-miss input threshold
  //                          (default 1000)
  //
  // Response:
  //   {
  //     ok: true,
  //     totals: { input, output, cacheRead, cacheCreate, requests },
  //     tree:   [ <repoNode>, ... ],   // sorted heavy-first
  //     misses: [...] | undefined      // only when includeMisses=1
  //   }
  //
  // The aggregation is computed on-demand from the on-disk usage rows.
  // For typical 50K-row token-usage.json this completes in <50ms — no
  // caching layer needed. If usage volume grows past ~500K rows,
  // re-evaluate.
  if (url.pathname === '/api/token-usage-tree' && req.method === 'GET') {
    try {
      const rows = loadTokenUsage();
      const params = url.searchParams;
      const opts = {};
      const repoFilter    = params.get('repo');
      const accountFilter = params.get('account');
      const modelFilter   = params.get('model');
      const fromStr       = params.get('from') || params.get('since');
      const toStr         = params.get('to');
      if (repoFilter)    opts.repoFilter    = repoFilter;
      if (accountFilter) opts.accountFilter = accountFilter;
      if (modelFilter)   opts.modelFilter   = modelFilter;
      if (fromStr) {
        const n = Number(fromStr);
        if (Number.isFinite(n)) opts.from = n;
      }
      if (toStr) {
        const n = Number(toStr);
        if (Number.isFinite(n)) opts.to = n;
      }
      // Phase 4 — CSV export branch. Same query-param contract as the
      // JSON response (repo/account/model/from/to all honored), but emits
      // the flat tree-aggregated rows from aggregateUsageForCsvExport
      // instead of the nested tree. Returns text/csv with a download
      // filename so a browser fetch+blob can save it directly.
      if (params.get('format') === 'csv') {
        const flat = aggregateUsageForCsvExport(rows, opts);
        const csv = renderUsageTreeCsv(flat);
        const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        res.writeHead(200, {
          'content-type': 'text/csv; charset=utf-8',
          'content-disposition': `attachment; filename="token-usage-tree-${stamp}.csv"`,
          'cache-control': 'no-store',
        });
        res.end(csv);
        return true;
      }
      const { totals, tree } = aggregateUsageTree(rows, opts);
      const response = { ok: true, totals, tree };
      if (params.get('includeMisses') === '1') {
        const missOpts = {};
        const minMissInputStr = params.get('minMissInput');
        if (minMissInputStr) {
          const n = Number(minMissInputStr);
          if (Number.isFinite(n) && n >= 0) missOpts.minInputForMissDetection = n;
        }
        // The cache-miss heuristic operates on the same rows but applies
        // the time-range filter inline (the function has no opts.from/to
        // because it's session-scoped, not range-scoped — so we pre-
        // filter here). Other filters (repo/account/model) are NOT
        // applied to misses on the theory that a user investigating
        // a cache-miss issue may want the full-session view.
        // NOTE: keep type='compact' rows in missRows even when
        // pre-filtering — buildCacheMissReport reads them to attribute
        // miss reasons (compact-boundary). Stripping them here would
        // silently degrade Phase 5 reason classification to "TTL-likely
        // or unknown" for every miss in a filtered view.
        let missRows = rows;
        if (opts.from != null || opts.to != null) {
          missRows = rows.filter(r => {
            if (!r) return false;
            const t = r.type || 'usage';
            if (t !== 'usage' && t !== 'compact') return false;
            if (opts.from != null && r.ts < opts.from) return false;
            if (opts.to   != null && r.ts > opts.to)   return false;
            return true;
          });
        }
        response.misses = buildCacheMissReport(missRows, missOpts);
        // Phase 5 — per-session aggregate. Same opts so the two stay
        // consistent. The summary uses the SAME flat-miss list under
        // the hood so the two views can never disagree.
        response.missSessions = summarizeCacheMissesBySession(missRows, missOpts);
        // Phase 6 — "tokens fully paid due to cache miss" time series
        // for the new carousel chart. Sent UNFILTERED-by-repo on
        // purpose — the UI's multi-select dropdown filters in memory
        // so changing the dropdown doesn't round-trip to the server.
        response.wastedSpend = buildWastedSpendSeries(missRows, missOpts);
      }
      json(res, response);
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  // ── Session Monitor API ──

  if (url.pathname === '/api/sessions' && req.method === 'GET') {
    const now = Date.now();
    const active = [];
    for (const [, s] of monitoredSessions) {
      active.push({
        id: s.id,
        account: s.account,
        model: s.model,
        cwd: s.cwd,
        repo: s.repo,
        branch: s.branch,
        timeline: s.timeline,
        currentActivity: s.currentActivity,
        requestCount: s.requestCount,
        totalInputTokens: s.totalInputTokens,
        totalOutputTokens: s.totalOutputTokens,
        startedAt: s.startedAt,
        lastActiveAt: s.lastActiveAt,
      });
    }
    // Sort: processing first, then by lastActiveAt desc
    active.sort((a, b) => {
      const aProc = (now - a.lastActiveAt) < SESSION_AWAITING_THRESHOLD;
      const bProc = (now - b.lastActiveAt) < SESSION_AWAITING_THRESHOLD;
      if (aProc !== bProc) return aProc ? -1 : 1;
      return b.lastActiveAt - a.lastActiveAt;
    });
    const recent = sessionHistory.slice(0, 20);
    json(res, {
      enabled: !!settings.sessionMonitor,
      active,
      recent,
      overhead: _summarizerOverhead,
      conflicts: getFileConflicts(),
    });
    return true;
  }

  return false;
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// Hard size cap on dashboard control-plane request bodies. Every /api/*
// handler that accepts a POST body uses readBody, and none of them
// legitimately need more than ~10KB (settings patch, account-prefs
// toggle, hook payload). Unbounded Buffer.concat lets a same-origin
// browser tab DoS the dashboard with a single multi-MB request — the
// CSRF allow-list rejects mutations from foreign origins, but the user's
// own tabs CAN reach this surface and a malicious page they navigated
// to could cost RAM via fetch('/api/account-prefs', { body: '<1GB>' }).
// 1 MiB is far above any legitimate payload while staying well clear of
// V8's Buffer.concat fragmentation threshold.
const READ_BODY_MAX = 1024 * 1024;
// SEC-11: per-request cap is necessary but not sufficient. Without a
// global cap, an attacker (or a confused local script) opening 200
// concurrent POSTs to /api/* with 1 MiB each accumulates 200 MiB
// across `chunks[]` arrays + per-handler scope, OOM-killing the
// dashboard. The proxy server already has `_bufferedBytes` /
// `MAX_GLOBAL_BUFFERED`; mirror that for the dashboard server.
const READ_BODY_GLOBAL_MAX = 64 * 1024 * 1024; // 64 MiB across ALL in-flight /api requests
let _apiBufferedBytes = 0;

function readBody(req, maxBytes = READ_BODY_MAX) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let aborted = false;
    let countedTotal = 0; // bytes already added to _apiBufferedBytes
    const _refundAndCleanup = () => {
      _apiBufferedBytes = Math.max(0, _apiBufferedBytes - countedTotal);
      countedTotal = 0;
      // Detach data listener so any chunk that arrives in the
      // socket-destroy window cannot re-increment _apiBufferedBytes
      // (PROXY-7 in the reliability audit).
      try { req.removeAllListeners('data'); } catch {}
    };
    req.on('data', c => {
      if (aborted) return;
      total += c.length;
      if (total > maxBytes) {
        aborted = true;
        const e = new Error('request body exceeded ' + maxBytes + ' bytes');
        e.code = 'E_BODY_TOO_LARGE';
        _refundAndCleanup();
        try { req.destroy(e); } catch {}
        reject(e);
        return;
      }
      if (_apiBufferedBytes + c.length > READ_BODY_GLOBAL_MAX) {
        aborted = true;
        const e = new Error('global API body buffer exceeded ' + READ_BODY_GLOBAL_MAX + ' bytes');
        e.code = 'E_GLOBAL_BUFFER_FULL';
        _refundAndCleanup();
        try { req.destroy(e); } catch {}
        reject(e);
        return;
      }
      _apiBufferedBytes += c.length;
      countedTotal += c.length;
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      const result = Buffer.concat(chunks).toString();
      _refundAndCleanup();
      resolve(result);
    });
    req.on('error', e => {
      if (aborted) return;
      _refundAndCleanup();
      reject(e);
    });
    req.on('close', () => {
      // Catches the case where the client closes the socket before
      // 'end' or 'error' fires. Without this, _apiBufferedBytes leaks
      // on dropped connections.
      if (countedTotal > 0) _refundAndCleanup();
    });
  });
}

// ─────────────────────────────────────────────────
// HTML Dashboard
// ─────────────────────────────────────────────────

function renderHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Van Damme-o-Matic</title>
<!-- vdm intentionally uses the OS system-ui stack instead of fetching
     Inter from Google Fonts. The previous preconnect+stylesheet pair
     leaked the dashboard visit (IP, User-Agent, timing) to Google's
     edge on every page load, contradicting the project's
     zero-dependency / privacy-first stance and breaking the dashboard
     for users behind captive portals or strict outbound-proxy SOCs. -->
<style>
  /* A11y: visually hidden but exposed to assistive tech. Lets us add
     <label for> associations to the dashboard's CSS-styled toggle
     switches without affecting the visual layout. */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
  :root {
    --bg: hsl(220 14% 96%);
    --card: #fff;
    --foreground: hsl(224 71% 4%);
    --muted: hsl(220 9% 46%);
    --border: hsl(220 13% 91%);
    --primary: hsl(217 91% 60%);
    --primary-soft: hsl(217 91% 97%);
    --green: hsl(142 71% 45%);
    --green-soft: hsl(142 76% 94%);
    --green-border: hsl(142 60% 80%);
    --yellow: hsl(38 92% 50%);
    --yellow-soft: hsl(48 100% 95%);
    --yellow-border: hsl(48 80% 75%);
    --red: hsl(0 84% 60%);
    --red-soft: hsl(0 86% 97%);
    --red-border: hsl(0 70% 85%);
    --blue-soft: hsl(217 91% 97%);
    --blue-border: hsl(217 60% 85%);
    --purple: hsl(271 81% 56%);
    --purple-soft: hsl(271 81% 97%);
    --purple-border: hsl(271 50% 85%);
    --cyan: hsl(187 85% 43%);
    --cyan-soft: hsl(187 70% 95%);
    --cyan-border: hsl(187 50% 80%);
    --shadow: 0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.06);
    --shadow-lg: 0 4px 12px -2px rgba(0,0,0,0.06), 0 2px 6px -1px rgba(0,0,0,0.04);
    --radius: 14px;
    --radius-sm: 10px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--foreground);
    min-height: 100vh;
    padding: 2.5rem 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 720px; margin: 0 auto; }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 1.5rem;
  }
  .header-left h1 {
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
  }
  .header-sub {
    font-size: 0.9375rem;
    color: var(--muted);
  }
  .ctrl {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    user-select: none;
  }
  .sw {
    position: relative;
    width: 32px;
    height: 18px;
    -webkit-appearance: none;
    appearance: none;
    background: var(--border);
    border-radius: 9px;
    cursor: pointer;
    transition: background 0.2s;
    outline: none;
    border: none;
  }
  .sw::before {
    content: '';
    position: absolute;
    top: 2px; left: 2px;
    width: 14px; height: 14px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0,0,0,0.15);
    transition: transform 0.2s;
  }
  .sw:checked { background: var(--green); }
  .sw:checked::before { transform: translateX(14px); }
  /* ── Config tab ── */
  .config-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    overflow: hidden;
  }
  .config-section {
    padding: 1.25rem 1.5rem;
  }
  .config-section + .config-section {
    border-top: 1px solid var(--border);
  }
  .config-section-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 0.875rem;
  }
  .config-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    padding: 0.5rem 0;
  }
  .config-row + .config-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    padding-top: 0.75rem;
    margin-top: 0.25rem;
  }
  .config-info { flex: 1; min-width: 0; }
  .config-label {
    font-size: 0.9375rem;
    font-weight: 500;
    color: var(--foreground);
  }
  .config-desc {
    font-size: 0.8125rem;
    color: var(--muted);
    margin-top: 0.125rem;
    line-height: 1.4;
  }
  .config-select {
    background: var(--card);
    color: var(--foreground);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.375rem 0.625rem;
    font-size: 0.875rem;
    font-weight: 500;
    font-family: inherit;
    cursor: pointer;
    outline: none;
    min-width: 120px;
  }
  .config-select:hover { border-color: var(--primary); }
  .strategy-list {
    margin-top: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
  }
  .strategy-item {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    padding: 0.5rem 0.625rem;
    border-radius: 8px;
    border: 1px solid transparent;
    transition: background 0.15s, border-color 0.15s;
  }
  .strategy-item.active {
    background: color-mix(in srgb, var(--primary) 8%, transparent);
    border-color: color-mix(in srgb, var(--primary) 25%, transparent);
  }
  .strategy-item-name {
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--foreground);
    white-space: nowrap;
    min-width: 5.5rem;
  }
  .strategy-item.active .strategy-item-name { color: var(--primary); }
  .strategy-item-desc {
    font-size: 0.8125rem;
    color: var(--muted);
    line-height: 1.4;
  }
  .config-select:focus { border-color: var(--primary); box-shadow: 0 0 0 2px var(--blue-soft); }

  /* ── Tabs ── */
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1.25rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.25rem;
    box-shadow: var(--shadow);
  }
  .tab {
    flex: 1;
    padding: 0.5rem 0;
    font-size: 0.9375rem;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    border: none;
    border-radius: 8px;
    background: none;
    transition: all 0.15s;
    font-family: inherit;
  }
  .tab:hover { color: var(--foreground); }
  .tab.active {
    background: var(--primary);
    color: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
  }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* ── Account cards ── */
  .accounts { display: flex; flex-direction: column; gap: 0.625rem; }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.25rem 1.5rem;
    transition: box-shadow 0.2s, border-color 0.2s;
  }
  .card:hover { box-shadow: var(--shadow-lg); }
  .card.active { border-color: var(--green); border-width: 2px; }
  .card.stale { opacity: 0.5; }
  .card.stale:hover { opacity: 0.7; }
  .stale-msg {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: var(--red);
    line-height: 1.4;
  }
  .stale-msg code {
    background: var(--bg);
    padding: 0.1em 0.4em;
    border-radius: 3px;
    font-size: 0.85em;
  }

  .card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }
  .card-identity {
    display: flex;
    align-items: center;
    gap: 0.625rem;
  }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .status-dot.active { background: var(--green); box-shadow: 0 0 0 3px hsl(142 71% 45% / 0.15); }
  .status-dot.inactive { background: var(--border); }
  .card-name {
    font-size: 1.0625rem;
    font-weight: 600;
  }
  .card-token-sep {
    color: var(--border);
    font-size: 0.875rem;
  }
  .card-token {
    font-size: 0.8125rem;
    color: var(--foreground);
    font-weight: 400;
  }

  .card-badges { display: flex; gap: 0.375rem; align-items: center; }
  .badge {
    display: inline-flex;
    align-items: center;
    font-size: 0.75rem;
    font-weight: 500;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    border: 1px solid;
  }
  .badge-max { color: var(--cyan); background: var(--cyan-soft); border-color: var(--cyan-border); }
  .badge-pro { color: var(--primary); background: var(--blue-soft); border-color: var(--blue-border); }
  .badge-free { color: var(--muted); background: var(--bg); border-color: var(--border); }
  .badge-active { color: var(--green); background: var(--green-soft); border-color: var(--green-border); }

  .card-token.tok-bad { color: var(--red); }

  /* Rate limit bars */
  .rate-bars {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 3rem;
  }
  .rate-group {}
  .rate-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.3125rem;
  }
  .rate-label {
    font-size: 0.75rem;
    color: var(--muted);
    font-weight: 500;
  }
  .rate-pct {
    font-size: 0.75rem;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .pct-ok { color: var(--green); }
  .pct-mid { color: var(--yellow); }
  .pct-high { color: var(--red); }
  .rate-track {
    height: 4px;
    background: var(--bg);
    border-radius: 2px;
    overflow: hidden;
  }
  .rate-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.4s ease;
  }
  .fill-ok { background: var(--green); }
  .fill-mid { background: var(--yellow); }
  .fill-high { background: var(--red); }
  .fill-full { background: var(--red); animation: pulse-fill 1.5s infinite; }
  @keyframes pulse-fill { 0%,100%{opacity:1} 50%{opacity:0.5} }
  .rate-reset {
    font-size: 0.6875rem;
    color: var(--muted);
    margin-top: 0.1875rem;
    font-variant-numeric: tabular-nums;
  }

  .switch-btn {
    padding: 0.5rem 1.125rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--foreground);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
  }
  .switch-btn:hover {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  }
  .switch-btn:active { transform: scale(0.98); }

  .remove-btn {
    padding: 0.375rem 0.75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
  }
  .remove-btn:hover {
    background: #dc2626;
    color: #fff;
    border-color: #dc2626;
  }

  .refresh-btn {
    padding: 0.375rem 0.75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--primary);
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
  }
  .refresh-btn:hover {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
  }

  .card.switching { opacity: 0.5; pointer-events: none; }

  /* ── Session Monitor ── */
  .session-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 0.875rem 1rem;
    margin-bottom: 0.75rem;
    border-left: 3px solid var(--muted);
    position: relative;
  }
  .session-card.processing { border-left-color: #3fb950; }
  .session-card.awaiting { border-left-color: var(--yellow); }
  .session-card.completed { border-left-color: var(--muted); opacity: 0.85; }
  .session-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    color: var(--muted);
    margin-bottom: 0.5rem;
    cursor: pointer;
    user-select: none;
  }
  .session-card.collapsed .session-header { margin-bottom: 0; }
  .session-header b { color: var(--foreground); font-weight: 600; }
  .session-header-left { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .session-header-right { flex-shrink: 0; white-space: nowrap; display: flex; align-items: center; gap: 0.5rem; margin-left: 0.5rem; }
  .session-collapse-indicator { font-size: 0.625rem; color: var(--muted); transition: transform 0.15s; }
  .session-card.collapsed .session-collapse-indicator { transform: rotate(-90deg); }
  .session-card.collapsed .session-timeline,
  .session-card.collapsed .session-meta,
  .session-card.collapsed .session-copy-btn { display: none; }
  .session-collapsed-activity {
    display: none;
    font-size: 0.75rem;
    color: var(--muted);
    font-style: italic;
    margin-top: 0.375rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .session-card.collapsed .session-collapsed-activity { display: block; }
  .session-awaiting {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    background: var(--yellow-soft);
    color: var(--yellow);
    border: 1px solid var(--yellow-border);
    border-radius: 4px;
    padding: 0.0625rem 0.375rem;
    font-size: 0.6875rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .session-timeline {
    font-size: 0.8125rem;
    line-height: 1.6;
    margin: 0.375rem 0;
    max-height: 500px;
    overflow-y: auto;
  }
  .tl-input {
    color: var(--foreground);
    font-weight: 600;
  }
  .tl-input::before { content: '\\2192 '; color: var(--primary); }
  .tl-action {
    color: var(--muted);
    padding-left: 1.25rem;
  }
  .tl-action::before { content: '\\21B3 '; }
  .tl-current {
    color: var(--muted);
    padding-left: 1.25rem;
    font-style: italic;
    font-size: 0.75rem;
  }
  .session-meta {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.375rem;
    display: flex;
    gap: 0.75rem;
  }
  .session-conflicts {
    background: rgba(248,81,73,0.08);
    border: 1px solid rgba(248,81,73,0.3);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.75rem;
    font-size: 0.8125rem;
    color: #f85149;
  }
  .session-copy-btn {
    position: absolute;
    bottom: 0.5rem;
    right: 0.5rem;
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    color: var(--muted);
    opacity: 0;
    transition: opacity 0.15s;
  }
  .session-card:hover .session-copy-btn { opacity: 1; }
  .session-copy-btn:hover { background: var(--surface); }
  .tab-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--yellow);
    color: #000;
    font-size: 0.625rem;
    font-weight: 700;
    min-width: 1rem;
    height: 1rem;
    border-radius: 0.5rem;
    padding: 0 0.25rem;
    margin-left: 0.375rem;
    vertical-align: middle;
  }
  .session-section-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 0.75rem 0 0.375rem;
  }
  .session-overhead {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.75rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--border);
  }
  @keyframes braille-spin {
    0%   { content: '\\280B'; }
    10%  { content: '\\2819'; }
    20%  { content: '\\2839'; }
    30%  { content: '\\2838'; }
    40%  { content: '\\283C'; }
    50%  { content: '\\2834'; }
    60%  { content: '\\2826'; }
    70%  { content: '\\2827'; }
    80%  { content: '\\2807'; }
    90%  { content: '\\280F'; }
  }
  .braille-spin::before {
    content: '\\280B';
    animation: braille-spin 1.2s steps(1) infinite;
    margin-right: 0.25rem;
  }
  .braille-static::before {
    content: '\\28FF';
    margin-right: 0.25rem;
    opacity: 0.6;
  }

  /* ── Activity log ── */
  .activity-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1rem 1.25rem;
    max-height: 500px;
    overflow-y: auto;
  }
  .evt {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--bg);
    font-size: 0.875rem;
  }
  .evt:last-child { border-bottom: none; }
  .evt-time {
    color: var(--muted);
    font-size: 0.8125rem;
    white-space: nowrap;
    min-width: 100px;
    font-variant-numeric: tabular-nums;
  }
  .evt-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .evt-msg { flex: 1; color: var(--muted); line-height: 1.4; }
  .evt-msg b { color: var(--foreground); font-weight: 600; }

  /* ── Usage ── */
  .usage-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.5rem;
  }
  .usage-title {
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 1.25rem;
  }
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .stat-item {
    background: var(--bg);
    border-radius: var(--radius-sm);
    padding: 1rem 0.75rem;
    text-align: center;
  }
  .stat-val {
    font-size: 1.375rem;
    font-weight: 700;
    color: var(--foreground);
    font-variant-numeric: tabular-nums;
  }
  .stat-label {
    font-size: 0.6875rem;
    color: var(--muted);
    font-weight: 500;
    margin-top: 0.25rem;
  }
  .chart-legend {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
    margin-bottom: 0.5rem;
    font-size: 0.6875rem;
    color: var(--muted);
  }
  .chart-legend-item { display: flex; align-items: center; gap: 0.3rem; }
  .chart-legend-dot { width: 8px; height: 8px; border-radius: 2px; }
  .chart-container {
    height: 160px;
    display: flex;
    align-items: flex-end;
    gap: 3px;
  }
  .chart-day {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 0;
  }
  .chart-bars {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    width: 100%;
    justify-content: center;
    height: 125px;
  }
  .chart-bar {
    flex: 1;
    min-width: 4px;
    max-width: 16px;
    border-radius: 3px 3px 0 0;
    transition: height 0.3s;
    position: relative;
    cursor: default;
  }
  .chart-bar:hover { opacity: 0.75; z-index: 20; }
  .chart-bar:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--foreground);
    color: #fff;
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.6875rem;
    white-space: nowrap;
    z-index: 10;
    pointer-events: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .chart-bar.msg-bar { background: var(--primary); }
  .chart-bar.tok-bar { background: var(--purple); opacity: 0.6; }
  .chart-label {
    font-size: 0.625rem;
    color: var(--muted);
    margin-top: 0.375rem;
  }

  /* ── Toast ── */
  .toast {
    position: fixed;
    bottom: 1.5rem;
    left: 50%;
    transform: translateX(-50%) translateY(80px);
    background: var(--foreground);
    color: #fff;
    padding: 0.625rem 1.25rem;
    border-radius: var(--radius-sm);
    font-size: 0.8125rem;
    font-weight: 500;
    opacity: 0;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 100;
    box-shadow: 0 8px 20px rgba(0,0,0,0.15);
  }
  .toast.show { transform: translateX(-50%) translateY(0); opacity: 1; }

  .empty-state {
    text-align: center;
    padding: 3rem 1.5rem;
    color: var(--muted);
    font-size: 0.875rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .empty-state code {
    background: var(--bg);
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    font-size: 0.8125rem;
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: hsl(220 9% 46% / 0.25); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: hsl(220 9% 46% / 0.4); }

  /* ── Exhausted banner ── */
  .exhausted-banner {
    background: hsl(0 60% 15%);
    border: 1px solid hsl(0 50% 30%);
    border-radius: var(--radius-sm);
    padding: 0.625rem 1rem;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.625rem;
    font-size: 0.875rem;
    color: hsl(0 80% 80%);
    animation: pulse-border 2s ease-in-out infinite;
  }
  @keyframes pulse-border {
    0%, 100% { border-color: hsl(0 50% 30%); }
    50% { border-color: hsl(0 70% 50%); }
  }
  .exhausted-icon {
    width: 22px; height: 22px;
    border-radius: 50%;
    background: hsl(0 60% 40%);
    color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 0.8125rem;
    flex-shrink: 0;
  }

  /* ── Sparklines ── */
  .sparkline-wrap {
    margin-top: 0.375rem;
    width: 100%;
  }
  .sparkline-svg { display: block; width: 100%; height: auto; }
  .velocity-badge {
    font-size: 0.6875rem;
    font-weight: 500;
    color: var(--muted);
    white-space: nowrap;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.125rem 0.5rem;
    font-variant-numeric: tabular-nums;
  }
  .velocity-badge.velocity-ok { color: var(--green); border-color: var(--green-border); background: var(--green-soft); }
  .velocity-badge.velocity-warn { color: var(--yellow); border-color: var(--yellow-border); background: var(--yellow-soft); }
  .velocity-badge.velocity-crit { color: var(--red); border-color: var(--red-border); background: var(--red-soft); }

  /* ── Animations ── */
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .card { animation: fadeInUp 0.3s ease-out; }

  /* ── Tokens tab ── */
  .tok-filters {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }
  .tok-filters .config-select {
    flex: 1;
    min-width: 100px;
  }
  .tok-proportion {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 1rem;
  }
  .tok-proportion-seg {
    height: 100%;
    transition: width 0.3s;
  }
  .tok-model-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0;
    font-size: 0.875rem;
    flex-wrap: wrap;
  }
  .tok-model-row + .tok-model-row {
    border-top: 1px solid var(--bg);
  }
  .tok-model-dot {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex-shrink: 0;
  }
  .tok-model-name {
    font-weight: 500;
    min-width: 120px;
  }
  .tok-model-detail {
    color: var(--muted);
    font-size: 0.8125rem;
    flex: 1;
  }
  .tok-model-total {
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .tok-model-pct {
    color: var(--muted);
    font-size: 0.8125rem;
    font-variant-numeric: tabular-nums;
    min-width: 3rem;
    text-align: right;
  }
  .tok-branch-row {
    padding: 0.75rem 0;
    font-size: 0.875rem;
  }
  .tok-branch-row + .tok-branch-row {
    border-top: 1px solid var(--bg);
  }
  .tok-branch-name {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }
  .tok-branch-badge {
    font-size: 0.6875rem;
    font-weight: 500;
    color: var(--cyan);
    background: var(--cyan-soft);
    border: 1px solid var(--cyan-border);
    border-radius: 4px;
    padding: 0.0625rem 0.375rem;
  }
  .tok-branch-stats {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-top: 0.25rem;
  }
  .tok-branch-total {
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .tok-branch-pct {
    color: var(--muted);
    font-size: 0.8125rem;
    font-variant-numeric: tabular-nums;
  }
  .tok-branch-detail {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.25rem;
    line-height: 1.6;
  }
  #tok-stats.stat-grid { grid-template-columns: repeat(5, 1fr); }
  .tok-stat-sub { font-size: 0.5625rem; color: var(--muted); margin-top: 0.0625rem; }
  .tok-savings-banner {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    color: var(--muted);
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }
  .tok-savings-banner select {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--foreground);
  }
  .tok-savings-val { color: var(--green); font-weight: 600; }
  .tok-trend { font-size: 0.6875rem; font-weight: 500; margin-top: 0.125rem; }
  .tok-trend.up { color: var(--red); }
  .tok-trend.down { color: var(--green); }
  .tok-repo-group { margin-bottom: 0.25rem; }
  .tok-repo-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.625rem 0;
    cursor: pointer;
    user-select: none;
  }
  .tok-repo-header:hover { opacity: 0.8; }
  .tok-repo-group + .tok-repo-group .tok-repo-header {
    border-top: 1px solid var(--bg);
  }
  .tok-repo-chevron {
    font-size: 0.625rem;
    color: var(--muted);
    transition: transform 0.15s;
    flex-shrink: 0;
    width: 1rem;
    text-align: center;
  }
  .tok-repo-chevron.collapsed { transform: rotate(-90deg); }
  .tok-repo-name { font-weight: 600; }
  .tok-repo-inactive { opacity: 0.5; }
  .tok-branch-inactive { opacity: 0.6; }
  .tok-inactive-sep {
    font-size: 0.6875rem;
    color: var(--muted);
    padding: 0.75rem 0 0.25rem;
    border-top: 1px dashed var(--border);
    margin-top: 0.5rem;
  }
  .tok-model-cost {
    font-size: 0.8125rem;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
    min-width: 4rem;
    text-align: right;
  }
  /* TRDD-1645134b Phase 3 — usage tree view */
  .tree-view {
    font-family: var(--mono);
    font-size: 0.8125rem;
    line-height: 1.5;
  }
  .tree-view details { margin: 0; }
  .tree-view summary {
    list-style: none;
    cursor: pointer;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .tree-view summary::-webkit-details-marker { display: none; }
  .tree-view summary:hover { background: var(--bg); }
  .tree-view summary::before {
    content: "▶";
    font-size: 0.625rem;
    color: var(--text-muted);
    transition: transform 0.1s ease-in-out;
    display: inline-block;
    width: 0.625rem;
    flex-shrink: 0;
  }
  .tree-view details[open] > summary::before { transform: rotate(90deg); }
  .tree-view .tree-leaf {
    padding: 0.25rem 0.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .tree-view .tree-leaf::before {
    content: "·";
    color: var(--text-muted);
    width: 0.625rem;
    flex-shrink: 0;
    text-align: center;
  }
  .tree-view .tree-children { padding-left: 1.25rem; }
  .tree-view .tree-name {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .tree-view .tree-kind-icon {
    flex-shrink: 0;
    font-size: 0.6875rem;
    padding: 0.0625rem 0.375rem;
    border-radius: 3px;
    background: var(--bg);
    color: var(--text-muted);
  }
  .tree-view .tree-kind-icon.repo      { background: var(--blue-soft);    color: var(--blue); }
  .tree-view .tree-kind-icon.branch    { background: var(--green-soft);   color: var(--green); }
  .tree-view .tree-kind-icon.worktree  { background: var(--yellow-soft);  color: var(--yellow); }
  .tree-view .tree-kind-icon.component { background: var(--purple-soft);  color: var(--purple); }
  .tree-view .tree-kind-icon.tool      { background: var(--bg); color: var(--text-muted); }
  .tree-view .tree-totals {
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
    color: var(--text);
  }
  .tree-view .tree-totals .tree-pct {
    color: var(--text-muted);
    font-size: 0.75rem;
    margin-left: 0.375rem;
  }
  .tree-view .tree-cache-badge {
    flex-shrink: 0;
    font-size: 0.625rem;
    padding: 0.0625rem 0.375rem;
    border-radius: 3px;
    background: var(--bg);
    color: var(--text-muted);
    font-variant-numeric: tabular-nums;
  }
  .tree-view .tree-cache-badge.high { background: var(--green-soft); color: var(--green); }
  .tree-view .tree-cache-badge.low  { background: var(--yellow-soft); color: var(--yellow); }
  .tree-view .tree-loading,
  .tree-view .tree-empty,
  .tree-view .tree-error {
    padding: 0.5rem;
    color: var(--text-muted);
    font-style: italic;
  }
  .tree-view .tree-error { color: var(--red); }
  .tree-misses-card { margin-top: 1rem; }
  .tree-misses-card .miss-row {
    display: flex;
    gap: 0.5rem;
    padding: 0.25rem 0.5rem;
    font-family: var(--mono);
    font-size: 0.75rem;
    border-bottom: 1px solid var(--border);
  }
  .tree-misses-card .miss-row:last-child { border-bottom: none; }
  .tree-misses-card .miss-ts { color: var(--text-muted); flex-shrink: 0; }
  .tree-misses-card .miss-account { flex: 1; overflow: hidden; text-overflow: ellipsis; }
  .tree-misses-card .miss-tokens { font-variant-numeric: tabular-nums; flex-shrink: 0; }
  /* Phase 5 — per-session grouping + model + reason columns. */
  .tree-misses-card .miss-session {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-bottom: 0.5rem;
    background: var(--bg);
  }
  .tree-misses-card .miss-session > summary {
    cursor: pointer;
    padding: 0.4rem 0.6rem;
    display: flex;
    gap: 0.5rem;
    align-items: center;
    font-size: 0.78rem;
    list-style: none;
  }
  .tree-misses-card .miss-session > summary::-webkit-details-marker { display: none; }
  .tree-misses-card .miss-session > summary::before {
    content: "▶";
    display: inline-block;
    transition: transform 0.15s ease;
    color: var(--text-muted);
    width: 0.7rem;
    flex-shrink: 0;
  }
  .tree-misses-card .miss-session[open] > summary::before { transform: rotate(90deg); }
  .tree-misses-card .miss-sess-id {
    font-family: var(--mono);
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .tree-misses-card .miss-sess-loc {
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--text-muted);
  }
  .tree-misses-card .miss-rate-badge {
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 0.1rem 0.4rem;
    border-radius: var(--radius-sm);
    flex-shrink: 0;
  }
  .tree-misses-card .miss-rate-badge.high {
    background: var(--green-soft);
    color: var(--green);
  }
  .tree-misses-card .miss-rate-badge.low {
    background: var(--red-soft);
    color: var(--red);
  }
  .tree-misses-card .miss-rate-counts { color: var(--text-muted); }
  .tree-misses-card .miss-model {
    font-family: var(--mono);
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .tree-misses-card .miss-reason {
    font-family: var(--mono);
    font-size: 0.7rem;
    padding: 0.05rem 0.3rem;
    border-radius: var(--radius-sm);
    flex-shrink: 0;
    background: var(--bg);
    color: var(--text-muted);
  }
  /* Reason-specific tints — reuse existing soft palette so we don't
     introduce a new color set. compact-boundary is benign (user
     action), TTL-likely is the most common (default red-soft because
     it represents "you re-paid for cache build"), model-changed is
     rare. unknown stays neutral. */
  .tree-misses-card .miss-reason.reason-TTL-likely {
    background: var(--yellow-soft);
    color: var(--yellow);
  }
  .tree-misses-card .miss-reason.reason-compact-boundary {
    background: var(--blue-soft);
    color: var(--primary);
  }
  .tree-misses-card .miss-reason.reason-model-changed {
    background: var(--purple-soft);
    color: var(--purple);
  }

  .tok-export-btn {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--foreground);
    font-size: 0.75rem;
    padding: 0.375rem 0.75rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .tok-export-btn:hover { background: var(--bg); }
  .tok-chart-wrap {
    display: flex;
    align-items: flex-end;
    gap: 2px;
  }
  .tok-chart-bar-area {
    height: 120px;
    display: flex;
    align-items: flex-end;
    justify-content: center;
    width: 100%;
  }
  .tok-chart-bar-group {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 4px;
  }
  .tok-chart-stack {
    width: 100%;
    max-width: 28px;
    display: flex;
    flex-direction: column-reverse;
  }
  .tok-chart-seg {
    width: 100%;
    min-height: 0;
    transition: height 0.3s;
    position: relative;
    cursor: default;
  }
  .tok-chart-seg:first-child { border-radius: 0 0 2px 2px; }
  .tok-chart-seg:last-child { border-radius: 2px 2px 0 0; }
  .tok-chart-seg:hover { opacity: 0.75; z-index: 20; }
  .tok-chart-seg:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--foreground);
    color: #fff;
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.6875rem;
    white-space: nowrap;
    z-index: 10;
    pointer-events: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .tok-chart-label {
    font-size: 0.5625rem;
    color: var(--muted);
    margin-top: 0.25rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
    text-align: center;
  }

  /* ── Chart carousel ── */
  .chart-carousel {
    position: relative;
  }
  .chart-carousel-inner {
    overflow: hidden;
  }
  .chart-carousel-slides {
    display: flex;
    transition: transform 0.3s ease;
  }
  .chart-carousel-slide {
    min-width: 100%;
    flex-shrink: 0;
  }
  .chart-carousel-dots {
    display: flex;
    justify-content: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  .chart-carousel-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--border);
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background 0.2s;
  }
  .chart-carousel-dot.active { background: var(--primary); }
  .chart-carousel-dot:hover { background: var(--muted); }

  /* Phase 6 — Project multi-select filter (chart-scoped). Anchored
     top-right of the carousel card. Empty selection = aggregate all. */
  .chart-project-filter {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    z-index: 10;
  }
  .cpf-toggle {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.25rem 0.6rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--foreground);
    font-size: 0.72rem;
    font-family: var(--mono);
    cursor: pointer;
    transition: background 0.15s, border-color 0.15s;
    max-width: 220px;
  }
  .cpf-toggle:hover { border-color: var(--muted); }
  .cpf-toggle[aria-expanded="true"] {
    border-color: var(--primary);
    background: var(--primary-soft);
  }
  .cpf-toggle .cpf-chevron {
    color: var(--text-muted);
    font-size: 0.7rem;
    transition: transform 0.15s ease;
  }
  .cpf-toggle[aria-expanded="true"] .cpf-chevron { transform: rotate(180deg); }
  .cpf-panel {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow-lg);
    padding: 0.5rem;
    min-width: 240px;
    max-width: 360px;
    max-height: 320px;
    overflow-y: auto;
  }
  .cpf-actions {
    display: flex;
    gap: 0.5rem;
    padding-bottom: 0.4rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.4rem;
  }
  .cpf-link {
    background: transparent;
    border: none;
    color: var(--primary);
    font-size: 0.72rem;
    cursor: pointer;
    padding: 0.1rem 0.3rem;
  }
  .cpf-link:hover { text-decoration: underline; }
  .cpf-list { display: flex; flex-direction: column; gap: 0.15rem; }
  .cpf-item {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.2rem 0.3rem;
    cursor: pointer;
    font-size: 0.72rem;
    font-family: var(--mono);
    color: var(--foreground);
    border-radius: 4px;
  }
  .cpf-item:hover { background: var(--bg); }
  .cpf-item input[type="checkbox"] {
    margin: 0;
    accent-color: var(--primary);
    flex-shrink: 0;
  }
  .cpf-item-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .cpf-empty {
    padding: 0.5rem;
    color: var(--text-muted);
    font-style: italic;
    font-size: 0.75rem;
  }

  /* Phase 6 — Wasted-spend chart (cache-miss cost over time). */
  .tok-wasted-wrap {
    padding: 0.5rem 0;
  }
  .tok-wasted-bar-area {
    height: 140px;
    display: flex;
    align-items: flex-end;
    gap: 1px;
    padding: 0 0.25rem;
  }
  .tok-wasted-bar {
    flex: 1;
    min-width: 1px;
    background: var(--yellow);
    border-radius: 2px 2px 0 0;
    transition: opacity 0.15s;
    position: relative;
    cursor: default;
  }
  .tok-wasted-bar:hover { opacity: 0.75; }
  .tok-wasted-bar:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 4px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--foreground);
    color: var(--card);
    padding: 0.25rem 0.5rem;
    border-radius: var(--radius-sm);
    font-size: 0.7rem;
    white-space: nowrap;
    z-index: 30;
    pointer-events: none;
  }
  .tok-wasted-totals {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 0 0.5rem 0.5rem;
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .tok-wasted-totals .total-cost {
    color: var(--red);
    font-family: var(--mono);
    font-weight: 600;
  }

  /* ── Cost savings chart ── */
  .savings-chart-container {
    position: relative;
    height: 160px;
    margin-top: 0.5rem;
  }
  .savings-chart-svg {
    width: 100%;
    height: 100%;
  }
  .savings-chart-svg .grid-line {
    stroke: var(--border);
    stroke-width: 0.5;
  }
  .savings-chart-svg .axis-label {
    fill: var(--muted);
    font-size: 9px;
    font-family: inherit;
  }
  .savings-chart-svg .line-plan {
    stroke: var(--muted);
    stroke-width: 1.5;
    stroke-dasharray: 6 3;
    fill: none;
  }
  .savings-chart-svg .line-api {
    stroke: var(--primary);
    stroke-width: 2;
    fill: none;
  }
  .savings-chart-svg .area-savings {
    opacity: 0.10;
  }
  .savings-chart-legend {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }
  .savings-chart-legend-item {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.6875rem;
    color: var(--muted);
  }
  .savings-chart-legend-line {
    width: 16px;
    height: 2px;
    border-radius: 1px;
  }
  .savings-chart-legend-line.dashed {
    background: repeating-linear-gradient(90deg, var(--muted) 0 6px, transparent 6px 9px);
    height: 2px;
  }
  .savings-chart-legend-line.solid {
    background: var(--primary);
  }
  .savings-chart-total {
    font-size: 0.8125rem;
    color: var(--foreground);
    margin-top: 0.5rem;
    text-align: center;
  }
  .savings-chart-total .saved { color: var(--green); font-weight: 600; }
  .savings-chart-total .over { color: var(--red); font-weight: 600; }

  /* ── Phase C — date-range scrubber ── */
  .vs-bar {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    box-shadow: var(--shadow);
    padding: 0.625rem 0.875rem;
    margin-bottom: 0.875rem;
    position: sticky;
    top: 0;
    z-index: 5;
  }
  .vs-bar.hidden { display: none; }
  .vs-bar-row {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    flex-wrap: wrap;
  }
  .vs-bar-row + .vs-bar-row { margin-top: 0.5rem; }
  .vs-presets {
    display: flex;
    gap: 0.25rem;
    flex-wrap: wrap;
  }
  .vs-preset-btn {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--foreground);
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
    cursor: pointer;
    font-family: inherit;
  }
  .vs-preset-btn:hover { background: var(--bg); }
  .vs-preset-btn.active { background: var(--primary); color: #fff; border-color: var(--primary); }
  .vs-window-info {
    font-size: 0.75rem;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
    margin-left: auto;
  }
  .vs-window-info b { color: var(--foreground); font-weight: 600; }
  .vs-track-wrap {
    flex: 1;
    min-width: 200px;
    position: relative;
    height: 36px;
    user-select: none;
    touch-action: none;
  }
  .vs-track {
    position: absolute;
    top: 50%;
    left: 0;
    right: 0;
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    transform: translateY(-50%);
  }
  /* No coloured fill between the thumbs. The previous .vs-track-fill rule
     painted a translucent blue rectangle the full height of the wrapper,
     which dominated the row visually and hid surrounding labels. The plain
     .vs-track + two thumbs convey "selected range" clearly enough on their
     own; if a fill is ever wanted, restore it as a 4-6px-tall element ON
     the track (top: 50%; height: 6px; transform: translateY(-50%)), NOT
     full-height. The element is also no longer rendered in the markup. */
  .vs-thumb {
    position: absolute;
    top: 50%;
    width: 16px;
    height: 16px;
    margin-left: -8px;
    background: var(--primary);
    border: 2px solid var(--card);
    border-radius: 50%;
    transform: translateY(-50%);
    cursor: grab;
    box-shadow: var(--shadow);
    outline: none;
  }
  .vs-thumb:focus { box-shadow: 0 0 0 3px var(--blue-soft); }
  .vs-thumb:active { cursor: grabbing; }
  .vs-thumb-label {
    position: absolute;
    top: -22px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.6875rem;
    color: var(--muted);
    white-space: nowrap;
    pointer-events: none;
    font-variant-numeric: tabular-nums;
  }
  .vs-fallback-inputs {
    display: none;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .vs-fallback-input {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--foreground);
    font-size: 0.75rem;
    padding: 0.25rem 0.5rem;
    font-family: inherit;
  }
  @media (max-width: 600px) {
    .vs-track-wrap { display: none; }
    .vs-fallback-inputs { display: flex; }
  }
  /* Tier chips */
  .vs-tier-chips {
    display: flex;
    gap: 0.25rem;
    flex-wrap: wrap;
    align-items: center;
  }
  .vs-tier-chip {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--muted);
    font-size: 0.6875rem;
    padding: 0.1875rem 0.5rem;
    cursor: pointer;
    font-family: inherit;
    text-transform: capitalize;
  }
  .vs-tier-chip:hover { background: var(--bg); }
  .vs-tier-chip.active { background: var(--primary); color: #fff; border-color: var(--primary); }
  .vs-tier-label {
    font-size: 0.6875rem;
    color: var(--muted);
    margin-right: 0.25rem;
  }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-left">
      <h1>Van Damme-o-Matic</h1>
      <div class="header-sub"><span id="account-count">0</span> accounts connected<span id="current-strategy"></span><span id="probe-stats"></span></div>
    </div>
  </div>

  <div id="exhausted-banner" class="exhausted-banner" style="display:none">
    <span class="exhausted-icon">!</span>
    <span>All accounts rate-limited. Next available: <strong id="exhausted-reset"> -</strong></span>
  </div>

  <noscript>
    <div style="background:#fef3c7;border:1px solid #f59e0b;color:#78350f;padding:1rem;margin:1rem 0;border-radius:6px">
      <strong>JavaScript is required.</strong> The dashboard is a single-page app — every panel below this banner is empty without JS.
      Enable JavaScript for <code>localhost:${PORT}</code> in your browser, or use the CLI: <code>vdm status</code>, <code>vdm list</code>, <code>vdm tokens</code>.
    </div>
  </noscript>

  <div class="tabs" role="tablist" aria-label="vdm dashboard sections">
    <button class="tab active" role="tab" aria-selected="true" aria-controls="tab-accounts" id="tabbtn-accounts" onclick="switchTab('accounts')">Accounts</button>
    <button class="tab" role="tab" aria-selected="false" aria-controls="tab-activity" id="tabbtn-activity" onclick="switchTab('activity')">Activity</button>
    <button class="tab" role="tab" aria-selected="false" aria-controls="tab-usage" id="tabbtn-usage" onclick="switchTab('usage')">Usage</button>
    <button class="tab" role="tab" aria-selected="false" aria-controls="tab-sessions" id="tabbtn-sessions" onclick="switchTab('sessions')">Sessions<span id="sessions-badge" class="tab-badge" style="display:none"></span></button>
    <button class="tab" role="tab" aria-selected="false" aria-controls="tab-config" id="tabbtn-config" onclick="switchTab('config')">Config</button>
    <button class="tab" role="tab" aria-selected="false" aria-controls="tab-logs" id="tabbtn-logs" onclick="switchTab('logs')">Logs</button>
  </div>

  <div id="tab-accounts" class="tab-content active" role="tabpanel" aria-labelledby="tabbtn-accounts">
    <div id="accounts" class="accounts">
      <div class="empty-state">Loading...</div>
    </div>
  </div>

  <div id="tab-activity" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-activity">
    <div id="activity-wrap" class="activity-card">
      <div id="activity-log" style="color:var(--muted);padding:2rem 0">No activity yet</div>
    </div>
  </div>

  <div id="tab-usage" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-usage">
    <div id="stats-section" class="usage-card" style="display:none">
      <div class="usage-title">Usage  - All Accounts</div>
      <div id="stats-grid" class="stat-grid"></div>
      <div>
        <div class="chart-legend">
          <div class="chart-legend-item"><span class="chart-legend-dot" style="background:var(--primary)"></span> Messages</div>
          <div class="chart-legend-item"><span class="chart-legend-dot" style="background:var(--purple)"></span> Tokens</div>
        </div>
        <div id="chart" class="chart-container"></div>
      </div>
    </div>
    <!-- Date-range scrubber. Sits BELOW the All Accounts summary card so the
         summary stays always-visible and the scrubber narrows the charts that
         follow. The tier-filter row from the prior version was a duplicate of
         the per-account selector under the daily chart and has been removed
         (a single source of truth for "which accounts/tiers count toward this
         view" — it lives on the per-account dropdown below). -->
    <div id="vs-bar" class="vs-bar hidden" role="group" aria-label="Date range filter">
      <div class="vs-bar-row">
        <div class="vs-presets">
          <button class="vs-preset-btn" data-preset="1h">Last hour</button>
          <button class="vs-preset-btn" data-preset="24h">Last 24h</button>
          <button class="vs-preset-btn" data-preset="7d">Last 7d</button>
          <button class="vs-preset-btn" data-preset="30d">Last 30d</button>
          <button class="vs-preset-btn" data-preset="all">All</button>
        </div>
        <div class="vs-track-wrap" id="vs-track-wrap">
          <div class="vs-track"></div>
          <div class="vs-thumb" id="vs-thumb-start" tabindex="0" role="slider" aria-label="Range start" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0">
            <div class="vs-thumb-label" id="vs-label-start"></div>
          </div>
          <div class="vs-thumb" id="vs-thumb-end" tabindex="0" role="slider" aria-label="Range end" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100">
            <div class="vs-thumb-label" id="vs-label-end"></div>
          </div>
        </div>
        <div class="vs-fallback-inputs">
          <label style="font-size:0.6875rem;color:var(--muted)">From <input type="datetime-local" class="vs-fallback-input" id="vs-input-start"></label>
          <label style="font-size:0.6875rem;color:var(--muted)">To <input type="datetime-local" class="vs-fallback-input" id="vs-input-end"></label>
        </div>
        <div class="vs-window-info"><b id="vs-window-text">--</b></div>
      </div>
    </div>
    <div class="tok-filters">
      <select class="config-select" id="tok-repo" onchange="tokFilterChange('repo')"><option value="">All repos</option></select>
      <select class="config-select" id="tok-branch" onchange="tokFilterChange('branch')"><option value="">All branches</option></select>
      <select class="config-select" id="tok-model" onchange="tokFilterChange('model')"><option value="">All models</option></select>
      <select class="config-select" id="tok-account" onchange="tokFilterChange('account')"><option value="">All accounts</option></select>
      <select class="config-select" id="tok-time" onchange="tokFilterChange('time')">
        <option value="1">1 day</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
        <option value="90">90 days</option>
      </select>
      <button class="tok-export-btn" onclick="exportUsageCsv()">Export CSV</button>
      <button class="tok-export-btn" onclick="exportUsageTreeCsv()" title="Tree-aggregated CSV — one row per repo/branch/component/tool bucket, with USD cost">Export tree CSV</button>
    </div>
    <div id="tok-empty" class="empty-state" style="display:none">No token usage data yet.</div>
    <div id="tok-content" style="display:none">
      <div class="usage-card chart-carousel" style="margin-bottom:1rem">
        <div class="chart-project-filter" id="chart-project-filter">
          <button type="button" class="cpf-toggle" id="cpf-toggle" onclick="toggleProjectFilter()" aria-haspopup="listbox" aria-expanded="false">
            <span id="cpf-label">All projects</span>
            <span class="cpf-chevron">▾</span>
          </button>
          <div class="cpf-panel" id="cpf-panel" hidden>
            <div class="cpf-actions">
              <button type="button" class="cpf-link" onclick="projectFilterSelectAll(true)">Select all</button>
              <button type="button" class="cpf-link" onclick="projectFilterSelectAll(false)">Clear</button>
            </div>
            <div class="cpf-list" id="cpf-list"></div>
          </div>
        </div>
        <div class="chart-carousel-inner">
          <div class="chart-carousel-slides" id="chart-carousel-slides">
            <div class="chart-carousel-slide" id="tok-savings-chart"></div>
            <div class="chart-carousel-slide" id="tok-chart"></div>
            <div class="chart-carousel-slide" id="tok-wasted-chart"></div>
          </div>
        </div>
        <div class="chart-carousel-dots" id="chart-carousel-dots">
          <button class="chart-carousel-dot active" onclick="chartCarouselGo(0)"></button>
          <button class="chart-carousel-dot" onclick="chartCarouselGo(1)"></button>
          <button class="chart-carousel-dot" onclick="chartCarouselGo(2)"></button>
        </div>
      </div>
      <div id="tok-stats" class="stat-grid" style="margin-bottom:0.5rem"></div>
      <div id="tok-savings" class="tok-savings-banner"></div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Model Breakdown</div>
        <div id="tok-models"></div>
      </div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Account Breakdown</div>
        <div id="tok-accounts"></div>
      </div>
      <div class="usage-card">
        <div class="usage-title">Repository &amp; Branch</div>
        <div id="tok-repos"></div>
      </div>
      <div class="usage-card" id="tok-tools-card" style="margin-top:1rem">
        <div class="usage-title">Tool Breakdown</div>
        <div id="tok-tools"></div>
      </div>
      <!-- TRDD-1645134b Phase 3 — usage tree view -->
      <div class="usage-card" id="tok-tree-card" style="margin-top:1rem">
        <div class="usage-title" style="display:flex;align-items:center;gap:0.5rem">
          <span>Usage Tree</span>
          <span style="font-size:0.625rem;font-weight:500;color:var(--text-muted);background:var(--bg);border-radius:3px;padding:0.125rem 0.375rem">repo &rsaquo; worktree &rsaquo; component &rsaquo; tool</span>
        </div>
        <div id="tok-tree" class="tree-view"><div class="tree-loading">Loading…</div></div>
      </div>
      <div class="usage-card tree-misses-card" id="tok-misses-card" style="display:none">
        <div class="usage-title" style="display:flex;align-items:center;gap:0.5rem">
          <span>Likely Cache Misses</span>
          <span style="font-size:0.625rem;font-weight:500;color:var(--text-muted);background:var(--bg);border-radius:3px;padding:0.125rem 0.375rem" id="tok-misses-count">0</span>
        </div>
        <div id="tok-misses"></div>
      </div>
    </div>
  </div>

  <div id="tab-sessions" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-sessions">
    <div id="sessions-content">
      <div class="empty-state" id="sessions-disabled">Session Monitor is OFF. Enable it in Config (BETA).</div>
    </div>
  </div>

  <div id="tab-config" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-config">
    <div class="config-card">
      <div class="config-section">
        <div class="config-section-title">Proxy</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Enable proxy</div>
            <div class="config-desc">Route Claude Code API calls through the local proxy for account switching</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-proxy" checked onchange="toggleSetting('proxyEnabled', this.checked)">
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Auto-switch on rate limit</div>
            <div class="config-desc">Automatically switch to another account when the current one hits a 429 or 401</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-autoswitch" checked onchange="toggleSetting('autoSwitch', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Rotation Strategy</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Strategy</div>
            <div class="config-desc" id="strategy-hint"></div>
          </div>
          <select class="config-select" id="sel-strategy" onchange="changeStrategy(this.value)">
            <option value="sticky">Sticky</option>
            <option value="conserve">Conserve</option>
            <option value="round-robin">Round-robin</option>
            <option value="spread">Spread</option>
            <option value="drain-first">Drain first</option>
          </select>
        </div>
        <div class="config-row" id="interval-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Rotation interval</div>
            <div class="config-desc">How often to rotate to the least-used account</div>
          </div>
          <select class="config-select" id="sel-interval" onchange="changeInterval(Number(this.value))">
            <option value="15">15 min</option>
            <option value="30">30 min</option>
            <option value="60">1 hr</option>
            <option value="120">2 hr</option>
          </select>
        </div>
        <div id="strategy-list" class="strategy-list"></div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Notifications</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Desktop notifications</div>
            <div class="config-desc">Show macOS notifications on account switches, rate limits, and errors</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-notifs" checked onchange="toggleSetting('notifications', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Request Serialization <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Serialize requests</div>
            <div class="config-desc">Queue concurrent API requests to avoid 429 collisions from multiple sessions</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-serialize" onchange="toggleSetting('serializeRequests', this.checked)">
        </div>
        <div class="config-row" id="serialize-delay-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Delay between requests</div>
            <div class="config-desc">Milliseconds to wait between dispatching queued requests</div>
          </div>
          <select class="config-select" id="sel-serialize-delay" onchange="changeSerializeDelay(Number(this.value))">
            <option value="0">0 ms</option>
            <option value="100">100 ms</option>
            <option value="200">200 ms</option>
            <option value="500">500 ms</option>
            <option value="1000">1000 ms</option>
          </select>
        </div>
        <div class="config-row" id="serialize-cap-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Max concurrent in-flight</div>
            <div class="config-desc">Hard cap on simultaneous in-flight requests. 1 = strict serialization (recommended for &gt;8 CC clients on a single account). Bump only if you have multiple accounts and want pipelining.</div>
          </div>
          <select class="config-select" id="sel-serialize-cap" onchange="changeSerializeMaxConcurrent(Number(this.value))">
            <option value="1">1 (strict)</option>
            <option value="2">2</option>
            <option value="3">3</option>
            <option value="4">4</option>
            <option value="6">6</option>
            <option value="8">8</option>
            <option value="12">12</option>
            <option value="16">16</option>
          </select>
        </div>
        <div id="queue-stats" style="font-size:0.8125rem;color:var(--muted);margin-top:0.25rem;display:none"></div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Commit Tokens <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Token-Usage commit trailer</div>
            <div class="config-desc">Append a Token-Usage trailer to commit messages showing tokens consumed since the last commit</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-commit-tokens" onchange="toggleSetting('commitTokenUsage', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Session Monitor <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Enable session monitor <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
            <div class="config-desc">
              Track active Claude Code sessions with AI-summarized timelines.
              <strong style="color:var(--yellow)">Sends excerpts of your prompts to Anthropic Claude Haiku for summarization</strong>
              (billed against the active account). Summaries persist to <code>session-history.json</code>
              (mode 0o600). Off by default; enable only on machines where you accept the extra
              outbound traffic and the on-disk summary trail.
            </div>
          </div>
          <label class="sr-only" for="toggle-session-monitor">Enable session monitor (sends prompts to Claude Haiku)</label>
          <input type="checkbox" class="sw" id="toggle-session-monitor" onchange="toggleSetting('sessionMonitor', this.checked)">
        </div>
      </div>

      <!-- M19 fix — UI toggle for perToolAttribution. CLAUDE.md promised
           this knob alongside the CLI vdm config per-tool-attribution
           on/off; the dashboard toggle was never added. Wired to
           /api/settings POST with key perToolAttribution and a boolean
           value, mirroring the commit-tokens / session-monitor pattern.
           Server-side handler already exists at line 1873. -->
      <div class="config-section">
        <div class="config-section-title">Per-Tool Attribution <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Track tokens per tool call</div>
            <div class="config-desc">Attribute token usage to individual tool calls (Read, Edit, Bash, etc.) via the PostToolBatch hook. Off by default because it materially increases the size of token-usage.json.</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-per-tool" onchange="toggleSetting('perToolAttribution', this.checked)">
        </div>
      </div>
    </div>
  </div>

  <div id="tab-logs" class="tab-content" role="tabpanel" aria-labelledby="tabbtn-logs">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem">
      <div style="font-size:0.8125rem;color:var(--muted)" id="log-status">Disconnected</div>
      <button onclick="clearLogs()" style="background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:0.25rem 0.75rem;border-radius:6px;cursor:pointer;font-size:0.75rem">Clear</button>
    </div>
    <div id="log-container" style="background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:0.75rem;font-family:'SF Mono',Monaco,Consolas,monospace;font-size:0.75rem;line-height:1.5;height:calc(100vh - 220px);overflow-y:auto;color:#c9d1d9"></div>
  </div>

</div>

<div id="toast" class="toast"></div>

<script>
function switchTab(id) {
  // A11y: maintain aria-selected so screen readers announce the
  // current tab. Without this, every .tab is announced "button"
  // with no current-state indication, even though the visual is clear.
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
  });
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  const btn = document.getElementById('tabbtn-' + id);
  if (btn) {
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
  }
  if (id === 'usage') refreshTokens();
  if (id === 'sessions') refreshSessions();
  if (id === 'logs') connectLogStream();
  // Phase C: scrubber is meaningful only on tabs that show time-series.
  // Hide it elsewhere to reclaim vertical space and avoid implying a
  // filter that isn't actually applied to e.g. the accounts list.
  vsApplyVisibility(id);
  const url = new URL(location);
  url.searchParams.set('tab', id);
  history.replaceState(null, '', url);
  // Persist to localStorage too, so closing & reopening the tab (which
  // loses the URL query string) still restores the user's last view.
  // URL param wins on initial load (it is an explicit request); when the
  // URL has no ?tab= query, we fall back to this stored value.
  try { localStorage.setItem('vdm.activeTab', id); } catch (e) { /* private mode / quota */ }
}

// ─────────────────────────────────────────────────
// Phase C — date-range scrubber + tier filter
// ─────────────────────────────────────────────────
//
// State machine: viewer-state.json on disk → /api/viewer-state →
// _vsState in memory. Mutations go through vsSet() which (a) clamps
// against the current dataRange, (b) updates the visual track, (c)
// debounces a POST back to /api/viewer-state, and (d) re-renders the
// time-series-dependent views (activity, token charts).
//
// The scrubber is hidden until at least one data point exists OR a
// persisted state with a real window is found — empty-data installs
// don't get a useless track.

var _vsState = { start: null, end: null, tierFilter: ['all'] };
var _vsDataRange = null;        // { oldest, newest } from /api/viewer-state
var _vsKnownTiers = [];          // populated from /api/profiles
var _vsAccountTierMap = {};      // accountName → tier (for filtering activity entries)
var _vsDragging = null;          // 'start' | 'end' | null
var _vsPostTimer = null;         // debounce handle for POST
var _vsRenderTimer = null;       // debounce handle for chart re-render

function vsSnapshot() {
  // Return a defensive copy so consumers can't mutate _vsState through
  // it. Kept minimal — chart renderers only need the three fields.
  return {
    start: _vsState.start,
    end: _vsState.end,
    tierFilter: (_vsState.tierFilter || ['all']).slice(),
  };
}

function vsTierForAccount(name) {
  if (!name) return null;
  return _vsAccountTierMap[name] || null;
}

function vsTierMatchesEntry(entry, snap) {
  // Pass-through if the filter is the "all" sentinel.
  if (!snap || !Array.isArray(snap.tierFilter) || !snap.tierFilter.length) return true;
  if (snap.tierFilter.indexOf('all') >= 0) return true;
  var tier = vsTierForAccount(entry.account);
  // Unattributed entries stay visible — better than silently dropping
  // them and confusing the user about why their totals shrank.
  if (!tier) return true;
  return snap.tierFilter.indexOf(tier) >= 0;
}

function vsFormatStamp(ms) {
  // Compact filesystem-safe timestamp for export filenames.
  // Local time + GMT offset (matches the agent-reports-location rule).
  if (!ms) return '0';
  var d = new Date(ms);
  var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
  var off = -d.getTimezoneOffset();
  var sign = off >= 0 ? '+' : '-';
  var oh = pad(Math.floor(Math.abs(off) / 60));
  var om = pad(Math.abs(off) % 60);
  return d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) +
    '_' + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds()) +
    sign + oh + om;
}

function vsFormatLabel(ms) {
  if (!ms) return '--';
  var d = new Date(ms);
  var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

function vsFormatDuration(ms) {
  if (!ms || ms < 0) return '--';
  var sec = Math.floor(ms / 1000);
  var min = Math.floor(sec / 60);
  var hr  = Math.floor(min / 60);
  var day = Math.floor(hr / 24);
  if (day >= 14) return Math.floor(day / 7) + ' weeks';
  if (day >= 1) return day + 'd ' + (hr % 24) + 'h';
  if (hr  >= 1) return hr + 'h ' + (min % 60) + 'm';
  if (min >= 1) return min + 'm';
  return sec + 's';
}

function vsApplyVisibility(tabId) {
  var bar = document.getElementById('vs-bar');
  if (!bar) return;
  var hasData = _vsDataRange && _vsDataRange.oldest && _vsDataRange.newest && _vsDataRange.newest > _vsDataRange.oldest;
  // Tabs that benefit from the scrubber: usage (charts), activity (log).
  // The scrubber is hidden on accounts/sessions/config/logs because
  // those panes don't use the start/end window.
  var useful = (tabId === 'usage' || tabId === 'activity');
  // First-load case: tabId is whatever the URL says or 'accounts' default.
  // Default to checking the currently-active tab if no id was provided.
  if (!tabId) {
    var act = document.querySelector('.tab-content.active');
    useful = !!(act && (act.id === 'tab-usage' || act.id === 'tab-activity'));
  }
  if (useful && hasData) bar.classList.remove('hidden');
  else bar.classList.add('hidden');
}

function vsClampLocal(start, end) {
  // Mirror of clampViewerState's bound logic, JS side. Server-side
  // clampViewerState handles the persistence path; the live drag uses
  // the local mirror so we don't round-trip on every frame. Keep the
  // two in sync.
  if (!_vsDataRange) return { start: start, end: end };
  var oldest = _vsDataRange.oldest, newest = _vsDataRange.newest;
  if (start > end) { var tmp = start; start = end; end = tmp; }
  start = Math.max(oldest, Math.min(start, newest));
  end   = Math.max(oldest, Math.min(end, newest));
  // Min-window: 5 minutes (matches VIEWER_STATE_MIN_WINDOW_MS).
  var MIN = 5 * 60 * 1000;
  if (newest - oldest >= MIN && (end - start) < MIN) {
    if (_vsDragging === 'start') start = Math.max(oldest, end - MIN);
    else end = Math.min(newest, start + MIN);
  }
  return { start: start, end: end };
}

function vsRenderTrack() {
  var wrap = document.getElementById('vs-track-wrap');
  var ts   = document.getElementById('vs-thumb-start');
  var te   = document.getElementById('vs-thumb-end');
  var ls   = document.getElementById('vs-label-start');
  var le   = document.getElementById('vs-label-end');
  var win  = document.getElementById('vs-window-text');
  if (!wrap || !ts || !te) return;
  if (!_vsDataRange) return;
  var span = _vsDataRange.newest - _vsDataRange.oldest;
  if (span <= 0) {
    ts.style.left = '0%'; te.style.left = '100%';
    return;
  }
  var sPct = ((_vsState.start - _vsDataRange.oldest) / span) * 100;
  var ePct = ((_vsState.end   - _vsDataRange.oldest) / span) * 100;
  sPct = Math.max(0, Math.min(100, sPct));
  ePct = Math.max(0, Math.min(100, ePct));
  ts.style.left = sPct + '%';
  te.style.left = ePct + '%';
  ts.setAttribute('aria-valuenow', String(Math.round(sPct)));
  te.setAttribute('aria-valuenow', String(Math.round(ePct)));
  if (ls) ls.textContent = vsFormatLabel(_vsState.start);
  if (le) le.textContent = vsFormatLabel(_vsState.end);
  if (win) win.textContent = vsFormatDuration(_vsState.end - _vsState.start);
  // Fallback inputs for narrow viewports (kept in sync with the visual
  // track so the user isn't presented with stale values when they
  // resize the window).
  var fis = document.getElementById('vs-input-start');
  var fie = document.getElementById('vs-input-end');
  if (fis && document.activeElement !== fis) fis.value = vsToInputLocal(_vsState.start);
  if (fie && document.activeElement !== fie) fie.value = vsToInputLocal(_vsState.end);
}

function vsToInputLocal(ms) {
  // datetime-local expects YYYY-MM-DDTHH:MM (no seconds, no timezone).
  if (!ms) return '';
  var d = new Date(ms);
  var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

function vsSet(start, end, tierFilter, opts) {
  opts = opts || {};
  var clamped = vsClampLocal(start != null ? start : _vsState.start, end != null ? end : _vsState.end);
  _vsState.start = clamped.start;
  _vsState.end   = clamped.end;
  if (Array.isArray(tierFilter)) _vsState.tierFilter = tierFilter.slice();
  vsRenderTrack();
  vsRenderPresetActive();
  vsRenderTierChips();
  // Re-render time-series views with debouncing so a fast drag doesn't
  // burn a chart redraw on every mouse-move event.
  if (_vsRenderTimer) clearTimeout(_vsRenderTimer);
  _vsRenderTimer = setTimeout(vsReRenderViews, 100);
  // Persist (debounced — don't spam the endpoint on every drag tick).
  if (!opts.noPersist) {
    if (_vsPostTimer) clearTimeout(_vsPostTimer);
    _vsPostTimer = setTimeout(vsPostState, 250);
  }
}

function vsReRenderViews() {
  // Re-render activity (uses cached log) — refresh() will repopulate
  // soon enough but we want the user to see a snappy filter response.
  // The activity log is already cached in _lastActivityHash machinery
  // — passing the most recent log keeps the existing diff path alive.
  // Token charts update through applyTokenModelFilter().
  applyTokenModelFilter();
  // Force activity re-render: clear hash so next /api/activity poll
  // re-applies the filter, AND re-render immediately from the data we
  // just rendered last. We do not keep a copy of the log, so we rely
  // on the next refresh tick (5 s) for the activity feed; the token
  // tab updates immediately via applyTokenModelFilter.
  _lastActivityHash = '';
}

function vsPostState() {
  // Round to integers — server validates Number.isInteger.
  var body = {
    start: Math.round(_vsState.start),
    end: Math.round(_vsState.end),
    tierFilter: _vsState.tierFilter.slice(),
  };
  fetch('/api/viewer-state', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(function() { /* best-effort persistence — UI keeps working */ });
}

function vsRenderPresetActive() {
  var btns = document.querySelectorAll('.vs-preset-btn');
  if (!btns || !btns.length || !_vsDataRange) return;
  // Find which preset (if any) matches the current window within 1 s.
  var win = _vsState.end - _vsState.start;
  var spanMap = {
    '1h':  60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d':  7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
  };
  var match = null;
  // 'all' = full data range
  if (Math.abs((_vsDataRange.newest - _vsDataRange.oldest) - win) < 60_000 &&
      Math.abs(_vsDataRange.newest - _vsState.end) < 60_000) {
    match = 'all';
  } else {
    Object.keys(spanMap).forEach(function(k) {
      if (match) return;
      // Preset windows always end at "now" (live data). We tolerate a
      // 60 s skew so a preset stays "active" if the user clicked it
      // moments ago and the data range has since drifted.
      if (Math.abs(spanMap[k] - win) < 60_000) match = k;
    });
  }
  btns.forEach(function(b) {
    b.classList.toggle('active', b.getAttribute('data-preset') === match);
  });
}

function vsApplyPreset(preset) {
  if (!_vsDataRange) return;
  var now = Date.now();
  // Use the live "now" rather than _vsDataRange.newest so presets
  // capture the most recent activity even if computeDataRange ran
  // milliseconds ago. The server clamps; the client is forgiving.
  var newest = Math.min(now, _vsDataRange.newest);
  if (preset === 'all') {
    vsSet(_vsDataRange.oldest, newest);
    return;
  }
  var spans = { '1h': 3600_000, '24h': 86400_000, '7d': 7 * 86400_000, '30d': 30 * 86400_000 };
  var span = spans[preset];
  if (!span) return;
  var start = Math.max(_vsDataRange.oldest, newest - span);
  vsSet(start, newest);
}

function vsRenderTierChips() {
  var holder = document.getElementById('vs-tier-chips');
  if (!holder) return;
  var tiers = ['all'].concat(_vsKnownTiers.slice());
  // Dedupe ('all' may collide if some odd profile reports literal 'all')
  var seen = {};
  tiers = tiers.filter(function(t) { if (seen[t]) return false; seen[t] = 1; return true; });
  var current = _vsState.tierFilter || ['all'];
  holder.innerHTML = tiers.map(function(t) {
    var active = (current.indexOf('all') >= 0 && t === 'all') || (current.indexOf(t) >= 0 && t !== 'all');
    var label = t === 'all' ? 'All' : t.replace(/_/g, ' ');
    return '<button class="vs-tier-chip' + (active ? ' active' : '') + '" data-tier="' + t.replace(/"/g, '&quot;') + '">' + label + '</button>';
  }).join('');
  holder.querySelectorAll('.vs-tier-chip').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var tier = btn.getAttribute('data-tier');
      var cur = (_vsState.tierFilter || ['all']).slice();
      if (tier === 'all') {
        cur = ['all'];
      } else {
        // Strip the 'all' sentinel when picking a specific tier.
        cur = cur.filter(function(x) { return x !== 'all'; });
        var idx = cur.indexOf(tier);
        if (idx >= 0) cur.splice(idx, 1);
        else cur.push(tier);
        if (cur.length === 0) cur = ['all'];
      }
      vsSet(null, null, cur);
    });
  });
}

function vsHandleThumbDown(which, ev) {
  ev.preventDefault();
  _vsDragging = which;
  var thumb = document.getElementById('vs-thumb-' + which);
  if (thumb) thumb.focus();
  document.addEventListener('mousemove', vsHandleMove);
  document.addEventListener('mouseup', vsHandleUp);
  document.addEventListener('touchmove', vsHandleMove, { passive: false });
  document.addEventListener('touchend', vsHandleUp);
}

function vsHandleMove(ev) {
  if (!_vsDragging || !_vsDataRange) return;
  ev.preventDefault();
  var wrap = document.getElementById('vs-track-wrap');
  if (!wrap) return;
  var rect = wrap.getBoundingClientRect();
  var x = (ev.touches && ev.touches[0]) ? ev.touches[0].clientX : ev.clientX;
  var pct = (x - rect.left) / rect.width;
  pct = Math.max(0, Math.min(1, pct));
  var ms = _vsDataRange.oldest + pct * (_vsDataRange.newest - _vsDataRange.oldest);
  if (_vsDragging === 'start') vsSet(ms, null, null, { noPersist: true });
  else vsSet(null, ms, null, { noPersist: true });
}

function vsHandleUp() {
  if (!_vsDragging) return;
  _vsDragging = null;
  document.removeEventListener('mousemove', vsHandleMove);
  document.removeEventListener('mouseup', vsHandleUp);
  document.removeEventListener('touchmove', vsHandleMove);
  document.removeEventListener('touchend', vsHandleUp);
  // Persist on drag-end (debounced 250 ms in vsSet).
  if (_vsPostTimer) clearTimeout(_vsPostTimer);
  _vsPostTimer = setTimeout(vsPostState, 100);
}

function vsHandleKey(which, ev) {
  if (!_vsDataRange) return;
  var step = (_vsDataRange.newest - _vsDataRange.oldest) / 100;
  if (ev.shiftKey) step *= 5;
  var delta = 0;
  if (ev.key === 'ArrowLeft' || ev.key === 'ArrowDown') delta = -step;
  else if (ev.key === 'ArrowRight' || ev.key === 'ArrowUp') delta = step;
  else return;
  ev.preventDefault();
  if (which === 'start') vsSet(_vsState.start + delta, null);
  else vsSet(null, _vsState.end + delta);
}

function vsHandleFallbackInput(which, value) {
  // datetime-local returns YYYY-MM-DDTHH:MM in local time. new Date() with
  // that string is interpreted as local time by browsers (per the HTML
  // spec).
  if (!value) return;
  var d = new Date(value);
  if (isNaN(d.getTime())) return;
  var ms = d.getTime();
  if (which === 'start') vsSet(ms, null);
  else vsSet(null, ms);
}

async function vsBootstrap() {
  // Populate known tiers from the live profile list. We hit /api/profiles
  // directly so the chip set is correct on first paint, before the main
  // refresh() cycle has run. Endpoint shape: { profiles, stats, ... }.
  try {
    var resp = await fetch('/api/profiles');
    var payload = await resp.json();
    var profiles = (payload && Array.isArray(payload.profiles)) ? payload.profiles : [];
    var tierSet = {};
    var map = {};
    profiles.forEach(function(p) {
      var t = p && p.rateLimitTier;
      if (t && t !== 'unknown') tierSet[t] = 1;
      if (p && p.name && t) map[p.name] = t;
      if (p && p.label && t) map[p.label] = t;
    });
    _vsKnownTiers = Object.keys(tierSet).sort();
    _vsAccountTierMap = map;
  } catch {}
  // Restore persisted state.
  try {
    var rs = await fetch('/api/viewer-state');
    var st = await rs.json();
    _vsDataRange = st.dataRange || null;
    if (st.start != null && st.end != null) {
      // Clamp restored values into the live range without persisting back.
      var clamped = (function() {
        if (!_vsDataRange) return { start: st.start, end: st.end };
        var s = Math.max(_vsDataRange.oldest, Math.min(st.start, _vsDataRange.newest));
        var e = Math.max(_vsDataRange.oldest, Math.min(st.end,   _vsDataRange.newest));
        if (s > e) { var t = s; s = e; e = t; }
        return { start: s, end: e };
      })();
      _vsState.start = clamped.start;
      _vsState.end   = clamped.end;
      _vsState.tierFilter = Array.isArray(st.tierFilter) ? st.tierFilter : ['all'];
    }
  } catch {}
  vsRenderTrack();
  vsRenderTierChips();
  vsRenderPresetActive();
  vsApplyVisibility();
  // Wire interactions.
  var thumbS = document.getElementById('vs-thumb-start');
  var thumbE = document.getElementById('vs-thumb-end');
  if (thumbS) {
    thumbS.addEventListener('mousedown', function(e) { vsHandleThumbDown('start', e); });
    thumbS.addEventListener('touchstart', function(e) { vsHandleThumbDown('start', e); }, { passive: false });
    thumbS.addEventListener('keydown', function(e) { vsHandleKey('start', e); });
  }
  if (thumbE) {
    thumbE.addEventListener('mousedown', function(e) { vsHandleThumbDown('end', e); });
    thumbE.addEventListener('touchstart', function(e) { vsHandleThumbDown('end', e); }, { passive: false });
    thumbE.addEventListener('keydown', function(e) { vsHandleKey('end', e); });
  }
  document.querySelectorAll('.vs-preset-btn').forEach(function(btn) {
    btn.addEventListener('click', function() { vsApplyPreset(btn.getAttribute('data-preset')); });
  });
  var fis = document.getElementById('vs-input-start');
  var fie = document.getElementById('vs-input-end');
  if (fis) fis.addEventListener('change', function() { vsHandleFallbackInput('start', fis.value); });
  if (fie) fie.addEventListener('change', function() { vsHandleFallbackInput('end', fie.value); });
}

// Refresh dataRange + tier map periodically so the scrubber tracks new
// data points and live tier additions without requiring a page reload.
async function vsRefreshDataRange() {
  // Pause auto-refresh visual updates while the user is mid-drag. Without
  // this, the 10s poll would re-render the track on top of the user's
  // in-flight drag — the thumb under the cursor jumps to a "fresh" data
  // range and the user's pointer is no longer over the same time value.
  // We still skip the network refresh entirely (rather than fetch but
  // skip render) to avoid serialising the new dataRange into _vsDataRange
  // mid-drag, which would silently shift the meaning of the user's drag.
  if (_vsDragging) return;
  try {
    var rs = await fetch('/api/viewer-state');
    var st = await rs.json();
    if (st.dataRange) {
      var prev = _vsDataRange;
      _vsDataRange = st.dataRange;
      // If we had no data before and now do, reveal the bar.
      if (!prev) vsApplyVisibility();
      // Re-clamp the current selection: if data aged out, our window
      // may now sit outside bounds.
      var c = vsClampLocal(_vsState.start, _vsState.end);
      if (c.start !== _vsState.start || c.end !== _vsState.end) {
        // In-memory clamp only — don't push back to the server because
        // the user didn't ask for this change. Their persisted preference
        // stays untouched until they drag/preset/chip again.
        _vsState.start = c.start;
        _vsState.end   = c.end;
        vsRenderTrack();
        vsRenderPresetActive();
      } else if (prev && (prev.oldest !== _vsDataRange.oldest || prev.newest !== _vsDataRange.newest)) {
        // Bounds shifted — re-render the track positions with the new span.
        vsRenderTrack();
        vsRenderPresetActive();
      }
    }
  } catch {}
}

function formatNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function fillClass(pct) {
  if (pct >= 1) return 'fill-full';
  if (pct >= 0.8) return 'fill-high';
  if (pct >= 0.5) return 'fill-mid';
  return 'fill-ok';
}
function pctClass(pct) {
  if (pct >= 80) return 'pct-high';
  if (pct >= 50) return 'pct-mid';
  return 'pct-ok';
}

function formatTimeLeft(resetUnix) {
  if (!resetUnix) return 'rolling window';
  const diff = resetUnix - Math.floor(Date.now() / 1000);
  if (diff <= 0) return 'resetting...';
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (h > 24) return Math.floor(h/24) + 'd ' + (h%24) + 'h left';
  if (h > 0) return h + 'h ' + m + 'm left';
  return m + 'm left';
}

function tokenStatus(expiresAt) {
  if (!expiresAt) return { text: 'Unknown', cls: '' };
  const diff = expiresAt - Date.now();
  if (diff <= 0) return { text: 'Expired', cls: 'tok-bad' };
  const h = Math.floor(diff / 3600000);
  const d = Math.floor(h / 24);
  if (d > 7) return { text: 'Valid', cls: 'tok-ok' };
  if (d >= 1) return { text: 'Expires in ' + d + 'd', cls: 'tok-warn' };
  if (h >= 1) return { text: 'Expires in ' + h + 'h', cls: 'tok-warn' };
  return { text: 'Expires soon', cls: 'tok-bad' };
}

function planBadge(subscriptionType, rateLimitTier) {
  const sub = (subscriptionType || 'free').toLowerCase();
  const tier = (rateLimitTier || '').toLowerCase();
  let label, cls;
  if (sub === 'max' || tier.indexOf('max') !== -1) {
    cls = 'badge-max';
    const m = tier.match(/(\d+)x/);
    label = m ? 'MAX ' + m[1] + 'x' : 'MAX';
  } else if (sub === 'pro' || tier.indexOf('pro') !== -1) {
    cls = 'badge-pro';
    label = 'PRO';
  } else {
    cls = 'badge-free';
    label = 'FREE';
  }
  return '<span class="badge ' + cls + '">' + label + '</span>';
}

function showToast(msg, opts) {
  // UX-D7 fix: longer timeout for errors (8s vs 2.2s default), add a
  // close button so the user can read at their pace. Errors that
  // arrive while the user is looking away no longer vanish before
  // they can be read.
  const t = document.getElementById('toast');
  const isError = opts && opts.error;
  const ms = (opts && typeof opts.timeoutMs === 'number') ? opts.timeoutMs : (isError ? 8000 : 2200);
  // Replace any existing close button + content; toast can be re-fired.
  t.innerHTML = '';
  const span = document.createElement('span');
  span.textContent = msg;
  t.appendChild(span);
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '×';
  closeBtn.setAttribute('aria-label', 'Dismiss notification');
  closeBtn.style.cssText = 'background:none;border:none;color:inherit;font-size:1.25rem;line-height:1;margin-left:0.75rem;cursor:pointer;padding:0 0.25rem;opacity:0.7';
  closeBtn.onclick = () => {
    t.classList.remove('show');
    clearTimeout(t._tid);
  };
  t.appendChild(closeBtn);
  t.classList.add('show');
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), ms);
}

async function doSwitch(name, displayName, e) {
  if (e) e.stopPropagation();
  // UX-D6: only grey out the TARGET card (the one being switched TO),
  // not every card on the dashboard. The previous behaviour made every
  // card flicker at 50% opacity for the duration of the switch — visual
  // jank on every action. The target card alone signals "this one is
  // becoming active in a moment".
  const targetCard = document.querySelector('.card[data-account-name="' + CSS.escape(name) + '"]')
    || (typeof e !== 'undefined' && e && e.target && e.target.closest && e.target.closest('.card'));
  if (targetCard) targetCard.classList.add('switching');
  try {
    const resp = await fetch('/api/switch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) {
      const toastName = data.label || displayName || name;
      let msg = 'Switched to ' + toastName;
      if (data.strategyChanged) msg += ' (strategy set to Sticky)';
      showToast(msg);
      if (data.strategyChanged) {
        document.getElementById('sel-strategy').value = data.strategy;
        updateStrategyUI(data.strategy);
      }
      setTimeout(refresh, 300);
    }
    else showToast('Error: ' + data.error, { error: true });
  } catch(e) { showToast('Failed to switch — ' + (e && e.message ? e.message : 'network error'), { error: true }); }
  if (targetCard) targetCard.classList.remove('switching');
}

async function doRemove(name, e) {
  if (e) e.stopPropagation();
  if (!confirm('Remove account "' + name + '"? This removes the saved keychain entry (vdm-account-' + name + ') and its label. The active Claude Code-credentials entry is not touched.')) return;
  try {
    const resp = await fetch('/api/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) { showToast('Removed ' + name); setTimeout(refresh, 300); }
    else showToast('Error: ' + data.error);
  } catch(e) { showToast('Failed to remove'); }
}

async function doRefresh(name, e) {
  if (e) e.stopPropagation();
  try {
    const resp = await fetch('/api/refresh', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) { showToast('Refreshed ' + name); setTimeout(refresh, 300); }
    else showToast('Refresh failed: ' + data.error);
  } catch(e) { showToast('Failed to refresh'); }
}

// Per-account "Exclude from auto-switch" toggle handler. Posts to
// /api/account-prefs and triggers an immediate refresh so the card
// re-renders with the new state. We optimistically toast on success;
// on failure we surface the server error and let the next refresh()
// re-set the checkbox to the persisted value.
async function doToggleExcludeFromAuto(name, checked) {
  try {
    const resp = await fetch('/api/account-prefs', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name, key: 'excludeFromAuto', value: !!checked })
    });
    const data = await resp.json();
    if (data.ok) {
      showToast(checked ? 'Excluded ' + name + ' from auto-switch' : 'Included ' + name + ' in auto-switch');
      // Bust the per-card cache so renderAccounts picks up the new
      // class/badge on the next refresh tick instead of skipping the
      // diff (the hash won't change because the toggle's checked
      // attribute is part of the inner string — but force a re-render
      // for instant visual feedback).
      _renderedCardCache.clear();
      setTimeout(refresh, 100);
    } else {
      showToast('Failed: ' + (data.error || 'unknown'));
      setTimeout(refresh, 100);
    }
  } catch(e) {
    showToast('Failed to update preferences');
    setTimeout(refresh, 100);
  }
}

function renderProbeStats(ps) {
  const el = document.getElementById('probe-stats');
  if (!ps || !ps.probeCount7d) { el.textContent = ''; return; }
  const totalTok = ps.inputTokens + ps.outputTokens;
  el.innerHTML = ' · ' + formatNum(ps.probeCount7d) + ' probes (7d) · ~' + formatNum(totalTok) + ' tokens overhead';
}

/**
 * Render a time-axis sparkline with real clock-time labels.
 * X-axis is a simple sliding window: [now - windowMs, now].
 *
 * @param {Array} hist - history entries with { ts, u5h, u7d }
 * @param {string} key - 'u5h' or 'u7d'
 * @param {number} windowMs - fixed x-axis span in ms (24h or 7d)
 * @param {string} mode - 'hours' or 'days'  - controls label generation
 */
function renderSparkline(hist, key, windowMs, mode) {
  const W = 320, H = 44, padL = 1, padR = 1, padT = 1, padB = 12;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const now = Date.now();

  const windowEnd = now;
  const windowStart = windowEnd - windowMs;

  // Generate real-time labels
  let svg = '';
  if (mode === 'hours') {
    // Hourly grid: show labels every 6 hours, minor gridlines every 3 hours
    const stepMs = 3 * 3600000; // 3-hour gridline step
    const firstHour = new Date(windowStart);
    firstHour.setMinutes(0, 0, 0);
    firstHour.setHours(Math.ceil(firstHour.getHours() / 3) * 3);
    if (firstHour.getTime() < windowStart) firstHour.setTime(firstHour.getTime() + stepMs);
    for (let t = firstHour.getTime(); t <= windowEnd; t += stepMs) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const h = d.getHours();
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      // Only label every 6 hours to prevent overlap
      if (h % 6 === 0) {
        svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + h + ':00</text>';
      }
    }
  } else {
    // Daily grid: find the first midnight >= windowStart, then every day
    const firstDay = new Date(windowStart);
    firstDay.setHours(0, 0, 0, 0);
    if (firstDay.getTime() < windowStart) firstDay.setTime(firstDay.getTime() + 86400000);
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    for (let t = firstDay.getTime(); t <= windowEnd; t += 86400000) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const label = dayNames[d.getDay()];
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + label + '</text>';
    }
  }

  // Binary activity area: ON (utilization > 0) vs OFF, with shaded fill.
  // hist is monotonically non-decreasing in ts (it is appended to in
  // chronological order by createUtilizationHistory). For a 7-day
  // sparkline against a 30-day history that's ~80% wasted iterations
  // when using filter(). Binary-search to find the first index >=
  // windowStart, then linear scan until ts > windowEnd. O(log n + k)
  // instead of O(n) per render.
  if (hist && hist.length >= 1) {
    var pts;
    var first = hist[0];
    var last  = hist[hist.length - 1];
    if (last.ts < windowStart || first.ts > windowEnd) {
      pts = [];
    } else if (first.ts >= windowStart && last.ts <= windowEnd) {
      // Whole history fits inside the window — no slicing needed.
      pts = hist;
    } else {
      // Binary search: lowest index i with hist[i].ts >= windowStart.
      var lo = 0, hi = hist.length;
      while (lo < hi) {
        var mid = (lo + hi) >>> 1;
        if (hist[mid].ts < windowStart) lo = mid + 1;
        else hi = mid;
      }
      var startIdx = lo;
      // Linear scan from startIdx until we exceed windowEnd. Most
      // sparklines render at most a few hundred points so this loop
      // is cheap; doing a second binary search for the end index
      // would only matter for truly enormous histories.
      var endIdx = startIdx;
      while (endIdx < hist.length && hist[endIdx].ts <= windowEnd) endIdx++;
      pts = hist.slice(startIdx, endIdx);
    }
    // Insert synthetic OFF points when gap between consecutive points > 10 min
    // This prevents the step function from holding ON state across long idle periods
    var GAP_THRESHOLD = 10 * 60 * 1000; // 10 minutes
    var filled = [];
    for (var gi = 0; gi < pts.length; gi++) {
      filled.push(pts[gi]);
      if (gi < pts.length - 1 && (pts[gi + 1].ts - pts[gi].ts) > GAP_THRESHOLD) {
        filled.push({ ts: pts[gi].ts + GAP_THRESHOLD, u5h: 0, u7d: 0 });
      }
    }
    pts = filled;
    if (pts.length) {
      var yOn = padT, yOff = padT + chartH;
      var d = 'M' + (padL + ((pts[0].ts - windowStart) / windowMs) * chartW).toFixed(1) + ',' + yOff;
      for (var pi = 0; pi < pts.length; pi++) {
        var x = padL + ((pts[pi].ts - windowStart) / windowMs) * chartW;
        var on = (pts[pi][key] || 0) > 0;
        d += ' L' + x.toFixed(1) + ',' + (on ? yOn : yOff).toFixed(1);
        // Step to next point (hold value until next timestamp)
        if (pi < pts.length - 1) {
          var xNext = padL + ((pts[pi + 1].ts - windowStart) / windowMs) * chartW;
          d += ' L' + xNext.toFixed(1) + ',' + (on ? yOn : yOff).toFixed(1);
        }
      }
      // Close path back to baseline
      var xLast = padL + ((pts[pts.length - 1].ts - windowStart) / windowMs) * chartW;
      d += ' L' + xLast.toFixed(1) + ',' + yOff + ' Z';
      svg += '<path d="' + d + '" fill="var(--primary)" opacity="0.25" />';
      // Top edge line for clarity
      var edge = '';
      for (var ei = 0; ei < pts.length; ei++) {
        var ex = padL + ((pts[ei].ts - windowStart) / windowMs) * chartW;
        var eOn = (pts[ei][key] || 0) > 0;
        edge += (ei === 0 ? 'M' : ' L') + ex.toFixed(1) + ',' + (eOn ? yOn : yOff).toFixed(1);
        if (ei < pts.length - 1) {
          var exNext = padL + ((pts[ei + 1].ts - windowStart) / windowMs) * chartW;
          edge += ' L' + exNext.toFixed(1) + ',' + (eOn ? yOn : yOff).toFixed(1);
        }
      }
      svg += '<path d="' + edge + '" fill="none" stroke="var(--primary)" stroke-width="1" />';
    }
  }

  return '<svg class="sparkline-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '">' + svg + '</svg>';
}

function formatEta(minutes) {
  if (minutes < 5) return '<5m';
  // Round to nearest 10 minutes
  const rounded = Math.round(minutes / 10) * 10;
  if (rounded <= 0) return '<5m';
  const h = Math.floor(rounded / 60);
  const m = rounded % 60;
  return h + ':' + String(m).padStart(2, '0');
}

function renderVelocityInline(p) {
  // 5h ETA badge — existing behavior unchanged.
  let html = '';
  if (p.minutesToLimit != null) {
    const min = p.minutesToLimit;
    let cls = 'velocity-badge';
    let text;
    if (min <= 0) { cls += ' velocity-crit'; text = 'at limit'; }
    else if (min < 300) { cls += ' velocity-crit'; text = 'Est. ' + formatEta(min) + ' to limit'; }
    else { cls += ' velocity-ok'; text = '>5hr to limit'; }
    html += '<span class="card-token-sep">&middot;</span>' +
      '<span class="' + cls + '" title="Estimated time until 5h rate limit is reached, based on current usage velocity">' + text + '</span>';
  }
  // Phase 6 (Item 9): parallel 7d ETA badge using minutesToLimit7d (already
  // emitted by /api/profiles via weeklyHistory.predictMinutesToLimit).
  // Color thresholds: green > 24h (1440 min), yellow 4-24h (240-1440), red < 4h.
  // The 7d window is independent of the 5h window — drain-first / spread
  // strategies need both numbers visible to decide whether to keep the
  // current account or rotate.
  if (p.minutesToLimit7d != null) {
    const min7 = p.minutesToLimit7d;
    let cls7 = 'velocity-badge';
    let text7;
    if (min7 <= 0) { cls7 += ' velocity-crit'; text7 = '7d: at limit'; }
    else if (min7 < 240) { cls7 += ' velocity-crit'; text7 = '7d ETA: ' + formatEta(min7); }
    else if (min7 < 1440) { cls7 += ' velocity-warn'; text7 = '7d ETA: ' + formatEta(min7); }
    else { cls7 += ' velocity-ok'; text7 = '7d ETA: ' + formatEta(min7); }
    html += '<span class="card-token-sep">&middot;</span>' +
      '<span class="' + cls7 + '" title="Estimated time until 7-day rate limit is reached, based on weekly usage velocity">' + text7 + '</span>';
  }
  return html;
}

let _lastProfilesHash = '';
var _cachedProfiles = [];
let _lastActivityHash = '';
let _lastStatsHash = '';
let _firstRender = true;
const _sparkCache = {};

// Cheap "did the data change?" check used by refresh loops to skip
// re-rendering when the response is byte-identical to the previous one.
//
// The previous implementation called JSON.stringify(obj) which, for a
// 50k-row token-usage array, allocated a multi-MB string on every poll
// (every 5s) just to compare against a stored copy of itself. For arrays
// with primitive-keyed objects we can do far better: walk the array
// once, fold each row into a 32-bit FNV-1a accumulator over its key
// values, and produce a 16-byte hex digest. ~30× faster for the
// token-usage hot path; identical results modulo ordering for the
// "did anything change" question.
//
// For non-array inputs (profiles, stats, log) we still use JSON.stringify
// — the size is bounded (~50 entries) so the savings don't pay for the
// added complexity, and stringify produces a stable canonical form
// without us having to think about object-key ordering.
function quickHash(obj) {
  if (!Array.isArray(obj)) return JSON.stringify(obj);
  // Schema detection — quickHash is called on three different array
  // shapes in this file:
  //   (a) token-usage rows  — { ts, model, account, repo, branch,
  //                             inputTokens, outputTokens, ... }
  //   (b) profile rows      — { name, label, isActive, expiresAt,
  //                             rateLimits, utilizationHistory, ... }
  //   (c) activity log rows — { ts, type, account/from/to, ... }
  // The token-usage fold (below) is much cheaper than JSON.stringify
  // for a 50k-row array, but folds ZERO discriminating fields for
  // shape (b) — every profile array would hash to the same value and
  // renderAccounts would never re-fire. Detect shape from the first
  // entry: if it has any token-usage marker field, use the fast fold;
  // otherwise fall back to JSON.stringify which guarantees a unique
  // canonical form regardless of shape.
  if (obj.length === 0) return 'L0';
  var sample = obj[0];
  var isUsageShape = sample != null && typeof sample === 'object' && (
    'inputTokens' in sample ||
    'outputTokens' in sample ||
    'cacheReadInputTokens' in sample ||
    'cacheCreationInputTokens' in sample
  );
  if (!isUsageShape) {
    // Profiles / activity log / unknown shape — JSON.stringify is
    // bounded (small array sizes) and gives perfect change detection.
    return JSON.stringify(obj);
  }
  // FNV-1a 32-bit, dual accumulator for a 64-bit-ish digest. Used for
  // the token-usage hot path (5s polling on a potentially 50k-row
  // array) where JSON.stringify allocated multi-MB strings just to
  // compare against itself.
  var lo = 0x811c9dc5 | 0;
  var hi = 0xcbf29ce4 | 0;
  function fold(s) {
    if (s == null) return;
    s = String(s);
    for (var i = 0, n = s.length; i < n; i++) {
      var c = s.charCodeAt(i);
      lo ^= c;       lo = Math.imul(lo, 0x01000193);
      hi ^= c + 31;  hi = Math.imul(hi, 0x01000193);
    }
  }
  // length first — distinguishes [] from [0] before any folds.
  fold(obj.length + '|');
  for (var i = 0, n = obj.length; i < n; i++) {
    var e = obj[i];
    if (e == null || typeof e !== 'object') {
      fold(typeof e); fold('=');
      fold(e); fold('|');
      continue;
    }
    fold(e.ts || e.timestamp || 0); fold('|');
    fold(e.model || '');            fold('|');
    fold(e.account || '');          fold('|');
    fold(e.repo || '');             fold('|');
    fold(e.branch || '');           fold('|');
    fold(e.inputTokens || 0);       fold('|');
    fold(e.outputTokens || 0);      fold('|');
    fold(e.cacheReadInputTokens || 0); fold('|');
    fold(e.cacheCreationInputTokens || 0); fold('|');
    fold(e.tool || '');             fold('|');
    fold(e.type || '');             fold(';');
  }
  // 16-char hex digest — same shape as the sha256 fingerprints elsewhere
  // so consumers comparing two hashes don't have to special-case length.
  function _h(n) { return ('00000000' + (n >>> 0).toString(16)).slice(-8); }
  return _h(lo) + _h(hi);
}

async function refresh() {
  try {
    const resp = await fetch('/api/profiles');
    const { profiles, stats, probeStats, allExhausted, earliestReset, rotationStrategy, queueStats } = await resp.json();
    _cachedProfiles = profiles;
    // Phase C: keep the tier map / known-tier list in sync with live
    // profiles so a newly-discovered account shows its chip immediately
    // and a removed account's tier disappears from the chip strip.
    if (Array.isArray(profiles)) {
      var tierSet = {};
      var map = {};
      profiles.forEach(function(p) {
        var t = p && p.rateLimitTier;
        if (t && t !== 'unknown') tierSet[t] = 1;
        if (p && p.name && t) map[p.name] = t;
        if (p && p.label && t) map[p.label] = t;
      });
      var newTiers = Object.keys(tierSet).sort();
      // Avoid re-rendering chips when nothing changed.
      var changed = newTiers.length !== _vsKnownTiers.length ||
                    newTiers.some(function(t, i) { return t !== _vsKnownTiers[i]; });
      _vsKnownTiers = newTiers;
      _vsAccountTierMap = map;
      if (changed) {
        // Drop tiers from the active filter that no longer exist; if all
        // dropped, fall back to ['all'].
        var current = (_vsState.tierFilter || ['all']).filter(function(t) {
          return t === 'all' || tierSet[t];
        });
        if (current.length === 0) current = ['all'];
        _vsState.tierFilter = current;
        vsRenderTierChips();
      }
    }
    const ph = quickHash(profiles);
    if (ph !== _lastProfilesHash) {
      _lastProfilesHash = ph;
      renderAccounts(profiles, _firstRender);
    }
    document.getElementById('account-count').textContent = profiles.length;
    if (rotationStrategy) {
      const strategyNames = { sticky: 'Sticky', conserve: 'Conserve', 'round-robin': 'Round-robin', spread: 'Spread', 'drain-first': 'Drain first' };
      document.getElementById('current-strategy').textContent = ' \\u00b7 ' + (strategyNames[rotationStrategy] || rotationStrategy);
    }
    if (probeStats) renderProbeStats(probeStats);
    // Queue stats
    if (queueStats) {
      var qEl = document.getElementById('queue-stats');
      if (queueStats.inflight > 0 || queueStats.queued > 0) {
        qEl.style.display = '';
        var capPart = queueStats.maxConcurrent ? ' (cap=' + queueStats.maxConcurrent + ')' : '';
        qEl.textContent = 'Queue: ' + queueStats.inflight + ' inflight, ' + queueStats.queued + ' queued' + capPart;
      } else {
        qEl.style.display = 'none';
      }
    }
    // Exhausted banner
    const banner = document.getElementById('exhausted-banner');
    if (allExhausted) {
      banner.style.display = '';
      document.getElementById('exhausted-reset').textContent = earliestReset || 'unknown';
    } else {
      banner.style.display = 'none';
    }
    if (stats) {
      const sh = quickHash(stats);
      if (sh !== _lastStatsHash) {
        _lastStatsHash = sh;
        renderStats(stats);
      }
    }
  } catch(e) { console.error('Refresh:', e); }
  try {
    const resp = await fetch('/api/activity');
    const log = (await resp.json()).log || [];
    const ah = quickHash(log);
    if (ah !== _lastActivityHash) {
      _lastActivityHash = ah;
      renderActivity(log);
    }
  } catch {}
  _firstRender = false;
  refreshTokens();
  // Only fetch sessions when the tab is active or periodically for badge updates
  var sessTab = document.getElementById('tab-sessions');
  if (sessTab && sessTab.classList.contains('active')) {
    refreshSessions();
  } else {
    refreshSessionsBadgeOnly();
  }
}

// Per-card hash cache for incremental DOM updates. The outer
// _lastProfilesHash gate prevents calling renderAccounts when nothing
// changed; THIS map prevents re-writing innerHTML for the unchanged
// cards within a renderAccounts call when only one account's status
// actually changed (e.g. one card's 5h utilization ticked from 78% to
// 79% — the other 4 cards shouldn't get DOM-recreated). Hashing the
// rendered HTML is the simplest correct check: if the HTML string
// matches what we last wrote, the DOM doesn't need to change.
var _renderedCardCache = new Map(); // safeName -> hash

// Tiny string hash (djb2 variant) — sufficient to distinguish two
// rendered card HTMLs of the same length but different content. Not
// cryptographic; collision probability across 5-10 cards is negligible.
function _cardHash(s) {
  var h = 5381 | 0;
  for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return h.toString(36);
}

// Bash-safe-ish identifier for the DOM id attribute. The keychain
// service-name spec already restricts account names to
// [a-zA-Z0-9._@-], so they're already safe — we just escape for
// extra defense in depth (the dashboard is local-only but the
// principle of "never assume your data is HTML-safe" applies).
function _safeIdForName(name) {
  return String(name || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function renderAccounts(profiles, animate) {
  const el = document.getElementById('accounts');
  if (!profiles.length) {
    el.innerHTML = '<div class="empty-state">No accounts yet. Run <code>claude login</code> in your terminal — vdm auto-discovers each account on the next API call.</div>';
    _renderedCardCache.clear();
    return;
  }
  // Build per-card HTML and per-card hash. We also track the order
  // so we can detect the cheap "nothing visible changed" case (same
  // names, same hashes, same order) without rewriting innerHTML.
  var newHashes = new Map();
  var cardHtmls = profiles.map((p, i) => {
    const active = p.isActive;
    // displayName is user-controlled (label files written by auto-
    // discover from the Anthropic API's organization_name field, OR
    // set manually via the vdm-label command). Two derived forms:
    //   * displayName    HTML-escaped for rendering in innerHTML.
    //   * displayNameJs  raw value with single-quote-as-JS-string
    //     escaping ONLY, used inside onclick=doSwitch single-quoted args.
    // The two MUST stay separate: HTML-escaping the JS-string form
    // would inject the &amp;#39; entity into the toast message instead
    // of an apostrophe.
    const rawDisplayName = p.label || p.name;
    const displayName = escHtml(rawDisplayName);
    const displayNameJs = String(rawDisplayName).replace(/'/g, "\\\\'");
    const eName = p.name.replace(/'/g, "\\\\'");
    const tok = tokenStatus(p.expiresAt);

    let barsHtml = '';
    if (p.rateLimits) {
      const rl = p.rateLimits;
      const f = Math.round(rl.fiveH.utilization * 100);
      const s = Math.round(rl.sevenD.utilization * 100);

      // 5hr sparkline  - 24h sliding window
      const hist5h = p.utilizationHistory || [];
      const spark5h = '<div class="sparkline-wrap">' +
        renderSparkline(hist5h, 'u5h', 24*60*60*1000, 'hours') +
        '</div>';

      // Weekly sparkline  - 7d sliding window
      const hist7d = p.weeklyHistory || [];
      const spark7d = '<div class="sparkline-wrap">' +
        renderSparkline(hist7d, 'u7d', 7*24*60*60*1000, 'days') +
        '</div>';

      barsHtml = '<div class="rate-bars">' +
        '<div class="rate-group">' +
          '<div class="rate-head"><span class="rate-label">5h window</span><span class="rate-pct ' + pctClass(f) + '">' + f + '%</span></div>' +
          '<div class="rate-track"><div class="rate-fill ' + fillClass(rl.fiveH.utilization) + '" style="width:' + Math.min(f,100) + '%"></div></div>' +
          '<div class="rate-reset" data-reset="' + rl.fiveH.reset + '">' + formatTimeLeft(rl.fiveH.reset) + '</div>' +
          spark5h +
        '</div>' +
        '<div class="rate-group">' +
          '<div class="rate-head"><span class="rate-label">Weekly</span><span class="rate-pct ' + pctClass(s) + '">' + s + '%</span></div>' +
          '<div class="rate-track"><div class="rate-fill ' + fillClass(rl.sevenD.utilization) + '" style="width:' + Math.min(s,100) + '%"></div></div>' +
          '<div class="rate-reset" data-reset="' + rl.sevenD.reset + '">' + formatTimeLeft(rl.sevenD.reset) + '</div>' +
          spark7d +
        '</div>' +
      '</div>';
    } else if (p.dormant) {
      barsHtml = '<div style="font-size:0.8125rem;color:var(--cyan);margin-top:0.25rem;font-weight:500">Dormant  - window preserved</div>';
    } else {
      barsHtml = '<div style="font-size:0.8125rem;color:var(--muted);margin-top:0.25rem">Rate limits unavailable</div>';
    }

    const animStyle = animate ? ' style="animation-delay:' + (i*0.05) + 's"' : ' style="animation:none"';
    const isStale = !active && (p.expired || p.refreshFailed || (p.expiresAt && p.expiresAt < Date.now()));
    var staleMsg = '';
    if (isStale) {
      if (p.refreshFailed && !p.refreshFailed.retriable) {
        staleMsg = '<div class="stale-msg">Token expired. Click Refresh or run <code>claude login</code> to reactivate.</div>';
      } else {
        staleMsg = '<div class="stale-msg">Token expired. Auto-refresh will retry shortly.</div>';
      }
    }
    var cardClass = 'card' + (active ? ' active' : '') + (isStale ? ' stale' : '') +
      (p.excludeFromAuto ? ' excluded-from-auto' : '');
    // Per-account "Exclude from auto-switch" toggle. Visible on every
    // card (active OR inactive) because users may want to opt OUT the
    // currently-active account too — the flag prevents AUTO selection
    // but doesn't force a rotation now (the active account stays
    // active until manually switched or rate-limited).
    var excludedBadge = p.excludeFromAuto
      ? '<span class="badge" style="background:var(--muted);color:var(--bg);font-size:0.65rem">excluded</span>'
      : '';
    var prefsHtml =
      '<label class="acct-pref-toggle" style="display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;color:var(--muted);margin-top:0.5rem;cursor:pointer">' +
        '<input type="checkbox" onchange="doToggleExcludeFromAuto(\\''+eName+'\\',this.checked)"' +
          (p.excludeFromAuto ? ' checked' : '') + ' />' +
        'Exclude from auto-switch' +
      '</label>';
    var buttonsHtml = '';
    if (!active) {
      buttonsHtml = '<div style="margin-top:0.875rem;display:flex;justify-content:space-between;align-items:center">' +
        '<button class="remove-btn" onclick="doRemove(\\''+eName+'\\',event)">Remove</button>' +
        (isStale ? '<button class="refresh-btn" onclick="doRefresh(\\''+eName+'\\',event)">Refresh</button>' : '<button class="switch-btn" onclick="doSwitch(\\''+eName+'\\',\\''+displayNameJs+'\\''+',event)">Switch to this account</button>') +
      '</div>';
    }
    var safeId = 'acct-card-' + _safeIdForName(p.name);
    var inner =
      '<div class="card-top">' +
        '<div class="card-identity">' +
          '<div class="status-dot ' + (active ? 'active' : 'inactive') + '"></div>' +
          '<span class="card-name">' + displayName + '</span>' +
          (active ? renderVelocityInline(p) : '') +
        '</div>' +
        '<div class="card-badges">' +
          planBadge(p.subscriptionType, p.rateLimitTier) +
          (active ? '<span class="badge badge-active">Active</span>' : '') +
          excludedBadge +
        '</div>' +
      '</div>' +
      barsHtml +
      staleMsg +
      prefsHtml +
      buttonsHtml;
    var h = _cardHash(cardClass + '|' + animStyle + '|' + inner);
    newHashes.set(p.name, h);
    // data-account-name lets doSwitch (UX-D6) find this card without
    // depending on the click event's target — useful when the switch
    // is invoked programmatically (e.g. from a keyboard shortcut).
    // Account name is escHtml'd at the source (escName) so it's safe
    // as an HTML attribute value.
    var escNameAttr = escHtml(p.name);
    return '<div class="' + cardClass + '" id="' + safeId + '" data-card-hash="' + h + '" data-account-name="' + escNameAttr + '"' + animStyle + '>' +
      inner +
    '</div>';
  });
  // Decide between three render strategies:
  //   (a) full innerHTML when the set/order of accounts changed (add /
  //       remove / re-order — DOM tree shape changes);
  //   (b) per-card outerHTML replacement for cards whose hash changed
  //       (existing children's DOM identity preserved);
  //   (c) skip everything when every card's hash matches the prior
  //       render — no DOM mutation at all.
  var prevNames = Array.from(_renderedCardCache.keys());
  var sameOrder = prevNames.length === profiles.length &&
    profiles.every(function(p, i) { return prevNames[i] === p.name; });
  if (!sameOrder) {
    el.innerHTML = cardHtmls.join('');
  } else {
    var anyChanged = false;
    for (var pi = 0; pi < profiles.length; pi++) {
      var pname = profiles[pi].name;
      if (_renderedCardCache.get(pname) !== newHashes.get(pname)) {
        anyChanged = true;
        var cardEl = document.getElementById('acct-card-' + _safeIdForName(pname));
        if (cardEl) cardEl.outerHTML = cardHtmls[pi];
        else { // unexpected: fall back to full re-render
          el.innerHTML = cardHtmls.join('');
          break;
        }
      }
    }
    if (!anyChanged) { /* no DOM write needed — fastest path */ }
  }
  // L5 — wholesale replacement (NOT cache.set on each pname). The
  // newHashes map only contains keys for the CURRENT profiles, so any
  // account that was removed since the last render naturally drops out
  // of the cache here. If a future refactor switches this to per-key
  // updates (e.g. for-of over newHashes calling cache.set), removed
  // accounts would leak hash entries forever — the _renderedCardCache
  // wholesale-replacement regression test pins this invariant.
  _renderedCardCache = newHashes;
}

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

const evtColors = {
  'auto-switch': 'var(--cyan)', 'proactive-switch': 'var(--purple)',
  'manual-switch': 'var(--primary)', 'rate-limited': 'var(--yellow)',
  'auth-expired': 'var(--red)', 'all-exhausted': 'var(--red)',
  'account-discovered': 'var(--green)', 'account-renamed': 'var(--muted)',
  'settings-changed': 'var(--muted)',
  'upgrade': 'var(--green)',
  'refresh-failed': 'var(--red)', 'token-refreshed': 'var(--green)',
};

function evtMsg(e) {
  // Every interpolated field is potentially user-controlled:
  //   * e.account / e.from / e.to: account NAMES are restricted to
  //     [a-zA-Z0-9._@-] so they're already HTML-safe, BUT some events
  //     (account-discovered, account-renamed) carry e.label which is
  //     arbitrary user input from the vdm-label command or from auto-
  //     discover's organization_name extraction. e.error from refresh-
  //     failed is an upstream API string. e.type is set by the dashboard
  //     code itself so it is safe.
  // Escape every dynamic field as a uniform discipline. The dashboard
  // binds to localhost only, so the blast radius is the user's own
  // host, but defense in depth is cheap.
  var h = function(s) { return escHtml(s == null ? '?' : String(s)); };
  switch (e.type) {
    case 'auto-switch': return 'Auto-switched from <b>' + h(e.from||'?') + '</b> to <b>' + h(e.to||'?') + '</b>';
    case 'proactive-switch': return 'Proactive switch to <b>' + h(e.to||'?') + '</b>';
    case 'manual-switch': return 'Switched to <b>' + h(e.to||'?') + '</b>';
    case 'rate-limited': return '<b>' + h(e.account||'?') + '</b> rate limited' + (e.retryAfter ? ' (' + Math.round(e.retryAfter/60) + ' min)' : '');
    case 'auth-expired': return '<b>' + h(e.account||'?') + '</b> token expired';
    case 'all-exhausted': return 'All accounts exhausted';
    case 'account-discovered': return 'Discovered <b>' + h(e.label||e.name||'?') + '</b>';
    case 'account-renamed': return 'Renamed <b>' + h(e.name||'?') + '</b> to <b>' + h(e.label||'?') + '</b>';
    case 'settings-changed': return 'Settings updated';
    case 'upgrade': return 'Upgraded to <b>' + h(e.to||'?') + '</b>';
    case 'refresh-failed': return '<b>' + h(e.account||'?') + '</b> refresh failed: ' + h(e.error||'unknown');
    case 'token-refreshed': return '<b>' + h(e.account||'?') + '</b> token refreshed';
    // M14 fix — explicit cases for Phase D/E/G/H event types added after
    // the original taxonomy. Without these the default case shows e.msg
    // (already populated via logActivity string coercion), but a labeled
    // prefix makes the activity feed scannable. Every dynamic field
    // routes through h(...) so the existing source-grep XSS regression
    // (test/lib.test.mjs describe XSS regression evtMsg) keeps passing.
    case 'worktree_create': return '<b>Worktree</b> ' + h(e.msg || 'created');
    case 'worktree_remove': return '<b>Worktree</b> ' + h(e.msg || 'removed');
    case 'task_created': return '<b>Task</b> ' + h(e.msg || 'created');
    case 'task_completed': return '<b>Task</b> ' + h(e.msg || 'completed');
    case 'auth_success': return '<b>Auth</b> ' + h(e.msg || 'success');
    case 'config_change': return '<b>Config</b> ' + h(e.msg || 'changed');
    case 'account-removed': return 'Removed account <b>' + h(e.name || '?') + '</b>';
    case 'account-prefs-changed': return '<b>Prefs</b> ' + h(e.msg || 'updated');
    // Serialize-mode auto-safeguards (queue_timeout breaker, all-429 breaker,
    // queue-depth alert). Fields routed through h(...) keep the source-grep
    // XSS regression test passing.
    case 'serialize-auto-disabled': return '<b>Serialize auto-disabled</b>: ' + h(e.reason || '?') + (e.count ? ' (count=' + h(String(e.count)) + ')' : '') + (e.accountCount ? ' (' + h(String(e.accountCount)) + ' accounts)' : '');
    case 'serialize-auto-enabled': return '<b>Serialize auto-enabled</b>: ' + h(e.reason || '?') + (e.account ? ' (' + h(e.account) + ')' : '') + (e.revert_after_quiet_min ? ' — auto-revert after ' + h(String(e.revert_after_quiet_min)) + 'min quiet' : '');
    case 'serialize-auto-reverted': return '<b>Serialize auto-reverted</b>: ' + h(String(e.quiet_min || '?')) + 'min of no rate-limits';
    case 'serialize-progressive-drain-start': return '<b>Serialize disengaging</b> (' + h(e.reason || '?') + ') — progressive drain of ' + h(String(e.queued || '?')) + ' queued at ' + h(String(Math.round(1000 / (e.interval_ms || 250)))) + '/s';
    case 'serialize-progressive-drain-end': return '<b>Serialize drain ' + (e.cancelled ? 'cancelled' : 'complete') + '</b>: released ' + h(String(e.released || '0')) + '/' + h(String(e.initial_queued || '?')) + ' (' + h(e.reason || '?') + ')';
    case 'oauth-bypass-enabled': return '<b>OAuth bypass mode</b>: ' + h(e.reason || 'all accounts revoked') + ' — proxy now passes requests transparently. Run <code>claude login</code> to recover.';
    case 'oauth-bypass-disabled': return '<b>OAuth bypass exited</b>: ' + h(e.reason || 'recovery') + (e.duration_min ? ' (was in bypass for ' + h(String(e.duration_min)) + 'min)' : '');
    case 'account-organization-disabled': return '<b>Account terminated</b>: ' + h(e.account || '?') + ' — Anthropic returned <code>organization has been disabled</code>. Marked permanently revoked.';
    case 'account-post-refresh-expired': return '<b>Refresh token dead</b>: ' + h(e.account || '?') + ' — refresh failed and <code>expiresAt</code> is still in the past. Marked permanently revoked.';
    case 'queue-depth-alert': return '<b>Queue depth alert</b>: ' + h(String(e.queued || '?')) + ' queued (≥' + h(String(e.threshold || '?')) + ') for ' + h(String(e.sustainedSeconds || '?')) + 's';
    // C4 fallthrough — events whose detail came in as a string get a .msg
    // field via logActivity's coercion. Surface that to the user. If only
    // .type is present (no msg), keep the legacy behavior (h(e.type)).
    default: return h(e.msg || e.type);
  }
}

function evtTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  const time = d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  if (d.toDateString() === now.toDateString()) return time;
  const y = new Date(now); y.setDate(y.getDate()-1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday ' + time;
  return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + time;
}

function renderActivity(log) {
  const el = document.getElementById('activity-log');
  if (!log.length) { el.innerHTML = '<div style="color:var(--muted);padding:2rem 0">No activity yet</div>'; return; }
  // Phase C: filter by scrubber window + tier. The activity log entries
  // carry the source account in e.account (or e.from / e.to for switch
  // events); for tier filtering we resolve the tier through
  // vsTierForAccount which maps account-name to the live profile tier.
  const snap = vsSnapshot();
  let filtered = log;
  if (snap && snap.start != null && snap.end != null) {
    filtered = filtered.filter(e => {
      const ts = Number(e.ts || 0);
      if (!ts) return true;
      return ts >= snap.start && ts <= snap.end;
    });
  }
  if (snap && Array.isArray(snap.tierFilter) && snap.tierFilter.length && snap.tierFilter[0] !== 'all') {
    filtered = filtered.filter(e => {
      // Match if any of the related accounts matches the tier filter.
      const candidates = [e.account, e.from, e.to, e.name].filter(Boolean);
      if (candidates.length === 0) return true; // unattributed events stay visible
      return candidates.some(name => {
        const tier = vsTierForAccount(name);
        return tier && snap.tierFilter.indexOf(tier) >= 0;
      });
    });
  }
  if (!filtered.length) {
    el.innerHTML = '<div style="color:var(--muted);padding:2rem 0">No activity in selected window</div>';
    return;
  }
  el.innerHTML = filtered.map(e => {
    const c = evtColors[e.type] || 'var(--muted)';
    return '<div class="evt">' +
      '<span class="evt-time">' + evtTime(e.ts) + '</span>' +
      '<span class="evt-dot" style="background:' + c + '"></span>' +
      '<span class="evt-msg">' + evtMsg(e) + '</span>' +
    '</div>';
  }).join('');
}

function formatChartDate(iso) {
  const p = iso.split('-');
  return parseInt(p[2],10) + ' ' + MONTHS[parseInt(p[1],10)-1];
}

function renderStats(stats) {
  document.getElementById('stats-section').style.display = '';
  const grid = document.getElementById('stats-grid');
  const totalTokens = Object.values(stats.modelUsage||{}).reduce((s,m) => s + (m.inputTokens||0) + (m.outputTokens||0), 0);
  const totalCache = Object.values(stats.modelUsage||{}).reduce((s,m) => s + (m.cacheReadInputTokens||0), 0);
  grid.innerHTML = [
    { v: formatNum(stats.totalSessions||0), l: 'Sessions' },
    { v: formatNum(stats.totalMessages||0), l: 'Messages' },
    { v: formatNum(totalTokens), l: 'Tokens' },
    { v: formatNum(totalCache), l: 'Cache Reads' },
  ].map(s => '<div class="stat-item"><div class="stat-val">' + s.v + '</div><div class="stat-label">' + s.l + '</div></div>').join('');

  const tokenMap = {};
  (stats.dailyModelTokens||[]).forEach(d => {
    tokenMap[d.date] = Object.values(d.tokensByModel||{}).reduce((s,v)=>s+v,0);
  });
  const daily = (stats.dailyActivity||[]).slice(-14);
  if (daily.length) {
    const maxMsg = Math.max(...daily.map(d => d.messageCount||0), 1);
    const maxTok = Math.max(...daily.map(d => tokenMap[d.date]||0), 1);
    const H = 115;
    document.getElementById('chart').innerHTML = daily.map(d => {
      const msgs = d.messageCount||0;
      const toks = tokenMap[d.date]||0;
      const hM = Math.max(3, (msgs/maxMsg)*H);
      const hT = Math.max(3, (toks/maxTok)*H);
      const lbl = formatChartDate(d.date);
      return '<div class="chart-day"><div class="chart-bars">' +
        '<div class="chart-bar msg-bar" style="height:'+hM+'px" data-tooltip="'+lbl+': '+formatNum(msgs)+' msgs"></div>' +
        '<div class="chart-bar tok-bar" style="height:'+hT+'px" data-tooltip="'+lbl+': '+formatNum(toks)+' tokens"></div>' +
      '</div><div class="chart-label">'+lbl+'</div></div>';
    }).join('');
  }
}

function tickCountdowns() {
  document.querySelectorAll('[data-reset]').forEach(el => {
    el.textContent = formatTimeLeft(Number(el.dataset.reset));
  });
}

const STRATEGY_HINTS = {
  sticky: 'Stays on current account. Only switches when rate-limited (429/401).',
  conserve: 'Drains active accounts first (weekly limit primary). Untouched accounts stay dormant  - their windows never start.',
  'round-robin': 'Rotates to the least-used account on a timer. Good balance of safety and efficiency.',
  spread: 'Picks the least-used account on every request. Switches often  - may trigger Anthropic notices.',
  'drain-first': 'Uses the account with highest 5hr utilization first. Good for short sessions.',
};

async function loadSettingsUI() {
  try {
    const s = await (await fetch('/api/settings')).json();
    document.getElementById('toggle-proxy').checked = s.proxyEnabled;
    document.getElementById('toggle-autoswitch').checked = s.autoSwitch;
    document.getElementById('toggle-notifs').checked = s.notifications !== false;
    document.getElementById('sel-strategy').value = s.rotationStrategy || 'conserve';
    document.getElementById('sel-interval').value = s.rotationIntervalMin || 60;
    updateStrategyUI(s.rotationStrategy || 'conserve');
    // Serialization
    document.getElementById('toggle-serialize').checked = !!s.serializeRequests;
    document.getElementById('sel-serialize-delay').value = s.serializeDelayMs || 200;
    document.getElementById('serialize-delay-ctrl').style.display = s.serializeRequests ? '' : 'none';
    document.getElementById('sel-serialize-cap').value = s.serializeMaxConcurrent || 1;
    document.getElementById('serialize-cap-ctrl').style.display = s.serializeRequests ? '' : 'none';
    // Commit token usage
    document.getElementById('toggle-commit-tokens').checked = !!s.commitTokenUsage;
    // Session monitor
    document.getElementById('toggle-session-monitor').checked = !!s.sessionMonitor;
    // M19 fix — Per-tool attribution toggle. Mirrors the toggle-commit-tokens
    // pattern; the input id is read by document.getElementById('toggle-per-tool').
    document.getElementById('toggle-per-tool').checked = !!s.perToolAttribution;
  } catch {}
}

const STRATEGY_DETAILS = {
  sticky:        { name: 'Sticky',      desc: 'Stay on the current account until it hits a rate limit (429) or auth error (401). Never switches proactively  - minimal disruption.' },
  conserve:      { name: 'Conserve',    desc: 'Concentrate usage on accounts whose rate-limit windows are already active. Untouched accounts stay dormant so their 5hr and weekly windows never start  - maximizes total available capacity over time.' },
  'round-robin': { name: 'Round-robin', desc: 'Rotate to the least-used account on a fixed timer. Balances load evenly while limiting switch frequency.' },
  spread:        { name: 'Spread',      desc: 'Always pick the account with the lowest 5hr utilization on every request. Switches often  - best for short, bursty sessions.' },
  'drain-first': { name: 'Drain first', desc: 'Use the account with the highest 5hr utilization first, draining it before moving on. Good for finishing off nearly-exhausted windows.' },
};

function updateStrategyUI(strategy) {
  document.getElementById('interval-ctrl').style.display = strategy === 'round-robin' ? '' : 'none';
  document.getElementById('strategy-hint').textContent = STRATEGY_HINTS[strategy] || '';
  const list = document.getElementById('strategy-list');
  list.innerHTML = Object.entries(STRATEGY_DETAILS).map(([key, s]) =>
    '<div class="strategy-item' + (key === strategy ? ' active' : '') + '">' +
      '<span class="strategy-item-name">' + s.name + '</span>' +
      '<span class="strategy-item-desc">' + s.desc + '</span>' +
    '</div>'
  ).join('');
}

async function toggleSetting(key, value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: value })
    });
    const msgs = {
      proxyEnabled: value ? 'Proxy enabled' : 'Proxy disabled  - passthrough mode',
      autoSwitch: value ? 'Auto-switch enabled' : 'Auto-switch disabled',
      notifications: value ? 'Notifications enabled' : 'Notifications disabled',
      serializeRequests: value ? 'Request serialization enabled' : 'Request serialization disabled',
      commitTokenUsage: value ? 'Commit token trailer enabled' : 'Commit token trailer disabled',
      // M19 fix — toast for the new perToolAttribution toggle.
      perToolAttribution: value ? 'Per-tool attribution enabled' : 'Per-tool attribution disabled',
    };
    showToast(msgs[key] || (key + ' = ' + value));
    // Show/hide serialize delay control
    if (key === 'serializeRequests') {
      document.getElementById('serialize-delay-ctrl').style.display = value ? '' : 'none';
      document.getElementById('serialize-cap-ctrl').style.display = value ? '' : 'none';
    }
  } catch { showToast('Failed to update'); }
}

async function changeSerializeDelay(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serializeDelayMs: value })
    });
    showToast('Serialize delay: ' + value + ' ms');
  } catch { showToast('Failed to update'); }
}

async function changeSerializeMaxConcurrent(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serializeMaxConcurrent: value })
    });
    showToast('Max concurrent: ' + value);
  } catch { showToast('Failed to update'); }
}

async function changeStrategy(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rotationStrategy: value })
    });
    updateStrategyUI(value);
    showToast('Rotation: ' + (document.getElementById('sel-strategy').selectedOptions[0]?.text || value));
  } catch { showToast('Failed to update'); }
}

async function changeInterval(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rotationIntervalMin: value })
    });
    showToast('Rotation interval: ' + (value >= 60 ? (value/60) + ' hr' : value + ' min'));
  } catch { showToast('Failed to update'); }
}

// ── Tokens tab ──

var TOK_COLORS = ['var(--primary)', 'var(--purple)', 'var(--cyan)', 'var(--green)', 'var(--yellow)', 'var(--red)'];

// Phase G — pricing table updated to include current generations + cache
// token rates. Pre-Phase-G: claude-opus-4-7 was missing entirely, falling
// through to the Sonnet default — silent 5x undercount on every Opus 4.7
// turn (this very session). Cache rates follow Anthropic published 1.25x
// (creation) / 0.10x (read) ratios. Per-row override allowed if any model
// ever diverges. Verify against https://claude.com/pricing if rates change.
// (Backticks intentionally avoided in this comment block — TOK_PRICING is
// declared inside renderHTML() template literal.)
var TOK_PRICING = {
  // Opus generation — flat $15/$75 across 4-5 / 4-6 / 4-7
  'claude-opus-4-7':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  'claude-opus-4-6':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  'claude-opus-4-5':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  // Sonnet generation — flat $3/$15
  'claude-sonnet-4-7': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  'claude-sonnet-4-6': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  'claude-sonnet-4-5': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  // Haiku generation — $0.80/$4
  'claude-haiku-4-6':  { input: 0.80,  output: 4.00,  cacheRead: 0.08,  cacheCreation: 1.00 },
  'claude-haiku-4-5':  { input: 0.80,  output: 4.00,  cacheRead: 0.08,  cacheCreation: 1.00 },
};
// Conservative default (Sonnet rates) for unknown models. Unknown-model hits
// are logged via _warnedUnknownModels so the rate table can be kept current.
var TOK_PRICING_DEFAULT = { input: 3, output: 15, cacheRead: 0.30, cacheCreation: 3.75 };
var _warnedUnknownModels = new Set();
var TOK_PLANS = {
  'pro':    { label: 'Pro ($20/mo)', monthly: 20 },
  'max5x':  { label: 'MAX 5x ($100/mo)', monthly: 100 },
  'max20x': { label: 'MAX 20x ($200/mo)', monthly: 200 },
};
var _tokPrevPeriodData = [];
var _tokRepoCollapsed = {};

function estimateCost(model, inTok, outTok, cacheReadTok, cacheCreationTok) {
  var key = Object.keys(TOK_PRICING).find(function(k) { return model && model.indexOf(k) === 0; });
  var p = key ? TOK_PRICING[key] : TOK_PRICING_DEFAULT;
  // Phase G — log first occurrence of each unknown model so rates can be kept
  // current. Avoid spamming the activity log: one warning per model per session.
  if (!key && model && !_warnedUnknownModels.has(model)) {
    _warnedUnknownModels.add(model);
    if (typeof logActivity === 'function') {
      try { logActivity('unknown-model', 'Unknown model in cost estimate: ' + model + ' (using Sonnet default rates)'); }
      catch { /* logActivity may not be defined in browser context — ignore */ }
    }
  }
  // L10 — defensive default for price-table entries that haven't set
  // cacheRead / cacheCreation yet. NOT a backward-compat shim: every
  // current model in the price table sets both rates explicitly. The
  // fallback exists so a future model addition that forgets the cache
  // rates produces $0 cache cost (visibly wrong) rather than NaN
  // (silently propagated everywhere downstream). Numeric type-check
  // also rejects accidental string rates that would coerce to NaN.
  var cacheRead = (typeof p.cacheRead === 'number') ? p.cacheRead : 0;
  var cacheCreation = (typeof p.cacheCreation === 'number') ? p.cacheCreation : 0;
  var crTok = Number(cacheReadTok) || 0;
  var ccTok = Number(cacheCreationTok) || 0;
  return (inTok / 1e6) * p.input
       + (outTok / 1e6) * p.output
       + (crTok / 1e6) * cacheRead
       + (ccTok / 1e6) * cacheCreation;
}

function formatCost(dollars) {
  if (dollars === 0) return '$0.00';
  if (dollars < 0.01) return '&lt;$0.01';
  if (dollars < 100) return '$' + dollars.toFixed(2);
  return '$' + Math.round(dollars).toLocaleString();
}

function toggleRepoCollapse(repoKey) {
  _tokRepoCollapsed[repoKey] = !_tokRepoCollapsed[repoKey];
  renderRepoBranchBreakdown(_tokFilteredData || []);
}

// L3 — single canonical HTML-escape helper for the browser bundle.
// Both escapeHtml and escHtml used to live here; the duplicate was
// removed in favour of escHtml (shorter, more call sites) and the
// null-check uses s == null rather than the falsy-check so numeric 0
// and boolean false round-trip as their string form instead of becoming
// the empty string. Escapes all 5 characters so the helper is safe for
// both text-content AND attribute interpolation.
//
// CLAUDE.md backtick-in-comment trap: this comment is INSIDE
// renderHTML()'s template literal (line ~2446 to ~6500). Any backtick
// here ends the template early. Plain-text wording only.
function escHtml(s) {
  if (s == null) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function shortModel(m) {
  if (!m) return 'unknown';
  var s = m.replace(/^claude-/, '').replace(/-\\d{8}$/, '');
  var match = s.match(/^([a-z]+(?:-[a-z]+)*)-(\\d+(?:-\\d+)*)$/);
  if (match) return match[1] + ' ' + match[2].replace(/-/g, '.');
  return s;
}

function getModelColor(model, sortedModels) {
  var idx = sortedModels.indexOf(model);
  if (idx < 0) idx = 0;
  return TOK_COLORS[idx % TOK_COLORS.length];
}

var _lastTokensHash = '';
var _tokensRawData = [];
var _tok30dData = [];
var _tokFilteredData = [];
var _tokFetching = false;
var _tokNeedsRefresh = false;
// Phase 6 — wasted-spend series received unfiltered-by-repo from
// /api/token-usage-tree?includeMisses=1 and filtered client-side
// using _chartProjectFilter so toggling the filter doesn't refetch.
var _wastedSpendRaw = [];
// Phase 6 — chart-scoped project multi-select filter. Empty Set =
// "all projects" (aggregate, the default). Non-empty = include only
// rows whose repo field is in the set. localStorage-persisted so the
// user selection survives a tab reload.
var _chartProjectFilter = new Set();
try {
  var _persistedCpf = localStorage.getItem('vdm.chartProjectFilter');
  if (_persistedCpf) {
    var arr = JSON.parse(_persistedCpf);
    if (Array.isArray(arr)) for (var __cpfI = 0; __cpfI < arr.length; __cpfI++) _chartProjectFilter.add(String(arr[__cpfI]));
  }
} catch (e) { /* ignore — clean slate is fine */ }
function _persistChartProjectFilter() {
  try {
    localStorage.setItem('vdm.chartProjectFilter', JSON.stringify(Array.from(_chartProjectFilter)));
  } catch (e) { /* quota / disabled — non-fatal */ }
}
// Apply the multi-select filter to a row array. Empty filter = pass-through.
function applyChartProjectFilter(rows) {
  if (!_chartProjectFilter.size) return rows;
  var out = [];
  for (var i = 0, n = rows.length; i < n; i++) {
    if (_chartProjectFilter.has(rows[i].repo || '')) out.push(rows[i]);
  }
  return out;
}

function tokTimeRange() {
  var sel = document.getElementById('tok-time');
  return sel ? parseInt(sel.value, 10) || 7 : 7;
}

async function refreshTokens() {
  var tab = document.getElementById('tab-usage');
  if (!tab || !tab.classList.contains('active')) return;
  if (_tokFetching) { _tokNeedsRefresh = true; return; }
  _tokFetching = true;
  _tokNeedsRefresh = false;
  try {
    var days = tokTimeRange();
    var now = Date.now();
    var currentCutoff = now - days * 24 * 60 * 60 * 1000;
    var since = now - Math.max(2 * days, 30) * 24 * 60 * 60 * 1000;
    var url = '/api/token-usage?since=' + since;
    var repoSel = document.getElementById('tok-repo');
    var branchSel = document.getElementById('tok-branch');
    if (repoSel && repoSel.value) url += '&repo=' + encodeURIComponent(repoSel.value);
    if (branchSel && branchSel.value) url += '&branch=' + encodeURIComponent(branchSel.value);
    var resp = await fetch(url);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    if (!Array.isArray(data)) data = [];
    var hash = quickHash(data);
    if (hash === _lastTokensHash) return;
    _lastTokensHash = hash;
    var cutoff30d = now - 30 * 24 * 60 * 60 * 1000;
    _tok30dData = data.filter(function(e) { return (e.timestamp || e.ts || 0) >= cutoff30d; });
    _tokensRawData = data.filter(function(e) { return (e.timestamp || e.ts || 0) >= currentCutoff; });
    _tokPrevPeriodData = data.filter(function(e) { var t = e.timestamp || e.ts || 0; return t < currentCutoff; });
    applyTokenModelFilter();
    // TRDD-1645134b Phase 3 — kick off the tree-view fetch in parallel.
    // Independent endpoint, independent error path; failure doesn't break
    // the existing usage panes.
    refreshUsageTree(currentCutoff).catch(function(e) {
      console.warn('Usage tree refresh failed:', e);
    });
  } catch (e) {
    console.error('Token fetch:', e);
    // Show empty state on error if no cached data
    if (!_tokensRawData.length) {
      var content = document.getElementById('tok-content');
      var empty = document.getElementById('tok-empty');
      if (content) content.style.display = 'none';
      if (empty) empty.style.display = '';
    }
  } finally {
    _tokFetching = false;
    if (_tokNeedsRefresh) refreshTokens();
  }
}

// TRDD-1645134b Phase 3 — usage tree view rendering.
//
// Fetches the pre-aggregated tree from /api/token-usage-tree (which
// computes the 4-level breakdown server-side via aggregateUsageTree),
// then renders nested <details>/<summary> elements. Native HTML
// collapse/expand — no JS framework, no event listeners per node.
//
// Cache-miss data piggybacks on the same fetch via includeMisses=1
// so we don't double-load token-usage.json.
//
// XSS-safe: every dynamic field flows through escHtml().
var _lastTreeHash = '';
var _treeFetching = false;
async function refreshUsageTree(currentCutoff) {
  if (_treeFetching) return;
  _treeFetching = true;
  try {
    var url = '/api/token-usage-tree?includeMisses=1&from=' + currentCutoff;
    // Inherit the time-window from the main usage refresh (currentCutoff).
    // Repo/branch filters from the dropdowns already apply via the main
    // tab's filter logic; the tree shows the FULL view by design (the
    // user uses the tree to pick what to drill into).
    var resp = await fetch(url);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    if (!data || data.ok !== true) throw new Error(data && data.error || 'malformed response');

    // Hash the tree skeleton + miss count + miss-session count + wasted-
    // spend point count so we don't re-render when nothing visible
    // changed (saves DOM churn on every 5s poll).
    var hash = (data.totals.requests | 0)
             + ':' + (data.misses ? data.misses.length : 0)
             + ':' + (data.missSessions ? data.missSessions.length : 0)
             + ':' + (data.wastedSpend ? data.wastedSpend.length : 0)
             + ':' + (data.tree ? data.tree.length : 0);
    if (hash === _lastTreeHash) return;
    _lastTreeHash = hash;

    renderUsageTree(data.totals, data.tree || []);
    renderCacheMisses(data.misses || [], data.missSessions || []);
    // Phase 6 — store the wasted-spend series and re-render the chart.
    // Stored UNFILTERED-by-repo; the chart applies _chartProjectFilter
    // at render time so toggling the multi-select doesn't refetch.
    _wastedSpendRaw = data.wastedSpend || [];
    renderWastedSpendChart();
  } finally {
    _treeFetching = false;
  }
}

function renderUsageTree(grandTotals, tree) {
  var el = document.getElementById('tok-tree');
  if (!el) return;
  if (!tree.length) {
    el.innerHTML = '<div class="tree-empty">No usage data in this time range.</div>';
    return;
  }
  // Render top-level repos open by default (so users see the breakdown
  // immediately), deeper levels collapsed.
  var html = '';
  for (var i = 0; i < tree.length; i++) {
    html += renderTreeNode(tree[i], grandTotals, /*depth*/0);
  }
  el.innerHTML = html;
}

// Recursive renderer. Each node renders as either a <details> (if it
// has children) or a flat row (leaf). The depth parameter controls
// the open-by-default policy: depth 0 (repos) opens automatically,
// depth >= 1 stays collapsed until the user clicks.
function renderTreeNode(node, parentTotals, depth) {
  var totals = node.totals || { input: 0, output: 0, cacheRead: 0, cacheCreate: 0, requests: 0 };
  var totalIO = (totals.input || 0) + (totals.output || 0);
  var parentIO = parentTotals
    ? ((parentTotals.input || 0) + (parentTotals.output || 0))
    : totalIO;
  var pct = parentIO > 0 ? Math.round((totalIO / parentIO) * 100) : 100;
  var pctStr = parentTotals && parentIO > 0 && pct < 100 ? ' <span class="tree-pct">' + pct + '%</span>' : '';

  // Cache hit-rate — read / (read + create) when there's any cache
  // activity. No badge when a node has no cache history at all.
  var cacheBadge = '';
  var cacheTotal = (totals.cacheRead || 0) + (totals.cacheCreate || 0);
  if (cacheTotal > 0) {
    var hitRate = Math.round((totals.cacheRead / cacheTotal) * 100);
    var cls = hitRate >= 50 ? 'high' : 'low';
    cacheBadge = '<span class="tree-cache-badge ' + cls + '" title="Cache hit rate (read / (read + create))">cache ' + hitRate + '%</span>';
  }

  var kindClass = node.kind || 'tool';
  if (node.kind === 'branch' && node.isWorktree) kindClass = 'worktree';
  var kindLabel = (node.kind === 'branch' && node.isWorktree) ? 'wt' : (node.kind || 'tool').slice(0, 4);

  var totalsHtml = '<span class="tree-totals">'
    + formatNum(totalIO) + ' tok'
    + pctStr
    + '</span>';
  var nameHtml = '<span class="tree-name" title="' + escHtml(node.name) + '">' + escHtml(node.name) + '</span>';
  var kindHtml = '<span class="tree-kind-icon ' + kindClass + '">' + escHtml(kindLabel) + '</span>';

  if (!node.children || !node.children.length) {
    // Leaf — flat row, no <details>
    return '<div class="tree-leaf">' + kindHtml + nameHtml + cacheBadge + totalsHtml + '</div>';
  }
  // Branch — recursive <details>
  var openAttr = depth === 0 ? ' open' : '';
  var html = '<details' + openAttr + '><summary>'
    + kindHtml + nameHtml + cacheBadge + totalsHtml
    + '</summary><div class="tree-children">';
  for (var i = 0; i < node.children.length; i++) {
    html += renderTreeNode(node.children[i], totals, depth + 1);
  }
  html += '</div></details>';
  return html;
}

// Phase 5 — render cache-miss list grouped by session, with hit-rate
// header per session and per-row model + reason columns.
//
// Both the flat misses list (used for the global count and as fallback
// when missSessions is unavailable) and the missSessions per-session
// aggregate come from /api/token-usage-tree?includeMisses=1.
function renderCacheMisses(misses, missSessions) {
  var card = document.getElementById('tok-misses-card');
  var el = document.getElementById('tok-misses');
  var countEl = document.getElementById('tok-misses-count');
  if (!card || !el) return;
  if (!misses.length) {
    card.style.display = 'none';
    return;
  }
  card.style.display = '';
  if (countEl) countEl.textContent = String(misses.length);

  // Render per-session groups (preferred). Cap at 5 sessions for DOM
  // bounds; within each session, cap at 10 most-recent misses. The full
  // count is always shown in the header so the operator knows what's
  // being elided.
  var SESSION_CAP = 5;
  var ROWS_PER_SESSION_CAP = 10;
  var sessions = (missSessions && missSessions.length) ? missSessions : [];

  if (!sessions.length) {
    // Fallback to the flat list (shouldn't happen post-Phase-5 but
    // protects against an older endpoint version that doesn't emit
    // missSessions).
    var shown = misses.slice(-50).reverse();
    var fallbackHtml = '';
    for (var i = 0; i < shown.length; i++) {
      var m = shown[i];
      var ts = m.ts ? new Date(m.ts).toLocaleString() : '?';
      fallbackHtml += '<div class="miss-row">'
        + '<span class="miss-ts">' + escHtml(ts) + '</span>'
        + '<span class="miss-account">' + escHtml((m.repo || '?') + ' / ' + (m.branch || '?')) + '</span>'
        + '<span class="miss-tokens">' + formatNum(m.inputTokens || 0) + ' input</span>'
        + '</div>';
    }
    if (misses.length > 50) {
      fallbackHtml += '<div class="miss-row" style="color:var(--text-muted);font-style:italic">… and ' + (misses.length - 50) + ' more</div>';
    }
    el.innerHTML = fallbackHtml;
    return;
  }

  var sessionsToShow = sessions.slice(0, SESSION_CAP);
  var html = '';
  for (var s = 0; s < sessionsToShow.length; s++) {
    var sess = sessionsToShow[s];
    var hitRateText = sess.hitRate != null ? sess.hitRate.toFixed(1) + '%' : 'n/a';
    var hitClass = (sess.hitRate != null && sess.hitRate >= 50) ? 'high' : 'low';
    // Truncate the sessionId display: keep the first 12 chars (the UUID
    // prefix is enough to be recognisable but doesn't dominate the row).
    var sidShort = (sess.sessionId || '?').slice(0, 12);
    html += '<details class="miss-session"' + (s === 0 ? ' open' : '') + '>'
      + '<summary>'
      + '<span class="miss-sess-id" title="' + escHtml(sess.sessionId || '?') + '">' + escHtml(sidShort) + '</span>'
      + '<span class="miss-sess-loc">' + escHtml((sess.repo || '?') + ' / ' + (sess.branch || '?')) + '</span>'
      + '<span class="miss-rate-badge ' + hitClass + '">'
        + escHtml(hitRateText)
        + ' <span class="miss-rate-counts">(' + (sess.hits | 0) + ' hits, ' + (sess.misses | 0) + ' misses)</span>'
      + '</span>'
      + '</summary>';
    // Per-session miss details — most recent first
    var details = (sess.missDetails || []).slice(-ROWS_PER_SESSION_CAP).reverse();
    for (var d = 0; d < details.length; d++) {
      var m2 = details[d];
      var ts2 = m2.ts ? new Date(m2.ts).toLocaleString() : '?';
      var modelText = m2.model || '?';
      var reasonText = m2.reason || 'unknown';
      var reasonClass = 'reason-' + reasonText.replace(/[^a-z0-9]/gi, '-');
      html += '<div class="miss-row">'
        + '<span class="miss-ts">' + escHtml(ts2) + '</span>'
        + '<span class="miss-model">' + escHtml(modelText) + '</span>'
        + '<span class="miss-tokens">' + formatNum(m2.inputTokens || 0) + ' input</span>'
        + '<span class="miss-reason ' + reasonClass + '">' + escHtml(reasonText) + '</span>'
        + '</div>';
    }
    if ((sess.missDetails || []).length > ROWS_PER_SESSION_CAP) {
      html += '<div class="miss-row" style="color:var(--text-muted);font-style:italic">… and '
        + (sess.missDetails.length - ROWS_PER_SESSION_CAP) + ' older miss(es) in this session</div>';
    }
    html += '</details>';
  }
  if (sessions.length > SESSION_CAP) {
    html += '<div class="miss-row" style="color:var(--text-muted);font-style:italic">… and '
      + (sessions.length - SESSION_CAP) + ' more session(s) with cache misses</div>';
  }
  el.innerHTML = html;
}

function applyTokenModelFilter() {
  var modelSel = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  var modelFilter   = (modelSel   && modelSel.value)   || '';
  var accountFilter = (accountSel && accountSel.value) || '';
  // Phase C: apply the scrubber window + tier filter on top of the
  // existing select-based filters. Snapshot at filter time so a fast
  // drag does not mutate data mid-render. populateTokenFilters runs
  // against the unwindowed dataset so the dropdown options never
  // collapse just because the scrubber narrows the timeline.
  var snap = vsSnapshot();
  var hasWindow = !!(snap && snap.start != null && snap.end != null);
  var hasTier   = !!(snap && Array.isArray(snap.tierFilter) && snap.tierFilter.length && snap.tierFilter[0] !== 'all');
  // Single-pass filter — the previous version did up to 4 sequential
  // .filter() calls, each rebuilding the array. For 50k+ rows that
  // was 4× the closure-allocation pressure; this collapses to one
  // pass per dataset (data + prevData) with all four predicates fused.
  function pass(e) {
    if (modelFilter   && e.model   !== modelFilter)   return false;
    if (accountFilter && e.account !== accountFilter) return false;
    if (hasWindow) {
      var ts = Number(e.timestamp || e.ts || 0);
      // Keep entries with no ts so we don't silently drop them — same
      // semantics as the previous "if (!ts) return true" guard.
      if (ts && (ts < snap.start || ts > snap.end)) return false;
    }
    if (hasTier && !vsTierMatchesEntry(e, snap)) return false;
    return true;
  }
  var data = [];
  for (var i = 0, n = _tokensRawData.length; i < n; i++) {
    if (pass(_tokensRawData[i])) data.push(_tokensRawData[i]);
  }
  var prevData = [];
  for (var j = 0, m = _tokPrevPeriodData.length; j < m; j++) {
    if (pass(_tokPrevPeriodData[j])) prevData.push(_tokPrevPeriodData[j]);
  }
  _tokFilteredData = data;
  // Filters update synchronously — they affect the dropdowns the user
  // is actively interacting with, so any latency here is visible.
  populateTokenFilters(_tokensRawData);
  // Batch the seven chart/list renders into a single rAF callback so
  // the browser performs ONE layout/paint per frame instead of seven
  // back-to-back innerHTML reflows. requestAnimationFrame is also a
  // natural debounce — fast scrubber drags or rapid model-filter
  // changes coalesce into the next frame instead of redundantly
  // re-rendering the chart on every change. Cancel any pending frame
  // first so we don't render stale data/prevData after a faster
  // re-call has already overwritten them.
  if (_renderChartsRaf != null) {
    cancelAnimationFrame(_renderChartsRaf);
    _renderChartsRaf = null;
  }
  // Phase 6 — project multi-select filter applied AFTER the existing
  // single-select filters but BEFORE any chart renderer sees the data.
  // This way the new control composes with everything (model, account,
  // repo, branch, time, scrubber, tier) without touching renderer code.
  // _tokensRawData drives the project-options list (populated in
  // populateProjectFilterOptions), so the filter dropdown reflects the
  // FULL repo set even when the user has narrowed the selection.
  var dataForCharts     = applyChartProjectFilter(data);
  var prevDataForCharts = applyChartProjectFilter(prevData);
  _renderChartsRaf = requestAnimationFrame(function() {
    _renderChartsRaf = null;
    renderTokenStats(dataForCharts, prevDataForCharts);
    renderDailyChart(dataForCharts);
    renderCostSavingsChart();
    renderModelBreakdown(dataForCharts);
    renderAccountBreakdown(dataForCharts);
    renderRepoBranchBreakdown(dataForCharts);
    renderToolBreakdown(dataForCharts);
    renderWastedSpendChart();
  });
}
var _renderChartsRaf = null;

function populateTokenFilters(data) {
  var repoSel = document.getElementById('tok-repo');
  var branchSel = document.getElementById('tok-branch');
  var modelSel = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  if (!repoSel || !branchSel || !modelSel) return;
  var prevRepo = repoSel.value;
  var prevBranch = branchSel.value;
  var prevModel = modelSel.value;
  var prevAccount = accountSel ? accountSel.value : '';
  // First-load restore from localStorage. The dropdowns are populated
  // here for the FIRST time after data arrives, so the page-load restore
  // earlier had nothing to attach to (only the default "All ..." option
  // existed). When prev* are still empty AND we have a saved value, use
  // it; if data shows the saved value still exists in the new dataset
  // it gets selected below by the equality checks against the prev*
  // variables (prevRepo, prevBranch, prevModel, prevAccount).
  try {
    if (!prevRepo)    prevRepo    = localStorage.getItem('vdm.filter.tok-repo')    || '';
    if (!prevBranch)  prevBranch  = localStorage.getItem('vdm.filter.tok-branch')  || '';
    if (!prevModel)   prevModel   = localStorage.getItem('vdm.filter.tok-model')   || '';
    if (!prevAccount) prevAccount = localStorage.getItem('vdm.filter.tok-account') || '';
  } catch (e) { /* private mode / quota */ }
  var repoSet = {}, modelSet = {}, accountSet = {};
  for (var i = 0; i < data.length; i++) {
    if (data[i].repo) repoSet[data[i].repo] = 1;
    if (data[i].model) modelSet[data[i].model] = 1;
    if (data[i].account) accountSet[data[i].account] = 1;
  }
  var repos = Object.keys(repoSet).sort();
  repoSel.innerHTML = '<option value="">All repos</option>' +
    repos.map(function(r) {
      return '<option value="' + escHtml(r) + '"' + (r === prevRepo ? ' selected' : '') + '>' + escHtml(r.split('/').pop()) + '</option>';
    }).join('');
  var branchData = prevRepo ? data.filter(function(e) { return e.repo === prevRepo; }) : data;
  var filteredBranches = {};
  for (var j = 0; j < branchData.length; j++) {
    if (branchData[j].branch) filteredBranches[branchData[j].branch] = 1;
  }
  var branches = Object.keys(filteredBranches).sort();
  branchSel.innerHTML = '<option value="">All branches</option>' +
    branches.map(function(b) {
      return '<option value="' + escHtml(b) + '"' + (b === prevBranch ? ' selected' : '') + '>' + escHtml(b) + '</option>';
    }).join('');
  var models = Object.keys(modelSet).sort();
  modelSel.innerHTML = '<option value="">All models</option>' +
    models.map(function(m) {
      return '<option value="' + escHtml(m) + '"' + (m === prevModel ? ' selected' : '') + '>' + escHtml(shortModel(m)) + '</option>';
    }).join('');
  if (accountSel) {
    var accounts = Object.keys(accountSet).sort();
    accountSel.innerHTML = '<option value="">All accounts</option>' +
      accounts.map(function(a) {
        return '<option value="' + escHtml(a) + '"' + (a === prevAccount ? ' selected' : '') + '>' + escHtml(a) + '</option>';
      }).join('');
  }
}

function renderTokenStats(data, prevData) {
  var content = document.getElementById('tok-content');
  var empty = document.getElementById('tok-empty');
  if (!content || !empty) return;
  if (!data.length) {
    content.style.display = 'none';
    empty.style.display = '';
    return;
  }
  content.style.display = '';
  empty.style.display = 'none';
  var totalIn = 0, totalOut = 0, requests = 0, totalCost = 0;
  for (var i = 0; i < data.length; i++) {
    var inT = data[i].inputTokens || 0;
    var outT = data[i].outputTokens || 0;
    var crT = data[i].cacheReadInputTokens || 0;
    var ccT = data[i].cacheCreationInputTokens || 0;
    totalIn += inT;
    totalOut += outT;
    totalCost += estimateCost(data[i].model, inT, outT, crT, ccT);
    requests++;
  }
  var trendHtml = '';
  if (prevData && prevData.length) {
    var prevTotal = 0;
    for (var p = 0; p < prevData.length; p++) prevTotal += (prevData[p].inputTokens || 0) + (prevData[p].outputTokens || 0);
    if (prevTotal > 0) {
      var curTotal = totalIn + totalOut;
      var pctChange = Math.round(((curTotal - prevTotal) / prevTotal) * 100);
      if (pctChange !== 0) {
        var arrow = pctChange > 0 ? '\u2191' : '\u2193';
        var cls = pctChange > 0 ? 'up' : 'down';
        trendHtml = '<div class="tok-trend ' + cls + '">' + arrow + ' ' + Math.abs(pctChange) + '% vs prev period</div>';
      }
    }
  }
  var statsEl = document.getElementById('tok-stats');
  if (statsEl) statsEl.innerHTML = [
    { v: formatNum(totalIn + totalOut), l: 'Total Tokens', extra: trendHtml },
    { v: formatNum(totalIn), l: 'Input' },
    { v: formatNum(totalOut), l: 'Output' },
    { v: formatNum(requests), l: 'Requests' },
    { v: formatCost(totalCost), l: 'API Equiv.', sub: 'at API rates' },
  ].map(function(s) {
    var h = '<div class="stat-item"><div class="stat-val">' + s.v + '</div><div class="stat-label">' + s.l + '</div>';
    if (s.sub) h += '<div class="tok-stat-sub">' + s.sub + '</div>';
    if (s.extra) h += s.extra;
    return h + '</div>';
  }).join('');
  // Savings banner — daily rate comparison
  var savingsEl = document.getElementById('tok-savings');
  if (savingsEl) {
    var days = tokTimeRange();
    var planSel = document.getElementById('tok-plan');
    // Persist the user's plan choice across reloads. localStorage is the
    // right scope here — the choice is per-user-per-browser, not part of
    // server-side config (which is shared with vdm CLI). On first render
    // the dropdown does not exist yet, so read the saved value from storage;
    // after this render writes savingsEl.innerHTML, the freshly-built
    // tok-plan select picks up the saved value via the selected attribute
    // produced by the loop below. (No backticks in this comment — they
    // would terminate the renderHTML template literal early.)
    var planKey;
    if (planSel) {
      planKey = planSel.value;
    } else {
      try { planKey = localStorage.getItem('vdm.tokPlan') || 'max5x'; }
      catch (_) { planKey = 'max5x'; }
    }
    if (!TOK_PLANS[planKey]) planKey = 'max5x';
    try { localStorage.setItem('vdm.tokPlan', planKey); } catch (_) {}
    var plan = TOK_PLANS[planKey] || TOK_PLANS['max5x'];
    var planDaily = plan.monthly / 30;
    var apiDaily = days > 0 ? totalCost / days : 0;
    var savedDaily = apiDaily - planDaily;
    var opts = Object.keys(TOK_PLANS).map(function(k) {
      return '<option value="' + k + '"' + (k === planKey ? ' selected' : '') + '>' + TOK_PLANS[k].label + '</option>';
    }).join('');
    var msg;
    if (savedDaily > 0) {
      msg = 'saves you ~<span class="tok-savings-val">' + formatCost(savedDaily) + '/day</span> vs API rates (' + formatCost(planDaily) + '/day plan vs ' + formatCost(apiDaily) + '/day API)';
    } else {
      msg = 'costs ' + formatCost(planDaily) + '/day \u00b7 API equiv ' + formatCost(apiDaily) + '/day';
    }
    savingsEl.innerHTML = 'Your <select id="tok-plan" onchange="applyTokenModelFilter()">' + opts + '</select> ' + msg;
  }
}

function renderModelBreakdown(data) {
  var el = document.getElementById('tok-models');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var modelMap = {};
  for (var i = 0; i < data.length; i++) {
    var m = data[i].model || 'unknown';
    if (!modelMap[m]) modelMap[m] = { input: 0, output: 0, total: 0, cacheRead: 0, cacheCreation: 0 };
    modelMap[m].input += data[i].inputTokens || 0;
    modelMap[m].output += data[i].outputTokens || 0;
    modelMap[m].cacheRead += data[i].cacheReadInputTokens || 0;
    modelMap[m].cacheCreation += data[i].cacheCreationInputTokens || 0;
    modelMap[m].total += (data[i].inputTokens || 0) + (data[i].outputTokens || 0);
  }
  var sortedModels = Object.keys(modelMap).sort().filter(function(k) { return modelMap[k].total > 0; });
  if (!sortedModels.length) { el.innerHTML = ''; return; }
  var grandTotal = 0;
  for (var j = 0; j < sortedModels.length; j++) grandTotal += modelMap[sortedModels[j]].total;
  if (!grandTotal) grandTotal = 1;
  var propBar = '<div class="tok-proportion">';
  for (var k = 0; k < sortedModels.length; k++) {
    var pct = (modelMap[sortedModels[k]].total / grandTotal) * 100;
    propBar += '<div class="tok-proportion-seg" style="width:'+pct+'%;background:'+getModelColor(sortedModels[k], sortedModels)+'"></div>';
  }
  propBar += '</div>';
  var rows = '';
  for (var r = 0; r < sortedModels.length; r++) {
    var md = modelMap[sortedModels[r]];
    var pctR = Math.round((md.total / grandTotal) * 100);
    var mdCost = estimateCost(sortedModels[r], md.input, md.output, md.cacheRead, md.cacheCreation);
    rows += '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:'+getModelColor(sortedModels[r], sortedModels)+'"></div>' +
      '<div class="tok-model-name">'+escHtml(shortModel(sortedModels[r]))+'</div>' +
      '<div class="tok-model-detail">'+formatNum(md.input)+' in / '+formatNum(md.output)+' out</div>' +
      '<div class="tok-model-total">'+formatNum(md.total)+'</div>' +
      '<div class="tok-model-cost">'+formatCost(mdCost)+'</div>' +
      '<div class="tok-model-pct">'+pctR+'%</div>' +
    '</div>';
  }
  el.innerHTML = propBar + rows;
}

function renderDailyChart(data) {
  var el = document.getElementById('tok-chart');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var days = tokTimeRange();
  var now = Date.now();
  var buckets, labelFn, bucketCount;
  if (days === 1) {
    bucketCount = 24;
    labelFn = function(idx) { return idx + 'h'; };
  } else if (days <= 30) {
    bucketCount = days;
    labelFn = function(idx) {
      var d = new Date(now - (days - 1 - idx) * 86400000);
      return (d.getMonth()+1) + '/' + d.getDate();
    };
  } else {
    bucketCount = 13;
    labelFn = function(idx) {
      var d = new Date(now - (12 - idx) * 7 * 86400000);
      return (d.getMonth()+1) + '/' + d.getDate();
    };
  }
  // Collect all models
  var allModels = {};
  for (var i = 0; i < data.length; i++) allModels[data[i].model || 'unknown'] = 1;
  var sortedModels = Object.keys(allModels).sort();
  // Init buckets
  buckets = [];
  for (var b = 0; b < bucketCount; b++) {
    var obj = { total: 0 };
    for (var mi = 0; mi < sortedModels.length; mi++) obj[sortedModels[mi]] = 0;
    buckets.push(obj);
  }
  // Fill buckets
  var periodStart = days === 1
    ? now - 24 * 3600000
    : days <= 30
      ? now - days * 86400000
      : now - 13 * 7 * 86400000;
  for (var j = 0; j < data.length; j++) {
    var ts = data[j].timestamp || data[j].ts || 0;
    var tok = (data[j].inputTokens || 0) + (data[j].outputTokens || 0);
    var elapsed = ts - periodStart;
    if (elapsed < 0) continue;
    var idx;
    if (days === 1) {
      idx = Math.floor(elapsed / 3600000);
    } else if (days <= 30) {
      idx = Math.floor(elapsed / 86400000);
    } else {
      idx = Math.floor(elapsed / (7 * 86400000));
    }
    if (idx >= bucketCount) idx = bucketCount - 1;
    if (idx < 0) idx = 0;
    var model = data[j].model || 'unknown';
    buckets[idx][model] = (buckets[idx][model] || 0) + tok;
    buckets[idx].total += tok;
  }
  var maxTotal = Math.max.apply(null, buckets.map(function(b) { return b.total; })) || 1;
  // Build legend
  var legend = '<div class="chart-legend">';
  for (var li = 0; li < sortedModels.length; li++) {
    legend += '<div class="chart-legend-item"><span class="chart-legend-dot" style="background:' + getModelColor(sortedModels[li], sortedModels) + '"></span> ' + escHtml(shortModel(sortedModels[li])) + '</div>';
  }
  legend += '</div>';
  // Build bars
  var showLabel = bucketCount <= 31;
  var bars = '<div class="tok-chart-wrap">';
  for (var k = 0; k < bucketCount; k++) {
    var bucket = buckets[k];
    var stackH = Math.round((bucket.total / maxTotal) * 120);
    bars += '<div class="tok-chart-bar-group">';
    bars += '<div class="tok-chart-bar-area"><div class="tok-chart-stack" style="height:' + stackH + 'px">';
    for (var si = 0; si < sortedModels.length; si++) {
      var segVal = bucket[sortedModels[si]] || 0;
      if (segVal <= 0) continue;
      var segH = Math.max(1, Math.round((segVal / bucket.total) * stackH));
      bars += '<div class="tok-chart-seg" style="height:' + segH + 'px;background:' + getModelColor(sortedModels[si], sortedModels) + '" data-tooltip="' + escHtml(shortModel(sortedModels[si])) + ': ' + formatNum(segVal) + '"></div>';
    }
    bars += '</div></div>';
    if (showLabel) {
      bars += '<div class="tok-chart-label">' + labelFn(k) + '</div>';
    }
    bars += '</div>';
  }
  bars += '</div>';
  var chartTitle = days === 1 ? 'Hourly Usage' : days <= 30 ? 'Daily Usage' : 'Weekly Usage';
  el.innerHTML = '<div class="usage-title">' + chartTitle + '</div>' + legend + bars;
}

var _chartCarouselIdx = 0;
var _chartCarouselTimer = null;
function chartCarouselGo(idx) {
  _chartCarouselIdx = idx;
  var slides = document.getElementById('chart-carousel-slides');
  var dots = document.getElementById('chart-carousel-dots');
  if (slides) slides.style.transform = 'translateX(-' + (idx * 100) + '%)';
  if (dots) {
    var btns = dots.querySelectorAll('.chart-carousel-dot');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', i === idx);
    }
  }
  clearInterval(_chartCarouselTimer);
  _chartCarouselTimer = setInterval(chartCarouselNext, 10000);
}
function chartCarouselNext() {
  var dots = document.getElementById('chart-carousel-dots');
  var count = dots ? dots.querySelectorAll('.chart-carousel-dot').length : 2;
  chartCarouselGo((_chartCarouselIdx + 1) % count);
}
_chartCarouselTimer = setInterval(chartCarouselNext, 10000);

// ── Phase 6 — chart-scoped project multi-select dropdown ──

function toggleProjectFilter() {
  var btn = document.getElementById('cpf-toggle');
  var panel = document.getElementById('cpf-panel');
  if (!btn || !panel) return;
  var open = !panel.hidden;
  if (open) {
    panel.hidden = true;
    btn.setAttribute('aria-expanded', 'false');
    return;
  }
  populateProjectFilterOptions();
  panel.hidden = false;
  btn.setAttribute('aria-expanded', 'true');
  // Click-away-to-close: install a one-shot capture handler. Removed
  // when the panel closes so we don't leak listeners across opens.
  setTimeout(function() {
    document.addEventListener('click', _closeProjectFilterOnOutside, true);
  }, 0);
}
function _closeProjectFilterOnOutside(ev) {
  var root = document.getElementById('chart-project-filter');
  if (!root) {
    document.removeEventListener('click', _closeProjectFilterOnOutside, true);
    return;
  }
  if (root.contains(ev.target)) return;
  var panel = document.getElementById('cpf-panel');
  var btn = document.getElementById('cpf-toggle');
  if (panel) panel.hidden = true;
  if (btn) btn.setAttribute('aria-expanded', 'false');
  document.removeEventListener('click', _closeProjectFilterOnOutside, true);
}

function populateProjectFilterOptions() {
  // Source-of-truth = the union of repo strings across the unfiltered
  // raw dataset AND the unfiltered wasted-spend series, so the
  // dropdown reflects every project that could appear in any chart.
  var listEl = document.getElementById('cpf-list');
  if (!listEl) return;
  var seen = new Set();
  for (var i = 0, n = _tokensRawData.length; i < n; i++) {
    var r = _tokensRawData[i].repo;
    if (r) seen.add(r);
  }
  for (var j = 0, m = _wastedSpendRaw.length; j < m; j++) {
    var r2 = _wastedSpendRaw[j].repo;
    if (r2) seen.add(r2);
  }
  var sorted = Array.from(seen).sort();
  if (!sorted.length) {
    listEl.innerHTML = '<div class="cpf-empty">No projects in current data range.</div>';
    return;
  }
  // Drop selected entries that no longer exist in the dataset (data
  // window changed, project disappeared) so the saved selection
  // doesn't pin a stale filter forever.
  var changed = false;
  Array.from(_chartProjectFilter).forEach(function(repo) {
    if (!seen.has(repo)) { _chartProjectFilter.delete(repo); changed = true; }
  });
  if (changed) {
    _persistChartProjectFilter();
    _refreshProjectFilterLabel();
  }
  var html = '';
  for (var k = 0; k < sorted.length; k++) {
    var name = sorted[k];
    var checked = _chartProjectFilter.has(name) ? ' checked' : '';
    var safeName = escHtml(name);
    var safeAttr = name.replace(/"/g, '&quot;');
    html += '<label class="cpf-item">'
      + '<input type="checkbox" data-repo="' + safeAttr + '"' + checked
      + ' onchange="toggleProjectInFilter(this)">'
      + '<span class="cpf-item-label" title="' + safeAttr + '">' + safeName + '</span>'
      + '</label>';
  }
  listEl.innerHTML = html;
}

function toggleProjectInFilter(cb) {
  var name = cb.getAttribute('data-repo');
  if (!name) return;
  if (cb.checked) _chartProjectFilter.add(name);
  else _chartProjectFilter.delete(name);
  _persistChartProjectFilter();
  _refreshProjectFilterLabel();
  applyTokenModelFilter();   // re-runs all chart renderers
}

function projectFilterSelectAll(selectAll) {
  if (selectAll) {
    // "Select all" is semantically equivalent to "Clear" for this
    // filter (empty set = aggregate all). But the user may want to
    // see every box ticked as a visual cue, so explicitly add each.
    _chartProjectFilter.clear();
    var listEl = document.getElementById('cpf-list');
    if (listEl) {
      var boxes = listEl.querySelectorAll('input[type="checkbox"]');
      for (var i = 0; i < boxes.length; i++) {
        var n = boxes[i].getAttribute('data-repo');
        if (n) _chartProjectFilter.add(n);
        boxes[i].checked = true;
      }
    }
  } else {
    _chartProjectFilter.clear();
    var listEl2 = document.getElementById('cpf-list');
    if (listEl2) {
      var boxes2 = listEl2.querySelectorAll('input[type="checkbox"]');
      for (var j = 0; j < boxes2.length; j++) boxes2[j].checked = false;
    }
  }
  _persistChartProjectFilter();
  _refreshProjectFilterLabel();
  applyTokenModelFilter();
}

function _refreshProjectFilterLabel() {
  var labelEl = document.getElementById('cpf-label');
  if (!labelEl) return;
  var n = _chartProjectFilter.size;
  if (n === 0) labelEl.textContent = 'All projects';
  else if (n === 1) {
    // Show the single project's basename so the label fits the button
    var only = Array.from(_chartProjectFilter)[0];
    var base = only.split('/').filter(Boolean).pop() || only;
    labelEl.textContent = base;
  } else labelEl.textContent = n + ' projects';
}

// ── Phase 6 — wasted-spend chart (cache-miss cost over time) ──
//
// Bars are aggregated per day for readability. Y-axis is total
// inputTokens that were billed at full rate due to a cache miss.
// Hover shows the per-day breakdown.
function renderWastedSpendChart() {
  var el = document.getElementById('tok-wasted-chart');
  if (!el) return;
  // Apply the project multi-select filter
  var filtered = _wastedSpendRaw;
  if (_chartProjectFilter.size) {
    filtered = [];
    for (var i = 0, n = _wastedSpendRaw.length; i < n; i++) {
      if (_chartProjectFilter.has(_wastedSpendRaw[i].repo || '')) filtered.push(_wastedSpendRaw[i]);
    }
  }
  // Apply the same time range as the rest of the Tokens tab so the
  // wasted-spend bar area stays in sync with the other charts.
  var snap = vsSnapshot();
  if (snap.start != null || snap.end != null) {
    var fStart = snap.start, fEnd = snap.end;
    filtered = filtered.filter(function(p) {
      var ts = p.ts || 0;
      if (fStart != null && ts < fStart) return false;
      if (fEnd   != null && ts > fEnd)   return false;
      return true;
    });
  }
  if (!filtered.length) {
    el.innerHTML = '<div class="usage-title">Tokens Paid (Cache Misses)</div>'
      + '<div style="color:var(--muted);font-size:0.8125rem;padding:2rem 0;text-align:center">No cache-miss spend in this time range. Higher cache hit rates = fewer bars.</div>';
    return;
  }
  // Aggregate per local-time day
  var byDay = new Map();
  var totalTokens = 0;
  var totalCost   = 0;
  for (var p = 0; p < filtered.length; p++) {
    var pt = filtered[p];
    var d = new Date(pt.ts);
    var dayKey = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
    var bucket = byDay.get(dayKey);
    if (!bucket) { bucket = { day: dayKey, tokens: 0, cost: 0, count: 0 }; byDay.set(dayKey, bucket); }
    bucket.tokens += (pt.inputTokens || 0);
    bucket.cost   += (pt.costUSD     || 0);
    bucket.count  += 1;
    totalTokens += (pt.inputTokens || 0);
    totalCost   += (pt.costUSD     || 0);
  }
  var days = Array.from(byDay.values()).sort(function(a, b) { return a.day < b.day ? -1 : 1; });
  var maxTokens = 0;
  for (var di = 0; di < days.length; di++) if (days[di].tokens > maxTokens) maxTokens = days[di].tokens;
  // Build the bars
  var bars = '<div class="tok-wasted-bar-area">';
  for (var dj = 0; dj < days.length; dj++) {
    var dy = days[dj];
    var pct = maxTokens > 0 ? Math.max(2, Math.round((dy.tokens / maxTokens) * 100)) : 2;
    var tooltip = dy.day + ' • ' + formatNum(dy.tokens) + ' tok • $'
                  + (Math.round(dy.cost * 100) / 100).toFixed(2)
                  + ' • ' + dy.count + ' miss' + (dy.count === 1 ? '' : 'es');
    bars += '<div class="tok-wasted-bar" style="height:' + pct + '%" data-tooltip="' + escHtml(tooltip) + '"></div>';
  }
  bars += '</div>';
  var totalsLine = '<div class="tok-wasted-totals">'
    + '<span>' + formatNum(totalTokens) + ' tokens fully paid across ' + filtered.length
    + ' miss' + (filtered.length === 1 ? '' : 'es') + '</span>'
    + '<span class="total-cost">$' + (Math.round(totalCost * 100) / 100).toFixed(2)
    + ' wasted</span>'
    + '</div>';
  el.innerHTML = '<div class="usage-title" title="Input tokens billed at full rate because no prior cache could be re-used. Plotted per day.">Tokens Paid (Cache Misses)</div>'
    + '<div class="tok-wasted-wrap">' + totalsLine + bars + '</div>';
}

function getPlanMonthlyCost(subscriptionType, rateLimitTier) {
  var sub = (subscriptionType || '').toLowerCase();
  var tier = (rateLimitTier || '').toLowerCase();
  // Infer subscription type from tier string when subscriptionType is missing/unknown
  var isMax = sub === 'max' || tier.indexOf('max') !== -1;
  var isPro = sub === 'pro' || tier.indexOf('pro') !== -1;
  if (isMax) {
    var m = tier.match(/(\d+)x/);
    if (m) {
      var mult = parseInt(m[1], 10);
      if (mult >= 20) return 200;
      return 100;
    }
    return 100;
  }
  if (isPro) return 20;
  return 0;
}

function renderCostSavingsChart() {
  var el = document.getElementById('tok-savings-chart');
  if (!el) return;
  var data = _tok30dData;
  if (!data.length) { el.innerHTML = '<div class="usage-title">Cost Savings</div><div style="color:var(--muted);font-size:0.8125rem;padding:2rem 0;text-align:center">No usage data for savings chart</div>'; return; }

  // Compute total monthly plan cost from profiles
  var totalMonthlyPlan = 0;
  for (var pi = 0; pi < _cachedProfiles.length; pi++) {
    totalMonthlyPlan += getPlanMonthlyCost(_cachedProfiles[pi].subscriptionType, _cachedProfiles[pi].rateLimitTier);
  }
  if (totalMonthlyPlan === 0) totalMonthlyPlan = 100; // fallback

  var dailyPlanCost = totalMonthlyPlan / 30;

  // Build 30-day buckets of API cost
  var now = Date.now();
  var dayMs = 86400000;
  var bucketCount = 30;
  var periodStart = now - bucketCount * dayMs;
  var dailyCosts = [];
  for (var b = 0; b < bucketCount; b++) dailyCosts.push(0);

  for (var i = 0; i < data.length; i++) {
    var ts = data[i].timestamp || data[i].ts || 0;
    var elapsed = ts - periodStart;
    if (elapsed < 0) continue;
    var idx = Math.floor(elapsed / dayMs);
    if (idx >= bucketCount) idx = bucketCount - 1;
    if (idx < 0) idx = 0;
    dailyCosts[idx] += estimateCost(data[i].model, data[i].inputTokens || 0, data[i].outputTokens || 0, data[i].cacheReadInputTokens || 0, data[i].cacheCreationInputTokens || 0);
  }

  // Accumulate
  var cumPlan = [];
  var cumApi = [];
  var runPlan = 0, runApi = 0;
  for (var d = 0; d < bucketCount; d++) {
    runPlan += dailyPlanCost;
    runApi += dailyCosts[d];
    cumPlan.push(runPlan);
    cumApi.push(runApi);
  }

  var maxVal = Math.max(cumPlan[bucketCount - 1], cumApi[bucketCount - 1], 1);
  var totalSaved = cumApi[bucketCount - 1] - cumPlan[bucketCount - 1];

  // SVG dimensions
  var svgW = 500, svgH = 140;
  var padL = 45, padR = 10, padT = 10, padB = 25;
  var chartW = svgW - padL - padR;
  var chartH = svgH - padT - padB;

  function xPos(idx) { return padL + (idx / (bucketCount - 1)) * chartW; }
  function yPos(val) { return padT + chartH - (val / maxVal) * chartH; }

  // Grid lines
  var gridLines = '';
  var gridCount = 4;
  for (var g = 0; g <= gridCount; g++) {
    var gVal = (maxVal / gridCount) * g;
    var gy = yPos(gVal);
    gridLines += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (svgW - padR) + '" y2="' + gy + '" class="grid-line"/>';
    gridLines += '<text x="' + (padL - 4) + '" y="' + (gy + 3) + '" class="axis-label" text-anchor="end">$' + Math.round(gVal) + '</text>';
  }

  // X-axis labels (every 5 days)
  var xLabels = '';
  for (var xl = 0; xl < bucketCount; xl += 5) {
    var labelDate = new Date(periodStart + (xl + 0.5) * dayMs);
    xLabels += '<text x="' + xPos(xl) + '" y="' + (svgH - 2) + '" class="axis-label" text-anchor="middle">' + (labelDate.getMonth() + 1) + '/' + labelDate.getDate() + '</text>';
  }
  // Last day label
  var lastDate = new Date(now - 0.5 * dayMs);
  xLabels += '<text x="' + xPos(bucketCount - 1) + '" y="' + (svgH - 2) + '" class="axis-label" text-anchor="middle">' + (lastDate.getMonth() + 1) + '/' + lastDate.getDate() + '</text>';

  // Build path strings
  var planPath = '', apiPath = '';
  for (var p = 0; p < bucketCount; p++) {
    var cmd = p === 0 ? 'M' : 'L';
    planPath += cmd + xPos(p).toFixed(1) + ',' + yPos(cumPlan[p]).toFixed(1);
    apiPath += cmd + xPos(p).toFixed(1) + ',' + yPos(cumApi[p]).toFixed(1);
  }

  // Area between the two lines (for savings visualization)
  var areaPath = '';
  for (var a = 0; a < bucketCount; a++) {
    areaPath += (a === 0 ? 'M' : 'L') + xPos(a).toFixed(1) + ',' + yPos(cumApi[a]).toFixed(1);
  }
  for (var a2 = bucketCount - 1; a2 >= 0; a2--) {
    areaPath += 'L' + xPos(a2).toFixed(1) + ',' + yPos(cumPlan[a2]).toFixed(1);
  }
  areaPath += 'Z';

  var areaColor = totalSaved > 0 ? 'var(--green)' : 'var(--red)';

  var svg = '<svg class="savings-chart-svg" viewBox="0 0 ' + svgW + ' ' + svgH + '" preserveAspectRatio="none">' +
    gridLines + xLabels +
    '<path d="' + areaPath + '" class="area-savings" fill="' + areaColor + '"/>' +
    '<path d="' + planPath + '" class="line-plan"/>' +
    '<path d="' + apiPath + '" class="line-api"/>' +
    '</svg>';

  var legend = '<div class="savings-chart-legend">' +
    '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line dashed"></span>Plan cost</div>' +
    '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line solid"></span>API equiv.</div>' +
    '</div>';

  var totalLine = '';
  if (totalSaved > 0) {
    totalLine = '<div class="savings-chart-total">30-day savings: <span class="saved">' + formatCost(totalSaved) + '</span> (' + formatCost(totalMonthlyPlan) + '/mo plan vs ' + formatCost(cumApi[bucketCount - 1]) + ' API)</div>';
  } else {
    totalLine = '<div class="savings-chart-total">30-day delta: <span class="over">' + formatCost(Math.abs(totalSaved)) + ' over</span> (' + formatCost(totalMonthlyPlan) + '/mo plan vs ' + formatCost(cumApi[bucketCount - 1]) + ' API)</div>';
  }

  el.innerHTML = '<div class="usage-title">Cost Savings (30 days)</div>' + legend +
    '<div class="savings-chart-container">' + svg + '</div>' + totalLine;
}

function renderAccountBreakdown(data) {
  var el = document.getElementById('tok-accounts');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var accountMap = {};
  for (var i = 0; i < data.length; i++) {
    var acct = data[i].account || 'unknown';
    if (!accountMap[acct]) accountMap[acct] = { input: 0, output: 0, total: 0, cost: 0 };
    var inT = data[i].inputTokens || 0;
    var outT = data[i].outputTokens || 0;
    var crT = data[i].cacheReadInputTokens || 0;
    var ccT = data[i].cacheCreationInputTokens || 0;
    accountMap[acct].input += inT;
    accountMap[acct].output += outT;
    accountMap[acct].total += inT + outT;
    accountMap[acct].cost += estimateCost(data[i].model, inT, outT, crT, ccT);
  }
  var sortedAccounts = Object.keys(accountMap).sort(function(a,b) { return accountMap[b].total - accountMap[a].total; });
  if (!sortedAccounts.length) { el.innerHTML = ''; return; }
  var grandTotal = 0;
  for (var j = 0; j < sortedAccounts.length; j++) grandTotal += accountMap[sortedAccounts[j]].total;
  if (!grandTotal) grandTotal = 1;
  var propBar = '<div class="tok-proportion">';
  for (var k = 0; k < sortedAccounts.length; k++) {
    var pct = (accountMap[sortedAccounts[k]].total / grandTotal) * 100;
    propBar += '<div class="tok-proportion-seg" style="width:' + pct + '%;background:' + TOK_COLORS[k % TOK_COLORS.length] + '"></div>';
  }
  propBar += '</div>';
  var rows = '';
  for (var r = 0; r < sortedAccounts.length; r++) {
    var ad = accountMap[sortedAccounts[r]];
    var pctR = Math.round((ad.total / grandTotal) * 100);
    var cost = ad.cost;
    rows += '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:' + TOK_COLORS[r % TOK_COLORS.length] + '"></div>' +
      '<div class="tok-model-name">' + escHtml(sortedAccounts[r]) + '</div>' +
      '<div class="tok-model-detail">' + formatNum(ad.input) + ' in / ' + formatNum(ad.output) + ' out</div>' +
      '<div class="tok-model-total">' + formatNum(ad.total) + '</div>' +
      '<div class="tok-model-cost">' + formatCost(cost) + '</div>' +
      '<div class="tok-model-pct">' + pctR + '%</div>' +
    '</div>';
  }
  el.innerHTML = propBar + rows;
}

function renderRepoBranchBreakdown(data) {
  var el = document.getElementById('tok-repos');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var now = Date.now();
  var inactiveThreshold = now - 3 * 86400000;
  var allModels = {};
  // Group by repo, then by branch
  var repoMap = {};
  for (var i = 0; i < data.length; i++) {
    var repo = data[i].repo || 'unknown';
    var branch = data[i].branch || 'unknown';
    var inTok = data[i].inputTokens || 0;
    var outTok = data[i].outputTokens || 0;
    var crTok = data[i].cacheReadInputTokens || 0;
    var ccTok = data[i].cacheCreationInputTokens || 0;
    var m = data[i].model || 'unknown';
    var ts = data[i].timestamp || data[i].ts || 0;
    allModels[m] = 1;
    if (!repoMap[repo]) repoMap[repo] = { totalIn: 0, totalOut: 0, lastTs: 0, cost: 0, branches: {} };
    repoMap[repo].totalIn += inTok;
    repoMap[repo].totalOut += outTok;
    repoMap[repo].cost += estimateCost(m, inTok, outTok, crTok, ccTok);
    if (ts > repoMap[repo].lastTs) repoMap[repo].lastTs = ts;
    if (!repoMap[repo].branches[branch]) repoMap[repo].branches[branch] = { totalIn: 0, totalOut: 0, lastTs: 0, models: {} };
    var br = repoMap[repo].branches[branch];
    br.totalIn += inTok;
    br.totalOut += outTok;
    if (ts > br.lastTs) br.lastTs = ts;
    if (!br.models[m]) br.models[m] = { input: 0, output: 0 };
    br.models[m].input += inTok;
    br.models[m].output += outTok;
  }
  var sortedAllModels = Object.keys(allModels).sort();
  var grandTotal = 0;
  var repoList = Object.keys(repoMap).map(function(r) {
    var rd = repoMap[r];
    var total = rd.totalIn + rd.totalOut;
    grandTotal += total;
    return { key: r, name: r.split('/').pop(), totalIn: rd.totalIn, totalOut: rd.totalOut, total: total, lastTs: rd.lastTs, cost: rd.cost, branches: rd.branches };
  });
  if (!grandTotal) grandTotal = 1;
  // Split active/inactive
  var active = repoList.filter(function(r) { return r.lastTs >= inactiveThreshold; });
  var inactive = repoList.filter(function(r) { return r.lastTs < inactiveThreshold; });
  active.sort(function(a,b) { return b.total - a.total; });
  inactive.sort(function(a,b) { return b.total - a.total; });
  // Default collapse: collapsed if more than 3 active repos
  var defaultCollapsed = active.length > 3;
  function renderRepoGroup(repo, isInactive) {
    if (_tokRepoCollapsed[repo.key] === undefined) {
      _tokRepoCollapsed[repo.key] = isInactive ? true : defaultCollapsed;
    }
    var collapsed = _tokRepoCollapsed[repo.key];
    var pct = Math.round((repo.total / grandTotal) * 100);
    var cost = repo.cost;
    var cls = 'tok-repo-group' + (isInactive ? ' tok-repo-inactive' : '');
    var chevCls = 'tok-repo-chevron' + (collapsed ? ' collapsed' : '');
    var h = '<div class="' + cls + '">';
    h += '<div class="tok-repo-header" onclick="toggleRepoCollapse(this.dataset.key)" data-key="' + escHtml(repo.key) + '">';
    h += '<span class="' + chevCls + '">\u25BC</span>';
    h += '<span class="tok-repo-name">' + escHtml(repo.name) + '</span>';
    h += '<span class="tok-model-detail" style="flex:1">' + formatNum(repo.totalIn) + ' in / ' + formatNum(repo.totalOut) + ' out</span>';
    h += '<span class="tok-model-cost">' + formatCost(cost) + '</span>';
    h += '<span class="tok-model-pct">' + pct + '%</span>';
    h += '</div>';
    if (!collapsed) {
      var branchKeys = Object.keys(repo.branches).sort(function(a,b) {
        var ta = repo.branches[a].totalIn + repo.branches[a].totalOut;
        var tb = repo.branches[b].totalIn + repo.branches[b].totalOut;
        return tb - ta;
      });
      // Cap per-repo branch rendering to keep the DOM bounded. A long-lived
      // repo with many feature branches (or worktree-* auto-names) used to
      // render hundreds of rows on every refresh, doubling page weight and
      // making scroll laggy. Show top-N by total tokens; collapse the rest
      // into a footer row that sums them. RENDER_BRANCH_CAP is per-repo.
      var RENDER_BRANCH_CAP = 25;
      var hiddenBranchCount = 0;
      var hiddenBranchTotalIn = 0;
      var hiddenBranchTotalOut = 0;
      if (branchKeys.length > RENDER_BRANCH_CAP) {
        for (var hi = RENDER_BRANCH_CAP; hi < branchKeys.length; hi++) {
          var hb = repo.branches[branchKeys[hi]];
          hiddenBranchTotalIn += hb.totalIn;
          hiddenBranchTotalOut += hb.totalOut;
          hiddenBranchCount++;
        }
        branchKeys = branchKeys.slice(0, RENDER_BRANCH_CAP);
      }
      for (var bi = 0; bi < branchKeys.length; bi++) {
        var br = repo.branches[branchKeys[bi]];
        var brTotal = br.totalIn + br.totalOut;
        var brPct = Math.round((brTotal / grandTotal) * 100);
        var brInactive = br.lastTs < inactiveThreshold;
        var brCls = 'tok-branch-row' + (brInactive ? ' tok-branch-inactive' : '');
        var modelEntries = Object.entries(br.models).sort(function(a,b) { return (b[1].input + b[1].output) - (a[1].input + a[1].output); });
        var modelDetail = modelEntries.map(function(e) {
          return '<span style="color:'+getModelColor(e[0], sortedAllModels)+'">'+escHtml(shortModel(e[0]))+'</span> '+formatNum(e[1].input)+' / '+formatNum(e[1].output);
        }).join(' \u00b7 ');
        h += '<div class="' + brCls + '" style="padding-left:1.5rem">';
        h += '<div class="tok-branch-name"><span class="tok-branch-badge">' + escHtml(branchKeys[bi]) + '</span></div>';
        h += '<div class="tok-branch-stats">';
        h += '<span class="tok-branch-total">' + formatNum(br.totalIn) + ' / ' + formatNum(br.totalOut) + '</span>';
        h += '<span class="tok-branch-pct">' + brPct + '%</span>';
        h += '</div>';
        h += '<div class="tok-branch-detail">' + modelDetail + '</div>';
        h += '</div>';
      }
      // Footer row summarising hidden branches (only when we actually
      // capped the display above).
      if (hiddenBranchCount > 0) {
        var hiddenTotal = hiddenBranchTotalIn + hiddenBranchTotalOut;
        var hiddenPct = Math.round((hiddenTotal / grandTotal) * 100);
        h += '<div class="tok-branch-row tok-branch-inactive" style="padding-left:1.5rem;font-style:italic;opacity:0.75">';
        h += '<div class="tok-branch-name">… and ' + hiddenBranchCount + ' more branch' + (hiddenBranchCount === 1 ? '' : 'es') + '</div>';
        h += '<div class="tok-branch-stats">';
        h += '<span class="tok-branch-total">' + formatNum(hiddenBranchTotalIn) + ' / ' + formatNum(hiddenBranchTotalOut) + '</span>';
        h += '<span class="tok-branch-pct">' + hiddenPct + '%</span>';
        h += '</div>';
        h += '</div>';
      }
    }
    h += '</div>';
    return h;
  }
  var html = '';
  for (var a = 0; a < active.length; a++) html += renderRepoGroup(active[a], false);
  if (inactive.length) {
    html += '<div class="tok-inactive-sep">Inactive (no usage in last 3 days)</div>';
    for (var n = 0; n < inactive.length; n++) html += renderRepoGroup(inactive[n], true);
  }
  el.innerHTML = html;
}

// Phase E — Tool Breakdown panel. Mirrors renderModelBreakdown's structure
// (proportion bar + per-row stats). Auto-hides when there's no per-tool
// attribution data so users don't get an empty panel — the gate flag is
// off by default. Bucketing is server-side via /api/token-usage/by-tool.
function renderToolBreakdown(data) {
  var el = document.getElementById('tok-tools');
  var card = document.getElementById('tok-tools-card');
  if (!el || !card) return;
  // Compute client-side from the same filtered data the other breakdowns
  // use so the totals reconcile. (Server endpoint /api/token-usage/by-tool
  // exists for external consumers but the dashboard uses the in-memory data
  // to keep the scrubber's window filtering in sync.)
  var buckets = {};
  var hasAttributed = false;
  for (var i = 0; i < data.length; i++) {
    var row = data[i];
    var inT = row.inputTokens || 0;
    var outT = row.outputTokens || 0;
    if (inT === 0 && outT === 0) continue;
    var tool = (typeof row.tool === 'string' && row.tool.length > 0) ? row.tool : '(no per-tool attribution)';
    var mcp = (typeof row.mcpServer === 'string' && row.mcpServer.length > 0) ? row.mcpServer : null;
    if (tool !== '(no per-tool attribution)') hasAttributed = true;
    var key = mcp ? mcp + ':' + tool : tool;
    if (!buckets[key]) buckets[key] = { tool: tool, mcp: mcp, input: 0, output: 0, total: 0, count: 0 };
    buckets[key].input += inT;
    buckets[key].output += outT;
    buckets[key].total += inT + outT;
    buckets[key].count += 1;
  }
  // Hide the card entirely when no row has a tool field — the gate is off
  // and showing only "(no per-tool attribution)" would be useless.
  if (!hasAttributed) {
    card.style.display = 'none';
    el.innerHTML = '';
    return;
  }
  card.style.display = '';
  var keys = Object.keys(buckets).sort(function(a,b) { return buckets[b].total - buckets[a].total; });
  var grandTotal = 0;
  for (var k = 0; k < keys.length; k++) grandTotal += buckets[keys[k]].total;
  if (!grandTotal) grandTotal = 1;
  var propBar = '<div class="tok-proportion">';
  for (var p = 0; p < keys.length; p++) {
    var pct = (buckets[keys[p]].total / grandTotal) * 100;
    propBar += '<div class="tok-proportion-seg" style="width:' + pct + '%;background:' + TOK_COLORS[p % TOK_COLORS.length] + '"></div>';
  }
  propBar += '</div>';
  var rows = '';
  for (var r = 0; r < keys.length; r++) {
    var b = buckets[keys[r]];
    var pctR = Math.round((b.total / grandTotal) * 100);
    var label = b.mcp ? b.mcp + '/' + b.tool : b.tool;
    rows += '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:' + TOK_COLORS[r % TOK_COLORS.length] + '"></div>' +
      '<div class="tok-model-name">' + escHtml(label) + '</div>' +
      '<div class="tok-model-detail">' + formatNum(b.input) + ' in / ' + formatNum(b.output) + ' out · ' + b.count + ' calls</div>' +
      '<div class="tok-model-total">' + formatNum(b.total) + '</div>' +
      '<div class="tok-model-pct">' + pctR + '%</div>' +
    '</div>';
  }
  el.innerHTML = propBar + rows;
}

function tokFilterChange(which) {
  // Persist the new filter value(s) to localStorage so a browser
  // refresh / reopen retains the user's selection. We persist BEFORE
  // the refresh/apply so even if the network call below fails, the
  // next page load picks up the right filter state.
  try {
    const _ids = which === 'repo'
      ? ['tok-repo', 'tok-branch']  // repo also resets branch  - persist both
      : ['tok-' + which];
    for (const id of _ids) {
      const el = document.getElementById(id);
      if (el) localStorage.setItem('vdm.filter.' + id, el.value || '');
    }
  } catch (e) { /* private mode / quota */ }
  if (which === 'repo') {
    var branchEl = document.getElementById('tok-branch');
    if (branchEl) branchEl.value = '';
    _lastTokensHash = '';
    refreshTokens();
  } else if (which === 'model' || which === 'account') {
    applyTokenModelFilter();
  } else {
    _lastTokensHash = '';
    refreshTokens();
  }
}

function exportUsageCsv() {
  // Phase C: snapshot scrubber values at the moment of click. The user
  // may keep dragging while the download is queued — we intentionally
  // freeze [start,end] and tierFilter HERE so the file matches what the
  // dashboard showed when they clicked, not what is selected when the
  // browser actually flushes the blob.
  //
  // Start from the model/account/repo/branch-filtered baseline
  // (_tokFilteredData), then apply the SNAPSHOT scrubber + tier on top.
  // We do NOT start from _tokFilteredData because that was filtered with
  // the scrubber values at the time of the last applyTokenModelFilter()
  // call — which may be out of sync with the click-moment values when
  // the user drags then clicks export immediately. Starting from
  // _tokensRawData and re-applying the SAME select filters gives the
  // exact post-filter set the user sees right now.
  var snap = vsSnapshot();
  var modelSel   = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  var modelV   = modelSel   ? modelSel.value   : '';
  var accountV = accountSel ? accountSel.value : '';
  var data = (_tokensRawData || []).filter(function(e) {
    if (modelV   && e.model   !== modelV)   return false;
    if (accountV && e.account !== accountV) return false;
    var ts = Number(e.timestamp || e.ts || 0);
    if (!ts) return false;
    if (snap.start != null && ts < snap.start) return false;
    if (snap.end   != null && ts > snap.end)   return false;
    if (!vsTierMatchesEntry(e, snap)) return false;
    return true;
  });
  if (!data.length) { showToast('No data to export'); return; }
  var lines = ['timestamp,repo,branch,model,account,tier,input_tokens,output_tokens'];
  for (var i = 0; i < data.length; i++) {
    var e = data[i];
    var ts = e.timestamp || e.ts || '';
    if (ts) ts = new Date(ts).toISOString();
    lines.push([
      ts,
      '"' + (e.repo || '').replace(/"/g, '""') + '"',
      '"' + (e.branch || '').replace(/"/g, '""') + '"',
      '"' + (e.model || '').replace(/"/g, '""') + '"',
      '"' + (e.account || '').replace(/"/g, '""') + '"',
      '"' + (vsTierForAccount(e.account) || '').replace(/"/g, '""') + '"',
      e.inputTokens || 0,
      e.outputTokens || 0
    ].join(','));
  }
  var blob = new Blob([lines.join('\\n')], { type: 'text/csv' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  // Filename includes the window in YYYYMMDD_HHMMSS form so multiple
  // exports from the same day don't clobber each other in Downloads.
  a.download = 'vdm-export-' + vsFormatStamp(snap.start) + '_to_' + vsFormatStamp(snap.end) + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// TRDD-1645134b Phase 4 — tree-aggregated CSV export.
//
// Unlike exportUsageCsv() (which is one-row-per-API-request and computed
// client-side from _tokensRawData), this is one-row-per-bucket
// (repo|branch|component|tool) WITH per-bucket USD cost — and that cost
// calc lives server-side in lib.mjs (MODEL_PRICING + estimateModelCost).
// So we hit /api/token-usage-tree?format=csv and let the browser save
// the response via Content-Disposition.
//
// We honor the same dropdown filters as the rest of the Tokens tab
// (model/account/repo/time) — branch is omitted because the server-side
// aggregator doesn't take a branch filter (branch is a sub-grouping
// inside each repo node, not a top-level slicer).
function exportUsageTreeCsv() {
  var snap = vsSnapshot();
  var modelSel   = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  var repoSel    = document.getElementById('tok-repo');
  var modelV   = modelSel   ? modelSel.value   : '';
  var accountV = accountSel ? accountSel.value : '';
  var repoV    = repoSel    ? repoSel.value    : '';
  var qs = ['format=csv'];
  if (snap.start != null) qs.push('from=' + encodeURIComponent(snap.start));
  if (snap.end   != null) qs.push('to=' + encodeURIComponent(snap.end));
  if (modelV)   qs.push('model=' + encodeURIComponent(modelV));
  if (accountV) qs.push('account=' + encodeURIComponent(accountV));
  if (repoV)    qs.push('repo=' + encodeURIComponent(repoV));
  // Anchor download trigger — letting the browser save by following the
  // Content-Disposition header avoids loading a potentially large CSV
  // into memory as a Blob first.
  var a = document.createElement('a');
  a.href = '/api/token-usage-tree?' + qs.join('&');
  // The href filename is the server-emitted one (Content-Disposition);
  // setting a.download to '' lets the browser honor it but suppresses the
  // "Open with" prompt some browsers show when no download attr is set.
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

refresh();
loadSettingsUI();
vsBootstrap();
// Phase 6 — reflect the persisted multi-select filter in the toggle
// button label as soon as the page paints (so the user sees their
// existing selection rather than a default "All projects" that flips
// after the next data fetch).
_refreshProjectFilterLabel();
setInterval(refresh, 5000);
setInterval(tickCountdowns, 1000);
// Phase C: poll data-range / tier map every 10 s so the scrubber tracks
// fresh data points and newly-discovered accounts without a reload.
setInterval(vsRefreshDataRange, 10000);
// Restore tab from URL query param, falling back to localStorage so a
// freshly-opened browser tab (no ?tab= in URL) still lands on the user's
// last-viewed view. URL wins because users explicitly bookmark + share
// links with ?tab=NAME and that should take precedence.
let _initTab = new URLSearchParams(location.search).get('tab');
if (!_initTab) {
  try { _initTab = localStorage.getItem('vdm.activeTab'); } catch (e) { _initTab = null; }
}
if (_initTab && document.getElementById('tab-' + _initTab)) switchTab(_initTab);

// Restore Token-Usage filters from localStorage on page load. Each
// filter is stored independently so we can grow this set without
// versioning. We restore BEFORE the first refreshTokens() so the
// initial fetch reflects the user's previous filter selection rather
// than the defaults.
try {
  const _tokFilterKeys = ['tok-repo', 'tok-branch', 'tok-model', 'tok-account', 'tok-time'];
  for (const k of _tokFilterKeys) {
    const v = localStorage.getItem('vdm.filter.' + k);
    if (v == null) continue;
    const el = document.getElementById(k);
    if (!el) continue;
    // Only restore if the stored value still corresponds to a real option
    // — otherwise an old filter (e.g. a deleted repo) would leave the
    // dropdown stuck on a value that produces an empty result set.
    let valid = false;
    for (let i = 0; i < el.options.length; i++) {
      if (el.options[i].value === v) { valid = true; break; }
    }
    if (valid) el.value = v;
  }
} catch (e) { /* private mode / quota / DOM not ready */ }

// ── Log stream ──
let _logES = null;
const LOG_MAX_LINES = 5000;
const LOG_TAG_COLORS = {
  error: '#f85149', warn: '#f85149',
  switch: '#d29922', proactive: '#d29922',
  refresh: '#58a6ff', circuit: '#58a6ff', fallback: '#58a6ff',
  info: '#8b949e', system: '#8b949e',
};

function connectLogStream() {
  if (_logES) return; // already connected
  const container = document.getElementById('log-container');
  const status = document.getElementById('log-status');
  status.textContent = 'Connecting...';
  _logES = new EventSource('/api/logs/stream');
  _logES.onopen = () => { status.textContent = 'Connected'; status.style.color = '#3fb950'; };
  _logES.onerror = () => { status.textContent = 'Reconnecting...'; status.style.color = '#f85149'; };
  _logES.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      const line = document.createElement('div');
      const tag = (data.tag || 'info').toLowerCase();
      const color = LOG_TAG_COLORS[tag] || '#8b949e';
      // H7 fix — escape the tag identifier before HTML interpolation.
      // Currently every log() caller passes a programmer-set string, but a
      // future regression (or an attacker-controlled tag via OTLP payload
      // spillover) would execute injected script. Defense-in-depth: escape
      // uniformly. NB: avoid markdown backticks in comments inside renderHTML
      // because the whole function body is one big template literal and any
      // stray backtick terminates it (see CLAUDE.md backtick-in-comment trap).
      line.innerHTML = '<span style="color:' + color + ';font-weight:600">[' + escHtml(tag.toUpperCase()) + ']</span> ' + escHtml(data.msg || data.line || '');
      // Check scroll position before DOM changes
      const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 60;
      container.appendChild(line);
      // Prune oldest lines, preserving scroll position if user scrolled up
      var pruneCount = container.childElementCount - LOG_MAX_LINES;
      if (pruneCount > 0 && !atBottom) {
        var removedHeight = 0;
        while (pruneCount-- > 0) {
          removedHeight += container.firstChild.offsetHeight;
          container.removeChild(container.firstChild);
        }
        container.scrollTop -= removedHeight;
      } else {
        while (container.childElementCount > LOG_MAX_LINES) container.removeChild(container.firstChild);
      }
      if (atBottom) container.scrollTop = container.scrollHeight;
    } catch {}
  };
}

function clearLogs() {
  const container = document.getElementById('log-container');
  container.innerHTML = '';
}

// ── Session Monitor ──

function sessionDuration(ms) {
  if (ms < 60000) return Math.floor(ms / 1000) + 's';
  if (ms < 3600000) return Math.floor(ms / 60000) + 'm ' + Math.floor((ms % 60000) / 1000) + 's';
  return Math.floor(ms / 3600000) + 'h ' + Math.floor((ms % 3600000) / 60000) + 'm';
}

function sessionTimeAgo(ts) {
  var d = Date.now() - ts;
  if (d < 60000) return Math.floor(d / 1000) + 's ago';
  if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
  return Math.floor(d / 3600000) + 'h ago';
}

function sessionEstCost(inTok, outTok, model) {
  // Rough estimates per 1M tokens
  var inCost = 15, outCost = 75; // opus defaults
  if (model && model.includes('sonnet')) { inCost = 3; outCost = 15; }
  if (model && model.includes('haiku')) { inCost = 0.25; outCost = 1.25; }
  return ((inTok * inCost + outTok * outCost) / 1e6).toFixed(2);
}

var _lastBadgeRefresh = 0;
var _collapsedSessions = new Set();
function toggleSessionCollapse(id) {
  if (_collapsedSessions.has(id)) _collapsedSessions.delete(id);
  else _collapsedSessions.add(id);
  var card = document.querySelector('.session-card[data-sid="' + id + '"]');
  if (card) card.classList.toggle('collapsed');
}
function refreshSessionsBadgeOnly() {
  // Throttle badge-only fetches to once per 10s
  var now = Date.now();
  if (now - _lastBadgeRefresh < 10000) return;
  _lastBadgeRefresh = now;
  fetch('/api/sessions').then(function(r) { return r.json(); }).then(function(data) {
    var threshold = ${SESSION_AWAITING_THRESHOLD};
    updateSessionsBadge((data.active || []).filter(function(s) { return (Date.now() - s.lastActiveAt) >= threshold; }).length);
  }).catch(function() {});
}

async function refreshSessions() {
  try {
    var resp = await fetch('/api/sessions');
    var data = await resp.json();
    // No quickHash guard — time-derived displays (duration, idle, state) must
    // update even when API data is unchanged (wall-clock drives state transitions)
    renderSessions(data);
    var threshold = ${SESSION_AWAITING_THRESHOLD};
    updateSessionsBadge((data.active || []).filter(function(s) { return (Date.now() - s.lastActiveAt) >= threshold; }).length);
  } catch {}
}

function renderSessions(data) {
  var el = document.getElementById('sessions-content');
  if (!el) return;
  var active = data.active || [];
  var recent = data.recent || [];
  if (!active.length && !recent.length) {
    if (!data.enabled) {
      el.innerHTML = '<div class="empty-state">Session Monitor is OFF. Enable it in Config (BETA).</div>';
    } else {
      el.innerHTML = '<div class="empty-state">No sessions yet. Start a Claude Code session with the proxy running.</div>';
    }
    return;
  }
  var html = '';

  // Conflicts banner
  if (data.conflicts && data.conflicts.length) {
    html += '<div class="session-conflicts">';
    data.conflicts.forEach(function(c) {
      html += '<div>\\u26A0 ' + c.count + ' sessions editing ' + escHtml(c.file) + '</div>';
    });
    html += '</div>';
  }

  // Active sessions
  if (active.length) {
    html += '<div class="session-section-title">ACTIVE</div>';
    active.forEach(function(s) {
      var idleMs = Date.now() - s.lastActiveAt;
      var state = idleMs < ${SESSION_AWAITING_THRESHOLD} ? 'processing' : 'awaiting';
      var dur = sessionDuration(Date.now() - s.startedAt);
      var idle = state === 'awaiting' ? sessionDuration(idleMs) : '';
      var proj = sessionProj(s);
      var collapsed = _collapsedSessions.has(s.id) ? ' collapsed' : '';
      html += '<div class="session-card ' + state + collapsed + '" data-sid="' + s.id + '">';
      html += '<button class="session-copy-btn" onclick="copyTimeline(\\'' + s.id + '\\')">\\uD83D\\uDCCB</button>';
      html += '<div class="session-header" onclick="toggleSessionCollapse(\\'' + s.id + '\\')">';
      html += '<span class="session-collapse-indicator">\\u25BC</span>';
      html += '<span class="session-header-left"><b>' + escHtml(s.account) + '</b> \\u00b7 ' + escHtml(proj) + '</span>';
      html += '<span class="session-header-right"><span>' + dur + '</span>';
      if (state === 'awaiting') {
        html += '<span class="session-awaiting">\\u23F8 input ' + idle + '</span>';
      }
      html += '</span>';
      html += '</div>';
      // Collapsed activity summary (visible only when collapsed)
      if (s.currentActivity) {
        var brailleC = state === 'processing' ? 'braille-spin' : 'braille-static';
        html += '<div class="session-collapsed-activity"><span class="' + brailleC + '"></span>' + escHtml(s.currentActivity) + '</div>';
      }
      // Timeline
      html += '<div class="session-timeline">';
      s.timeline.forEach(function(e) {
        if (e.type === 'input') html += '<div class="tl-input">' + escHtml(e.text) + '</div>';
        else html += '<div class="tl-action">' + escHtml(e.text) + '</div>';
      });
      // Current activity
      if (s.currentActivity) {
        var brailleClass = state === 'processing' ? 'braille-spin' : 'braille-static';
        html += '<div class="tl-current"><span class="' + brailleClass + '"></span>' + escHtml(s.currentActivity) + '</div>';
      }
      html += '</div>';
      // Meta
      html += '<div class="session-meta">';
      html += '<span>' + s.requestCount + ' req</span>';
      html += '<span>' + formatNum(s.totalInputTokens + s.totalOutputTokens) + ' tok</span>';
      html += '</div>';
      html += '</div>';
    });
  }

  // Recent sessions
  if (recent.length) {
    html += '<div class="session-section-title">RECENT</div>';
    recent.forEach(function(s) {
      var ago = sessionTimeAgo(s.completedAt || s.startedAt);
      var dur = sessionDuration(s.duration || 0);
      var cost = sessionEstCost(s.totalInputTokens || 0, s.totalOutputTokens || 0, s.model);
      var proj = sessionProj(s);
      var collapsed = _collapsedSessions.has(s.id) ? ' collapsed' : '';
      html += '<div class="session-card completed' + collapsed + '" data-sid="' + s.id + '">';
      html += '<button class="session-copy-btn" onclick="copyTimeline(\\'' + s.id + '\\')">\\uD83D\\uDCCB</button>';
      html += '<div class="session-header" onclick="toggleSessionCollapse(\\'' + s.id + '\\')">';
      html += '<span class="session-collapse-indicator">\\u25BC</span>';
      html += '<span class="session-header-left"><span>' + ago + '</span> \\u00b7 <b>' + escHtml(s.account) + '</b> \\u00b7 ' + escHtml(proj) + '</span>';
      html += '<span class="session-header-right"><span>' + dur + ' \\u00b7 ~$' + cost + '</span></span>';
      html += '</div>';
      html += '<div class="session-timeline">';
      (s.timeline || []).forEach(function(e) {
        if (e.type === 'input') html += '<div class="tl-input">' + escHtml(e.text) + '</div>';
        else html += '<div class="tl-action">' + escHtml(e.text) + '</div>';
      });
      html += '</div>';
      html += '<div class="session-meta">';
      html += '<span>' + (s.requestCount || 0) + ' req</span>';
      html += '<span>' + formatNum((s.totalInputTokens || 0) + (s.totalOutputTokens || 0)) + ' tok</span>';
      html += '</div>';
      html += '</div>';
    });
  }

  // Overhead footer
  if (data.overhead) {
    var oh = data.overhead.inputTokens + data.overhead.outputTokens;
    if (oh > 0) {
      html += '<div class="session-overhead">Summarizer overhead: ' + formatNum(oh) + ' tokens (Haiku)</div>';
    }
  }

  el.innerHTML = html;
}

function updateSessionsBadge(count) {
  var badge = document.getElementById('sessions-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

function sessionProj(s) {
  if (s.branch) {
    if (s.branch === 'main' || s.branch === 'master') return (s.repo || '') + '/' + s.branch;
    var parts = s.branch.split('/');
    return parts[parts.length - 1];
  }
  return s.repo || s.cwd || 'unknown';
}
function copyTimeline(sessionId) {
  // Find session data from last render
  fetch('/api/sessions').then(function(r) { return r.json(); }).then(function(data) {
    var s = (data.active || []).find(function(a) { return a.id === sessionId; })
         || (data.recent || []).find(function(a) { return a.id === sessionId; });
    if (!s) { showToast('Session not found'); return; }
    var proj = sessionProj(s);
    var dur = sessionDuration(s.duration || (Date.now() - s.startedAt));
    var tok = formatNum((s.totalInputTokens || 0) + (s.totalOutputTokens || 0));
    var md = '## Session: ' + proj + ' (' + dur + ', ' + tok + ' tokens)\\n';
    (s.timeline || []).forEach(function(e) {
      if (e.type === 'input') md += '- \\u2192 ' + e.text + '\\n';
      else md += '  - ' + e.text + '\\n';
    });
    navigator.clipboard.writeText(md).then(function() {
      showToast('Timeline copied');
    }).catch(function() {
      showToast('Copy failed');
    });
  }).catch(function() { showToast('Failed to fetch session'); });
}
</script>
<footer style="text-align:center;padding:2rem 0 1rem;font-size:0.75rem;color:#9ca3af;line-height:1.8">
  <div>🤙 Vibe coded with love by LJ &middot; ${PROJECT_VERSION}</div>
  <a href="https://github.com/Emasoft/claude-acct-switcher" target="_blank" rel="noopener" style="color:#9ca3af;text-decoration:none">github.com/Emasoft/claude-acct-switcher</a>
</footer>
</body>
</html>`;
}

// ─────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────

// CSRF / cross-origin protection.
//
// The dashboard binds to 127.0.0.1, but a malicious local webpage in
// the user's browser could still POST to /api/switch, /api/remove,
// /api/refresh, /api/settings — every mutating endpoint — without the
// user noticing. Previously CORS was wide-open
// (Access-Control-Allow-Origin: *) which made the situation worse:
// the browser would treat the response as readable, completing the
// CSRF.
//
// Defence:
//   1. Restrict Access-Control-Allow-Origin to a small allow-list of
//      same-host origins. Anything else gets no CORS headers (the
//      browser blocks the response from being read by JS).
//   2. Mutating methods (POST/PUT/DELETE) require either:
//        a. An Origin header that's in the allow-list, OR
//        b. No Origin header (Claude Code itself, vdm CLI via curl).
//      A request with a foreign Origin is rejected 403 before any
//      handler runs.
// PROXY_PORT is declared later in the file (the proxy server lives
// further down). Build the allow-list lazily on first request so the
// constant is defined by then. Cache after first build to avoid
// rebuilding on every request.
let _ALLOWED_ORIGINS = null;
function _getAllowedOrigins() {
  if (_ALLOWED_ORIGINS) return _ALLOWED_ORIGINS;
  const proxyPort = (typeof PROXY_PORT !== 'undefined') ? PROXY_PORT : parseInt(process.env.CSW_PROXY_PORT || '3334', 10);
  _ALLOWED_ORIGINS = new Set([
    `http://localhost:${PORT}`,
    `http://127.0.0.1:${PORT}`,
    `http://localhost:${proxyPort}`,
    `http://127.0.0.1:${proxyPort}`,
  ]);
  return _ALLOWED_ORIGINS;
}

function _isOriginAllowed(origin) {
  if (!origin) return true; // CLI / non-browser callers
  return _getAllowedOrigins().has(origin);
}

// SECURITY: Host-header allow-list for DNS-rebinding defense. The
// previous Origin allow-list only fires on mutating requests, leaving
// every GET (`/api/profiles` returns emails+fingerprints; `/api/sessions`
// returns prompt excerpts; `/api/logs/stream` is a live SSE feed) exposed
// to a malicious local web page that DNS-rebinds attacker.example to
// 127.0.0.1. The browser treats the iframe as same-origin to attacker.example
// AND lets attacker JS hit `/api/profiles` once the rebind takes effect.
// Validating Host: shuts that path because the browser sends Host: attacker.example
// even after the IP rebinds — only literal localhost / 127.0.0.1 / [::1]
// pass. Applied to dashboard, proxy, and OTLP servers.
function _isLocalhostHost(host, expectedPort) {
  if (typeof host !== 'string' || !host) return false;
  // Accept `localhost`, `127.0.0.1`, `[::1]` (IPv6 bracketed) on the
  // configured port. Reject everything else, including spoofed Hosts that
  // happen to start with localhost (e.g. localhost.attacker.example).
  const allowed = [
    `localhost:${expectedPort}`,
    `127.0.0.1:${expectedPort}`,
    `[::1]:${expectedPort}`,
  ];
  return allowed.includes(host.toLowerCase());
}

const server = createServer(async (req, res) => {
  try {
    // DNS-rebind defense — see comment above.
    if (!_isLocalhostHost(req.headers.host, PORT)) {
      res.writeHead(421, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'misdirected request: invalid Host header' }));
      return;
    }
    // CORS — same-host allow-list, NOT wildcard. Browser CSRF guard.
    const origin = req.headers.origin || '';
    if (origin && _getAllowedOrigins().has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // Health check — used by install.sh during atomic install AND by
    // the rc-snippet's auto-start guard. Returns 200 with a tiny JSON
    // body the moment the listener accepts connections, so the installer
    // can stop polling and proceed to write hooks. No CORS, no auth,
    // no shared state — must respond regardless of init progress. HEAD
    // is also accepted (Node's http server strips the body automatically
    // for HEAD), so cheap probes that only care about status work too.
    if ((req.method === 'GET' || req.method === 'HEAD') && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, server: 'dashboard', port: PORT }));
      return;
    }

    // Reject mutating requests from foreign origins. Reads (GET) are
    // tolerated because the browser still won't expose the response
    // body without matching CORS headers, but mutations could side-
    // effect even on a 0-byte response.
    const isMutating = req.method && req.method !== 'GET' && req.method !== 'HEAD';
    if (isMutating && !_isOriginAllowed(origin)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'cross-origin request rejected' }));
      return;
    }

    // API routes
    if (req.url.startsWith('/api/')) {
      const handled = await handleAPI(req, res);
      if (handled) return;
    }

    // Dashboard HTML
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(renderHTML());
  } catch (e) {
    console.error('Server error:', e);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: e.message }));
  }
});

// Bind to localhost only — never expose the dashboard or its mutating
// API surface (`/api/switch`, `/api/refresh`, `/api/remove`, `/api/settings`)
// to the network. Default Node bind is `::` / `0.0.0.0` which is a
// multi-user-laptop and accidental-LAN exposure vector.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
  // Discover any existing keychain token on startup so the dashboard
  // shows accounts immediately (don't wait for the first proxy request)
  autoDiscoverAccount().catch((e) => {
    log('warn', `Startup autoDiscoverAccount failed: ${e && e.message}`);
  });
});

// Without this, a duplicate spawn from the rc-snippet race (two terminals
// opening within 100 ms) raises an UNHANDLED EADDRINUSE that silently
// crashes the loser AFTER it has already set up timers. Exit 0 so the
// already-bound dashboard wins cleanly.
server.on('error', (e) => {
  if (e && e.code === 'EADDRINUSE') {
    console.error(`Dashboard port ${PORT} already in use — another instance is already running. Exiting.`);
    process.exit(0);
  }
  throw e;
});

// ─────────────────────────────────────────────────
// Transparent API Proxy (port 3334) with AUTO-SWITCH
//
// All Claude Code sessions should set:
//   ANTHROPIC_BASE_URL=http://localhost:3334
//
// On each request the proxy:
//  1. Picks the best available account (proactive)
//  2. Forwards to api.anthropic.com
//  3. On 429 → auto-retries with next account
//  4. On 401 → marks token expired, tries next
//  5. On 529 → returns as-is (server overload)
//  6. Tracks per-account rate-limit state from
//     every response's headers
// ─────────────────────────────────────────────────

const PROXY_PORT = parseInt(process.env.CSW_PROXY_PORT || '3334', 10);

// Phase F — proxy queue + timeout tuning. All env-var configurable so users
// on different plans / load profiles can adjust without code changes.
//
// Defaults reflect lessons from Phase F's audit:
//   - PROXY_TIMEOUT (idle socket timeout per upstream call): 15 min.
//     Was 5 min, which can be too short for Opus 4 extended-thinking
//     phases where SSE chunks arrive sparsely.
//   - REQUEST_DEADLINE_MS (total handleProxyRequest wall-clock cap): 10 min.
//     Was 45 s, which routinely killed legitimate refresh+retry chains.
//     Successful first-attempt streams are not affected (the deadline is
//     only checked at retry boundaries). For pathological loops only.
//   - MAX_INFLIGHT_PER_ACCOUNT: 8 (was 4). Now actually enforced for the
//     full stream lifetime — see forwardToAnthropic().
//   - MIN_INTERVAL_PER_ACCOUNT_MS: 100 (was 125). Slightly less conservative.
//   - MAX_PERMIT_WAIT_MS: 5 min (was 30 s). Combined with REQUEST_DEADLINE_MS
//     this means high-load queueing no longer manufactures false 504s.
const PROXY_TIMEOUT = parseInt(process.env.CSW_PROXY_TIMEOUT_MS || '900000', 10);          // 15 min
const REQUEST_DEADLINE_MS = parseInt(process.env.CSW_REQUEST_DEADLINE_MS || '600000', 10); // 10 min
// Phase F audit B1/G1 — queueTimeoutMs MUST be larger than REQUEST_DEADLINE_MS,
// otherwise queued requests get rejected with `queue_timeout` (→ 503) before
// the deadline guard ever fires. Default = REQUEST_DEADLINE_MS + 60s buffer.
// Was hard-coded to 120s in lib.mjs (un-tunable, smaller than REQUEST_DEADLINE_MS).
// Tune via CSW_QUEUE_TIMEOUT_MS for sites with very long Opus streams.
// FG4 follow-up — validate the parsed env-var. With the lib.mjs `??`
// change, an explicit `0` propagates all the way through the queue and
// rejects every queued request immediately. That's a useful test mode
// but a footgun in production. Warn loudly when the value looks
// pathological, but don't override — the operator is in charge.
const _rawQueueTimeoutMs = parseInt(
  process.env.CSW_QUEUE_TIMEOUT_MS || String(REQUEST_DEADLINE_MS + 60_000),
  10
);
const QUEUE_TIMEOUT_MS = Number.isFinite(_rawQueueTimeoutMs) && _rawQueueTimeoutMs >= 0
  ? _rawQueueTimeoutMs
  : (REQUEST_DEADLINE_MS + 60_000);
if (process.env.CSW_QUEUE_TIMEOUT_MS && QUEUE_TIMEOUT_MS < REQUEST_DEADLINE_MS) {
  // setLog() hasn't been wired yet at module load — defer the warning
  // to next tick so the log() function exists by the time it fires.
  setImmediate(() => {
    try {
      log('warn', `CSW_QUEUE_TIMEOUT_MS=${QUEUE_TIMEOUT_MS}ms is less than REQUEST_DEADLINE_MS=${REQUEST_DEADLINE_MS}ms — queued requests will be rejected with queue_timeout before the deadline guard fires (re-introduces the audit B1/G1 regression). Set ≥ REQUEST_DEADLINE_MS or omit to use the default.`);
    } catch {}
  });
}

// Phase H — opt-in OTLP/HTTP/JSON receiver for cross-checking vdm's
// hook-derived counts against Claude Code's first-party telemetry. Off by
// default (CSW_OTEL_ENABLED=1 to enable). When enabled, opens a third HTTP
// listener on CSW_OTLP_PORT (default 3335) accepting POST /v1/logs and
// POST /v1/metrics. The user must also set, in their shell or in
// ~/.claude/settings.json env block:
//   CLAUDE_CODE_ENABLE_TELEMETRY=1
//   OTEL_LOGS_EXPORTER=otlp  OTEL_METRICS_EXPORTER=otlp
//   OTEL_EXPORTER_OTLP_PROTOCOL=http/json
//   OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3335
// vdm does NOT auto-mutate settings.json for this — opt-in only because
// turning telemetry on has privacy implications (the user_prompt event
// contains prompt text when OTEL_LOG_USER_PROMPTS=1).
const OTEL_ENABLED = process.env.CSW_OTEL_ENABLED === '1';
const OTLP_PORT = parseInt(process.env.CSW_OTLP_PORT || '3335', 10);
const OTEL_BUFFER_MAX = parseInt(process.env.CSW_OTEL_BUFFER_MAX || '5000', 10);

// ── Structured logger ──

// ── Live log streaming (SSE subscribers for `vdm logs`) ──
const _logSubscribers = new Set();
const _logBuffer = [];
const LOG_BUFFER_MAX = 2000;

// Redact secrets from a string before it enters the log stream. The
// SSE subscribers (vdm logs / dashboard activity / startup.log file)
// have a wider audience than the in-memory state, so anything that
// might contain credentials should pass through this first.
//
// We do PATTERN-BASED REDACTION rather than truncation: truncating
// hides the response shape and length, which are useful for
// diagnosing "why didn't the JSON parse" without leaking the body's
// secret content. Each match is replaced with a typed sentinel so
// developers can still see WHAT got redacted.
//
// Patterns covered (ordered most-specific-first):
//   - Bearer / Authorization tokens
//   - sk-* / sk-ant-* / Anthropic API keys
//   - OAuth refresh / access tokens (long URL-safe-base64 strings)
//   - UUIDs
//   - Email addresses (PII, not always secret but worth redacting)
//   - Long hex runs (≥32 chars) — fingerprints, hashes
//   - JSON values for keys named "token" / "secret" / "password" /
//     "apiKey" / "api_key" / "authorization" (covers structured logs)
function _redactForLog(s) {
  if (typeof s !== 'string') return s;
  if (s.length === 0) return s;
  let out = s;
  // JSON-shaped key/value pairs first — captures the most context.
  out = out.replace(
    /("(?:token|access_token|refresh_token|secret|password|api[_-]?key|authorization)"\s*:\s*)"[^"]*"/gi,
    '$1"[REDACTED:KV]"'
  );
  // Authorization: Bearer / Basic / etc.
  out = out.replace(/Bearer\s+[A-Za-z0-9._\-/+]+=*/g, 'Bearer [REDACTED:BEARER]');
  out = out.replace(/Basic\s+[A-Za-z0-9+/=]+/g, 'Basic [REDACTED:BASIC]');
  // Anthropic API keys
  out = out.replace(/sk-ant-[A-Za-z0-9_\-]{20,}/g, '[REDACTED:KEY]');
  out = out.replace(/sk-[A-Za-z0-9_\-]{20,}/g, '[REDACTED:KEY]');
  // OAuth tokens (URL-safe base64 ≥ 32 chars). Must run BEFORE the
  // hex pattern because token alphabets overlap.
  out = out.replace(/[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}/g, '[REDACTED:JWT]');
  // UUIDs
  out = out.replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '[REDACTED:UUID]');
  // Emails (organisation_name, user labels, etc.)
  out = out.replace(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, '[REDACTED:EMAIL]');
  // Long hex runs (≥ 40 chars — sha-1+ length). Order matters so this
  // runs after JWT/UUID; both of those have shorter components.
  out = out.replace(/\b[0-9a-fA-F]{40,}\b/g, '[REDACTED:HEX]');
  return out;
}

function log(tag, msg, extra = '') {
  // L4 — store entry.ts as Date.now() (epoch ms) instead of the
  // pre-formatted en-GB locale string. Storing the raw epoch lets SSE
  // consumers re-format in their own locale (or filter by time window
  // numerically). The pre-formatted display string moves to
  // entry.tsDisplay so the inline `line` field — and any downstream
  // consumer that wants the on-the-wire human form — keep working
  // unchanged. The console / SSE `line` text continues to embed the
  // formatted display so existing renderers don't change.
  const tsEpoch = Date.now();
  const tsDisplay = new Date(tsEpoch).toLocaleTimeString('en-GB', { hour12: false });
  const line = `[${tsDisplay}] [${tag}] ${msg}${extra ? ' ' + extra : ''}`;
  try { console.log(line); } catch { /* stdout broken (EIO/EPIPE) — ignore */ }
  const entry = { ts: tsEpoch, tsDisplay, tag, msg: msg + (extra ? ' ' + extra : ''), line };
  // Buffer for replay to new SSE clients
  _logBuffer.push(entry);
  if (_logBuffer.length > LOG_BUFFER_MAX) _logBuffer.shift();
  // Push to all SSE subscribers (these still work even when stdout is dead)
  for (const res of [..._logSubscribers]) {
    try { res.write(`data: ${JSON.stringify(entry)}\n\n`); }
    catch { _logSubscribers.delete(res); }
  }
}

// ── Event log (proxy state transitions) ──
//
// Phase 6 cleanup: the in-memory `proxyEventLog` ring buffer was a dead
// pipeline — exposed via /api/proxy-status as `recentEvents` but never
// consumed by the UI (the activity log already covers the same content
// via logActivity()). Removing it eliminates duplicate state and ~50
// entries of redundant in-memory data per dashboard process.

// Dedup noisy events (rate-limited / all-exhausted) so the activity log
// doesn't fill up when Claude Code retries against an already-limited account.
const _eventDedupMap = new Map(); // "type:key" → timestamp
const EVENT_DEDUP_WINDOW = 5 * 60 * 1000; // 5 min
const EVENT_DEDUP_MAX = 500;       // hard cap; periodic TTL prune below

function logEvent(type, detail = {}) {
  if (type === 'rate-limited' || type === 'all-exhausted') {
    const dedupKey = type === 'rate-limited' ? `rate-limited:${detail.account || ''}` : 'all-exhausted';
    const lastTs = _eventDedupMap.get(dedupKey);
    if (lastTs && Date.now() - lastTs < EVENT_DEDUP_WINDOW) return;
    _capMapInsert(_eventDedupMap, dedupKey, Date.now(), EVENT_DEDUP_MAX);
  }

  // Persist to the activity log (the only consumer — UI reads /api/activity-log).
  logActivity(type, detail);
}

// ── Keychain token cache ──

let _kcCache = null;
let _kcCacheAt = 0;
const KC_CACHE_TTL = 2000;

function getActiveToken() {
  const now = Date.now();
  if (_kcCache && now - _kcCacheAt < KC_CACHE_TTL) return _kcCache;
  const creds = readKeychain();
  _kcCache = creds?.claudeAiOauth?.accessToken || null;
  _kcCacheAt = now;
  return _kcCache;
}

function invalidateTokenCache() {
  _kcCache = null;
  _kcCacheAt = 0;
}

// ── Per-account state ──
// Map<token, { name, limited, expired, resetAt, retryAfter,
//              utilization5h, utilization7d, updatedAt }>

const accountState = createAccountStateManager();

// ── Persisted state (keyed by fingerprint, survives restarts) ──
// Saved: { [fingerprint]: { utilization5h, utilization7d, resetAt, resetAt7d, updatedAt } }

let persistedState = {};

function loadPersistedState() {
  // Distinguish ENOENT (fresh install — start clean) from any other
  // failure (parse error, EIO, partial write that survived a crash).
  // The previous swallow-and-init-empty silently zeroed ALL accounts'
  // ban flags on corruption, so the next proxy request happily probed
  // every account including ones that should still be cooling down on
  // a 7-day limit — turning a transient disk hiccup into a fresh
  // 7-day rate limit. Mirror the loadViewerState recovery pattern.
  if (!existsSync(STATE_FILE)) {
    persistedState = {};
    return;
  }
  let raw;
  try {
    raw = readFileSync(STATE_FILE, 'utf8');
  } catch (e) {
    // Read failed (permissions / disk error). Keep the previous
    // in-memory state if we already have one, otherwise empty.
    try {
      log('error', `loadPersistedState read failed for ${STATE_FILE}: ${e.message} — keeping previous in-memory state`);
    } catch { console.error(`loadPersistedState read failed: ${e.message}`); }
    if (!persistedState) persistedState = {};
    return;
  }
  try {
    persistedState = JSON.parse(raw);
    if (!persistedState || typeof persistedState !== 'object') {
      throw new Error(`expected JSON object, got ${typeof persistedState}`);
    }
  } catch (e) {
    // Parse failed — back up the corrupt file so the user can recover
    // ban-state forensics, then start clean. Loud log + activity event
    // so the recovery is visible in the dashboard UI.
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `${STATE_FILE}.corrupt-${ts}`;
    try {
      writeFileSync(backupPath, raw, { mode: 0o600 });
    } catch (writeErr) {
      // If we can't even back up, just log and continue.
      try { log('error', `loadPersistedState corrupt backup write failed: ${writeErr.message}`); } catch {}
    }
    try {
      log('error', `account-state.json was corrupt (${e.message}); backed up to ${basename(backupPath)} and reinitialized to empty. Re-evaluation of ban flags will happen on next proxy request.`);
    } catch { console.error(`account-state.json corrupt: ${e.message}`); }
    try {
      logActivity('persisted-state-recovery', { reason: e.message, backup: basename(backupPath) });
    } catch {}
    persistedState = {};
  }
}

function savePersistedState() {
  try {
    // Pretty-print so `cat account-state.json` is human-debuggable
    // (CORRUPT-4). 2x file size is acceptable — the file is bounded
    // by account count, typically <10 KB.
    atomicWriteFileSync(STATE_FILE, JSON.stringify(persistedState, null, 2));
  } catch {}
}

// ── Viewer-state (Phase C — date-range scrubber + tier filter) ──
// Persisted shape: { start: ms_epoch, end: ms_epoch, tierFilter: string[] }.
// Defaults are computed at load time against the live data range, so a
// fresh install with no on-disk state still gets a sensible window.
//
// Why GET fabricates `dataRange` per-call instead of caching it:
// token-usage.json + activity-log.json change continuously while the
// process is running (every proxy request, every settings toggle), so a
// cached oldest/newest would drift seconds-stale. The lookup is O(N) over
// two arrays we already pay to keep in memory — cheap on every hit.

let _viewerStateCache = null;

function loadViewerState() {
  if (_viewerStateCache) return _viewerStateCache;
  let recovered = false;
  try {
    if (existsSync(VIEWER_STATE_FILE)) {
      const raw = readFileSync(VIEWER_STATE_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      // Sanity check: must be a plain object with the right shape.
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        _viewerStateCache = {
          start: Number.isFinite(parsed.start) ? Number(parsed.start) : null,
          end: Number.isFinite(parsed.end) ? Number(parsed.end) : null,
          tierFilter: Array.isArray(parsed.tierFilter) ? parsed.tierFilter : ['all'],
        };
        return _viewerStateCache;
      }
      log('warn', 'viewer-state.json malformed — overwriting with defaults');
      recovered = true;
    }
  } catch (e) {
    // Malformed JSON / unreadable / partial write survived a crash. Write
    // a fresh defaults file atomically so the next read succeeds and
    // the user doesn't get the same warning every page load.
    log('warn', `viewer-state.json read failed (${e.message}) — overwriting with defaults`);
    recovered = true;
  }
  if (recovered) {
    // Don't recursively invoke saveViewerState (which sets _viewerStateCache);
    // write defaults inline. CORRUPT-3 fix: cache the defaults in
    // _viewerStateCache too — the previous code left the cache null,
    // forcing every API call to re-read from disk forever after recovery.
    const defaults = { start: null, end: null, tierFilter: ['all'] };
    try {
      atomicWriteFileSync(VIEWER_STATE_FILE, JSON.stringify(defaults));
    } catch { /* best-effort recovery */ }
    _viewerStateCache = defaults;
    return defaults;
  }
  _viewerStateCache = null;
  return null;
}

function saveViewerState(state) {
  try {
    atomicWriteFileSync(VIEWER_STATE_FILE, JSON.stringify(state));
    _viewerStateCache = state;
  } catch (e) {
    log('warn', `viewer-state.json write failed: ${e.message}`);
  }
}

// Compute the live data range across token-usage and activity-log.
// Returns { oldest, newest } in ms epoch, or null if there's no data on
// disk yet (caller hides the scrubber). The activity log already lives
// in memory; loadTokenUsage caches the parsed JSON so this is one
// in-memory linear scan per array — N is bounded by ACTIVITY_MAX_ENTRIES
// (500) and TOKEN_USAGE_MAX_ENTRIES (50_000).
// Cache the data range so the 10s `vsRefreshDataRange` poll doesn't
// re-walk 50k+ token-usage rows on every tick. Invalidation: whenever
// either the token-usage cache reference changes (atomic replacement
// in _flushTokenUsage / appendTokenUsage's prune step) OR the activity
// log length grows. The cached array IDENTITY check is the cheapest
// reliable signal — `_tokenUsageCache` is reassigned on every prune,
// not mutated in place after that. Falls back to a recompute every
// COMPUTE_DATA_RANGE_TTL_MS as a safety net for any path that mutates
// the array without reassigning the reference.
let _dataRangeCache = null;        // { oldest, newest, ref, activityLen, ts }
const COMPUTE_DATA_RANGE_TTL_MS = 5_000;
function computeDataRange() {
  const usage = loadTokenUsage();
  const now = Date.now();
  const c = _dataRangeCache;
  if (
    c &&
    c.ref === usage &&
    c.activityLen === activityLog.length &&
    (now - c.ts) < COMPUTE_DATA_RANGE_TTL_MS
  ) {
    if (c.oldest == null) return null;
    return { oldest: c.oldest, newest: c.newest };
  }
  let oldest = Infinity;
  let newest = -Infinity;
  for (let i = 0; i < usage.length; i++) {
    const ts = Number(usage[i].ts || usage[i].timestamp || 0);
    if (!Number.isFinite(ts) || ts <= 0) continue;
    if (ts < oldest) oldest = ts;
    if (ts > newest) newest = ts;
  }
  for (let i = 0; i < activityLog.length; i++) {
    const ts = Number(activityLog[i].ts || 0);
    if (!Number.isFinite(ts) || ts <= 0) continue;
    if (ts < oldest) oldest = ts;
    if (ts > newest) newest = ts;
  }
  if (!Number.isFinite(oldest) || !Number.isFinite(newest)) {
    _dataRangeCache = { oldest: null, newest: null, ref: usage, activityLen: activityLog.length, ts: now };
    return null;
  }
  _dataRangeCache = { oldest, newest, ref: usage, activityLen: activityLog.length, ts: now };
  return { oldest, newest };
}

function updatePersistedState(fingerprint, data) {
  // Preserve any prior name/ban-flag fields when called from the probe
  // path (which only carries utilization + reset). `accountState` is the
  // canonical source for `limited`/`expired`/`retryAfter`/`name`; we
  // mirror them into persistedState whenever updateAccountState runs so
  // a SIGKILL/restart can rehydrate the ban flags. Without this, every
  // restart wastes one round-trip per banned account rediscovering the
  // ban — exactly what the audit's Concern 3 flagged.
  const prior = persistedState[fingerprint] || {};
  persistedState[fingerprint] = {
    name: data.name != null ? data.name : prior.name,
    utilization5h: data.utilization5h || 0,
    utilization7d: data.utilization7d || 0,
    resetAt: data.resetAt || 0,
    resetAt7d: data.resetAt7d || 0,
    limited: data.limited != null ? data.limited : (prior.limited || false),
    expired: data.expired != null ? data.expired : (prior.expired || false),
    retryAfter: data.retryAfter != null ? data.retryAfter : (prior.retryAfter || 0),
    updatedAt: Date.now(),
  };
  savePersistedState();
}

// Rehydrate accountState ban flags on startup so a freshly-started proxy
// doesn't re-probe accounts known to be limited/expired. Skips entries
// whose 5h reset has already elapsed by wall-clock so we don't carry
// stale bans across long-offline windows.
function rehydrateAccountStateFromPersisted() {
  const accounts = loadAllAccountTokens();
  const nowSec = Math.floor(Date.now() / 1000);
  const now = Date.now();
  for (const a of accounts) {
    const fp = getFingerprintFromToken(a.token);
    const ps = persistedState[fp];
    if (!ps) continue;
    // Seed utilization regardless (cheap and useful to the UI).
    accountState.update(a.token, a.name, {
      'anthropic-ratelimit-unified-status': ps.limited ? 'limited' : 'ok',
      'anthropic-ratelimit-unified-5h-utilization': String(ps.utilization5h || 0),
      'anthropic-ratelimit-unified-7d-utilization': String(ps.utilization7d || 0),
      'anthropic-ratelimit-unified-5h-reset': String(ps.resetAt || 0),
      'anthropic-ratelimit-unified-7d-reset': String(ps.resetAt7d || 0),
    });
    // Re-mark expired/limited only if the cooldown is still in the future.
    if (ps.expired) {
      accountState.markExpired(a.token, a.name);
    }
    if (ps.limited) {
      const stillLimited =
        (ps.resetAt && ps.resetAt > nowSec) ||
        (ps.retryAfter && ps.retryAfter > now);
      if (stillLimited) {
        const retryAfterSec = ps.retryAfter && ps.retryAfter > now
          ? Math.ceil((ps.retryAfter - now) / 1000)
          : 0;
        accountState.markLimited(a.token, a.name, retryAfterSec);
      }
    }
  }
}

// Periodic clearing pass: when a 5h/7d window elapses, we want the
// `limited:true` flag dropped immediately so the dashboard reflects
// reality and the next inbound request picks the account without first
// burning a probe to "discover" the reset. Runs every 60 s — cheap.
function clearStaleLimitedFlags() {
  const nowSec = Math.floor(Date.now() / 1000);
  const now = Date.now();
  for (const [token, st] of accountState.entries()) {
    if (!st || !st.limited) continue;
    const resetPassed = st.resetAt && st.resetAt < nowSec;
    const retryPassed = st.retryAfter && st.retryAfter < now;
    // If neither cooldown is set, treat as expired-now to avoid a wedge.
    const noCooldown = !st.resetAt && !st.retryAfter;
    if (resetPassed || retryPassed || noCooldown) {
      // Re-issue a non-limited update preserving utilization + name. Any
      // subsequent real response from this account will overwrite with
      // fresh headers.
      accountState.update(token, st.name, {
        'anthropic-ratelimit-unified-status': 'ok',
        'anthropic-ratelimit-unified-5h-utilization': String(st.utilization5h || 0),
        'anthropic-ratelimit-unified-7d-utilization': String(st.utilization7d || 0),
        'anthropic-ratelimit-unified-5h-reset': String(st.resetAt || 0),
        'anthropic-ratelimit-unified-7d-reset': String(st.resetAt7d || 0),
      });
      const fp = getFingerprintFromToken(token);
      // Also clear in persisted state so a restart doesn't re-mark it.
      const ps = persistedState[fp];
      if (ps && (ps.limited || ps.retryAfter)) {
        ps.limited = false;
        ps.retryAfter = 0;
        savePersistedState();
      }
    }
  }
}
setInterval(clearStaleLimitedFlags, 60_000).unref();

// CORRUPT-1: PID-file mutex preventing two-instance startup races.
// Two dashboards racing the same state files would each call
// loadPersistedState → pruneStaleHistory → savePersistedState; a
// silent write race could clobber recent ban state. This is best-effort
// (no kernel flock — that requires a native module); the protection is
// "first instance writes its PID, subsequent instances see a live PID
// and exit cleanly with a clear message." Stale PIDs (process is
// gone) are reaped; live PIDs cause a clean exit.
(function _enforceSingletonDashboard() {
  const lockFile = join(__dirname, '.dashboard.lock');
  try {
    if (existsSync(lockFile)) {
      const livePid = parseInt(readFileSync(lockFile, 'utf8').trim(), 10);
      if (Number.isFinite(livePid) && livePid > 0) {
        // `process.kill(pid, 0)` checks existence without signaling.
        try {
          process.kill(livePid, 0);
          // Process exists. Exit cleanly. proxyServer will EADDRINUSE
          // anyway (port 3334 already bound), but failing here gives
          // a clearer diagnostic than the EADDRINUSE handler.
          console.error(`[vdm dashboard] Another dashboard is already running (PID ${livePid}). Exiting.`);
          process.exit(0);
        } catch (e) {
          if (e.code === 'ESRCH') {
            // Stale lock — previous dashboard died without cleaning up.
            try { unlinkSync(lockFile); } catch {}
          } else {
            // EPERM means the PID exists but we can't signal it (different
            // user — extremely unusual on a per-user dashboard). Treat as
            // live to be safe.
            console.error(`[vdm dashboard] Lock file points at PID ${livePid} which we can't signal — assuming alive. Exiting.`);
            process.exit(0);
          }
        }
      }
    }
    writeFileSync(lockFile, String(process.pid), { mode: 0o600 });
    // Best-effort cleanup on graceful exit. Hard kill leaves the file —
    // the next startup will reap it via the ESRCH branch above.
    process.on('exit', () => { try { unlinkSync(lockFile); } catch {} });
  } catch (e) {
    // Lock-file IO failed (read-only fs, etc.). Log and continue —
    // the EADDRINUSE handler is the second line of defense.
    console.error(`[vdm dashboard] Singleton lock setup failed (${e.message}); falling back to EADDRINUSE check.`);
  }
})();

// Load on startup
loadPersistedState();
// Migrate any plaintext accounts/<name>.json files into the keychain
// before any code path tries to read accounts. Idempotent — safe to
// call repeatedly. Files with no matching keychain entry are migrated
// then deleted; files that already have a matching entry are deleted
// without re-writing.
migrateAccountsToKeychain();
// Re-mark `limited` / `expired` accounts that we knew about before the
// last shutdown, so the first inbound request doesn't burn one wasted
// round-trip per banned account rediscovering bans we already had on disk.
rehydrateAccountStateFromPersisted();

// Phase I+ — start log rotation. Rotates events.jsonl + startup.log
// at startup, then every 6h. 7-day retention; older snapshots get
// unlinked. logForensicEvent() (defined above) writes to events.jsonl.
_startLogRotationTimer();
logForensicEvent('dashboard_start', {
  pid: process.pid,
  port: PORT,
  proxyPort: PROXY_PORT,
  nodeVersion: process.version,
  vdmVersion: PROJECT_VERSION || 'unknown',
});

// Prune history entries that predate a known window reset
(function pruneStaleHistory() {
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [fp, ps] of Object.entries(persistedState)) {
    if (ps.resetAt && ps.resetAt < nowSec) {
      const resetMs = ps.resetAt * 1000;
      const hist = utilizationHistory.getHistory(fp);
      const fresh = hist.filter(e => e.ts > resetMs);
      utilizationHistory.load(fp, fresh);
    }
    if (ps.resetAt7d && ps.resetAt7d < nowSec) {
      const resetMs = ps.resetAt7d * 1000;
      const hist = weeklyHistory.getHistory(fp);
      const fresh = hist.filter(e => e.ts > resetMs);
      weeklyHistory.load(fp, fresh);
    }
  }
  saveHistoryToDisk();
})();

// Server-side sparkline cache (cleared on window resets to force re-render)
const _sparkCache = {};

function updateAccountState(token, name, headers, fingerprint) {
  accountState.update(token, name, headers);
  // Stamp last-success timestamp + clear any prior revocation strikes
  // — these feed the all-accounts-dead detector. Every 200 from
  // Anthropic is unambiguous proof the token is alive, so we erase
  // any speculation that built up from earlier refresh failures.
  try {
    const prev = accountState.get(token) || {};
    // Reuse the state-set primitive via a follow-up update — the
    // accountState API doesn't expose direct field setters, so we
    // hide the field on the existing entry by re-running .update
    // with an extra header-shaped tag. Cleaner to mutate prev in
    // place since accountState.update already ran above and the
    // returned object reference is held in the Map.
    prev.lastSuccessAtMs = Date.now();
  } catch {}
  try { accountState.clearPermanentRevocation(token); } catch {}
  // If we were in bypass mode and just got a 200, that means SOMEONE'S
  // token works. Re-evaluate so we exit bypass on the next path through.
  if (_oauthBypassMode) {
    try { _evaluateBypassMode(); } catch {}
  }
  if (fingerprint) {
    const u5h = parseFloat(headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    const u7d = parseFloat(headers['anthropic-ratelimit-unified-7d-utilization'] || '0');
    const reset7d = Number(headers['anthropic-ratelimit-unified-7d-reset'] || 0);
    const reset5h = Number(headers['anthropic-ratelimit-unified-5h-reset'] || 0);

    // Detect window resets using actual reset timestamps from API headers.
    // Rolling windows advance the reset epoch by seconds on each request,
    // so require a large jump (>1h) to distinguish a true window reset from
    // normal rolling advancement.  Also require utilization to have dropped.
    const RESET_JUMP = 3600; // 1 hour in seconds
    const prevReset5h = persistedState[fingerprint]?.resetAt || 0;
    if (reset5h > prevReset5h + RESET_JUMP && prevReset5h > 0 && u5h < (utilizationHistory.getHistory(fingerprint).slice(-1)[0]?.u5h ?? u5h)) {
      utilizationHistory.load(fingerprint, []);
      delete _sparkCache[fingerprint + '_5h'];
    }
    const prevReset7d = persistedState[fingerprint]?.resetAt7d || 0;
    if (reset7d > prevReset7d + RESET_JUMP && prevReset7d > 0 && u7d < (weeklyHistory.getHistory(fingerprint).slice(-1)[0]?.u7d ?? u7d)) {
      weeklyHistory.load(fingerprint, []);
      delete _sparkCache[fingerprint + '_7d'];
    }

    utilizationHistory.record(fingerprint, u5h, u7d);
    weeklyHistory.record(fingerprint, u5h, u7d);
    // Mirror current ban-flag state so it survives a SIGKILL (Concern 3).
    const st = accountState.get(token) || {};
    updatePersistedState(fingerprint, {
      name,
      utilization5h: u5h,
      utilization7d: u7d,
      resetAt: reset5h,
      resetAt7d: reset7d,
      limited: !!st.limited,
      expired: !!st.expired,
      retryAfter: st.retryAfter || 0,
    });
    saveHistoryToDisk();
  }
}

function markAccountLimited(token, name, retryAfterSec = 0) {
  accountState.markLimited(token, name, retryAfterSec);
  // Mirror to persistedState so a restart doesn't drop the ban (Concern 3).
  const fp = getFingerprintFromToken(token);
  const st = accountState.get(token) || {};
  updatePersistedState(fp, {
    name,
    utilization5h: st.utilization5h || 0,
    utilization7d: st.utilization7d || 0,
    resetAt: st.resetAt || 0,
    resetAt7d: st.resetAt7d || 0,
    limited: true,
    expired: !!st.expired,
    retryAfter: st.retryAfter || 0,
  });
}

function markAccountExpired(token, name) {
  accountState.markExpired(token, name);
  const fp = getFingerprintFromToken(token);
  const st = accountState.get(token) || {};
  updatePersistedState(fp, {
    name,
    utilization5h: st.utilization5h || 0,
    utilization7d: st.utilization7d || 0,
    resetAt: st.resetAt || 0,
    resetAt7d: st.resetAt7d || 0,
    limited: !!st.limited,
    expired: true,
    retryAfter: st.retryAfter || 0,
  });
}

// ── Load saved accounts from keychain ──
// Declarations live higher up the file (next to `_lastKeychainWriteAt`)
// because rehydrateAccountStateFromPersisted is called at startup and
// references loadAllAccountTokens before this point would be reached
// otherwise — `let` is in TDZ until its declaration is executed.

function loadAllAccountTokens() {
  const now = Date.now();
  if (_accountsCache && now - _accountsCacheAt < ACCOUNTS_CACHE_TTL) return _accountsCache;
  try {
    const names = listVdmAccountKeychainEntries();
    const accounts = [];
    for (const name of names) {
      try {
        const creds = readAccountKeychain(name);
        const token = creds?.claudeAiOauth?.accessToken;
        if (!token) continue;
        let label = '';
        try { label = readFileSync(join(ACCOUNTS_DIR, `${name}.label`), 'utf8').trim(); } catch {}
        const expiresAt = creds.claudeAiOauth?.expiresAt || 0;
        // Attach per-account user preferences. The picker layer in
        // lib.mjs filters by `excludeFromAuto` when present so an
        // opted-out account never gets selected by the rotation logic.
        const prefs = getAccountPrefs(name);
        accounts.push({
          name, label, token, creds, expiresAt,
          excludeFromAuto: prefs.excludeFromAuto,
          priority: prefs.priority,
        });
      } catch { /* skip corrupt */ }
    }
    _accountsCache = accounts;
    _accountsCacheAt = now;
    return accounts;
  } catch {
    return _accountsCache || [];
  }
}

function invalidateAccountsCache() {
  _accountsCache = null;
  _accountsCacheAt = 0;
}

// ── Account picker ──

function isAccountAvailable(token, expiresAt) {
  return _isAccountAvailable(token, expiresAt, accountState);
}

function pickBestAccount(excludeTokens = new Set()) {
  return _pickBestAccount(loadAllAccountTokens(), accountState, excludeTokens);
}

// Fallback: pick any untried account even if marked limited (in case state is stale)
function pickAnyUntried(excludeTokens) {
  return _pickAnyUntried(loadAllAccountTokens(), excludeTokens);
}

// ── Build forwarding headers ──

function buildForwardHeaders(originalHeaders, token) {
  return _buildForwardHeaders(originalHeaders, token);
}

// ── Forward request with timeout ──

// Phase F audit C2 — custom https.Agent with bounded keepAlive policy.
// Node's default `https.globalAgent` has unbounded keepAlive pool and no
// idle timeout. Anthropic's load balancers terminate idle TLS connections
// after ~60-120s with TCP RST or TLS close-notify; reusing such a stale
// socket triggers `socket.on('close')` WITHOUT raising `request.on('error')`
// (Node treats the TLS close-notify as graceful since no app data was lost).
// Combined with the missing close-event reject sinks below, this used to
// produce permits that leaked forever. Bounded pool + 60s idle timeout +
// scheduling:'fifo' makes stale-socket reuse rare AND survivable.
const _upstreamAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30_000,
  maxSockets: 100,
  maxFreeSockets: 8,
  scheduling: 'fifo',
  timeout: 60_000,   // close idle sockets after 60s
});

function _forwardToAnthropicRaw(method, path, headers, body, timeout = PROXY_TIMEOUT) {
  return new Promise((resolve, reject) => {
    // Phase F audit A1 — idempotent settle wrapper. The previous version
    // wired `error` and `timeout` as the only reject sinks, missing the
    // `close` events on both the request itself AND the underlying socket.
    // When a recycled keepAlive socket was torn down by TLS close-notify or
    // OS keepalive timeout, neither error nor timeout fired — the Promise
    // hung forever, the per-account permit leaked, and the slot eventually
    // wedged at inflight=8 (audit K1). Three reject sinks now cover every
    // termination path; settle() guards against duplicate settle calls
    // (e.g. error after close).
    let settled = false;
    const settle = (fn) => (...args) => {
      if (settled) return;
      settled = true;
      fn(...args);
    };
    const _resolve = settle(resolve);
    const _reject  = settle(reject);
    const req = https.request({
      hostname: 'api.anthropic.com',
      port: 443,
      path, method, headers,
      timeout,
      agent: _upstreamAgent,
    }, _resolve);
    req.on('timeout', () => {
      req.destroy(new Error('upstream timeout'));
      _reject(new Error('upstream timeout'));
    });
    req.on('error', _reject);
    // request 'close' fires when the request is fully sent and the response
    // is fully consumed OR when the request is destroyed. If neither resolve
    // (response received) nor error fired before close, the socket was torn
    // down without a response — reject so the caller's permit can release.
    req.on('close', () => {
      _reject(new Error('upstream socket closed before response'));
    });
    // Belt-and-braces: also reject on the underlying TCP/TLS socket close.
    // For pooled keepAlive sockets recycled stale, this is the ONLY event
    // that fires when the peer drops the connection mid-write.
    //
    // CRITICAL: with keepAlive=true the socket is reused across many
    // requests; if we just `sock.on('close', ...)` and never remove the
    // listener, every reused request leaves one closure attached to the
    // socket forever. After ~11 reuses Node fires MaxListenersExceeded,
    // and each closure pins this request's _reject + the entire scope
    // (memory leak proportional to total requests * pool size). Fix:
    // remove the listener when the request itself closes (which fires
    // for both success and failure paths per Node's HTTP contract).
    req.on('socket', (sock) => {
      const onSockClose = () => _reject(new Error('upstream tcp socket closed'));
      sock.on('close', onSockClose);
      req.once('close', () => sock.removeListener('close', onSockClose));
    });
    if (body.length) req.write(body);
    req.end();
  });
}

// ── Per-account outbound RPS / concurrency limiter ──
// Anthropic's anti-abuse heuristics flag burst patterns where many
// concurrent requests fan onto a single bearer in the same Node tick.
// With 20 Claude Code instances all routing through the same proxy and
// the same active token, that is exactly the pattern we present without
// throttling. We bound:
//
//   * concurrency: at most MAX_INFLIGHT_PER_ACCOUNT outstanding upstream
//     requests per account at any moment (other CC instances queue);
//   * burst rate: at least MIN_INTERVAL_PER_ACCOUNT_MS between successive
//     dispatches against the same account (~ MAX_RPS_PER_ACCOUNT sustained).
//
// The limiter is keyed by fingerprint, NOT by token, so token rotation
// during a refresh does not double-count the same account. Falls back to
// a 'unknown' slot when no Bearer is present (the proxy's own probe /
// summary calls).
// Phase F — env-var configurable limiter knobs. See PROXY_TIMEOUT comment
// above for the rationale on the new defaults.
const MAX_INFLIGHT_PER_ACCOUNT = parseInt(process.env.CSW_MAX_INFLIGHT_PER_ACCOUNT || '8', 10);
const MIN_INTERVAL_PER_ACCOUNT_MS = parseInt(process.env.CSW_MIN_INTERVAL_PER_ACCOUNT_MS || '100', 10);
const MAX_PERMIT_WAIT_MS = parseInt(process.env.CSW_MAX_PERMIT_WAIT_MS || '300000', 10); // 5 min

const _accountSlots = new Map(); // fp -> { inflight, lastDispatchAt, waiters: [] }

function _slot(fp) {
  let s = _accountSlots.get(fp);
  if (!s) {
    s = { inflight: 0, lastDispatchAt: 0, waiters: [] };
    _accountSlots.set(fp, s);
  }
  return s;
}

function _tokenFromHeaders(headers) {
  const a = headers && (headers.authorization || headers.Authorization || headers['authorization']);
  if (typeof a !== 'string') return '';
  const m = a.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}

async function acquireAccountPermit(fp) {
  const s = _slot(fp);
  if (s.inflight >= MAX_INFLIGHT_PER_ACCOUNT) {
    // Forensic event — captures inflight escalation: when did queueing
    // start, how many were in flight, how many waiters were ahead.
    // Useful for "why did my prompt sit for 5 minutes" investigations.
    try {
      logForensicEvent('inflight_escalation', {
        account_fp: fp,
        inflight: s.inflight,
        waiters: s.waiters.length,
        cap: MAX_INFLIGHT_PER_ACCOUNT,
        max_wait_ms: MAX_PERMIT_WAIT_MS,
      });
    } catch {}
    // Wait for a permit. Bounded so a wedged limiter cannot pin a request
    // forever — instead the await rejects and the caller surfaces a 504.
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = s.waiters.indexOf(entry);
        if (idx !== -1) s.waiters.splice(idx, 1);
        reject(new Error('account_permit_timeout'));
      }, MAX_PERMIT_WAIT_MS);
      const entry = () => { clearTimeout(timer); resolve(); };
      s.waiters.push(entry);
    });
  }
  s.inflight++;
  // Spacing gate: prevent burst even if concurrency budget allows it.
  const since = Date.now() - s.lastDispatchAt;
  if (since < MIN_INTERVAL_PER_ACCOUNT_MS) {
    await new Promise(r => setTimeout(r, MIN_INTERVAL_PER_ACCOUNT_MS - since));
  }
  s.lastDispatchAt = Date.now();
}

function releaseAccountPermit(fp) {
  const s = _slot(fp);
  s.inflight = Math.max(0, s.inflight - 1);
  const next = s.waiters.shift();
  if (next) next();
}

// Wraps the raw forward in the per-account limiter. Backward-compatible
// signature — call sites are unchanged.
//
// Phase F bug-fix: the permit is held until the response stream is fully
// consumed (or aborted/errored), NOT released at headers. This is the
// load-bearing change for streaming responses (Anthropic's default for all
// Claude Code traffic): _forwardToAnthropicRaw resolves with the response
// when HEADERS arrive — which for SSE is milliseconds — but the actual
// body streams for seconds-to-minutes. The previous implementation released
// the permit at headers, so the documented MAX_INFLIGHT_PER_ACCOUNT cap
// was silently bypassed for streams. Result: with N>4 concurrent CC
// instances on one bearer, all N streams ran concurrently against
// upstream, triggering Anthropic's anti-abuse heuristics (false 429s,
// connection drops, "rate limited" reports). Now permits actually cap
// concurrent streams.
async function forwardToAnthropic(method, path, headers, body, timeout = PROXY_TIMEOUT) {
  const tok = _tokenFromHeaders(headers);
  const fp = tok ? getFingerprintFromToken(tok) : 'unknown';
  await acquireAccountPermit(fp);
  let released = false;
  // Phase F audit follow-up (F3 — TDZ hardening) — declare `watchdog` BEFORE
  // `release` so the closure captures an initialized binding (null) rather
  // than the Temporal Dead Zone. Without this hoist, any future refactor that
  // calls `release()` before the `setTimeout(...)` line below would throw
  // ReferenceError instead of silently no-op'ing on the `if (watchdog)` guard.
  let watchdog = null;
  const release = () => {
    if (released) return;
    released = true;
    if (watchdog) clearTimeout(watchdog);
    releaseAccountPermit(fp);
  };
  // Phase F audit A1 — defensive watchdog. Even with the new close-event
  // reject sinks in _forwardToAnthropicRaw and the end/error/close listeners
  // wired below, an exotic stream state (mid-flight server bug, malformed
  // chunked encoding, kernel TCP weirdness) could still in principle leave
  // the permit pinned. The watchdog fires PROXY_TIMEOUT + 5s after permit
  // acquisition and force-releases. This is a backstop, not the primary
  // mechanism — if it ever fires, that's a bug worth investigating.
  watchdog = setTimeout(() => {
    if (!released) {
      log('warn', `forwardToAnthropic watchdog: force-releasing permit for fp=${fp.slice(0, 8)} after ${(timeout + 5000) / 1000}s`);
      release();
    }
  }, timeout + 5000);
  // Don't keep the process alive solely for this timer (e.g. on shutdown).
  if (typeof watchdog.unref === 'function') watchdog.unref();
  try {
    const res = await _forwardToAnthropicRaw(method, path, headers, body, timeout);
    // Hold the permit until the response stream finishes. The first of
    // these events to fire wins; release() is idempotent so duplicate
    // events (rare but possible during destroy) are harmless.
    res.once('end', release);
    res.once('error', release);
    res.once('close', release);
    res.once('aborted', release);  // Phase F audit A4 — pre-Node-13 abort path
    return res;
  } catch (e) {
    // _forwardToAnthropicRaw rejected before headers — release immediately
    // (no response stream exists to hook auto-release onto).
    release();
    throw e;
  }
}

function getAccountSlotStats() {
  const out = {};
  for (const [fp, s] of _accountSlots) {
    out[fp] = { inflight: s.inflight, queued: s.waiters.length };
  }
  return out;
}

// Phase F audit K1 — periodic GC sweep of `_accountSlots`. Runs every 5
// minutes; deletes entries that have been idle for >1 hour. Catches
// retired fingerprints that migrateAccountState couldn't drop synchronously
// (because they had in-flight requests at the moment of migration). Keeps
// the Map size bounded over long uptimes. Pure logic lives in lib.mjs's
// gcAccountSlots() for unit-testability; this is just the wiring.
const _accountSlotsGcTimer = setInterval(() => {
  try {
    const purged = gcAccountSlots(_accountSlots);
    if (purged > 0) log('debug', `GC: purged ${purged} idle account slot(s)`);
  } catch (e) {
    log('warn', `_accountSlots GC sweep error: ${e.message}`);
  }
}, 5 * 60_000);
if (typeof _accountSlotsGcTimer.unref === 'function') _accountSlotsGcTimer.unref();

// Drain a response and return the body (for error responses).
// Destroys the stream on timeout to prevent partial-data races.
function drainResponse(res) {
  return new Promise(r => {
    let done = false;
    const chunks = [];
    const finish = () => { if (!done) { done = true; r(Buffer.concat(chunks)); } };
    res.on('data', c => chunks.push(c));
    res.on('end', finish);
    res.on('error', finish);
    // Safety: if stream stalls, destroy it and resolve with whatever we have
    setTimeout(() => { res.destroy(); finish(); }, 5000);
  });
}

// ── Empty-body 400 detection ──
// The Anthropic API returns "400 with no body" when OAuth tokens are
// null/expired.  Legitimate 400s always include a JSON error body.
function isEmptyBody400(statusCode, bodyBuffer) {
  return statusCode === 400 && (!bodyBuffer || bodyBuffer.length === 0);
}

// ── Smart passthrough ──
// Shared logic for proxy-disabled and circuit-breaker passthrough modes.
// 1. Forward to Anthropic with provided auth
// 2. If 400-empty-body → read fresh token from keychain (bypass cache), retry
// 3. If still 400-empty-body → return 401 to trigger Claude Code re-auth
// 4. Otherwise → forward response as-is
async function _smartPassthrough(clientReq, clientRes, body, fwd, label) {
  const res = await forwardToAnthropic(clientReq.method, clientReq.url, fwd, body, PROXY_TIMEOUT);
  // Drain body to inspect for empty-body 400
  const resBuf = await drainResponse(res);
  if (isEmptyBody400(res.statusCode, resBuf)) {
    log('fallback', `${label}: 400-empty-body detected — trying fresh keychain token`);
    // Bypass cache: read directly from keychain
    invalidateTokenCache();
    const freshCreds = readKeychain();
    const freshToken = freshCreds?.claudeAiOauth?.accessToken;
    if (freshToken && freshToken !== fwd['authorization']?.replace(/^Bearer\s+/i, '')) {
      const retryFwd = { ...fwd, authorization: `Bearer ${freshToken}` };
      retryFwd['content-length'] = String(body.length);
      try {
        const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, retryFwd, body, 15_000);
        const retryBuf = await drainResponse(retryRes);
        if (!isEmptyBody400(retryRes.statusCode, retryBuf)) {
          // Fresh token worked — forward the response
          if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
          const hdrs = { ...retryRes.headers };
          if (retryBuf.length) hdrs['content-length'] = String(retryBuf.length);
          clientRes.writeHead(retryRes.statusCode, hdrs);
          clientRes.end(retryBuf);
          return;
        }
        log('fallback', `${label}: fresh token also got 400-empty-body`);
      } catch (e) {
        log('error', `${label}: fresh-token retry failed: ${e.message}`);
      }
    }
    // All tokens stale → convert to 401 so Claude Code re-authenticates
    log('fallback', `${label}: converting 400-empty-body → 401 to trigger re-auth`);
    if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
    clientRes.writeHead(401, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({
      type: 'error',
      error: { type: 'authentication_error', message: 'Token expired (proxy: empty-body 400 converted to 401)' },
    }));
    return;
  }
  // Normal response (non-empty or non-400) — forward as-is
  if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
  const hdrs = { ...res.headers };
  if (resBuf.length) hdrs['content-length'] = String(resBuf.length);
  clientRes.writeHead(res.statusCode, hdrs);
  clientRes.end(resBuf);
}

// ── Passthrough fallback ──
// When all proxy recovery strategies fail, forward the request with the
// ORIGINAL client authorization header.  This lets Claude Code reach the
// real API and trigger its own re-auth flow instead of the proxy returning
// an opaque error that makes sessions permanently stale.

async function _passthroughFallback(clientReq, clientRes, body, reason) {
  // Guard: client already disconnected — nothing to deliver
  if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) {
    log('fallback', `Passthrough skipped (${reason}) — client already disconnected or headers sent`);
    return false;
  }
  try {
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    log('fallback', `Proxy recovery exhausted (${reason}) — passthrough with original auth`);
    // Short timeout: we've already spent time on recovery, don't stall further
    const res = await forwardToAnthropic(clientReq.method, clientReq.url, fwd, body, 15_000);
    // Drain body to check for empty-body 400
    const resBuf = await drainResponse(res);
    if (isEmptyBody400(res.statusCode, resBuf)) {
      log('fallback', `Passthrough (${reason}): 400-empty-body — trying fresh keychain token`);
      // Read the keychain INSIDE withSwitchLock so we never observe the
      // 50–200 ms gap between writeKeychain's delete-and-add (now atomic
      // via update -U after Phase 1A, but the lock is still the right
      // serialization point against /api/switch and the proxy's own
      // proactive rotations). The previous unlocked read was the audit's
      // newly-discovered N-1 fallback-keychain-race issue.
      let freshCreds = null;
      await withSwitchLock(() => {
        invalidateTokenCache();
        freshCreds = readKeychain();
      });
      const freshToken = freshCreds?.claudeAiOauth?.accessToken;
      if (freshToken && freshToken !== fwd['authorization']?.replace(/^Bearer\s+/i, '')) {
        const retryFwd = { ...fwd, authorization: `Bearer ${freshToken}` };
        retryFwd['content-length'] = String(body.length);
        try {
          const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, retryFwd, body, 15_000);
          const retryBuf = await drainResponse(retryRes);
          if (!isEmptyBody400(retryRes.statusCode, retryBuf)) {
            if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return false;
            const hdrs = { ...retryRes.headers };
            if (retryBuf.length) hdrs['content-length'] = String(retryBuf.length);
            clientRes.writeHead(retryRes.statusCode, hdrs);
            clientRes.end(retryBuf);
            _consecutiveExhausted = 0;
            if (retryRes.statusCode < 400) _consecutive400s = 0;
            return true;
          }
        } catch (e) {
          log('error', `Passthrough fresh-token retry failed (${reason}): ${e.message}`);
        }
      }
      // Convert to 401 so Claude Code re-authenticates
      log('fallback', `Passthrough (${reason}): converting 400-empty-body → 401 to trigger re-auth`);
      if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return false;
      clientRes.writeHead(401, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: { type: 'authentication_error', message: 'Token expired (proxy: empty-body 400 converted to 401)' },
      }));
      _consecutiveExhausted = 0;
      return true; // we delivered a response (401)
    }
    // Forward whatever the upstream returns — even errors.
    // A standard 401 from the real API lets Claude Code re-authenticate,
    // which is far better than a proxy 502 that kills the session.
    if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) {
      return false;
    }
    const hdrs = { ...res.headers };
    if (resBuf.length) hdrs['content-length'] = String(resBuf.length);
    clientRes.writeHead(res.statusCode, hdrs);
    clientRes.end(resBuf);
    // Passthrough delivered a response — reset failure counters
    _consecutiveExhausted = 0;
    if (res.statusCode < 400) _consecutive400s = 0;
    return true;
  } catch (e) {
    log('error', `Passthrough fallback failed (${reason}): ${e.message}`);
    _consecutiveExhausted++;
    if (_consecutiveExhausted >= CIRCUIT_OPEN_THRESHOLD) {
      _openCircuit(`${_consecutiveExhausted} consecutive failures`);
    }
    return false;
  }
}

// ── Mutex for auto-switch (prevents interleaved keychain writes) ──

let _switchLock = Promise.resolve();

function withSwitchLock(fn) {
  const prev = _switchLock;
  let release;
  _switchLock = new Promise(r => { release = r; });
  return prev.then(fn).finally(release);
}

// ─────────────────────────────────────────────────
// OAuth Token Refresh
// ─────────────────────────────────────────────────

// OAuth token endpoint. The historical default (`platform.claude.com/v1/oauth/token`)
// is the OLD endpoint that Anthropic retired during the platform.claude.com →
// console.anthropic.com migration; refreshes against it now silently 404, so a
// dashboard built against the old default would log "refresh failed" forever and
// never recover. The correct endpoint as of Claude Code 2.x is
// `console.anthropic.com/v1/oauth/token` (verified against the leaked Claude
// Code OAuth flow gist and current Claude Code authentication docs). Tests
// override via `OAUTH_TOKEN_URL` env var pointing at an in-process mock.
const OAUTH_TOKEN_URL = process.env.OAUTH_TOKEN_URL || 'https://console.anthropic.com/v1/oauth/token';
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const OAUTH_DEFAULT_SCOPES = 'user:profile user:inference user:sessions:claude_code user:mcp_servers';
const REFRESH_BUFFER_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
const REFRESH_MAX_RETRIES = 3;
const REFRESH_BACKOFF_BASE = 1000; // 1s, 2s, 4s

const refreshLock = createPerAccountLock();
// Track refresh failures per account: name → { error, retriable, ts }
const refreshFailures = new Map();

// Phase 6: cross-account refresh storm cap.
//
// `refreshLock` (per-account mutex) dedupes concurrent refreshes for the
// SAME account — two parallel requests can't double-spend the same
// refresh token. But it does NOT cap refreshes ACROSS accounts: the
// 400-empty-body bulk-recovery path runs Promise.allSettled across N
// accounts, which can fire 10+ parallel POSTs to platform.claude.com from
// a single IP. That's a textbook way to get the OAuth endpoint
// rate-limited from the upstream side.
//
// `_refreshSem` caps *concurrent* OAuth POSTs at 3 regardless of which
// account each one targets. Pending acquirers queue FIFO; throughput is
// unaffected for low-N refreshes.
const _refreshSem = createSemaphore(3);

/**
 * Persist account credentials. Backed by the macOS keychain
 * (`security add-generic-password -U`), which is itself atomic — there is
 * no half-written-blob window equivalent to a partial file rename.
 */
async function atomicWriteAccountFile(name, creds) {
  writeAccountKeychain(name, creds);
}

/**
 * Call the OAuth refresh endpoint. Returns parsed result via parseRefreshResponse.
 */
function callRefreshEndpoint(refreshToken, scopes) {
  return new Promise((resolve) => {
    const scope = Array.isArray(scopes)
      ? scopes.join(' ')
      : (typeof scopes === 'string' ? scopes.replace(/,/g, ' ') : OAUTH_DEFAULT_SCOPES);
    const body = buildRefreshRequestBody(refreshToken, OAUTH_CLIENT_ID, scope);
    const parsed = new URL(OAUTH_TOKEN_URL);
    const isHttp = parsed.protocol === 'http:';
    const mod = isHttp ? http : https;
    const port = parsed.port || (isHttp ? 80 : 443);

    const req = mod.request({
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        resolve(parseRefreshResponse(res.statusCode, data));
      });
      res.on('error', (err) => resolve({ ok: false, error: `response stream: ${err.message}`, retriable: true }));
    });
    req.on('error', (err) => resolve({ ok: false, error: err.message, retriable: true }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout', retriable: true }); });
    req.write(body);
    req.end();
  });
}

/**
 * Migrate all state from old fingerprint to new fingerprint after token refresh.
 */
function migrateAccountState(oldToken, newToken, oldFp, newFp, name) {
  // Migrate in-memory account state
  const oldState = accountState.get(oldToken);
  if (oldState) {
    accountState.update(newToken, name, {
      'anthropic-ratelimit-unified-status': oldState.limited ? 'limited' : 'ok',
      'anthropic-ratelimit-unified-5h-utilization': String(oldState.utilization5h || 0),
      'anthropic-ratelimit-unified-7d-utilization': String(oldState.utilization7d || 0),
      'anthropic-ratelimit-unified-5h-reset': String(oldState.resetAt || 0),
      'anthropic-ratelimit-unified-7d-reset': String(oldState.resetAt7d || 0),
    });
    // BUG FIX: accountState.update(...) always sets `expired: false` because
    // there is no header-derived expiry signal — the response above only
    // covers `limited`. Without the explicit markExpired below, a token
    // that was 401-expired BEFORE refresh would have its `expired` flag
    // silently dropped during migration. The picker would then re-select
    // the (still-expired) token, get another 401, and loop until the
    // circuit breaker opens. Mirror the `limited` path for `expired`.
    if (oldState.expired) accountState.markExpired(newToken, name);
    accountState.remove(oldToken);
  }

  // Migrate utilization history (5h + weekly)
  const hist5h = utilizationHistory.getHistory(oldFp);
  if (hist5h.length) {
    utilizationHistory.load(newFp, hist5h);
    utilizationHistory.load(oldFp, []); // clear old
  }
  const histWeekly = weeklyHistory.getHistory(oldFp);
  if (histWeekly.length) {
    weeklyHistory.load(newFp, histWeekly);
    weeklyHistory.load(oldFp, []); // clear old
  }

  // Migrate persisted state
  if (persistedState[oldFp]) {
    persistedState[newFp] = { ...persistedState[oldFp], updatedAt: Date.now() };
    delete persistedState[oldFp];
    savePersistedState();
  }

  // Migrate email cache
  const cachedEmail = emailCache.get(oldFp);
  if (cachedEmail) {
    emailCache.set(newFp, cachedEmail);
    emailCache.delete(oldFp);
  }

  // Migrate rate limit cache
  const cachedRate = rateLimitCache.get(oldFp);
  if (cachedRate) {
    rateLimitCache.set(newFp, cachedRate);
    rateLimitCache.delete(oldFp);
  }

  // Phase F audit K1 — explicitly drop the old fingerprint's per-account
  // limiter slot. Without this, every refresh creates a new fp keyed slot
  // and the old slot leaks forever. Combined with leaked permits (audit A1),
  // retired fingerprints accumulated with inflight>0 forever, eventually
  // wedging the limiter and producing the "works for hours then breaks"
  // ConnectionRefused symptom. Only safe to delete when inflight is 0 —
  // if a refresh races with an in-flight request on the OLD token, drop
  // the slot only when it drains (deferred delete via the GC sweep below).
  const oldSlot = _accountSlots.get(oldFp);
  if (oldSlot && oldSlot.inflight === 0 && oldSlot.waiters.length === 0) {
    _accountSlots.delete(oldFp);
  }
}

/**
 * Main refresh orchestrator for a single account.
 * Wrapped in per-account lock to prevent concurrent refreshes.
 */
async function refreshAccountToken(accountName, { force = false } = {}) {
  return refreshLock.withLock(accountName, async () => {
    // Phase 6: cap concurrent OAuth POSTs across all accounts at 3 to
    // avoid IP-level rate limiting on platform.claude.com. The
    // per-account `refreshLock` (above) only dedupes refreshes for the
    // SAME account; the 400-recovery bulk path can run
    // Promise.allSettled across N accounts and fire N parallel POSTs
    // from a single IP without this semaphore. The wrap is *inside* the
    // per-account lock so two concurrent calls for the same account
    // serialise on the lock first, and only the winner spends a
    // semaphore slot.
    return _refreshSem.run(async () => {
    // 1. Re-read credentials from the keychain (may have been refreshed by
    // a concurrent request that already updated the keychain entry under
    // refreshLock. The keychain is the source of truth — there is no
    // accounts/<name>.json file to consult anymore.)
    const rawCreds = readAccountKeychain(accountName);
    if (!rawCreds) {
      log('refresh', `Failed to read keychain entry for ${accountName}`);
      return { ok: false, error: `Cannot read keychain entry for ${accountName}` };
    }

    const oauth = rawCreds.claudeAiOauth;
    if (!oauth) {
      return { ok: false, error: 'No claudeAiOauth in credentials' };
    }

    let accountLabel = accountName;
    try { accountLabel = readFileSync(join(ACCOUNTS_DIR, `${accountName}.label`), 'utf8').trim() || accountName; } catch {}

    // 2. Check if still needs refresh (double-check after lock)
    //    Skip this check when force=true (e.g. 401/400 from API means token is invalid
    //    regardless of what the stored expiresAt says)
    if (!force && !shouldRefreshToken(oauth.expiresAt, REFRESH_BUFFER_MS)) {
      log('refresh', `${accountName}: token still valid, skipping refresh`);
      return { ok: true, skipped: true };
    }

    // 3. Verify refresh token exists
    if (!oauth.refreshToken) {
      log('refresh', `${accountName}: no refresh token available`);
      return { ok: false, error: 'No refresh token' };
    }

    const oldToken = oauth.accessToken;
    const oldFp = getFingerprintFromToken(oldToken);

    // Bracket the ENTIRE refresh window — including the OAuth POST —
    // with `_refreshesInProgress`. Previously the increment happened
    // AFTER callRefreshEndpoint returned, so a concurrent
    // autoDiscoverAccount firing DURING the OAuth call would see the
    // OLD keychain creds, match no saved account by fingerprint, and
    // create a bogus auto-N entry that gets overwritten the moment
    // the refresh completes. Moving the increment up closes the race.
    // Decrement is guaranteed via the outer try/finally.
    _refreshesInProgress++;
    try {
      // 4. Call OAuth endpoint with retry + exponential backoff
      let result;
      for (let attempt = 0; attempt < REFRESH_MAX_RETRIES; attempt++) {
        result = await callRefreshEndpoint(oauth.refreshToken, oauth.scopes);
        if (result.ok) break;
        if (!result.retriable) break;
        // Exponential backoff: 1s, 2s, 4s
        const delay = REFRESH_BACKOFF_BASE * Math.pow(2, attempt);
        log('refresh', `${accountName}: attempt ${attempt + 1} failed (${result.error}), retrying in ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      }

      if (!result.ok) {
        log('refresh', `${accountName}: refresh failed after retries: ${result.error}`);
        refreshFailures.set(accountName, { error: result.error, retriable: !!result.retriable, ts: Date.now(), fp: oldFp });
        logActivity('refresh-failed', { account: accountLabel, error: result.error, retriable: !!result.retriable });
        // Bypass-mode trigger: classify the error. If it's a revocation
        // (invalid_grant / unauthorized_client / invalid_client /
        // access_denied), record one strike against this account. After
        // 3 strikes spread over 1 hour, isPermanentlyRevoked() flips
        // permanentlyRevoked=true. Then evaluate whether ALL accounts
        // are now terminally dead → enter bypass mode.
        if (!result.retriable && isOAuthRevocationError(result.error)) {
          try {
            accountState.recordPermanentRefreshFailure(oldToken, accountName);
            // Calling isPermanentlyRevoked has the side effect of
            // flipping the flag if the threshold is crossed.
            accountState.isPermanentlyRevoked(oldToken);
          } catch (e) {
            log('warn', `recordPermanentRefreshFailure failed: ${e.message}`);
          }
          try { _evaluateBypassMode(); } catch (e) {
            log('warn', `_evaluateBypassMode failed: ${e.message}`);
          }
        }
        // CC-style "post-refresh truly expired" hard-revocation signal
        // (per github.com/chauncygu/.../bridge/initReplBridge.ts:203-240
        // in CC v2.1.89): if the refresh chain completed with !ok AND
        // the token's expiresAt is STILL in the past, no future refresh
        // attempt will succeed without user re-auth. Force-mark
        // immediately rather than waiting for 3 strikes over 1 hour.
        // Catches refresh failures with non-standard error formats that
        // isOAuthRevocationError doesn't recognize.
        if (isPostRefreshTrulyExpired(oauth.expiresAt)) {
          try {
            accountState.forceMarkPermanentlyRevoked(
              oldToken, accountName, 'post-refresh-truly-expired',
            );
            log('warn', `${accountName}: post-refresh truly expired (expiresAt ${new Date(oauth.expiresAt).toISOString()}) — force-marked permanently revoked`);
            logActivity('account-post-refresh-expired', { account: accountLabel });
          } catch (e) {
            log('warn', `forceMarkPermanentlyRevoked failed: ${e.message}`);
          }
          try { _evaluateBypassMode(); } catch {}
        }
        if (!result.retriable) {
          notify(
            'Token Refresh Failed',
            `${accountLabel}: ${result.error}. Re-login required.`,
            'refreshFailed'
          );
        }
        return { ok: false, error: result.error };
      }
      // Successful refresh — clear any prior revocation strikes against
      // the OLD token (the new token gets its own clean state via the
      // migrateAccountState call further down). If we were in bypass
      // mode and any account just refreshed successfully, exit bypass.
      try { accountState.clearPermanentRevocation(oldToken); } catch {}
      try { _evaluateBypassMode(); } catch {}

      // 5. Build new credentials and write to the keychain
      const newExpiresAt = result.expiresIn
        ? computeExpiresAt(result.expiresIn)
        : Date.now() + 8 * 60 * 60 * 1000; // fallback: 8 hours
      const newCreds = buildUpdatedCreds(rawCreds, result.accessToken, result.refreshToken, newExpiresAt);

      try {
        await atomicWriteAccountFile(accountName, newCreds);
      } catch (e) {
        log('refresh', `CRITICAL: ${accountName}: refresh succeeded but keychain write failed: ${e.message}`);
        return { ok: false, error: `Keychain write failed: ${e.message}` };
      }

      const newFp = getFingerprintFromToken(result.accessToken);
      log('refresh', `${accountName}: token refreshed successfully (fp ${oldFp} → ${newFp}, expires ${new Date(newExpiresAt).toISOString()})`);

      // 6. Migrate state from old fingerprint to new fingerprint
      migrateAccountState(oldToken, result.accessToken, oldFp, newFp, accountName);

      // 7. Update keychain if this is the active account
      const activeToken = getActiveToken();
      if (activeToken === oldToken) {
        try {
          await withSwitchLock(() => {
            writeKeychain(newCreds);
            invalidateTokenCache();
          });
          log('refresh', `${accountName}: updated keychain (was active account)`);
        } catch (e) {
          log('warn', `${accountName}: keychain update failed after refresh: ${e.message}`);
        }
      }

      // 8. Invalidate caches
      invalidateAccountsCache();
      refreshFailures.delete(accountName);
      logActivity('token-refreshed', { account: accountLabel });

      return { ok: true, accessToken: result.accessToken, expiresAt: newExpiresAt };
    } finally {
      // The disk-write + keychain-write window is closed; allow
      // autoDiscoverAccount to run again. Math.max guard keeps the
      // counter from going negative if some prior bug double-decremented.
      _refreshesInProgress = Math.max(0, _refreshesInProgress - 1);
    }
    });
  });
}

// ── Background refresh timer ──

const REFRESH_FAILURE_TTL = 2 * 60 * 60 * 1000; // 2 hours

// Periodic cache prune. Walks the time-keyed Maps and drops entries
// whose TTL has elapsed. Each cache also has a hard size cap enforced
// at insert time (_capMapInsert), so this is a SAFETY NET — without
// it, low-traffic dashboards would accumulate stale entries forever
// because nothing else evicts them. Runs every 5 minutes via an
// unrefed timer (so it doesn't keep the process alive on its own).
function _pruneCachesPeriodic() {
  try {
    const now = Date.now();
    let dropped = 0;
    dropped += _pruneMapByTtl(emailCache,     v => v && v.fetchedAt, EMAIL_CACHE_TTL,      now);
    dropped += _pruneMapByTtl(rateLimitCache, v => v && v.fetchedAt, RATE_LIMIT_CACHE_TTL, now);
    dropped += _pruneMapByTtl(_eventDedupMap, v => v,                EVENT_DEDUP_WINDOW,   now);
    // refreshFailures uses .ts. Drop entries past 2× the failure TTL
    // so a long-stale entry doesn't pin a fingerprint forever.
    dropped += _pruneMapByTtl(refreshFailures, v => v && v.ts,        REFRESH_FAILURE_TTL * 2, now);
    if (dropped > 0) log('cache', `pruned ${dropped} stale cache entries`);
  } catch (e) {
    log('warn', `cache prune failed: ${e && e.message}`);
  }
}
const _CACHE_PRUNE_INTERVAL = 5 * 60 * 1000;
const _cachePruneTimer = setInterval(_pruneCachesPeriodic, _CACHE_PRUNE_INTERVAL);
_cachePruneTimer.unref?.();

// Safeguard B — periodic poll of the serialization queue depth. 5-second
// interval is short enough to detect a sustained backup well within the
// 60-second sustainMs default, long enough to avoid measurable CPU
// overhead. Runs even when serialize is OFF so a user toggling it on
// during heavy load gets the alert at the next sample.
const _QUEUE_DEPTH_POLL_INTERVAL = 5_000;
const _queueDepthPollTimer = setInterval(() => {
  try { _checkQueueDepthAlert(); } catch (e) {
    // Don't let a transient log/save error kill the timer.
    try { log('warn', `_checkQueueDepthAlert poll failed: ${e.message}`); } catch {}
  }
}, _QUEUE_DEPTH_POLL_INTERVAL);
_queueDepthPollTimer.unref?.();

async function refreshSweep(label = 'refresh-bg') {
  const accounts = loadAllAccountTokens();
  // Decide which accounts are due for refresh BEFORE dispatching, so we
  // can fan out via Promise.allSettled. The serial `for...await` form
  // (pre-fix) made wake-from-sleep painful: with N expired tokens and
  // ~17 s worst-case per OAuth refresh (1 connect + 3 retries × ~5 s
  // each), N=5 → 85 s end-to-end before ANY healthy account is usable.
  // The OAuth client itself is bounded by `_refreshSem` (cap 3) so this
  // does NOT issue more than 3 concurrent refreshes against the
  // upstream — it just stops blocking accounts 2..N behind account 1.
  const dueAccounts = [];
  for (const acct of accounts) {
    if (!shouldRefreshToken(acct.expiresAt, REFRESH_BUFFER_MS)) continue;
    const prior = refreshFailures.get(acct.name);
    if (prior && !prior.retriable) {
      if (Date.now() - prior.ts < REFRESH_FAILURE_TTL) continue;
      // TTL expired — retry
      log(label, `${acct.label || acct.name}: retrying after non-retriable failure (${Math.round((Date.now() - prior.ts) / 60000)}m ago)`);
    }
    log(label, `${acct.label || acct.name}: token near expiry, refreshing...`);
    dueAccounts.push(acct);
  }
  await Promise.allSettled(dueAccounts.map(async (acct) => {
    try {
      await refreshAccountToken(acct.name);
    } catch (e) {
      log(label, `${acct.label || acct.name}: background refresh error: ${e.message}`);
      const failFp = getFingerprintFromToken(acct.token);
      refreshFailures.set(acct.name, { error: e.message, retriable: true, ts: Date.now(), fp: failFp });
      logActivity('refresh-failed', { account: acct.label || acct.name, error: e.message, retriable: true });
    }
  }));
}

// Run immediately on startup (handles expired tokens after sleep/restart)
refreshSweep('refresh-startup').catch((e) => {
  log('warn', `Startup refreshSweep failed: ${e && e.message}`);
});

// Detect system wake: if the timer fires much later than expected, the
// system slept. The async callback used to swallow rejections silently
// because Node's setInterval doesn't await the body — a thrown error
// inside refreshSweep would be lost. Wrap in try/catch + explicit log.
let lastRefreshTick = Date.now();
const _refreshSweepTimer = setInterval(async () => {
  try {
    const now = Date.now();
    const drift = now - lastRefreshTick - REFRESH_CHECK_INTERVAL;
    lastRefreshTick = now;
    if (drift > 30_000) {
      log('refresh-wake', `System wake detected (drift ${Math.round(drift / 1000)}s), refreshing all tokens...`);
      // Clear non-retriable failures so all accounts get a fresh chance after sleep
      for (const [name, entry] of refreshFailures) {
        if (!entry.retriable) refreshFailures.delete(name);
      }
    }
    await refreshSweep();
  } catch (e) {
    log('warn', `Periodic refreshSweep failed: ${e && e.message}`);
  }
}, REFRESH_CHECK_INTERVAL);
// M11 fix — unref so this timer doesn't block clean process exit. The
// shutdown handler still has its own debounced flush + 5s drain window.
_refreshSweepTimer.unref?.();

// ── Startup: clean orphaned .json.tmp files left over from the
// pre-keychain era. Account credentials now live in the keychain via
// `security add-generic-password -U`, which is itself atomic, so the
// .tmp recovery path that used to recover from interrupted file
// rename writes is no longer reachable. Any .tmp file we still find
// is a relic of an upgrade that crashed mid-migration — safe to drop.
(function cleanupTmpFiles() {
  try {
    const files = readdirSync(ACCOUNTS_DIR);
    for (const file of files) {
      if (!file.endsWith('.json.tmp')) continue;
      const tmpPath = join(ACCOUNTS_DIR, file);
      try { unlinkSync(tmpPath); log('startup', `Cleaned orphaned tmp file: ${file}`); } catch {}
    }
  } catch {}
})();

// ─────────────────────────────────────────────────
// Request Serialization Queue
// ─────────────────────────────────────────────────
//
// Backed by createSerializationQueue() in lib.mjs. The previous
// in-file implementation had an `inflight === 0` early-return bypass
// that broke strict serialization under sustained load — see lib.mjs
// for the full bug analysis. The factory removes the bypass and adds
// a configurable max-concurrent cap (settings.serializeMaxConcurrent,
// default 1 = strict serialize-everything).

const _serializationQueue = createSerializationQueue({
  getEnabled: () => !!settings.serializeRequests,
  getDelayMs: () => settings.serializeDelayMs | 0,
  getMaxConcurrent: () => Math.max(1, settings.serializeMaxConcurrent | 0 || 1),
  // Phase F audit G1 — was hard-coded 120s (lib.mjs default), smaller than
  // REQUEST_DEADLINE_MS (600s). Result: every queued request rejected with
  // queue_timeout → 503 before the deadline guard could ever fire. Now tunable
  // via CSW_QUEUE_TIMEOUT_MS, default REQUEST_DEADLINE_MS + 60s buffer.
  queueTimeoutMs: QUEUE_TIMEOUT_MS,
});

function getQueueStats() {
  const s = _serializationQueue.getStats();
  // Only report maxConcurrent when serialization is actually enabled.
  // When disabled, every request bypasses the cap, so reporting one
  // would be misleading — the inflight count is uncapped in that mode.
  const cap = settings.serializeRequests
    ? Math.max(1, settings.serializeMaxConcurrent | 0 || 1)
    : null;
  return {
    inflight: s.inflight,
    queued: s.queued,
    maxConcurrent: cap,
    accountSlots: getAccountSlotStats(),
  };
}

// Progressive drain — used by every "serialize is turning OFF" path
// (user toggle, Breakers A/C auto-disable, Safeguard D auto-revert)
// so a backlog of pending payloads doesn't hit Anthropic in one
// microsecond and trigger an immediate rate-limit cascade. The
// dispatch cadence defaults to whatever serializeDelayMs was tuned
// to (so we never drain faster than the user's chosen rate); falls
// back to 250ms = 4 RPS, which is below tier-1's ~50 RPM sustained
// limit and therefore safe for any account tier.
//
// Returns the controller from createSerializationQueue.drainProgressively
// so the caller can cancel mid-drain (e.g. user re-enables serialize
// while we're still draining the previous backlog).
let _activeProgressiveDrain = null;
function progressivelyDrainSerializationQueue(reason = '') {
  // If a drain is already running, cancel it first — we don't want
  // two drains racing through the same queue.
  if (_activeProgressiveDrain) {
    try { _activeProgressiveDrain.cancel(); } catch {}
    _activeProgressiveDrain = null;
  }
  const intervalMs = Math.max(
    250,
    Math.min(settings.serializeDelayMs | 0 || 250, 5_000),
  );
  const initialQueued = _serializationQueue.getStats().queued;
  if (initialQueued === 0) return; // nothing to drain
  log('info', `serialize disengaging (${reason}): progressive drain of ${initialQueued} queued at ${1000 / intervalMs}/s`);
  logActivity('serialize-progressive-drain-start', {
    reason: reason || 'unspecified',
    queued: initialQueued,
    interval_ms: intervalMs,
  });
  _activeProgressiveDrain = _serializationQueue.drainProgressively({
    intervalMs,
    onDrained: ({ released, cancelled }) => {
      _activeProgressiveDrain = null;
      log('info', `serialize progressive drain ${cancelled ? 'cancelled' : 'complete'}: released ${released}/${initialQueued}`);
      logActivity('serialize-progressive-drain-end', {
        reason: reason || 'unspecified',
        released,
        cancelled: !!cancelled,
        initial_queued: initialQueued,
      });
    },
  });
}

function withSerializationQueue(fn, isRetry = false) {
  return _serializationQueue.acquire(fn, isRetry);
}

// ─────────────────────────────────────────────────
// Serialize-mode auto-safeguards (queue_timeout / depth / 429-burst)
// ─────────────────────────────────────────────────
//
// Three independent safeguards watch for the failure modes serialize mode
// can produce in production:
//
//   A. queue_timeout breaker — counts 503 queue_timeout responses in a
//      sliding window. Above threshold → auto-disable serialize. These
//      503s mean the serialization queue is so backed up that requests
//      time out before reaching forwardToAnthropic — turning serialize
//      off lets the backlog drain in parallel and unblocks the user.
//
//   B. queue depth alert — informational only. If the in-queue depth
//      stays above the threshold for sustainMs, log + emit activity
//      event so the user sees the warning sign before the breaker
//      trips. Doesn't auto-disable because legitimate burst traffic
//      can produce a deep queue without indicating a problem.
//
//   C. all-accounts-429 breaker — tracks every 429 received from
//      Anthropic. If the set of accounts that hit 429 within
//      all429BreakerWindowMs covers EVERY known account AND serialize
//      is on, auto-disable serialize. The original symptom: with
//      strict serialize the queue lined up behind the slowest
//      account, so when one account started 429-ing the whole queue
//      piled up against it and other accounts also got rate-limited
//      because the rotation logic couldn't switch between them in
//      parallel. Disabling serialize lets the rotation work in
//      parallel and the queue drains.
//
// All three safeguards check settings.serializeAutoDisableEnabled at
// trip time — a user who explicitly wants serialize on through hell
// or high water can set that to false.

const _queueTimeoutCounter = createSlidingWindowCounter({
  windowMs: DEFAULT_SETTINGS.queueTimeoutBreakerWindowMs,
  threshold: DEFAULT_SETTINGS.queueTimeoutBreakerThreshold,
});

// Map<accountFingerprint, lastSeen429AtMs> — used by safeguard C to
// answer "have all known accounts been seen 429-ing within window".
// Key by FINGERPRINT not name so a rename mid-incident doesn't cause
// a false-positive trip from "the renamed account hasn't 429'd yet".
const _all429ByFingerprint = new Map();

// State for safeguard B (sustained queue depth).
let _queueDepthHighSince = null;       // ms when depth first exceeded threshold
let _queueDepthAlertEmittedAt = 0;     // ms of last alert (debounce — once per sustain window)

// Last time we auto-disabled serialize. Debounce so two rapid trips
// (queue_timeout + all-429) don't double-emit the same alert.
let _lastSerializeAutoDisableAt = 0;
const _SERIALIZE_AUTO_DISABLE_DEBOUNCE_MS = 30_000; // 30s — enough for the user to see + react

// ─────────────────────────────────────────────────
// Safeguard D — burst rate-limit detector → AUTO-ENABLE serialize
// ─────────────────────────────────────────────────
//
// User-reported scenario (Phase I+):
//   "If multiple Claude Code instances just got rate limited because
//    they sent requests with too big payloads at the same time, do not
//    immediately switch to another oauth, because that will surely
//    cause the new oauth to be banned too. Instead switch automatically
//    to queue mode, and with the new oauth send the requests serially
//    with a delay between them, and only in that case switch back to
//    non-queue mode (unless the user is already in queue mode)."
//
// Detection heuristic:
//   - 3+ 429s on the SAME account within 30s, AND
//   - serializeRequests is currently OFF, AND
//   - serializeAutoEnableEnabled is true (default ON)
//   → enable serializeRequests=true with a small delay (250ms) +
//     concurrent=1, log forensic event, fire a notification
//
// Auto-revert: 30 minutes with NO new 429 from any account → set
// settings.serializeRequests back to whatever was before, IF we were
// the ones who enabled it (track via _serializeAutoEnabledAt). If
// the user was already in serialize mode, do nothing on detection
// AND nothing on revert.
const _BURST_429_WINDOW_MS = 30_000;   // 30s sliding window
const _BURST_429_THRESHOLD = 3;        // 3 429s within window
const _SERIALIZE_AUTO_REVERT_MS = 30 * 60 * 1000; // 30 min of quiet → revert
let _serializeAutoEnabledAt = 0;       // 0 = user-controlled; >0 = WE enabled it
let _last429AnyAccountAt = 0;          // for the auto-revert quiet window
const _burst429ByFingerprint = new Map(); // fp → SlidingWindowCounter

// Auto-disable serialize mode + emit activity event explaining why.
// Idempotent; safe to call from any safeguard's trip path.
function _autoDisableSerialize(reason, detail = {}) {
  if (!settings.serializeAutoDisableEnabled) return;
  if (!settings.serializeRequests) return; // already off
  const now = Date.now();
  if (now - _lastSerializeAutoDisableAt < _SERIALIZE_AUTO_DISABLE_DEBOUNCE_MS) return;
  _lastSerializeAutoDisableAt = now;

  settings.serializeRequests = false;
  try { saveSettings(settings); } catch (e) {
    log('warn', `auto-disable: saveSettings failed: ${e.message}`);
  }
  // Progressive drain — a backlog from a queue_timeout / all-429 burst
  // would otherwise flood Anthropic the moment we flip the flag.
  try { progressivelyDrainSerializationQueue(`auto-disable: ${reason}`); } catch {}
  // Reset the breakers so the user can re-enable without an immediate
  // re-trip from the same recorded events.
  _queueTimeoutCounter.reset();
  _all429ByFingerprint.clear();
  _queueDepthHighSince = null;

  log('warn', `serialize auto-disabled: ${reason}`);
  logActivity('serialize-auto-disabled', { reason, ...detail });
  notify(
    'vdm: Serialize mode auto-disabled',
    `Reason: ${reason}. Re-enable from Settings if intentional.`,
    'circuitBreaker',
  );
}

// Safeguard D — auto-ENABLE serialize on burst 429 from a single
// account. Mirrors _autoDisableSerialize's contract: best-effort,
// debounced, only acts when the user hasn't opted out via settings.
// Also tracks _serializeAutoEnabledAt so the auto-revert timer knows
// whether vdm or the user owns the current serialize state.
function _autoEnableSerializeOnBurst(account_fp, account_name) {
  // User-disabled the auto-safeguards entirely → respect that.
  if (!settings.serializeAutoDisableEnabled) return;
  // Already in serialize mode (whoever enabled it) → no-op.
  if (settings.serializeRequests) return;
  // Auto-enable was turned off by the user via settings → respect.
  if (settings.serializeAutoEnableEnabled === false) return;

  // Make sure we have a per-account counter, then record this 429.
  let counter = _burst429ByFingerprint.get(account_fp);
  if (!counter) {
    counter = createSlidingWindowCounter({
      windowMs: _BURST_429_WINDOW_MS,
      threshold: _BURST_429_THRESHOLD,
    });
    _burst429ByFingerprint.set(account_fp, counter);
  }
  counter.record();
  if (!counter.tripped()) return;

  // Threshold crossed — enable serialize mode + a small inter-request
  // delay so the next account doesn't get bombarded by the same
  // parallel-payload burst.
  settings.serializeRequests = true;
  settings.serializeMaxConcurrent = Math.max(1, settings.serializeMaxConcurrent || 1);
  if (!settings.serializeDelayMs || settings.serializeDelayMs < 250) {
    settings.serializeDelayMs = 250;
  }
  _serializeAutoEnabledAt = Date.now();

  try { saveSettings(settings); } catch (e) {
    log('warn', `auto-enable serialize: saveSettings failed: ${e.message}`);
  }
  // Forensic event — captures everything you'd need to investigate why
  // serialize flipped on by itself. Includes the account that triggered
  // the trip + the 429 burst count.
  try {
    logForensicEvent('serialize_auto_enabled', {
      reason: 'burst-429-on-single-account',
      account_fp,
      account_name,
      window_ms: _BURST_429_WINDOW_MS,
      threshold: _BURST_429_THRESHOLD,
      serialize_max_concurrent: settings.serializeMaxConcurrent,
      serialize_delay_ms: settings.serializeDelayMs,
    });
  } catch {}
  log('warn', `serialize auto-ENABLED: ${account_name} burst-429 (${_BURST_429_THRESHOLD} in ${_BURST_429_WINDOW_MS / 1000}s) — switching to queue mode to avoid bombarding the next account`);
  logActivity('serialize-auto-enabled', {
    reason: 'burst-429',
    account: account_name,
    revert_after_quiet_min: Math.round(_SERIALIZE_AUTO_REVERT_MS / 60000),
  });
  notify(
    'vdm: Serialize mode auto-enabled',
    `${account_name} hit ${_BURST_429_THRESHOLD} rate-limits in ${_BURST_429_WINDOW_MS / 1000}s. Queueing requests to avoid burning the next account. Will revert after 30min quiet.`,
    'circuitBreaker',
  );
}

// Periodic check (every 60s): if WE auto-enabled serialize and there
// has been NO 429 from any account for _SERIALIZE_AUTO_REVERT_MS,
// disable serialize and clear the auto-enable marker. If the user
// turned serialize on themselves (_serializeAutoEnabledAt === 0), the
// auto-revert is a no-op — only vdm-owned auto-enable cleans itself
// up.
function _maybeAutoRevertSerialize() {
  if (_serializeAutoEnabledAt === 0) return;     // user owns the state
  if (!settings.serializeRequests) {
    // Someone else turned it off (user, _autoDisableSerialize, etc.)
    // Clear our marker so we don't fight them.
    _serializeAutoEnabledAt = 0;
    return;
  }
  const quietMs = Date.now() - _last429AnyAccountAt;
  if (quietMs < _SERIALIZE_AUTO_REVERT_MS) return;

  settings.serializeRequests = false;
  _serializeAutoEnabledAt = 0;
  _burst429ByFingerprint.clear();
  try { saveSettings(settings); } catch {}
  // Progressive drain on auto-revert too — same flood risk as
  // _autoDisableSerialize. Without this, a queue that filled up
  // during the just-elapsed quiet window dumps in one shot.
  try { progressivelyDrainSerializationQueue('auto-revert: quiet-window-elapsed'); } catch {}
  try {
    logForensicEvent('serialize_auto_reverted', {
      reason: 'quiet-window-elapsed',
      quiet_ms: quietMs,
    });
  } catch {}
  log('info', `serialize auto-reverted: ${Math.round(quietMs / 60000)}min of no 429s`);
  logActivity('serialize-auto-reverted', { quiet_min: Math.round(quietMs / 60000) });
  // No notification on revert — it's good news, no user action needed.
}
const _serializeAutoRevertTimer = setInterval(_maybeAutoRevertSerialize, 60_000);
if (_serializeAutoRevertTimer.unref) _serializeAutoRevertTimer.unref();

// ─────────────────────────────────────────────────
// OAuth-bypass mode — when ALL saved accounts have permanently
// revoked refresh tokens (per RFC 6749 §5.2 invalid_grant /
// unauthorized_client / invalid_client / access_denied), there's
// nothing for vdm to rotate to. Switching from a dead token to
// another dead token isn't a "switch", it's just churn that confuses
// the user with cascading "switching account..." toasts. In bypass
// mode, the proxy stops trying to rotate or refresh — it just
// forwards whatever the keychain currently has, transparently. The
// serialize queue still applies (it's upstream of rotation logic).
//
// User contract: vdm notifies once with HIGH_PRIORITY ("Run
// `claude login`") and STOPS trying to be helpful until that happens.
// As soon as ANY account responds 200 (the user just logged in →
// new token in keychain → autoDiscover → forward → 200 → bypass
// exits), we leave bypass and resume normal rotation.
//
// Detection caveats — bypass mode engages ONLY when:
//   - settings.oauthBypassEnabled is true (default ON; user can disable)
//   - At least one account is on file (zero accounts = nothing to
//     conclude, just forward the request and let Anthropic 401)
//   - EVERY account is in `permanentlyRevoked` state (which itself
//     requires 3+ revocation-class refresh failures spread over 1h —
//     so a brief OAuth-server outage cannot trip bypass)
//   - No account has a 5h/7d-reset window in the future (those are
//     temporary, will recover)
//   - No account has had a 200 response in last 24h
let _oauthBypassMode = false;
let _oauthBypassEnteredAt = 0;
let _oauthBypassRecoveryTimer = null;
const _OAUTH_BYPASS_RECOVERY_INTERVAL_MS = 5 * 60 * 1000; // 5 min

function _enterOAuthBypass(reason) {
  if (_oauthBypassMode) return; // already in bypass
  _oauthBypassMode = true;
  _oauthBypassEnteredAt = Date.now();
  log('warn', `OAuth bypass mode ENTERED: ${reason}`);
  logActivity('oauth-bypass-enabled', { reason: reason || 'all-accounts-revoked' });
  try {
    logForensicEvent('oauth_bypass_enabled', {
      reason: reason || 'all-accounts-revoked',
      account_count: 0,  // populated below if available
    });
  } catch {}
  notify(
    'vdm: All OAuth tokens revoked',
    'Run `claude login` to authenticate, then `vdm add` to register the new account. The proxy is now passing requests transparently — no rotation.',
    'circuitBreaker',  // HIGH_PRIORITY → bypasses 10s throttle
  );
  // Start a low-frequency probe — if any revoked account refreshes
  // successfully (e.g. user did `claude login` AND the new credentials
  // happen to be in a vdm-account-* slot), we want to detect it without
  // waiting for a fresh request to reach updateAccountState.
  if (_oauthBypassRecoveryTimer === null) {
    _oauthBypassRecoveryTimer = setInterval(_probeBypassRecovery, _OAUTH_BYPASS_RECOVERY_INTERVAL_MS);
    if (_oauthBypassRecoveryTimer.unref) _oauthBypassRecoveryTimer.unref();
  }
}

function _exitOAuthBypass(reason) {
  if (!_oauthBypassMode) return;
  const durationMs = Date.now() - _oauthBypassEnteredAt;
  _oauthBypassMode = false;
  _oauthBypassEnteredAt = 0;
  if (_oauthBypassRecoveryTimer) {
    clearInterval(_oauthBypassRecoveryTimer);
    _oauthBypassRecoveryTimer = null;
  }
  log('info', `OAuth bypass mode EXITED: ${reason} (was in bypass for ${Math.round(durationMs / 60_000)}min)`);
  logActivity('oauth-bypass-disabled', { reason: reason || 'recovery', duration_min: Math.round(durationMs / 60_000) });
  try {
    logForensicEvent('oauth_bypass_disabled', {
      reason: reason || 'recovery',
      duration_ms: durationMs,
    });
  } catch {}
  // No notification on exit — it's good news (the user fixed their auth),
  // and they'll see normal vdm operation resume on their next prompt.
}

// Recompute "all accounts dead" using the current state, then enter or
// exit bypass mode accordingly. Cheap to call from any code path
// (refresh-failed, refresh-success, 200-response). Respects the user's
// opt-out via settings.oauthBypassEnabled.
function _evaluateBypassMode() {
  if (settings.oauthBypassEnabled === false) {
    // Feature disabled by user — exit if currently engaged.
    if (_oauthBypassMode) _exitOAuthBypass('user-disabled');
    return;
  }
  let accounts;
  try { accounts = loadAllAccountTokens(); } catch { return; }
  if (!Array.isArray(accounts) || accounts.length === 0) {
    // No accounts saved — no decision to make. Exit if somehow in bypass.
    if (_oauthBypassMode) _exitOAuthBypass('no-accounts');
    return;
  }
  const allDead = areAllAccountsTerminallyDead(accounts, accountState);
  if (allDead && !_oauthBypassMode) {
    _enterOAuthBypass(`${accounts.length} accounts all permanently revoked`);
  } else if (!allDead && _oauthBypassMode) {
    _exitOAuthBypass('at-least-one-account-recovered');
  }
}

// Background probe — every 5 min while bypass is engaged, attempt to
// refresh each account once. If any succeeds, the refresh handler
// clears that account's revocation state and calls _evaluateBypassMode,
// which exits bypass. The probe is bounded by _refreshSem (3 concurrent
// upstream OAuth POSTs across all accounts) so it can't hammer the
// OAuth server even with N revoked accounts.
async function _probeBypassRecovery() {
  if (!_oauthBypassMode) return;
  let accounts;
  try { accounts = loadAllAccountTokens(); } catch { return; }
  if (!Array.isArray(accounts) || accounts.length === 0) {
    _exitOAuthBypass('no-accounts');
    return;
  }
  log('info', `OAuth bypass recovery probe: attempting refresh on ${accounts.length} accounts`);
  // Best-effort, fire-and-forget. The refresh handler itself will call
  // _evaluateBypassMode on success/failure, so we don't need to await
  // each one in series.
  for (const a of accounts) {
    if (!a || !a.name) continue;
    try {
      // refreshAccountToken handles its own retries + classification.
      // force=true so we attempt the refresh even if the cached
      // expiresAt says the token is still valid (it isn't — it's revoked).
      refreshAccountToken(a.name, { force: true }).catch(() => {});
    } catch {}
  }
}

// Called from the proxy queue_timeout 503 catch handler. Records the
// event, then trips the breaker if the count crosses threshold AND
// serialize is on. The window/threshold are read from live settings on
// each trip-check so a user tuning them via the API doesn't need a
// dashboard restart.
function _recordQueueTimeout() {
  _queueTimeoutCounter.record();
  if (!settings.serializeRequests) return;
  if (!settings.serializeAutoDisableEnabled) return;
  const threshold = Math.max(1, settings.queueTimeoutBreakerThreshold | 0 || 5);
  // Re-check against the live threshold (the counter was instantiated
  // with the DEFAULT but the user may have tuned it). The window is
  // fixed at counter-creation time; tuning windowMs at runtime would
  // require recreating the counter, which is a future enhancement.
  if (_queueTimeoutCounter.count() >= threshold) {
    _autoDisableSerialize('queue_timeout breaker tripped', {
      count: _queueTimeoutCounter.count(),
      windowMs: settings.queueTimeoutBreakerWindowMs,
    });
  }
}

// Called from forwardToAnthropic when a 429 is received from Anthropic.
// Records by account FINGERPRINT so a rename between record + check
// doesn't desync. Trips when EVERY known account has been seen 429-ing
// within window AND serialize is on.
function _record429ForAccount(fingerprint) {
  if (!fingerprint) return;
  const now = Date.now();
  _all429ByFingerprint.set(fingerprint, now);
  if (!settings.serializeRequests) return;
  if (!settings.serializeAutoDisableEnabled) return;
  const windowMs = Math.max(1000, settings.all429BreakerWindowMs | 0 || 60000);
  // Prune entries outside the window. Doing it here keeps the map
  // bounded by account count + window-fresh entries.
  for (const [fp, ts] of _all429ByFingerprint) {
    if (now - ts > windowMs) _all429ByFingerprint.delete(fp);
  }
  // Check if every known account fingerprint is in the recent-429 set.
  // loadAllAccountTokens reads from the keychain (sync) — we already do
  // this on the proxy hot path so it's cached. Skip the trip if
  // accounts can't be read (degraded mode — better to leave serialize
  // on than auto-disable on a transient keychain error).
  let knownFps;
  try {
    // BUG FIX: was a.accessToken (undefined on every account object)
    // → getFingerprintFromToken(undefined) returned null → knownFps was
    // always [] after the .filter(Boolean) → the early return at the
    // empty-knownFps check fired unconditionally, so this safeguard had
    // never been able to trip in production. loadAllAccountTokens() emits
    // objects with `.token` (the access token string); the OAuth blob
    // also lives at `.creds.claudeAiOauth.accessToken`. Every other
    // call site uses `a.token`. See lib.mjs for the source-of-truth shape.
    knownFps = loadAllAccountTokens()
      .map(a => getFingerprintFromToken(a.token))
      .filter(Boolean);
  } catch {
    return;
  }
  if (knownFps.length === 0) return;          // no accounts → nothing to compare
  if (knownFps.length < 2) return;            // single-account installs can't trip this — that's just "the only account is rate-limited", not a serialize symptom
  for (const fp of knownFps) {
    if (!_all429ByFingerprint.has(fp)) return; // at least one healthy account → no trip
  }
  _autoDisableSerialize('all-accounts-429 burst', {
    accountCount: knownFps.length,
    windowMs,
  });
}

// Called from the periodic queue-stats poll. Tracks the queued count;
// if it stays above threshold for sustainMs, emits an alert. Does NOT
// auto-disable — bursts of legitimate traffic can produce deep queues.
function _checkQueueDepthAlert() {
  if (!settings.serializeRequests) {
    _queueDepthHighSince = null;
    return;
  }
  const stats = _serializationQueue.getStats();
  const threshold = Math.max(1, settings.queueDepthAlertThreshold | 0 || 50);
  const sustainMs = Math.max(1000, settings.queueDepthAlertSustainMs | 0 || 60000);
  const now = Date.now();
  if (stats.queued < threshold) {
    _queueDepthHighSince = null;
    return;
  }
  if (_queueDepthHighSince == null) {
    _queueDepthHighSince = now;
    return;
  }
  // Debounce: only emit once per sustain window so a 5-min sustained
  // backup doesn't spam the activity log every poll-interval.
  if (now - _queueDepthHighSince >= sustainMs &&
      now - _queueDepthAlertEmittedAt >= sustainMs) {
    _queueDepthAlertEmittedAt = now;
    log('warn', `serialize queue depth alert: queued=${stats.queued} (threshold=${threshold}) sustained ${Math.round((now - _queueDepthHighSince) / 1000)}s`);
    logActivity('queue-depth-alert', {
      queued: stats.queued,
      threshold,
      sustainedSeconds: Math.round((now - _queueDepthHighSince) / 1000),
    });
  }
}

// ─────────────────────────────────────────────────
// Token Usage Extractor (SSE Transform Stream)
// ─────────────────────────────────────────────────

// FG4 follow-up — the extractor itself lives in lib.mjs so its
// `finishParsing()` idempotency contract (audit M2 — abort-path token
// rescue) can be unit-tested. This thin wrapper just injects the
// dashboard's `log()` function so debug events from malformed trailing
// lines bubble through the existing log pipeline.
function createUsageExtractor() {
  return _createUsageExtractor({ logger: log });
}

// ─────────────────────────────────────────────────
// Session Monitor — server-side functions
// ─────────────────────────────────────────────────

// FNV-1a hash (32-bit) — fast, deterministic, good distribution
function _fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16);
}

// Simple string hash for turn detection
function _simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}

function extractCwd(bodyObj) {
  // Search system prompt for working directory
  const sysContent = bodyObj.system;
  let searchText = '';
  if (typeof sysContent === 'string') {
    searchText = sysContent;
  } else if (Array.isArray(sysContent)) {
    searchText = sysContent.map(b => typeof b === 'string' ? b : b.text || '').join(' ');
  }
  const match = searchText.match(/working directory:\s*(.+)/i);
  if (match) return match[1].trim().split('\n')[0].trim();
  // Fallback: hash first 200 chars of system prompt
  return '_sys_' + _fnv1a(searchText.slice(0, 200));
}

function deriveSessionId(cwd, account) {
  return _fnv1a(cwd + '::' + account);
}

function detectNewTurn(bodyObj, session) {
  const msgs = bodyObj.messages || [];
  // Find last user message
  let lastUserText = '';
  let assistantContext = '';
  const toolUses = [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role === 'user' && !lastUserText) {
      if (typeof m.content === 'string') lastUserText = m.content;
      else if (Array.isArray(m.content)) {
        lastUserText = m.content.filter(b => b.type === 'text').map(b => b.text).join(' ');
      }
    }
    if (m.role === 'assistant' && !assistantContext) {
      if (typeof m.content === 'string') assistantContext = m.content;
      else if (Array.isArray(m.content)) {
        for (const b of m.content) {
          if (b.type === 'text') assistantContext = (assistantContext || '') + b.text;
          if (b.type === 'tool_use') toolUses.push(b);
        }
      }
    }
    if (lastUserText && assistantContext) break;
  }
  if (!lastUserText) return null;
  // Clean inputs before summarisation
  lastUserText = lastUserText.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '').trim();
  assistantContext = assistantContext
    .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '')
    .replace(/```[\s\S]*?```/g, '')           // strip code blocks
    .replace(/`[^`]+`/g, '')                  // strip inline code
    .replace(/^I'll [^\n]*/gm, '')            // strip "I'll do X" preambles
    .replace(/^Let me [^\n]*/gm, '')          // strip "Let me..." preambles
    .replace(/\n{2,}/g, '\n').trim();
  const hash = _simpleHash(lastUserText);
  if (hash === session.lastUserHash) return null;
  session.lastUserHash = hash;
  return { userText: lastUserText, assistantContext, toolUses };
}

function formatCurrentActivity(bodyObj) {
  const msgs = bodyObj.messages || [];
  // Scan from end for last assistant tool_use (skip user messages — tool_result
  // content is raw tool output and not useful as an activity label)
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role === 'assistant' && Array.isArray(m.content)) {
      for (let j = m.content.length - 1; j >= 0; j--) {
        const b = m.content[j];
        if (b.type === 'tool_use') {
          const name = b.name || 'unknown';
          let arg = '';
          if (b.input) {
            if (b.input.command) arg = b.input.command.replace(/\n/g, ' ');
            else if (b.input.file_path) arg = b.input.file_path;
            else if (b.input.pattern) arg = b.input.pattern;
            else if (b.input.query) arg = b.input.query.replace(/\n/g, ' ');
          }
          const text = arg ? `${name} ${arg}` : name;
          return text.length > 60 ? text.slice(0, 57) + '...' : text;
        }
      }
    }
  }
  return null;
}

function extractFilesModified(toolUses) {
  const files = new Set();
  for (const tu of toolUses) {
    if (!tu.input) continue;
    if (tu.name === 'Edit' || tu.name === 'Write') {
      const fp = tu.input.file_path;
      if (fp) files.add(basename(fp));
    }
    if (tu.name === 'Bash' && typeof tu.input.command === 'string') {
      // Heuristic: detect common file-modifying patterns
      const cmd = tu.input.command;
      const editMatch = cmd.match(/(?:sed|awk|tee|>)\s+["']?([^\s"'|;]+)/);
      if (editMatch) files.add(basename(editMatch[1]));
    }
  }
  return [...files];
}

async function callHaikuSummary(userText, assistantContext, toolUses) {
  // Check backoff
  if (_haikuBackoffUntil > Date.now()) return null;

  // Skip if no meaningful content to summarize
  const trimmedUser = userText.trim();
  const trimmedCtx = (assistantContext || '').trim();
  if (!trimmedUser && !trimmedCtx && !toolUses.length) return null;

  const toolList = toolUses.map(t => {
    const name = t.name || 'unknown';
    let arg = '';
    if (t.input) {
      if (t.input.command) arg = t.input.command.replace(/\n/g, ' ').slice(0, 60);
      else if (t.input.file_path) arg = `${basename(t.input.file_path)}`;
      else if (t.input.pattern) arg = t.input.pattern.slice(0, 40);
    }
    return arg ? `${name} ${arg}` : name;
  }).slice(0, 10).join(', ');

  const sysMsg = 'You summarize coding activity for a monitoring dashboard. Output ONLY 2-3 plain-text sentences. Past tense. No code, no markdown, no bullets, no preamble. Never quote code snippets or commands. Never start with "The user" or "I\'ll". Focus on what was decided, found, or changed. Skip verification steps, test runs, and routine checks.';
  const userMsg = `${trimmedUser.slice(0, 500)}${trimmedCtx ? '\n' + trimmedCtx.slice(0, 300) : ''}${toolList ? '\nTools: ' + toolList : ''}`;

  let token;
  try { token = getActiveToken(); } catch { return null; }
  if (!token) return null;

  const reqBody = JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 300,
    system: sysMsg,
    messages: [{ role: 'user', content: userMsg }],
  });

  try {
    const res = await forwardToAnthropic('POST', '/v1/messages', {
      'host': 'api.anthropic.com',
      'authorization': `Bearer ${token}`,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(reqBody)),
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'oauth-2025-04-20',
    }, Buffer.from(reqBody), HAIKU_TIMEOUT);

    const buf = await drainResponse(res);
    if (res.statusCode !== 200) {
      _haikuFailCount++;
      if (_haikuFailCount >= 3) _haikuBackoffUntil = Date.now() + HAIKU_BACKOFF_MS;
      return null;
    }

    _haikuFailCount = 0;
    const data = JSON.parse(buf.toString('utf8'));

    // Track overhead tokens
    if (data.usage) {
      _summarizerOverhead.inputTokens += data.usage.input_tokens || 0;
      _summarizerOverhead.outputTokens += data.usage.output_tokens || 0;
    }

    // Parse response — split into sentences, first = input, rest = actions
    const raw = (data.content?.[0]?.text || '').replace(/<[^>]+>/g, '').trim();
    if (!raw) return null;
    // Split on sentence boundaries (period/exclamation/question followed by space or end)
    const isMeta = s => /^(The user |I'll |I don't |I can't |However|Please share|Since there|This appears|You've provided|Let me )/i.test(s);
    const sentences = raw.split(/(?<=[.!?])\s+/)
      .map(s => s.replace(/^[\s*\-•>]+/, '').trim())
      .filter(s => s && !isMeta(s));
    if (!sentences.length) return null;
    const input = sentences[0].slice(0, 200);
    const actions = sentences.slice(1, 4).map(s => s.slice(0, 200));

    if (input || actions.length) {
      return { input, actions };
    }
    return null;
  } catch {
    _haikuFailCount++;
    if (_haikuFailCount >= 3) _haikuBackoffUntil = Date.now() + HAIKU_BACKOFF_MS;
    return null;
  }
}

function formatTurnFallback(userText, toolUses) {
  // Rule-based: truncate user text as input, format tool names as actions
  const input = userText.slice(0, 60).replace(/\n/g, ' ').trim();
  const actions = toolUses.slice(0, 3).map(t => {
    const name = t.name || 'unknown';
    let arg = '';
    if (t.input) {
      if (t.input.file_path) arg = basename(t.input.file_path);
      else if (t.input.command) arg = t.input.command.replace(/\n/g, ' ').slice(0, 40);
    }
    return arg ? `${name}: ${arg}` : name;
  });
  return { input: input || 'working...', actions };
}

function updateSessionTimeline(bodyObj, acctName, usage) {
  const cwd = extractCwd(bodyObj);
  const sessionId = deriveSessionId(cwd, acctName);
  const model = bodyObj.model || '';

  // Detect repo/branch from cwd
  let repo = '', branch = '';
  const cwdStr = typeof cwd === 'string' && !cwd.startsWith('_sys_') ? cwd : '';
  if (cwdStr) {
    repo = basename(cwdStr);
    // _runGit uses execFileSync with argv[]: cwd is passed as a separate
    // argument so shell metacharacters in it cannot inject commands. The
    // previous regex `/["$`\\]/` blocked only chars that broke out of a
    // shell-interpolated double-quoted form — not enough (newline still
    // worked). This is the correct fix: no shell at all.
    // _runGitCached: this fires on every proxy SSE response — without the
    // 30s TTL cache, sustained load made `git rev-parse` the #1 blocker on
    // the event loop.
    try {
      branch = _runGitCached(cwdStr, ['rev-parse', '--abbrev-ref', 'HEAD'], 2000).trim();
    } catch {}
  }

  // Create or retrieve session
  let session = monitoredSessions.get(sessionId);
  if (!session) {
    // Enforce max active sessions
    if (monitoredSessions.size >= SESSION_MAX_ACTIVE) {
      // Expire oldest
      let oldestId = null, oldestTs = Infinity;
      for (const [id, s] of monitoredSessions) {
        if (s.lastActiveAt < oldestTs) { oldestTs = s.lastActiveAt; oldestId = id; }
      }
      if (oldestId) {
        persistCompletedSession(monitoredSessions.get(oldestId));
        monitoredSessions.delete(oldestId);
      }
    }
    session = {
      id: sessionId,
      account: acctName,
      model,
      cwd: cwdStr || cwd,
      repo,
      branch,
      timeline: [],
      currentActivity: null,
      filesModified: [],
      requestCount: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUserHash: null,
      pendingHaiku: false,
      queuedTurns: [],
      startedAt: Date.now(),
      lastActiveAt: Date.now(),
      status: 'active',
      completedAt: null,
    };
    monitoredSessions.set(sessionId, session);
  }

  // Update session metadata
  session.lastActiveAt = Date.now();
  session.requestCount++;
  if (model) session.model = model;
  if (usage) {
    session.totalInputTokens += usage.inputTokens || 0;
    session.totalOutputTokens += usage.outputTokens || 0;
  }

  // Update current activity (no AI)
  const activity = formatCurrentActivity(bodyObj);
  if (activity) session.currentActivity = activity;

  // Detect new turn
  const turn = detectNewTurn(bodyObj, session);
  if (!turn) return;

  // Extract files modified from tool uses
  const newFiles = extractFilesModified(turn.toolUses);
  for (const f of newFiles) {
    if (!session.filesModified.includes(f)) {
      session.filesModified.push(f);
      if (session.filesModified.length > SESSION_FILES_MAX) session.filesModified.shift();
    }
  }

  // Batch turns: accumulate for 10s, then summarise together
  session.queuedTurns.push(turn);
  if (session.queuedTurns.length > 10) session.queuedTurns.splice(0, session.queuedTurns.length - 5);
  if (session._batchTimer || session.pendingHaiku) return;
  session._batchTimer = setTimeout(() => {
    session._batchTimer = null;
    const batch = session.queuedTurns.splice(0);
    if (!batch.length) return;
    // Merge batch: combine user texts and tool uses, use latest assistant context
    const mergedUser = batch.map(t => t.userText).join(' | ');
    const mergedContext = batch[batch.length - 1].assistantContext;
    const mergedTools = batch.flatMap(t => t.toolUses);
    session.pendingHaiku = true;
    callHaikuSummary(mergedUser, mergedContext, mergedTools).then(result => {
      const summary = result || formatTurnFallback(mergedUser, mergedTools);
      if (summary.input) {
        session.timeline.push({ type: 'input', text: summary.input });
      }
      for (const action of (summary.actions || [])) {
        session.timeline.push({ type: 'action', text: action });
      }
      while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
      session.pendingHaiku = false;
      // If more turns arrived while we were waiting, kick off another batch
      if (session.queuedTurns.length > 0) {
        session._batchTimer = setTimeout(() => {
          session._batchTimer = null;
          // Re-trigger with the rule-based fallback (no Haiku call here —
          // this branch fires when more turns piled up while we were
          // waiting on the first Haiku response, and we don't want to
          // double-charge the user's tokens for back-to-back summaries).
          // formatTurnFallback only consumes user text + tool list, so
          // assistant context is intentionally dropped.
          const next = session.queuedTurns.splice(0);
          if (!next.length) return;
          const mu = next.map(t => t.userText).join(' | ');
          const mt = next.flatMap(t => t.toolUses);
          const fb = formatTurnFallback(mu, mt);
          if (fb.input) session.timeline.push({ type: 'input', text: fb.input });
          for (const a of fb.actions) session.timeline.push({ type: 'action', text: a });
          while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
        }, 10000);
      }
    }).catch(() => {
      const fb = formatTurnFallback(mergedUser, mergedTools);
      if (fb.input) session.timeline.push({ type: 'input', text: fb.input });
      for (const a of fb.actions) session.timeline.push({ type: 'action', text: a });
      while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
      session.pendingHaiku = false;
      session.queuedTurns.splice(0);
    });
  }, 10000);
}

// Same debounce pattern used for token-usage.json: don't fsync the entire
// (potentially N-MB pretty-printed) session-history.json on every session
// completion. The 30s sweeper bursts can complete dozens of sessions
// in milliseconds and each unsynced write blocks the event loop. Coalesce
// into one disk write per ~750 ms.
let _sessionHistoryDirty = false;
let _sessionHistoryFlushTimer = null;
const SESSION_HISTORY_FLUSH_MS = 750;

function _flushSessionHistory() {
  _sessionHistoryFlushTimer = null;
  if (!_sessionHistoryDirty) return;
  _sessionHistoryDirty = false;
  try {
    atomicWriteFileSync(SESSION_HISTORY_FILE, JSON.stringify(sessionHistory, null, 2));
  } catch (e) {
    log('warn', `Failed to write session-history.json: ${e.message}`);
    // Re-arm so the next completion retries the write.
    _sessionHistoryDirty = true;
  }
}

function flushSessionHistorySync() {
  if (_sessionHistoryFlushTimer) {
    clearTimeout(_sessionHistoryFlushTimer);
    _sessionHistoryFlushTimer = null;
  }
  _flushSessionHistory();
}

function persistCompletedSession(session) {
  if (!session) return;
  session.status = 'completed';
  session.completedAt = session.completedAt || Date.now();
  sessionHistory.unshift({
    id: session.id,
    account: session.account,
    model: session.model,
    cwd: session.cwd,
    repo: session.repo,
    branch: session.branch,
    timeline: session.timeline.slice(0, SESSION_TIMELINE_MAX),
    requestCount: session.requestCount,
    totalInputTokens: session.totalInputTokens,
    totalOutputTokens: session.totalOutputTokens,
    startedAt: session.startedAt,
    completedAt: session.completedAt,
    duration: session.completedAt - session.startedAt,
  });
  if (sessionHistory.length > SESSION_HISTORY_MAX) sessionHistory.length = SESSION_HISTORY_MAX;
  // Mark dirty + arm the debounce timer. The previous synchronous write
  // was a 50ms+ event-loop block on every session completion under load.
  _sessionHistoryDirty = true;
  if (!_sessionHistoryFlushTimer) {
    _sessionHistoryFlushTimer = setTimeout(_flushSessionHistory, SESSION_HISTORY_FLUSH_MS);
    _sessionHistoryFlushTimer.unref?.();
  }
}

function getFileConflicts() {
  const fileToSessions = new Map(); // file → [{ id, account }]
  for (const [, session] of monitoredSessions) {
    if (session.status !== 'active') continue;
    for (const f of session.filesModified) {
      if (!fileToSessions.has(f)) fileToSessions.set(f, []);
      fileToSessions.get(f).push({ id: session.id, account: session.account });
    }
  }
  const conflicts = [];
  for (const [file, sessions] of fileToSessions) {
    // Deduplicate by session ID (same session can only count once)
    const uniqueById = new Map();
    for (const s of sessions) uniqueById.set(s.id, s.account);
    if (uniqueById.size >= 2) {
      const accounts = [...new Set(uniqueById.values())];
      conflicts.push({ file, accounts, count: uniqueById.size });
    }
  }
  return conflicts;
}

// Session expiry timer — check every 30s
const _sessionExpiryTimer = setInterval(() => {
  const now = Date.now();
  for (const [id, session] of monitoredSessions) {
    if (session.status === 'active' && now - session.lastActiveAt > SESSION_INACTIVITY_MS) {
      persistCompletedSession(session);
      monitoredSessions.delete(id);
    }
  }
}, 30000);
_sessionExpiryTimer.unref?.();

// ─────────────────────────────────────────────────
// Ensure prepare-commit-msg hook in repos with local core.hooksPath
// ─────────────────────────────────────────────────

const _hookedRepoPaths = new Set(); // avoid re-checking the same repo
const _HOOKED_REPO_PATHS_MAX = 200; // hard cap — typical user has < 50 repos

// Async because the IO ops (readFile / writeFile / mkdir / rename / chmod)
// run on EVERY /api/session-start for every freshly-discovered repo. The
// `_hookedRepoPaths.has` gate makes the work idempotent per resolvedLocal,
// but the FIRST hit per repo used to block the event loop on
// readFileSync(globalHookFile) + readFileSync(localHookFile) +
// writeFileSync(localHookFile) — non-trivial on cold cache or NFS.
// Caller is fire-and-forget (see line ~1761) so the absence of an `await`
// doesn't lose any work; the function logs its own outcome via `log()`.
async function ensureLocalCommitHook(cwd) {
  try {
    if (!settings.commitTokenUsage) return;
    // Check for local core.hooksPath override.
    // _runGitCached: this function is called on every UserPromptSubmit
    // (session-start). The first git call here used to be ~95% of the
    // execFileSync cost in steady state — by far the highest-frequency
    // candidate for caching. Below the `_hookedRepoPaths.has` gate makes
    // file-IO idempotent per repo; the cache makes the git lookups
    // idempotent per cwd within 30s.
    let localHooksPath;
    try {
      localHooksPath = _runGitCached(cwd, ['config', '--local', 'core.hooksPath']).trim();
    } catch { return; } // no local override
    if (!localHooksPath) return;

    // Resolve relative paths
    let repoRoot;
    try {
      repoRoot = _runGitCached(cwd, ['rev-parse', '--show-toplevel']).trim();
    } catch { return; }

    const resolvedLocal = localHooksPath.startsWith('/') ? localHooksPath : join(repoRoot, localHooksPath);

    // Skip if already checked this repo
    if (_hookedRepoPaths.has(resolvedLocal)) return;
    // Cap the set so a long-running dashboard doesn't accumulate
    // forever (e.g. CI runner that hits hundreds of repos).
    if (_hookedRepoPaths.size >= _HOOKED_REPO_PATHS_MAX) {
      // Drop the OLDEST entry (insertion order is preserved in Set).
      const oldest = _hookedRepoPaths.values().next().value;
      if (oldest !== undefined) _hookedRepoPaths.delete(oldest);
    }
    _hookedRepoPaths.add(resolvedLocal);

    // Check for global hooks path. This is a `git config --global` call —
    // no cwd argument needed, no injection vector — execFileSync still
    // bypasses shell interpolation. Suppress stderr the way the previous
    // `2>/dev/null` redirect did.
    let globalHooksPath;
    try {
      globalHooksPath = execFileSync('git', ['config', '--global', 'core.hooksPath'], {
        encoding: 'utf8', timeout: 3000, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
    } catch { return; }
    if (!globalHooksPath) return;
    globalHooksPath = globalHooksPath.replace(/^~/, process.env.HOME || '');

    // If local == global, no problem
    if (resolvedLocal === globalHooksPath) return;

    // Read the global hook content. Async — this runs once per repo but
    // sync IO on every session-start adds up across many repos.
    const globalHookFile = join(globalHooksPath, 'prepare-commit-msg');
    let globalHookContent;
    try {
      globalHookContent = await readFile(globalHookFile, 'utf8');
    } catch { return; } // missing global hook is the common path — bail silently
    if (!globalHookContent.includes('vdm-token-usage')) return;

    // Check if local hook already has our marker
    const localHookFile = join(resolvedLocal, 'prepare-commit-msg');
    let existingLocal = null;
    try { existingLocal = await readFile(localHookFile, 'utf8'); } catch { /* not present — that's fine */ }
    if (existingLocal != null) {
      if (existingLocal.includes('vdm-token-usage')) return; // already installed
      // Back up existing hook (still sync — only fires once per repo)
      try { renameSync(localHookFile, localHookFile + '.vdm-original'); } catch {}
    }

    // Copy global hook to local hooks dir.
    // mkdirSync stays sync — it's a single inode operation, finishes in
    // microseconds even on slow disks. writeFile is async because the
    // hook file can be 1-10KB and async lets the proxy keep serving
    // requests while the write drains.
    try { mkdirSync(resolvedLocal, { recursive: true }); } catch {}
    try {
      await writeFile(localHookFile, globalHookContent);
    } catch (e) {
      log('warn', `Failed to write local commit hook ${localHookFile}: ${e.message}`);
      return;
    }
    // chmod via execFileSync — argv[] form, no shell, no injection. The
    // previous shell-interpolated form was safe in practice (localHookFile
    // is composed from git config output) but this is defense-in-depth
    // and matches the rest of the file's exec hygiene.
    try {
      execFileSync('chmod', ['+x', localHookFile], { timeout: 2000, stdio: ['ignore', 'ignore', 'ignore'] });
    } catch {}
    log('tokens', `Installed commit hook in ${resolvedLocal} (local hooksPath override detected)`);
  } catch { /* silent — best effort */ }
}

// ─────────────────────────────────────────────────
// Token Usage Ring Buffer
// ─────────────────────────────────────────────────

const recentUsage = []; // { ts, inputTokens, outputTokens, cacheCreationInputTokens, cacheReadInputTokens, model, account, claimed }
// Raised from 2000. With per-Stop claim windows that can span minutes and
// parallel sub-agents producing multiple SSE responses per second, 2000
// ran out under burst traffic and silently shifted unclaimed entries off
// the head — the audit's F2 silent-data-loss bug.
const RECENT_USAGE_MAX = 50_000;
let _recentUsageOverflowWarned = 0;

function recordUsage(usage, account) {
  // Accept any response that carries non-zero tokens of ANY kind, including
  // cache creation/read responses. The previous filter only checked input
  // and output, so prompt-cache-only responses (billed) were silently
  // dropped — audit finding F1.
  if (!usage) return;
  const total =
    (usage.inputTokens || 0) +
    (usage.outputTokens || 0) +
    (usage.cacheCreationInputTokens || 0) +
    (usage.cacheReadInputTokens || 0);
  if (total <= 0) return;
  recentUsage.push({
    ts: usage.ts || Date.now(),
    inputTokens: usage.inputTokens || 0,
    outputTokens: usage.outputTokens || 0,
    cacheCreationInputTokens: usage.cacheCreationInputTokens || 0,
    cacheReadInputTokens: usage.cacheReadInputTokens || 0,
    model: usage.model,
    // Anthropic message UUID — surfaced via createUsageExtractor in lib.mjs.
    // Threaded through claimUsageInRange → appendTokenUsage so the
    // (sessionId, messageId) dedup can reject hook re-fires that would
    // otherwise double-count the same assistant turn.
    messageId: usage.messageId || null,
    account,
    claimed: false,
  });
  // Warn before silently dropping unclaimed entries on overflow. Throttled
  // to one log line per 60 s to avoid spam under sustained overflow.
  while (recentUsage.length > RECENT_USAGE_MAX) {
    const dropped = recentUsage.shift();
    if (dropped && !dropped.claimed) {
      const now = Date.now();
      if (now - _recentUsageOverflowWarned > 60_000) {
        _recentUsageOverflowWarned = now;
        log('warn', `recentUsage ring buffer overflow — dropping unclaimed entries (cap ${RECENT_USAGE_MAX}). Increase RECENT_USAGE_MAX or check that sessions are claiming.`);
      }
    }
  }
}

function claimUsageInRange(startTs, endTs) {
  const claimed = [];
  for (const entry of recentUsage) {
    if (!entry.claimed && entry.ts >= startTs && entry.ts <= endTs) {
      entry.claimed = true;
      claimed.push(entry);
    }
  }
  return claimed;
}

/**
 * When inside a Claude Code git worktree, the checked-out branch is an
 * auto-generated name like `worktree-jolly-dazzling-dolphin`.  Resolve it
 * back to the real feature branch so token usage is attributed correctly.
 */
function _resolveWorktreeBranch(cwd, detectedBranch) {
  if (!detectedBranch.startsWith('worktree-')) return detectedBranch;
  // _runGitCached: gitDir/commonDir are quasi-static per cwd (only change
  // on worktree add/remove). branch--points-at HEAD and the log walk DO
  // change as the user commits, but for a cwd that's currently checked
  // into a Claude-Code worktree, the resolved real branch flips at most
  // a few times per session — 30s TTL is well within the noise floor.
  try {
    const gitDir = _runGitCached(cwd, ['rev-parse', '--path-format=absolute', '--git-dir']).trim();
    const commonDir = _runGitCached(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']).trim();
    if (gitDir === commonDir) return detectedBranch;
  } catch { return detectedBranch; }

  // Strategy 1: find a non-worktree branch at the exact same commit
  try {
    const candidates = _runGitCached(cwd, ['branch', '--points-at', 'HEAD'])
      .trim().split('\n')
      .map(b => b.replace(/^[*+]?\s+/, '').trim())
      .filter(b => b && !b.startsWith('worktree-'));
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) return candidates.find(b => b.includes('/')) || candidates[0];
  } catch { /* ignore */ }

  // Strategy 2: walk recent commits for the closest decorated non-worktree branch
  try {
    const lines = _runGitCached(cwd, ['log', '--format=%D', '--max-count=30']).trim().split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      const refs = line.split(',').map(r => r.trim())
        .filter(r => r && !r.startsWith('HEAD') && !r.startsWith('worktree-') && !r.startsWith('origin/') && !r.startsWith('tag:'));
      if (refs.length > 0) return refs.find(r => r.includes('/')) || refs[0];
    }
  } catch { /* ignore */ }

  return detectedBranch;
}

// ─────────────────────────────────────────────────
// Session Tracking
// ─────────────────────────────────────────────────

// Phase D — pendingSessions entries grew from
//   { repo, branch, commitHash, cwd, startedAt }
// to
//   { repo, branch, commitHash, cwd, startedAt,
//     parentSessionId,    // sub-agent → parent linkage (null for primary sessions)
//     agentType,          // sub-agent matcher value (null for primary)
//     lastBatchToolNames, // most recent PostToolBatch tool list (gated by perToolAttribution)
//     teamId }            // agent-teams rollup (reserved; null until §4 wiring)
//
// Existing call sites that didn't set these fields rely on the spread
// pattern in registerSubagent / appendTokenUsage callers — `?? null`
// always wins so a session built by /api/session-start (which doesn't
// touch the new fields) becomes a primary session row with parentSessionId
// === null on persist.
const pendingSessions = new Map();

// H11 fix — prune stale pendingSessions periodically. Cleanup was previously
// only triggered inside /api/session-start (24h-stale prune). A crashed CC
// session leaks its entry until the NEXT session-start arrives, which on a
// quiet machine could be hours-to-days later. Runs every 5 minutes; same
// 24h staleness threshold + same _autoClaimSession-before-delete behavior
// as the inline prune at /api/session-start.
function _prunePendingSessions() {
  const staleThreshold = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, s] of pendingSessions) {
    if (s.startedAt < staleThreshold) {
      try { _autoClaimSession(id, s); } catch { /* best-effort */ }
      pendingSessions.delete(id);
    }
  }
}
const _pendingSessionsGcTimer = setInterval(_prunePendingSessions, 5 * 60 * 1000);
_pendingSessionsGcTimer.unref?.();

// Phase 6 (CL-3): SubagentStop and SessionEnd hooks may fire with a
// session_id that pendingSessions has never seen — for SubagentStop
// because Claude Code subagents (CLAUDE_CODE_FORK_SUBAGENT=1) get their
// own session_id distinct from the parent's; for SessionEnd because the
// user might quit before the dashboard ever saw a session-start hook.
// Resolve in this order:
//   (a) If the hook payload includes a parent session id field
//       (parent_session_id, parentSessionId, transcript_id are all known
//       Claude Code shapes across CC 2.1.117/120/121), use that.
//   (b) Otherwise fall back to the most-recently-active session in the
//       same cwd as the hook payload — the orchestrator that spawned the
//       subagent has the strongest claim on the unattributed usage.
//   (c) If neither resolves, return null and let the caller log the
//       drop in activity log so the user can see it.
function _resolveSessionForHook(payload) {
  if (!payload) return null;
  const sid = payload.session_id;
  if (sid && pendingSessions.has(sid)) return sid;
  const parentId = payload.parent_session_id || payload.parentSessionId || payload.transcript_id;
  if (parentId && pendingSessions.has(parentId)) return parentId;
  // Fallback (b): most-recently-active session in the same cwd.
  const cwd = payload.cwd;
  if (cwd) {
    let bestId = null, bestStart = -Infinity;
    for (const [id, s] of pendingSessions) {
      if (s.cwd === cwd && s.startedAt > bestStart) {
        bestStart = s.startedAt;
        bestId = id;
      }
    }
    if (bestId) return bestId;
  }
  return null;
}

// Phase 6 (Item 8h): shared logic between /api/session-stop and
// /api/session-end. Idempotent — unknown sessions return claimed:0
// without erroring. CL-3 attribution: if the incoming session_id is
// unknown, try to resolve it via parent_session_id / cwd before dropping.
function _claimAndPersistForSession(sessionId, payload, kind /* 'stop' | 'end' */) {
  let session = pendingSessions.get(sessionId);
  let resolvedId = sessionId;
  if (!session) {
    const fallbackId = _resolveSessionForHook(payload);
    if (fallbackId) {
      resolvedId = fallbackId;
      session = pendingSessions.get(fallbackId);
      log('tokens', `Session ${kind}: ${sessionId.slice(0, 8)}… unknown — attributing to parent/cwd ${fallbackId.slice(0, 8)}…`);
    }
  }
  if (!session) {
    // Unknown sessionId AND no parent/cwd match — log to activity log so
    // the user can see unattributed usage in the UI instead of silently
    // dropping it.
    if (kind === 'end') {
      log('tokens', `Session end: ${sessionId.slice(0, 8)}… (not found — already auto-claimed)`);
    } else {
      log('tokens', `Session ${kind}: ${sessionId.slice(0, 8)}… (not found — may have been auto-claimed)`);
      try {
        logActivity('session-unattributed', { sessionId, kind, cwd: payload?.cwd || null });
      } catch { /* best-effort */ }
    }
    return { claimed: 0 };
  }
  const stopAt = Date.now();
  const claimed = claimUsageInRange(session.startedAt, stopAt);
  // Phase D — when this is a CL-3 fallback (resolvedId !== sessionId), we
  // attribute to the parent session BUT preserve the sub-agent's session_id
  // and synthesise parentSessionId so the on-disk row still tells the user
  // "this came from a sub-agent of <parent>". When the resolved id matches
  // the wire id, we use the session's own attribution (it was registered
  // either as a primary session via /api/session-start or as a sub-agent
  // via /api/subagent-start — either way `_attachSessionAttribution`
  // already does the right thing).
  for (const entry of claimed) {
    let row;
    if (resolvedId === sessionId) {
      row = _attachSessionAttribution(sessionId, session, {
        ts: entry.ts,
        repo: session.repo,
        branch: session.branch ?? null,
        commitHash: session.commitHash,
        model: entry.model,
        inputTokens: entry.inputTokens,
        outputTokens: entry.outputTokens,
        cacheReadInputTokens: entry.cacheReadInputTokens || 0,
        cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
        messageId: entry.messageId ?? null,
        account: entry.account,
      });
    } else {
      // Fallback path — sub-agent's session_id never registered. Tag the
      // row with the sub-agent's id (so the user sees the right cardinality)
      // and parentSessionId === resolvedId. agentType stays null because we
      // never saw the SubagentStart hook for this sub-agent — payload type
      // is unknown.
      const baseEntry = _attachSessionAttribution(sessionId, session, {
        ts: entry.ts,
        repo: session.repo,
        branch: session.branch ?? null,
        commitHash: session.commitHash,
        model: entry.model,
        inputTokens: entry.inputTokens,
        outputTokens: entry.outputTokens,
        cacheReadInputTokens: entry.cacheReadInputTokens || 0,
        cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
        messageId: entry.messageId ?? null,
        account: entry.account,
      });
      row = { ...baseEntry, parentSessionId: resolvedId, agentType: null };
    }
    appendTokenUsage(row);
  }
  // Only delete the pendingSessions entry on a primary stop/end for the
  // matching id — a subagent-stop attributed to its parent must NOT
  // delete the parent's session.
  if (resolvedId === sessionId) {
    pendingSessions.delete(sessionId);
  } else if (claimed.length > 0) {
    // Advance startedAt so the parent doesn't re-claim the same window
    // when its own stop arrives.
    session.startedAt = stopAt;
  }
  log('tokens', `Session ${kind}: ${sessionId.slice(0, 8)}… (claimed ${claimed.length} entries)`);
  return { claimed: claimed.length };
}

// Claim and persist usage for a session (used by auto-claim and stale pruning)
function _autoClaimSession(sessionId, session) {
  // Re-read branch before persisting (handles worktree branch switches).
  // _runGitCached: this runs from the periodic auto-persist timer (every
  // 2 min) and from the 24h stale-prune sweep — both are background loops
  // where 30s-stale branch info is acceptable in exchange for not blocking
  // the event loop on every iteration.
  if (session.cwd) {
    try {
      const cur = _resolveWorktreeBranch(session.cwd, _runGitCached(session.cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
      if (cur && cur !== session.branch) {
        session.branch = cur;
        session.commitHash = _runGitCached(session.cwd, ['rev-parse', '--short', 'HEAD']).trim();
      }
    } catch { /* ignore */ }
  }
  const claimed = claimUsageInRange(session.startedAt, Date.now());
  for (const entry of claimed) {
    appendTokenUsage(_attachSessionAttribution(sessionId, session, {
      ts: entry.ts,
      repo: session.repo,
      // Phase 6: branchAtWriteTime null-safe.
      branch: session.branch ?? null,
      commitHash: session.commitHash,
      model: entry.model,
      inputTokens: entry.inputTokens,
      outputTokens: entry.outputTokens,
      cacheReadInputTokens: entry.cacheReadInputTokens || 0,
      cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
      messageId: entry.messageId ?? null,
      account: entry.account,
    }));
  }
  if (claimed.length > 0) {
    log('tokens', `Auto-claimed ${claimed.length} entries for session ${sessionId.slice(0, 8)}…`);
  }
}

// Periodically auto-persist unclaimed usage so the Tokens tab shows data
// even for long-running sessions that haven't called session-stop yet.
const TOKEN_AUTO_PERSIST_INTERVAL = 2 * 60 * 1000; // every 2 minutes
const _tokenAutoPersistTimer = setInterval(() => {
  // TIMER-2: wrap the body in try/catch so a single bad session
  // (corrupt cwd, _runGitCached >4096-char rejection, atomicWriteFileSync
  // ENOSPC, etc.) doesn't prevent the OTHER sessions' entries from
  // persisting on this tick. The previous behaviour: one throw and
  // every session in this iteration was skipped, with no log.
  try {
  // For each active session, claim any unclaimed entries and persist them.
  // Update startedAt so we don't double-count on next interval.
  for (const [id, session] of pendingSessions) {
    const now = Date.now();
    // Re-read branch before persisting (handles worktree branch switches).
    // _runGitCached: 2-minute timer × N active sessions could otherwise
    // block the event loop for 50ms+ per iteration; with 30s TTL the cost
    // collapses to one git call per cwd per period.
    if (session.cwd) {
      try {
        const cur = _resolveWorktreeBranch(session.cwd, _runGitCached(session.cwd, ['rev-parse', '--abbrev-ref', 'HEAD']).trim());
        if (cur && cur !== session.branch) {
          log('tokens', `Periodic: session ${id.slice(0, 8)}… branch updated: ${session.branch} → ${cur}`);
          session.branch = cur;
          session.commitHash = _runGitCached(session.cwd, ['rev-parse', '--short', 'HEAD']).trim();
        }
      } catch { /* ignore */ }
    }
    const claimed = claimUsageInRange(session.startedAt, now);
    for (const entry of claimed) {
      appendTokenUsage(_attachSessionAttribution(id, session, {
        ts: entry.ts,
        repo: session.repo,
        // Phase 6: branchAtWriteTime null-safe.
        branch: session.branch ?? null,
        commitHash: session.commitHash,
        model: entry.model,
        inputTokens: entry.inputTokens,
        outputTokens: entry.outputTokens,
        cacheReadInputTokens: entry.cacheReadInputTokens || 0,
        cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
        messageId: entry.messageId ?? null,
        account: entry.account,
      }));
    }
    if (claimed.length > 0) {
      session.startedAt = now; // advance so we don't re-claim
      log('tokens', `Periodic persist: ${claimed.length} entries for session ${id.slice(0, 8)}…`);
    }
  }
  // Unclaimed entries outside any session's time range are left in the ring
  // buffer — they'll be claimed by session-stop, or age out naturally.
  // No (unknown) attribution: better to lose data than misattribute it.
  } catch (e) {
    try { log('warn', `_tokenAutoPersistTimer iteration failed: ${e.message}`); } catch {}
  }
}, TOKEN_AUTO_PERSIST_INTERVAL);
_tokenAutoPersistTimer.unref?.();

// ─────────────────────────────────────────────────
// Token Usage Storage (token-usage.json)
// ─────────────────────────────────────────────────

// Retention defaults — overridable per-user via /api/settings or vdm
// `config token-usage-max-age` / `token-usage-max-entries`. Settings
// take precedence at runtime (see _tokenUsageMaxEntries / *MaxAge
// helpers below).
const TOKEN_USAGE_MAX_ENTRIES = 50_000;
const TOKEN_USAGE_MAX_AGE = 90 * 24 * 60 * 60 * 1000; // 90 days
function _tokenUsageMaxEntries() {
  const v = settings && Number.isFinite(settings.tokenUsageMaxEntries) ? settings.tokenUsageMaxEntries : 0;
  return v > 0 ? v : TOKEN_USAGE_MAX_ENTRIES;
}
function _tokenUsageMaxAgeMs() {
  const days = settings && Number.isFinite(settings.tokenUsageMaxAgeDays) ? settings.tokenUsageMaxAgeDays : 0;
  return days > 0 ? days * 24 * 60 * 60 * 1000 : TOKEN_USAGE_MAX_AGE;
}
let _tokenUsageCache = null;
// Debounced disk-write coalescer. Each appendTokenUsage call updates
// the in-memory cache + flag and schedules a single setTimeout that
// eventually writes the WHOLE current array. At sustained 10 row/s
// traffic this collapses 10 disk writes/second into 2 writes/second
// (the default 500 ms debounce). The previous implementation wrote
// the full file (50k rows × ~400B = 20 MB pretty-printed) on every
// single append, blocking the event loop and thrashing the disk.
let _tokenUsageDirty = false;
let _tokenUsageFlushTimer = null;
const TOKEN_USAGE_FLUSH_MS = 500;

function loadTokenUsage() {
  if (_tokenUsageCache) return _tokenUsageCache;
  // L9 — distinguish three distinct disk states so a real disk error
  // doesn't silently masquerade as "missing file = empty start":
  //   (a) file does not exist → start with an empty array (expected on
  //       fresh installs).
  //   (b) file exists but content is malformed JSON OR the parsed value
  //       isn't an array → log a warn, then start empty so the dashboard
  //       boots. If we crashed here, the dashboard would be unbootable
  //       on a single corrupt file.
  //   (c) file exists, JSON is well-formed, but readFileSync threw a
  //       real I/O error (EACCES, EIO, EBUSY) → log a warn so the
  //       operator sees the failure rather than silently treating it as
  //       case (b).
  if (!existsSync(TOKEN_USAGE_FILE)) {
    _tokenUsageCache = [];
    return _tokenUsageCache;
  }
  let raw;
  try {
    raw = readFileSync(TOKEN_USAGE_FILE, 'utf8');
  } catch (e) {
    log('warn', `loadTokenUsage: read failed (${e.code || 'EUNKNOWN'}): ${e.message}`);
    _tokenUsageCache = [];
    return _tokenUsageCache;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    log('warn', `loadTokenUsage: JSON parse failed (${e.message}); starting empty`);
    _tokenUsageCache = [];
    return _tokenUsageCache;
  }
  if (!Array.isArray(parsed)) {
    log('warn', `loadTokenUsage: top-level JSON must be an array, got ${typeof parsed}; starting empty`);
    _tokenUsageCache = [];
    return _tokenUsageCache;
  }
  _tokenUsageCache = parsed;
  return _tokenUsageCache;
}

/**
 * Phase D — wrapper around mergeSessionAttribution (lib.mjs) that reads
 * the perToolAttribution gate from current settings. Centralises the rule
 * so the five appendTokenUsage call sites (flush endpoint,
 * _claimAndPersistForSession, _autoClaimSession, periodic timer, shutdown
 * handler) all attach the same attribution.
 *
 * Per-tool attribution (Refinement 1) is gated by settings.perToolAttribution.
 * When the gate is OFF, mergeSessionAttribution returns null tool/mcpServer.
 */
function _attachSessionAttribution(sessionId, session, entry) {
  return mergeSessionAttribution(sessionId, session, entry, {
    perToolAttributionEnabled: settings && settings.perToolAttribution === true,
  });
}

/**
 * Persist a token-usage entry to disk (token-usage.json).
 *
 * Schema (Phase D — extended for sub-agent attribution + compaction):
 *   {
 *     // Always-present base fields
 *     ts: number,                    // ms epoch when usage was observed
 *     type: 'usage'|'compact_boundary', // row kind. Defaults to 'usage'
 *                                    //   so existing rows on disk
 *                                    //   (pre-Phase-D) remain valid; the
 *                                    //   reader path treats absent type
 *                                    //   as 'usage' for backward compat.
 *     repo: string,                  // git remote-name or '(non-git)'
 *     branch: string|null,           // branchAtWriteTime — git branch at
 *                                    //   the moment of persistence; null
 *                                    //   if no git, captured eagerly at
 *                                    //   session-start and re-read at
 *                                    //   periodic-flush / session-stop /
 *                                    //   shutdown to reflect mid-session
 *                                    //   branch switches.
 *     commitHash: string,            // short HEAD SHA at write time
 *
 *     // Usage rows (type === 'usage')
 *     model: string,                 // anthropic model id
 *     inputTokens: number,
 *     outputTokens: number,
 *     account: string,               // account label/name attribution
 *     sessionId: string|null,        // session_id of the registered window
 *
 *     // Phase D — sub-agent attribution (Refinement 3)
 *     parentSessionId: string|null,  // parent session for sub-agents (null for
 *                                    //   primary sessions). Populated from
 *                                    //   the SubagentStart hook payload.
 *     agentType: string|null,        // 'Bash' | 'Explore' | 'Plan' | custom.
 *                                    //   Distinguishes parallel sub-agents
 *                                    //   from the same parent.
 *
 *     // Phase D — per-tool attribution (Refinement 1, gated)
 *     tool: string|null,             // comma-joined tool names from the most
 *                                    //   recent PostToolBatch hook (when
 *                                    //   perToolAttribution: true). Null when
 *                                    //   the gate is off OR for the
 *                                    //   pre-tool LLM turn (planning step).
 *     mcpServer: string|null,        // server segment of an mcp__ tool name.
 *                                    //   Set when `tool` starts with mcp__.
 *
 *     // Phase D — agent-teams rollup (Refinement 4, stub)
 *     teamId: string|null,           // ~/.claude/teams/<team>/config.json id.
 *                                    //   Schema field reserved; wiring is a
 *                                    //   later-phase task per the contract.
 *
 *     // Compact-boundary rows (type === 'compact_boundary')
 *     trigger: string|null,          // 'manual' | 'auto' (PreCompact/PostCompact matcher)
 *     preTokens: number|null,        // context size before compaction
 *     postTokens: number|null,       // context size after (PostCompact only)
 *   }
 *
 * Existing readers that pre-date these fields tolerate the addition (JSON
 * consumers ignore unknown keys). Aggregation readers MUST skip rows where
 * type === 'compact_boundary' so the marker rows aren't summed as usage —
 * see `isUsageRow` in lib.mjs.
 *
 * Callers MUST pass `branch: session.branch ?? null` — a literal `null`
 * sentinel beats `undefined` because JSON.stringify drops undefined keys
 * and downstream filters that test `e.branch === null` would silently
 * miss those entries.
 */
// Synthetic-model detector — matches CC's filtering of internal control
// messages from billable token totals (utils/stats.ts:313-316 in CC v2.1.89:
// "Skip synthetic messages — they are internal and shouldn't appear in
// stats"). The exact sentinel value isn't documented but observable
// patterns are angle-bracket-wrapped tokens (e.g. "<synthetic>") that no
// real Anthropic model name uses. Real models all start with "claude-".
const _SYNTHETIC_MODEL_RE = /^<.*>$/;
function _isSyntheticModel(model) {
  if (!model || typeof model !== 'string') return false;
  return _SYNTHETIC_MODEL_RE.test(model);
}

// Per-message dedup — rejects token-usage rows whose Anthropic message ID
// has already been recorded for the same session. This catches the common
// hook-re-fire bug class: dashboard restart mid-turn → Stop fires twice;
// duplicate hook delivery from CC; manual replay during debugging.
//
// The seen-set is bounded to _SEEN_MESSAGES_MAX entries with a 24h TTL.
// Lazy GC on insert (no timer) — overhead is amortised over inserts.
const _SEEN_MESSAGES_MAX = 10_000;
const _SEEN_MESSAGES_TTL_MS = 24 * 60 * 60 * 1000;
const _seenMessageEntries = new Map();   // key → ts (ms)
function _isDuplicateMessage(sessionId, messageId) {
  if (!messageId) return false;          // no ID → can't dedup, accept
  const key = `${sessionId || '_unknown'}|${messageId}`;
  if (_seenMessageEntries.has(key)) return true;
  // GC if oversized: drop expired entries, then drop oldest 25% by
  // insertion order if still over budget.
  if (_seenMessageEntries.size >= _SEEN_MESSAGES_MAX) {
    const cutoff = Date.now() - _SEEN_MESSAGES_TTL_MS;
    for (const [k, ts] of _seenMessageEntries) {
      if (ts < cutoff) _seenMessageEntries.delete(k);
    }
    if (_seenMessageEntries.size >= _SEEN_MESSAGES_MAX) {
      const target = Math.floor(_SEEN_MESSAGES_MAX * 0.75);
      let toDrop = _seenMessageEntries.size - target;
      for (const k of _seenMessageEntries.keys()) {
        if (toDrop-- <= 0) break;
        _seenMessageEntries.delete(k);
      }
    }
  }
  _seenMessageEntries.set(key, Date.now());
  return false;
}

function appendTokenUsage(entry) {
  // Phase D — normalise the entry against the extended schema. Every new
  // nullable field defaults to null (NOT undefined — JSON.stringify drops
  // undefined keys). type defaults to 'usage' so callers that pre-date
  // Phase D don't have to thread the field through. Any caller passing
  // explicit null/undefined for these fields is honored (null wins).
  const normalized = {
    ts: entry.ts,
    type: entry.type || 'usage',
    repo: entry.repo,
    branch: entry.branch ?? null,
    commitHash: entry.commitHash,
    model: entry.model,
    inputTokens: entry.inputTokens,
    outputTokens: entry.outputTokens,
    cacheReadInputTokens: entry.cacheReadInputTokens || 0,
    cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
    account: entry.account,
    sessionId: entry.sessionId ?? null,
    // Phase D additions
    parentSessionId: entry.parentSessionId ?? null,
    agentType: entry.agentType ?? null,
    tool: entry.tool ?? null,
    mcpServer: entry.mcpServer ?? null,
    teamId: entry.teamId ?? null,
    // Anthropic message UUID — null if SSE never delivered a
    // message_start (e.g. abort before headers, non-streaming
    // responses) or if entry came from a non-proxy code path.
    messageId: entry.messageId ?? null,
    // compact_boundary fields (null on usage rows)
    trigger: entry.trigger ?? null,
    preTokens: entry.preTokens ?? null,
    postTokens: entry.postTokens ?? null,
  };
  // Filter synthetic-model rows (CC's internal control messages — never
  // billed, must not pollute totals). Compact-boundary rows are exempt:
  // they're not usage rows, they don't carry a model, and the
  // <whatever> sentinel test never matches their null.
  if (normalized.type === 'usage' && _isSyntheticModel(normalized.model)) {
    log('tokens-filter', `synthetic model "${normalized.model}" — skipped`);
    return;
  }
  // Dedup by (sessionId, messageId). Compact-boundary rows skip dedup
  // because they don't have a messageId by design.
  if (normalized.type === 'usage' && _isDuplicateMessage(normalized.sessionId, normalized.messageId)) {
    log('tokens-dedup', `duplicate messageId ${normalized.messageId} for session ${(normalized.sessionId || '_unknown').slice(0, 12)} — skipped`);
    return;
  }
  const usage = loadTokenUsage();
  usage.push(normalized);
  // Prune old entries — honour user-set retention from settings.
  const cutoff = Date.now() - _tokenUsageMaxAgeMs();
  const maxEntries = _tokenUsageMaxEntries();
  const pruned = usage.filter(e => e.ts >= cutoff);
  const final = pruned.length > maxEntries
    ? pruned.slice(pruned.length - maxEntries)
    : pruned;
  // Update the cache immediately (readers see the new row) but DEBOUNCE
  // the disk write — at sustained traffic the 50K-row pretty-printed
  // JSON write was thrashing the disk on every append.
  _tokenUsageCache = final;
  _tokenUsageDirty = true;
  if (!_tokenUsageFlushTimer) {
    _tokenUsageFlushTimer = setTimeout(_flushTokenUsage, TOKEN_USAGE_FLUSH_MS);
    _tokenUsageFlushTimer.unref?.();
  }
}

// Single point that actually writes token-usage.json. Always writes
// the current cache (not the closed-over `final` from append) so the
// last-write-wins semantics match what reads will see. Compact JSON
// (no `,2` indent) — cuts file size ~30% and write latency ~50%.
function _flushTokenUsage() {
  _tokenUsageFlushTimer = null;
  if (!_tokenUsageDirty) return;
  _tokenUsageDirty = false;
  try {
    atomicWriteFileSync(TOKEN_USAGE_FILE, JSON.stringify(_tokenUsageCache || []));
  } catch (e) {
    log('error', `Failed to write token-usage.json: ${e.message}`);
    // Re-set the dirty flag so the next append retries the write.
    _tokenUsageDirty = true;
  }
}

// Force an immediate flush — used by shutdown() so a pending debounced
// write doesn't get lost when the process exits.
function flushTokenUsageSync() {
  if (_tokenUsageFlushTimer) {
    clearTimeout(_tokenUsageFlushTimer);
    _tokenUsageFlushTimer = null;
  }
  _flushTokenUsage();
}

/**
 * Phase D — append a compact_boundary marker row from PreCompact/PostCompact.
 *
 * The marker is recorded in the same token-usage.json buffer so the dashboard
 * can render compaction tick marks alongside usage rows on the same time axis.
 * Callers MUST NOT pass model/inputTokens/outputTokens — those are the usage
 * row's territory; here they're left null and aggregation readers skip the
 * row via isUsageRow (lib.mjs).
 *
 * Row shape is built by buildCompactBoundaryEntry (lib.mjs) which is unit-tested.
 */
function appendCompactBoundary({ sessionId, repo, branch, commitHash, trigger, preTokens, postTokens, account }) {
  appendTokenUsage(buildCompactBoundaryEntry({
    ts: Date.now(),
    sessionId, repo, branch, commitHash, trigger, preTokens, postTokens, account,
  }));
}

// ─────────────────────────────────────────────────
// Pipe helper — waits for stream to complete
// ─────────────────────────────────────────────────

function pipeAndWait(src, dst) {
  return new Promise(resolve => {
    let resolved = false;
    const done = () => { if (!resolved) { resolved = true; resolve(); } };
    src.on('end', done);
    src.on('error', done);
    dst.on('close', done);
    dst.on('error', done);
    src.pipe(dst);
  });
}

// Phase F audit B1/D1 — Run a streaming continuation that handleProxyRequest
// returned. This lives OUTSIDE the serialization queue so a single long SSE
// stream cannot block other queued requests for its full lifetime.
//
// Continuation kinds:
//   - 'sse'  — text/event-stream success path. Pipe through usage extractor,
//              call recordUsage() when stream ends, fire session-monitor
//              timeline update.
//   - 'pipe' — non-SSE success path OR 529 server-overload pass-through.
//              Plain pipe with end/error/close handlers.
//
// Errors during streaming are logged + best-effort socket close. The caller
// (proxyServer's catch block) sees the rejection and writes a 502 if no
// headers were sent, otherwise just logs and ends the socket.
async function _runStreamingContinuation(cont, clientRes) {
  if (!cont) return;
  // Phase F audit M1 — defensive cleanup. If anything between the descriptor
  // arriving and the body pipe being established throws synchronously
  // (createUsageExtractor, _streamPipeline construction, etc.) the proxyRes
  // is already an open upstream socket holding kernel buffers. Without this
  // guard the request hangs until the watchdog timer fires (PROXY_TIMEOUT +
  // 5s). With this guard, the socket is destroyed immediately on failure.
  try {
  if (cont.kind === 'sse') {
    const { proxyRes, body, acctName } = cont;
    const extractor = createUsageExtractor();
    // Phase F audit A2 — use stream.pipeline() for the SSE chain. The previous
    // `proxyRes.pipe(extractor).pipe(clientRes)` + manual `extractor.on('end')`
    // await had three race windows where the per-account permit (released
    // on proxyRes.on('end'|'error'|'close')) could leak when the client
    // aborted mid-stream. pipeline() guarantees that an error or close in
    // any of the three streams propagates to the others via destroy(), so
    // proxyRes is always destroyed when the chain ends — which fires its
    // 'close' event and reliably releases the permit.
    // Track stream metrics for the forensic log entry that fires if
    // the client disconnects mid-stream.
    const _sseStartedAt = Date.now();
    let _sseBytesOut = 0;
    let _clientClosedEarly = false;
    extractor.on('data', chunk => { _sseBytesOut += chunk.length; });
    clientRes.on('close', () => {
      // 'close' fires on graceful end too; only treat as early close
      // if proxyRes hasn't ended yet.
      if (proxyRes && proxyRes.readableEnded === false && !proxyRes.destroyed) {
        _clientClosedEarly = true;
      }
    });
    await new Promise(resolve => {
      _streamPipeline(proxyRes, extractor, clientRes, () => {
        // Errors here are expected on client-abort; we don't surface them
        // because headers were already sent. The permit-release wiring on
        // proxyRes (in forwardToAnthropic) handles cleanup.
        resolve();
      });
    });
    // Phase F audit M2 — pipeline() calls destroy() (not end()) on abort/error,
    // bypassing the extractor's _flush callback and silently losing the final
    // message_delta. finishParsing() is idempotent: on the success path the
    // flush already ran and this is a no-op; on the abort path it processes
    // the trailing-buffer that destroy() would have orphaned.
    try { extractor.finishParsing(); } catch (e) {
      try { log('debug', `extractor.finishParsing() failed: ${e.message}`); } catch {}
    }
    recordUsage(extractor.getUsage(), acctName);
    // Forensic event — log mid-stream client disconnects so the user
    // can investigate "why are my long Opus turns dropping". Records
    // the bytes that DID make it through and the duration before close.
    if (_clientClosedEarly) {
      try {
        logForensicEvent('client_disconnect', {
          account_name: acctName,
          bytes_streamed: _sseBytesOut,
          duration_ms: Date.now() - _sseStartedAt,
          partial_usage: extractor.getUsage(),
        });
      } catch {}
    }
    setImmediate(() => {
      try {
        if (!settings.sessionMonitor) return;
        if (body.length > SESSION_BODY_MAX) {
          const rawPrefix = body.toString('utf8', 0, Math.min(body.length, 4096));
          const cwdMatch = rawPrefix.match(/working directory:\s*(.+)/i);
          if (cwdMatch) {
            const cwd = cwdMatch[1].trim().split('\\n')[0].trim();
            const sid = deriveSessionId(cwd, acctName);
            const s = monitoredSessions.get(sid);
            if (s) s.lastActiveAt = Date.now();
          }
          return;
        }
        const bodyObj = JSON.parse(body.toString('utf8'));
        updateSessionTimeline(bodyObj, acctName, extractor.getUsage());
      } catch (e) {
        // Body parse / timeline-update can legitimately fail (malformed JSON,
        // body too large was handled above, etc.) but a fully-silent catch
        // hides regressions in updateSessionTimeline. Log at debug-level so
        // it shows up only when log filtering is loosened.
        try { log('debug', `session-monitor post-stream update failed: ${e.message}`); } catch {}
      }
    });
    return;
  }
  if (cont.kind === 'pipe') {
    await pipeAndWait(cont.proxyRes, clientRes);
    return;
  }
  } catch (e) {
    // Synchronous escape on the streaming-continuation handoff. Destroy the
    // upstream response so the per-account permit (held by forwardToAnthropic
    // until 'end'|'error'|'close') is released promptly. Re-throw so the
    // outer proxyServer catch block can decide whether to write a 502.
    try { if (cont && cont.proxyRes) cont.proxyRes.destroy(e); } catch {}
    try { log('error', `_runStreamingContinuation handoff threw: ${e.message}`); } catch {}
    throw e;
  }
}

// ── Proxy server ──

const proxyServer = createServer((clientReq, clientRes) => {
  // DNS-rebind defense — same rationale as on the dashboard server.
  // The proxy receives ALL Anthropic API traffic, including request
  // bodies that contain the user's prompts. A rebinding attacker could
  // POST to localhost:3334/v1/messages with their own bearer to steal
  // tokens, or read responses via SSE. Reject non-localhost Hosts up
  // front; legitimate Claude Code traffic always sends Host: localhost:<port>
  // because ANTHROPIC_BASE_URL is http://localhost:<port>.
  if (!_isLocalhostHost(clientReq.headers.host, PROXY_PORT)) {
    clientRes.writeHead(421, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ error: 'misdirected request: invalid Host header' }));
    return;
  }
  // Health checks bypass the serialization queue
  if (clientReq.method === 'GET' && clientReq.url === '/health') {
    handleProxyRequest(clientReq, clientRes).catch(err => {
      log('error', `Unhandled proxy error: ${err.message}\n${err.stack}`);
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Proxy error: ${err.message}` } }));
      }
    });
    return;
  }

  // Phase F audit B1/D1 — handleProxyRequest may return a "streaming
  // continuation" descriptor for the success/529 paths. The serialization
  // queue releases at handleProxyRequest's resolution (decision boundary);
  // the body pipe then runs OUTSIDE the queue via _runStreamingContinuation.
  // For non-streaming responses (passthrough, 429-exhausted, 401, etc.)
  // handleProxyRequest writes the response itself and returns undefined.
  withSerializationQueue(() => handleProxyRequest(clientReq, clientRes))
    .then(cont => _runStreamingContinuation(cont, clientRes))
    .catch(err => {
      if (err.message === 'queue_timeout') {
        log('warn', 'Request timed out in serialization queue');
        // Forensic event — captures everything you'd want to know to
        // reconstruct WHY the queue timed out: queue depth, in-flight
        // count, and the configured timeout that was hit.
        try {
          const stats = (typeof getQueueStats === 'function') ? getQueueStats() : {};
          logForensicEvent('queue_saturation', {
            queued: stats.queued,
            inflight: stats.inflight,
            queueTimeoutMs: QUEUE_TIMEOUT_MS,
            requestDeadlineMs: REQUEST_DEADLINE_MS,
            serializeRequests: !!settings.serializeRequests,
            serializeMaxConcurrent: settings.serializeMaxConcurrent || 1,
            url: clientReq.url,
          });
        } catch {}
        // Safeguard A — feed the breaker. Trip + auto-disable serialize
        // when the count crosses threshold within window.
        try { _recordQueueTimeout(); } catch (e) {
          log('warn', `_recordQueueTimeout failed: ${e.message}`);
        }
        if (!clientRes.headersSent) {
          // Phase F — return 503 + overloaded_error (with explicit "[vdm proxy]"
          // prefix in message and x-vdm-proxy header) so Claude Code's retry
          // logic treats this as a transient backpressure event from OUR proxy,
          // not a timeout from Anthropic. Without this, CC reported the proxy's
          // own queue-full as "Anthropic unresponsive".
          clientRes.writeHead(503, {
            'Content-Type': 'application/json',
            'Retry-After': '5',
            'x-vdm-proxy': 'true',
          });
          clientRes.end(JSON.stringify({
            type: 'error',
            error: {
              type: 'overloaded_error',
              message: '[vdm proxy] request queued too long (serialization queue timeout). Anthropic upstream was not contacted.',
            },
          }));
        } else {
          // Headers already sent (rare with B1's early-release but possible
          // if the queue rejects mid-streaming-continuation — should be
          // impossible because the continuation runs after queue release,
          // but defensively close the socket).
          try { clientRes.end(); } catch {}
        }
        return;
      }
      log('error', `Unhandled proxy error: ${err.message}\n${err.stack}`);
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, {
          'Content-Type': 'application/json',
          'x-vdm-proxy': 'true',
        });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `[vdm proxy] ${err.message}` } }));
      } else {
        // Phase F audit I1 — when an error escapes after headers are sent,
        // the previous code did nothing; the kernel held the socket open
        // until CC's request timeout fired (looking like ConnectionRefused
        // to the user). Closing promptly gives CC a clean signal.
        try { clientRes.end(); } catch {}
      }
    });
});

async function handleProxyRequest(clientReq, clientRes) {
  // Health check
  if (clientReq.method === 'GET' && clientReq.url === '/health') {
    clientRes.writeHead(200, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({
      status: _circuitOpen ? 'passthrough' : 'ok',
      accounts: loadAllAccountTokens().length,
      activeToken: getActiveToken() ? 'present' : 'missing',
      circuitBreaker: _circuitOpen ? 'open' : 'closed',
      consecutiveExhausted: _consecutiveExhausted,
    }));
    return;
  }

  // ── Proxy disabled: smart passthrough ──
  // Buffers the body so we can detect 400-empty-body and retry with a fresh
  // keychain token or convert to 401 for Claude Code re-auth.
  if (!settings.proxyEnabled) {
    const bodyChunks = [];
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => bodyChunks.push(c));
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
    const body = Buffer.concat(bodyChunks);
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    try {
      await _smartPassthrough(clientReq, clientRes, body, fwd, 'proxy-disabled');
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Passthrough error: ${err.message}` } }));
      }
    }
    return;
  }

  // ── Circuit breaker: auto-passthrough after repeated proxy failures ──
  // When open, skip all proxy logic and forward directly to Anthropic.
  // This lets Claude Code's own auth / re-auth work normally.
  if (_isCircuitOpen()) {
    log('circuit', 'Circuit breaker open — smart passthrough');
    const bodyChunks = [];
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => bodyChunks.push(c));
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
    const body = Buffer.concat(bodyChunks);
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    try {
      await _smartPassthrough(clientReq, clientRes, body, fwd, 'circuit-breaker');
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Passthrough error: ${err.message}` } }));
      }
    }
    return;
  }

  // ── OAuth bypass: all accounts permanently revoked ──
  // When the bypass detector concludes EVERY account has a dead refresh
  // token (3+ invalid_grant failures spread over 1h, no recent 200, no
  // future rate-limit reset), there's nothing to rotate to. Forward
  // requests transparently — Anthropic will return 401 against the
  // user's keychain token, and Claude Code's own re-auth UI handles it.
  // Serialize queue still applies (it wraps this whole function from
  // the createServer layer).
  if (_oauthBypassMode) {
    log('bypass', 'OAuth bypass mode — smart passthrough (all accounts revoked)');
    const bodyChunks = [];
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => bodyChunks.push(c));
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
    const body = Buffer.concat(bodyChunks);
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    try {
      await _smartPassthrough(clientReq, clientRes, body, fwd, 'oauth-bypass');
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Passthrough error: ${err.message}` } }));
      }
    }
    return;
  }

  // Buffer request body for replay on retry. Two guards:
  //   (a) per-request MAX_BODY_SIZE — caps a single oversized payload
  //   (b) global _bufferedBytes — caps aggregate memory across requests
  //       so 10 concurrent 49 MB uploads can't push the heap to ~1 GB
  //       and OOM-kill the dashboard.
  const MAX_BODY_SIZE = 50 * 1024 * 1024;        // per-request cap (50 MB)
  const MAX_GLOBAL_BUFFERED = 200 * 1024 * 1024; // global cap (200 MB)
  const bodyChunks = [];
  let bodySize = 0;
  try {
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => {
        bodySize += c.length;
        if (bodySize > MAX_BODY_SIZE) {
          reject(new Error('body_too_large'));
          clientReq.destroy();
          return;
        }
        if (_bufferedBytes + c.length > MAX_GLOBAL_BUFFERED) {
          reject(new Error('global_buffer_exceeded'));
          clientReq.destroy();
          return;
        }
        _bufferedBytes += c.length;
        bodyChunks.push(c);
      });
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
  } catch (e) {
    // Always release the global accounting on early-out paths.
    _bufferedBytes -= bodyChunks.reduce((n, c) => n + c.length, 0);
    if (e.message === 'body_too_large') {
      clientRes.writeHead(413, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: `Request body too large (max ${MAX_BODY_SIZE / 1024 / 1024}MB)` }));
      return;
    }
    if (e.message === 'global_buffer_exceeded') {
      clientRes.writeHead(503, { 'Content-Type': 'application/json', 'Retry-After': '5' });
      clientRes.end(JSON.stringify({ error: 'Proxy busy: in-flight request bodies exceed memory budget. Retry shortly.' }));
      return;
    }
    throw e;
  }
  const body = Buffer.concat(bodyChunks);
  // Release the streaming-phase accounting now that the chunks are
  // consolidated into `body`. The held-body memory is still real but
  // bounded per-request (50 MB) and per-account (4 in flight).
  _bufferedBytes -= bodySize;
  bodyChunks.length = 0; // help GC reclaim the chunks promptly
  const deadline = Date.now() + REQUEST_DEADLINE_MS;
  const isDeadlineExceeded = () => Date.now() > deadline;

  // Check if keychain has a token we haven't saved yet (e.g. user just did /login)
  // Skip during error spirals to avoid creating bogus auto-accounts from stale keychain tokens
  if (_consecutive400s < 3) {
    await autoDiscoverAccount().catch((e) => {
      log('warn', `Per-request autoDiscoverAccount failed: ${e && e.message}`);
    });
  }

  let allAccounts = loadAllAccountTokens();
  if (!allAccounts.length) {
    log('error', 'No accounts configured — trying passthrough');
    if (await _passthroughFallback(clientReq, clientRes, body, 'no-accounts')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No accounts configured. Run: vdm add <name>' } }));
    return;
  }

  const maxAttempts = allAccounts.length + 2; // +1 for refresh retry, +1 for minimal-header retry
  const triedTokens = new Set();
  const billingMarkedTokens = new Set(); // tokens marked billing-unavailable this request
  const refreshAttempted = new Set(); // track refresh attempts to prevent infinite loops
  let _bulkRefreshAttempted = false;   // per-request: tried force-refreshing all tokens?
  let _minimalHeaderRetried = false;   // per-request: tried minimal-header last resort?

  // Start with active keychain token, apply rotation strategy
  let token = getActiveToken();
  const activeAcct = allAccounts.find(a => a.token === token);

  if (settings.autoSwitch) {
    const { account: strategyPick, rotated } = _pickByStrategy({
      strategy: settings.rotationStrategy || 'conserve',
      intervalMin: settings.rotationIntervalMin || 60,
      currentToken: token,
      lastRotationTime,
      accounts: allAccounts,
      stateManager: accountState,
      excludeTokens: new Set(),
    });

    if (strategyPick) {
      const oldName = activeAcct?.label || activeAcct?.name || 'none';
      const pickName = strategyPick.label || strategyPick.name;
      const isSameAccount = activeAcct && strategyPick.name === activeAcct.name;
      const reason = rotated ? settings.rotationStrategy : 'unavailable';
      if (!isSameAccount) {
        log('proactive', `${oldName} → switch to ${pickName} (${reason})`);
      }
      try {
        await withSwitchLock(() => {
          writeKeychain(strategyPick.creds);
          invalidateTokenCache();
        });
      } catch (e) {
        log('warn', `Keychain write failed during proactive switch: ${e.message}`);
      }
      token = strategyPick.token;
      lastRotationTime = Date.now();
      if (!isSameAccount) {
        logEvent('proactive-switch', { from: oldName, to: pickName, reason });
        if (reason === 'unavailable') {
          notify('Account Switched', `${oldName} unavailable → ${pickName}`, 'switch');
        }
      }
    } else if (!token) {
      log('error', 'No active account in keychain — trying passthrough');
      if (await _passthroughFallback(clientReq, clientRes, body, 'no-active-account')) return;
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No active account in keychain' } }));
      return;
    }
  }

  // Guard: never forward a null/empty token (causes 400 with no body)
  if (!token) {
    log('error', 'No active token available — trying passthrough with original auth');
    if (await _passthroughFallback(clientReq, clientRes, body, 'no-active-token')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No active token available — check keychain access' } }));
    return;
  }

  // Pre-flight refresh: if the selected token is already expired, refresh it
  // before forwarding to avoid a wasted 401 round-trip (e.g. after laptop sleep)
  {
    const preAcct = allAccounts.find(a => a.token === token);
    if (preAcct && preAcct.expiresAt && preAcct.expiresAt < Date.now() && !isDeadlineExceeded()) {
      log('refresh-preflight', `${preAcct.label || preAcct.name}: token expired, refreshing before forwarding...`);
      const preAcctName = preAcct.label || preAcct.name;
      try {
        const result = await refreshAccountToken(preAcct.name);
        if (result.ok && result.skipped) {
          // Another process refreshed the on-disk token but our in-memory copy
          // is stale — do NOT seed refreshAttempted so the 401 handler can retry
          // with force: true to pick up the new token.
          log('refresh-preflight', `${preAcctName}: skipped (another process refreshed), will allow 401 retry`);
        } else if (result.ok) {
          refreshAttempted.add(preAcctName);
          invalidateAccountsCache();
          const refreshed = loadAllAccountTokens().find(a => a.name === preAcct.name);
          if (refreshed) {
            token = refreshed.token;
            try {
              await withSwitchLock(() => {
                writeKeychain(refreshed.creds);
                invalidateTokenCache();
              });
            } catch {}
            log('refresh-preflight', `${preAcctName}: refreshed OK, proceeding with new token`);
          }
        } else {
          // Refresh failed — seed refreshAttempted to avoid retrying the same
          // account in the 401 handler (it would just fail again after ~37s)
          refreshAttempted.add(preAcctName);
        }
      } catch (e) {
        refreshAttempted.add(preAcctName);
        log('refresh-preflight', `${preAcctName}: preflight refresh failed: ${e.message}`);
      }
    }
  }

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Deadline guard: on retries, bail early if we've run out of time
    if (attempt > 0 && isDeadlineExceeded()) {
      log('deadline', `Request deadline exceeded after ${attempt} attempts (${REQUEST_DEADLINE_MS}ms) — trying passthrough`);
      if (await _passthroughFallback(clientReq, clientRes, body, 'deadline-exceeded')) return;
      // Phase F — return 503 with explicit proxy-side framing instead of
      // 504/timeout_error. The deadline cap is OUR retry-budget, not an
      // Anthropic timeout — old wording made CC report this as "Anthropic
      // unresponsive". Retry-After:10 gives CC's retry loop a sane delay.
      clientRes.writeHead(503, {
        'Content-Type': 'application/json',
        'Retry-After': '10',
        'x-vdm-proxy': 'true',
      });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'overloaded_error',
          message: `[vdm proxy] retry-budget exhausted after ${attempt} attempts (${REQUEST_DEADLINE_MS / 1000}s). All token refreshes/rotations took too long. Tune CSW_REQUEST_DEADLINE_MS if this recurs.`,
        },
      }));
      return;
    }

    triedTokens.add(token);
    const acct = allAccounts.find(a => a.token === token);
    const acctName = acct?.label || acct?.name || 'unknown';

    let proxyRes;
    let lastNetworkError;
    try {
      const headers = buildForwardHeaders(clientReq.headers, token);
      headers['content-length'] = String(body.length);
      proxyRes = await forwardToAnthropic(clientReq.method, clientReq.url, headers, body);
    } catch (err) {
      lastNetworkError = err;
      // Network error  - retry once with same token on transient errors
      if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' || err.code === 'ECONNREFUSED') {
        log('retry', `Network error (${err.code}) on ${acctName}, retrying once...`);
        await new Promise(r => setTimeout(r, 500));
        try {
          const headers = buildForwardHeaders(clientReq.headers, token);
          headers['content-length'] = String(body.length);
          proxyRes = await forwardToAnthropic(clientReq.method, clientReq.url, headers, body);
          lastNetworkError = null;
        } catch (err2) {
          lastNetworkError = err2;
          log('error', `Retry also failed on ${acctName}: ${err2.message}`);
        }
      } else {
        log('error', `Forward error on ${acctName}: ${err.message}`);
      }
    }

    // Network failure after retry  - try switching to another account before giving up
    if (lastNetworkError) {
      if (settings.autoSwitch) {
        const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
        if (next) {
          log('switch', `  → network error on ${acctName}, switching to ${next.label || next.name}`);
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during network-error switch: ${e.message}`);
          }
          token = next.token;
          logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: 'network-error' });
          continue;
        }
      }
      // All accounts tried or autoSwitch off — try passthrough fallback
      if (await _passthroughFallback(clientReq, clientRes, body, 'network-error-all-exhausted')) return;
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Upstream unreachable: ${lastNetworkError.message}` } }));
      return;
    }

    const status = proxyRes.statusCode;

    // ── 429: Rate limited → auto-switch (if enabled) ──
    if (status === 429) {
      // Forensic event — captures everything you'd need to reconstruct
      // a rate-limit incident: which account, which reset windows,
      // what retry-after the server asked for, what error type.
      try {
        const fp = getFingerprintFromToken(token);
        const headers = proxyRes.headers || {};
        logForensicEvent('rate_limit', {
          account_fp: fp,
          account_name: acctName,
          retry_after_raw: headers['retry-after'] || null,
          ratelimit_5h_reset: headers['anthropic-ratelimit-unified-5h-reset'] || null,
          ratelimit_7d_reset: headers['anthropic-ratelimit-unified-7d-reset'] || null,
          ratelimit_5h_util: headers['anthropic-ratelimit-unified-5h-utilization'] || null,
          ratelimit_7d_util: headers['anthropic-ratelimit-unified-7d-utilization'] || null,
          ratelimit_status: headers['anthropic-ratelimit-unified-status'] || null,
          url: clientReq.url,
        });
      } catch {}
      // Safeguard C — feed the all-accounts-429 breaker. Records by
      // FINGERPRINT (not name) so a rename mid-incident doesn't desync.
      // No-op if serialize is off.
      try { _record429ForAccount(getFingerprintFromToken(token)); } catch (e) {
        log('warn', `_record429ForAccount failed: ${e.message}`);
      }
      // Safeguard D — burst-429 detector. If we hit 3+ 429s on the
      // SAME account within 30s, auto-enable serialize so the next
      // account doesn't get bombarded by the same parallel-payload
      // burst. The 429 timestamp also feeds the auto-revert quiet
      // window (no 429 from anyone for 30 min → revert).
      _last429AnyAccountAt = Date.now();
      try { _autoEnableSerializeOnBurst(getFingerprintFromToken(token), acctName); } catch (e) {
        log('warn', `_autoEnableSerializeOnBurst failed: ${e.message}`);
      }
      // RFC 7231 §7.1.3 allows Retry-After to be a delta-seconds OR an
      // HTTP-date. The previous parseInt(…) returned 0 for HTTP-date and
      // any malformed value, which classified the response as "transient"
      // (retry-after < 60) and passed it through to the client without
      // marking the account limited or rotating — exactly the failure
      // mode auto-switch was meant to prevent. parseRetryAfter (lib.mjs)
      // handles both forms and returns 0 only for genuinely missing /
      // unparseable / past-date values.
      const retryAfter = parseRetryAfter(proxyRes.headers['retry-after']);

      // Phase G — drain the body once and parse error.type so we can
      // distinguish PLAN-side throttle (rate_limit_error → rotating to
      // another account helps) from SERVER-side throttle (overloaded_error
      // → rotating doesn't help; every account hits the same surge).
      // Pre-Phase-G vdm rotated on every long-retry-after 429, burning
      // accounts during Anthropic-wide capacity events.
      //
      // We need the body buffered anyway for both the pass-through and
      // rotation paths (the rotation path already calls drainResponse).
      // Buffering once + holding the bytes lets us inspect AND replay
      // them to the client. _drainBuf429 is the small captured body
      // (always small for a 429 — single error JSON object).
      const _drainBuf429 = await drainResponse(proxyRes);
      let _is429Server = false;
      try {
        const parsed = JSON.parse(_drainBuf429.toString('utf8'));
        const etype = parsed && parsed.error && parsed.error.type;
        _is429Server = etype === 'overloaded_error';
      } catch { /* not JSON or empty body — treat as plan-side */ }

      // Transient burst 429s (short retry-after) are normal — Claude Code
      // retries on its own.  Pass through silently without noisy logging,
      // marking the account as limited, or sending notifications.
      // Phase G — server-side overloaded_error is also "transient" from
      // vdm's perspective: rotating to another account just hits the same
      // upstream surge, so the right move is to pass it through and let
      // CC's own retry-with-backoff handle it.
      const isTransient = retryAfter < 60 || _is429Server;

      // Phase 6: thundering-herd dedup — late-arriving 429s from N
      // concurrent requests get retried against the new active without N
      // rotations. When N in-flight requests all hit 429 against the same
      // active token, the first one rotates AWAY and marks the source
      // token; the rest must NOT independently pick + writeKeychain again
      // (that produces N rotations in 100 ms when 1 was sufficient and
      // can ping-pong the keychain across accounts the user never asked
      // to use). Window is 500 ms — long enough to absorb the typical
      // burst of streaming-completion 429s, short enough that genuinely
      // new rate limits on the new token still trigger normal rotation.
      if (!isTransient && accountState.wasRecentlySwitchedFrom(token, 500)) {
        // Phase G: body already drained into _drainBuf429 above — no need
        // to drain again. Just continue to the next attempt.
        log('switch', `${acctName} → 429 dedup: token was recently rotated away, retrying against new active`);
        triedTokens.add(token);
        try {
          const fresh = readKeychain();
          const freshToken = fresh?.claudeAiOauth?.accessToken;
          if (freshToken && freshToken !== token) {
            token = freshToken;
            continue;
          }
        } catch (e) {
          log('warn', `Keychain re-read failed during 429 dedup: ${e.message}`);
        }
        // Fallback: keychain re-read produced same token (or failed) —
        // fall through to the normal rotation path so the request still
        // makes progress.
      }

      if (!isTransient) {
        markAccountLimited(token, acctName, retryAfter);
        logEvent('rate-limited', { account: acctName, retryAfter });
      }
      const _429kind = _is429Server
        ? 'server overload (overloaded_error)'
        : (isTransient ? 'transient' : 'rate limited');
      log('switch', `${acctName} → 429 ${_429kind} (retry-after: ${retryAfter}s)`);

      if (!settings.autoSwitch || isTransient) {
        if (!isTransient) log('switch', '  → auto-switch OFF, returning 429 as-is');
        if (_is429Server) log('switch', '  → server-side 429: passing through (rotation would not help)');
        // Phase G — body was drained above into _drainBuf429; replay it to
        // the client instead of trying to pipe a now-consumed stream.
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        clientRes.end(_drainBuf429);
        return;
      }

      // Phase G: body already drained above; no second drain needed.

      // Phase 6: mark the source token as just-rotated-away BEFORE the
      // keychain swap so any concurrent in-flight 429 lands in the dedup
      // branch above instead of independently rotating again. Order
      // matters — markSwitchedFrom() must precede pickBestAccount() so
      // even a sub-millisecond race observes the marker.
      accountState.markSwitchedFrom(token);

      // Try next best account
      const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
      if (next) {
        log('switch', `  → switching to ${next.label || next.name}`);
        try {
          await withSwitchLock(() => {
            writeKeychain(next.creds);
            invalidateTokenCache();
            invalidateAccountsCache();
          });
        } catch (e) {
          log('warn', `Keychain write failed during 429 switch: ${e.message}`);
        }
        token = next.token;
        logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '429' });
        notify('Account Switched', `${acctName} rate-limited → ${next.label || next.name}`, 'switch');
        continue;
      }

      // All exhausted
      log('switch', '  → all accounts exhausted, returning 429');
      logEvent('all-exhausted', {});
      notify('All Accounts Exhausted', `All ${allAccounts.length} accounts rate-limited. Reset: ${getEarliestReset()}`, 'exhausted');
      // Compute a real Retry-After (in seconds) so Claude Code's own retry
      // loop knows when to come back. Without this header CC retries on
      // its own (often-overly-aggressive) timer or surfaces the error
      // immediately. We pick the soonest reset across all known
      // 5h/7d windows; capped at 1 hour to bound user-visible wait.
      let retryAfterSec = 0;
      const nowSec = Math.floor(Date.now() / 1000);
      for (const [, st] of accountState.entries()) {
        for (const t of [st && st.resetAt, st && st.resetAt7d]) {
          if (t && t > nowSec) {
            const delta = t - nowSec;
            if (retryAfterSec === 0 || delta < retryAfterSec) retryAfterSec = delta;
          }
        }
      }
      const retryAfterCapped = Math.min(retryAfterSec || 60, 3600);
      clientRes.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfterCapped),
      });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'rate_limit_error',
          message: `All ${allAccounts.length} accounts rate limited. Earliest reset: ${getEarliestReset()}`,
        },
      }));
      return;
    }

    // ── 401: Auth error → try refresh first, then fallback to switch ──
    if (status === 401) {
      log('switch', `${acctName} → 401 auth error`);
      try {
        logForensicEvent('auth_failure', {
          account_fp: getFingerprintFromToken(token),
          account_name: acctName,
          url: clientReq.url,
        });
      } catch {}

      await drainResponse(proxyRes);

      // Try to refresh the token (once per account per request).
      // Skip if a recent non-retriable failure is on file — every fresh
      // 401 was previously hitting the OAuth endpoint with a known-revoked
      // refresh token, burning rate budget AND any chance of recovery.
      // The per-request `refreshAttempted` Set covers within-request loops;
      // `refreshFailures` covers the across-request case the audit flagged
      // as Concern 03.C5.
      const REFRESH_FAILURE_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
      const priorFailure = refreshFailures.get(acctName);
      const skipRefresh =
        priorFailure &&
        priorFailure.retriable === false &&
        Date.now() - priorFailure.ts < REFRESH_FAILURE_TTL_MS;
      if (acct && !refreshAttempted.has(acctName) && !isDeadlineExceeded() && !skipRefresh) {
        refreshAttempted.add(acctName);
        log('refresh', `${acctName}: attempting token refresh after 401...`);
        try {
          const refreshResult = await refreshAccountToken(acct.name, { force: true });
          if (refreshResult.ok && !refreshResult.skipped) {
            log('refresh', `${acctName}: refresh succeeded, retrying request`);
            // Re-read the account to get new token
            invalidateAccountsCache();
            const refreshedAccounts = loadAllAccountTokens();
            const refreshedAcct = refreshedAccounts.find(a => a.name === acct.name);
            if (refreshedAcct && refreshedAcct.token !== acct.token) {
              token = refreshedAcct.token;
              triedTokens.delete(acct.token); // allow retry with genuinely new token
              continue;
            }
            // Refresh returned same token — treat as failed
            log('refresh', `${acctName}: refresh returned same token, treating as failed`);
          }
        } catch (e) {
          log('refresh', `${acctName}: refresh failed: ${e.message}`);
        }
      }

      // Refresh failed or already attempted  - fall through to existing logic
      markAccountExpired(token, acctName);
      logEvent('auth-expired', { account: acctName });

      if (!settings.autoSwitch) {
        log('switch', '  → auto-switch OFF — trying passthrough');
        if (await _passthroughFallback(clientReq, clientRes, body, '401-autoswitch-off')) return;
        clientRes.writeHead(401, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'Token expired' },
        }));
        return;
      }

      const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
      if (next) {
        log('switch', `  → switching to ${next.label || next.name}`);
        try {
          await withSwitchLock(() => {
            writeKeychain(next.creds);
            invalidateTokenCache();
          });
        } catch (e) {
          log('warn', `Keychain write failed during 401 switch: ${e.message}`);
        }
        token = next.token;
        logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '401' });
        notify('Account Switched', `${acctName} token expired → ${next.label || next.name}`, 'switch');
        continue;
      }

      // No valid accounts left — try passthrough so Claude Code can re-auth
      log('switch', '  → no valid accounts remain — trying passthrough fallback');
      notify('All Tokens Expired', 'No valid accounts remain — trying passthrough', 'expired');
      if (await _passthroughFallback(clientReq, clientRes, body, 'all-401-expired')) return;
      clientRes.writeHead(401, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'authentication_error',
          message: 'All account tokens are expired. Re-add accounts with: vdm add <name>',
        },
      }));
      return;
    }

    // ── 400: Bad request → multi-layer recovery ──
    //
    // The Anthropic API returns 400 for many reasons: bad tokens, expired
    // OAuth, malformed headers, AND legitimate request errors.  We must
    // distinguish between "request is wrong" (switching won't help) and
    // "something about the proxy/token is wrong" (switching/refreshing can
    // help).  Multiple recovery strategies are tried in order.
    if (status === 400) {
      const bodyBuf = await drainResponse(proxyRes);
      const bodyStr = bodyBuf.toString('utf8').trim();

      // Parse error type from response body (do this FIRST, before counter logic)
      let errorType = null;
      let parsedError = null;
      if (bodyStr) {
        try {
          parsedError = JSON.parse(bodyStr);
          errorType = parsedError?.error?.type || parsedError?.type || null;
        } catch {
          // Not JSON — HTML error page, garbled data, etc.
        }
      }

      // Extract error message early so the auth-heuristic can use it
      const errorMessage = parsedError?.error?.message || '';

      // Detect the specific "no body" / empty-body / non-JSON patterns that
      // indicate this is NOT a legitimate request validation error
      const looksLikeAuthIssue =
        !bodyStr ||                                  // truly empty
        !parsedError ||                              // not valid JSON
        errorType === 'authentication_error' ||      // explicit auth error
        errorType === 'permission_error' ||           // permission issue
        /status code|no body|invalid.*token|unauthorized/i.test(errorMessage);  // heuristic

      // Billing errors (credit balance too low) are never fixable by token
      // refresh — skip straight to account switching (Strategy 3).
      const isBillingError = /credit balance|billing.*issue|payment.*required/i.test(errorMessage);

      // Per Claude Code's error reference (https://code.claude.com/docs/en/errors),
      // a 400 with body containing "This organization has been disabled"
      // is account-level termination by Anthropic — STRONGER signal than
      // the 3-strikes-over-1h OAuth-revocation heuristic. One occurrence
      // means this account is dead permanently; rotation/refresh won't
      // help. Hard-mark and let the bypass-mode evaluator decide whether
      // ALL accounts are now in this state.
      const isOrgDisabledError = /organization has been disabled|organization is disabled/i.test(errorMessage);
      if (isOrgDisabledError && token) {
        try {
          accountState.forceMarkPermanentlyRevoked(token, acctName, 'organization-disabled-400');
        } catch (e) {
          log('warn', `forceMarkPermanentlyRevoked failed: ${e.message}`);
        }
        try {
          logForensicEvent('account_organization_disabled', {
            account: acctName,
            error_message: errorMessage.slice(0, 300),
          });
        } catch {}
        log('error', `${acctName}: organization-disabled 400 — account marked permanently revoked`);
        logActivity('account-organization-disabled', { account: acctName });
        try { _evaluateBypassMode(); } catch (e) {
          log('warn', `_evaluateBypassMode failed: ${e.message}`);
        }
      }

      // ── Content 400: pass through immediately ──
      // If the API returned a well-formed invalid_request_error and it doesn't
      // look like an auth/billing issue, this is a request *body* problem
      // (bad model, invalid params, etc).  Switching accounts or refreshing
      // tokens will never fix it — pass through without polluting the
      // consecutive-400 counter or triggering recovery strategies.
      if (errorType === 'invalid_request_error' && !looksLikeAuthIssue && !isBillingError) {
        log('info', `${acctName} → 400 invalid_request_error (passing through): ${bodyStr.slice(0, 200)}`);
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
        return;
      }

      // Billing errors: mark this account as temporarily unavailable so
      // pickBestAccount / pickByStrategy won't keep selecting it.
      // This is THE key fix for the death spiral: without this, the account
      // looks "available" (not expired, not rate-limited) and gets re-selected
      // on every subsequent request, causing an infinite cycle.
      if (isBillingError && token) {
        const BILLING_COOLDOWN_SEC = 300; // 5 min cooldown
        accountState.markLimited(token, acctName, BILLING_COOLDOWN_SEC);
        billingMarkedTokens.add(token);
        log('billing', `${acctName}: marked unavailable for ${BILLING_COOLDOWN_SEC}s (billing error)`);
      }

      // Track this 400 for the global consecutive-failure counter.
      // Only auth-looking and billing 400s count — content 400s were already
      // passed through above and should not escalate the counter.
      // Time-decay: reset if last 400 was >30s ago (prevents stale counter
      // from a past episode affecting unrelated future requests).
      if (_consecutive400s > 0 && Date.now() - _consecutive400sAt > 30_000) {
        _consecutive400s = 0;
      }
      // PROXY-6: don't count 400s during the post-close grace window.
      // Otherwise 10 in-flight CC sessions all hitting stale-token 400
      // the instant the breaker closes can re-open it within seconds,
      // bouncing open/closed/open every 2 minutes for hours. Inside
      // the grace window we still let the recovery strategy run — we
      // just don't escalate the counter.
      if (!_inCircuitPostCloseGrace()) {
        _consecutive400s++;
        _consecutive400sAt = Date.now();
      }

      // ── Circuit breaker: stop the death spiral ──
      // If we've hit too many consecutive 400s across requests, all accounts
      // are likely dead (billing, expired, etc).  Open the circuit breaker
      // and fall through to passthrough mode instead of keep switching.
      if (_consecutive400s >= CIRCUIT_400_THRESHOLD) {
        _openCircuit(`${_consecutive400s} consecutive 400 errors`);
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
        return;
      }

      const reason = isBillingError ? `billing error (${errorMessage.slice(0, 80)})` :
        looksLikeAuthIssue ? 'auth/token issue' :
        _consecutive400s >= 3 ? `repeated 400s (${_consecutive400s} consecutive)` :
        `unknown (type: ${errorType || 'none'})`;
      log('error', `${acctName} → 400 (${reason}, body: ${bodyStr.slice(0, 300) || '(empty)'})`);
      logEvent('bad-request-400', { account: acctName, errorType, consecutive: _consecutive400s });

      // ── Strategy 1: Force-refresh ALL tokens if we're in a repeated-failure loop ──
      // (Skip for billing errors — refreshing tokens won't restore credits)
      if (_consecutive400s >= 3 && !_bulkRefreshAttempted && !isDeadlineExceeded() && !isBillingError) {
        _bulkRefreshAttempted = true;
        log('error', `${_consecutive400s} consecutive 400s — force-refreshing ALL account tokens (parallel)`);
        const toRefresh = allAccounts.filter(a => !refreshAttempted.has(a.label || a.name));
        for (const a of toRefresh) refreshAttempted.add(a.label || a.name);
        const results = await Promise.allSettled(
          toRefresh.map(a => refreshAccountToken(a.name, { force: true }))
        );
        for (let i = 0; i < results.length; i++) {
          if (results[i].status === 'rejected') {
            log('refresh', `${toRefresh[i].name}: bulk refresh failed: ${results[i].reason?.message}`);
          }
        }
        invalidateAccountsCache();
        allAccounts = loadAllAccountTokens(); // refresh stale allAccounts so account lookups work
        const refreshedAcct = allAccounts.find(a => a.name === (acct?.name));
        if (refreshedAcct && refreshedAcct.token !== token) {
          token = refreshedAcct.token;
          triedTokens.clear(); // all tokens changed — retry everything
          continue;
        }
      }

      // ── Strategy 2: Refresh this specific account's token ──
      // (Skip for billing errors — refreshing tokens won't restore credits)
      if (acct && !refreshAttempted.has(acctName) && !isDeadlineExceeded() && !isBillingError) {
        refreshAttempted.add(acctName);
        log('refresh', `${acctName}: attempting token refresh after 400...`);
        try {
          const refreshResult = await refreshAccountToken(acct.name, { force: true });
          if (refreshResult.ok && !refreshResult.skipped) {
            log('refresh', `${acctName}: refresh succeeded, retrying request`);
            invalidateAccountsCache();
            const refreshedAccounts = loadAllAccountTokens();
            const refreshedAcct = refreshedAccounts.find(a => a.name === acct.name);
            if (refreshedAcct && refreshedAcct.token !== acct.token) {
              token = refreshedAcct.token;
              triedTokens.delete(acct.token);
              continue;
            }
            log('refresh', `${acctName}: refresh returned same token, treating as failed`);
          }
        } catch (e) {
          log('refresh', `${acctName}: refresh failed: ${e.message}`);
        }
      }

      // ── Strategy 3: Switch to another account ──
      if (settings.autoSwitch) {
        const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
        if (next) {
          log('switch', `  → 400 on ${acctName}, switching to ${next.label || next.name}`);
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during 400 switch: ${e.message}`);
          }
          token = next.token;
          logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '400-error' });
          notify('Account Switched', `${acctName} → 400 error → ${next.label || next.name}`, 'switch');
          continue;
        }
      }

      // ── Strategy 4 (last resort): Retry with minimal headers ──
      // If ALL accounts failed, the problem might be a forwarded header that
      // the API rejects.  Retry once with only the essential headers.
      if (!_minimalHeaderRetried) {
        _minimalHeaderRetried = true;
        log('error', 'All accounts returned 400 — retrying with minimal headers (last resort)');
        const minimalHeaders = {
          'host': 'api.anthropic.com',
          'authorization': `Bearer ${token}`,
          'content-type': clientReq.headers['content-type'] || 'application/json',
          'content-length': String(body.length),
          'anthropic-version': clientReq.headers['anthropic-version'] || '2023-06-01',
          'anthropic-beta': 'oauth-2025-04-20',
        };
        try {
          const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, minimalHeaders, body);
          if (retryRes.statusCode < 400 || retryRes.statusCode >= 500) {
            // It worked (or it's a server error, not our fault) — pipe through
            log('info', `Minimal-header retry succeeded (status ${retryRes.statusCode})`);
            _consecutive400s = 0;

            // The minimal-header retry succeeded — billing errors were header-caused,
            // not genuine. Clear the false billing marks from this request.
            if (billingMarkedTokens.size > 0) {
              for (const t of billingMarkedTokens) {
                accountState.clearBillingCooldown(t);
              }
              log('billing', `Cleared ${billingMarkedTokens.size} false-positive billing marks (header-caused)`);
            }

            // Log header diff for debugging: which headers were in the full request
            // but NOT in the minimal retry? One of these caused the 400.
            const fullHeaders = buildForwardHeaders(clientReq.headers, token);
            const strippedKeys = Object.keys(fullHeaders)
              .filter(k => !(k.toLowerCase() in {
                'host': 1, 'authorization': 1, 'content-type': 1,
                'content-length': 1, 'anthropic-version': 1, 'anthropic-beta': 1,
              }));
            if (strippedKeys.length > 0) {
              log('info', `Headers in full request but not minimal retry: ${strippedKeys.join(', ')}`);
            }
            clientRes.writeHead(retryRes.statusCode, retryRes.headers);
            retryRes.on('error', () => { try { clientRes.end(); } catch {} });
            clientRes.on('close', () => { retryRes.destroy(); });
            // Phase F audit B1 — return continuation here too. The previous
            // `await pipeAndWait` inside the queue-protected region held the
            // serialization permit for the full body lifetime on the cold-path
            // minimal-header retry, re-introducing the exact regression that
            // B1 set out to eliminate.
            return { kind: 'pipe', proxyRes: retryRes };
          }
          // Still 4xx — it's genuinely a bad request or truly dead tokens
          const retryBuf = await drainResponse(retryRes);
          log('error', `Minimal-header retry also returned ${retryRes.statusCode}: ${retryBuf.toString('utf8').slice(0, 200)}`);
        } catch (e) {
          log('error', `Minimal-header retry failed: ${e.message}`);
        }
      }

      // All strategies exhausted — try passthrough with original auth header
      // so Claude Code can reach the real API / trigger its own re-auth flow.
      log('error', `All 400 recovery strategies exhausted — trying passthrough fallback`);
      if (await _passthroughFallback(clientReq, clientRes, body, 'all-400-strategies-exhausted')) return;
      // Passthrough also failed — return the best error we have
      if (bodyStr) {
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
      } else {
        // Empty body = auth failure — return 401 to trigger Claude Code re-auth
        log('fallback', 'Final fallback: converting empty-body 400 → 401 to trigger re-auth');
        clientRes.writeHead(401, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: {
            type: 'authentication_error',
            message: 'Token expired (proxy: empty-body 400 converted to 401 after all recovery strategies)',
          },
        }));
      }
      return;
    }

    // ── 529: Overloaded → pass through, switching won't help ──
    if (status === 529) {
      log('info', `${acctName} → 529 overloaded (not switching  - server-side issue)`);
      try {
        logForensicEvent('server_error', {
          account_fp: getFingerprintFromToken(token),
          account_name: acctName,
          status_code: 529,
          error_type: 'overloaded_error',
          url: clientReq.url,
        });
      } catch {}
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
      clientRes.on('close', () => { proxyRes.destroy(); });
      // Phase F audit B1: return a streaming continuation instead of awaiting
      // here. The serialization-queue permit was held until this await
      // resolved, blocking every other queued request for the full pipe
      // duration. Returning a continuation lets the queue release at the
      // headers boundary; the body pipe runs OUTSIDE the queue.
      return { kind: 'pipe', proxyRes };
    }

    // Catch all OTHER 5xx responses for the forensic log.
    if (status >= 500 && status !== 529) {
      try {
        logForensicEvent('server_error', {
          account_fp: getFingerprintFromToken(token),
          account_name: acctName,
          status_code: status,
          error_type: proxyRes.headers['anthropic-error-type'] || 'unknown',
          url: clientReq.url,
        });
      } catch {}
    }

    // ── Any other response: success or client error → pipe through ──
    _consecutive400s = 0; // reset on any non-400 response
    _consecutiveExhausted = 0;
    updateAccountState(token, acctName, proxyRes.headers, getFingerprintFromToken(token));

    // Check if utilization is critically high and log a warning (only at 90%, 95%, 100%)
    const u5h = parseFloat(proxyRes.headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    if (u5h >= 0.9) {
      const tier = u5h >= 1.0 ? 100 : u5h >= 0.95 ? 95 : 90;
      const lastTier = _lastWarnPct.get(acctName);
      if (lastTier !== tier) {
        _lastWarnPct.set(acctName, tier);
        log('warn', `${acctName} at ${tier}% of 5h limit`);
      }
    }

    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
    clientRes.on('close', () => { proxyRes.destroy(); });

    // Phase F audit B1/D1 — return a streaming continuation rather than
    // awaiting the body pipe in-line. The previous version awaited
    // `extractor.on('end')` / `pipeAndWait` here, holding the serialization-
    // queue permit for the full SSE stream lifetime (60-300s for typical
    // Opus turns). With cap=1, that meant a single stream blocked every
    // other queued request until queueTimeoutMs (120s) fired and they 503'd —
    // and because queue rejections never reach forwardToAnthropic, recordUsage
    // never ran for those rejected requests, silently breaking token tracking
    // (audit D1). Returning a continuation here lets the queue release at the
    // headers boundary; the body pipe + recordUsage run OUTSIDE the queue.
    const contentType = proxyRes.headers['content-type'] || '';
    if (contentType.includes('text/event-stream')) {
      return { kind: 'sse', proxyRes, body, acctName };
    }
    return { kind: 'pipe', proxyRes };
  }

  // Should not reach here, but safety net
  log('error', 'Exhausted all retry attempts without resolution — trying passthrough');
  if (!clientRes.headersSent) {
    if (await _passthroughFallback(clientReq, clientRes, body, 'all-retries-exhausted')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'All accounts tried, none succeeded' } }));
  }
}

function getEarliestReset() {
  const fromState = _getEarliestReset(accountState);
  if (fromState !== 'unknown') return fromState;
  // Fallback: check persisted state
  let earliest = Infinity;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const ps of Object.values(persistedState)) {
    if (ps.resetAt && ps.resetAt > nowSec && ps.resetAt < earliest) earliest = ps.resetAt;
    if (ps.resetAt7d && ps.resetAt7d > nowSec && ps.resetAt7d < earliest) earliest = ps.resetAt7d;
  }
  if (earliest === Infinity) return 'unknown';
  const d = new Date(earliest * 1000);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ── Expose proxy state to dashboard ──

function getProxyStatus() {
  const accounts = loadAllAccountTokens();
  // Phase 6: dropped `recentEvents` field — proxyEventLog ring buffer was a
  // dead pipeline (UI never rendered it). Activity log via /api/activity-log
  // is the single source for proxy state transitions.
  return {
    accounts: accounts.map(a => {
      const state = accountState.get(a.token);
      return {
        name: a.name,
        label: a.label,
        available: isAccountAvailable(a.token, a.expiresAt),
        ...(state || {}),
      };
    }),
  };
}

// ── Graceful shutdown ──
//
// Called on SIGINT/SIGTERM. Three responsibilities, in order:
//   (1) Flush every pendingSessions entry so the in-flight token-usage
//       claim window for each active Claude Code session is persisted to
//       token-usage.json. WITHOUT this, killing the dashboard while a
//       session is mid-flight silently drops every unclaimed entry — the
//       Tokens tab would underreport and the prepare-commit-msg trailer
//       would lose tokens. Mirrors the periodic auto-claim timer logic.
//   (2) Persist every active monitored session (Session Monitor beta).
//   (3) Tell both HTTP servers to stop accepting new connections, then
//       exit. We DO NOT await server.close() because long-poll SSE
//       subscribers (`/api/logs/stream`) keep the listener open
//       indefinitely — calling close() flips its accept flag and we exit
//       on the next tick. process.exit() then unwinds open sockets.
let _shuttingDown = false;
function shutdown(signal) {
  if (_shuttingDown) return;   // SIGINT after SIGTERM races otherwise
  _shuttingDown = true;
  log('info', `Received ${signal}, shutting down...`);
  // (1) Flush in-flight token-usage claims for every active session.
  try {
    const now = Date.now();
    let totalClaimed = 0;
    for (const [sessionId, session] of pendingSessions) {
      const claimed = claimUsageInRange(session.startedAt, now);
      for (const entry of claimed) {
        try {
          appendTokenUsage(_attachSessionAttribution(sessionId, session, {
            ts: entry.ts, repo: session.repo,
            // Phase 6: branchAtWriteTime null-safe.
            branch: session.branch ?? null,
            commitHash: session.commitHash, model: entry.model,
            inputTokens: entry.inputTokens, outputTokens: entry.outputTokens,
            cacheReadInputTokens: entry.cacheReadInputTokens || 0,
            cacheCreationInputTokens: entry.cacheCreationInputTokens || 0,
            messageId: entry.messageId ?? null,
            account: entry.account,
          }));
        } catch { /* best-effort during shutdown */ }
      }
      totalClaimed += claimed.length;
    }
    if (totalClaimed > 0) log('info', `Shutdown flush: persisted ${totalClaimed} token-usage entries`);
  } catch (e) {
    try { log('warn', `Shutdown token-usage flush failed: ${e.message}`); } catch {}
  }
  // Drain any pending debounced token-usage write so the in-flight
  // claims persisted above + any backlog from the last 500 ms make it
  // to disk before we close the listeners.
  try { flushTokenUsageSync(); } catch {}
  // (2) Persist active monitored sessions. Each call now arms the
  // debounce timer instead of writing immediately, so we MUST drain
  // the timer at the end with flushSessionHistorySync — otherwise the
  // active-session snapshot is lost on shutdown.
  for (const [id, session] of monitoredSessions) {
    try { persistCompletedSession(session); } catch {}
    monitoredSessions.delete(id);
  }
  try { flushSessionHistorySync(); } catch {}
  // (3) Graceful shutdown: stop accepting new connections, then wait
  // for in-flight SSE subscribers and proxy streams to drain BEFORE
  // we kill the process. Previously we called process.exit(0)
  // immediately, which dropped every long-running SSE connection
  // (vdm logs, dashboard activity poll, proxy SSE forwarders) and
  // any Claude Code session piping through the proxy lost data
  // mid-stream. Drain window is bounded — after _SHUTDOWN_DRAIN_MS
  // (default 5s) we exit anyway so a wedged stream cannot hold the
  // process forever.
  const _SHUTDOWN_DRAIN_MS = 5_000;
  try { proxyServer.close(); } catch {}
  try { server.close(); } catch {}
  // M12 fix — close the OTLP listener (Phase H, opt-in via CSW_OTEL_ENABLED).
  // Without this it stays open during the 5s drain and process.exit, leaking
  // the bound port to the kernel until OS reclaim. Null-safe since OTEL is
  // off by default and _otlpServer stays null.
  if (_otlpServer) { try { _otlpServer.close(); } catch {} }
  // End every SSE log subscriber (`/api/logs/stream`) cleanly so the
  // client sees a connection close, not a half-buffer reset. Without
  // this they'd hang until Node tears down the socket on exit.
  try {
    if (typeof _logSubscribers !== 'undefined' && _logSubscribers && typeof _logSubscribers.forEach === 'function') {
      _logSubscribers.forEach((sub) => { try { sub.end(); } catch {} });
    }
  } catch {}
  // Give in-flight handlers a moment, then exit. process.exit(0) is
  // still required because SSE subscribers and persistent keep-alives
  // keep the event loop occupied — server.close() merely flips the
  // accept flag. The keepAlive agent is destroyed RIGHT BEFORE exit
  // (FG4 follow-up): https.Agent.destroy() iterates BOTH freeSockets
  // AND in-use sockets, so calling it before the drain window would
  // rip in-flight upstream requests mid-stream — directly contradicting
  // the drain window's purpose. Running it inside the exit timer means
  // it fires after legitimate streams have either completed or been
  // abandoned, then we exit. Same goal (clean FIN, free FDs) without
  // the regression.
  const _exitTimer = setTimeout(() => {
    try { _upstreamAgent.destroy(); } catch {}
    process.exit(0);
  }, _SHUTDOWN_DRAIN_MS);
  // If both servers report 'close' before the timer, exit early.
  let _closed = 0;
  const _maybeExit = () => {
    if (++_closed >= 2) {
      clearTimeout(_exitTimer);
      // Same FG4 invariant — destroy the agent at the very last moment,
      // never before in-flight streams have had a chance to drain.
      try { _upstreamAgent.destroy(); } catch {}
      process.exit(0);
    }
  };
  try { proxyServer.once('close', _maybeExit); } catch {}
  try { server.once('close', _maybeExit); } catch {}
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGHUP', () => shutdown('SIGHUP'));
let _inExceptionHandler = false;
process.on('uncaughtException', (err) => {
  if (_inExceptionHandler) return;        // break recursive EIO death spiral
  _inExceptionHandler = true;
  try {
    log('fatal', `Uncaught exception: ${err.message}`);
    log('fatal', err.stack);
  } catch { /* if even log() fails, swallow — keeping process alive is paramount */ }
  _inExceptionHandler = false;
  // Keep running  - the proxy is more useful alive with a logged error
});
process.on('unhandledRejection', (reason) => {
  try { log('fatal', `Unhandled rejection: ${reason}`); } catch { /* swallow */ }
});

// The proxy MUST be 127.0.0.1-only: it forwards Bearer tokens read from
// the local Keychain to api.anthropic.com and would happily proxy them
// for any host that can reach the listening interface.
proxyServer.listen(PROXY_PORT, '127.0.0.1', () => {
  const s = settings;
  log('info', `API proxy on http://localhost:${PROXY_PORT} (proxy=${s.proxyEnabled ? 'on' : 'off'}, auto-switch=${s.autoSwitch ? 'on' : 'off'}, rotation=${s.rotationStrategy || 'conserve'}, ${loadAllAccountTokens().length} accounts)`);
});

proxyServer.on('error', (e) => {
  if (e && e.code === 'EADDRINUSE') {
    log('error', `Proxy port ${PROXY_PORT} already in use — another instance is already running. Exiting.`);
    process.exit(0);
  }
  throw e;
});

// ─────────────────────────────────────────────────
// Phase H — OTLP/HTTP/JSON receiver (opt-in via CSW_OTEL_ENABLED=1)
// ─────────────────────────────────────────────────
//
// Cross-checks vdm's hook-derived counts against Claude Code's first-party
// telemetry. The user must (a) set CSW_OTEL_ENABLED=1 in the dashboard env
// AND (b) configure Claude Code's own telemetry (CLAUDE_CODE_ENABLE_TELEMETRY,
// OTEL_LOGS_EXPORTER=otlp, OTEL_METRICS_EXPORTER=otlp,
// OTEL_EXPORTER_OTLP_PROTOCOL=http/json,
// OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3335).
//
// Stored as in-memory ring buffers (not persisted) — this is observability
// not source-of-truth; if vdm restarts, telemetry resumes from the next
// upstream OTLP send. Buffer cap configurable via CSW_OTEL_BUFFER_MAX
// (default 5000 entries each for logs / metrics).
const _otelLogs = [];     // [{ts, severity, body, scope, attributes}, ...]
const _otelMetrics = [];  // [{ts, name, value, kind, attributes}, ...]
let _otelStats = { logs: 0, metrics: 0, errors: 0, lastReceivedAt: 0 };

function _appendOtelLogs(records) {
  for (const r of records) {
    _otelLogs.push(r);
    _otelStats.logs++;
  }
  while (_otelLogs.length > OTEL_BUFFER_MAX) _otelLogs.shift();
}

function _appendOtelMetrics(records) {
  for (const r of records) {
    _otelMetrics.push(r);
    _otelStats.metrics++;
  }
  while (_otelMetrics.length > OTEL_BUFFER_MAX) _otelMetrics.shift();
}

// Module-level handle so the shutdown sequence can close it (M12 fix).
// Stays null when CSW_OTEL_ENABLED is unset.
let _otlpServer = null;
if (OTEL_ENABLED) {
  const otlpServer = createServer(async (req, res) => {
    // DNS-rebind defense — same rationale as the dashboard / proxy
    // servers. The OTLP receiver buffers Claude Code telemetry which
    // can include `claude_code.user_prompt` events with prompt text
    // when OTEL_LOG_USER_PROMPTS=1. Reject any non-localhost Host.
    if (!_isLocalhostHost(req.headers.host, OTLP_PORT)) {
      res.writeHead(421, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'misdirected request: invalid Host header' }));
      return;
    }
    // Only handle the two endpoints we care about; everything else 404s.
    const u = new URL(req.url, `http://localhost:${OTLP_PORT}`);
    const isLogs = u.pathname === '/v1/logs';
    const isMetrics = u.pathname === '/v1/metrics';
    // Internal status endpoint for the dashboard UI.
    if (u.pathname === '/internal/stats' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ..._otelStats, bufferedLogs: _otelLogs.length, bufferedMetrics: _otelMetrics.length }));
      return;
    }
    if (req.method !== 'POST' || (!isLogs && !isMetrics)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
      return;
    }
    // H9 fix — CSRF protection. The receiver binds to 127.0.0.1 only, but a
    // malicious browser tab on http://localhost:9999 can still POST OTLP-shaped
    // JSON into our ring buffers (then surfaced via /api/otel-events). The main
    // dashboard server has _isOriginAllowed as a mutating-method guard at
    // line ~7202; reuse it here. Claude Code's OTLP exporter sends no Origin
    // header (it's a Node process, not a browser), so the absent-Origin path
    // in _isOriginAllowed correctly accepts it.
    const origin = req.headers.origin;
    if (!_isOriginAllowed(origin)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden origin' }));
      return;
    }
    // Buffer the body. OTLP/HTTP/JSON payloads are small — typical CC export
    // is < 50 KB; cap at 8 MB for safety.
    let bytes = 0;
    const chunks = [];
    const cap = 8 * 1024 * 1024;
    let aborted = false;
    req.on('data', (c) => {
      if (aborted) return;
      bytes += c.length;
      if (bytes > cap) {
        aborted = true;
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'payload too large' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      try {
        // OTLP/HTTP/JSON declares Content-Type: application/json. Some
        // exporters use protobuf at the same path; we reject those because
        // we have no protobuf parser (would violate zero-deps).
        const ct = (req.headers['content-type'] || '').toLowerCase();
        if (!ct.includes('application/json')) {
          res.writeHead(415, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unsupported media type — vdm OTLP receiver only accepts application/json (set OTEL_EXPORTER_OTLP_PROTOCOL=http/json)' }));
          return;
        }
        const body = Buffer.concat(chunks).toString('utf8');
        const payload = JSON.parse(body);
        const records = isLogs ? parseOtlpLogs(payload) : parseOtlpMetrics(payload);
        if (isLogs) _appendOtelLogs(records);
        else _appendOtelMetrics(records);
        _otelStats.lastReceivedAt = Date.now();
        // OTLP wants the partial-success shape; we accept everything.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{}');
      } catch (e) {
        _otelStats.errors++;
        log('warn', `OTLP parse error: ${e.message}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'parse error: ' + e.message }));
      }
    });
    req.on('error', () => { /* socket closed early — drop */ });
  });

  otlpServer.listen(OTLP_PORT, '127.0.0.1', () => {
    log('info', `OTLP/HTTP/JSON receiver on http://localhost:${OTLP_PORT} (logs at /v1/logs, metrics at /v1/metrics; buffer cap ${OTEL_BUFFER_MAX})`);
  });
  _otlpServer = otlpServer;

  otlpServer.on('error', (e) => {
    if (e && e.code === 'EADDRINUSE') {
      log('error', `OTLP port ${OTLP_PORT} already in use — set CSW_OTLP_PORT to an unused port. Continuing without OTel.`);
      return;
    }
    log('error', `OTLP server error: ${e.message}`);
  });
}
