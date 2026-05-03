// Van Damme-o-Matic  - Core Library
// Pure/testable functions extracted from dashboard.mjs.
// Zero dependencies, uses Node.js built-in modules only.

import { createHash } from 'node:crypto';
import { Transform } from 'node:stream';

// ─────────────────────────────────────────────────
// Fingerprinting
// ─────────────────────────────────────────────────

export function getFingerprint(creds) {
  const token = creds?.claudeAiOauth?.accessToken || '';
  return createHash('sha256').update(token).digest('hex').slice(0, 16);
}

export function getFingerprintFromToken(token) {
  return createHash('sha256').update(token || '').digest('hex').slice(0, 16);
}

// ─────────────────────────────────────────────────
// Header building for proxy forwarding
// ─────────────────────────────────────────────────

// RFC 7230 §6.1: hop-by-hop headers that MUST NOT be forwarded by proxies.
// Also includes `connection` itself — plus any headers named in its value.
export const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
  // proxy-connection is not in RFC 7230 but every major proxy implementation
  // (Apache, NGINX, Squid) treats it as hop-by-hop. Some HTTP clients still
  // send it without listing it in `Connection: ...`. Strip on forward so we
  // don't bloat upstream requests with a header api.anthropic.com ignores.
  'proxy-connection',
  // Not strictly hop-by-hop, but must be recalculated by the proxy:
  'host', 'content-length',
  // Strip accept-encoding: proxy must read/inspect error bodies (400, 401, etc.)
  // and compressed responses break the text-based error parsing. Localhost
  // traffic doesn't benefit from compression anyway.
  'accept-encoding',
  // Strip x-api-key: if Claude Code or another client forwards this header,
  // it can cause the API to bill a different account than the OAuth Bearer
  // token, leading to false "credit balance too low" 400 errors.
  'x-api-key',
]);

/**
 * Strip hop-by-hop headers from a headers object (for passthrough / raw forwarding).
 * Also strips any custom hop-by-hop headers declared in the Connection header.
 */
export function stripHopByHopHeaders(originalHeaders) {
  // Locate the Connection header without assuming a specific casing. Node's
  // server normalises to lowercase, but raw callers (tests, custom clients,
  // header objects built by hand) can pass `Connection`, `CONNECTION`, or
  // any mixed form. Walking the keys once is the only correct lookup.
  let connVal = '';
  for (const k of Object.keys(originalHeaders)) {
    if (k.toLowerCase() === 'connection') { connVal = originalHeaders[k] || ''; break; }
  }
  const extraHop = new Set(
    String(connVal).split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  );
  const fwd = {};
  for (const [k, v] of Object.entries(originalHeaders)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || extraHop.has(lk)) continue;
    fwd[k] = v;
  }
  return fwd;
}

export function buildForwardHeaders(originalHeaders, token) {
  const fwd = stripHopByHopHeaders(originalHeaders);
  if (!token || typeof token !== 'string') {
    throw new Error(`Cannot forward request: token is ${token === null ? 'null' : typeof token}`);
  }
  // Strip any case-variant of headers we're about to set canonically.
  // Without this, an inbound `Authorization` (capital A) preserved by
  // stripHopByHopHeaders would coexist with our lowercase `authorization`,
  // causing Node to emit two Authorization headers and the upstream API
  // to reject the request. Same goes for `Anthropic-Beta` vs `anthropic-beta`.
  const TO_REPLACE = new Set(['authorization', 'anthropic-beta']);
  let existingBetas = '';
  for (const k of Object.keys(fwd)) {
    const lk = k.toLowerCase();
    if (!TO_REPLACE.has(lk)) continue;
    if (lk === 'anthropic-beta' && !existingBetas) existingBetas = fwd[k] || '';
    delete fwd[k];
  }
  fwd['authorization'] = `Bearer ${token}`;
  fwd['host'] = 'api.anthropic.com';
  // Ensure OAuth beta
  const betas = existingBetas.split(',').map(s => s.trim()).filter(Boolean);
  if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
  fwd['anthropic-beta'] = betas.join(',');
  return fwd;
}

// ─────────────────────────────────────────────────
// Account state management
// ─────────────────────────────────────────────────

export function createAccountStateManager() {
  const state = new Map();

  function update(token, name, headers) {
    const status = headers['anthropic-ratelimit-unified-status'];
    const u5h = parseFloat(headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    const u7d = parseFloat(headers['anthropic-ratelimit-unified-7d-utilization'] || '0');
    const reset5h = Number(headers['anthropic-ratelimit-unified-5h-reset'] || 0);
    const reset7d = Number(headers['anthropic-ratelimit-unified-7d-reset'] || 0);
    state.set(token, {
      name,
      limited: status === 'limited',
      expired: false,
      resetAt: reset5h,
      resetAt7d: reset7d,
      retryAfter: 0,
      utilization5h: u5h,
      utilization7d: u7d,
      updatedAt: Date.now(),
    });
  }

  function markLimited(token, name, retryAfterSec = 0) {
    const prev = state.get(token) || {};
    state.set(token, {
      ...prev, name, limited: true,
      retryAfter: retryAfterSec ? Date.now() + retryAfterSec * 1000 : prev.retryAfter || 0,
      updatedAt: Date.now(),
    });
  }

  function markExpired(token, name) {
    const prev = state.get(token) || {};
    state.set(token, { ...prev, name, expired: true, updatedAt: Date.now() });
  }

  // Permanent-revocation tracking — feeds the "all accounts dead →
  // proxy bypass" detector. `recordPermanentRefreshFailure` records ONE
  // refresh attempt that returned an OAuth revocation error (per
  // isOAuthRevocationError); after PERMANENT_REVOCATION_FAILURE_THRESHOLD
  // such failures spread across PERMANENT_REVOCATION_MIN_DURATION_MS,
  // the token is considered permanently revoked. Any subsequent
  // successful refresh OR 200 response clears the marker via
  // `clearPermanentRevocation`. This conservative threshold prevents
  // a brief OAuth server outage (returning invalid_grant for legitimate
  // tokens) from tripping bypass mode prematurely.
  function recordPermanentRefreshFailure(token, name, nowMs = Date.now()) {
    const prev = state.get(token) || {};
    const count = (prev.permanentRefreshFailureCount || 0) + 1;
    const firstAt = prev.firstPermanentFailureAtMs || nowMs;
    state.set(token, {
      ...prev, name,
      permanentRefreshFailureCount: count,
      firstPermanentFailureAtMs: firstAt,
      lastPermanentFailureAtMs: nowMs,
      updatedAt: nowMs,
    });
  }

  // Hard-mark a token as permanently revoked, bypassing the 3-strikes-
  // over-1h threshold. Used for unambiguous account-termination signals
  // that arrive in a single API response rather than across multiple
  // refresh attempts — specifically Anthropic's "This organization has
  // been disabled" 400 from the model API. One occurrence of that
  // message means the account is dead regardless of how many refresh
  // attempts succeed; the refresh token may still mint valid bearers,
  // but the API will reject every model call. Treating it as a hard
  // revocation lets bypass mode engage immediately instead of churning
  // 3 OAuth refresh attempts to confirm what we already know.
  function forceMarkPermanentlyRevoked(token, name, reason = '') {
    const prev = state.get(token) || {};
    state.set(token, {
      ...prev, name,
      permanentlyRevoked: true,
      permanentRevocationReason: reason || 'forced',
      permanentRefreshFailureCount: Math.max(prev.permanentRefreshFailureCount || 0, 3),
      firstPermanentFailureAtMs: prev.firstPermanentFailureAtMs || Date.now(),
      lastPermanentFailureAtMs: Date.now(),
      updatedAt: Date.now(),
    });
  }

  function clearPermanentRevocation(token) {
    const prev = state.get(token);
    if (!prev) return;
    if (
      prev.permanentlyRevoked ||
      prev.permanentRefreshFailureCount ||
      prev.firstPermanentFailureAtMs ||
      prev.lastPermanentFailureAtMs
    ) {
      state.set(token, {
        ...prev,
        permanentlyRevoked: false,
        permanentRefreshFailureCount: 0,
        firstPermanentFailureAtMs: 0,
        lastPermanentFailureAtMs: 0,
        updatedAt: Date.now(),
      });
    }
  }

  // Returns true if the token has crossed the count + duration threshold
  // for "permanent revocation" — i.e. enough consecutive revocation-class
  // refresh failures spread over enough wall-clock time that a transient
  // OAuth-server outage is no longer a plausible explanation. Also flips
  // the `permanentlyRevoked` flag the first time it crosses the threshold
  // so callers can read the flag directly via .get().
  function isPermanentlyRevoked(token, nowMs = Date.now(), threshold = 3, minDurationMs = 60 * 60 * 1000) {
    const s = state.get(token);
    if (!s) return false;
    if (s.permanentlyRevoked) return true;
    const count = s.permanentRefreshFailureCount || 0;
    const firstAt = s.firstPermanentFailureAtMs || 0;
    if (count >= threshold && firstAt > 0 && (nowMs - firstAt) >= minDurationMs) {
      // Flip the flag so future reads short-circuit.
      state.set(token, { ...s, permanentlyRevoked: true, updatedAt: nowMs });
      return true;
    }
    return false;
  }

  function clearBillingCooldown(token) {
    const prev = state.get(token);
    if (prev && prev.retryAfter > 0) {
      state.set(token, { ...prev, retryAfter: 0, updatedAt: Date.now() });
    }
  }

  // Per-source-account switch tracking. Used by the proxy's 429 handler to
  // dedupe thundering-herd cascades: when N concurrent in-flight requests
  // all hit 429 against the same just-rotated-away token, only the first
  // should trigger a rotation. The rest must observe the recent switch and
  // retry against the new active token instead of independently picking
  // another "next best" account (N rotations in 100 ms when 1 was enough).
  function markSwitchedFrom(token) {
    const prev = state.get(token) || {};
    state.set(token, { ...prev, lastSwitchAtMs: Date.now(), updatedAt: Date.now() });
  }

  function wasRecentlySwitchedFrom(token, windowMs = 500, nowMs = Date.now()) {
    const acctState = state.get(token);
    if (!acctState || !acctState.lastSwitchAtMs) return false;
    return nowMs - acctState.lastSwitchAtMs < windowMs;
  }

  function get(token) {
    return state.get(token);
  }

  function entries() {
    return state.entries();
  }

  function clear() {
    state.clear();
  }

  function remove(token) {
    state.delete(token);
  }

  return {
    update, markLimited, markExpired, clearBillingCooldown,
    markSwitchedFrom, wasRecentlySwitchedFrom,
    recordPermanentRefreshFailure, forceMarkPermanentlyRevoked,
    clearPermanentRevocation, isPermanentlyRevoked,
    get, entries, clear, remove,
  };
}

/**
 * Returns true if EVERY known account is in a state where vdm rotation
 * cannot help — typically because every refresh token has been revoked.
 * An account is "alive" if ANY of:
 *   - permanentlyRevoked is not set / false
 *   - it has a 5h-reset or 7d-reset window in the future (so it's
 *     temporarily limited, not permanently dead)
 *   - it has had a successful response within liveResponseWindowMs
 *
 * Returns false if no accounts are known (we can't conclude "all dead"
 * from zero data) — bypass mode should only engage when we have at
 * least one account on file and ALL of them have failed.
 *
 * @param {Array<{token: string, expiresAt?: number}>} accounts
 * @param {Object} stateManager — accountStateManager instance
 * @param {Object} [opts]
 * @param {number} [opts.now] — current timestamp (ms since epoch)
 * @param {number} [opts.liveResponseWindowMs] — default 24h
 */
export function areAllAccountsTerminallyDead(accounts, stateManager, opts = {}) {
  if (!Array.isArray(accounts) || accounts.length === 0) return false;
  const now = opts.now || Date.now();
  const liveWindow = opts.liveResponseWindowMs ?? (24 * 60 * 60 * 1000);
  for (const a of accounts) {
    if (!a || !a.token) continue;
    const s = stateManager.get(a.token);
    // No state recorded yet → unknown, treat as alive (don't false-flag
    // a freshly-added account)
    if (!s) return false;
    // Any successful response within the live-window → alive
    const lastSuccessAt = s.lastSuccessAtMs || 0;
    if (lastSuccessAt > 0 && (now - lastSuccessAt) < liveWindow) return false;
    // Permanently revoked? If not, alive.
    if (!s.permanentlyRevoked) return false;
    // Permanently revoked AND has a future rate-limit reset window?
    // That would be a contradictory state (a revoked token shouldn't
    // get rate-limit responses), but we play conservative: alive.
    if (s.resetAt && s.resetAt * 1000 > now) return false;
    if (s.resetAt7d && s.resetAt7d * 1000 > now) return false;
  }
  return true;
}

// ─────────────────────────────────────────────────
// Account availability & selection
// ─────────────────────────────────────────────────

export function isAccountAvailable(token, expiresAt, stateManager, now = Date.now()) {
  const nowSec = Math.floor(now / 1000);
  const acctState = stateManager.get(token);

  // Token expired according to saved expiresAt
  if (expiresAt && expiresAt < now) return false;
  // Marked expired by a 401
  if (acctState?.expired) return false;
  // Limited: unavailable if ANY active cooldown hasn't passed yet.
  // Comparisons use `>` (strict): the rate-limit reset epoch is the moment
  // the account becomes available again, so equality counts as available.
  // The 7-day window is checked alongside the 5-hour one — a weekly cap
  // outlives a 5-hour reset, so missing it would mark a still-limited
  // account available the moment the 5h window rolls over.
  if (acctState?.limited) {
    if (acctState.retryAfter && acctState.retryAfter > now) return false;        // billing cooldown active
    if (acctState.resetAt && acctState.resetAt > nowSec) return false;            // 5h rate-limit active
    if (acctState.resetAt7d && acctState.resetAt7d > nowSec) return false;        // 7d rate-limit active
    return true; // all cooldowns expired
  }
  return true;
}

export function scoreAccount(token, stateManager) {
  const acctState = stateManager.get(token);
  if (!acctState) return 0; // unknown = fresh, try first
  return acctState.utilization5h || 0;
}

// Per-account `excludeFromAuto` flag — opted-out accounts MUST never be
// returned by any auto-pick path. Manual switches (via /api/switch or
// `vdm switch <name>`) bypass these helpers entirely, so the flag does
// what its name says: disable AUTO selection only.
function _isPickable(a, excludeTokens, stateManager, now = Date.now()) {
  return !excludeTokens.has(a.token) &&
    !a.excludeFromAuto &&
    isAccountAvailable(a.token, a.expiresAt, stateManager, now);
}

export function pickBestAccount(accounts, stateManager, excludeTokens = new Set(), now = Date.now()) {
  const candidates = accounts
    .filter(a => _isPickable(a, excludeTokens, stateManager, now))
    .map(a => ({ ...a, score: scoreAccount(a.token, stateManager) }))
    .sort((a, b) => a.score - b.score);
  return candidates[0] || null;
}

export function pickDrainFirst(accounts, stateManager, excludeTokens = new Set(), now = Date.now()) {
  const candidates = accounts
    .filter(a => _isPickable(a, excludeTokens, stateManager, now))
    .map(a => ({ ...a, score: scoreAccount(a.token, stateManager) }))
    .sort((a, b) => b.score - a.score); // highest utilization first
  return candidates[0] || null;
}

/**
 * Score for the "conserve" strategy.
 * Concentrates usage on accounts whose windows are already active.
 * Weekly utilization is primary (scarce resource  - resets once/week).
 * 5hr utilization is secondary tiebreaker.
 * Untouched accounts (0% on both) score 0  - their windows stay dormant.
 */
export function scoreAccountConserve(token, stateManager) {
  const acctState = stateManager.get(token);
  if (!acctState) return 0; // unknown = untouched, preserve it
  const w7d = acctState.utilization7d || 0;
  const w5h = acctState.utilization5h || 0;
  // Weekly dominates (×100), 5hr is tiebreaker (×1)
  return w7d * 100 + w5h;
}

export function pickConserve(accounts, stateManager, excludeTokens = new Set(), now = Date.now()) {
  const candidates = accounts
    .filter(a => _isPickable(a, excludeTokens, stateManager, now))
    .map(a => ({ ...a, score: scoreAccountConserve(a.token, stateManager) }))
    .sort((a, b) => b.score - a.score); // highest combined utilization first
  return candidates[0] || null;
}

export function pickAnyUntried(accounts, excludeTokens, now = Date.now()) {
  // pickAnyUntried is the LAST-RESORT fallback when every other strategy
  // has run out of candidates. Honor `excludeFromAuto` here too — the
  // user explicitly opted that account out of auto selection, so an
  // emergency fallback isn't a good reason to override their choice.
  // `now` is accepted for parameter-list parity with the other pickers
  // (so callers like pickByStrategy can forward `now` uniformly); this
  // function does not check availability so the value is currently unused.
  void now;
  return accounts.find(a => !excludeTokens.has(a.token) && !a.excludeFromAuto) || null;
}

// ─────────────────────────────────────────────────
// Rotation strategies
// ─────────────────────────────────────────────────

export const ROTATION_STRATEGIES = {
  sticky:        { label: 'Sticky',        desc: 'Stay on current account, only switch on rate limit' },
  conserve:      { label: 'Conserve',      desc: 'Max out active accounts first  - untouched windows stay dormant' },
  'round-robin': { label: 'Round-robin',   desc: 'Rotate to lowest-utilization account on a timer' },
  spread:        { label: 'Spread',        desc: 'Always pick lowest utilization (switches often)' },
  'drain-first': { label: 'Drain first',   desc: 'Use highest 5hr-utilization account first' },
};

export const ROTATION_INTERVALS = [15, 30, 60, 120]; // minutes

/**
 * Pick the proactive account based on rotation strategy.
 * Returns null if the current account should be kept (sticky / timer not elapsed).
 *
 * @param {object} opts
 * @param {string} opts.strategy - 'sticky' | 'conserve' | 'round-robin' | 'spread' | 'drain-first'
 * @param {number} opts.intervalMin - rotation interval in minutes (for round-robin)
 * @param {string|null} opts.currentToken - token currently in the keychain
 * @param {number} opts.lastRotationTime - timestamp of last proactive rotation
 * @param {Array} opts.accounts - all account objects
 * @param {object} opts.stateManager - account state manager
 * @param {Set} opts.excludeTokens - tokens to exclude
 * @param {number} [opts.now] - current time (for testing)
 * @returns {{ account: object|null, rotated: boolean }}
 */
export function pickByStrategy(opts) {
  const {
    strategy, intervalMin, currentToken, lastRotationTime,
    accounts, stateManager, excludeTokens = new Set(),
    now = Date.now(),
  } = opts;

  // For all strategies: if current account is unavailable, always pick a replacement
  const currentAcct = accounts.find(a => a.token === currentToken);
  const currentAvailable = currentToken && currentAcct &&
    isAccountAvailable(currentToken, currentAcct.expiresAt, stateManager, now);

  if (!currentAvailable) {
    // Must switch  - pick lowest utilization as safe default
    const best = pickBestAccount(accounts, stateManager, excludeTokens, now);
    return { account: best, rotated: !!best };
  }

  // Current is still usable. Honor `excludeFromAuto` strictly here:
  // the flag's literal meaning is "don't auto-PICK this account", but
  // since the picker functions filter the current account out when it's
  // flagged, every non-sticky strategy below would AUTO-ROTATE-AWAY on
  // every poll (because pickConserve/pickBestAccount returns a different
  // account from current). That violates user intent — they opted out
  // of auto-switching, not opted into mandatory rotation. Treat an
  // excluded-but-available current as "sticky for now": no rotation
  // until either the user manually switches or the account becomes
  // unavailable (rate-limited / expired), at which point the
  // unavailable branch above takes over and pickBestAccount returns
  // the best non-excluded candidate.
  if (currentAcct && currentAcct.excludeFromAuto) {
    return { account: null, rotated: false };
  }

  switch (strategy) {
    case 'sticky':
      // Never proactively switch  - keep current
      return { account: null, rotated: false };

    case 'conserve': {
      // Pick account with highest weekly utilization (windows already active)
      // Untouched accounts stay dormant  - their windows don't start
      const conserved = pickConserve(accounts, stateManager, excludeTokens, now);
      if (conserved && conserved.token !== currentToken) {
        // CR-005 (Codex review): Rotate only if the candidate's conserve
        // score is STRICTLY GREATER than the current account's score.
        // Pre-fix the equal-score case (e.g. all accounts at 0% utilization,
        // or any tie among warm windows) would force-rotate off the
        // current account into another equally-conservative one — waking
        // that account's window for no benefit and violating conserve's
        // promise ("drain already-active windows first, leave dormant
        // accounts dormant"). pickConserve attaches `.score` to the
        // returned spread account.
        const currentScore = scoreAccountConserve(currentToken, stateManager);
        if (conserved.score > currentScore) {
          return { account: conserved, rotated: true };
        }
      }
      return { account: null, rotated: false };
    }

    case 'round-robin': {
      const elapsed = now - (lastRotationTime || 0);
      const intervalMs = (intervalMin || 60) * 60 * 1000;
      if (elapsed < intervalMs) {
        return { account: null, rotated: false }; // timer not elapsed
      }
      const best = pickBestAccount(accounts, stateManager, excludeTokens, now);
      if (best && best.token !== currentToken) {
        return { account: best, rotated: true };
      }
      return { account: null, rotated: false }; // already on best
    }

    case 'spread':
      // Always pick lowest utilization (current behavior)
      const lowest = pickBestAccount(accounts, stateManager, excludeTokens, now);
      if (lowest && lowest.token !== currentToken) {
        return { account: lowest, rotated: true };
      }
      return { account: null, rotated: false };

    case 'drain-first': {
      const drain = pickDrainFirst(accounts, stateManager, excludeTokens, now);
      if (drain && drain.token !== currentToken) {
        return { account: drain, rotated: true };
      }
      return { account: null, rotated: false };
    }

    default:
      return { account: null, rotated: false };
  }
}

// ─────────────────────────────────────────────────
// Earliest reset time
// ─────────────────────────────────────────────────

export function getEarliestReset(stateManager) {
  let earliest = Infinity;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [, acctState] of stateManager.entries()) {
    // Check 5h reset
    if (acctState.resetAt && acctState.resetAt > nowSec && acctState.resetAt < earliest) {
      earliest = acctState.resetAt;
    }
    // Check 7d reset
    if (acctState.resetAt7d && acctState.resetAt7d > nowSec && acctState.resetAt7d < earliest) {
      earliest = acctState.resetAt7d;
    }
  }
  if (earliest === Infinity) return 'unknown';
  const d = new Date(earliest * 1000);
  // Include the weekday when the reset is not today, otherwise just the
  // time. The previous bare `HH:MM` form was misleading for 7-d resets
  // (which almost always cross a calendar boundary): a 36-hour wait read
  // as "8 a.m. today" with no calendar context.
  const now = new Date();
  const sameDay =
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate();
  if (sameDay) {
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleString('en-GB', {
    weekday: 'short', hour: '2-digit', minute: '2-digit',
  });
}

// ─────────────────────────────────────────────────
// Probe cost tracking (rolling 7-day window)
// ─────────────────────────────────────────────────

const PROBE_INPUT_TOKENS = 11;
const PROBE_OUTPUT_TOKENS = 5;
const PROBE_LOG_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

export function createProbeTracker(maxAge = PROBE_LOG_MAX_AGE) {
  const log = [];

  function record(ts = Date.now()) {
    log.push({ ts });
    // Prune entries older than max age
    const cutoff = Date.now() - maxAge;
    while (log.length && log[0].ts < cutoff) log.shift();
  }

  function getStats() {
    const cutoff = Date.now() - maxAge;
    const recent = log.filter(p => p.ts >= cutoff);
    const count = recent.length;
    return {
      probeCount7d: count,
      inputTokens: count * PROBE_INPUT_TOKENS,
      outputTokens: count * PROBE_OUTPUT_TOKENS,
    };
  }

  function getLog() {
    return log;
  }

  function load(entries) {
    // load() is a "replace state" operation — an empty array must clear
    // the in-memory log, not silently keep stale entries from a previous
    // load. Only a non-array (null/undefined/garbage) is a no-op, which
    // matches createUtilizationHistory.load below.
    if (!Array.isArray(entries)) return;
    const cutoff = Date.now() - maxAge;
    const valid = entries.filter(e => e && typeof e.ts === 'number' && e.ts >= cutoff);
    log.length = 0;
    for (const e of valid) log.push(e);
  }

  function toJSON() {
    return log.slice();
  }

  return { record, getStats, getLog, load, toJSON };
}

// Re-export constants for tests
export { PROBE_INPUT_TOKENS, PROBE_OUTPUT_TOKENS, PROBE_LOG_MAX_AGE };

// ─────────────────────────────────────────────────
// Utilization history (for sparklines & velocity)
// ─────────────────────────────────────────────────

const HISTORY_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const HISTORY_MIN_INTERVAL = 2 * 60 * 1000; // 2 min between points

export { HISTORY_MAX_AGE, HISTORY_MIN_INTERVAL };

export function createUtilizationHistory(maxAge = HISTORY_MAX_AGE, minInterval = HISTORY_MIN_INTERVAL) {
  // Map<fingerprint, Array<{ ts, u5h, u7d }>>
  const history = new Map();

  function record(fingerprint, u5h, u7d, ts = Date.now()) {
    if (!history.has(fingerprint)) history.set(fingerprint, []);
    const arr = history.get(fingerprint);
    // STATE-5: clock-jump-backward defense. If `ts` is BEFORE the last
    // entry's ts (NTP correction after a wrong-clock period, manual
    // `date -s`, VM clock weirdness), the previous code:
    //   - update-in-place branch produced a NEGATIVE delta on the
    //     `ts - last.ts < minInterval` check (still true — collapses
    //     the entry but with a non-monotonic ts that breaks OLS
    //     regression in getVelocity downstream)
    //   - cutoff = ts - maxAge becomes a value BEFORE every existing
    //     entry, so the prune loop runs zero iterations and stale
    //     "future" entries persist for hours.
    // Fix: detect a backward jump (ts strictly older than last entry)
    // and reset the array to just the new entry. createSlidingWindowCounter
    // already follows the same convention.
    if (arr.length > 0 && ts < arr[arr.length - 1].ts) {
      arr.length = 0;
      arr.push({ ts, u5h, u7d });
      return;
    }
    // If the last entry is too recent, update it in place (keeps latest value)
    if (arr.length > 0 && ts - arr[arr.length - 1].ts < minInterval) {
      arr[arr.length - 1] = { ts, u5h, u7d };
    } else {
      arr.push({ ts, u5h, u7d });
    }
    // Prune entries older than the window
    const cutoff = ts - maxAge;
    while (arr.length > 0 && arr[0].ts < cutoff) arr.shift();
  }

  function getHistory(fingerprint) {
    return history.get(fingerprint) || [];
  }

  /**
   * Calculate utilization velocity (change per hour) for the 5h window
   * using ordinary least-squares (OLS) linear regression over the last
   * 30 minutes of data.
   *
   * Why regression instead of (last - first)/(last.ts - first.ts):
   * the naive 2-point delta is dominated by the noise on the two endpoints.
   * A single sample landing at a quota tick boundary makes the velocity
   * jump ±2x the true rate, which is what users perceive as "imprecise
   * estimations" and "the prediction keeps swinging". OLS over all points
   * in the window averages out per-sample noise and reduces back to the
   * 2-point formula in the trivial 2-point case (so existing behaviour is
   * preserved for short histories).
   *
   * Returns null when:
   *   - fewer than 2 points exist in the window
   *   - the window spans less than ~9.6 min (preserved from the old impl)
   *   - the slope is non-positive (utilization is flat or dropping; happens
   *     post-reset and would otherwise produce a misleading negative ETA)
   */
  function getVelocity(fingerprint) {
    const arr = history.get(fingerprint);
    if (!arr || arr.length < 2) return null;
    // Use recent window (last 30 min) for velocity, not entire history
    const recentCutoff = Date.now() - 30 * 60 * 1000;
    const recent = arr.filter(e => e.ts >= recentCutoff);
    if (recent.length < 2) return null;
    const first = recent[0];
    const last = recent[recent.length - 1];
    if (last.ts - first.ts < 0.16 * 3600 * 1000) return null; // need ≥ ~9.6 min span
    // OLS slope of u5h regressed on time-in-hours.
    // Convert ts to hours-since-firstTs to keep the numerics small —
    // raw ms timestamps would overflow the squared sums on long-running
    // dashboards and produce subtly wrong slopes.
    const firstTs = first.ts;
    const n = recent.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (const p of recent) {
      const x = (p.ts - firstTs) / 3600000; // hours
      const y = p.u5h;
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumXX += x * x;
    }
    const denom = n * sumXX - sumX * sumX;
    if (denom === 0) return null; // all x identical (shouldn't happen post span-check)
    const slope = (n * sumXY - sumX * sumY) / denom; // utilization-per-hour
    if (slope <= 0) return null; // non-positive slope: dropping or flat
    return slope;
  }

  /**
   * Predict minutes until 5h utilization reaches 1.0 (rate limit).
   * Returns null if velocity is <= 0, insufficient data, OR the projected
   * limit-reach is past the next 5h reset epoch (in which case utilization
   * will roll back to 0 first and the prediction is meaningless).
   *
   * Pass `resetAt5h` (unix epoch seconds) when available so the prediction
   * is clamped against the actual next reset. Without it the function
   * happily returns "6h to limit" while the window is about to roll over
   * in 30 min — exactly the misleading "wrong estimation at end of cycle"
   * pattern users have reported.
   */
  function predictMinutesToLimit(fingerprint, resetAt5h = 0) {
    const arr = history.get(fingerprint);
    if (!arr || arr.length < 2) return null;
    const velocity = getVelocity(fingerprint);
    if (!velocity || velocity <= 0) return null;
    const current = arr[arr.length - 1].u5h;
    const remaining = 1.0 - current;
    if (remaining <= 0) return 0;
    const minutes = Math.round((remaining / velocity) * 60);
    if (resetAt5h && resetAt5h > 0) {
      const nowSec = Math.floor(Date.now() / 1000);
      const minutesToReset = Math.floor((resetAt5h - nowSec) / 60);
      if (minutesToReset > 0 && minutes > minutesToReset) return null;
    }
    return minutes;
  }

  function getAllFingerprints() {
    return [...history.keys()];
  }

  function load(fingerprint, entries) {
    // Mirror createProbeTracker.load semantics (Phase 5 contract):
    //   - Non-array (null/undefined/garbage) is a no-op — do NOT touch the
    //     in-memory state. Callers that explicitly want to clear an entry
    //     must pass an empty array.
    //   - Empty array is a "replace state" operation that clears the slot
    //     so stale entries from a previous load() don't linger.
    // Without this, `load(fp, undefined)` (e.g. from a partially-malformed
    // history JSON whose `fiveH[fp]` is missing) would silently wipe an
    // in-memory entry that the caller never intended to clear.
    if (!Array.isArray(entries)) return;
    if (entries.length === 0) {
      history.set(fingerprint, []);
      return;
    }
    const cutoff = Date.now() - maxAge;
    const valid = entries.filter(e => e && typeof e.ts === 'number' && e.ts >= cutoff);
    history.set(fingerprint, valid);
  }

  function toJSON() {
    const out = {};
    for (const [fp, arr] of history.entries()) {
      if (arr.length) out[fp] = arr;
    }
    return out;
  }

  function clear() {
    history.clear();
  }

  return { record, getHistory, getVelocity, predictMinutesToLimit, getAllFingerprints, load, toJSON, clear };
}

// ─────────────────────────────────────────────────
// OAuth Token Refresh  - Pure Functions
// ─────────────────────────────────────────────────

/**
 * Parse a Retry-After HTTP header value into a delta in seconds.
 *
 * RFC 7231 §7.1.3 allows two forms:
 *   1. delta-seconds: `Retry-After: 120`
 *   2. HTTP-date:     `Retry-After: Fri, 31 Dec 1999 23:59:59 GMT`
 *
 * The previous code used `parseInt(header, 10)` which silently returned
 * 0 for HTTP-date form (and any malformed value). With 0 seconds the
 * 429 was classified as "transient" and passed through to the client
 * without rotation — defeating the auto-switch behaviour for the very
 * case it was designed to handle (long upstream rate-limit window).
 *
 * Returns a non-negative integer count of seconds. 0 if header is
 * missing/empty/unparseable; for HTTP-date in the past, also 0.
 * Result is capped at PARSE_RETRY_AFTER_MAX so a hostile or
 * misconfigured upstream can't talk us into a multi-year cooldown via
 * `Retry-After: Sat, 01 Jan 2099 00:00:00 GMT`. M2 fix bumped the cap
 * from 86400 (1d) to 604800 (7d) so a legitimate Anthropic 7d-window
 * Retry-After response is honored; the previous 1d cap silently dropped
 * the lower bits of any 7d-window value, started a thundering-herd retry
 * mid-window, and burned the upstream rate-limit deeper.
 *
 * Pure function — `now` is injectable for unit tests.
 */
export const PARSE_RETRY_AFTER_MAX = 604_800; // 7d (Anthropic's longest published window)

export function parseRetryAfter(headerValue, now = Date.now()) {
  if (headerValue == null) return 0;
  const trimmed = String(headerValue).trim();
  if (!trimmed) return 0;
  let raw = 0;
  // Form 1: delta-seconds — purely numeric, non-negative integer.
  // We use a regex test (not parseInt) so "120abc" doesn't masquerade
  // as a valid 120-second delta.
  if (/^\d+$/.test(trimmed)) {
    const n = parseInt(trimmed, 10);
    raw = Number.isFinite(n) && n >= 0 ? n : 0;
  } else {
    // Form 2: HTTP-date — let Date.parse handle the three RFC-allowed
    // formats (RFC 1123, RFC 850, asctime). NaN means "unparseable".
    const targetMs = Date.parse(trimmed);
    if (!Number.isFinite(targetMs)) return 0;
    const deltaMs = targetMs - now;
    if (deltaMs <= 0) return 0;
    raw = Math.ceil(deltaMs / 1000);
  }
  // Cap to defend against absurd upstream values (e.g. far-future
  // HTTP-date or a hostile delta-seconds like 999999999). 0 is left
  // unchanged because callers use it as the "transient, pass through"
  // sentinel.
  return Math.min(raw, PARSE_RETRY_AFTER_MAX);
}

/**
 * Build JSON POST body for the OAuth token refresh endpoint.
 */
export function buildRefreshRequestBody(refreshToken, clientId, scope) {
  const body = { grant_type: 'refresh_token', refresh_token: refreshToken };
  if (clientId) body.client_id = clientId;
  if (scope) body.scope = scope;
  return JSON.stringify(body);
}

/**
 * Parse the OAuth refresh endpoint response.
 * Returns { ok, accessToken, refreshToken, expiresIn } on success,
 * or { ok: false, error, retriable } on failure.
 */
export function parseRefreshResponse(statusCode, bodyStr) {
  if (statusCode >= 200 && statusCode < 300) {
    try {
      const data = JSON.parse(bodyStr);
      const accessToken = data.access_token || data.accessToken;
      const refreshToken = data.refresh_token || data.refreshToken;
      const expiresInRaw = data.expires_in != null ? data.expires_in
                         : data.expiresIn != null ? data.expiresIn
                         : 0;
      // M1 fix — type-validate every field. A buggy/hostile upstream sending
      // {access_token: 12345, expires_in: "huge"} could otherwise produce a
      // numeric Bearer token or NaN expiresAt (= "never expires"). Reject
      // with a non-retriable error so the caller falls back to the documented
      // 8h default in the dashboard wrapper rather than looping the OAuth
      // endpoint on a malformed response.
      if (typeof accessToken !== 'string' || accessToken.length === 0) {
        return { ok: false, error: 'No access_token in response (missing or not a non-empty string)', retriable: false };
      }
      if (refreshToken != null && (typeof refreshToken !== 'string' || refreshToken.length === 0)) {
        return { ok: false, error: 'refresh_token must be a non-empty string or absent', retriable: false };
      }
      // M5 fix — reject expires_in <= 0 and non-finite values. expires_in: 0
      // would make shouldRefreshToken always return true (immediate-refresh
      // loop). Negative expires_in produces past expiresAt → token treated
      // as already-expired → another refresh loop. Non-finite (NaN, "huge")
      // produces NaN expiresAt → token treated as never-expiring.
      // REFRESH-2 fix: distinguish FORMAT errors (non-number, NaN — never
      // retriable) from VALUE errors (zero / negative — Anthropic might
      // legitimately emit `expires_in: 0` for a token that needs immediate
      // re-auth, and the previous non-retriable behavior froze the user
      // out for 2 hours). Numeric-but-non-positive is now retriable so
      // the next sweep retries in minutes.
      if (typeof expiresInRaw !== 'number' || !Number.isFinite(expiresInRaw)) {
        return { ok: false, error: `expires_in must be a finite number, got ${typeof expiresInRaw === 'number' ? expiresInRaw : typeof expiresInRaw}`, retriable: false };
      }
      if (expiresInRaw <= 0) {
        return { ok: false, error: `expires_in is non-positive (${expiresInRaw}) — token requires re-auth`, retriable: true };
      }
      return { ok: true, accessToken, refreshToken: refreshToken || null, expiresIn: expiresInRaw };
    } catch (e) {
      return { ok: false, error: `Invalid JSON: ${e.message}`, retriable: false };
    }
  }
  // Retriable: 429 (rate limit), 500+ (server errors)
  const retriable = statusCode === 429 || statusCode >= 500;
  let error = `HTTP ${statusCode}`;
  try {
    const data = JSON.parse(bodyStr);
    const raw = data.error_description || data.error || data.message || error;
    error = typeof raw === 'string' ? raw : (raw && raw.message) || JSON.stringify(raw);
  } catch {}
  return { ok: false, error, retriable };
}

/**
 * Convert expires_in (seconds) to an absolute millisecond timestamp.
 */
export function computeExpiresAt(expiresInSec, now = Date.now()) {
  return now + expiresInSec * 1000;
}

/**
 * Classify an OAuth refresh-endpoint error as "the refresh token itself
 * is dead" (true) vs "transient / try again later / unknown" (false).
 *
 * Per RFC 6749 §5.2, the refresh endpoint emits a 400 with `error` set
 * to one of: `invalid_request` | `invalid_client` | `invalid_grant` |
 * `unauthorized_client` | `unsupported_grant_type` | `invalid_scope`.
 *
 * Of those, three indicate the GRANT (refresh token) itself is dead:
 *   - `invalid_grant`         — refresh token revoked/expired/invalid
 *   - `unauthorized_client`   — client_id no longer allowed for this grant
 *   - `invalid_client`        — client_id rejected (also terminal for vdm,
 *                               which uses one hardcoded client_id)
 *
 * `access_denied` is added because Anthropic occasionally returns it for
 * accounts that have been administratively suspended.
 *
 * Distinguishing these from transient failures is what lets vdm's
 * "all-accounts-revoked → bypass mode" detector avoid false positives:
 * a 429 / 5xx / network timeout will NEVER classify as a revocation, so
 * an OAuth-server outage cannot trip bypass mode.
 *
 * @param {string} errorText — error text or JSON body from refresh
 *   response. Tolerates JSON, key=value pairs, or a bare error code.
 * @returns {boolean} true if the error indicates permanent revocation
 */
export function isOAuthRevocationError(errorText) {
  if (typeof errorText !== 'string' || !errorText) return false;
  const PERMANENT = new Set([
    'invalid_grant',
    'unauthorized_client',
    'invalid_client',
    'access_denied',
  ]);
  // Try JSON parse first — RFC 6749 standard form.
  try {
    const parsed = JSON.parse(errorText);
    if (parsed && typeof parsed === 'object') {
      if (typeof parsed.error === 'string' && PERMANENT.has(parsed.error)) return true;
      // Some non-conformant servers nest under `error.code`
      if (parsed.error && typeof parsed.error.code === 'string' && PERMANENT.has(parsed.error.code)) return true;
    }
  } catch { /* fall through to substring match */ }
  // Substring fallback — covers cases where the caller already extracted
  // the error_description string (parseRefreshResponse does this) and
  // the raw `error` code is no longer in the text. We look for the bare
  // token preceded by a non-word character (or start-of-string) and
  // followed by a non-word character (or end-of-string) so we don't
  // false-positive on `not_invalid_grant_lookup_table` etc.
  for (const code of PERMANENT) {
    const re = new RegExp(`(^|[^a-z_])${code}([^a-z_]|$)`, 'i');
    if (re.test(errorText)) return true;
  }
  return false;
}

/**
 * Immutably build updated credentials, preserving all fields except tokens/expiry.
 */
export function buildUpdatedCreds(oldCreds, newAccessToken, newRefreshToken, newExpiresAt) {
  return {
    ...oldCreds,
    claudeAiOauth: {
      ...oldCreds.claudeAiOauth,
      accessToken: newAccessToken,
      ...(newRefreshToken != null ? { refreshToken: newRefreshToken } : {}),
      expiresAt: newExpiresAt,
    },
  };
}

/**
 * Returns true if the token is within bufferMs of expiry.
 * Returns false for unknown/falsy expiresAt (don't proactively refresh unknown tokens).
 */
export function shouldRefreshToken(expiresAt, bufferMs = 60 * 60 * 1000, now = Date.now()) {
  if (!expiresAt) return false;
  return expiresAt - now <= bufferMs;
}

/**
 * Return true if `cwd` points inside a directory that is NEVER a real
 * user project — system caches, plugin caches, temp dirs, package
 * installation dirs, etc. Token-usage rows whose attribution would
 * otherwise resolve to one of these paths are misleading because the
 * SAME directory hosts code shared across many distinct CC sessions
 * (e.g. ~/.claude/plugins/cache/<plugin>/ is referenced by every
 * session that uses that plugin — attributing tokens to the plugin
 * instead of the user's project hides who actually consumed them).
 *
 * Detection is conservative: only matches well-known system paths.
 * Anything in $HOME outside the listed prefixes is still treated as
 * a real project.
 *
 * @param {string} cwd absolute path to test (typically from a hook
 *   payload's `cwd` field).
 * @param {string} [home] override $HOME for testing
 * @returns {boolean}
 */
export function isNonProjectCwd(cwd, home = process.env.HOME || '') {
  if (typeof cwd !== 'string' || !cwd) return false;
  // Normalise trailing slashes — `/foo/` and `/foo` are the same.
  const norm = cwd.replace(/\/+$/, '');
  // System / temp roots — never user projects.
  const SYSTEM_PREFIXES = [
    '/tmp/',
    '/private/tmp/',
    '/var/tmp/',
    '/var/folders/',     // macOS per-user tmp under /var/folders/<X>/<Y>/T/
    '/private/var/',
    '/usr/',
    '/opt/',
  ];
  for (const p of SYSTEM_PREFIXES) {
    if (norm === p.replace(/\/$/, '') || norm.startsWith(p)) return true;
  }
  // node_modules anywhere in path — the package install lives there but
  // the project isn't node_modules itself.
  if (norm.includes('/node_modules/') || norm.endsWith('/node_modules')) {
    return true;
  }
  // $HOME-relative caches — only if $HOME is known.
  if (home && norm.startsWith(home + '/')) {
    const HOME_PREFIXES = [
      '/.claude/',         // CC's own state — sessions, plugins, settings
      '/.npm/',
      '/.cache/',
      '/.local/share/',
      '/.local/state/',
      '/.config/',
      '/Library/Caches/',  // macOS user caches
      '/Library/Application Support/Code/',
      '/Library/Application Support/Claude/',
    ];
    const tail = norm.slice(home.length);
    for (const p of HOME_PREFIXES) {
      if (tail === p.replace(/\/$/, '') || tail.startsWith(p)) return true;
    }
  }
  return false;
}

/**
 * Stronger "this refresh token is dead" detector than `shouldRefreshToken`.
 * Returns true ONLY when `expiresAt` is in the ACTUAL past (no buffer). The
 * 5-minute / 1-hour proactive-refresh buffer that `shouldRefreshToken` uses
 * is the right heuristic for "should refresh soon" but the WRONG one for
 * "provably unusable" — a token with 3 minutes left plus a transient OAuth-
 * server blip (5xx, timeout, wifi reconnect) would falsely classify as dead
 * even though the still-valid token would connect fine.
 *
 * Per the Claude Code source (bridge/initReplBridge.ts:203-240, v2.1.89):
 *   "Check actual expiry instead: past-expiry AND refresh-failed → truly dead."
 *
 * The vdm refresh wrapper retries up to REFRESH_MAX_RETRIES with exponential
 * backoff, so by the time it returns !ok the OAuth endpoint has been given
 * multiple chances. If `expiresAt < now()` STILL holds at that point, no
 * future refresh attempt will succeed without user re-auth — the refresh
 * grant has been revoked at the IdP.
 *
 * Returns false for unknown/falsy expiresAt (env-var / FD tokens carry
 * `expiresAt: null` and must never trip this check).
 *
 * @param {number|null|undefined} expiresAt — epoch ms or null
 * @param {number} [now] — current time (for testing)
 * @returns {boolean}
 */
export function isPostRefreshTrulyExpired(expiresAt, now = Date.now()) {
  if (!expiresAt) return false;          // null = unknown → don't speculate
  if (typeof expiresAt !== 'number') return false;
  if (!Number.isFinite(expiresAt)) return false;
  return expiresAt <= now;
}

// ─────────────────────────────────────────────────
// Phase 1 of TRDD-1645134b — usage tree aggregation
// ─────────────────────────────────────────────────

/**
 * Classify a token-usage row's "component" — one level of the
 * 4-level tree breakdown (CC instance → worktree → COMPONENT → tool).
 *
 * Returns one of:
 *   - 'main'                 — the parent CC's main agent turn
 *   - 'subagent:<type>'      — a sub-agent turn (Task tool, Explore, etc.)
 *   - 'skill:<name>'         — a skill execution
 *   - 'main'                 — fallback when none of the above apply
 *
 * The classification is purely from the row's existing fields (no
 * disk reads, no IPC) so it can be applied to historical rows during
 * aggregation without inflating run-time.
 *
 * @param {Object} row — a token-usage row (Phase D schema)
 * @returns {string}
 */
export function classifyUsageComponent(row) {
  if (!row || typeof row !== 'object') return 'main';
  // Subagent: parent attribution + agent type both must be set.
  // parentSessionId alone isn't enough — sub-agent rows that fell back
  // through CL-3 attribution have parentSessionId=parentId but
  // agentType=null. In that case treat as a generic subagent.
  if (row.parentSessionId) {
    const t = (row.agentType || '').trim();
    return t ? `subagent:${t}` : 'subagent:unknown';
  }
  // Skill rows — identified by tool name. Claude Code's Skill tool
  // names follow the convention `Skill(<plugin>:<skill>)`, `Skill: <name>`,
  // or just `Skill` with mcpServer field carrying the plugin name.
  if (typeof row.tool === 'string') {
    const trimmed = row.tool.trim();
    // Audit SC-OPUS-007 (CWE-1333) — defensive length cap. The
    // /^Skill[\s(:]/ test is linear-time and ReDoS-safe, but a
    // pathological 1MB tool name from a hostile sub-agent would still
    // consume CPU. Tool names have no legitimate use case beyond
    // a few hundred chars; treat anything over 256 as "main" so
    // the regex never sees it.
    if (trimmed.length > 256) return 'main';
    if (trimmed === 'Skill' || /^Skill[\s(:]/.test(trimmed)) {
      // Try to extract the skill name. Patterns observed:
      //   "Skill(plugin:skill)"  → "plugin:skill"
      //   "Skill: foo"           → "foo"
      //   "Skill foo"            → "foo"
      //   "Skill"                → use mcpServer if present, else "unknown"
      // Audit MINOR-5: try paren form first (must close); fall back to
      // colon/whitespace form. Without the explicit close-paren the
      // earlier single regex consumed trailing junk into the capture
      // (e.g. "Skill(foo) extra" → "foo) extra").
      let m = trimmed.match(/^Skill\s*\(\s*(.+?)\s*\)\s*$/);
      if (!m) m = trimmed.match(/^Skill\s*[:\s]\s*(.+?)\s*$/);
      // Audit Round-2 R2-MINOR-1: `m[1].trim()` can be empty when the
      // user wrote "Skill( )" (whitespace-only inside parens) —
      // `(.+?)` requires at least one char which whitespace satisfies,
      // but trim() collapses to ''. Treat empty-after-trim as no match
      // so we fall through to the mcpServer fallback rather than
      // emitting `skill:` (an unhelpful UI label).
      if (m && m[1]) {
        const skillName = m[1].trim();
        if (skillName) return `skill:${skillName}`;
      }
      const fallback = (row.mcpServer || '').trim();
      return `skill:${fallback || 'unknown'}`;
    }
  }
  return 'main';
}

/**
 * Aggregate token-usage rows into the 4-level tree structure
 * documented in TRDD-1645134b §"Tree-view design":
 *
 *   repo → branch (worktree) → component → tool → totals
 *
 * Returns:
 *   {
 *     totals: { input, output, cacheRead, cacheCreate, requests },
 *     tree:   [ <repoNode>, ... ]
 *   }
 *
 * Each tree node has shape:
 *   {
 *     name: string,
 *     kind: 'repo' | 'branch' | 'component' | 'tool',
 *     totals: { ... },
 *     children: [ ... ]   // omitted on tool-level leaves
 *     isWorktree: boolean // only on 'branch' nodes
 *   }
 *
 * Skips:
 *   - Rows with type !== 'usage' (compact_boundary markers etc.)
 *   - Rows with non-finite/missing token fields (defensive — bad rows
 *     in the on-disk file shouldn't crash the aggregator)
 *
 * @param {Array<Object>} rows — token-usage rows
 * @param {Object} [opts]
 * @param {string} [opts.repoFilter]    — only this repo
 * @param {string} [opts.accountFilter] — only this account
 * @param {string} [opts.modelFilter]   — only this model
 * @param {number} [opts.from]          — earliest ts (epoch ms)
 * @param {number} [opts.to]            — latest ts (epoch ms)
 * @returns {{totals: Object, tree: Array<Object>}}
 */
export function aggregateUsageTree(rows, opts = {}) {
  const TOOL_NULL_KEY = '<assistant>';   // synthetic name for tool=null rows
  function emptyTotals() {
    return { input: 0, output: 0, cacheRead: 0, cacheCreate: 0, requests: 0 };
  }
  function addToTotals(t, row) {
    t.input       += row.inputTokens               || 0;
    t.output      += row.outputTokens              || 0;
    t.cacheRead   += row.cacheReadInputTokens      || 0;
    t.cacheCreate += row.cacheCreationInputTokens  || 0;
    t.requests    += 1;
  }

  const grandTotals = emptyTotals();
  // Map<repo, Map<branch, Map<component, Map<tool, totals>>>>
  const repos = new Map();

  if (!Array.isArray(rows)) return { totals: grandTotals, tree: [] };

  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    if ((row.type || 'usage') !== 'usage') continue;
    if (opts.repoFilter    && row.repo    !== opts.repoFilter)    continue;
    if (opts.accountFilter && row.account !== opts.accountFilter) continue;
    if (opts.modelFilter   && row.model   !== opts.modelFilter)   continue;
    // Audit MINOR-6: when a time bound is set, require the row to have a
    // finite ts. Without this guard, rows where ts is undefined/null
    // pass both the < and > checks (undefined comparisons → false) and
    // get silently INCLUDED in a date-range view.
    if ((opts.from != null || opts.to != null)
        && (typeof row.ts !== 'number' || !Number.isFinite(row.ts))) continue;
    if (opts.from != null && row.ts < opts.from) continue;
    if (opts.to   != null && row.ts > opts.to)   continue;

    // Defensive: any non-finite OR NEGATIVE token field skips the row
    // rather than poisoning the totals with NaN/Infinity (MAJOR-3) or
    // negatives that would silently subtract from grand totals.
    const tokens = [row.inputTokens, row.outputTokens, row.cacheReadInputTokens, row.cacheCreationInputTokens];
    if (tokens.some(t => t != null && (typeof t !== 'number' || !Number.isFinite(t) || t < 0))) {
      continue;
    }

    const repoKey      = row.repo   || '(unknown-repo)';
    const branchKey    = row.branch || '(unknown-branch)';
    const componentKey = classifyUsageComponent(row);
    const toolKey      = row.tool ? row.tool : TOOL_NULL_KEY;

    addToTotals(grandTotals, row);

    let branches = repos.get(repoKey);
    if (!branches) { branches = new Map(); repos.set(repoKey, branches); }

    let components = branches.get(branchKey);
    if (!components) { components = new Map(); branches.set(branchKey, components); }

    let tools = components.get(componentKey);
    if (!tools) { tools = new Map(); components.set(componentKey, tools); }

    let toolTotals = tools.get(toolKey);
    if (!toolTotals) { toolTotals = emptyTotals(); tools.set(toolKey, toolTotals); }

    addToTotals(toolTotals, row);
  }

  // Walk the maps and build the tree array. Roll up child totals as we go.
  const tree = [];
  for (const [repoName, branches] of repos) {
    const repoNode = { name: repoName, kind: 'repo', totals: emptyTotals(), children: [] };
    for (const [branchName, components] of branches) {
      // A branch is a "worktree" when it differs from the conventional
      // primary-branch names. Conservative heuristic: anything other
      // than 'main', 'master', '(no git)', '(unknown-branch)' is treated
      // as a worktree. Real heads named 'main' inside a worktree would
      // mis-classify as non-worktree, but that's a rare and harmless
      // case (the user can still see the branch name).
      const branchNode = {
        name: branchName,
        kind: 'branch',
        isWorktree: !['main', 'master', '(no git)', '(unknown-branch)'].includes(branchName),
        totals: emptyTotals(),
        children: [],
      };
      for (const [componentName, tools] of components) {
        const compNode = { name: componentName, kind: 'component', totals: emptyTotals(), children: [] };
        for (const [toolName, toolTotals] of tools) {
          compNode.children.push({ name: toolName, kind: 'tool', totals: toolTotals });
          // Roll into component
          compNode.totals.input       += toolTotals.input;
          compNode.totals.output      += toolTotals.output;
          compNode.totals.cacheRead   += toolTotals.cacheRead;
          compNode.totals.cacheCreate += toolTotals.cacheCreate;
          compNode.totals.requests    += toolTotals.requests;
        }
        branchNode.children.push(compNode);
        // Roll into branch
        branchNode.totals.input       += compNode.totals.input;
        branchNode.totals.output      += compNode.totals.output;
        branchNode.totals.cacheRead   += compNode.totals.cacheRead;
        branchNode.totals.cacheCreate += compNode.totals.cacheCreate;
        branchNode.totals.requests    += compNode.totals.requests;
      }
      repoNode.children.push(branchNode);
      // Roll into repo
      repoNode.totals.input       += branchNode.totals.input;
      repoNode.totals.output      += branchNode.totals.output;
      repoNode.totals.cacheRead   += branchNode.totals.cacheRead;
      repoNode.totals.cacheCreate += branchNode.totals.cacheCreate;
      repoNode.totals.requests    += branchNode.totals.requests;
    }
    tree.push(repoNode);
  }
  // Sort each level by total tokens descending — the heavy hitters
  // surface at the top, so users see the consequential rows first
  // without scrolling.
  // Audit NIT-2: secondary sort by name keeps tied siblings in
  // deterministic order so the UI hash-diff cache doesn't flap when
  // a single new row lands between two ties.
  function sortByInputDesc(a, b) {
    const d = (b.totals.input + b.totals.output) - (a.totals.input + a.totals.output);
    if (d !== 0) return d;
    return (a.name || '').localeCompare(b.name || '');
  }
  tree.sort(sortByInputDesc);
  for (const repo of tree) {
    repo.children.sort(sortByInputDesc);
    for (const branch of repo.children) {
      branch.children.sort(sortByInputDesc);
      for (const component of branch.children) {
        component.children.sort(sortByInputDesc);
      }
    }
  }
  return { totals: grandTotals, tree };
}

// Model pricing in USD per million tokens. Mirrors the dashboard.mjs
// TOK_PRICING table — kept here so server-side CSV export can compute
// cost without round-tripping to the client. When updating one, update
// both. Source of truth for rates: https://claude.com/pricing.
//
// Cache rates follow Anthropic's published 1.25x (creation) /
// 0.10x (read) ratios on top of input rate.
export const MODEL_PRICING = {
  // Opus generation — $15/$75
  'claude-opus-4-7':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  'claude-opus-4-6':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  'claude-opus-4-5':   { input: 15.00, output: 75.00, cacheRead: 1.50,  cacheCreation: 18.75 },
  // Sonnet generation — $3/$15
  'claude-sonnet-4-7': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  'claude-sonnet-4-6': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  'claude-sonnet-4-5': { input: 3.00,  output: 15.00, cacheRead: 0.30,  cacheCreation: 3.75 },
  // Haiku generation — $0.80/$4
  'claude-haiku-4-6':  { input: 0.80,  output: 4.00,  cacheRead: 0.08,  cacheCreation: 1.00 },
  'claude-haiku-4-5':  { input: 0.80,  output: 4.00,  cacheRead: 0.08,  cacheCreation: 1.00 },
};
// Median fallback (Sonnet rates) for any unknown model — returns a
// non-zero cost so the operator notices something is unaccounted for
// versus returning 0 which would silently undercount. NOTE: this is
// "median", NOT "conservative" — it UNDER-counts an Opus-generation
// model (5x cheaper than reality) and OVER-counts a Haiku-generation
// model (3-4x more expensive). Operators should add new model entries
// to MODEL_PRICING above as soon as Anthropic ships them rather than
// relying on this default.
export const MODEL_PRICING_DEFAULT = { input: 3, output: 15, cacheRead: 0.30, cacheCreation: 3.75 };

/**
 * Compute USD cost for a single row's token counts.
 * @param {string|null} model
 * @param {number} inTok
 * @param {number} outTok
 * @param {number} cacheReadTok
 * @param {number} cacheCreationTok
 * @returns {number} cost in USD (may be 0 if all token counts are 0)
 */
export function estimateModelCost(model, inTok, outTok, cacheReadTok, cacheCreationTok) {
  // Audit MAJOR-2: clamp inputs to non-negative finite numbers BEFORE
  // any arithmetic so downstream sums can't be poisoned by NaN /
  // Infinity / negative values. The (inTok || 0) further down then
  // becomes redundant but harmless; left for readability.
  inTok            = Math.max(0, Number.isFinite(inTok)            ? inTok            : 0);
  outTok           = Math.max(0, Number.isFinite(outTok)           ? outTok           : 0);
  cacheReadTok     = Math.max(0, Number.isFinite(cacheReadTok)     ? cacheReadTok     : 0);
  cacheCreationTok = Math.max(0, Number.isFinite(cacheCreationTok) ? cacheCreationTok : 0);
  if (!model || typeof model !== 'string') {
    // Unknown / unset model — apply the default rates so we don't silently
    // emit $0 for every row that happens to be missing a model field.
    const p = MODEL_PRICING_DEFAULT;
    return ((inTok || 0)              * p.input
          + (outTok || 0)             * p.output
          + (cacheReadTok || 0)       * p.cacheRead
          + (cacheCreationTok || 0)   * p.cacheCreation) / 1_000_000;
  }
  // Match by prefix so future date-suffixed model IDs (e.g.
  // claude-opus-4-7-20260315) still resolve to the right base price.
  let p = null;
  for (const key of Object.keys(MODEL_PRICING)) {
    if (model === key || model.startsWith(key + '-')) { p = MODEL_PRICING[key]; break; }
  }
  if (!p) p = MODEL_PRICING_DEFAULT;
  return ((inTok || 0)              * p.input
        + (outTok || 0)             * p.output
        + (cacheReadTok || 0)       * p.cacheRead
        + (cacheCreationTok || 0)   * p.cacheCreation) / 1_000_000;
}

/**
 * Aggregate token-usage rows into flat (repo, branch, component, tool)
 * rows suitable for CSV export. This is the SAME bucketing as
 * aggregateUsageTree but emits a flat array instead of a nested tree,
 * AND tracks `totalCostUSD` per bucket (computed per-row using the
 * row's `model` field, then summed across the bucket — so a single
 * leaf may include cost from multiple models).
 *
 * The cost column is the only reason this can't reuse aggregateUsageTree
 * verbatim — the tree throws away per-row model info on its way to a
 * single per-bucket totals object.
 *
 * @param {Array<Object>} rows
 * @param {Object} [opts] same filter shape as aggregateUsageTree
 * @returns {Array<{repo, branch, isWorktree, component, tool,
 *   inputTokens, outputTokens, cacheReadTokens, cacheCreationTokens,
 *   totalCostUSD, requestCount}>}
 */
export function aggregateUsageForCsvExport(rows, opts = {}) {
  const TOOL_NULL_KEY = '<assistant>';
  if (!Array.isArray(rows)) return [];

  // Map<key, accumulator>  where key = repo|branch|component|tool
  const buckets = new Map();

  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    if ((row.type || 'usage') !== 'usage') continue;
    if (opts.repoFilter    && row.repo    !== opts.repoFilter)    continue;
    if (opts.accountFilter && row.account !== opts.accountFilter) continue;
    if (opts.modelFilter   && row.model   !== opts.modelFilter)   continue;
    // Audit MINOR-6: require finite ts when either bound is set so
    // un-timestamped rows don't silently pass both comparisons.
    if ((opts.from != null || opts.to != null)
        && (typeof row.ts !== 'number' || !Number.isFinite(row.ts))) continue;
    if (opts.from != null && row.ts < opts.from) continue;
    if (opts.to   != null && row.ts > opts.to)   continue;

    // Audit MAJOR-3: also reject negative token fields — the bare
    // !Number.isFinite check let -500 through and that subtracted
    // from grand totals.
    const tokens = [row.inputTokens, row.outputTokens, row.cacheReadInputTokens, row.cacheCreationInputTokens];
    if (tokens.some(t => t != null && (typeof t !== 'number' || !Number.isFinite(t) || t < 0))) continue;

    const repoKey      = row.repo   || '(unknown-repo)';
    const branchKey    = row.branch || '(unknown-branch)';
    const componentKey = classifyUsageComponent(row);
    const toolKey      = row.tool ? row.tool : TOOL_NULL_KEY;

    // Use NUL byte as separator so a literal pipe in any field can't
    // collide with another bucket's key (file paths can contain |
    // technically; \0 cannot).
    const key = repoKey + '\0' + branchKey + '\0' + componentKey + '\0' + toolKey;
    let acc = buckets.get(key);
    if (!acc) {
      acc = {
        repo: repoKey,
        branch: branchKey,
        isWorktree: !['main', 'master', '(no git)', '(unknown-branch)'].includes(branchKey),
        component: componentKey,
        tool: toolKey,
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheCreationTokens: 0,
        totalCostUSD: 0,
        requestCount: 0,
      };
      buckets.set(key, acc);
    }
    const inTok        = row.inputTokens                 || 0;
    const outTok       = row.outputTokens                || 0;
    const cacheRead    = row.cacheReadInputTokens        || 0;
    const cacheCreate  = row.cacheCreationInputTokens    || 0;
    acc.inputTokens         += inTok;
    acc.outputTokens        += outTok;
    acc.cacheReadTokens     += cacheRead;
    acc.cacheCreationTokens += cacheCreate;
    acc.totalCostUSD        += estimateModelCost(row.model, inTok, outTok, cacheRead, cacheCreate);
    acc.requestCount        += 1;
  }

  // Sort by total tokens desc so the CSV is human-readable (heavy hitters
  // at the top) without an extra step for spreadsheet importers.
  const out = Array.from(buckets.values());
  out.sort((a, b) => (b.inputTokens + b.outputTokens) - (a.inputTokens + a.outputTokens));
  return out;
}

/**
 * Encode a value as a CSV field per RFC 4180:
 *   - Always wrap in double-quotes
 *   - Escape internal " by doubling it
 *   - Strings, numbers, booleans, null/undefined all handled
 *   - Newlines preserved (RFC 4180 allows \n inside quoted fields)
 *
 * Always-quote (vs. quote-only-when-needed) keeps the parser code
 * trivially simple on the importer side.
 *
 * @param {*} v
 * @returns {string}
 */
export function csvField(v) {
  if (v == null) return '""';
  let s;
  let isUserString = false;
  if (typeof v === 'boolean') s = v ? 'true' : 'false';
  else if (typeof v === 'number') s = Number.isFinite(v) ? String(v) : '';
  else { s = String(v); isUserString = true; }
  // Audit SC-OPUS-001 — CSV formula injection (CWE-1236, OWASP A03:2021).
  // Cells starting with =, +, -, @, \t, or \r are evaluated as formulas
  // by Excel / LibreOffice / Sheets / Numbers when the file is opened.
  // Repo paths, sub-agent names, skill names, and tool names are all
  // user-controlled (third-party plugins, user-cloned repo dirs), so a
  // hostile sub-agent name like `=cmd|'/c calc'!A0` would land in a
  // CSV bucket and fire when the operator opened the export. Prefix
  // with a single quote so the cell renders as the literal string.
  //
  // Only apply to STRING inputs — a legitimate negative number (-1.5)
  // is produced via String(v) above and isn't an injection vector
  // (Excel parses it as a numeric cell). Prefixing it with ' would
  // turn a numeric column into text and break spreadsheet sums.
  // Audit Round-2 R2-MINOR-2: include \n in the trigger set. Excel
  // ignores leading whitespace in formulas, so a cell starting with
  // \n=cmd would still execute. \r is already covered; without \n
  // a multi-line cell payload would slip past.
  if (isUserString && s.length > 0 && /^[=+\-@\t\r\n]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

/**
 * Render the flat aggregated rows from `aggregateUsageForCsvExport`
 * to a complete CSV string per RFC 4180.
 *
 * Header line is always emitted, even when the row array is empty —
 * importers that auto-detect schema from the header still get
 * something parseable.
 *
 * @param {Array<Object>} rows from aggregateUsageForCsvExport
 * @returns {string} complete CSV (header + body, lines joined by \n)
 */
export function renderUsageTreeCsv(rows) {
  const header = [
    'repo', 'branch', 'isWorktree', 'component', 'tool',
    'inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheCreationTokens',
    'totalCostUSD', 'requestCount',
  ].join(',');
  // Audit MINOR-2: RFC 4180 §2.1 mandates CRLF between records. Excel
  // handles both, but Python's csv module strict mode and some JVM
  // parsers reject LF-only files.
  if (!Array.isArray(rows) || !rows.length) return header + '\r\n';
  const lines = [header];
  for (const r of rows) {
    lines.push([
      csvField(r.repo),
      csvField(r.branch),
      csvField(r.isWorktree),
      csvField(r.component),
      csvField(r.tool),
      csvField(r.inputTokens),
      csvField(r.outputTokens),
      csvField(r.cacheReadTokens),
      csvField(r.cacheCreationTokens),
      // Cost rounded to 6 decimals — fractions of a cent are noise but
      // rounding to 2 decimals would silently zero out small turns.
      csvField(Math.round((r.totalCostUSD || 0) * 1_000_000) / 1_000_000),
      csvField(r.requestCount),
    ].join(','));
  }
  return lines.join('\r\n') + '\r\n';
}

/**
 * Cache-miss heuristic per TRDD-1645134b §"Cache-miss detection".
 *
 * For each session (grouped by sessionId), iterate rows in
 * chronological order. A row counts as a likely cache MISS when:
 *   - Some prior row in the same session had cacheCreationInputTokens > 0
 *     (i.e. a cache existed at some point)
 *   - This row's cacheReadInputTokens === 0 (it didn't read the cache)
 *   - This row's inputTokens >= minInputForMissDetection (default 1000)
 *
 * Phase 5 — richer reason classification:
 *   - "compact-boundary" — a `compact_boundary` row (written by the
 *     PreCompact/PostCompact hooks via buildCompactBoundaryEntry —
 *     that's the canonical schema in token-usage.json) preceded this
 *     miss in the same session. Anthropic invalidates the cache on
 *     every compact (the prefix changes by definition). Not really a
 *     "miss" in the pejorative sense — surfaced so the operator can
 *     correlate spend against compaction frequency.
 *   - "model-changed" — the prior cache-creation row was on a different
 *     model. Caches are model-scoped; switching from claude-opus-* to
 *     claude-sonnet-* mid-session forces a fresh cache build.
 *   - "TTL-likely" — gap between the prior cache-creating row and this
 *     one exceeds CACHE_TTL_LIKELY_MS (default 5 min, matching
 *     Anthropic's documented prompt-cache TTL).
 *   - "unknown" — none of the above; could be a `/clear`, an
 *     OAuth-rotation gap, or a real cache-prefix change. Documented
 *     as "no signal."
 *
 * Limitations (documented for the UI's tooltip):
 *   - First turn of a thread legitimately has no cache → not a miss
 *     (correctly excluded — no prior creation row exists)
 *   - Different conversations within one sessionId are aggregated
 *     together (rare in practice — sessionId is per-CC-process)
 *
 * @param {Array<Object>} rows
 * @param {Object} [opts]
 * @param {number} [opts.minInputForMissDetection] default 1000
 * @param {number} [opts.cacheTtlMs] default 300000 (5 minutes)
 * @returns {Array<{sessionId, ts, model, inputTokens, repo, branch,
 *   account, reason}>}
 *   Phase 5 enriches `reason`; Round-2 audit added `account` so the
 *   wasted-spend chart can apply its account-dropdown filter without
 *   re-joining against the source rows. Existing UI consumers ignoring
 *   the extra field still work.
 *   Per-session aggregates are exposed via the SEPARATE
 *   `summarizeCacheMissesBySession()` function below.
 */
export const CACHE_TTL_LIKELY_MS = 5 * 60 * 1000; // Anthropic prompt-cache TTL

export function buildCacheMissReport(rows, opts = {}) {
  if (!Array.isArray(rows)) return [];
  const minInput = (opts.minInputForMissDetection != null) ? opts.minInputForMissDetection : 1000;
  const ttlMs    = (opts.cacheTtlMs                != null) ? opts.cacheTtlMs                : CACHE_TTL_LIKELY_MS;

  // Group rows by session. Include compact-boundary markers
  // (type='compact_boundary' — see buildCompactBoundaryEntry in this
  // file; that's the canonical schema written to token-usage.json by
  // the PreCompact/PostCompact hooks) alongside usage rows because we
  // need them for reason inference; we skip them in the miss-emission
  // step itself. Audit SR-OP-001: an earlier draft of this filter
  // checked for 'compact' (not 'compact_boundary'), which made the
  // compact-boundary classifier dead code in production — every miss
  // after a real /compact was downgraded to TTL-likely or unknown.
  const bySession = new Map();
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const t = row.type || 'usage';
    if (t !== 'usage' && t !== 'compact_boundary') continue;
    const sid = row.sessionId || '_unknown';
    let arr = bySession.get(sid);
    if (!arr) { arr = []; bySession.set(sid, arr); }
    arr.push(row);
  }

  const misses = [];
  for (const [sessionId, sessionRows] of bySession) {
    sessionRows.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    let lastCacheCreatedAt = 0;     // ts of the most recent row that created cache
    let lastCacheCreatedModel = null;
    let lastCompactAt = 0;          // ts of the most recent compact-boundary marker
    for (const row of sessionRows) {
      const t = row.type || 'usage';
      if (t === 'compact_boundary') {
        lastCompactAt = row.ts || 0;
        continue;
      }
      const created = row.cacheCreationInputTokens || 0;
      const read    = row.cacheReadInputTokens     || 0;
      const input   = row.inputTokens              || 0;
      const ts      = row.ts || 0;

      if (lastCacheCreatedAt > 0 && read === 0 && input >= minInput) {
        // Reason classification — order matters because compact-boundary
        // dominates the others (a compact between us and the last cache
        // makes the gap-since-creation moot).
        let reason = 'unknown';
        // Audit MAJOR-1: use >= so a compact at the SAME ts as the cache
        // creation row (clock-resolution collisions, batched flushes)
        // still classifies the downstream miss as compact-boundary.
        // The outer `lastCacheCreatedAt > 0` guard ensures we never
        // enter this branch with the both-zero sentinel state.
        if (lastCompactAt >= lastCacheCreatedAt && lastCompactAt <= ts) {
          reason = 'compact-boundary';
        } else if (lastCacheCreatedModel && row.model && row.model !== lastCacheCreatedModel) {
          reason = 'model-changed';
        } else if (ts - lastCacheCreatedAt >= ttlMs) {
          reason = 'TTL-likely';
        }
        misses.push({
          sessionId,
          ts,
          model: row.model || null,
          inputTokens: input,
          repo: row.repo || null,
          branch: row.branch || null,
          // Audit Round-2 QR5: include account so the wasted-spend
          // chart's account-filter check (in renderWastedSpendChart)
          // has a field to compare against. Without this the filter
          // was a no-op (every row's p.account === undefined → never
          // matched the dropdown's value).
          account: row.account || null,
          reason,
        });
      }
      if (created > 0) {
        lastCacheCreatedAt = ts;
        lastCacheCreatedModel = row.model || null;
      }
    }
  }
  // Sort by ts ascending so the UI can render a chronological list
  // without an extra step.
  misses.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  return misses;
}

/**
 * Phase 5 — Per-session cache-miss aggregate.
 *
 * Pairs with `buildCacheMissReport()` to produce the UI's per-session
 * header line: "session-abc-12345  Cache hit rate: 67% (4 hits, 2 misses)"
 *
 * Hit/miss accounting:
 *   - A "hit" is any usage row with cacheReadInputTokens > 0.
 *   - A "miss" is any row that buildCacheMissReport flags (i.e. a
 *     prior cache existed but wasn't read, AND input >= threshold).
 *   - Rows that don't qualify as either (no prior cache, or input
 *     below the threshold) don't count toward EITHER side. This
 *     keeps the rate meaningful — the denominator is "turns where
 *     a cache outcome was possible," not "all turns."
 *
 * @param {Array<Object>} rows
 * @param {Object} [opts] same shape as buildCacheMissReport, plus:
 * @param {Array<Object>} [opts._precomputedMisses] callers that
 *   already invoked buildCacheMissReport(rows, opts) can pass the
 *   result here to avoid the second walk. Trusted-input contract:
 *   the leading underscore signals "internal API"; never accept
 *   this from a request body without re-validating the shape.
 * @returns {Array<{sessionId, repo, branch, hits, misses, hitRate, lastTs, missDetails}>}
 *   Sorted by lastTs descending so the UI's "recently active first"
 *   order is the natural one.
 */
export function summarizeCacheMissesBySession(rows, opts = {}) {
  if (!Array.isArray(rows)) return [];
  const minInput = (opts.minInputForMissDetection != null) ? opts.minInputForMissDetection : 1000;

  // Re-use the flat miss list as the source of truth for misses so
  // the two views can never disagree about WHICH rows are misses.
  // Audit CC-DASH-016: callers that already have a flat list (e.g.
  // the /api/token-usage-tree endpoint, which now computes
  // buildCacheMissReport once and passes it to all three downstream
  // helpers) can supply it via opts._precomputedMisses to avoid
  // re-walking the dataset.
  const flatMisses = Array.isArray(opts._precomputedMisses)
    ? opts._precomputedMisses
    : buildCacheMissReport(rows, opts);
  const missesBySession = new Map();
  for (const m of flatMisses) {
    let arr = missesBySession.get(m.sessionId);
    if (!arr) { arr = []; missesBySession.set(m.sessionId, arr); }
    arr.push(m);
  }

  const sessionAcc = new Map();
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    if ((row.type || 'usage') !== 'usage') continue;
    const sid = row.sessionId || '_unknown';
    let acc = sessionAcc.get(sid);
    if (!acc) {
      acc = {
        sessionId: sid,
        repo: row.repo || null,
        branch: row.branch || null,
        hits: 0,
        misses: 0,
        lastTs: 0,
      };
      sessionAcc.set(sid, acc);
    }
    // Track most-recent repo/branch — sessions can wander as the user
    // cd's between turns; we want the LAST observed pair for the
    // header label so it matches the user's current expectation.
    if ((row.ts || 0) >= acc.lastTs) {
      acc.lastTs = row.ts || 0;
      if (row.repo)   acc.repo   = row.repo;
      if (row.branch) acc.branch = row.branch;
    }
    const read  = row.cacheReadInputTokens || 0;
    const input = row.inputTokens          || 0;
    // Audit MINOR-4: apply the same input threshold to hits that the
    // miss heuristic uses, so hit-rate denominators stay symmetric.
    // Previously a tiny-input row with read=50 counted as a hit while
    // a tiny-input row with read=0 was excluded from BOTH counts —
    // skewed the rate high.
    if (read > 0 && input >= minInput) acc.hits += 1;
    // misses are sourced from the flat report (computed below) so we
    // skip the per-row miss bookkeeping here.
  }

  const out = [];
  for (const [sid, acc] of sessionAcc) {
    const sessionMisses = missesBySession.get(sid) || [];
    acc.misses = sessionMisses.length;
    const total = acc.hits + acc.misses;
    acc.hitRate = total > 0 ? Math.round((acc.hits / total) * 1000) / 10 : null;
    acc.missDetails = sessionMisses;
    // Drop sessions that had neither hits nor misses — they're noise
    // for the UI (sessions where every turn was below the threshold
    // and no cache ever existed).
    if (total > 0) out.push(acc);
  }
  out.sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  return out;
}

/**
 * Build the "wasted spend due to cache miss" time series.
 *
 * For every row that buildCacheMissReport classifies as a cache miss,
 * the input tokens were billed at the FULL rate when, with a cache
 * hit, they would have been billed at ~10% (the cache-read rate).
 * Plotting these per-request gives the operator a direct view of
 * "tokens I paid full price for that I ideally shouldn't have."
 *
 * Notes on what's INCLUDED vs. EXCLUDED:
 *   - INCLUDED: rows the heuristic flagged as misses (cache existed
 *     but wasn't read; input >= threshold).
 *   - EXCLUDED: legitimate first-turn cache builds (no prior cache
 *     existed → not a miss). We're measuring waste, not cost.
 *   - EXCLUDED: rows below the input threshold (heuristic ignores
 *     those — small turns may legitimately not need a cache).
 *
 * The y-axis value per point is the raw `inputTokens` count for the
 * miss. UI can compute the dollar-cost equivalent via
 * estimateModelCost(model, inputTokens, 0, 0, 0) at render time.
 *
 * @param {Array<Object>} rows
 * @param {Object} [opts]
 * @param {number} [opts.minInputForMissDetection]
 * @param {number} [opts.cacheTtlMs]
 * @param {Set<string>|Array<string>} [opts.repoFilter] include only
 *   rows whose `repo` is in this set. Empty/missing = include all.
 * @param {Array<Object>} [opts._precomputedMisses] callers that
 *   already invoked buildCacheMissReport(rows, opts) can pass the
 *   result here to avoid the second walk. Trusted-input contract.
 * @returns {Array<{ts, inputTokens, model, repo, branch, sessionId,
 *   account, reason, costUSD, wastedUSD}>}
 *   Sorted by ts ascending.
 *   - `costUSD` = full input price the user paid for this miss row,
 *     computed via estimateModelCost(model, inputTokens, 0, 0, 0).
 *   - `wastedUSD` (Audit MINOR-3) = the SAVABLE differential —
 *     `costUSD` minus what the same tokens would have cost if billed
 *     at the cache-read rate (~10% of input rate). This is the actual
 *     "I could have avoided this" amount; the UI should plot it for
 *     "wasted spend" labeling. `costUSD` stays as the gross figure
 *     for users who want to see total exposure.
 */
export function buildWastedSpendSeries(rows, opts = {}) {
  // Audit CC-DASH-016: accept a pre-computed misses array so the
  // endpoint can call buildCacheMissReport once and feed all three
  // downstream consumers from the same flat list.
  const misses = Array.isArray(opts._precomputedMisses)
    ? opts._precomputedMisses
    : buildCacheMissReport(rows, opts);
  if (!misses.length) return [];
  let allowedRepos = null;
  if (opts.repoFilter) {
    if (opts.repoFilter instanceof Set) {
      allowedRepos = opts.repoFilter.size > 0 ? opts.repoFilter : null;
    } else if (Array.isArray(opts.repoFilter) && opts.repoFilter.length > 0) {
      allowedRepos = new Set(opts.repoFilter);
    }
  }
  const out = [];
  for (const m of misses) {
    if (allowedRepos && !allowedRepos.has(m.repo || '')) continue;
    const fullCost  = estimateModelCost(m.model, m.inputTokens, 0, 0, 0);
    // What it WOULD have cost if read from cache at the read rate.
    const cacheCost = estimateModelCost(m.model, 0, 0, m.inputTokens, 0);
    out.push({
      ts:          m.ts,
      inputTokens: m.inputTokens,
      model:       m.model,
      repo:        m.repo,
      branch:      m.branch,
      sessionId:   m.sessionId,
      // Audit Round-2 QR5: pass account through so the chart's
      // account-filter check has a value to compare.
      account:     m.account || null,
      reason:      m.reason,
      costUSD:     fullCost,
      wastedUSD:   Math.max(0, fullCost - cacheCost),
    });
  }
  // Already chronological from buildCacheMissReport; explicit sort
  // here for safety in case that contract changes.
  out.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  return out;
}

// ─────────────────────────────────────────────────
// UX-WS2 — Wasted-spend severity gradient
//
// The wasted-spend chart used a single yellow for every bar regardless
// of how catastrophic the day was. Operators couldn't tell at a glance
// "this day was $5" from "this day was $50" without hovering each bar.
// The fix is a percentile-based gradient: bars at or below the 50th
// percentile of the visible window get a calm soft-yellow; bars between
// the 50th and 90th percentile get the saturated yellow; bars STRICTLY
// above the 90th percentile get red ("look here first").
//
// Why percentile and not absolute thresholds:
//   - Absolute thresholds ($1 / $10 / $100) drift as Anthropic's pricing
//     and the user's traffic volume change. A small-traffic user would
//     never see red; a high-traffic user would see only red.
//   - Percentile-of-current-dataset is naturally normalised to whatever
//     the user is looking at right now. A "bad day" stands out against
//     the user's own baseline.
//
// Why a pure function:
//   - The dashboard inlines this helper into renderHTML's <script>
//     block via source duplication (no bundler), but the source-of-
//     truth lives here so the unit test in test/lib.test.mjs covers
//     the percentile math directly.
//   - The CSS-variable returns are constants so the dashboard never
//     introduces hex colours that drift from the :root palette.
// ─────────────────────────────────────────────────
export const WASTED_SEVERITY_LOW  = 'var(--yellow-soft)';
export const WASTED_SEVERITY_MED  = 'var(--yellow)';
export const WASTED_SEVERITY_HIGH = 'var(--red)';

/**
 * Pick a severity colour for a wasted-spend bar based on its position
 * in the distribution of the visible bars.
 *
 * @param {number} value — the wasted dollar amount for this bar
 * @param {Array<number>|null} allValues — the full set of visible
 *   wasted values (one entry per bar in the rendered chart). Used to
 *   compute the 50th and 90th percentile thresholds.
 * @returns {string} a CSS-variable expression usable as `background:`
 *   on the bar element. Always returns one of WASTED_SEVERITY_LOW /
 *   WASTED_SEVERITY_MED / WASTED_SEVERITY_HIGH.
 *
 * Defensive contract:
 *   - null/undefined/NaN/negative `value` → LOW (no crash, no red).
 *   - empty/null/undefined `allValues` → LOW (no distribution to
 *     compare against — calm default).
 *   - single-value or flat `allValues` → LOW (no variance means no
 *     gradient is meaningful; without this branch the lone bar would
 *     score above its own zero-width "90th percentile" and turn red).
 */
export function wastedSeverity(value, allValues) {
  // Defensive input gates.
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    return WASTED_SEVERITY_LOW;
  }
  if (!Array.isArray(allValues) || allValues.length === 0) {
    return WASTED_SEVERITY_LOW;
  }
  // Filter to finite non-negative values so the percentile math is
  // not skewed by NaN / null / negative entries that may have slipped
  // through from a malformed dataset.
  const cleaned = [];
  for (let i = 0; i < allValues.length; i++) {
    const v = allValues[i];
    if (typeof v === 'number' && Number.isFinite(v) && v >= 0) {
      cleaned.push(v);
    }
  }
  if (cleaned.length === 0) return WASTED_SEVERITY_LOW;
  // Flat / single-value distributions have no meaningful gradient.
  // Without this short-circuit the lone bar (or every bar in a flat
  // dataset) would clear the 90th percentile threshold (since 90th of
  // [7] is 7 and we use `value > p90` which is false, so this is also
  // strictly defensive — the comparator is the load-bearing safeguard,
  // but the early return saves the percentile sort on the common case).
  let allEqual = true;
  for (let i = 1; i < cleaned.length; i++) {
    if (cleaned[i] !== cleaned[0]) { allEqual = false; break; }
  }
  if (allEqual) return WASTED_SEVERITY_LOW;
  // Sort ascending and compute 50th + 90th percentile via linear
  // interpolation (the standard "type 7" definition used by Excel and
  // most stats libraries — same one users would compute by hand).
  const sorted = cleaned.slice().sort((a, b) => a - b);
  const p50 = _percentile(sorted, 0.50);
  const p90 = _percentile(sorted, 0.90);
  // Strict-inequality thresholds match the spec: HIGH only when the
  // bar exceeds the 90th — being AT the 90th is still MED. A bar that
  // sits exactly on the 50th (the median) is LOW (calm default).
  if (value > p90) return WASTED_SEVERITY_HIGH;
  if (value > p50) return WASTED_SEVERITY_MED;
  return WASTED_SEVERITY_LOW;
}

/**
 * Linear-interpolation percentile (type 7). Internal helper.
 * `sorted` MUST be sorted ascending. `p` is in [0, 1].
 */
function _percentile(sorted, p) {
  const n = sorted.length;
  if (n === 0) return 0;
  if (n === 1) return sorted[0];
  const rank = p * (n - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return sorted[lo];
  const frac = rank - lo;
  return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
}

/**
 * Promise-chain mutex keyed by account name.
 * Ensures only one refresh runs per account at a time.
 *
 * Eviction note: when a chain finishes and no later caller has chained
 * onto its tail, the Map entry is deleted so the lock table doesn't grow
 * unboundedly across the lifetime of the dashboard process. Without this,
 * every distinct key (account name, fingerprint, etc.) ever passed in
 * would leak a settled promise reference, and `accountState.remove()`
 * (added in Phase 5) would have no symmetric cleanup here.
 */
export function createPerAccountLock() {
  const locks = new Map();

  function withLock(key, fn) {
    const prev = locks.get(key) || Promise.resolve();
    let release;
    const next = new Promise(r => { release = r; });
    locks.set(key, next);
    // The eviction step folds into the same .finally that releases `next`,
    // so the caller-visible chain settles with the original outcome of
    // `fn`. The identity check `locks.get(key) === next` is load-bearing:
    // if a later caller B has already chained onto our tail, locks.get(key)
    // is now B's `next`, and we must NOT delete it — doing so would let a
    // future call C bypass B and run in parallel. The check guarantees
    // we only evict tails that nobody is queued behind.
    return prev.then(fn).finally(() => {
      release();
      if (locks.get(key) === next) locks.delete(key);
    });
  }

  // Test-only diagnostic: number of live lock entries. Exposed so the
  // memory-growth audit fix can be verified deterministically without
  // peeking at module internals. Production code MUST NOT depend on this.
  function _size() { return locks.size; }

  return { withLock, _size };
}

// ─────────────────────────────────────────────────
// Counting semaphore (FIFO queue)
// ─────────────────────────────────────────────────

/**
 * Counting semaphore that caps the number of concurrent runs.
 *
 * Designed to throttle bulk OAuth-refresh fan-out: the 400-recovery path
 * in dashboard.mjs does `Promise.allSettled(toRefresh.map(refreshAccount))`
 * which can fire 10+ parallel POSTs from one IP and trigger Anthropic-side
 * rate limiting on the OAuth endpoint itself. Wrapping each refresh call
 * in `sem.run(fn)` caps in-flight requests at maxConcurrent.
 *
 * Contract:
 *   const sem = createSemaphore(3);
 *   await sem.acquire();
 *   try { ... } finally { sem.release(); }
 *   // or:
 *   await sem.run(asyncFn);
 *
 * Pending acquirers are released in FIFO order. release() is reentrant-safe:
 * calling more times than acquire is a no-op (counter is clamped at 0),
 * not an underflow that would let extra runs slip past the cap.
 */
export function createSemaphore(maxConcurrent) {
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
    throw new Error(`createSemaphore: maxConcurrent must be a positive integer, got ${maxConcurrent}`);
  }
  const max = maxConcurrent;
  let inFlight = 0;
  const pending = []; // FIFO queue of resolvers

  function acquire() {
    if (inFlight < max) {
      inFlight++;
      return Promise.resolve();
    }
    return new Promise(resolve => { pending.push(resolve); });
  }

  function release() {
    // Reentrant safety: if a caller releases more times than it acquired
    // (or releases without an acquire at all), the counter must NOT go
    // negative — that would silently let extra runs bypass the cap on the
    // next acquire(). Clamp at 0 and treat the extra release as a no-op.
    if (pending.length > 0) {
      // Hand the slot directly to the next waiter without dipping inFlight,
      // so a fresh acquire() racing with release() can't sneak past the
      // queued caller. The waiter inherits the slot we already counted.
      const next = pending.shift();
      next();
      return;
    }
    if (inFlight > 0) inFlight--;
  }

  async function run(fn) {
    await acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }

  // Test-only diagnostic: current in-flight count. Exposed so concurrency
  // tests can assert the cap deterministically. Production code MUST NOT
  // depend on this.
  function _inFlight() { return inFlight; }
  function _pending() { return pending.length; }

  return { acquire, release, run, _inFlight, _pending };
}

// ─────────────────────────────────────────────────
// Sliding-window event counter (circuit-breaker primitive)
// ─────────────────────────────────────────────────

/**
 * Bounded sliding-window counter for "N events within last X ms" checks.
 *
 * Designed for the serialize-mode safeguards: count queue_timeout 503s
 * over the last 10 minutes, count all-accounts-429 events over the last
 * 60 seconds, etc. The pattern shows up everywhere a rate-of-failure
 * threshold needs to trip a circuit breaker without leaking unbounded
 * timestamp history.
 *
 * Contract:
 *   const cb = createSlidingWindowCounter({ windowMs: 600_000, threshold: 5 });
 *   cb.record();              // record an event at "now"
 *   cb.record(t);             // record at explicit timestamp
 *   cb.count();               // events within window ending now
 *   cb.tripped();             // count() >= threshold
 *   cb.reset();               // clear all events (e.g. after auto-disable fires)
 *   cb._size();               // diagnostic — internal array length
 *
 * Memory bound: array length is bounded by the natural arrival rate
 * within `windowMs` because every read prunes events older than the
 * window. There's no separate cap — pathological insert-without-read
 * traffic would grow unbounded, but the only call sites here always
 * read after recording (record → count/tripped pair).
 */
export function createSlidingWindowCounter({ windowMs, threshold } = {}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new Error(`createSlidingWindowCounter: windowMs must be a positive number, got ${windowMs}`);
  }
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new Error(`createSlidingWindowCounter: threshold must be a positive integer, got ${threshold}`);
  }

  // Sorted ascending by insertion (which is monotonic by Date.now()
  // unless the system clock jumps — see below). The prune step uses
  // this ordering so it can stop at the first in-window entry.
  let events = [];

  function _prune(now) {
    const cutoff = now - windowMs;
    // Find first index whose timestamp is within the window. Linear
    // scan from front because the array is sorted ascending. For the
    // expected sizes (handful of events per window) this is faster
    // than a binary-search overhead.
    let i = 0;
    while (i < events.length && events[i] < cutoff) i++;
    if (i > 0) events = events.slice(i);
  }

  function record(ts = Date.now()) {
    // System-clock jump backwards: an NTP correction could insert a
    // timestamp older than the previous one. Treat that as a one-off
    // — the new event still belongs in the window. The prune step is
    // tolerant; the array order is "best effort sorted", and the
    // count() loop scans every element anyway.
    events.push(ts);
  }

  function count(now = Date.now()) {
    _prune(now);
    return events.length;
  }

  function tripped(now = Date.now()) {
    return count(now) >= threshold;
  }

  function reset() {
    events = [];
  }

  function _size() { return events.length; }

  return { record, count, tripped, reset, _size };
}

// ─────────────────────────────────────────────────
// Viewer-state helpers (Phase C — date-range scrubber)
// ─────────────────────────────────────────────────

/**
 * Clamp a persisted viewer-state record against a live data-range and
 * the set of currently-known subscription tiers.
 *
 * Why this is its own function:
 *   - Persisted state outlives data: a window persisted before token-usage
 *     entries aged out will reference timestamps no longer covered by the
 *     archive, so the UI must clamp into the live bounds before rendering.
 *   - Persisted state outlives tiers: an account producing a previously-
 *     unique tier may be removed, leaving stale entries in `tierFilter`
 *     that no longer correspond to any live profile. Drop them silently.
 *   - Persisted state may be malformed: start > end (clock skew, race),
 *     non-finite numbers, missing fields. Always emit a sane window.
 *
 * Inputs (all optional — missing fields default to a reasonable value):
 *   start         — ms epoch (number); falls back to dataRange.oldest
 *   end           — ms epoch (number); falls back to dataRange.newest
 *   tierFilter    — string[]; falls back to ['all']
 *   dataRange     — { oldest: number, newest: number }; required (caller
 *                   computes from token-usage + activity-log)
 *   knownTiers    — string[]; the tiers actually present on live profiles.
 *                   When empty/undefined the filter passes through unchanged
 *                   (no live profiles → nothing to validate against).
 *
 * Output:
 *   { start, end, tierFilter } — always a valid record where:
 *     - start ≤ end (swap on inversion)
 *     - start ≥ dataRange.oldest, end ≤ dataRange.newest
 *     - end - start ≥ MIN_WINDOW_MS (5 minutes), unless dataRange itself
 *       is narrower than that — in which case both bounds collapse to
 *       dataRange.{oldest,newest}
 *     - tierFilter is either ['all'] or a deduped subset of knownTiers
 *       (entries referencing tiers no longer present are silently dropped)
 *
 * The MIN_WINDOW_MS guard prevents zero-width selections (a user could
 * otherwise persist start === end, then every chart shows "no data" with
 * no obvious recovery).
 */
export const VIEWER_STATE_MIN_WINDOW_MS = 5 * 60 * 1000;

export function clampViewerState({ start, end, tierFilter, dataRange, knownTiers } = {}) {
  // Normalise dataRange. Caller is expected to supply both oldest/newest;
  // we tolerate missing/invalid by collapsing to a single instant at "now"
  // — the empty-data path the UI uses to hide the scrubber.
  const now = Date.now();
  const dr = dataRange && Number.isFinite(dataRange.oldest) && Number.isFinite(dataRange.newest)
    ? dataRange
    : { oldest: now, newest: now };
  const oldest = Math.min(dr.oldest, dr.newest);
  const newest = Math.max(dr.oldest, dr.newest);

  // Normalise start/end. Non-finite or missing values fall back to the
  // dataRange edges so the UI can render with safe defaults the moment a
  // fresh viewer-state.json appears (no first-render flicker).
  let s = Number.isFinite(start) ? Number(start) : oldest;
  let e = Number.isFinite(end)   ? Number(end)   : newest;

  // Swap on inversion. Clock-skew during a session can produce start>end
  // when a preset's "Last 24h" computes against an older `now` than the
  // current. Swapping is cheaper than asking the user to fix the JSON.
  if (s > e) { const tmp = s; s = e; e = tmp; }

  // Clamp into bounds. If the persisted window is fully outside the live
  // data range (e.g. all data aged out and the user's last selection
  // pointed at older entries), the clamp collapses both ends to the
  // nearest live edge.
  s = Math.max(oldest, Math.min(s, newest));
  e = Math.max(oldest, Math.min(e, newest));

  // Enforce MIN_WINDOW_MS — but only if the live data range itself is
  // wide enough to host a 5-minute window. For brand-new installs with
  // a single data point, oldest === newest and the window is [now,now]
  // by design (the UI hides the scrubber in that state).
  const dataWidth = newest - oldest;
  if (dataWidth >= VIEWER_STATE_MIN_WINDOW_MS && (e - s) < VIEWER_STATE_MIN_WINDOW_MS) {
    // Pad symmetrically around the midpoint so neither edge punches out
    // of dataRange. If centring would cross a bound, anchor at that bound
    // and extend the other side.
    const mid = (s + e) / 2;
    let ns = mid - VIEWER_STATE_MIN_WINDOW_MS / 2;
    let ne = mid + VIEWER_STATE_MIN_WINDOW_MS / 2;
    if (ns < oldest) { ns = oldest; ne = oldest + VIEWER_STATE_MIN_WINDOW_MS; }
    if (ne > newest) { ne = newest; ns = newest - VIEWER_STATE_MIN_WINDOW_MS; }
    s = ns; e = ne;
  }

  // Tier filter. Sentinel ['all'] means "no filter" — pass through.
  // Otherwise drop any entries not present in knownTiers; if the result
  // is empty, fall back to ['all'] (an empty filter would render zero
  // data for no obvious reason; the user has to actively re-select a
  // tier to filter again).
  let tf;
  if (!Array.isArray(tierFilter) || tierFilter.length === 0) {
    tf = ['all'];
  } else if (tierFilter.includes('all')) {
    tf = ['all'];
  } else if (Array.isArray(knownTiers) && knownTiers.length > 0) {
    const known = new Set(knownTiers);
    const filtered = tierFilter.filter(t => typeof t === 'string' && known.has(t));
    tf = filtered.length > 0 ? Array.from(new Set(filtered)) : ['all'];
  } else {
    // No knownTiers context — preserve the filter as-is (deduped, string-only).
    const cleaned = tierFilter.filter(t => typeof t === 'string' && t.length > 0);
    tf = cleaned.length > 0 ? Array.from(new Set(cleaned)) : ['all'];
  }

  return { start: s, end: e, tierFilter: tf };
}

// ─────────────────────────────────────────────────
// Phase D — Hook payload parsers
// ─────────────────────────────────────────────────

/**
 * Validate and normalise a PreCompact / PostCompact hook payload.
 *
 * Both events share the same shape on the wire. The ONLY difference is that
 * PostCompact carries postTokens and PreCompact does not. Caller decides
 * which kind it is via the `kind` parameter ('pre' | 'post').
 *
 * Returns:
 *   { ok: true,  sessionId, cwd, trigger, preTokens, postTokens, transcriptPath }
 *   { ok: false, error: string }   // for malformed payloads
 *
 * Why a pure parser:
 *   The HTTP handler used to embed the validation inline, mixing JSON parsing
 *   errors with schema errors. Splitting the parse step lets us unit-test the
 *   schema rules without spinning up an HTTP server, and produces consistent
 *   400-error messages so the tests can assert on them.
 */
export function parseCompactPayload(data, kind) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  if (kind !== 'pre' && kind !== 'post') {
    return { ok: false, error: 'kind must be "pre" or "post"' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  // cwd is documented as required on every hook payload but we don't reject
  // missing cwd here — compact_boundary rows survive without it (it's only
  // used to refresh branch resolution downstream).
  const cwd = typeof data.cwd === 'string' && data.cwd.length > 0 ? data.cwd : null;
  // trigger comes from the hook matcher — 'manual' | 'auto'. Tolerate
  // missing trigger by defaulting to 'auto' (the documented default in
  // hooks-guide §"Hook input").
  let trigger = data.trigger;
  if (trigger !== 'manual' && trigger !== 'auto') {
    trigger = 'auto';
  }
  // preTokens is required on BOTH PreCompact and PostCompact (from
  // sub-agents.txt §"Compaction metadata"). Coerce to a finite number; if
  // it's missing or NaN, fall back to null so the row still persists
  // without injecting bogus arithmetic into downstream graphs.
  const preTokens = Number.isFinite(Number(data.preTokens))
    ? Number(data.preTokens)
    : null;
  // postTokens MUST be null on PreCompact (event hasn't fired yet) and is
  // best-effort on PostCompact — if Claude Code sends it, we record it; if
  // not, we leave it null and the UI can compute postTokens = preTokens
  // minus the next turn's input delta.
  const postTokens = kind === 'post' && Number.isFinite(Number(data.postTokens))
    ? Number(data.postTokens)
    : null;
  const transcriptPath = typeof data.transcript_path === 'string'
    ? data.transcript_path
    : null;
  return { ok: true, sessionId, cwd, trigger, preTokens, postTokens, transcriptPath };
}

/**
 * Derive the MCP server name from a tool_name like "mcp__github__create_pr".
 *
 * Returns the server segment (e.g. "github") for tools matching the
 * `mcp__<server>__<tool>` convention. Returns null for tools that don't
 * follow the MCP naming pattern (Bash, Read, Edit, Glob, etc.).
 *
 * Why pure: the dispatch code in dashboard.mjs builds two fields from one
 * input string — `tool` (full name) and `mcpServer` (derived). Putting the
 * derivation here keeps the rule in one place and makes the "is this an
 * MCP tool?" check trivially testable.
 */
export function inferMcpServerFromToolName(toolName) {
  if (typeof toolName !== 'string' || toolName.length === 0) return null;
  if (!toolName.startsWith('mcp__')) return null;
  // Format: mcp__<server>__<tool>. Reject malformed (mcp__foo with no
  // __<tool> suffix) — those aren't real MCP tools.
  const parts = toolName.split('__');
  if (parts.length < 3) return null;
  const server = parts[1];
  if (!server || server.length === 0) return null;
  return server;
}

/**
 * Validate and normalise a SubagentStart hook payload.
 *
 * Returns:
 *   { ok: true,  sessionId, parentSessionId, agentType, cwd, transcriptPath }
 *   { ok: false, error: string }
 *
 * agentType is the matcher value from the hook (Bash, Explore, Plan, or any
 * custom plugin agent name). parent_session_id is documented as always
 * present on SubagentStart — we still tolerate missing parent because some
 * Claude Code releases (per the contract §2) sometimes use parentSessionId
 * or transcript_id instead.
 */
export function parseSubagentStartPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  const cwd = typeof data.cwd === 'string' && data.cwd.length > 0 ? data.cwd : null;
  // Phase G — `agent_id` is the spec field (per-subagent instance ID).
  // `parent_session_id` / `parentSessionId` / `transcript_id` are NOT in
  // the documented payload — the parent's identity is implicit (Claude Code
  // tracks it internally; the hook payload only carries the subagent's own
  // session_id + agent_id + agent_type + transcript_path). We keep the
  // legacy fallback chain so old tests/fixtures don't break, but in production
  // these will all be null and parent attribution is best-effort via cwd
  // matching at handler time. The `transcript_path` field IS in the spec
  // and is the canonical handle for tail-reading the subagent's JSONL log.
  const parentSessionId = data.parent_session_id || data.parentSessionId || data.transcript_id || null;
  const agentId = typeof data.agent_id === 'string' && data.agent_id.length > 0
    ? data.agent_id
    : null;
  const agentType = typeof data.agent_type === 'string' && data.agent_type.length > 0
    ? data.agent_type
    : null;
  const transcriptPath = typeof data.transcript_path === 'string'
    ? data.transcript_path
    : null;
  // Phase G — derive the PARENT session_id from transcript_path. The spec
  // doesn't carry parent_session_id in the SubagentStart payload, but the
  // canonical Claude Code transcript layout is:
  //   ~/.claude/projects/{project}/{parentSessionId}/subagents/agent-{agentId}.jsonl
  // …so the second-to-last directory component IS the parent's session_id.
  // Falls back to the legacy parent_session_id chain (always null in
  // production) if the path doesn't match the documented layout.
  const derivedParent = parentSessionId || parseParentSessionFromTranscriptPath(transcriptPath);
  return { ok: true, sessionId, cwd, agentId, parentSessionId: derivedParent, agentType, transcriptPath };
}

/**
 * Phase G — Extract the parent session_id from a subagent transcript path.
 *
 * Documented layout per the sub-agents spec:
 *   ~/.claude/projects/{project}/{parentSessionId}/subagents/agent-{agentId}.jsonl
 *
 * We accept either '/' or '\\' separators (cross-platform) and tolerate
 * surrounding noise — only the structural anchor (`/subagents/agent-…jsonl`)
 * needs to match. UUID validation is intentionally relaxed: the spec doesn't
 * formally require RFC-4122, just a unique opaque session_id, so we accept
 * any non-empty string in that position.
 *
 * Returns: parent session_id string, or null if the path doesn't match.
 */
export function parseParentSessionFromTranscriptPath(transcriptPath) {
  if (typeof transcriptPath !== 'string' || transcriptPath.length === 0) return null;
  // Normalise separators so the regex works on any platform.
  const norm = transcriptPath.replace(/\\/g, '/');
  // Capture the directory component immediately preceding `/subagents/`.
  // Anchor is structural (last `/subagents/agent-*.jsonl` boundary) so
  // arbitrary prefixes (~/.claude/, /private/var/, /tmp/test/, etc.) all work.
  const m = norm.match(/\/([^/]+)\/subagents\/agent-[^/]*\.jsonl$/);
  return m && m[1] ? m[1] : null;
}

/**
 * Validate and normalise a CwdChanged hook payload.
 *
 * Returns:
 *   { ok: true,  sessionId, previousCwd, cwd }
 *   { ok: false, error: string }
 */
export function parseCwdChangedPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  const cwd = data.cwd;
  if (typeof cwd !== 'string' || cwd.length === 0) {
    return { ok: false, error: 'cwd required' };
  }
  // previous_cwd is informational — may be null/missing if Claude Code
  // doesn't know the prior dir (first cd in a session, for example).
  const previousCwd = typeof data.previous_cwd === 'string' && data.previous_cwd.length > 0
    ? data.previous_cwd
    : null;
  return { ok: true, sessionId, cwd, previousCwd };
}

/**
 * Phase D — predicate that returns true when an entry is a usage row.
 *
 * Aggregation readers MUST skip rows where this returns false (currently
 * only compact_boundary rows). Pre-Phase-D rows on disk lack the `type`
 * field — those are usage rows by definition (forward-compat).
 */
export function isUsageRow(entry) {
  return !entry || entry.type === undefined || entry.type === 'usage';
}

/**
 * Phase D — build a compact_boundary entry shape (without the ts).
 *
 * This is the pure shape-builder used by appendCompactBoundary in
 * dashboard.mjs. Pulling it here lets us unit-test the rules around
 * preTokens / postTokens coercion and ensures the schema stays stable.
 *
 * The caller (appendCompactBoundary) injects ts: Date.now() at write time;
 * this function is deterministic given its inputs.
 */
export function buildCompactBoundaryEntry({ ts, sessionId, repo, branch, commitHash, trigger, preTokens, postTokens, account }) {
  // Number coercion guard: Number(null) === 0 and Number.isFinite(0) === true,
  // so a literal null preTokens/postTokens would silently turn into 0
  // unless we short-circuit on null/undefined first. The 0 would then poison
  // downstream graphs that distinguish "no data" (null) from "compaction
  // discarded everything" (0).
  const _coerce = (v) => {
    if (v === null || v === undefined) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  return {
    ts,
    type: 'compact_boundary',
    repo: repo || '(non-git)',
    branch: branch ?? null,
    commitHash: commitHash || '',
    // Usage fields are explicitly nulled — aggregation readers skip
    // type !== 'usage' rows but the row format MUST stay homogeneous so
    // a stale reader that ignores the type discriminator still parses
    // each row without crashing.
    model: null,
    inputTokens: null,
    outputTokens: null,
    account: account ?? null,
    sessionId: sessionId ?? null,
    parentSessionId: null,
    agentType: null,
    tool: null,
    mcpServer: null,
    teamId: null,
    trigger: trigger ?? null,
    preTokens: _coerce(preTokens),
    postTokens: _coerce(postTokens),
  };
}

/**
 * Phase D — merge a session's sub-agent attribution into a usage entry.
 *
 * Used by appendTokenUsage call sites in dashboard.mjs to thread
 * parentSessionId / agentType / teamId / tool / mcpServer onto every
 * persisted row consistently. perToolAttributionEnabled gates the
 * `tool` / `mcpServer` fields — when false, both are nulled out.
 *
 * Inputs:
 *   sessionId — the session to attribute the row to
 *   session   — pendingSessions entry (may carry parentSessionId, agentType,
 *               teamId, lastBatchToolNames)
 *   entry     — base entry (ts, repo, branch, commitHash, model,
 *               inputTokens, outputTokens, account)
 *   options.perToolAttributionEnabled — gates the tool/mcpServer derivation
 *
 * Returns a NEW object (entry is not mutated).
 */
export function mergeSessionAttribution(sessionId, session, entry, { perToolAttributionEnabled = false } = {}) {
  const s = session || {};
  let tool = null;
  let mcpServer = null;
  if (perToolAttributionEnabled && Array.isArray(s.lastBatchToolNames) && s.lastBatchToolNames.length > 0) {
    tool = s.lastBatchToolNames.join(',');
    for (const t of s.lastBatchToolNames) {
      const srv = inferMcpServerFromToolName(t);
      if (srv) { mcpServer = srv; break; }
    }
  }
  return {
    ...entry,
    sessionId,
    parentSessionId: s.parentSessionId ?? null,
    agentType: s.agentType ?? null,
    teamId: s.teamId ?? null,
    tool,
    mcpServer,
  };
}

/**
 * Validate and normalise a PostToolBatch hook payload.
 *
 * Returns:
 *   { ok: true,  sessionId, cwd, tools: Array<{toolName, mcpServer}> }
 *   { ok: false, error: string }
 *
 * Tool entries are deduped while preserving order so a turn that ran Bash
 * three times shows as ['Bash'] not ['Bash','Bash','Bash']. mcpServer is
 * derived per-entry via inferMcpServerFromToolName.
 */
export function parsePostToolBatchPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  const cwd = typeof data.cwd === 'string' && data.cwd.length > 0 ? data.cwd : null;
  // Phase G — the spec key is `tool_calls`; `tools` was a vdm-internal name
  // used in early development. Reading the wrong key was making every
  // PostToolBatch event return 400 — per-tool attribution was fully broken
  // until this fix. Accept both for forward-compat with future schema renames
  // and old test fixtures.
  const arr = Array.isArray(data.tool_calls)
    ? data.tool_calls
    : (Array.isArray(data.tools) ? data.tools : null);
  if (!arr) {
    return { ok: false, error: 'tool_calls must be an array' };
  }
  const seen = new Set();
  const tools = [];
  for (const t of arr) {
    if (!t || typeof t !== 'object') continue;
    const toolName = t.tool_name;
    // Audit Round-2 SR-P2-005 (CWE-79 / CWE-117 defense-in-depth):
    // reject tool names containing CR, LF, or NUL — they would
    // round-trip through token-usage.json into downstream consumers
    // (jq, awk, naive CSV importers) that don't handle embedded
    // line-breaks. Also cap length at 256 chars to bound memory and
    // ReDoS exposure (matches classifyUsageComponent's guard).
    if (typeof toolName !== 'string' || toolName.length === 0) continue;
    if (toolName.length > 256) continue;
    if (/[\r\n\x00]/.test(toolName)) continue;
    if (seen.has(toolName)) continue;
    seen.add(toolName);
    tools.push({ toolName, mcpServer: inferMcpServerFromToolName(toolName) });
  }
  return { ok: true, sessionId, cwd, tools };
}

// ─── Phase E — additional hook payload parsers + breakdown helpers ───
//
// These complete the Phase D hook-coverage plan (worktree events, agent-team
// events) and surface the per-tool data we already collect (tool breakdown).

/**
 * Phase E — Validate and normalise a WorktreeCreate / WorktreeRemove payload.
 *
 * Both events emit the same shape — the dashboard caller passes `kind`
 * ('create' or 'remove') to disambiguate. Why subscribe at all when
 * CwdChanged covers `cd`-into-worktree? Because a worktree can be
 * REMOVED while a session is still attributed to it: without this hook,
 * subsequent token rows still record the now-deleted branch path.
 *
 * Returns:
 *   { ok: true,  sessionId, worktreePath, branch }
 *   { ok: false, error: string }
 */
export function parseWorktreeEventPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  const worktreePath = (typeof data.worktree_path === 'string' && data.worktree_path.length > 0)
    ? data.worktree_path
    : ((typeof data.path === 'string' && data.path.length > 0) ? data.path : null);
  if (!worktreePath) {
    return { ok: false, error: 'worktree_path required' };
  }
  const branch = (typeof data.branch === 'string' && data.branch.length > 0)
    ? data.branch
    : null;
  return { ok: true, sessionId, worktreePath, branch };
}

/**
 * Phase E — Validate and normalise a TaskCreated / TaskCompleted payload.
 *
 * Both events emit the same field set; the dashboard caller passes `kind`
 * ('created' or 'completed'). Used for agent-team task tracking — these
 * are agent-team-level lifecycle events that complement SubagentStart/Stop
 * with task-level metadata (description, status). When the parent session
 * is unknown (e.g. team launched outside a tracked Claude Code session),
 * the row is still recorded but parentSessionId stays null.
 *
 * Returns:
 *   { ok: true,  sessionId, taskId, parentSessionId, agentType, status, description }
 *   { ok: false, error: string }
 */
export function parseTaskEventPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  const taskId = (typeof data.task_id === 'string' && data.task_id.length > 0)
    ? data.task_id
    : null;
  if (!taskId) {
    return { ok: false, error: 'task_id required' };
  }
  // Phase G — the spec payload for TaskCreated/TaskCompleted carries ONLY
  // `task_id`, `task_title`, and (TaskCreated only) `task_description`.
  // `parent_session_id`, `agent_type`, `status`, and `description` were
  // vdm-internal guesses that never appear in real payloads. We keep them as
  // legacy fallbacks (always null in production) so old test fixtures still
  // work, and add the spec-correct `taskTitle` / `taskDescription` fields.
  const parentSessionId = data.parent_session_id || data.parentSessionId || null;
  const agentType = (typeof data.agent_type === 'string' && data.agent_type.length > 0)
    ? data.agent_type
    : null;
  const status = (typeof data.status === 'string' && data.status.length > 0)
    ? data.status
    : null;
  const taskTitle = (typeof data.task_title === 'string' && data.task_title.length > 0)
    ? data.task_title.slice(0, 200)
    : null;
  // Truncate description to 500 chars — task descriptions can be long
  // (multi-paragraph prompts) and we don't want to bloat token-usage.json.
  // Spec field is `task_description`; older fixtures may use `description`.
  const rawDescription = (typeof data.task_description === 'string' && data.task_description.length > 0)
    ? data.task_description
    : (typeof data.description === 'string' && data.description.length > 0
        ? data.description
        : null);
  const taskDescription = rawDescription ? rawDescription.slice(0, 500) : null;
  // Backward-compat: keep `description` as an alias of `taskDescription` so
  // existing dashboard.mjs handlers don't need to be updated in lockstep.
  const description = taskDescription;
  return { ok: true, sessionId, taskId, taskTitle, taskDescription, parentSessionId, agentType, status, description };
}

/**
 * Phase E — Validate and normalise a TeammateIdle payload.
 *
 * Fires when a Claude Code teammate (in agent-teams mode) goes idle.
 * Purely informational — doesn't affect token attribution. We log it
 * to the activity feed so users can correlate idle gaps with token-usage
 * lulls in the timeline view.
 *
 * Returns:
 *   { ok: true,  sessionId, teammateId }
 *   { ok: false, error: string }
 */
export function parseTeammateIdlePayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, error: 'payload must be an object' };
  }
  const sessionId = data.session_id;
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return { ok: false, error: 'session_id required' };
  }
  // Phase G — the spec payload uses `agent_id` (subagent instance ID) and
  // `agent_type`. `teammate_id` / `team_id` were vdm-internal guesses and are
  // never sent. Read both — the spec fields take precedence; the legacy names
  // are accepted so old test fixtures still pass.
  const agentId = (typeof data.agent_id === 'string' && data.agent_id.length > 0)
    ? data.agent_id
    : null;
  const agentType = (typeof data.agent_type === 'string' && data.agent_type.length > 0)
    ? data.agent_type
    : null;
  const teammateId = agentId
    || ((typeof data.teammate_id === 'string' && data.teammate_id.length > 0) ? data.teammate_id : null)
    || ((typeof data.team_id === 'string' && data.team_id.length > 0) ? data.team_id : null);
  return { ok: true, sessionId, agentId, agentType, teammateId };
}

/**
 * Phase E — Aggregate token-usage rows by `tool` field for the Tool
 * Breakdown UI panel.
 *
 * Skips non-usage rows (compact_boundary, etc.) via isUsageRow. Rows
 * without a `tool` field — which is the common case until perToolAttribution
 * is enabled — are bucketed under '(no per-tool attribution)' so the totals
 * still reconcile against the global aggregate (the user can immediately
 * see "X% of tokens are unattributed because the gate is off").
 *
 * MCP tools are bucketed by `mcpServer:tool` so two tools with the same
 * short name from different MCP servers don't collapse into one bucket.
 *
 * Optional second arg `range` filters by ts inclusively on both ends.
 *
 * Returns: [{ tool, mcpServer, inputTokens, outputTokens, totalTokens, count }]
 *          sorted by totalTokens desc.
 */
export function aggregateByTool(rows, range = null) {
  const buckets = new Map();
  const startMs = (range && typeof range.start === 'number') ? range.start : null;
  const endMs = (range && typeof range.end === 'number') ? range.end : null;
  for (const row of rows || []) {
    if (!isUsageRow(row)) continue;
    if (startMs !== null && (typeof row.ts !== 'number' || row.ts < startMs)) continue;
    if (endMs !== null && (typeof row.ts !== 'number' || row.ts > endMs)) continue;
    const tool = (typeof row.tool === 'string' && row.tool.length > 0)
      ? row.tool
      : '(no per-tool attribution)';
    const mcpServer = (typeof row.mcpServer === 'string' && row.mcpServer.length > 0)
      ? row.mcpServer
      : null;
    const key = mcpServer ? `${mcpServer}:${tool}` : tool;
    const inputTokens = Number(row.inputTokens) || 0;
    const outputTokens = Number(row.outputTokens) || 0;
    const existing = buckets.get(key);
    if (existing) {
      existing.inputTokens += inputTokens;
      existing.outputTokens += outputTokens;
      existing.totalTokens += inputTokens + outputTokens;
      existing.count += 1;
    } else {
      buckets.set(key, {
        tool,
        mcpServer,
        inputTokens,
        outputTokens,
        totalTokens: inputTokens + outputTokens,
        count: 1,
      });
    }
  }
  return Array.from(buckets.values()).sort((a, b) => b.totalTokens - a.totalTokens);
}

// ─── Phase J — keychain-based account storage ───
//
// Pre-Phase-J vdm cached every saved account's OAuth blob (accessToken +
// refreshToken + expiresAt) at `<INSTALL_DIR>/accounts/<name>.json` in
// plaintext, world-readable on default umask. Anyone with read access to
// $HOME could grab the refresh tokens (~ 90-day lifetime) and authenticate
// as the user against Anthropic. Phase J moves each account's blob into
// its own macOS Keychain entry under service `vdm-account-<name>` (account
// = $USER, same as the active CC entry). The user-visible label stays in
// `accounts/<name>.label` because labels are not secrets.

export const VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX = 'vdm-account-';

/**
 * Phase J — Derive the keychain service name for an account by name.
 *
 * Naming rules (intentionally tight to keep `security` CLI argv parsing
 * predictable across BSD / GNU / future replacements):
 *   - allowed chars: a-z A-Z 0-9 . _ @ -
 *   - must be non-empty
 *   - must not be the literal `index` (reserved for future index files)
 *
 * Throws on invalid input — callers should validate filenames upstream
 * (the existing `vdm add <name>` validation already enforces a stricter
 * subset, so this is defense-in-depth).
 */
export function vdmAccountServiceName(name) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error('account name required');
  }
  if (!/^[a-zA-Z0-9._@-]+$/.test(name)) {
    throw new Error(`invalid account name: ${name} (allowed: a-z A-Z 0-9 . _ @ -)`);
  }
  if (name === 'index') {
    throw new Error('"index" is reserved as an account name');
  }
  return `${VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX}${name}`;
}

/**
 * Phase J — Inverse of vdmAccountServiceName: extract the account name from
 * a keychain service string. Returns null if the service is not a vdm
 * account entry. Used during keychain enumeration.
 */
export function vdmAccountNameFromService(service) {
  if (typeof service !== 'string') return null;
  if (!service.startsWith(VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX)) return null;
  const name = service.slice(VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX.length);
  if (name.length === 0) return null;
  if (!/^[a-zA-Z0-9._@-]+$/.test(name)) return null;
  return name;
}

/**
 * CR-006 (Codex review): Validate a session_id from a Claude Code hook
 * payload. CC's session_id is spec'd as an opaque UUID-like string;
 * rejecting non-conforming values at the hook-endpoint boundary means
 * the dashboard renderer can interpolate s.id into HTML attributes and
 * inline JS handlers without escaping every site (and without paying
 * the cost of a future regression where a renderer site forgets to
 * escape). The character set covers UUIDs, ULIDs, and the dot-separated
 * sub-IDs that a future spec might add. Length cap defends against
 * pathological 1MB session_ids that would bloat token-usage.json and
 * blow renderer performance.
 *
 * Returns true iff `s` is a non-empty string ≤128 chars matching
 * /^[a-zA-Z0-9._-]+$/. Used by /api/session-start, /api/session-stop,
 * /api/session-end. Other session-aware endpoints (subagent-start,
 * post-tool-batch, etc.) already route through dedicated parsers
 * (parseSubagentStartPayload / parsePostToolBatchPayload) that apply
 * their own bounded-string guards.
 */
export function isValidSessionId(s) {
  return typeof s === 'string' && s.length > 0 && s.length <= 128 && /^[a-zA-Z0-9._-]+$/.test(s);
}

// ─── Phase H — OTLP/HTTP/JSON parser helpers ───
//
// vdm exposes an opt-in OTLP receiver (CSW_OTEL_ENABLED=1) so users can
// cross-check vdm's hook-derived token counts against Claude Code's
// first-party telemetry. We support the JSON-flavoured OTLP protocol only
// (http/json), not protobuf — JSON is widely understood, is what most
// users default to, and avoids pulling in a protobuf dependency (which
// would violate vdm's zero-deps rule anyway).
//
// Reference shape (subset of the OTLP/HTTP/JSON v1 schema):
//   POST /v1/logs
//   {
//     "resourceLogs": [
//       {
//         "resource":  { "attributes": [ {key, value:{...}}, ... ] },
//         "scopeLogs": [
//           { "scope": {...},
//             "logRecords": [
//               { "timeUnixNano": "169...", "severityNumber": 9,
//                 "severityText": "INFO",
//                 "body": { "stringValue": "claude_code.api_request" },
//                 "attributes": [...] } ]
//           }
//         ]
//       }
//     ]
//   }
//
// The parsers below are FORGIVING — Claude Code's exact payload shape can
// vary by version, so we accept any reasonable subset of the schema and
// flatten attributes into a plain JS object for downstream queries.

/**
 * Phase H — Convert one OTLP attribute-value object to a plain JS scalar.
 * OTLP wraps every value in a typed envelope: {stringValue, intValue,
 * doubleValue, boolValue, arrayValue, kvlistValue, bytesValue}. We unwrap
 * recursively so downstream code sees just numbers/strings/etc.
 */
export function unwrapOtlpValue(v) {
  if (!v || typeof v !== 'object') return null;
  if (typeof v.stringValue === 'string') return v.stringValue;
  // intValue is documented as a string-encoded int64 (JSON has no 64-bit
  // ints) — accept either form and return a JS number when safe.
  if (v.intValue !== undefined && v.intValue !== null) {
    const n = typeof v.intValue === 'string' ? Number(v.intValue) : v.intValue;
    return Number.isFinite(n) ? n : null;
  }
  if (typeof v.doubleValue === 'number') return v.doubleValue;
  if (typeof v.boolValue === 'boolean') return v.boolValue;
  if (Array.isArray(v.arrayValue?.values)) {
    return v.arrayValue.values.map(unwrapOtlpValue);
  }
  if (Array.isArray(v.kvlistValue?.values)) {
    return otlpAttrsToObject(v.kvlistValue.values);
  }
  if (typeof v.bytesValue === 'string') return v.bytesValue; // base64 — keep as-is
  return null;
}

/**
 * Phase H — Flatten an OTLP attributes array (`[{key, value}, ...]`) into a
 * plain object. Last-write-wins on duplicate keys (rare, but possible).
 */
export function otlpAttrsToObject(attrs) {
  // M4 fix — explicitly skip reserved keys that could pollute or shadow
  // Object.prototype methods. The OTLP receiver accepts any attribute keys
  // from external Claude Code processes (CSW_OTEL_ENABLED=1 is opt-in, but
  // the receiver's contract is "untrusted external input" regardless).
  const out = {};
  if (!Array.isArray(attrs)) return out;
  for (const a of attrs) {
    if (!a || typeof a !== 'object' || typeof a.key !== 'string') continue;
    if (a.key === '__proto__' || a.key === 'constructor' || a.key === 'prototype') continue;
    out[a.key] = unwrapOtlpValue(a.value);
  }
  return out;
}

/**
 * Phase H — Parse an OTLP/HTTP/JSON `ExportLogsServiceRequest` into a flat
 * array of records, each: { ts, severity, body, resource, scope, attributes }.
 *
 * `ts` is a JS Date.now()-style number in ms. OTLP carries time in Unix
 * nanoseconds (string), so we divide by 1e6. If `timeUnixNano` is missing
 * or unparseable we fall back to the current wall-clock time.
 *
 * `body` is the unwrapped Body field (commonly a string for events;
 * structured logs would yield an object).
 *
 * `attributes` merges the LogRecord-level attrs with resource+scope context
 * (resource attrs are duplicated onto each record so downstream queries can
 * filter by `service.name` / `user.account_id` / etc. without cross-walks).
 */
export function parseOtlpLogs(payload) {
  const out = [];
  if (!payload || typeof payload !== 'object') return out;
  const resourceLogs = Array.isArray(payload.resourceLogs) ? payload.resourceLogs : [];
  for (const rl of resourceLogs) {
    const resourceAttrs = otlpAttrsToObject(rl?.resource?.attributes);
    const scopeLogs = Array.isArray(rl?.scopeLogs) ? rl.scopeLogs : [];
    for (const sl of scopeLogs) {
      const scopeName = sl?.scope?.name || '';
      const logRecords = Array.isArray(sl?.logRecords) ? sl.logRecords : [];
      for (const lr of logRecords) {
        const recordAttrs = otlpAttrsToObject(lr.attributes);
        // OTLP nanos are encoded as strings (JSON int64 limitation). Be
        // generous about format: accept string OR number.
        const nanos = lr.timeUnixNano !== undefined ? Number(lr.timeUnixNano) : 0;
        const ts = nanos > 0 && Number.isFinite(nanos) ? Math.floor(nanos / 1e6) : Date.now();
        out.push({
          ts,
          severity: lr.severityText || (lr.severityNumber != null ? String(lr.severityNumber) : ''),
          body: unwrapOtlpValue(lr.body),
          scope: scopeName,
          resource: resourceAttrs,
          attributes: { ...resourceAttrs, ...recordAttrs },
        });
      }
    }
  }
  return out;
}

/**
 * Phase H — Parse an OTLP/HTTP/JSON `ExportMetricsServiceRequest` into a
 * flat array of data-point records: { ts, name, value, attributes, kind }.
 *
 * Supports `sum`, `gauge`, `histogram` (count only), `summary` (sum only).
 * Histograms / summaries lose their distribution information; vdm is
 * interested in totals (token counts), not buckets.
 */
export function parseOtlpMetrics(payload) {
  const out = [];
  if (!payload || typeof payload !== 'object') return out;
  const resourceMetrics = Array.isArray(payload.resourceMetrics) ? payload.resourceMetrics : [];
  for (const rm of resourceMetrics) {
    const resourceAttrs = otlpAttrsToObject(rm?.resource?.attributes);
    const scopeMetrics = Array.isArray(rm?.scopeMetrics) ? rm.scopeMetrics : [];
    for (const sm of scopeMetrics) {
      const metrics = Array.isArray(sm?.metrics) ? sm.metrics : [];
      for (const m of metrics) {
        const name = m.name || '';
        const dataPoints =
          (m.sum?.dataPoints) ||
          (m.gauge?.dataPoints) ||
          (m.histogram?.dataPoints) ||
          (m.exponentialHistogram?.dataPoints) ||
          (m.summary?.dataPoints) ||
          [];
        const kind = m.sum ? 'sum' : m.gauge ? 'gauge'
          : m.histogram ? 'histogram'
          : m.exponentialHistogram ? 'expHistogram'
          : m.summary ? 'summary' : 'unknown';
        for (const dp of dataPoints) {
          // For sum/gauge: asInt or asDouble. For histogram/summary: count.
          let value = null;
          if (dp.asDouble !== undefined) value = Number(dp.asDouble);
          else if (dp.asInt !== undefined) value = Number(dp.asInt);
          else if (dp.count !== undefined) value = Number(dp.count);
          else if (dp.sum !== undefined) value = Number(dp.sum);
          if (value !== null && !Number.isFinite(value)) value = null;
          const dpAttrs = otlpAttrsToObject(dp.attributes);
          const nanos = dp.timeUnixNano !== undefined ? Number(dp.timeUnixNano) : 0;
          const ts = nanos > 0 && Number.isFinite(nanos) ? Math.floor(nanos / 1e6) : Date.now();
          out.push({
            ts,
            name,
            value,
            kind,
            attributes: { ...resourceAttrs, ...dpAttrs },
          });
        }
      }
    }
  }
  return out;
}

// ─────────────────────────────────────────────────
// Serialization Queue (settings-level, separate from
// per-account-permit limiter in dashboard.mjs)
// ─────────────────────────────────────────────────
//
// Why this is a factory (not module-level state):
//   - Unit-testable. Caller injects fake clock + getters and asserts
//     that inflight never exceeds the configured cap.
//   - Reusable across more than one queue if needed.
//
// What it fixes (the bug that motivated this factory):
//   The previous module-level implementation in dashboard.mjs had an
//   `if (inflight === 0) <bypass-queue>` early-return. Under sustained
//   load (15+ concurrent CC clients), every time the queue's 200ms
//   dispatch timer was waiting to fire, a fresh request whose inflight
//   counter was momentarily 0 would bypass the queue entirely. The
//   queue then dispatched its own pending entry on top, producing
//   inflight counts of 18+ even though the user had configured strict
//   serialization. This factory removes the bypass: when enabled,
//   every request goes through the queue and inflight is HARD-CAPPED
//   at getMaxConcurrent().
//
// Semantics:
//   - getEnabled() === false: every call bypasses the queue (free for all).
//   - isRetry === true (per-call flag): bypasses the queue. Retries are
//     "make progress at any cost" paths from the caller's loop and must
//     not deadlock against their own queued ancestor.
//   - Otherwise: pushed onto the queue. The dispatch loop pulls one
//     entry whenever inflight < cap, waiting at least getDelayMs()
//     between successive dispatches.
//   - drain(): release every queued entry immediately (used when the
//     user toggles serialization OFF — open the floodgates).
//
// Re-entrancy: dispatching is gated by a single timer handle so two
// completion callbacks firing in the same microtask cannot both fire
// off a fresh dispatch. The timer is cleared and re-scheduled on each
// state change.
/**
 * Garbage-collect idle account-slot Map entries.
 *
 * Phase F audit K1 — the per-account limiter slots Map (in dashboard.mjs)
 * grows monotonically: every refresh creates a new fingerprint and the old
 * fingerprint's slot is never deleted by the limiter itself. Combined with
 * permit leaks (audit A1), retired fingerprints accumulate with inflight>0
 * forever, eventually wedging the limiter and causing the "works for hours
 * then breaks" ConnectionRefused symptom.
 *
 * `gcAccountSlots` is a pure sweep over the Map: for every entry where
 *   inflight === 0 && waiters.length === 0 && (now - lastDispatchAt) > idleMs
 * the entry is deleted. Returns the count of purged entries.
 *
 * Pure for testability — no side effects beyond mutating the passed-in Map.
 *
 * @param {Map<string, {inflight:number,waiters:Array,lastDispatchAt:number}>} slotsMap
 * @param {number} [now=Date.now()]   - clock injection for tests
 * @param {number} [idleMs=3600000]   - idle-eligible threshold (default 1h)
 * @returns {number} count of purged entries
 */
export function gcAccountSlots(slotsMap, now = Date.now(), idleMs = 3600_000) {
  if (!slotsMap || typeof slotsMap.entries !== 'function') return 0;
  let purged = 0;
  for (const [fp, s] of slotsMap) {
    if (
      s &&
      s.inflight === 0 &&
      Array.isArray(s.waiters) &&
      s.waiters.length === 0 &&
      typeof s.lastDispatchAt === 'number' &&
      (now - s.lastDispatchAt) > idleMs
    ) {
      slotsMap.delete(fp);
      purged++;
    }
  }
  return purged;
}

export function createSerializationQueue(opts = {}) {
  const getMaxConcurrent = opts.getMaxConcurrent || (() => 1);
  const getDelayMs = opts.getDelayMs || (() => 0);
  const getEnabled = opts.getEnabled || (() => true);
  // Phase F audit follow-up — use `??` so an explicit `0` (or any falsy-but-valid
  // value) is honored as a configured override. The previous `||` form silently
  // replaced a deliberate `queueTimeoutMs: 0` with the 120s default.
  const queueTimeoutMs = opts.queueTimeoutMs ?? 120_000;
  const now = opts.now || (() => Date.now());

  let inflight = 0;
  let lastDispatchAt = 0;
  let dispatchTimer = null;
  const queue = [];

  function _maybeDispatch() {
    if (dispatchTimer) return; // a dispatch is already pending
    if (queue.length === 0) return;
    if (inflight >= Math.max(1, getMaxConcurrent())) return;
    const delay = Math.max(0, getDelayMs() | 0);
    const sinceLast = now() - lastDispatchAt;
    const wait = Math.max(0, delay - sinceLast);
    dispatchTimer = setTimeout(() => {
      dispatchTimer = null;
      // Re-validate at fire time — settings may have changed during the
      // wait, the queue may have been drained, etc.
      if (queue.length === 0) return;
      if (inflight >= Math.max(1, getMaxConcurrent())) {
        // Cap re-tightened while we waited — back off and let an
        // inflight completion call us again.
        return;
      }
      const entry = queue.shift();
      if (!entry) return;
      clearTimeout(entry.timeoutHandle);
      entry.dispatched = true;
      inflight++;
      lastDispatchAt = now();
      // Promise.resolve().then(...) wraps the run call so a fn() that
      // throws synchronously (non-async function) becomes a rejection
      // instead of an exception propagating out of the timer callback.
      Promise.resolve()
        .then(() => entry.run())
        .finally(() => {
          inflight--;
          _maybeDispatch();
        });
      // If headroom remains (cap > 1) and queue still has work, fire
      // the next one too — but route through _maybeDispatch so the
      // delay between successive dispatches is still honored.
      _maybeDispatch();
    }, wait);
  }

  function acquire(fn, isRetry = false) {
    if (!getEnabled() || isRetry) {
      inflight++;
      lastDispatchAt = now();
      return Promise.resolve()
        .then(fn)
        .finally(() => {
          inflight--;
          _maybeDispatch();
        });
    }
    return new Promise((resolve, reject) => {
      const entry = {
        // Wrap fn in Promise.resolve().then(...) so a synchronous throw
        // from a non-async fn becomes a rejection routed through the
        // outer Promise, rather than throwing out of the dispatcher.
        run: () => Promise.resolve().then(fn).then(resolve, reject),
        timeoutHandle: null,
        dispatched: false,
      };
      entry.timeoutHandle = setTimeout(() => {
        // Guard against the dispatcher having shifted+dispatched this
        // entry between the timer firing and our callback running.
        // Without this, a queued entry that JUST started executing
        // could be rejected with queue_timeout while still running.
        if (entry.dispatched) return;
        const idx = queue.indexOf(entry);
        if (idx !== -1) queue.splice(idx, 1);
        reject(new Error('queue_timeout'));
      }, queueTimeoutMs);
      queue.push(entry);
      _maybeDispatch();
    });
  }

  function drain() {
    // Cancel any pending dispatch timer — we're going to flush now.
    if (dispatchTimer) {
      clearTimeout(dispatchTimer);
      dispatchTimer = null;
    }
    while (queue.length > 0) {
      const entry = queue.shift();
      clearTimeout(entry.timeoutHandle);
      entry.dispatched = true;
      inflight++;
      lastDispatchAt = now();
      Promise.resolve()
        .then(() => entry.run())
        .finally(() => {
          inflight--;
          _maybeDispatch();
        });
    }
  }

  // Progressive drain — releases queued entries one at a time at
  // `intervalMs` cadence instead of flushing all at once. Used when
  // serialize mode disengages (user toggle, breaker auto-disable,
  // Safeguard D auto-revert): without it, a backlog of N pending
  // payloads hits Anthropic in the same millisecond and produces an
  // immediate rate-limit cascade across whichever account is active.
  // Returns a controller object so callers can cancel mid-drain
  // (e.g. if the user re-enables serialize while a drain is running).
  //
  // Contract:
  //   - intervalMs ≥ 50 ms (anything tighter is "instant flush" in
  //     practice; that's what drain() is for).
  //   - Cancels and replaces any pending _maybeDispatch timer so we
  //     don't have two dispatchers racing.
  //   - If queue is already empty, fires onDrained() synchronously
  //     and returns.
  //   - Schedules at most ONE dispatch per interval. inflight cap is
  //     ignored (the whole point of progressive drain is to release
  //     the backlog regardless of normal-mode concurrency caps —
  //     though no in-flight will exceed serializeMaxConcurrent at any
  //     instant because each tick releases exactly one entry).
  //   - onDrained() fires when the queue empties, OR when cancel()
  //     is called externally.
  function drainProgressively(opts = {}) {
    const intervalMs = Math.max(50, opts.intervalMs | 0 || 250);
    const onDrained = typeof opts.onDrained === 'function' ? opts.onDrained : null;
    if (dispatchTimer) {
      clearTimeout(dispatchTimer);
      dispatchTimer = null;
    }
    if (queue.length === 0) {
      if (onDrained) try { onDrained({ released: 0, cancelled: false }); } catch {}
      return { cancel: () => {}, released: () => 0, remaining: () => 0 };
    }
    let released = 0;
    let cancelled = false;
    let tickHandle = null;
    const tick = () => {
      tickHandle = null;
      if (cancelled) return;
      if (queue.length === 0) {
        if (onDrained) try { onDrained({ released, cancelled: false }); } catch {}
        return;
      }
      const entry = queue.shift();
      clearTimeout(entry.timeoutHandle);
      entry.dispatched = true;
      inflight++;
      lastDispatchAt = now();
      released++;
      Promise.resolve()
        .then(() => entry.run())
        .finally(() => {
          inflight--;
          // Don't call _maybeDispatch here — we own the dispatch
          // schedule for the duration of the progressive drain.
        });
      if (queue.length > 0) {
        tickHandle = setTimeout(tick, intervalMs);
        if (tickHandle.unref) tickHandle.unref();
      } else if (onDrained) {
        try { onDrained({ released, cancelled: false }); } catch {}
      }
    };
    // Fire the first dispatch immediately (rate is "1 per intervalMs"
    // counted from now, not "1 after intervalMs delay").
    tick();
    return {
      cancel: () => {
        cancelled = true;
        if (tickHandle) {
          clearTimeout(tickHandle);
          tickHandle = null;
        }
        if (onDrained) try { onDrained({ released, cancelled: true }); } catch {}
      },
      released: () => released,
      remaining: () => queue.length,
    };
  }

  function getStats() {
    return { inflight, queued: queue.length };
  }

  return { acquire, drain, drainProgressively, getStats };
}

// ─────────────────────────────────────────────────
// SSE Token-Usage Extractor
// ─────────────────────────────────────────────────

// Extracted to lib.mjs (FG4 follow-up) so the abort-path token-rescue
// behavior of finishParsing() can be unit-tested. Pre-extraction the
// extractor lived in dashboard.mjs as a private factory and the M2 fix
// (idempotent finishParsing for pipeline-destroy bypass) had zero direct
// test coverage — a regression in the Anthropic SSE format would have
// silently dropped output_tokens on every aborted stream.
//
// Pure factory: depends only on `Transform` from `node:stream`. The
// optional `logger` parameter mirrors dashboard.mjs's `log()` shape
// (`(level, message) => void`) so debug events bubble through the
// dashboard's normal log pipeline without coupling lib.mjs to it.
//
// Usage shape:
//   const extractor = createUsageExtractor({ logger: log });
//   pipeline(srcRes, extractor, clientRes, callback);
//   // After pipeline resolves (success OR error/abort):
//   extractor.finishParsing();          // idempotent
//   const usage = extractor.getUsage(); // { inputTokens, outputTokens, ... }
export function createUsageExtractor({ logger = null } = {}) {
  let inputTokens = 0;
  let outputTokens = 0;
  // Cache tokens are billed separately by Anthropic; the original extractor
  // ignored them entirely, so any response whose only "delta" was cache
  // creation/read showed up as 0/0 and got dropped by recordUsage.
  let cacheCreationInputTokens = 0;
  let cacheReadInputTokens = 0;
  let model = '';
  // Anthropic's `message_start` event carries a `message.id` (the assistant
  // turn UUID, e.g. "msg_01ABC…"). Capturing it lets appendTokenUsage dedup
  // by (sessionId, messageId) so a hook re-fire (dashboard restart mid-turn,
  // duplicate-delivery, etc.) doesn't double-count the same turn.
  let messageId = '';
  let lineBuffer = '';
  let nextEventType = '';
  // Phase F audit M2 — trailing-buffer parsing must run on BOTH the success
  // path (Transform's flush()) AND the abort path (pipeline destroy bypasses
  // flush). `_finishedParsing` makes finishParsing idempotent so calling it
  // from both ends is safe.
  let _finishedParsing = false;

  function _processTrailingLine() {
    if (_finishedParsing) return;
    _finishedParsing = true;
    const trimmed = lineBuffer.trim();
    lineBuffer = '';
    if (trimmed.startsWith('data:') && nextEventType === 'message_delta') {
      try {
        const data = JSON.parse(trimmed.slice(5).trim());
        if (data.usage) {
          outputTokens = data.usage.output_tokens || outputTokens;
          if (data.usage.cache_creation_input_tokens != null) {
            cacheCreationInputTokens = data.usage.cache_creation_input_tokens;
          }
          if (data.usage.cache_read_input_tokens != null) {
            cacheReadInputTokens = data.usage.cache_read_input_tokens;
          }
        }
      } catch (e) {
        // Trailing partial line was malformed JSON. Surface it
        // (debug-level — these can happen legitimately during
        // upstream cancellation) so we don't silently lose token
        // counts on every interrupted SSE stream.
        if (logger) {
          try { logger('debug', `flush: trailing message_delta parse failed: ${e.message}`); } catch {}
        }
      }
    }
  }

  const extractor = new Transform({
    // `_encoding` is required by the Transform API positional signature
    // (transform(chunk, encoding, callback)) but unused — chunks are always
    // Buffers here because the upstream is an http.IncomingMessage.
    transform(chunk, _encoding, callback) {
      // Pass through bytes unchanged
      this.push(chunk);

      // Scan for usage data in SSE events
      const text = chunk.toString('utf8');
      lineBuffer += text;

      const lines = lineBuffer.split('\n');
      // Keep the last (potentially incomplete) line in the buffer
      lineBuffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('event:')) {
          nextEventType = trimmed.slice(6).trim();
        } else if (trimmed.startsWith('data:') && nextEventType) {
          try {
            const data = JSON.parse(trimmed.slice(5).trim());
            if (nextEventType === 'message_start' && data.message) {
              if (data.message.usage) {
                inputTokens = data.message.usage.input_tokens || 0;
                cacheCreationInputTokens = data.message.usage.cache_creation_input_tokens || 0;
                cacheReadInputTokens = data.message.usage.cache_read_input_tokens || 0;
              }
              if (data.message.model) {
                model = data.message.model;
              }
              if (typeof data.message.id === 'string' && data.message.id) {
                messageId = data.message.id;
              }
            } else if (nextEventType === 'message_delta' && data.usage) {
              outputTokens = data.usage.output_tokens || 0;
              // message_delta usage may also carry final cache totals.
              if (data.usage.cache_creation_input_tokens != null) {
                cacheCreationInputTokens = data.usage.cache_creation_input_tokens;
              }
              if (data.usage.cache_read_input_tokens != null) {
                cacheReadInputTokens = data.usage.cache_read_input_tokens;
              }
            }
          } catch { /* not JSON or malformed — skip */ }
          nextEventType = '';
        }
      }

      callback();
    },
    flush(callback) {
      // Try the trailing partial line one last time so the final
      // message_delta isn't lost when upstream closes between newlines.
      // Delegated to the shared helper so the abort path can run the
      // exact same logic via finishParsing().
      _processTrailingLine();
      callback();
    },
  });

  extractor.getUsage = () => ({
    inputTokens,
    outputTokens,
    cacheCreationInputTokens,
    cacheReadInputTokens,
    model,
    messageId: messageId || null,
    ts: Date.now(),
  });

  // Phase F audit M2 — explicit idempotent trailing-buffer flush. pipeline()
  // calls destroy() (not end()) when ANY stream in the chain errors or the
  // client aborts. destroy() bypasses _flush, so the trailing-line parser
  // never runs and the final message_delta is silently lost — which manifests
  // as recordUsage seeing outputTokens=0 on every aborted SSE stream. The
  // continuation runner calls finishParsing() unconditionally after pipeline
  // resolves, and the success path is a no-op via _finishedParsing.
  extractor.finishParsing = _processTrailingLine;

  return extractor;
}

// ─────────────────────────────────────────────────
// JSON usage extractor (non-SSE responses)
// ─────────────────────────────────────────────────
// Companion to createUsageExtractor. The SSE extractor handles streaming
// Claude Code traffic. This one handles non-streaming JSON responses
// (direct curl, SDK calls without stream=true, /v1/messages/count_tokens,
// scripts, debug probes). Without it, every API call that doesn't use
// streaming bypasses recordUsage and never lands in token-usage.json —
// even though the proxy sees the full response with `usage` data in the
// body. The two extractors form a symmetric pair so the proxy → recentUsage
// → claimUsageInRange → token-usage.json join works regardless of whether
// the caller chose stream=true or stream=false.
//
// Returns a Transform that PASSES THROUGH every byte unchanged (so the
// downstream pipe to the client is not delayed) AND tees a copy into a
// bounded buffer for parsing at end. The buffer is capped at maxBytes
// (default 1 MiB) — bigger responses are truncated and getUsage() returns
// null rather than parse a partial JSON. Error responses, non-JSON content
// types, and parse failures all return null; the caller is expected to
// gate the recordUsage call on a non-null return.
//
// Usage:
//   const extractor = createJsonUsageExtractor({ logger: log });
//   proxyRes.pipe(extractor).pipe(clientRes);
//   await new Promise(r => clientRes.on('finish', r));
//   const usage = extractor.getUsage();
//   if (usage) recordUsage(usage, accountName);
export function createJsonUsageExtractor({ logger = null, maxBytes = 1024 * 1024 } = {}) {
  const chunks = [];
  let bufLen = 0;
  let truncated = false;

  const transform = new Transform({
    transform(chunk, _enc, cb) {
      try {
        if (!truncated) {
          if (bufLen + chunk.length <= maxBytes) {
            chunks.push(chunk);
            bufLen += chunk.length;
          } else {
            // Take what room is left and mark truncated. The downstream
            // pipe still gets the full chunk via cb(null, chunk).
            const room = Math.max(0, maxBytes - bufLen);
            if (room > 0) {
              chunks.push(chunk.slice(0, room));
              bufLen += room;
            }
            truncated = true;
          }
        }
      } catch (e) {
        if (logger) try { logger('debug', 'json-usage-extractor buffer failed: ' + e.message); } catch {}
      }
      cb(null, chunk);  // ALWAYS pass-through — never delay the client
    },
  });

  transform.getUsage = function() {
    if (truncated) return null;
    if (bufLen === 0) return null;
    let parsed;
    try {
      parsed = JSON.parse(Buffer.concat(chunks, bufLen).toString('utf8'));
    } catch (e) {
      if (logger) try { logger('debug', 'json-usage-extractor parse failed: ' + e.message); } catch {}
      return null;
    }
    if (!parsed || typeof parsed !== 'object') return null;
    const u = parsed.usage;
    if (!u || typeof u !== 'object') return null;
    // Mirror the field names the SSE extractor produces and recordUsage expects.
    return {
      inputTokens: u.input_tokens || 0,
      outputTokens: u.output_tokens || 0,
      cacheCreationInputTokens: u.cache_creation_input_tokens || 0,
      cacheReadInputTokens: u.cache_read_input_tokens || 0,
      model: parsed.model || '',
      messageId: parsed.id || '',
    };
  };

  // Compatibility shim with createUsageExtractor's API — the SSE extractor
  // exposes finishParsing() for the abort path. The JSON extractor doesn't
  // need it (no streaming state) but accepts the same call so downstream
  // code can treat both extractor types interchangeably.
  transform.finishParsing = function() {};

  return transform;
}

// ─────────────────────────────────────────────────
// UX-X8 / UX-X9 — unified time + token-count formatters
// ─────────────────────────────────────────────────
// One canonical place to convert raw numbers into human-readable
// strings, plus their unabbreviated counterparts for hover tooltips.
// dashboard.mjs ships browser-side mirrors of these (fmtTokenCountShort
// / fmtTokenCountExact / fmtDurationShort / fmtDurationExact) inside
// renderHTML(), but the algorithm is defined HERE so a single fix
// propagates to every site.
//
// Why dual-output {short, exact}:
//   - UX-X9: formatNum(1234567) returned "1.2M" — silently truncating
//     234,567 tokens. Power users couldn't tell "1.2M vs 1.2M" apart
//     (could be 1.2M and 1.7M in raw counts). Returning BOTH the
//     compact form AND the exact form lets the caller render the
//     compact in the cell and the exact in title="..." for hover.
//   - UX-X8: rotation interval said "15 min", scrubber said "Last hour",
//     ETA said "1:30", session duration said "5m 23s" — five spellings
//     for the same concept. fmtDuration emits ONE compact form ("5m
//     12s" / "2h 30m" / "3d 5h") used everywhere a duration is shown.

/**
 * Compact + exact dual-output for token/integer counts.
 *
 *   fmtTokenCount(0)       → { short: '0',     exact: '0' }
 *   fmtTokenCount(15500)   → { short: '15.5K', exact: '15,500' }
 *   fmtTokenCount(1234567) → { short: '1.2M',  exact: '1,234,567' }
 *   fmtTokenCount(2.5e9)   → { short: '2.5B',  exact: '2,500,000,000' }
 *
 * Defensive: null / undefined / NaN / negative / Infinity / non-numeric
 * all fall back to {short:'0', exact:'0'} — token counts cannot be
 * negative and the UI must never show NaN. Floating-point inputs are
 * floored (token counts are integral).
 *
 * Pure: no DOM, no time-of-day, no global state.
 */
export function fmtTokenCount(n) {
  // Defensive normalisation. Anything that isn't a finite, non-negative
  // number collapses to 0 — this is the single chokepoint that prevents
  // "NaN tokens" or "-1.7M tokens" from ever reaching the UI.
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) {
    return { short: '0', exact: '0' };
  }
  const v = Math.floor(n);
  let short;
  if (v >= 1e9) short = (v / 1e9).toFixed(1) + 'B';
  else if (v >= 1e6) short = (v / 1e6).toFixed(1) + 'M';
  else if (v >= 1e3) short = (v / 1e3).toFixed(1) + 'K';
  else short = String(v);
  // Exact form uses en-US grouping (1,234,567) — universally recognised
  // even by non-en locales because the comma is conventional in
  // monospace-readable contexts (JSON, CSV, log output, dev tools).
  // Hard-coding the locale keeps the regression tests deterministic.
  const exact = v.toLocaleString('en-US');
  return { short, exact };
}

/**
 * Compact + verbose dual-output for time durations expressed in
 * milliseconds.
 *
 *   fmtDuration(0)            → { short: '0s',      exact: '0 milliseconds' }
 *   fmtDuration(750)          → { short: '0s',      exact: '750 milliseconds' }
 *   fmtDuration(45_000)       → { short: '45s',     exact: '45 seconds' }
 *   fmtDuration(312_000)      → { short: '5m 12s',  exact: '5 minutes 12 seconds' }
 *   fmtDuration(9_000_000)    → { short: '2h 30m',  exact: '2 hours 30 minutes' }
 *   fmtDuration(277_200_000)  → { short: '3d 5h',   exact: '3 days 5 hours' }
 *
 * Defensive: null / undefined / NaN / negative / Infinity / non-numeric
 * all fall back to {short:'0s', exact:'0 milliseconds'}. Durations
 * cannot be negative; sub-second values keep the millisecond resolution
 * in `exact` (so a 750 ms "0s" cell still has a useful hover tooltip).
 *
 * Pure: no Date.now, no DOM, no global state. Inputs are absolute ms.
 */
export function fmtDuration(ms) {
  // Defensive normalisation — same chokepoint pattern as fmtTokenCount.
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms < 0) {
    return { short: '0s', exact: '0 milliseconds' };
  }
  const v = Math.floor(ms);
  if (v === 0) return { short: '0s', exact: '0 milliseconds' };
  // Sub-second: short rounds DOWN to "0s" (matches the existing
  // sessionDuration behaviour — sub-1s deltas are visually "instant"
  // and don't deserve a busy "0.7s" cell), but exact keeps the raw ms
  // so the hover still tells the truth.
  if (v < 1000) {
    return { short: '0s', exact: v + ' milliseconds' };
  }
  const sec  = Math.floor(v / 1000);
  const min  = Math.floor(sec / 60);
  const hr   = Math.floor(min / 60);
  const day  = Math.floor(hr / 24);
  const remS = sec % 60;
  const remM = min % 60;
  const remH = hr % 24;
  // Compact form — ONE spelling everywhere (UX-X8). Two-segment cap so
  // "3d 5h 17m 22s" never appears: every duration in the UI is either
  // an estimate or a rounded display, and three-segment forms make the
  // dashboard feel like a stopwatch app.
  let short;
  if (day >= 1)      short = day + 'd ' + remH + 'h';
  else if (hr  >= 1) short = hr  + 'h ' + remM + 'm';
  else if (min >= 1) short = min + 'm ' + remS + 's';
  else               short = sec + 's';
  // Verbose form — singular/plural correct, no segment shown when its
  // value is zero. Used in title="..." tooltips and screen-reader text.
  const parts = [];
  if (day > 0) parts.push(day + (day === 1 ? ' day'    : ' days'));
  if (day > 0 || hr > 0) {
    if (remH > 0 || day > 0)  parts.push(remH + (remH === 1 ? ' hour'   : ' hours'));
  }
  if (day === 0 && hr === 0 && min > 0) {
    parts.push(min + (min === 1 ? ' minute' : ' minutes'));
    if (remS > 0) parts.push(remS + (remS === 1 ? ' second' : ' seconds'));
  } else if (day === 0 && hr > 0) {
    // Already pushed hours; add minutes if non-zero (skip seconds —
    // matches the two-segment short form's semantics).
    if (remM > 0) parts.push(remM + (remM === 1 ? ' minute' : ' minutes'));
  } else if (day > 0) {
    // Already pushed day + hour; nothing else to add.
  } else if (sec > 0) {
    parts.push(sec + (sec === 1 ? ' second' : ' seconds'));
  }
  // Special-cases for the "exactly N units, no remainder" forms
  // (1 hour, 1 day, etc.) — the loop above pushes "1 hour 0 minutes"
  // which reads worse than "1 hour". Trim the trailing zero unit.
  let exact = parts.join(' ');
  exact = exact.replace(/ 0 (minute|minutes|hour|hours|second|seconds)$/, '');
  if (!exact) exact = sec + (sec === 1 ? ' second' : ' seconds');
  return { short, exact };
}
