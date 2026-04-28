// Van Damme-o-Matic  - Core Library
// Pure/testable functions extracted from dashboard.mjs.
// Zero dependencies, uses Node.js built-in modules only.

import { createHash } from 'node:crypto';

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
    get, entries, clear, remove,
  };
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

export function pickBestAccount(accounts, stateManager, excludeTokens = new Set()) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager))
    .map(a => ({ ...a, score: scoreAccount(a.token, stateManager) }))
    .sort((a, b) => a.score - b.score);
  return candidates[0] || null;
}

export function pickDrainFirst(accounts, stateManager, excludeTokens = new Set()) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager))
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

export function pickConserve(accounts, stateManager, excludeTokens = new Set()) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager))
    .map(a => ({ ...a, score: scoreAccountConserve(a.token, stateManager) }))
    .sort((a, b) => b.score - a.score); // highest combined utilization first
  return candidates[0] || null;
}

export function pickAnyUntried(accounts, excludeTokens) {
  return accounts.find(a => !excludeTokens.has(a.token)) || null;
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
    const best = pickBestAccount(accounts, stateManager, excludeTokens);
    return { account: best, rotated: !!best };
  }

  switch (strategy) {
    case 'sticky':
      // Never proactively switch  - keep current
      return { account: null, rotated: false };

    case 'conserve': {
      // Pick account with highest weekly utilization (windows already active)
      // Untouched accounts stay dormant  - their windows don't start
      const conserved = pickConserve(accounts, stateManager, excludeTokens);
      if (conserved && conserved.token !== currentToken) {
        return { account: conserved, rotated: true };
      }
      return { account: null, rotated: false };
    }

    case 'round-robin': {
      const elapsed = now - (lastRotationTime || 0);
      const intervalMs = (intervalMin || 60) * 60 * 1000;
      if (elapsed < intervalMs) {
        return { account: null, rotated: false }; // timer not elapsed
      }
      const best = pickBestAccount(accounts, stateManager, excludeTokens);
      if (best && best.token !== currentToken) {
        return { account: best, rotated: true };
      }
      return { account: null, rotated: false }; // already on best
    }

    case 'spread':
      // Always pick lowest utilization (current behavior)
      const lowest = pickBestAccount(accounts, stateManager, excludeTokens);
      if (lowest && lowest.token !== currentToken) {
        return { account: lowest, rotated: true };
      }
      return { account: null, rotated: false };

    case 'drain-first': {
      const drain = pickDrainFirst(accounts, stateManager, excludeTokens);
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
      const expiresIn = data.expires_in || data.expiresIn || 0;
      if (!accessToken) {
        return { ok: false, error: 'No access_token in response', retriable: false };
      }
      return { ok: true, accessToken, refreshToken: refreshToken || null, expiresIn };
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
  return { ok: true, sessionId, cwd, agentId, parentSessionId, agentType, transcriptPath };
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
    if (typeof toolName !== 'string' || toolName.length === 0) continue;
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
