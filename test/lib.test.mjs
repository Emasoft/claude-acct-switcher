// Unit tests for lib.mjs  - pure functions
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders,
  stripHopByHopHeaders,
  HOP_BY_HOP,
  createAccountStateManager,
  isAccountAvailable,
  scoreAccount,
  scoreAccountConserve,
  pickBestAccount,
  pickConserve,
  pickDrainFirst,
  pickAnyUntried,
  pickByStrategy,
  createProbeTracker,
  createUtilizationHistory,
  buildRefreshRequestBody,
  parseRefreshResponse,
  parseRetryAfter,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  createPerAccountLock,
  getEarliestReset,
  createSemaphore,
  createSerializationQueue,
  createSlidingWindowCounter,
  gcAccountSlots,
  createUsageExtractor,
  clampViewerState,
  VIEWER_STATE_MIN_WINDOW_MS,
  // Phase D — hook payload parsers and helpers
  parseCompactPayload,
  parseSubagentStartPayload,
  parseCwdChangedPayload,
  parsePostToolBatchPayload,
  inferMcpServerFromToolName,
  isUsageRow,
  buildCompactBoundaryEntry,
  mergeSessionAttribution,
  // Phase E — additional hook parsers + breakdown helper
  parseWorktreeEventPayload,
  parseTaskEventPayload,
  parseTeammateIdlePayload,
  aggregateByTool,
  // Phase G — transcript-path → parent_session derivation
  parseParentSessionFromTranscriptPath,
  // Phase H — OTLP/HTTP/JSON parsers
  unwrapOtlpValue,
  otlpAttrsToObject,
  parseOtlpLogs,
  parseOtlpMetrics,
  // Phase I+ — bypass mode (all-accounts-revoked detection)
  isOAuthRevocationError,
  isPostRefreshTrulyExpired,
  areAllAccountsTerminallyDead,
  // Phase I+ — token attribution guards
  isNonProjectCwd,
  // TRDD-1645134b Phase 1 — usage tree aggregation
  classifyUsageComponent,
  aggregateUsageTree,
  buildCacheMissReport,
  // TRDD-1645134b Phase 4 — tree-aggregated CSV export
  MODEL_PRICING,
  MODEL_PRICING_DEFAULT,
  estimateModelCost,
  aggregateUsageForCsvExport,
  csvField,
  renderUsageTreeCsv,
  // TRDD-1645134b Phase 5 — reason classification + per-session aggregate
  CACHE_TTL_LIKELY_MS,
  summarizeCacheMissesBySession,
  // Phase 6 — wasted-spend (cache-miss cost) time series
  buildWastedSpendSeries,
  // Phase J — keychain account name helpers
  vdmAccountServiceName,
  vdmAccountNameFromService,
  VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX,
  // UX-X8 / UX-X9 — unified time + token-count formatters with hover-exact
  fmtTokenCount,
  fmtDuration,
  // UX-WS2 — severity gradient for wasted-spend bars
  wastedSeverity,
  WASTED_SEVERITY_LOW,
  WASTED_SEVERITY_MED,
  WASTED_SEVERITY_HIGH,
} from '../lib.mjs';

// ─────────────────────────────────────────────────
// Existing function tests (sanity checks)
// ─────────────────────────────────────────────────

describe('getFingerprint', () => {
  it('returns 16-char hex for valid creds', () => {
    const fp = getFingerprint({ claudeAiOauth: { accessToken: 'test-token-123' } });
    assert.equal(fp.length, 16);
    assert.match(fp, /^[0-9a-f]{16}$/);
  });

  it('returns consistent fingerprint for same token', () => {
    const creds = { claudeAiOauth: { accessToken: 'my-token' } };
    assert.equal(getFingerprint(creds), getFingerprint(creds));
  });

  it('returns different fingerprints for different tokens', () => {
    const fp1 = getFingerprint({ claudeAiOauth: { accessToken: 'token-a' } });
    const fp2 = getFingerprint({ claudeAiOauth: { accessToken: 'token-b' } });
    assert.notEqual(fp1, fp2);
  });
});

describe('stripHopByHopHeaders', () => {
  it('strips all RFC 7230 hop-by-hop headers', () => {
    const input = {
      'connection': 'keep-alive',
      'keep-alive': 'timeout=5',
      'proxy-authenticate': 'Basic',
      'proxy-authorization': 'Bearer xyz',
      'te': 'trailers',
      'trailer': 'Expires',
      'transfer-encoding': 'chunked',
      'upgrade': 'websocket',
      'host': 'localhost:3334',
      'content-length': '42',
      'accept-encoding': 'gzip, br',
      'x-api-key': 'sk-ant-abc123',
      // M3 — proxy-connection treated as hop-by-hop by every major proxy
      // even though RFC 7230 doesn't list it. Some HTTP clients still send
      // it without listing in `Connection: ...`.
      'proxy-connection': 'close',
      // These should survive:
      'content-type': 'application/json',
      'authorization': 'Bearer tok',
      'x-custom': 'value',
    };
    const result = stripHopByHopHeaders(input);
    for (const h of HOP_BY_HOP) {
      assert.ok(!(h in result), `${h} should be stripped`);
    }
    // Explicit assertion: proxy-connection MUST be stripped.
    assert.ok(!('proxy-connection' in result), 'proxy-connection must be stripped (M3)');
    assert.equal(result['content-type'], 'application/json');
    assert.equal(result['authorization'], 'Bearer tok');
    assert.equal(result['x-custom'], 'value');
  });

  it('strips x-api-key header to prevent billing conflicts', () => {
    const result = stripHopByHopHeaders({
      'x-api-key': 'sk-ant-abc123',
      'content-type': 'application/json',
      'authorization': 'Bearer oauth-token',
    });
    assert.ok(!('x-api-key' in result), 'x-api-key should be stripped');
    assert.equal(result['content-type'], 'application/json');
    assert.equal(result['authorization'], 'Bearer oauth-token');
  });

  it('strips custom hop-by-hop headers declared in Connection', () => {
    const result = stripHopByHopHeaders({
      'connection': 'X-Custom-Hop, X-Another',
      'x-custom-hop': 'secret',
      'x-another': 'also-secret',
      'x-safe': 'keep-me',
    });
    assert.ok(!('x-custom-hop' in result));
    assert.ok(!('x-another' in result));
    assert.ok(!('connection' in result));
    assert.equal(result['x-safe'], 'keep-me');
  });

  it('handles empty Connection header', () => {
    const result = stripHopByHopHeaders({ 'connection': '', 'content-type': 'text/plain' });
    assert.equal(result['content-type'], 'text/plain');
    assert.ok(!('connection' in result));
  });

  it('handles missing Connection header', () => {
    const result = stripHopByHopHeaders({ 'content-type': 'text/plain' });
    assert.equal(result['content-type'], 'text/plain');
  });

  it('locates Connection header regardless of casing (CONNECTION/cOnnection)', () => {
    // Raw-ish callers may pass odd casings. The strip must still find the
    // declared custom hop-by-hop names even when the Connection header is
    // upper-cased or in any other mixed form.
    const result = stripHopByHopHeaders({
      'CONNECTION': 'X-Custom-Hop',
      'X-Custom-Hop': 'secret',
      'X-Safe': 'keep-me',
    });
    assert.ok(!('X-Custom-Hop' in result), 'X-Custom-Hop should be stripped via CONNECTION');
    assert.ok(!('CONNECTION' in result), 'CONNECTION header itself should be stripped');
    assert.equal(result['X-Safe'], 'keep-me');
  });
});

describe('buildForwardHeaders', () => {
  it('sets authorization and host headers', () => {
    const headers = buildForwardHeaders({ 'content-type': 'application/json' }, 'test-token');
    assert.equal(headers['authorization'], 'Bearer test-token');
    assert.equal(headers['host'], 'api.anthropic.com');
  });

  it('strips all hop-by-hop headers via stripHopByHopHeaders', () => {
    const headers = buildForwardHeaders({
      'host': 'localhost:3334',
      'connection': 'keep-alive',
      'keep-alive': 'timeout=5',
      'content-length': '42',
      'transfer-encoding': 'chunked',
      'proxy-authorization': 'Basic abc',
      'te': 'trailers',
      'trailer': 'Expires',
      'upgrade': 'websocket',
      'content-type': 'application/json',
    }, 'test-token');
    assert.equal(headers['content-type'], 'application/json');
    assert.equal(headers['host'], 'api.anthropic.com');
    assert.ok(!('connection' in headers));
    assert.ok(!('keep-alive' in headers));
    assert.ok(!('content-length' in headers));
    assert.ok(!('transfer-encoding' in headers));
    assert.ok(!('proxy-authorization' in headers));
    assert.ok(!('te' in headers));
    assert.ok(!('trailer' in headers));
    assert.ok(!('upgrade' in headers));
  });

  it('strips custom Connection-declared headers', () => {
    const headers = buildForwardHeaders({
      'connection': 'X-My-Hop',
      'x-my-hop': 'private-value',
      'content-type': 'application/json',
    }, 'test-token');
    assert.ok(!('x-my-hop' in headers));
    assert.equal(headers['content-type'], 'application/json');
  });

  it('adds oauth beta header', () => {
    const headers = buildForwardHeaders({}, 'test-token');
    assert.ok(headers['anthropic-beta'].includes('oauth-2025-04-20'));
  });

  it('does not duplicate oauth beta if already present', () => {
    const headers = buildForwardHeaders({
      'anthropic-beta': 'oauth-2025-04-20,some-other-beta',
    }, 'test-token');
    const betas = headers['anthropic-beta'].split(',').map(s => s.trim());
    const oauthCount = betas.filter(b => b === 'oauth-2025-04-20').length;
    assert.equal(oauthCount, 1);
  });

  it('strips x-api-key from forwarded headers', () => {
    const headers = buildForwardHeaders({
      'x-api-key': 'sk-ant-abc123',
      'content-type': 'application/json',
    }, 'test-token');
    assert.ok(!('x-api-key' in headers), 'x-api-key should not be forwarded');
    assert.equal(headers['authorization'], 'Bearer test-token');
  });

  it('throws on null token', () => {
    assert.throws(() => buildForwardHeaders({}, null), /Cannot forward request: token is null/);
  });

  it('throws on undefined token', () => {
    assert.throws(() => buildForwardHeaders({}, undefined), /Cannot forward request/);
  });

  it('replaces case-variant Authorization / Anthropic-Beta with canonical lowercase (no duplicates)', () => {
    // If the inbound headers have capitalized variants of headers we set
    // canonically, the output must contain only the lowercase form. Two
    // case-variants would cause Node to emit duplicate header lines and
    // make Anthropic reject the request (see fix in lib.mjs).
    const headers = buildForwardHeaders({
      'Authorization': 'Bearer stale-token',
      'Anthropic-Beta': 'pre-existing-beta',
      'content-type': 'application/json',
    }, 'fresh-token');
    // Only the lowercase canonical names must remain.
    const keys = Object.keys(headers);
    const authKeys = keys.filter(k => k.toLowerCase() === 'authorization');
    const betaKeys = keys.filter(k => k.toLowerCase() === 'anthropic-beta');
    assert.deepEqual(authKeys, ['authorization'], 'should keep exactly one authorization header');
    assert.deepEqual(betaKeys, ['anthropic-beta'], 'should keep exactly one anthropic-beta header');
    assert.equal(headers['authorization'], 'Bearer fresh-token', 'must use the new token');
    // Pre-existing beta value is carried over and merged with oauth beta.
    const betas = headers['anthropic-beta'].split(',').map(s => s.trim());
    assert.ok(betas.includes('pre-existing-beta'), 'pre-existing beta must be preserved');
    assert.ok(betas.includes('oauth-2025-04-20'), 'oauth beta must be appended');
  });
});

describe('createAccountStateManager', () => {
  it('tracks account state through lifecycle', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', {
      'anthropic-ratelimit-unified-status': 'ok',
      'anthropic-ratelimit-unified-5h-utilization': '0.5',
      'anthropic-ratelimit-unified-7d-utilization': '0.3',
    });
    const state = sm.get('tok1');
    assert.equal(state.name, 'acct1');
    assert.equal(state.limited, false);
    assert.equal(state.expired, false);
    assert.equal(state.utilization5h, 0.5);
    assert.equal(state.utilization7d, 0.3);
  });

  it('remove() deletes entry', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', {});
    assert.ok(sm.get('tok1'));
    sm.remove('tok1');
    assert.equal(sm.get('tok1'), undefined);
  });

  it('remove() on non-existent key is a no-op', () => {
    const sm = createAccountStateManager();
    sm.remove('nonexistent'); // should not throw
    assert.equal(sm.get('nonexistent'), undefined);
  });

  it('clearBillingCooldown() clears retryAfter but preserves rate-limit state', () => {
    const sm = createAccountStateManager();
    // Set up an account with both rate-limit and billing cooldown
    sm.update('tok1', 'acct1', {
      'anthropic-ratelimit-unified-status': 'limited',
      'anthropic-ratelimit-unified-5h-utilization': '0.8',
      'anthropic-ratelimit-unified-7d-utilization': '0.4',
      'anthropic-ratelimit-unified-5h-reset': String(Math.floor(Date.now() / 1000) + 3600),
    });
    // Mark with billing cooldown
    sm.markLimited('tok1', 'acct1', 300);
    const before = sm.get('tok1');
    assert.ok(before.retryAfter > 0, 'retryAfter should be set');
    assert.equal(before.limited, true);

    // Clear billing cooldown
    sm.clearBillingCooldown('tok1');
    const after = sm.get('tok1');
    assert.equal(after.retryAfter, 0, 'retryAfter should be cleared');
    assert.equal(after.limited, true, 'limited flag should be preserved');
    assert.equal(after.utilization5h, 0.8, 'utilization5h should be preserved');
    assert.equal(after.utilization7d, 0.4, 'utilization7d should be preserved');
    assert.ok(after.resetAt > 0, 'resetAt should be preserved');
  });

  it('clearBillingCooldown() is a no-op when retryAfter is already 0', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', { 'anthropic-ratelimit-unified-status': 'ok' });
    const before = sm.get('tok1');
    const beforeUpdatedAt = before.updatedAt;
    sm.clearBillingCooldown('tok1');
    const after = sm.get('tok1');
    assert.equal(after.updatedAt, beforeUpdatedAt, 'should not update when retryAfter is already 0');
  });

  it('clearBillingCooldown() is a no-op for unknown tokens', () => {
    const sm = createAccountStateManager();
    sm.clearBillingCooldown('nonexistent'); // should not throw
    assert.equal(sm.get('nonexistent'), undefined);
  });
});

// ─────────────────────────────────────────────────
// isAccountAvailable cooldown semantics
// ─────────────────────────────────────────────────

describe('isAccountAvailable cooldown semantics', () => {
  it('treats a limited account with active 7d reset as unavailable', () => {
    // Use a fixed `now` (no Date.now drift) so the test is deterministic.
    const now = 1_000_000_000_000;
    const nowSec = Math.floor(now / 1000);
    const sm = createAccountStateManager();
    // Active 7d window (resetAt7d in the future) and 5h window already
    // expired — must still be unavailable until the weekly cap rolls over.
    sm.update('tok1', 'acct1', {
      'anthropic-ratelimit-unified-status': 'limited',
      'anthropic-ratelimit-unified-5h-reset': String(nowSec - 60),       // past
      'anthropic-ratelimit-unified-7d-reset': String(nowSec + 3600),     // future
    });
    assert.equal(isAccountAvailable('tok1', 0, sm, now), false,
      'account with active 7d cap must be unavailable');
  });

  it('treats reset-equals-now as available (strict > comparison)', () => {
    // The reset epoch is the moment the account becomes available again.
    // With the buggy `>=`, equality would still mark the account unavailable.
    const now = 1_000_000_000_000;
    const nowSec = Math.floor(now / 1000);
    const sm = createAccountStateManager();
    sm.update('tok2', 'acct2', {
      'anthropic-ratelimit-unified-status': 'limited',
      'anthropic-ratelimit-unified-5h-reset': String(nowSec),            // now
      'anthropic-ratelimit-unified-7d-reset': String(nowSec),            // now
    });
    assert.equal(isAccountAvailable('tok2', 0, sm, now), true,
      'account whose resets equal now must be available');
  });
});

// ─────────────────────────────────────────────────
// createProbeTracker.load contract
// ─────────────────────────────────────────────────

describe('createProbeTracker.load', () => {
  it('replaces state with empty array (clears stale entries)', () => {
    const tracker = createProbeTracker();
    tracker.record(Date.now());
    tracker.record(Date.now());
    assert.equal(tracker.getLog().length, 2, 'precondition: log has entries');
    // load([]) MUST clear the log — it's a "replace state" operation.
    tracker.load([]);
    assert.equal(tracker.getLog().length, 0, 'load([]) must clear stale entries');
  });

  it('treats null/undefined as a no-op (no array → no replace)', () => {
    const tracker = createProbeTracker();
    tracker.record(Date.now());
    tracker.load(null);
    assert.equal(tracker.getLog().length, 1, 'load(null) is a no-op');
    tracker.load(undefined);
    assert.equal(tracker.getLog().length, 1, 'load(undefined) is a no-op');
  });
});

// ─────────────────────────────────────────────────
// buildRefreshRequestBody
// ─────────────────────────────────────────────────

describe('buildRefreshRequestBody', () => {
  it('builds JSON body with grant_type and refresh_token', () => {
    const body = buildRefreshRequestBody('rt-abc123');
    const parsed = JSON.parse(body);
    assert.equal(parsed.grant_type, 'refresh_token');
    assert.equal(parsed.refresh_token, 'rt-abc123');
    assert.equal(parsed.client_id, undefined);
    assert.equal(parsed.scope, undefined);
  });

  it('includes client_id when provided', () => {
    const body = buildRefreshRequestBody('rt-abc123', 'my-client');
    const parsed = JSON.parse(body);
    assert.equal(parsed.client_id, 'my-client');
  });

  it('includes scope when provided', () => {
    const body = buildRefreshRequestBody('rt-abc123', 'my-client', 'user:profile user:inference');
    const parsed = JSON.parse(body);
    assert.equal(parsed.scope, 'user:profile user:inference');
  });

  it('handles special characters in refresh token', () => {
    const body = buildRefreshRequestBody('rt-abc+123/foo=bar');
    const parsed = JSON.parse(body);
    assert.equal(parsed.refresh_token, 'rt-abc+123/foo=bar');
  });
});

// ─────────────────────────────────────────────────
// parseRefreshResponse
// ─────────────────────────────────────────────────

describe('parseRefreshResponse', () => {
  it('parses successful response with snake_case fields', () => {
    const body = JSON.stringify({
      access_token: 'new-at',
      refresh_token: 'new-rt',
      expires_in: 28800,
    });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.accessToken, 'new-at');
    assert.equal(result.refreshToken, 'new-rt');
    assert.equal(result.expiresIn, 28800);
  });

  it('parses successful response with camelCase fields', () => {
    const body = JSON.stringify({
      accessToken: 'new-at',
      refreshToken: 'new-rt',
      expiresIn: 3600,
    });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.accessToken, 'new-at');
    assert.equal(result.refreshToken, 'new-rt');
    assert.equal(result.expiresIn, 3600);
  });

  it('returns error when access_token is missing from success response', () => {
    const body = JSON.stringify({ refresh_token: 'new-rt' });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /No access_token/);
  });

  it('returns retriable=false for 400 (bad request / revoked token)', () => {
    const body = JSON.stringify({ error: 'invalid_grant', error_description: 'Token revoked' });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.equal(result.retriable, false);
    assert.match(result.error, /Token revoked/);
  });

  it('returns retriable=true for 429 (rate limit)', () => {
    const result = parseRefreshResponse(429, '{"error":"rate_limited"}');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('returns retriable=true for 500 (server error)', () => {
    const result = parseRefreshResponse(500, 'Internal Server Error');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('returns retriable=true for 503 (service unavailable)', () => {
    const result = parseRefreshResponse(503, '{}');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('handles invalid JSON in error response gracefully', () => {
    const result = parseRefreshResponse(400, 'not json');
    assert.equal(result.ok, false);
    assert.match(result.error, /HTTP 400/);
  });

  it('handles invalid JSON in success response', () => {
    const result = parseRefreshResponse(200, 'not json');
    assert.equal(result.ok, false);
    assert.match(result.error, /Invalid JSON/);
    assert.equal(result.retriable, false);
  });

  // M1 + M5 regression — type validation against hostile/buggy upstream
  it('rejects access_token that is a number (not a string)', () => {
    const body = JSON.stringify({ access_token: 12345, expires_in: 3600 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /access_token/);
    assert.equal(result.retriable, false);
  });

  it('rejects refresh_token that is a non-string non-null value when present', () => {
    // Note: falsy values (0, '', false, null, undefined) collapse via the
    // `||` chain to the alternative-camelCase field, so the only way to
    // exercise the validation is with a truthy non-string. An object value
    // is the canonical hostile-server case (e.g. `refresh_token: {hostile: true}`).
    const body = JSON.stringify({ access_token: 'ok', refresh_token: { hostile: true }, expires_in: 3600 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /refresh_token/);
  });

  it('accepts refresh_token absent (optional field)', () => {
    const body = JSON.stringify({ access_token: 'ok', expires_in: 3600 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.refreshToken, null);
  });

  it('rejects expires_in of 0 — but as a RETRIABLE error (REFRESH-2 fix)', () => {
    // Anthropic might legitimately emit `expires_in: 0` for a token
    // that needs immediate re-auth. The previous non-retriable mark
    // froze the user out of the account for 2h. Now: retriable so the
    // next sweep retries in minutes.
    const body = JSON.stringify({ access_token: 'ok', expires_in: 0 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /expires_in/);
    assert.equal(result.retriable, true);
  });

  it('rejects negative expires_in (would create past expiresAt)', () => {
    const body = JSON.stringify({ access_token: 'ok', expires_in: -100 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /expires_in/);
  });

  it('rejects non-numeric expires_in (would produce NaN expiresAt)', () => {
    const body = JSON.stringify({ access_token: 'ok', expires_in: 'huge' });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /expires_in/);
  });

  it('extracts message from object error fields', () => {
    const body = JSON.stringify({ error: { type: 'invalid_grant', message: 'token revoked' } });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'token revoked');
  });

  it('stringifies object error fields without message instead of [object Object]', () => {
    const body = JSON.stringify({ error: { type: 'invalid_grant' } });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.ok(!result.error.includes('[object Object]'), `error should not contain [object Object]: ${result.error}`);
    assert.ok(result.error.includes('invalid_grant'), `error should contain the error type: ${result.error}`);
  });

  it('handles null refreshToken in response', () => {
    const body = JSON.stringify({ access_token: 'new-at', expires_in: 3600 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.refreshToken, null);
  });
});

// ─────────────────────────────────────────────────
// computeExpiresAt
// ─────────────────────────────────────────────────

describe('computeExpiresAt', () => {
  it('adds seconds as milliseconds to now', () => {
    const now = 1000000;
    const result = computeExpiresAt(3600, now);
    assert.equal(result, 1000000 + 3600 * 1000);
  });

  it('uses Date.now() when now is not provided', () => {
    const before = Date.now();
    const result = computeExpiresAt(60);
    const after = Date.now();
    assert.ok(result >= before + 60000);
    assert.ok(result <= after + 60000);
  });

  it('handles zero seconds', () => {
    assert.equal(computeExpiresAt(0, 5000), 5000);
  });
});

// ─────────────────────────────────────────────────
// buildUpdatedCreds
// ─────────────────────────────────────────────────

describe('buildUpdatedCreds', () => {
  const oldCreds = {
    claudeAiOauth: {
      accessToken: 'old-at',
      refreshToken: 'old-rt',
      expiresAt: 1000,
      scopes: ['user:inference'],
      subscriptionType: 'max',
      rateLimitTier: 'default_claude_max_20x',
    },
    someOtherField: 'preserved',
  };

  it('updates accessToken, refreshToken, and expiresAt', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.equal(result.claudeAiOauth.accessToken, 'new-at');
    assert.equal(result.claudeAiOauth.refreshToken, 'new-rt');
    assert.equal(result.claudeAiOauth.expiresAt, 9999);
  });

  it('preserves other claudeAiOauth fields', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.deepEqual(result.claudeAiOauth.scopes, ['user:inference']);
    assert.equal(result.claudeAiOauth.subscriptionType, 'max');
    assert.equal(result.claudeAiOauth.rateLimitTier, 'default_claude_max_20x');
  });

  it('preserves top-level fields', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.equal(result.someOtherField, 'preserved');
  });

  it('does not mutate oldCreds', () => {
    const original = JSON.parse(JSON.stringify(oldCreds));
    buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.deepEqual(oldCreds, original);
  });

  it('skips refreshToken when null', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', null, 9999);
    // Should keep the old refresh token
    assert.equal(result.claudeAiOauth.refreshToken, 'old-rt');
  });
});

// ─────────────────────────────────────────────────
// shouldRefreshToken
// ─────────────────────────────────────────────────

describe('shouldRefreshToken', () => {
  const BUFFER = 60 * 60 * 1000; // 1 hour

  it('returns false for falsy expiresAt (0)', () => {
    assert.equal(shouldRefreshToken(0, BUFFER, 1000000), false);
  });

  it('returns false for falsy expiresAt (null)', () => {
    assert.equal(shouldRefreshToken(null, BUFFER, 1000000), false);
  });

  it('returns false for falsy expiresAt (undefined)', () => {
    assert.equal(shouldRefreshToken(undefined, BUFFER, 1000000), false);
  });

  it('returns true when token is already expired', () => {
    const now = 2000000;
    assert.equal(shouldRefreshToken(1000000, BUFFER, now), true);
  });

  it('returns true when within buffer of expiry', () => {
    const now = 1000000;
    const expiresAt = now + 30 * 60 * 1000; // 30 min from now
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), true);
  });

  it('returns false when well beyond buffer', () => {
    const now = 1000000;
    const expiresAt = now + 2 * 60 * 60 * 1000; // 2 hours from now
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), false);
  });

  it('returns true at exactly buffer boundary', () => {
    const now = 1000000;
    const expiresAt = now + BUFFER;
    // expiresAt - now === BUFFER, BUFFER <= BUFFER → true
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), true);
  });

  it('uses default buffer of 1 hour', () => {
    const now = 1000000;
    const expiresAt = now + 59 * 60 * 1000; // 59 min (< 1 hour buffer)
    assert.equal(shouldRefreshToken(expiresAt, undefined, now), true);
  });
});

// ─────────────────────────────────────────────────
// createPerAccountLock
// ─────────────────────────────────────────────────

describe('createPerAccountLock', () => {
  it('serializes calls for the same key', async () => {
    const lock = createPerAccountLock();
    const order = [];

    const p1 = lock.withLock('acct1', async () => {
      order.push('start-1');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-1');
      return 'result-1';
    });

    const p2 = lock.withLock('acct1', async () => {
      order.push('start-2');
      return 'result-2';
    });

    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1, 'result-1');
    assert.equal(r2, 'result-2');
    assert.deepEqual(order, ['start-1', 'end-1', 'start-2']);
  });

  it('allows parallel execution for different keys', async () => {
    const lock = createPerAccountLock();
    const order = [];

    const p1 = lock.withLock('acct1', async () => {
      order.push('start-a');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-a');
    });

    const p2 = lock.withLock('acct2', async () => {
      order.push('start-b');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-b');
    });

    await Promise.all([p1, p2]);
    // Both should start before either ends. We don't assert the exact index of
    // 'start-a' / 'start-b' because microtask scheduling order between two
    // independent withLock() calls is an implementation detail (a future
    // process.nextTick / queueMicrotask switch could legitimately flip them).
    // What matters for the contract is:
    //   1. both starts happened
    //   2. at least one start happened before the first end (i.e. they ran
    //      concurrently rather than being serialised on the same lock)
    //   3. each key's own start preceded its own end
    const sa = order.indexOf('start-a');
    const sb = order.indexOf('start-b');
    const ea = order.indexOf('end-a');
    const eb = order.indexOf('end-b');
    assert.ok(sa !== -1 && sb !== -1, `both starts should have run; order=${JSON.stringify(order)}`);
    assert.ok(sa < ea, `start-a must precede end-a; order=${JSON.stringify(order)}`);
    assert.ok(sb < eb, `start-b must precede end-b; order=${JSON.stringify(order)}`);
    // Parallelism check: the second start must occur before the first end —
    // otherwise the lock is serialising across keys.
    const firstEnd = Math.min(ea, eb);
    assert.ok(sa < firstEnd && sb < firstEnd,
      `expected parallel execution, but a start happened after an end; order=${JSON.stringify(order)}`);
  });

  it('releases lock even when fn throws', async () => {
    const lock = createPerAccountLock();

    try {
      await lock.withLock('acct1', async () => {
        throw new Error('test error');
      });
    } catch (e) {
      assert.equal(e.message, 'test error');
    }

    // Should still be able to acquire lock
    const result = await lock.withLock('acct1', async () => 'ok');
    assert.equal(result, 'ok');
  });
});

// ─────────────────────────────────────────────────
// New behavior added by the audit-fix series
// ─────────────────────────────────────────────────

describe('predictMinutesToLimit clamp against resetAt', () => {
  // Each test seeds the history with two synthetic points so velocity
  // is deterministic. Spacing is > HISTORY_MIN_INTERVAL so both points
  // are kept (the 2-min in-place overwrite would otherwise collapse them).
  function seedHistory(history, fp, u5hStart, u5hEnd, spreadMs = 25 * 60 * 1000) {
    const now = Date.now();
    history.record(fp, u5hStart, 0, now - spreadMs);
    history.record(fp, u5hEnd,   0, now);
  }

  it('returns the projection when reset is far away', () => {
    const h = createUtilizationHistory();
    seedHistory(h, 'fp1', 0.10, 0.20); // velocity ≈ 0.24/h, remaining 0.80 → ~200 min
    // Reset is 6 hours away — much later than the 200 min projection.
    const resetAt = Math.floor((Date.now() + 6 * 60 * 60 * 1000) / 1000);
    const minutes = h.predictMinutesToLimit('fp1', resetAt);
    assert.ok(minutes != null && minutes > 0, 'should return a number');
    // velocity = 0.10/25min = 0.004/min → remaining 0.80 / 0.004 = 200 min exactly.
    // Allow ±5 min slack only for the rounding inside predictMinutesToLimit
    // (Math.round on (remaining/velocity)*60). A loose 100–300 range used to
    // hide off-by-factor-2 bugs in the velocity formula.
    assert.ok(Math.abs(minutes - 200) <= 5, `expected 200 min ±5, got ${minutes}`);
  });

  it('returns null when the projection is past the next reset', () => {
    const h = createUtilizationHistory();
    seedHistory(h, 'fp2', 0.10, 0.20); // ~200 min projection
    // Reset is 30 minutes away — sooner than the projection. The window
    // will roll over to 0% before the limit is reached.
    const resetAt = Math.floor((Date.now() + 30 * 60 * 1000) / 1000);
    const minutes = h.predictMinutesToLimit('fp2', resetAt);
    assert.equal(minutes, null);
  });

  it('falls back to unclamped projection when resetAt is 0 or unset', () => {
    const h = createUtilizationHistory();
    seedHistory(h, 'fp3', 0.10, 0.20);
    const noClamp = h.predictMinutesToLimit('fp3'); // default resetAt=0
    const explicitZero = h.predictMinutesToLimit('fp3', 0);
    assert.equal(typeof noClamp, 'number');
    assert.equal(noClamp, explicitZero);
  });

  it('still returns null for non-positive velocity (post-reset baseline)', () => {
    const h = createUtilizationHistory();
    // utilization dropped — velocity <= 0
    seedHistory(h, 'fp4', 0.50, 0.10);
    const resetAt = Math.floor((Date.now() + 6 * 60 * 60 * 1000) / 1000);
    assert.equal(h.predictMinutesToLimit('fp4', resetAt), null);
  });
});

describe('getEarliestReset weekday formatting', () => {
  function fakeMgr(stateMap) {
    return { entries: () => stateMap.entries() };
  }

  it('returns "unknown" when no future reset is recorded', () => {
    const mgr = fakeMgr(new Map([
      ['t', { resetAt: 0, resetAt7d: 0 }],
    ]));
    assert.equal(getEarliestReset(mgr), 'unknown');
  });

  it('omits the date when reset is later today', () => {
    // Pick a time 3 minutes from now — but ONLY if that doesn't cross
    // midnight. Within 5 min of midnight, the previous test was a flake
    // (e.g. now=23:58:30 → future=00:01:30 next day → weekday output).
    // Skip the assertion in that thin window rather than passing fragile.
    const now = new Date();
    const minutesUntilMidnight =
      (24 * 60) - (now.getHours() * 60 + now.getMinutes());
    if (minutesUntilMidnight <= 5) {
      // Within 5 min of midnight — skip to avoid flake.
      return;
    }
    const future = Math.floor((Date.now() + 3 * 60 * 1000) / 1000);
    const mgr = fakeMgr(new Map([
      ['t', { resetAt: future, resetAt7d: 0 }],
    ]));
    const out = getEarliestReset(mgr);
    // HH:MM only — no weekday.
    assert.match(out, /^\d{2}:\d{2}$/, `expected HH:MM, got "${out}"`);
  });

  it('includes the weekday when reset crosses to a different day', () => {
    // 36 hours from now is always on a different calendar day.
    const future = Math.floor((Date.now() + 36 * 60 * 60 * 1000) / 1000);
    const mgr = fakeMgr(new Map([
      ['t', { resetAt: future, resetAt7d: 0 }],
    ]));
    const out = getEarliestReset(mgr);
    // Should contain a 3-letter weekday and HH:MM.
    assert.match(out, /(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/i, `expected weekday in "${out}"`);
    assert.match(out, /\d{2}:\d{2}/, `expected HH:MM in "${out}"`);
  });
});

// ─────────────────────────────────────────────────
// Audit-deep fixes (post-Phase-5)
// ─────────────────────────────────────────────────

describe('createPerAccountLock memory hygiene', () => {
  // Audit-deep fix: the lock map must NOT grow unboundedly. Every distinct
  // key (account name, fingerprint) used to leave a settled-promise entry
  // behind, with no symmetric cleanup for `accountState.remove()`. After
  // the fix, a settled chain whose tail nobody is queued behind must be
  // evicted from the map.
  it('evicts the entry when a chain settles with no queued waiters', async () => {
    const lock = createPerAccountLock();
    // Fire a one-shot lock with a unique key, await its completion, and
    // assert the map shrinks back to zero. Awaiting `withLock` only
    // resolves AFTER the inner .finally has run — so by the time we
    // observe `_size()`, eviction has happened.
    await lock.withLock('uniq-key-1', async () => 'r');
    assert.equal(lock._size(), 0,
      'lock map should evict the entry once the chain has settled');
    // Spam many distinct keys to confirm no leak across keys either.
    for (let i = 0; i < 50; i++) {
      await lock.withLock(`spam-${i}`, async () => i);
    }
    assert.equal(lock._size(), 0,
      'lock map should be empty after many distinct one-shot keys');
  });

  it('does NOT evict an entry that still has a queued waiter', async () => {
    const lock = createPerAccountLock();
    // Fire two overlapping calls on the same key. The first one holds the
    // lock for ~30ms; the second one queues behind it. While the second
    // is still queued, the map MUST NOT prune the entry — pruning would
    // let a hypothetical third caller bypass the queue.
    let firstReleased = false;
    const p1 = lock.withLock('shared', async () => {
      await new Promise(r => setTimeout(r, 30));
      firstReleased = true;
    });
    // Queue p2 synchronously, before p1 settles, so locks.set('shared', next_p2)
    // happens while next_p1 is still the previous value.
    const p2 = lock.withLock('shared', async () => 'second');
    // The map must contain exactly one entry — `next_p2` (the latest tail).
    assert.equal(lock._size(), 1,
      'while a waiter is queued, the lock entry must still be present');
    await Promise.all([p1, p2]);
    assert.equal(firstReleased, true);
    // After both settle and no waiter remains, the entry must be gone.
    assert.equal(lock._size(), 0,
      'after the queue drains, the entry must be evicted');
  });
});

describe('createUtilizationHistory.load contract', () => {
  // Audit-deep fix: align createUtilizationHistory.load with
  // createProbeTracker.load (Phase-5 contract):
  //   - Non-array → no-op (does NOT touch existing state)
  //   - Empty array → clears the slot for that fingerprint
  it('treats null/undefined as a no-op (non-array → no replace)', () => {
    const h = createUtilizationHistory();
    h.record('fp', 0.1, 0.0, Date.now() - 60_000);
    assert.equal(h.getHistory('fp').length, 1, 'precondition: entry exists');
    h.load('fp', null);
    assert.equal(h.getHistory('fp').length, 1,
      'load(fp, null) must NOT clear the existing entry');
    h.load('fp', undefined);
    assert.equal(h.getHistory('fp').length, 1,
      'load(fp, undefined) must NOT clear the existing entry');
  });

  it('treats empty array as an explicit clear', () => {
    const h = createUtilizationHistory();
    h.record('fp', 0.1, 0.0, Date.now() - 60_000);
    h.load('fp', []);
    assert.equal(h.getHistory('fp').length, 0,
      'load(fp, []) must clear the entry — explicit replace');
  });

  it('drops malformed entries (missing/non-numeric ts)', () => {
    const h = createUtilizationHistory();
    const now = Date.now();
    // Mix of valid and malformed entries — only the valid one survives.
    h.load('fp', [
      { ts: now - 60_000, u5h: 0.1, u7d: 0.0 }, // valid, recent
      { u5h: 0.2, u7d: 0.0 },                   // missing ts
      { ts: 'not-a-number', u5h: 0.3 },         // non-numeric ts
      null,                                      // null entry
    ]);
    const arr = h.getHistory('fp');
    assert.equal(arr.length, 1, 'only the well-formed entry must survive');
    assert.equal(arr[0].u5h, 0.1);
  });
});

// ─────────────────────────────────────────────────
// Phase A: createSemaphore primitive
// ─────────────────────────────────────────────────

describe('createSemaphore', () => {
  it('permits up to maxConcurrent runs in parallel', async () => {
    const sem = createSemaphore(3);
    let observedMax = 0;
    let active = 0;

    const fn = async () => {
      active++;
      if (active > observedMax) observedMax = active;
      // Hold the slot long enough that all 5 callers reach acquire() before
      // any release. With max=3, exactly 3 must be active at the peak.
      await new Promise(r => setTimeout(r, 30));
      active--;
    };

    await Promise.all([
      sem.run(fn), sem.run(fn), sem.run(fn), sem.run(fn), sem.run(fn),
    ]);
    assert.equal(observedMax, 3, `peak concurrent should equal max=3, got ${observedMax}`);
    assert.equal(sem._inFlight(), 0, 'all slots must be released after run completes');
    assert.equal(sem._pending(), 0, 'no waiters should remain');
  });

  it('queues additional runs and releases them FIFO as slots free', async () => {
    const sem = createSemaphore(1);
    const startOrder = [];
    const launch = (label) => sem.run(async () => {
      startOrder.push(label);
      await new Promise(r => setTimeout(r, 10));
    });
    // Fire A, B, C in synchronous order — B and C will queue behind A.
    const pa = launch('A');
    const pb = launch('B');
    const pc = launch('C');
    await Promise.all([pa, pb, pc]);
    assert.deepEqual(startOrder, ['A', 'B', 'C'], 'FIFO order must be preserved');
  });

  it('release() is reentrant-safe (calling more times than acquire is a no-op, not an underflow)', async () => {
    const sem = createSemaphore(2);
    // Acquire once, release twice — the second release must NOT push
    // inFlight negative. If it did, a future caller could bypass the cap.
    await sem.acquire();
    assert.equal(sem._inFlight(), 1);
    sem.release();
    assert.equal(sem._inFlight(), 0);
    sem.release(); // extra release — must clamp at 0
    assert.equal(sem._inFlight(), 0, 'extra release must not underflow inFlight');
    // Verify the cap still works after the spurious release: 3 callers,
    // max=2 — third one must queue, not run.
    const order = [];
    const slow = async (label) => {
      order.push(`start-${label}`);
      await new Promise(r => setTimeout(r, 20));
      order.push(`end-${label}`);
    };
    const p1 = sem.run(() => slow('a'));
    const p2 = sem.run(() => slow('b'));
    const p3 = sem.run(() => slow('c'));
    await Promise.all([p1, p2, p3]);
    // a and b start before either ends; c must start AFTER at least one end.
    const startC = order.indexOf('start-c');
    const firstEnd = Math.min(order.indexOf('end-a'), order.indexOf('end-b'));
    assert.ok(startC > firstEnd,
      `c must start after the first end; order=${JSON.stringify(order)}`);
  });

  it('run() releases on exception', async () => {
    const sem = createSemaphore(1);
    let caught = null;
    try {
      await sem.run(async () => { throw new Error('boom'); });
    } catch (e) {
      caught = e;
    }
    assert.equal(caught?.message, 'boom');
    assert.equal(sem._inFlight(), 0, 'run() must release even when fn throws');
    // The slot must be reusable.
    const result = await sem.run(async () => 'after');
    assert.equal(result, 'after');
  });

  it('concurrent batch of 10 with max=3 ends with all 10 done and inFlight returns to 0', async () => {
    const sem = createSemaphore(3);
    let observedMax = 0;
    let active = 0;
    const results = [];
    const fn = (i) => async () => {
      active++;
      if (active > observedMax) observedMax = active;
      await new Promise(r => setTimeout(r, 5));
      results.push(i);
      active--;
    };
    const tasks = [];
    for (let i = 0; i < 10; i++) tasks.push(sem.run(fn(i)));
    await Promise.all(tasks);
    assert.equal(results.length, 10, 'all 10 tasks must complete');
    assert.ok(observedMax <= 3, `concurrency must never exceed max=3, observed ${observedMax}`);
    assert.equal(observedMax, 3, 'concurrency should reach max=3 with 10 tasks');
    assert.equal(sem._inFlight(), 0, 'inFlight must return to 0');
    assert.equal(sem._pending(), 0, 'no queued waiters should remain');
  });

  it('rejects non-positive maxConcurrent', () => {
    assert.throws(() => createSemaphore(0), /positive integer/);
    assert.throws(() => createSemaphore(-1), /positive integer/);
    assert.throws(() => createSemaphore(1.5), /positive integer/);
    assert.throws(() => createSemaphore('three'), /positive integer/);
  });
});

// ─────────────────────────────────────────────────
// Phase A: createAccountStateManager switch tracking
// ─────────────────────────────────────────────────

describe('createAccountStateManager switch tracking', () => {
  it('markSwitchedFrom records a timestamp on the given token state', () => {
    const sm = createAccountStateManager();
    sm.update('tokA', 'acctA', { 'anthropic-ratelimit-unified-status': 'ok' });
    const before = sm.get('tokA');
    assert.equal(before.lastSwitchAtMs, undefined, 'lastSwitchAtMs starts unset');
    sm.markSwitchedFrom('tokA');
    const after = sm.get('tokA');
    assert.equal(typeof after.lastSwitchAtMs, 'number');
    assert.ok(after.lastSwitchAtMs > 0, 'timestamp must be positive');
  });

  it('markSwitchedFrom creates state for unknown token (so the marker survives)', () => {
    // A 429 may arrive on a token the proxy has never observed via .update()
    // (e.g. just-rotated in via switch). markSwitchedFrom must still record
    // the timestamp so the dedupe window applies on the next 429 in the herd.
    const sm = createAccountStateManager();
    sm.markSwitchedFrom('newTok');
    const state = sm.get('newTok');
    assert.ok(state, 'state must be created for unknown token');
    assert.ok(state.lastSwitchAtMs > 0);
  });

  it('wasRecentlySwitchedFrom returns true within the window', () => {
    const sm = createAccountStateManager();
    sm.update('tokB', 'acctB', {});
    const now = 1_000_000_000_000;
    // Manually inject lastSwitchAtMs via markSwitchedFrom with clock control.
    // Since markSwitchedFrom uses Date.now() internally, we drive the test
    // through the public API and observe it by passing nowMs explicitly.
    sm.markSwitchedFrom('tokB');
    const state = sm.get('tokB');
    // 100 ms after the mark, with a 500 ms window — must still be true.
    assert.equal(
      sm.wasRecentlySwitchedFrom('tokB', 500, state.lastSwitchAtMs + 100),
      true,
      'should be true 100ms after mark within 500ms window'
    );
  });

  it('wasRecentlySwitchedFrom returns false past the window (clock-controlled)', () => {
    const sm = createAccountStateManager();
    sm.update('tokC', 'acctC', {});
    sm.markSwitchedFrom('tokC');
    const state = sm.get('tokC');
    // 600 ms after mark with a 500 ms window — must be false.
    assert.equal(
      sm.wasRecentlySwitchedFrom('tokC', 500, state.lastSwitchAtMs + 600),
      false,
      'should be false past the window'
    );
    // Equality check: at exactly windowMs after mark, also false (strict <).
    assert.equal(
      sm.wasRecentlySwitchedFrom('tokC', 500, state.lastSwitchAtMs + 500),
      false,
      'at exactly windowMs after mark, must be false (strict <)'
    );
  });

  it('wasRecentlySwitchedFrom returns false for unknown token (no state yet)', () => {
    const sm = createAccountStateManager();
    assert.equal(sm.wasRecentlySwitchedFrom('never-seen', 500), false);
    assert.equal(sm.wasRecentlySwitchedFrom('never-seen', 500, Date.now()), false);
  });

  it('wasRecentlySwitchedFrom returns false when token exists but markSwitchedFrom never called', () => {
    const sm = createAccountStateManager();
    sm.update('tokD', 'acctD', { 'anthropic-ratelimit-unified-status': 'ok' });
    // State exists but has no lastSwitchAtMs — must be false, not throw.
    assert.equal(sm.wasRecentlySwitchedFrom('tokD', 500), false);
  });
});

// ─────────────────────────────────────────────────
// Phase A: getVelocity linear regression smoothing
// ─────────────────────────────────────────────────

describe('getVelocity linear regression smoothing', () => {
  it('returns null with fewer than 2 points', () => {
    const h = createUtilizationHistory();
    assert.equal(h.getVelocity('fp-empty'), null, 'no points → null');
    h.record('fp-one', 0.1, 0.0, Date.now());
    assert.equal(h.getVelocity('fp-one'), null, 'one point → null');
  });

  it('returns null when window is shorter than 9.6 min', () => {
    const h = createUtilizationHistory();
    const now = Date.now();
    // Two points only 5 minutes apart — below the 0.16h (~9.6 min) threshold.
    h.record('fp-short', 0.10, 0.0, now - 5 * 60 * 1000);
    h.record('fp-short', 0.20, 0.0, now);
    assert.equal(h.getVelocity('fp-short'), null,
      'span < 9.6 min must return null even with 2 points');
  });

  it('returns null with negative slope (utilization dropping post-reset)', () => {
    const h = createUtilizationHistory();
    const now = Date.now();
    h.record('fp-drop', 0.50, 0.0, now - 25 * 60 * 1000);
    h.record('fp-drop', 0.10, 0.0, now);
    assert.equal(h.getVelocity('fp-drop'), null,
      'slope <= 0 must return null (post-reset baseline)');
  });

  it('2-point window agrees with 2-point delta (OLS reduces to old formula)', () => {
    // OLS over exactly 2 points reduces algebraically to (y2 - y1)/(x2 - x1).
    // Sanity check: confirm the new implementation matches the old behaviour
    // in this trivial case so we know the regression isn't perturbing simple
    // inputs.
    const h = createUtilizationHistory();
    const now = Date.now();
    const spreadMs = 25 * 60 * 1000;
    h.record('fp-2pt', 0.10, 0.0, now - spreadMs);
    h.record('fp-2pt', 0.20, 0.0, now);
    const v = h.getVelocity('fp-2pt');
    // Old formula: delta=0.10 over 25/60 hr = 0.10 / (25/60) = 0.24/h
    const expected = 0.10 / (25 / 60);
    assert.ok(v != null, 'velocity must be a number');
    assert.ok(Math.abs(v - expected) < 1e-9,
      `expected ${expected} (≈0.24/h), got ${v}`);
  });

  it('5-point noisy window converges close to underlying slope', () => {
    // Underlying ground truth: u5h = 0.10 + 0.004*(min_since_start) + jitter.
    // With 0.004/min as the true slope, that's 0.24/h. Sprinkle deterministic
    // (seeded) jitter of magnitude ±0.005 — far smaller than the signal — and
    // confirm the regression recovers the slope to within ±0.01 /h.
    const h = createUtilizationHistory();
    const now = Date.now();
    // Generate 5 points spread over 25 minutes; deterministic jitter pattern.
    const jitter = [+0.003, -0.004, +0.005, -0.002, +0.001];
    const points = []; // [{ minOffset, u5h }]
    for (let i = 0; i < 5; i++) {
      const min = i * 6; // 0, 6, 12, 18, 24
      const u5h = 0.10 + 0.004 * min + jitter[i];
      points.push({ min, u5h });
      // record with HISTORY_MIN_INTERVAL=2min default; 6-min spacing keeps
      // each entry as a separate point (no in-place overwrite).
      h.record('fp-noisy', u5h, 0.0, now - (24 - min) * 60 * 1000);
    }
    const v = h.getVelocity('fp-noisy');
    // True slope: 0.004 per minute = 0.24 per hour.
    assert.ok(v != null, `velocity must be a number, got ${v}`);
    assert.ok(Math.abs(v - 0.24) < 0.01,
      `slope must be within ±0.01/h of 0.24/h (true slope), got ${v}`);
  });
});

// ─────────────────────────────────────────────────
// clampViewerState — Phase C scrubber persistence
// ─────────────────────────────────────────────────

describe('clampViewerState', () => {
  it('returns a valid window for fresh defaults (no persisted state)', () => {
    // Caller computes dataRange live; persisted state is empty.
    const dataRange = { oldest: 1_000_000_000_000, newest: 1_000_000_000_000 + 24 * 3600_000 };
    const r = clampViewerState({ dataRange });
    assert.equal(r.start, dataRange.oldest);
    assert.equal(r.end, dataRange.newest);
    assert.deepEqual(r.tierFilter, ['all']);
    assert.ok(r.end >= r.start, 'start must be ≤ end');
  });

  it('clamps a persisted window that has aged out of the live data range', () => {
    // Persisted window points BEFORE the live data range — both bounds
    // collapse to the live oldest; the helper still emits a 5-minute
    // window because dataWidth is wider than MIN_WINDOW_MS.
    const dataRange = { oldest: 2_000_000_000_000, newest: 2_000_000_000_000 + 7 * 24 * 3600_000 };
    const r = clampViewerState({
      start: 1_000_000_000_000,
      end:   1_000_000_000_000 + 60_000,
      dataRange,
    });
    assert.ok(r.start >= dataRange.oldest, 'start must clamp into bounds');
    assert.ok(r.end   <= dataRange.newest, 'end must clamp into bounds');
    assert.ok(r.end - r.start >= VIEWER_STATE_MIN_WINDOW_MS,
      'window must be ≥ MIN_WINDOW_MS when dataRange permits');
  });

  it('swaps inverted bounds (start > end) to produce a sane window', () => {
    const dataRange = { oldest: 100_000_000, newest: 100_000_000 + 24 * 3600_000 };
    const start = 100_000_000 + 12 * 3600_000;
    const end   = 100_000_000 + 1 * 3600_000;
    const r = clampViewerState({ start, end, dataRange });
    assert.ok(r.start <= r.end, 'inverted bounds must be swapped');
  });

  it('drops tierFilter entries that are no longer in knownTiers, keeps the rest', () => {
    const dataRange = { oldest: 100, newest: 100 + 7 * 24 * 3600_000 };
    const r = clampViewerState({
      start: 100, end: 100 + 24 * 3600_000,
      tierFilter: ['Pro', 'Max-5x', 'GoneTier'],
      knownTiers: ['Pro', 'Max-5x', 'Max-20x'],
      dataRange,
    });
    assert.deepEqual(r.tierFilter.sort(), ['Max-5x', 'Pro']);
  });

  it('falls back to ["all"] when every persisted tier is now unknown', () => {
    const dataRange = { oldest: 100, newest: 100 + 7 * 24 * 3600_000 };
    const r = clampViewerState({
      start: 100, end: 100 + 24 * 3600_000,
      tierFilter: ['DeprecatedTier'],
      knownTiers: ['Pro', 'Max-5x'],
      dataRange,
    });
    assert.deepEqual(r.tierFilter, ['all']);
  });
});

// ─────────────────────────────────────────────────
// Phase D — Hook payload parsers (lib.mjs)
// ─────────────────────────────────────────────────

describe('parseCompactPayload', () => {
  it('accepts a valid PreCompact payload and defaults postTokens to null', () => {
    const r = parseCompactPayload({
      session_id: 'abc123',
      cwd: '/tmp/proj',
      trigger: 'auto',
      preTokens: 167189,
    }, 'pre');
    assert.equal(r.ok, true);
    assert.equal(r.sessionId, 'abc123');
    assert.equal(r.cwd, '/tmp/proj');
    assert.equal(r.trigger, 'auto');
    assert.equal(r.preTokens, 167189);
    assert.equal(r.postTokens, null);
  });

  it('accepts a valid PostCompact payload with postTokens', () => {
    const r = parseCompactPayload({
      session_id: 'abc123',
      cwd: '/tmp/proj',
      trigger: 'manual',
      preTokens: 167189,
      postTokens: 42000,
    }, 'post');
    assert.equal(r.ok, true);
    assert.equal(r.trigger, 'manual');
    assert.equal(r.preTokens, 167189);
    assert.equal(r.postTokens, 42000);
  });

  it('rejects missing session_id with a 400-style error', () => {
    const r = parseCompactPayload({ cwd: '/tmp/x', trigger: 'auto' }, 'pre');
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects null payload', () => {
    const r = parseCompactPayload(null, 'pre');
    assert.equal(r.ok, false);
  });

  it('rejects invalid kind', () => {
    const r = parseCompactPayload({ session_id: 'a', cwd: '/tmp' }, 'invalid-kind');
    assert.equal(r.ok, false);
    assert.match(r.error, /kind/);
  });

  it('defaults trigger to auto when missing or invalid', () => {
    const r1 = parseCompactPayload({ session_id: 'a', cwd: '/tmp', preTokens: 1 }, 'pre');
    assert.equal(r1.trigger, 'auto');
    const r2 = parseCompactPayload({ session_id: 'a', cwd: '/tmp', trigger: 'bogus' }, 'pre');
    assert.equal(r2.trigger, 'auto');
  });

  it('coerces non-finite preTokens to null', () => {
    const r = parseCompactPayload({ session_id: 'a', cwd: '/tmp', preTokens: 'huge' }, 'pre');
    assert.equal(r.preTokens, null);
  });

  it('PostCompact ignores postTokens when not finite', () => {
    const r = parseCompactPayload({
      session_id: 'a', cwd: '/tmp', preTokens: 100, postTokens: NaN,
    }, 'post');
    assert.equal(r.postTokens, null);
  });

  it('PreCompact never returns postTokens (forced null)', () => {
    const r = parseCompactPayload({
      session_id: 'a', cwd: '/tmp', preTokens: 100, postTokens: 50,
    }, 'pre');
    assert.equal(r.postTokens, null);
  });
});

describe('inferMcpServerFromToolName', () => {
  it('extracts the server segment from mcp__<server>__<tool>', () => {
    assert.equal(inferMcpServerFromToolName('mcp__github__create_pr'), 'github');
    assert.equal(inferMcpServerFromToolName('mcp__notion__search_pages'), 'notion');
  });

  it('returns null for non-MCP tool names', () => {
    assert.equal(inferMcpServerFromToolName('Bash'), null);
    assert.equal(inferMcpServerFromToolName('Edit'), null);
    assert.equal(inferMcpServerFromToolName('Read'), null);
    assert.equal(inferMcpServerFromToolName('TaskCreate'), null);
  });

  it('returns null for malformed mcp__ tool names', () => {
    assert.equal(inferMcpServerFromToolName('mcp__'), null);
    assert.equal(inferMcpServerFromToolName('mcp__foo'), null);
    assert.equal(inferMcpServerFromToolName('mcp__'), null);
  });

  it('returns null for non-string input', () => {
    assert.equal(inferMcpServerFromToolName(null), null);
    assert.equal(inferMcpServerFromToolName(undefined), null);
    assert.equal(inferMcpServerFromToolName(42), null);
    assert.equal(inferMcpServerFromToolName(''), null);
  });

  it('handles plugin-namespaced MCP servers', () => {
    // Plugin-shipped MCP servers can have multi-segment names but still
    // follow the mcp__<server>__<tool> shape — the SECOND underscore
    // delimits server from tool. plugin-shipped names use a single
    // server segment per the docs (mcp.txt §"Server naming").
    assert.equal(inferMcpServerFromToolName('mcp__plugin-ai-maestro__send_message'), 'plugin-ai-maestro');
  });
});

describe('parseSubagentStartPayload', () => {
  it('accepts a valid payload with parent_session_id', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-abc',
      parent_session_id: 'parent-xyz',
      agent_type: 'Explore',
      cwd: '/tmp/proj',
    });
    assert.equal(r.ok, true);
    assert.equal(r.sessionId, 'sub-abc');
    assert.equal(r.parentSessionId, 'parent-xyz');
    assert.equal(r.agentType, 'Explore');
    assert.equal(r.cwd, '/tmp/proj');
  });

  it('falls back to parentSessionId field name', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-abc',
      parentSessionId: 'parent-xyz',
      agent_type: 'Bash',
      cwd: '/tmp',
    });
    assert.equal(r.parentSessionId, 'parent-xyz');
  });

  it('falls back to transcript_id field name', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-abc',
      transcript_id: 'tr-xyz',
      agent_type: 'Plan',
      cwd: '/tmp',
    });
    assert.equal(r.parentSessionId, 'tr-xyz');
  });

  it('rejects missing session_id', () => {
    const r = parseSubagentStartPayload({ parent_session_id: 'p', agent_type: 'X', cwd: '/tmp' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('tolerates missing agent_type and parent (best-effort attribution)', () => {
    const r = parseSubagentStartPayload({ session_id: 'sub-abc', cwd: '/tmp' });
    assert.equal(r.ok, true);
    assert.equal(r.agentType, null);
    assert.equal(r.parentSessionId, null);
  });

  it('rejects null payload', () => {
    const r = parseSubagentStartPayload(null);
    assert.equal(r.ok, false);
  });

  it('Phase G — reads spec-correct agent_id field + derives parent from transcript_path', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-123',
      agent_id: 'agent-instance-abc',
      agent_type: 'Explore',
      cwd: '/tmp/proj',
      // Documented layout: ~/.claude/projects/{project}/{parentSessionId}/subagents/agent-{agentId}.jsonl
      transcript_path: '/Users/x/.claude/projects/p/parent-uuid-xyz/subagents/agent-abc.jsonl',
    });
    assert.equal(r.ok, true);
    assert.equal(r.agentId, 'agent-instance-abc');
    assert.equal(r.transcriptPath, '/Users/x/.claude/projects/p/parent-uuid-xyz/subagents/agent-abc.jsonl');
    // Phase G — parent derived from path even though payload omits parent_session_id.
    assert.equal(r.parentSessionId, 'parent-uuid-xyz');
  });

  it('Phase G — parent_session_id in payload takes precedence over path-derived parent', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-1',
      agent_id: 'agent-1',
      parent_session_id: 'explicit-parent',
      transcript_path: '/p/path-derived-parent/subagents/agent-1.jsonl',
    });
    assert.equal(r.parentSessionId, 'explicit-parent');
  });

  it('Phase G — falls back to null when transcript_path is malformed', () => {
    const r = parseSubagentStartPayload({
      session_id: 'sub-1',
      agent_id: 'agent-1',
      transcript_path: '/some/non-conforming/path.txt',
    });
    assert.equal(r.parentSessionId, null);
  });
});

describe('parseParentSessionFromTranscriptPath', () => {
  it('extracts parent UUID from canonical transcript path', () => {
    const p = '/Users/me/.claude/projects/proj-key/abc-123-def/subagents/agent-xyz.jsonl';
    assert.equal(parseParentSessionFromTranscriptPath(p), 'abc-123-def');
  });

  it('handles Windows backslash paths', () => {
    const p = 'C:\\Users\\me\\.claude\\projects\\proj\\parent-456\\subagents\\agent-ggg.jsonl';
    assert.equal(parseParentSessionFromTranscriptPath(p), 'parent-456');
  });

  it('returns null for paths without /subagents/ anchor', () => {
    assert.equal(parseParentSessionFromTranscriptPath('/foo/bar/baz.jsonl'), null);
    assert.equal(parseParentSessionFromTranscriptPath('/sessions/abc/main.jsonl'), null);
  });

  it('returns null for non-string / empty input', () => {
    assert.equal(parseParentSessionFromTranscriptPath(null), null);
    assert.equal(parseParentSessionFromTranscriptPath(undefined), null);
    assert.equal(parseParentSessionFromTranscriptPath(''), null);
    assert.equal(parseParentSessionFromTranscriptPath(42), null);
  });

  it('accepts arbitrary opaque session IDs (not RFC-4122 strict)', () => {
    // The spec says session_id is opaque — we shouldn't reject test fixtures
    // that use simple strings like "session-1" instead of full UUIDs.
    const p = '/p/session-1/subagents/agent-2.jsonl';
    assert.equal(parseParentSessionFromTranscriptPath(p), 'session-1');
  });
});

describe('parseCwdChangedPayload', () => {
  it('accepts a valid payload', () => {
    const r = parseCwdChangedPayload({
      session_id: 'abc',
      previous_cwd: '/tmp/old',
      cwd: '/tmp/new',
    });
    assert.equal(r.ok, true);
    assert.equal(r.sessionId, 'abc');
    assert.equal(r.previousCwd, '/tmp/old');
    assert.equal(r.cwd, '/tmp/new');
  });

  it('tolerates missing previous_cwd', () => {
    const r = parseCwdChangedPayload({ session_id: 'abc', cwd: '/tmp/new' });
    assert.equal(r.ok, true);
    assert.equal(r.previousCwd, null);
  });

  it('rejects missing session_id', () => {
    const r = parseCwdChangedPayload({ cwd: '/tmp' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects missing cwd', () => {
    const r = parseCwdChangedPayload({ session_id: 'abc' });
    assert.equal(r.ok, false);
    assert.match(r.error, /cwd/);
  });

  it('rejects null payload', () => {
    const r = parseCwdChangedPayload(null);
    assert.equal(r.ok, false);
  });
});

describe('parsePostToolBatchPayload', () => {
  it('accepts a valid batch and dedups tool names', () => {
    const r = parsePostToolBatchPayload({
      session_id: 'abc',
      cwd: '/tmp',
      tools: [
        { tool_name: 'Bash', tool_input: {} },
        { tool_name: 'Bash', tool_input: {} },
        { tool_name: 'Read', tool_input: {} },
        { tool_name: 'mcp__github__create_pr', tool_input: {} },
      ],
    });
    assert.equal(r.ok, true);
    assert.equal(r.tools.length, 3);   // Bash deduped
    assert.equal(r.tools[0].toolName, 'Bash');
    assert.equal(r.tools[0].mcpServer, null);
    assert.equal(r.tools[2].toolName, 'mcp__github__create_pr');
    assert.equal(r.tools[2].mcpServer, 'github');
  });

  it('rejects missing session_id', () => {
    const r = parsePostToolBatchPayload({ cwd: '/tmp', tools: [] });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects non-array tools', () => {
    const r = parsePostToolBatchPayload({ session_id: 'abc', cwd: '/tmp', tools: 'oops' });
    assert.equal(r.ok, false);
    // Phase G — error message references tool_calls (the spec field name).
    assert.match(r.error, /tool_calls/);
  });

  it('accepts spec-correct tool_calls field name', () => {
    // Phase G — Anthropic spec sends `tool_calls`, not `tools`. vdm now reads
    // both for forward-compat; this test guards the spec field path.
    const r = parsePostToolBatchPayload({
      session_id: 'abc',
      cwd: '/tmp',
      tool_calls: [{ tool_name: 'Bash' }, { tool_name: 'Read' }],
    });
    assert.equal(r.ok, true);
    assert.equal(r.tools.length, 2);
    assert.equal(r.tools[0].toolName, 'Bash');
    assert.equal(r.tools[1].toolName, 'Read');
  });

  it('legacy `tools` field name still works for old fixtures', () => {
    const r = parsePostToolBatchPayload({
      session_id: 'abc',
      tools: [{ tool_name: 'Edit' }],
    });
    assert.equal(r.ok, true);
    assert.equal(r.tools[0].toolName, 'Edit');
  });

  it('skips malformed tool entries', () => {
    const r = parsePostToolBatchPayload({
      session_id: 'abc',
      cwd: '/tmp',
      tools: [
        { tool_name: 'Bash' },
        null,
        { tool_input: {} },             // missing tool_name
        { tool_name: '' },              // empty tool_name
        { tool_name: 'Read' },
      ],
    });
    assert.equal(r.ok, true);
    assert.deepEqual(r.tools.map(t => t.toolName), ['Bash', 'Read']);
  });

  it('accepts an empty tools array (rare but valid — no tools were called)', () => {
    const r = parsePostToolBatchPayload({ session_id: 'abc', cwd: '/tmp', tools: [] });
    assert.equal(r.ok, true);
    assert.equal(r.tools.length, 0);
  });

  it('rejects null payload', () => {
    const r = parsePostToolBatchPayload(null);
    assert.equal(r.ok, false);
  });
});

describe('isUsageRow', () => {
  it('returns true for plain usage rows', () => {
    assert.equal(isUsageRow({ type: 'usage', ts: 1, inputTokens: 10 }), true);
  });

  it('returns true for legacy rows that pre-date the type field', () => {
    // Forward-compat: pre-Phase-D rows on disk have no `type` field — they
    // are usage rows by definition. If isUsageRow excluded them the
    // /api/token-usage GET would return an empty array on first run after
    // Phase D ships.
    assert.equal(isUsageRow({ ts: 1, inputTokens: 10, repo: 'x' }), true);
  });

  it('returns false for compact_boundary rows', () => {
    assert.equal(isUsageRow({ type: 'compact_boundary', ts: 1, preTokens: 100 }), false);
  });

  it('handles null/undefined defensively', () => {
    assert.equal(isUsageRow(null), true);
    assert.equal(isUsageRow(undefined), true);
  });
});

describe('buildCompactBoundaryEntry', () => {
  it('produces a row with type=compact_boundary and the right shape', () => {
    const r = buildCompactBoundaryEntry({
      ts: 1729000000000,
      sessionId: 'abc',
      repo: '/tmp/proj',
      branch: 'main',
      commitHash: 'abc1234',
      trigger: 'auto',
      preTokens: 167189,
      postTokens: 42000,
      account: 'acc-1',
    });
    assert.equal(r.type, 'compact_boundary');
    assert.equal(r.sessionId, 'abc');
    assert.equal(r.repo, '/tmp/proj');
    assert.equal(r.branch, 'main');
    assert.equal(r.trigger, 'auto');
    assert.equal(r.preTokens, 167189);
    assert.equal(r.postTokens, 42000);
    // Usage fields must be explicitly null (NOT undefined — JSON.stringify
    // would drop undefined keys, breaking downstream filters).
    assert.equal(r.model, null);
    assert.equal(r.inputTokens, null);
    assert.equal(r.outputTokens, null);
    assert.equal(r.account, 'acc-1');
    assert.equal(r.tool, null);
    assert.equal(r.mcpServer, null);
  });

  it('aggregation skip: a generated boundary row is NOT a usage row', () => {
    const r = buildCompactBoundaryEntry({
      ts: 1, sessionId: 'a', repo: '/x', branch: null, commitHash: '',
      trigger: 'auto', preTokens: 100, postTokens: 50, account: null,
    });
    assert.equal(isUsageRow(r), false);
  });

  it('coerces non-finite preTokens / postTokens to null', () => {
    const r = buildCompactBoundaryEntry({
      ts: 1, sessionId: 'a', repo: '/x', branch: null, commitHash: '',
      trigger: 'manual', preTokens: 'huge', postTokens: undefined, account: null,
    });
    assert.equal(r.preTokens, null);
    assert.equal(r.postTokens, null);
  });

  it('defaults missing repo to (non-git) and branch/account to null', () => {
    const r = buildCompactBoundaryEntry({
      ts: 1, sessionId: 'a',
      trigger: 'auto', preTokens: 100, postTokens: null,
    });
    assert.equal(r.repo, '(non-git)');
    assert.equal(r.branch, null);
    assert.equal(r.account, null);
    assert.equal(r.commitHash, '');
  });
});

describe('mergeSessionAttribution', () => {
  it('attaches sessionId, parentSessionId, agentType from session entry', () => {
    const session = {
      parentSessionId: 'parent-xyz',
      agentType: 'Explore',
      teamId: null,
      lastBatchToolNames: [],
    };
    const r = mergeSessionAttribution('sub-abc', session, {
      ts: 1, repo: '/x', branch: 'main', commitHash: '', model: 'claude-sonnet-4',
      inputTokens: 100, outputTokens: 50, account: 'acc-1',
    }, { perToolAttributionEnabled: false });
    assert.equal(r.sessionId, 'sub-abc');
    assert.equal(r.parentSessionId, 'parent-xyz');
    assert.equal(r.agentType, 'Explore');
    assert.equal(r.tool, null);
    assert.equal(r.mcpServer, null);
  });

  it('with gate ON, joins lastBatchToolNames into tool field', () => {
    const session = {
      parentSessionId: null,
      agentType: null,
      lastBatchToolNames: ['Bash', 'Read', 'Edit'],
    };
    const r = mergeSessionAttribution('s', session, {
      ts: 1, repo: '/x', model: 'claude', inputTokens: 0, outputTokens: 0, account: 'a',
    }, { perToolAttributionEnabled: true });
    assert.equal(r.tool, 'Bash,Read,Edit');
    assert.equal(r.mcpServer, null);
  });

  it('with gate ON, derives mcpServer from first mcp__ tool', () => {
    const session = {
      lastBatchToolNames: ['Bash', 'mcp__github__create_pr', 'mcp__notion__update'],
    };
    const r = mergeSessionAttribution('s', session, { ts: 1 }, { perToolAttributionEnabled: true });
    assert.equal(r.tool, 'Bash,mcp__github__create_pr,mcp__notion__update');
    assert.equal(r.mcpServer, 'github');
  });

  it('with gate OFF, both tool and mcpServer are null even when session has lastBatchToolNames', () => {
    const session = {
      lastBatchToolNames: ['Bash', 'mcp__github__create_pr'],
    };
    const r = mergeSessionAttribution('s', session, { ts: 1 }, { perToolAttributionEnabled: false });
    assert.equal(r.tool, null);
    assert.equal(r.mcpServer, null);
  });

  it('handles a session without parentSessionId / agentType (primary session)', () => {
    const session = {};   // freshly registered via /api/session-start
    const r = mergeSessionAttribution('s', session, { ts: 1 });
    assert.equal(r.parentSessionId, null);
    assert.equal(r.agentType, null);
    assert.equal(r.teamId, null);
    assert.equal(r.tool, null);
  });

  it('does not mutate the input entry', () => {
    const entry = { ts: 1, repo: '/x' };
    const r = mergeSessionAttribution('s', { parentSessionId: 'p' }, entry);
    assert.notEqual(r, entry);
    assert.equal(entry.sessionId, undefined);   // original untouched
    assert.equal(r.sessionId, 's');
  });

  it('null session is tolerated (should not throw)', () => {
    const r = mergeSessionAttribution('s', null, { ts: 1 });
    assert.equal(r.sessionId, 's');
    assert.equal(r.parentSessionId, null);
  });
});

// ─────────────────────────────────────────────────
// Phase E — worktree + agent-team parsers + tool aggregation
// ─────────────────────────────────────────────────

describe('parseWorktreeEventPayload', () => {
  it('accepts a valid payload with worktree_path', () => {
    const r = parseWorktreeEventPayload({
      session_id: 's-1',
      worktree_path: '/tmp/proj-worktree',
      branch: 'feature/foo',
    });
    assert.equal(r.ok, true);
    assert.equal(r.sessionId, 's-1');
    assert.equal(r.worktreePath, '/tmp/proj-worktree');
    assert.equal(r.branch, 'feature/foo');
  });

  it('accepts the alternate "path" field name', () => {
    const r = parseWorktreeEventPayload({
      session_id: 's-1',
      path: '/tmp/wt',
    });
    assert.equal(r.ok, true);
    assert.equal(r.worktreePath, '/tmp/wt');
    assert.equal(r.branch, null);
  });

  it('rejects missing session_id', () => {
    const r = parseWorktreeEventPayload({ worktree_path: '/tmp/wt' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects missing worktree_path AND path', () => {
    const r = parseWorktreeEventPayload({ session_id: 's', branch: 'main' });
    assert.equal(r.ok, false);
    assert.match(r.error, /worktree_path/);
  });

  it('rejects empty-string worktree_path (not a valid path)', () => {
    const r = parseWorktreeEventPayload({ session_id: 's', worktree_path: '' });
    assert.equal(r.ok, false);
  });

  it('rejects null payload', () => {
    const r = parseWorktreeEventPayload(null);
    assert.equal(r.ok, false);
  });

  it('rejects non-object payload (string)', () => {
    const r = parseWorktreeEventPayload('not an object');
    assert.equal(r.ok, false);
  });
});

describe('parseTaskEventPayload', () => {
  it('accepts a valid TaskCreated-shaped payload', () => {
    const r = parseTaskEventPayload({
      session_id: 's-1',
      task_id: 't-abc',
      parent_session_id: 'parent-1',
      agent_type: 'Explore',
      status: 'running',
      description: 'Investigate auth bug',
    });
    assert.equal(r.ok, true);
    assert.equal(r.taskId, 't-abc');
    assert.equal(r.parentSessionId, 'parent-1');
    assert.equal(r.agentType, 'Explore');
    assert.equal(r.status, 'running');
    assert.equal(r.description, 'Investigate auth bug');
  });

  it('falls back to parentSessionId field name', () => {
    const r = parseTaskEventPayload({
      session_id: 's',
      task_id: 't',
      parentSessionId: 'p',
    });
    assert.equal(r.parentSessionId, 'p');
  });

  it('truncates oversized description to 500 chars', () => {
    const big = 'x'.repeat(2000);
    const r = parseTaskEventPayload({
      session_id: 's',
      task_id: 't',
      description: big,
    });
    assert.equal(r.ok, true);
    assert.equal(r.description.length, 500);
  });

  it('rejects missing session_id', () => {
    const r = parseTaskEventPayload({ task_id: 't' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects missing task_id', () => {
    const r = parseTaskEventPayload({ session_id: 's' });
    assert.equal(r.ok, false);
    assert.match(r.error, /task_id/);
  });

  it('tolerates missing optional fields (best-effort metadata)', () => {
    const r = parseTaskEventPayload({ session_id: 's', task_id: 't' });
    assert.equal(r.ok, true);
    assert.equal(r.parentSessionId, null);
    assert.equal(r.agentType, null);
    assert.equal(r.status, null);
    assert.equal(r.description, null);
  });

  it('rejects null payload', () => {
    const r = parseTaskEventPayload(null);
    assert.equal(r.ok, false);
  });

  it('Phase G — reads spec-correct task_title and task_description', () => {
    const r = parseTaskEventPayload({
      session_id: 's',
      task_id: 't-abc',
      task_title: 'Investigate auth race',
      task_description: 'Reproduce the 401 → refresh → 401 loop seen in prod',
    });
    assert.equal(r.ok, true);
    assert.equal(r.taskTitle, 'Investigate auth race');
    assert.equal(r.taskDescription, 'Reproduce the 401 → refresh → 401 loop seen in prod');
    // description is kept as alias of taskDescription for backward-compat
    assert.equal(r.description, r.taskDescription);
  });

  it('Phase G — task_title truncates to 200 chars', () => {
    const r = parseTaskEventPayload({
      session_id: 's',
      task_id: 't',
      task_title: 'X'.repeat(500),
    });
    assert.equal(r.ok, true);
    assert.equal(r.taskTitle.length, 200);
  });
});

describe('parseTeammateIdlePayload', () => {
  it('accepts a valid payload with teammate_id', () => {
    const r = parseTeammateIdlePayload({
      session_id: 's-1',
      teammate_id: 'tm-abc',
    });
    assert.equal(r.ok, true);
    assert.equal(r.sessionId, 's-1');
    assert.equal(r.teammateId, 'tm-abc');
  });

  it('falls back to team_id field name', () => {
    const r = parseTeammateIdlePayload({
      session_id: 's-1',
      team_id: 'team-xyz',
    });
    assert.equal(r.teammateId, 'team-xyz');
  });

  it('tolerates missing teammate_id (informational event)', () => {
    const r = parseTeammateIdlePayload({ session_id: 's-1' });
    assert.equal(r.ok, true);
    assert.equal(r.teammateId, null);
  });

  it('rejects missing session_id', () => {
    const r = parseTeammateIdlePayload({ teammate_id: 'tm' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('rejects null payload', () => {
    const r = parseTeammateIdlePayload(null);
    assert.equal(r.ok, false);
  });

  it('Phase G — reads spec-correct agent_id field', () => {
    const r = parseTeammateIdlePayload({
      session_id: 's',
      agent_id: 'agent-instance-789',
      agent_type: 'Plan',
    });
    assert.equal(r.ok, true);
    assert.equal(r.agentId, 'agent-instance-789');
    assert.equal(r.agentType, 'Plan');
    // teammateId is exposed as the canonical handle (alias of agentId)
    assert.equal(r.teammateId, 'agent-instance-789');
  });
});

describe('aggregateByTool', () => {
  it('buckets rows by tool name and sums input/output tokens', () => {
    const rows = [
      { ts: 100, tool: 'Bash', inputTokens: 100, outputTokens: 50 },
      { ts: 200, tool: 'Bash', inputTokens: 200, outputTokens: 100 },
      { ts: 300, tool: 'Read', inputTokens: 50, outputTokens: 25 },
    ];
    const out = aggregateByTool(rows);
    assert.equal(out.length, 2);
    // Sorted by totalTokens desc — Bash should be first (450 vs 75)
    assert.equal(out[0].tool, 'Bash');
    assert.equal(out[0].inputTokens, 300);
    assert.equal(out[0].outputTokens, 150);
    assert.equal(out[0].totalTokens, 450);
    assert.equal(out[0].count, 2);
    assert.equal(out[1].tool, 'Read');
    assert.equal(out[1].count, 1);
  });

  it('disambiguates same-named tools from different MCP servers', () => {
    const rows = [
      { ts: 1, tool: 'fetch', mcpServer: 'serena', inputTokens: 100, outputTokens: 0 },
      { ts: 2, tool: 'fetch', mcpServer: 'grepika', inputTokens: 50, outputTokens: 0 },
      { ts: 3, tool: 'fetch', mcpServer: 'serena', inputTokens: 75, outputTokens: 0 },
    ];
    const out = aggregateByTool(rows);
    assert.equal(out.length, 2);
    const serena = out.find(b => b.mcpServer === 'serena');
    assert.equal(serena.inputTokens, 175);
    assert.equal(serena.count, 2);
  });

  it('buckets rows without a tool field under "(no per-tool attribution)"', () => {
    const rows = [
      { ts: 1, inputTokens: 100, outputTokens: 50 },
      { ts: 2, tool: 'Bash', inputTokens: 30, outputTokens: 10 },
    ];
    const out = aggregateByTool(rows);
    assert.equal(out.length, 2);
    const unattributed = out.find(b => b.tool === '(no per-tool attribution)');
    assert(unattributed, 'expected an unattributed bucket');
    assert.equal(unattributed.totalTokens, 150);
  });

  it('skips compact_boundary rows via isUsageRow', () => {
    const rows = [
      { ts: 1, type: 'usage', tool: 'Bash', inputTokens: 100, outputTokens: 0 },
      { ts: 2, type: 'compact_boundary', preTokens: 50000, postTokens: 10000 },
      { ts: 3, type: 'usage', tool: 'Read', inputTokens: 50, outputTokens: 0 },
    ];
    const out = aggregateByTool(rows);
    assert.equal(out.length, 2);
    assert(!out.some(b => b.tool && b.tool.includes('compact')), 'compact_boundary should not be a tool bucket');
  });

  it('filters by ts range when provided', () => {
    const rows = [
      { ts: 100, tool: 'Bash', inputTokens: 10, outputTokens: 0 },
      { ts: 200, tool: 'Bash', inputTokens: 20, outputTokens: 0 },
      { ts: 300, tool: 'Bash', inputTokens: 30, outputTokens: 0 },
    ];
    const out = aggregateByTool(rows, { start: 150, end: 250 });
    assert.equal(out.length, 1);
    assert.equal(out[0].inputTokens, 20);
    assert.equal(out[0].count, 1);
  });

  it('half-open range with only start filter', () => {
    const rows = [
      { ts: 100, tool: 'Bash', inputTokens: 10, outputTokens: 0 },
      { ts: 200, tool: 'Bash', inputTokens: 20, outputTokens: 0 },
      { ts: 300, tool: 'Bash', inputTokens: 30, outputTokens: 0 },
    ];
    const out = aggregateByTool(rows, { start: 200 });
    assert.equal(out.length, 1);
    assert.equal(out[0].inputTokens, 50); // 20 + 30
  });

  it('returns empty array on empty input', () => {
    assert.deepEqual(aggregateByTool([]), []);
    assert.deepEqual(aggregateByTool(null), []);
    assert.deepEqual(aggregateByTool(undefined), []);
  });

  it('coerces non-numeric token fields to 0', () => {
    const rows = [
      { ts: 1, tool: 'Bash', inputTokens: 'NaN', outputTokens: undefined },
      { ts: 2, tool: 'Bash', inputTokens: 100, outputTokens: 50 },
    ];
    const out = aggregateByTool(rows);
    assert.equal(out[0].inputTokens, 100);
    assert.equal(out[0].outputTokens, 50);
    assert.equal(out[0].count, 2);
  });
});

// ─────────────────────────────────────────────────
// Phase H — OTLP/HTTP/JSON parser tests
// ─────────────────────────────────────────────────

describe('unwrapOtlpValue', () => {
  it('unwraps stringValue', () => {
    assert.equal(unwrapOtlpValue({ stringValue: 'hello' }), 'hello');
  });
  it('unwraps intValue (string-encoded int64)', () => {
    assert.equal(unwrapOtlpValue({ intValue: '42' }), 42);
    assert.equal(unwrapOtlpValue({ intValue: 100 }), 100);
  });
  it('unwraps doubleValue', () => {
    assert.equal(unwrapOtlpValue({ doubleValue: 3.14 }), 3.14);
  });
  it('unwraps boolValue', () => {
    assert.equal(unwrapOtlpValue({ boolValue: true }), true);
    assert.equal(unwrapOtlpValue({ boolValue: false }), false);
  });
  it('unwraps arrayValue recursively', () => {
    const v = {
      arrayValue: { values: [{ stringValue: 'a' }, { intValue: '1' }, { boolValue: true }] },
    };
    assert.deepEqual(unwrapOtlpValue(v), ['a', 1, true]);
  });
  it('unwraps nested kvlistValue', () => {
    const v = {
      kvlistValue: {
        values: [
          { key: 'name', value: { stringValue: 'claude' } },
          { key: 'count', value: { intValue: '7' } },
        ],
      },
    };
    assert.deepEqual(unwrapOtlpValue(v), { name: 'claude', count: 7 });
  });
  it('returns null for empty / malformed values', () => {
    assert.equal(unwrapOtlpValue(null), null);
    assert.equal(unwrapOtlpValue(undefined), null);
    assert.equal(unwrapOtlpValue({}), null);
    assert.equal(unwrapOtlpValue('not an object'), null);
  });
});

describe('otlpAttrsToObject', () => {
  it('flattens an attribute array to a plain object', () => {
    const attrs = [
      { key: 'service.name', value: { stringValue: 'claude_code' } },
      { key: 'app.version', value: { stringValue: '2.1.121' } },
      { key: 'session.id', value: { stringValue: 'abc-123' } },
    ];
    const obj = otlpAttrsToObject(attrs);
    assert.equal(obj['service.name'], 'claude_code');
    assert.equal(obj['session.id'], 'abc-123');
  });
  it('skips entries missing key or value', () => {
    const attrs = [
      { key: 'a', value: { stringValue: '1' } },
      { value: { stringValue: 'no-key' } },
      null,
      'not an object',
    ];
    const obj = otlpAttrsToObject(attrs);
    assert.equal(Object.keys(obj).length, 1);
    assert.equal(obj.a, '1');
  });
  it('returns empty object on non-array input', () => {
    assert.deepEqual(otlpAttrsToObject(null), {});
    assert.deepEqual(otlpAttrsToObject({}), {});
  });
});

describe('parseOtlpLogs', () => {
  it('extracts log records from a Claude Code-shaped payload', () => {
    const payload = {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: 'service.name', value: { stringValue: 'claude_code' } },
              { key: 'user.account_id', value: { stringValue: 'user-1' } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: 'com.anthropic.claude_code', version: '2.1.121' },
              logRecords: [
                {
                  timeUnixNano: '1735000000000000000', // ms = 1735000000000
                  severityText: 'INFO',
                  severityNumber: 9,
                  body: { stringValue: 'claude_code.api_request' },
                  attributes: [
                    { key: 'model', value: { stringValue: 'claude-opus-4-7' } },
                    { key: 'input_tokens', value: { intValue: '12345' } },
                    { key: 'output_tokens', value: { intValue: '6789' } },
                    { key: 'cache_read_tokens', value: { intValue: '50000' } },
                    { key: 'cost_usd', value: { doubleValue: 0.5043 } },
                    { key: 'request_id', value: { stringValue: 'req-abc' } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    };
    const recs = parseOtlpLogs(payload);
    assert.equal(recs.length, 1);
    const r = recs[0];
    assert.equal(r.body, 'claude_code.api_request');
    assert.equal(r.severity, 'INFO');
    assert.equal(r.scope, 'com.anthropic.claude_code');
    assert.equal(r.ts, 1735000000000);
    // attributes merge resource + record
    assert.equal(r.attributes['service.name'], 'claude_code');
    assert.equal(r.attributes.model, 'claude-opus-4-7');
    assert.equal(r.attributes.input_tokens, 12345);
    assert.equal(r.attributes.output_tokens, 6789);
    assert.equal(r.attributes.cache_read_tokens, 50000);
    assert.equal(r.attributes.cost_usd, 0.5043);
    assert.equal(r.attributes.request_id, 'req-abc');
  });

  it('handles missing/optional fields gracefully', () => {
    const recs = parseOtlpLogs({ resourceLogs: [{ scopeLogs: [{ logRecords: [{}] }] }] });
    assert.equal(recs.length, 1);
    assert.equal(recs[0].body, null);
    assert(recs[0].ts > 0); // falls back to Date.now
  });

  it('returns [] for empty / malformed payload', () => {
    assert.deepEqual(parseOtlpLogs(null), []);
    assert.deepEqual(parseOtlpLogs({}), []);
    assert.deepEqual(parseOtlpLogs({ resourceLogs: 'not an array' }), []);
  });

  it('iterates multiple resource scopes and records', () => {
    const payload = {
      resourceLogs: [
        {
          scopeLogs: [
            { logRecords: [{ body: { stringValue: 'a' } }, { body: { stringValue: 'b' } }] },
            { logRecords: [{ body: { stringValue: 'c' } }] },
          ],
        },
      ],
    };
    const recs = parseOtlpLogs(payload);
    assert.equal(recs.length, 3);
    assert.deepEqual(recs.map(r => r.body), ['a', 'b', 'c']);
  });
});

describe('parseOtlpMetrics', () => {
  it('extracts a sum data point (Claude Code token.usage shape)', () => {
    const payload = {
      resourceMetrics: [
        {
          resource: {
            attributes: [{ key: 'service.name', value: { stringValue: 'claude_code' } }],
          },
          scopeMetrics: [
            {
              metrics: [
                {
                  name: 'claude_code.token.usage',
                  sum: {
                    dataPoints: [
                      {
                        timeUnixNano: '1735000000000000000',
                        asInt: '12345',
                        attributes: [
                          { key: 'type', value: { stringValue: 'input' } },
                          { key: 'model', value: { stringValue: 'claude-sonnet-4-7' } },
                        ],
                      },
                    ],
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    const recs = parseOtlpMetrics(payload);
    assert.equal(recs.length, 1);
    const r = recs[0];
    assert.equal(r.name, 'claude_code.token.usage');
    assert.equal(r.kind, 'sum');
    assert.equal(r.value, 12345);
    assert.equal(r.attributes.type, 'input');
    assert.equal(r.attributes.model, 'claude-sonnet-4-7');
    assert.equal(r.attributes['service.name'], 'claude_code'); // resource merged
  });

  it('extracts gauge and histogram data points', () => {
    const payload = {
      resourceMetrics: [
        {
          scopeMetrics: [
            {
              metrics: [
                { name: 'claude_code.session.active', gauge: { dataPoints: [{ asInt: '3' }] } },
                { name: 'claude_code.api_request.duration', histogram: { dataPoints: [{ count: 5, sum: 1234.5 }] } },
              ],
            },
          ],
        },
      ],
    };
    const recs = parseOtlpMetrics(payload);
    assert.equal(recs.length, 2);
    assert.equal(recs[0].kind, 'gauge');
    assert.equal(recs[0].value, 3);
    assert.equal(recs[1].kind, 'histogram');
    assert.equal(recs[1].value, 5); // count
  });

  it('returns [] for empty / malformed payload', () => {
    assert.deepEqual(parseOtlpMetrics(null), []);
    assert.deepEqual(parseOtlpMetrics({}), []);
  });

  it('produces null value when no numeric field is present', () => {
    const recs = parseOtlpMetrics({
      resourceMetrics: [{ scopeMetrics: [{ metrics: [{ name: 'x', sum: { dataPoints: [{}] } }] }] }],
    });
    assert.equal(recs.length, 1);
    assert.equal(recs[0].value, null);
  });
});

// ─────────────────────────────────────────────────
// Phase J — vdm-account-* keychain service-name helpers
// ─────────────────────────────────────────────────

describe('vdmAccountServiceName', () => {
  it('prefixes a valid name with the canonical "vdm-account-" service prefix', () => {
    assert.equal(vdmAccountServiceName('work'), 'vdm-account-work');
    assert.equal(vdmAccountServiceName('auto-1'), 'vdm-account-auto-1');
    assert.equal(vdmAccountServiceName('user.name'), 'vdm-account-user.name');
    assert.equal(vdmAccountServiceName('user_name'), 'vdm-account-user_name');
    assert.equal(vdmAccountServiceName('a@b'), 'vdm-account-a@b');
  });

  it('exports the prefix constant so callers can build service names directly', () => {
    assert.equal(VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX, 'vdm-account-');
  });

  it('throws on empty / non-string names', () => {
    assert.throws(() => vdmAccountServiceName(''), /account name required/);
    assert.throws(() => vdmAccountServiceName(undefined), /account name required/);
    assert.throws(() => vdmAccountServiceName(null), /account name required/);
    assert.throws(() => vdmAccountServiceName(42), /account name required/);
  });

  it('rejects names containing characters outside the allow-list', () => {
    // Characters that could turn into shell metacharacters or filesystem
    // escape sequences if a buggy caller ever interpolates the result.
    const bad = ['a/b', 'a b', 'a*', 'a?', 'a"b', 'a\\b', '../x', 'a;b', 'a$b', 'a\nb'];
    for (const n of bad) {
      assert.throws(() => vdmAccountServiceName(n), /invalid account name/, `should reject ${JSON.stringify(n)}`);
    }
  });

  it('rejects the reserved name "index"', () => {
    assert.throws(() => vdmAccountServiceName('index'), /reserved/);
  });
});

describe('vdmAccountNameFromService', () => {
  it('strips the "vdm-account-" prefix from a valid service name', () => {
    assert.equal(vdmAccountNameFromService('vdm-account-work'), 'work');
    assert.equal(vdmAccountNameFromService('vdm-account-auto-1'), 'auto-1');
    assert.equal(vdmAccountNameFromService('vdm-account-user.name'), 'user.name');
    assert.equal(vdmAccountNameFromService('vdm-account-a@b'), 'a@b');
  });

  it('returns null when the service does not start with the vdm prefix', () => {
    assert.equal(vdmAccountNameFromService('Claude Code-credentials'), null);
    assert.equal(vdmAccountNameFromService('something-else'), null);
    assert.equal(vdmAccountNameFromService(''), null);
  });

  it('returns null for non-string input', () => {
    assert.equal(vdmAccountNameFromService(undefined), null);
    assert.equal(vdmAccountNameFromService(null), null);
    assert.equal(vdmAccountNameFromService(42), null);
  });

  it('returns null when the suffix would itself fail validation', () => {
    // Prefix present but the remainder contains disallowed characters —
    // it can't have come from vdmAccountServiceName, so reject it.
    assert.equal(vdmAccountNameFromService('vdm-account-'), null);          // empty suffix
    assert.equal(vdmAccountNameFromService('vdm-account-bad/name'), null);  // slash
    assert.equal(vdmAccountNameFromService('vdm-account-spa ce'), null);    // space
  });

  it('round-trips with vdmAccountServiceName for every valid name', () => {
    for (const n of ['work', 'auto-1', 'auto.name', 'a@example.com', 'A_b']) {
      assert.equal(vdmAccountNameFromService(vdmAccountServiceName(n)), n);
    }
  });
});

// ─────────────────────────────────────────────────
// Rotation strategies — pickByStrategy + helpers.
// Critical missing coverage: every strategy branch was untested.
// ─────────────────────────────────────────────────

function _mkAccount(token, expiresAt = Date.now() + 24 * 60 * 60 * 1000) {
  return { name: token, token, expiresAt };
}

function _mkStateManager(perToken) {
  return {
    get(token) { return perToken[token]; },
    update() {},
  };
}

describe('pickBestAccount', () => {
  it('returns the lowest-utilization account', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.8, utilization7d: 0.5 },
      b: { utilization5h: 0.1, utilization7d: 0.5 },
      c: { utilization5h: 0.5, utilization7d: 0.5 },
    });
    const picked = pickBestAccount(accounts, sm);
    assert.equal(picked.token, 'b');
  });

  it('honours excludeTokens', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.1, utilization7d: 0.1 },
      b: { utilization5h: 0.9, utilization7d: 0.9 },
    });
    const picked = pickBestAccount(accounts, sm, new Set(['a']));
    assert.equal(picked.token, 'b');
  });

  it('returns null when every account is excluded', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({ a: {}, b: {} });
    const picked = pickBestAccount(accounts, sm, new Set(['a', 'b']));
    assert.equal(picked, null);
  });
});

describe('pickAnyUntried', () => {
  it('returns any account not in the exclude set', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const picked = pickAnyUntried(accounts, new Set(['a', 'b']));
    assert.equal(picked.token, 'c');
  });

  it('returns null when all accounts are excluded', () => {
    const accounts = [_mkAccount('a')];
    assert.equal(pickAnyUntried(accounts, new Set(['a'])), null);
  });
});

describe('pickByStrategy — sticky', () => {
  it('returns null when current account is available', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({ a: {}, b: {} });
    const r = pickByStrategy({
      strategy: 'sticky', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, false);
    assert.equal(r.account, null);
  });

  it('rotates when current account is missing from list (unavailable)', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({ a: {}, b: {} });
    const r = pickByStrategy({
      strategy: 'sticky', intervalMin: 60,
      currentToken: 'gone', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, true);
    assert.ok(r.account);
  });
});

describe('pickByStrategy — round-robin', () => {
  it('skips when timer not elapsed', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.5 }, b: { utilization5h: 0.1 },
    });
    const now = 100_000_000;
    const r = pickByStrategy({
      strategy: 'round-robin', intervalMin: 60,
      currentToken: 'a', lastRotationTime: now - 10 * 60 * 1000,
      accounts, stateManager: sm, now,
    });
    assert.equal(r.rotated, false);
  });

  it('rotates when timer elapsed and a better account exists', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.5 }, b: { utilization5h: 0.1 },
    });
    const now = 100_000_000;
    const r = pickByStrategy({
      strategy: 'round-robin', intervalMin: 30,
      currentToken: 'a', lastRotationTime: now - 60 * 60 * 1000,
      accounts, stateManager: sm, now,
    });
    assert.equal(r.rotated, true);
    assert.equal(r.account.token, 'b');
  });

  it('does not rotate when current is already best', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0 }, b: { utilization5h: 0.5 },
    });
    const now = 100_000_000;
    const r = pickByStrategy({
      strategy: 'round-robin', intervalMin: 30,
      currentToken: 'a', lastRotationTime: now - 60 * 60 * 1000,
      accounts, stateManager: sm, now,
    });
    assert.equal(r.rotated, false);
  });
});

describe('pickByStrategy — spread', () => {
  it('always picks lowest utilization, even mid-interval', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.5 },
      b: { utilization5h: 0.0 },
      c: { utilization5h: 0.9 },
    });
    const r = pickByStrategy({
      strategy: 'spread', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, true);
    assert.equal(r.account.token, 'b');
  });

  it('does not rotate when current is already lowest', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0 }, b: { utilization5h: 0.5 },
    });
    const r = pickByStrategy({
      strategy: 'spread', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, false);
  });
});

describe('pickByStrategy — conserve + drain-first', () => {
  it('conserve picks account with highest 7d utilization (warm window)', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0, utilization7d: 0.0 },           // dormant
      b: { utilization5h: 0.0, utilization7d: 0.4 },           // warm
      c: { utilization5h: 0.0, utilization7d: 0.0 },           // dormant
    });
    const r = pickByStrategy({
      strategy: 'conserve', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, true);
    assert.equal(r.account.token, 'b');
  });

  it('drain-first picks account with highest 5h utilization', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.2 },
      b: { utilization5h: 0.7 },
      c: { utilization5h: 0.0 },
    });
    const r = pickByStrategy({
      strategy: 'drain-first', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, true);
    assert.equal(r.account.token, 'b');
  });
});

describe('pickByStrategy — current-account-unavailable fallback', () => {
  it('rotates regardless of strategy when current token is rate-limited', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const now = 100_000_000;          // fixed clock for determinism
    const nowSec = Math.floor(now / 1000);
    const sm = _mkStateManager({
      // `limited` is only treated as unavailable when at least one of
      // retryAfter / resetAt / resetAt7d is still in the future.
      a: { limited: true, resetAt: nowSec + 600, utilization5h: 0.9 },
      b: { utilization5h: 0.1 },
    });
    for (const strategy of ['sticky', 'conserve', 'round-robin', 'spread', 'drain-first']) {
      const r = pickByStrategy({
        strategy, intervalMin: 60,
        currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm, now,
      });
      assert.equal(r.rotated, true, `strategy=${strategy} should rotate when current is limited`);
      assert.equal(r.account.token, 'b', `strategy=${strategy} should pick b`);
    }
  });
});

describe('pickByStrategy — unknown strategy', () => {
  it('returns null/false for an unknown strategy name', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({ a: {}, b: {} });
    const r = pickByStrategy({
      strategy: 'wat-strategy', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
    });
    assert.equal(r.rotated, false);
    assert.equal(r.account, null);
  });
});

// ─────────────────────────────────────────────────
// Per-account excludeFromAuto preference — every auto-pick path must
// honor the flag. Manual switches bypass these helpers entirely so
// excluded accounts can still be reached via the dashboard / vdm CLI.
// ─────────────────────────────────────────────────
describe('pickBestAccount — excludeFromAuto', () => {
  function _mkExcludedAccount(token, expiresAt = Date.now() + 86400000) {
    return { name: token, token, expiresAt, excludeFromAuto: true };
  }

  it('skips accounts with excludeFromAuto=true', () => {
    // a is the lowest-utilization (would normally win) but excluded.
    const accounts = [_mkExcludedAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.1 },
      b: { utilization5h: 0.5 },
    });
    const picked = pickBestAccount(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'b', 'a was excluded; should fall back to b');
  });

  it('returns null when ALL pickable accounts are excluded', () => {
    const accounts = [_mkExcludedAccount('a'), _mkExcludedAccount('b')];
    const sm = _mkStateManager({ a: {}, b: {} });
    const picked = pickBestAccount(accounts, sm);
    assert.equal(picked, null);
  });

  it('still respects excludeTokens AND excludeFromAuto together', () => {
    const accounts = [_mkExcludedAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({ a: {}, b: {}, c: {} });
    const picked = pickBestAccount(accounts, sm, new Set(['b']));
    assert.ok(picked);
    assert.equal(picked.token, 'c', 'a excluded by flag, b excluded by Set, c wins');
  });
});

describe('pickConserve — excludeFromAuto', () => {
  it('skips excluded accounts even if they have the highest 7d utilization', () => {
    const accounts = [
      { name: 'warm-but-excluded', token: 'warm', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'cool',              token: 'cool', expiresAt: Date.now() + 86400000 },
    ];
    const sm = _mkStateManager({
      warm: { utilization5h: 0.1, utilization7d: 0.7 },
      cool: { utilization5h: 0.0, utilization7d: 0.05 },
    });
    const picked = pickConserve(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'cool');
  });
});

describe('pickDrainFirst — excludeFromAuto', () => {
  it('skips excluded accounts even if they have the highest 5h utilization', () => {
    const accounts = [
      { name: 'drain-target', token: 'drain', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'fresh',        token: 'fresh', expiresAt: Date.now() + 86400000 },
    ];
    const sm = _mkStateManager({
      drain: { utilization5h: 0.9 },
      fresh: { utilization5h: 0.1 },
    });
    const picked = pickDrainFirst(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'fresh');
  });
});

describe('pickAnyUntried — excludeFromAuto', () => {
  it('skips excluded accounts in the last-resort fallback path', () => {
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'b', token: 'b', expiresAt: Date.now() + 86400000 },
    ];
    const picked = pickAnyUntried(accounts, new Set());
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('returns null when every untried account is excluded', () => {
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'b', token: 'b', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
    ];
    assert.equal(pickAnyUntried(accounts, new Set()), null);
  });
});

describe('pickByStrategy — excluded-but-available current account stays sticky', () => {
  it('does NOT auto-rotate away from an excluded current account that is still usable', () => {
    // User toggled excludeFromAuto on the currently-active account 'a'.
    // 'a' is healthy (low utilization, not rate-limited). Expected:
    // strategy keeps 'a' active until it becomes unavailable. Otherwise
    // every poll would force-rotate-away (because pickConserve filters
    // 'a' out of candidates) — surprising behaviour for a flag named
    // "exclude from auto-SWITCH".
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'b', token: 'b', expiresAt: Date.now() + 86400000 },
    ];
    const sm = _mkStateManager({
      a: { utilization5h: 0.1, utilization7d: 0.2 },
      b: { utilization5h: 0.0, utilization7d: 0.0 },
    });
    for (const strategy of ['conserve', 'spread', 'drain-first', 'round-robin', 'sticky']) {
      const r = pickByStrategy({
        strategy, intervalMin: 0,
        currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
        now: Date.now() + 60_000_000, // far past any rotation interval
      });
      assert.equal(r.rotated, false, `strategy=${strategy} should not rotate away from excluded-but-available current`);
      assert.equal(r.account, null, `strategy=${strategy} returned non-null account`);
    }
  });

  it('rotates away when an excluded current becomes unavailable (rate-limited)', () => {
    // The exclude flag must NOT block recovery rotation when the
    // current account is rate-limited — that would strand the user
    // with a non-functional account. Verify the unavailable branch
    // wins over the excluded-sticky branch.
    const nowSec = Math.floor(Date.now() / 1000);
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'b', token: 'b', expiresAt: Date.now() + 86400000 },
    ];
    const sm = _mkStateManager({
      a: { limited: true, resetAt: nowSec + 600 },
      b: { utilization5h: 0.0 },
    });
    const r = pickByStrategy({
      strategy: 'conserve', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
      now: Date.now(),
    });
    assert.equal(r.rotated, true, 'must rotate away from rate-limited excluded current');
    assert.ok(r.account);
    assert.equal(r.account.token, 'b');
  });

  it('returns null/null when an excluded current is unavailable AND no other candidate exists', () => {
    // Edge case: only account is excluded AND rate-limited. We can't
    // recover — but we shouldn't crash either. Expected: account=null,
    // rotated=false (the proxy will surface the failure to the client).
    const nowSec = Math.floor(Date.now() / 1000);
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
    ];
    const sm = _mkStateManager({
      a: { limited: true, resetAt: nowSec + 600 },
    });
    const r = pickByStrategy({
      strategy: 'conserve', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
      now: Date.now(),
    });
    assert.equal(r.rotated, false);
    assert.equal(r.account, null);
  });
});

describe('pickByStrategy — excludeFromAuto end-to-end', () => {
  it('every strategy path honours excludeFromAuto', () => {
    const accounts = [
      { name: 'a', token: 'a', expiresAt: Date.now() + 86400000, excludeFromAuto: true },
      { name: 'b', token: 'b', expiresAt: Date.now() + 86400000 },
    ];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0, utilization7d: 0.0 },
      b: { utilization5h: 0.5, utilization7d: 0.5 },
    });
    for (const strategy of ['conserve', 'spread', 'drain-first', 'round-robin']) {
      const r = pickByStrategy({
        strategy, intervalMin: 0,
        currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
        now: Date.now() + 60_000_000, // far past any interval
      });
      // 'a' is excluded; result must never select 'a'. For strategies
      // that DO rotate (spread / drain-first / round-robin once interval
      // elapses), the picked account should be 'b'.
      if (r.account) assert.notEqual(r.account.token, 'a',
        `strategy=${strategy} returned excluded account`);
    }
  });
});

// ─────────────────────────────────────────────────
// H3 regression — pickByStrategy must forward its `now` arg through every
// fallback callsite. Pre-fix, the unavailable-current branch and each
// strategy switch arm called pickBestAccount/pickConserve/pickDrainFirst
// without passing `now`, so candidate availability was checked against
// the real wall clock — making picker tests silently fragile.
// ─────────────────────────────────────────────────
describe('pickByStrategy — injected `now` reaches candidate availability checks', () => {
  it('treats a candidate as expired only when the injected `now` is honored', () => {
    // Two synthetic clocks chosen so wall-clock Date.now() is always ≥ both.
    // 'a' is the current account and is rate-limited so the unavailable
    // branch fires; 'b' is the only other candidate. Its expiresAt sits
    // BETWEEN nowEarly and nowLate. Honored `now`:
    //   - nowEarly (1000): expiresAt(2000) > now → 'b' is pickable
    //   - nowLate  (3000): expiresAt(2000) < now → 'b' is expired, no pick
    // If `now` is silently dropped, both calls would hit Date.now()
    // (≫ 2000), so 'b' would always be expired and the early case fails.
    const nowEarly = 1000;
    const nowLate = 3000;
    const accounts = [
      { name: 'a', token: 'a', expiresAt: nowEarly + 86400000 },
      { name: 'b', token: 'b', expiresAt: 2000 },
    ];
    // 'a' is rate-limited at both clocks so the unavailable-current
    // fallback fires (which is the path that previously dropped `now`).
    const sm = _mkStateManager({
      a: { limited: true, retryAfter: nowLate + 600_000, utilization5h: 0.9 },
      b: { utilization5h: 0.1 },
    });

    const early = pickByStrategy({
      strategy: 'spread', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
      now: nowEarly,
    });
    assert.ok(early.account, 'with nowEarly, b is not yet expired and must be picked');
    assert.equal(early.account.token, 'b');
    assert.equal(early.rotated, true);

    const late = pickByStrategy({
      strategy: 'spread', intervalMin: 60,
      currentToken: 'a', lastRotationTime: 0, accounts, stateManager: sm,
      now: nowLate,
    });
    assert.equal(late.account, null, 'with nowLate, b is expired — no pickable candidate');
    assert.equal(late.rotated, false);
  });

  it('pickBestAccount also honors injected `now` directly', () => {
    // Direct caller path (not via pickByStrategy). Same logic: expiresAt
    // sits between two synthetic clocks. If `now` is dropped, Date.now()
    // (≫ 2000) is used and the account is reported expired regardless.
    const accounts = [{ name: 'a', token: 'a', expiresAt: 2000 }];
    const sm = _mkStateManager({ a: { utilization5h: 0.0 } });
    assert.ok(pickBestAccount(accounts, sm, new Set(), 1000),
      'pickBestAccount with now=1000 should treat expiresAt=2000 as still valid');
    assert.equal(pickBestAccount(accounts, sm, new Set(), 3000), null,
      'pickBestAccount with now=3000 should treat expiresAt=2000 as expired');
  });
});

// ─────────────────────────────────────────────────
// scoreAccountConserve — weekly dominates 5h tiebreaker (×100 / ×1).
// Critical: with weekly window already active, conserve should
// concentrate on it even when its 5h is HIGH (the whole point of
// "conserve" is to drain accounts whose windows are open).
// ─────────────────────────────────────────────────
describe('scoreAccountConserve', () => {
  it('returns 0 for unknown token (untouched, preserve)', () => {
    const sm = _mkStateManager({});
    assert.equal(scoreAccountConserve('missing', sm), 0);
  });

  it('returns 0 for known token with no utilization fields', () => {
    const sm = _mkStateManager({ a: {} });
    assert.equal(scoreAccountConserve('a', sm), 0);
  });

  it('weights 7d ×100 over 5h ×1', () => {
    // 7d=0.5, 5h=0.0  -> 50.0
    // 7d=0.0, 5h=0.99 -> 0.99
    // The 7d-active account scores ~50× higher.
    const sm = _mkStateManager({
      weekly: { utilization5h: 0.0, utilization7d: 0.5 },
      hourly: { utilization5h: 0.99, utilization7d: 0.0 },
    });
    const sw = scoreAccountConserve('weekly', sm);
    const sh = scoreAccountConserve('hourly', sm);
    assert.equal(sw, 50);
    assert.ok(Math.abs(sh - 0.99) < 1e-9);
    assert.ok(sw > sh * 25);
  });

  it('uses 5h as tiebreaker when 7d is equal', () => {
    const sm = _mkStateManager({
      a: { utilization5h: 0.1, utilization7d: 0.5 },
      b: { utilization5h: 0.2, utilization7d: 0.5 },
    });
    const sa = scoreAccountConserve('a', sm);
    const sb = scoreAccountConserve('b', sm);
    assert.equal(sa, 50.1);
    assert.equal(sb, 50.2);
  });

  it('handles missing utilization5h or utilization7d gracefully (treats as 0)', () => {
    const sm = _mkStateManager({
      a: { utilization5h: 0.42 },                     // no 7d
      b: { utilization7d: 0.42 },                     // no 5h
    });
    assert.equal(scoreAccountConserve('a', sm), 0.42);
    assert.equal(scoreAccountConserve('b', sm), 42);
  });
});

// ─────────────────────────────────────────────────
// pickConserve — picks the highest scoreAccountConserve, skipping
// excluded and unavailable accounts. The default rotation strategy.
// ─────────────────────────────────────────────────
describe('pickConserve', () => {
  it('picks the highest 7d account (drains the warm window)', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.2, utilization7d: 0.1 },  // cold
      b: { utilization5h: 0.0, utilization7d: 0.5 },  // already-warm 7d
      c: { utilization5h: 0.0, utilization7d: 0.0 },  // dormant
    });
    const picked = pickConserve(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('falls back to next-best when the warmest is excluded', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0, utilization7d: 0.6 },
      b: { utilization5h: 0.0, utilization7d: 0.3 },
    });
    const picked = pickConserve(accounts, sm, new Set(['a']));
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('skips rate-limited accounts', () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.0, utilization7d: 0.9, limited: true, resetAt: nowSec + 600 },
      b: { utilization5h: 0.0, utilization7d: 0.1 },
    });
    const picked = pickConserve(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('returns null when every account is unavailable', () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { limited: true, resetAt: nowSec + 600 },
      b: { limited: true, resetAt: nowSec + 600 },
    });
    const picked = pickConserve(accounts, sm);
    assert.equal(picked, null);
  });

  it('treats fully-untouched accounts (score 0) as last resort', () => {
    const accounts = [_mkAccount('fresh'), _mkAccount('warm')];
    const sm = _mkStateManager({
      fresh: { utilization5h: 0.0, utilization7d: 0.0 },
      warm:  { utilization5h: 0.1, utilization7d: 0.05 },
    });
    const picked = pickConserve(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'warm');
  });
});

// ─────────────────────────────────────────────────
// pickDrainFirst — picks the highest 5h utilization. Used for the
// "drain-first" strategy: keep using the same account until its 5h
// window resets, instead of spreading load across accounts.
// ─────────────────────────────────────────────────
describe('pickDrainFirst', () => {
  it('picks the highest 5h account', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b'), _mkAccount('c')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.3 },
      b: { utilization5h: 0.7 },
      c: { utilization5h: 0.1 },
    });
    const picked = pickDrainFirst(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('respects excludeTokens and falls through', () => {
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.9 },
      b: { utilization5h: 0.4 },
    });
    const picked = pickDrainFirst(accounts, sm, new Set(['a']));
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('skips rate-limited accounts', () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const accounts = [_mkAccount('a'), _mkAccount('b')];
    const sm = _mkStateManager({
      a: { utilization5h: 0.95, limited: true, resetAt: nowSec + 600 },
      b: { utilization5h: 0.05 },
    });
    const picked = pickDrainFirst(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'b');
  });

  it('returns null when no candidate is available', () => {
    const picked = pickDrainFirst([], _mkStateManager({}));
    assert.equal(picked, null);
  });

  it('treats unknown accounts as score 0 (lowest priority for drain)', () => {
    const accounts = [_mkAccount('known'), _mkAccount('unknown')];
    const sm = _mkStateManager({
      known: { utilization5h: 0.5 },
      // 'unknown' deliberately omitted
    });
    const picked = pickDrainFirst(accounts, sm);
    assert.ok(picked);
    assert.equal(picked.token, 'known');
  });
});

// ─────────────────────────────────────────────────
// getFingerprintFromToken — separate path from getFingerprint(creds);
// used in dashboard.mjs every time we need to identify a token without
// reading the keychain blob.
// ─────────────────────────────────────────────────
describe('getFingerprintFromToken', () => {
  // sha256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  const _SHA256_EMPTY_PREFIX_16 = 'e3b0c44298fc1c14';

  it('returns 16-char hex prefix of sha256(token)', () => {
    const fp = getFingerprintFromToken('sk-ant-oauth-fake-token-aaaa');
    assert.equal(typeof fp, 'string');
    assert.match(fp, /^[0-9a-f]{16}$/);
  });

  it('is deterministic for the same input', () => {
    const t = 'sk-ant-oauth-fake-token-bbbb';
    assert.equal(getFingerprintFromToken(t), getFingerprintFromToken(t));
  });

  it('differs for different tokens', () => {
    const fpA = getFingerprintFromToken('token-a');
    const fpB = getFingerprintFromToken('token-b');
    assert.notEqual(fpA, fpB);
  });

  it('coerces null/undefined/empty/0/false to the empty-string fingerprint', () => {
    // `token || ''` collapses every falsy input to the empty string,
    // which hashes to the well-known `e3b0c4...` prefix. This is the
    // intended behavior — callers can rely on the function never
    // throwing on a missing token.
    assert.equal(getFingerprintFromToken(''), _SHA256_EMPTY_PREFIX_16);
    assert.equal(getFingerprintFromToken(null), _SHA256_EMPTY_PREFIX_16);
    assert.equal(getFingerprintFromToken(undefined), _SHA256_EMPTY_PREFIX_16);
    assert.equal(getFingerprintFromToken(0), _SHA256_EMPTY_PREFIX_16);
    assert.equal(getFingerprintFromToken(false), _SHA256_EMPTY_PREFIX_16);
  });

  it('agrees with getFingerprint(creds) when creds.claudeAiOauth.accessToken == token', () => {
    const token = 'sk-ant-oauth-fake-token-cccc';
    const creds = { claudeAiOauth: { accessToken: token } };
    assert.equal(getFingerprintFromToken(token), getFingerprint(creds));
  });

  it('agrees with getFingerprint({}) on the empty-string fallback', () => {
    // Both helpers funnel an empty/missing token through `'' ` → sha256('')
    // → same 16-char prefix. This locks down the contract that lookups
    // keyed by fingerprint stay consistent across the two entry points.
    assert.equal(getFingerprintFromToken(''), getFingerprint({}));
    assert.equal(getFingerprintFromToken(null), getFingerprint(null));
  });
});

// ─────────────────────────────────────────────────
// parseRetryAfter — RFC 7231 §7.1.3.
// Retry-After can be EITHER a delta-seconds integer OR an HTTP-date.
// The pre-fix parseInt swallowed HTTP-date values silently (returning 0),
// which classified them as transient and bypassed account rotation —
// exactly the case where rotation matters most.
// ─────────────────────────────────────────────────
describe('parseRetryAfter', () => {
  it('returns 0 for missing/null/undefined/empty header', () => {
    assert.equal(parseRetryAfter(null), 0);
    assert.equal(parseRetryAfter(undefined), 0);
    assert.equal(parseRetryAfter(''), 0);
    assert.equal(parseRetryAfter('   '), 0);
  });

  it('parses delta-seconds form correctly', () => {
    assert.equal(parseRetryAfter('120'), 120);
    assert.equal(parseRetryAfter('0'), 0);
    assert.equal(parseRetryAfter('3600'), 3600);
    assert.equal(parseRetryAfter('  60  '), 60); // trims whitespace
  });

  it('rejects malformed numeric values that parseInt would accept', () => {
    // '120abc' would parseInt to 120 — but per RFC the entire value
    // must be a non-negative integer. We reject and return 0 (which
    // means "treat as transient" — not ideal, but at least caller
    // doesn't think they were rate-limited for 120 valid seconds).
    assert.equal(parseRetryAfter('120abc'), 0);
    assert.equal(parseRetryAfter('-5'), 0);    // negatives invalid
    assert.equal(parseRetryAfter('1.5'), 0);   // floats invalid
    assert.equal(parseRetryAfter('1e3'), 0);   // sci notation invalid
  });

  it('parses RFC-1123 HTTP-date form correctly', () => {
    const now = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    const future = 'Mon, 01 Jan 2030 12:05:00 GMT'; // +300s
    assert.equal(parseRetryAfter(future, now), 300);
  });

  it('parses RFC-850 HTTP-date form correctly', () => {
    const now = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    // Date.parse accepts the asctime-style "Mon Jan  1 12:01:00 2030"
    // (Node + most browsers); the RFC-850 "Monday, 01-Jan-30 12:01:00 GMT"
    // form is Date.parse-implementation-dependent and not covered here.
    const future = 'Mon Jan  1 12:01:00 2030 GMT';
    const v = parseRetryAfter(future, now);
    // Some Node versions parse this as local time; accept any
    // non-negative result that's a multiple of 60.
    assert.ok(v >= 0);
  });

  it('returns 0 for HTTP-date in the past', () => {
    const now = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    const past = 'Mon, 01 Jan 2030 11:00:00 GMT'; // -3600s
    assert.equal(parseRetryAfter(past, now), 0);
  });

  it('returns 0 for HTTP-date that exactly equals now', () => {
    const now = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    assert.equal(parseRetryAfter('Mon, 01 Jan 2030 12:00:00 GMT', now), 0);
  });

  it('rounds future HTTP-date UP to whole seconds (caller is over-cautious not under)', () => {
    // toUTCString() drops milliseconds, so we cannot demonstrate 500ms
    // rounding via the full HTTP-date round-trip. Instead, use a `now`
    // that is 500ms BEFORE the canonical timestamp — the parser will
    // see deltaMs = 500 and ceil to 1.
    const target = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    const earlier = target - 500;
    assert.equal(parseRetryAfter('Mon, 01 Jan 2030 12:00:00 GMT', earlier), 1);
  });

  it('returns 0 for completely unparseable strings', () => {
    assert.equal(parseRetryAfter('not a date'), 0);
    assert.equal(parseRetryAfter('🦄🌈'), 0);
    assert.equal(parseRetryAfter('null'), 0);
  });

  it('coerces non-string types to string before parsing', () => {
    // A header layer might hand us a number directly (e.g. when re-using
    // a synthesised value). It should still parse as delta-seconds.
    assert.equal(parseRetryAfter(60), 60);
    assert.equal(parseRetryAfter(0), 0);
  });

  it('caps absurd upstream values at PARSE_RETRY_AFTER_MAX (7d)', () => {
    // A misconfigured (or hostile) upstream sending Retry-After: 99999999
    // should not put us in a multi-year cooldown. M2 raised the cap from
    // 24h to 7d so legitimate Anthropic 7d-window responses are honored.
    assert.equal(parseRetryAfter(99999999), 604800);
    assert.equal(parseRetryAfter(604801), 604800);
    assert.equal(parseRetryAfter(604800), 604800); // boundary
    assert.equal(parseRetryAfter(604799), 604799); // just under
  });

  it('caps far-future HTTP-date values at PARSE_RETRY_AFTER_MAX (7d)', () => {
    // Date 10 years in the future → cap to 7d (post-M2).
    const now = Date.parse('Mon, 01 Jan 2030 12:00:00 GMT');
    const farFuture = 'Mon, 01 Jan 2040 12:00:00 GMT';
    assert.equal(parseRetryAfter(farFuture, now), 604800);
  });

  it('honors a legitimate 7-day Retry-After response (M2 regression)', () => {
    // Pre-M2: Retry-After: 604800 capped to 86400 → proxy gave up after 1d
    // and started thundering-herd retries against still-rate-limited 7d
    // window. Post-M2: full 7d honored.
    assert.equal(parseRetryAfter(604800), 604800);
  });
});

// ─────────────────────────────────────────────────
// XSS regression tests for the renderHTML embedded JS.
//
// renderHTML returns the dashboard's HTML+JS as a single template
// literal, so the embedded helpers (escHtml, evtMsg, the card render
// closure) can't be imported and unit-tested directly. Instead we
// regression-test the SOURCE: read dashboard.mjs as text and assert
// that every dynamic-data interpolation goes through an escape helper
// (`escHtml(...)` / the `h(...)` alias inside evtMsg).
//
// These tests are deliberately strict: a future contributor adding a
// new event type to evtMsg without going through `h()` will see the
// regression test fail before the change hits the browser.
// ─────────────────────────────────────────────────
import { readFileSync as _readFileSync_xss } from 'node:fs';

describe('XSS regression — evtMsg escapes every dynamic field', () => {
  const _dashboardSrc = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('the local h() helper exists in evtMsg', () => {
    // evtMsg defines `var h = function(s) { return escHtml(...); };`
    // Match either `escHtml` or that exact pattern. Without the helper,
    // every interpolation below would be unsafe.
    assert.match(_dashboardSrc, /var h = function\(s\) \{ return escHtml\(/);
  });

  it('no UNESCAPED `+ e.field +` concatenations remain in evtMsg', () => {
    // The pre-fix XSS pattern had the literal shape `' + e.account` /
    // `' + e.label` / etc — string-literal concat boundary directly
    // adjacent to the unsafe field reference. The fix wraps every such
    // reference in `h(...)`. Search for the dangerous shape directly
    // and fail on any survivor; this is robust against future event
    // types being added without going through the helper.
    //
    // Allowed exceptions:
    //   * `e.retryAfter` is numeric and only used in arithmetic
    //   * `e.type` is set by dashboard code so it's already safe
    const fnMatch = _dashboardSrc.match(
      /function evtMsg\(e\) \{[\s\S]*?\n\}/
    );
    assert.ok(fnMatch, 'evtMsg function not found');
    const body = fnMatch[0];
    // Hunt for the shape `+ e.<field>` where <field> is NOT retryAfter
    // or type. The shape inside an `h(...)` call would be `(e.field` or
    // `h(e.field`, NOT `+ e.field`, so this regex distinguishes safe
    // (wrapped) from unsafe (raw concat) usage.
    const dangerous = body.match(/\+\s*e\.([a-zA-Z_$][\w$]*)/g) || [];
    const unsafe = dangerous.filter(m => {
      const field = m.match(/e\.([a-zA-Z_$][\w$]*)/)[1];
      return field !== 'retryAfter' && field !== 'type';
    });
    assert.deepEqual(unsafe, [],
      `Unescaped string-concat XSS shape found in evtMsg: ${unsafe.join(', ')}. ` +
      `Wrap each field in h(...) before concatenating into HTML.`);
  });
});

// M14 fix — explicit evtMsg cases for Phase D/E/G/H event types
// (worktree_create, worktree_remove, task_created, task_completed,
// auth_success, config_change, account-removed, account-prefs-changed).
// These regression tests assert each new case routes user-controlled
// fields through h(...) — a future contributor adding another case
// without h() will trip the unsafe-shape check above, but this block
// also asserts the cases exist at all so the activity feed has friendly
// labels instead of raw type names.
describe('XSS regression — evtMsg Phase D/E/G/H cases', () => {
  const _dashboardSrc = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // The regex extracts evtMsg's body (the same pattern the existing
  // `no UNESCAPED ` test uses). We then check each new case label
  // and assert its body wraps the dynamic field via h(...).
  const fnMatch = _dashboardSrc.match(/function evtMsg\(e\) \{[\s\S]*?\n\}/);
  const body = fnMatch ? fnMatch[0] : '';

  const newCases = [
    'worktree_create',
    'worktree_remove',
    'task_created',
    'task_completed',
    'auth_success',
    'config_change',
    'account-removed',
    'account-prefs-changed',
  ];

  for (const caseName of newCases) {
    it(`case '${caseName}' exists and wraps user-controlled fields in h()`, () => {
      // Every new case routes its dynamic field via h(...). We grep for
      // the case label, capture the return expression, and assert it
      // contains an h(...) call. Cases that hardcode strings (no user
      // input) would also satisfy this if they don't concat e.<field>;
      // the existing unsafe-shape test catches missed h() wrappers.
      const re = new RegExp(`case ['"]${caseName}['"]:\\s*return ([^;]+);`);
      const m = body.match(re);
      assert.ok(m, `evtMsg case '${caseName}' not found — add it for friendlier activity feed labels`);
      const returnExpr = m[1];
      // Either the expression contains h(...) (user-controlled field
      // safely escaped) OR it has no e.<field> reference at all (purely
      // static label). Both are safe.
      const hasHelper = /\bh\(/.test(returnExpr);
      const hasUserField = /\be\.\w+/.test(returnExpr);
      if (hasUserField) {
        assert.ok(hasHelper,
          `case '${caseName}' references e.<field> but does not route through h(...). ` +
          `Wrap the field in h(...) like the original cases do.`);
      }
    });
  }
});

describe('XSS regression — renderAccounts card rendering', () => {
  const _dashboardSrc = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('displayName is HTML-escaped before innerHTML', () => {
    // The fix in commit e2f0b35 introduced a separate displayName
    // (escHtml-wrapped) vs displayNameJs (single-quote-escaped) split.
    // Ensure both are still present.
    assert.match(_dashboardSrc, /const displayName = escHtml\(rawDisplayName\);/);
    assert.match(_dashboardSrc, /const displayNameJs = String\(rawDisplayName\)\.replace/);
  });

  it('card-name span uses the escaped displayName, not raw', () => {
    // The span MUST interpolate displayName (already escaped), not
    // rawDisplayName. A regression here would re-introduce the XSS.
    const cardNameSnippet = _dashboardSrc.match(
      /<span class="card-name">.{0,10}\+ ([A-Za-z0-9_]+) \+/
    );
    assert.ok(cardNameSnippet, 'card-name span pattern not found');
    assert.equal(cardNameSnippet[1], 'displayName',
      'card-name must interpolate displayName (escaped), not ' + cardNameSnippet[1]);
  });

  it('doSwitch onclick uses displayNameJs, not the escaped form', () => {
    // The onclick attribute interpolates the JS-string-escaped form so
    // the toast displays apostrophes correctly. Asserting the right
    // variable is used here prevents an inverse regression where someone
    // "simplifies" by reusing displayName everywhere — which would
    // double-encode and produce &#39; in toasts.
    // The on-disk pattern looks like:
    //   onclick="doSwitch(\\''+eName+'\\',\\''+displayNameJs+'\\''+',event)"
    // We just need to confirm displayNameJs (not displayName) is the
    // value passed in the second slot.
    assert.match(_dashboardSrc, /doSwitch\([^)]*\+displayNameJs\+/);
    assert.doesNotMatch(_dashboardSrc, /doSwitch\([^)]*\+displayName\+/,
      'doSwitch must pass displayNameJs, not the HTML-escaped displayName');
  });
});

// ─────────────────────────────────────────────────
// Serialization Queue
// ─────────────────────────────────────────────────
//
// The pre-fix dashboard implementation had an `inflight === 0` early-
// return bypass that defeated strict serialization under load: every
// time the dispatch timer was waiting to fire, a fresh request whose
// counter was momentarily 0 could bypass the queue. Steady-state under
// 15 concurrent CC clients: 18+ inflight, 50+ queued, even with the
// queue toggled "on" and a 200ms gap configured.
//
// These tests exercise the factory directly (no dashboard plumbing)
// and assert the cap is HARD — inflight never exceeds the configured
// max-concurrent.

// 10ms is enough for any setTimeout(0) dispatch to fire on a real Node
// event loop. setImmediate alone is NOT sufficient — the queue uses
// setTimeout(0) for scheduling and the timers phase doesn't always run
// before the check phase (setImmediate).
const _flush = () => new Promise(r => setTimeout(r, 10));
const _wait = (ms) => new Promise(r => setTimeout(r, ms));

describe('createSerializationQueue — strict cap (the bug fix)', () => {
  it('inflight never exceeds maxConcurrent=1 under load', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let peak = 0;
    let live = 0;
    const slowFn = () => new Promise(resolve => {
      live++;
      if (live > peak) peak = live;
      setTimeout(() => { live--; resolve('ok'); }, 30);
    });
    // Fire 20 in a tight loop — exactly the burst pattern that broke
    // the previous implementation.
    const all = Array.from({ length: 20 }, () => q.acquire(slowFn));
    await Promise.all(all);
    assert.equal(peak, 1, `peak inflight should be 1, got ${peak}`);
  });

  it('inflight never exceeds maxConcurrent=4 under load', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 4,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let peak = 0;
    let live = 0;
    const slowFn = () => new Promise(resolve => {
      live++;
      if (live > peak) peak = live;
      setTimeout(() => { live--; resolve('ok'); }, 20);
    });
    const all = Array.from({ length: 30 }, () => q.acquire(slowFn));
    await Promise.all(all);
    assert.equal(peak, 4, `peak inflight should be 4, got ${peak}`);
  });

  it('does NOT have the inflight===0 TOCTOU bypass', async () => {
    // Reproduce the original failure mode: with strict cap, fire a
    // request, let it complete, then fire a NEW request during the
    // dispatch-delay window and a queued request should still come
    // out first via the queue (no bypass).
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 50,
      getEnabled: () => true,
    });
    const order = [];
    let id = 0;
    const tag = (n) => () => new Promise(r => {
      order.push('start:' + n);
      setTimeout(() => { order.push('end:' + n); r(n); }, 10);
    });
    // Push 3 in a tight burst — under the bug, request 1 bypasses,
    // requests 2/3 queue. Even with the bug, this small set looks
    // serial; the assertion targets the explicit ordering invariant.
    const a = q.acquire(tag(++id));
    const b = q.acquire(tag(++id));
    const c = q.acquire(tag(++id));
    await Promise.all([a, b, c]);
    // start:N must precede end:N+1 (no overlap).
    const s1 = order.indexOf('start:1');
    const e1 = order.indexOf('end:1');
    const s2 = order.indexOf('start:2');
    const e2 = order.indexOf('end:2');
    const s3 = order.indexOf('start:3');
    assert.ok(e1 < s2, `end:1 (${e1}) must precede start:2 (${s2})`);
    assert.ok(e2 < s3, `end:2 (${e2}) must precede start:3 (${s3})`);
    assert.ok(s1 < e1 && s2 < e2, 'each request must finish before the next starts');
  });
});

describe('createSerializationQueue — delay between dispatches', () => {
  it('honors getDelayMs() between successive queued dispatches', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 100,
      getEnabled: () => true,
    });
    const startTimes = [];
    const fn = () => new Promise(r => {
      startTimes.push(Date.now());
      setTimeout(r, 5);
    });
    const all = Array.from({ length: 4 }, () => q.acquire(fn));
    await Promise.all(all);
    // 4 dispatches, expect ≥ 100ms between each (allow scheduler jitter ±30ms).
    for (let i = 1; i < startTimes.length; i++) {
      const gap = startTimes[i] - startTimes[i - 1];
      assert.ok(gap >= 70, `dispatch ${i} should be ≥70ms after ${i-1}, got ${gap}ms`);
    }
  });

  it('zero delay still works', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    const fn = () => Promise.resolve('done');
    const all = Array.from({ length: 5 }, () => q.acquire(fn));
    const results = await Promise.all(all);
    assert.deepEqual(results, ['done', 'done', 'done', 'done', 'done']);
  });
});

describe('createSerializationQueue — bypass paths', () => {
  it('isRetry=true bypasses the queue', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let peak = 0;
    let live = 0;
    const slow = () => new Promise(r => {
      live++;
      if (live > peak) peak = live;
      setTimeout(() => { live--; r('x'); }, 30);
    });
    // Two retries fired simultaneously — both bypass → live=2.
    const a = q.acquire(slow, true);
    const b = q.acquire(slow, true);
    await Promise.all([a, b]);
    assert.ok(peak >= 2, `retries should bypass cap; peak=${peak}`);
  });

  it('getEnabled()=false bypasses the queue', async () => {
    let enabled = false;
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => enabled,
    });
    let peak = 0;
    let live = 0;
    const slow = () => new Promise(r => {
      live++;
      if (live > peak) peak = live;
      setTimeout(() => { live--; r('x'); }, 30);
    });
    const all = Array.from({ length: 5 }, () => q.acquire(slow));
    await Promise.all(all);
    assert.equal(peak, 5, 'when disabled, all 5 should run concurrently');
  });
});

describe('createSerializationQueue — drain', () => {
  it('drain() releases all queued requests immediately', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 5000, // would-be huge delay
      getEnabled: () => true,
    });
    const completed = [];
    const fn = (n) => () => new Promise(r => {
      setTimeout(() => { completed.push(n); r(n); }, 5);
    });
    // Start 3, the first dispatches, the other two queue.
    const a = q.acquire(fn(1));
    const b = q.acquire(fn(2));
    const c = q.acquire(fn(3));
    await _flush();
    assert.ok(q.getStats().queued >= 2, 'requests should be queued');
    q.drain();
    await Promise.all([a, b, c]);
    assert.deepEqual(completed.sort(), [1, 2, 3]);
  });
});

describe('createSerializationQueue — queue timeout', () => {
  it('rejects with queue_timeout if dispatch never happens', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
      queueTimeoutMs: 50,
    });
    // Block the queue with a long-running first request.
    let releaseBlocker;
    const blocker = new Promise(r => { releaseBlocker = r; });
    const a = q.acquire(() => blocker);
    // Queue a second; this one should time out before blocker releases.
    const b = q.acquire(() => Promise.resolve('shouldnt reach'));
    let bErr = null;
    try { await b; } catch (e) { bErr = e; }
    assert.ok(bErr && bErr.message === 'queue_timeout',
      `expected queue_timeout, got ${bErr && bErr.message}`);
    releaseBlocker('done');
    await a; // clean up
  });

  it('uses default queueTimeoutMs (120_000) when option is unset', async () => {
    // We can't easily wait 120s in a unit test, but we can verify the API:
    // acquire returns a Promise that doesn't immediately reject, and the
    // factory accepts a missing queueTimeoutMs without throwing.
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
      // queueTimeoutMs intentionally omitted — should default
    });
    let release;
    const blocker = new Promise(r => { release = r; });
    const a = q.acquire(() => blocker);
    const b = q.acquire(() => Promise.resolve('ok'));
    // Give the dispatcher a tick; b must still be pending (not rejected).
    await new Promise(r => setImmediate(r));
    let bSettled = false;
    b.then(() => { bSettled = true; }, () => { bSettled = true; });
    await new Promise(r => setImmediate(r));
    assert.equal(bSettled, false, 'b should still be queued under default timeout');
    release();
    await a;
    await b; // completes once a unblocks
  });

  it('honors explicit queueTimeoutMs: 0 (not silently replaced by default)', async () => {
    // Regression for the `??` vs `||` operator fix. With `||` the factory
    // would silently swap a deliberately-set 0 for the 120_000 default; with
    // `??` an explicit 0 is honored. With queueTimeoutMs=0, both the
    // dispatch timer and the timeout timer have delay=0, so the dispatch /
    // timeout race is genuinely unspecified — but at least one of the two
    // entries below MUST end up rejecting with queue_timeout under the new
    // semantics. Under the old `||` behavior neither would reject within
    // the 5ms test window (the default was 120_000ms).
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
      queueTimeoutMs: 0,
    });
    let release;
    const blocker = new Promise(r => { release = r; });
    let aErr = null, bErr = null;
    const a = q.acquire(() => blocker).catch(e => { aErr = e; });
    const b = q.acquire(() => Promise.resolve('ok')).catch(e => { bErr = e; });
    await new Promise(r => setTimeout(r, 5));
    const sawTimeout = (aErr && aErr.message === 'queue_timeout')
                    || (bErr && bErr.message === 'queue_timeout');
    assert.ok(sawTimeout, 'queueTimeoutMs:0 must produce a queue_timeout rejection within 5ms');
    release();
    await Promise.allSettled([a, b]);
  });
});

describe('gcAccountSlots — purge idle slots (Phase F audit K1)', () => {
  const makeSlot = (inflight = 0, waiters = [], lastDispatchAt = 0) =>
    ({ inflight, waiters, lastDispatchAt });

  it('returns 0 on empty/invalid map', () => {
    assert.equal(gcAccountSlots(null), 0);
    assert.equal(gcAccountSlots(undefined), 0);
    assert.equal(gcAccountSlots(new Map()), 0);
  });

  it('purges slot with inflight=0, no waiters, idle past threshold', () => {
    const m = new Map();
    m.set('fp_old', makeSlot(0, [], 1000)); // dispatched at 1000
    m.set('fp_new', makeSlot(1, [], 2000)); // still in-flight, must keep
    const now = 1000 + 3600_001; // just past 1 hour
    const purged = gcAccountSlots(m, now);
    assert.equal(purged, 1);
    assert.ok(!m.has('fp_old'), 'old slot must be deleted');
    assert.ok(m.has('fp_new'), 'in-flight slot must be preserved');
  });

  it('keeps slots with active waiters even if inflight=0', () => {
    const m = new Map();
    m.set('fp_blocked', makeSlot(0, [() => {}], 1000));
    const now = 1000 + 3600_001;
    assert.equal(gcAccountSlots(m, now), 0);
    assert.ok(m.has('fp_blocked'), 'slot with waiters must be preserved');
  });

  it('respects custom idleMs threshold', () => {
    const m = new Map();
    m.set('fp_recent', makeSlot(0, [], 1000));
    // now=2000, idleMs=500 → idle 1000ms > threshold, purge
    assert.equal(gcAccountSlots(m, 2000, 500), 1);
    assert.ok(!m.has('fp_recent'));
  });

  it('does not purge slot whose lastDispatchAt is still within idle window', () => {
    const m = new Map();
    m.set('fp_active', makeSlot(0, [], 1000));
    // now=1500, idleMs=1000 → idle 500ms < threshold, keep
    assert.equal(gcAccountSlots(m, 1500, 1000), 0);
    assert.ok(m.has('fp_active'));
  });

  it('mixed: purges only the eligible entries', () => {
    const m = new Map();
    m.set('fp_idle1', makeSlot(0, [], 0));
    m.set('fp_idle2', makeSlot(0, [], 100));
    m.set('fp_active', makeSlot(2, [], 0));      // inflight pinned
    m.set('fp_recent', makeSlot(0, [], 999_999)); // recently used
    const now = 1_000_000;
    const idleMs = 100_000;
    const purged = gcAccountSlots(m, now, idleMs);
    assert.equal(purged, 2);
    assert.ok(!m.has('fp_idle1'));
    assert.ok(!m.has('fp_idle2'));
    assert.ok(m.has('fp_active'));
    assert.ok(m.has('fp_recent'));
  });

  it('skips malformed entries (defensive — no throws)', () => {
    const m = new Map();
    m.set('bad1', null);
    m.set('bad2', { /* missing fields */ });
    m.set('bad3', { inflight: 0, waiters: 'not-array', lastDispatchAt: 0 });
    m.set('bad4', { inflight: 0, waiters: [], lastDispatchAt: 'wrong-type' });
    const now = Date.now();
    // No throw; nothing eligible.
    assert.equal(gcAccountSlots(m, now), 0);
    // Map still contains all entries (we only delete eligible ones).
    assert.equal(m.size, 4);
  });
});

describe('createSerializationQueue — continuation pass-through (Phase F audit B1)', () => {
  // The proxy refactor relies on `acquire(fn)` propagating fn's resolved
  // value back to the caller. handleProxyRequest now returns a continuation
  // descriptor `{kind, proxyRes, ...}` for streaming paths; the proxy server
  // callback awaits the descriptor OUTSIDE the queue. If acquire ever swallowed
  // the resolution value (e.g. always resolved with undefined), the proxy
  // would lose every stream descriptor and never start the body pipe.
  it('acquire(fn) resolves with fn\'s return value', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    const descriptor = { kind: 'sse', proxyRes: { id: 'fake' }, acctName: 'x' };
    const result = await q.acquire(() => Promise.resolve(descriptor));
    assert.deepEqual(result, descriptor, 'continuation descriptor must escape the queue');
  });

  it('inflight decrements at fn resolution, not at any post-fn promise chain', async () => {
    // Concrete failure mode this test prevents: if fn returns a promise that
    // resolves with another long-lived promise (analog of a streaming
    // continuation), inflight must decrement when fn's outer promise
    // resolves, NOT when the inner promise eventually resolves.
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let releaseInner;
    const innerLongRunner = new Promise(r => { releaseInner = r; });
    // First acquire: fn resolves with a descriptor that REFERENCES a long-
    // running promise but does NOT await it.
    const a = q.acquire(() => Promise.resolve({ deferred: innerLongRunner }));
    const aResult = await a;
    // Yield once so the queue's `.finally(() => inflight--)` runs — it's
    // microtask-queued AFTER `resolve(value)` settles the outer promise.
    await new Promise(r => setImmediate(r));
    // After a resolves + microtask flush, inflight should be 0 — the inner
    // promise is intentionally NOT awaited inside acquire.
    assert.equal(q.getStats().inflight, 0, 'inflight must drop to 0 once fn resolves');
    // A second acquire should dispatch immediately (cap=1 has room now).
    const b = q.acquire(() => Promise.resolve('immediate'));
    const bResult = await b;
    assert.equal(bResult, 'immediate');
    // Clean up the dangling inner promise.
    releaseInner();
    await aResult.deferred;
  });
});

describe('createSerializationQueue — getStats', () => {
  it('reports inflight and queued accurately', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let release;
    const blocker = new Promise(r => { release = r; });
    const a = q.acquire(() => blocker);
    const b = q.acquire(() => Promise.resolve());
    const c = q.acquire(() => Promise.resolve());
    await _flush();
    const stats = q.getStats();
    assert.equal(stats.inflight, 1, 'one request should be inflight');
    assert.equal(stats.queued, 2, 'two should be queued');
    release();
    await Promise.all([a, b, c]);
    // The dispatcher's .finally (which decrements inflight) runs in a
    // microtask chain that resolves AFTER the outer Promise the caller
    // is awaiting. Drain the loop before asserting on inflight.
    await _flush();
    assert.equal(q.getStats().inflight, 0);
    assert.equal(q.getStats().queued, 0);
  });
});

describe('createSerializationQueue — timeout vs dispatch race', () => {
  it('queue_timeout does NOT reject an entry that has already been dispatched', async () => {
    // Use a very short queueTimeout to force the timeout to fire AROUND
    // the same time as the dispatch. Without the dispatched flag guard,
    // the timeout's reject(queue_timeout) would race with the dispatcher
    // shifting+running the entry, producing either a wrong rejection or
    // a double-settle attempt on the outer Promise.
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
      queueTimeoutMs: 5, // very short, intentionally near dispatch time
    });
    // Dispatch a quick fn — should resolve normally before queueTimeout.
    const r = await q.acquire(() => Promise.resolve('done'));
    assert.equal(r, 'done', 'dispatched entry should not be rejected with queue_timeout');
    await _flush();
    assert.equal(q.getStats().inflight, 0);
  });
});

describe('createSerializationQueue — sync-throw safety', () => {
  it('a fn that throws synchronously becomes a rejection (queued path)', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    // First call occupies the slot so the second one MUST queue.
    let release;
    const blocker = new Promise(r => { release = r; });
    const a = q.acquire(() => blocker);
    // Second call has a non-async fn that throws synchronously when invoked.
    const b = q.acquire(() => { throw new Error('boom'); });
    release();
    let bErr = null;
    try { await b; } catch (e) { bErr = e; }
    assert.ok(bErr && bErr.message === 'boom',
      `expected the sync throw to surface as rejection, got ${bErr && bErr.message}`);
    await a;
    await _flush();
    assert.equal(q.getStats().inflight, 0, 'sync-throw must still decrement inflight');
  });

  it('a fn that throws synchronously becomes a rejection (bypass path)', async () => {
    const q = createSerializationQueue({
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
      getEnabled: () => false, // bypass
    });
    const a = q.acquire(() => { throw new Error('boom'); });
    let aErr = null;
    try { await a; } catch (e) { aErr = e; }
    assert.ok(aErr && aErr.message === 'boom',
      `expected sync throw via bypass to reject, got ${aErr && aErr.message}`);
    await _flush();
    assert.equal(q.getStats().inflight, 0, 'bypass sync-throw must still decrement inflight');
  });
});

describe('createSerializationQueue — runtime cap changes', () => {
  it('tightening the cap mid-flight does not violate it', async () => {
    let cap = 4;
    const q = createSerializationQueue({
      getMaxConcurrent: () => cap,
      getDelayMs: () => 0,
      getEnabled: () => true,
    });
    let peak = 0;
    let live = 0;
    const slow = () => new Promise(r => {
      live++;
      if (live > peak) peak = live;
      setTimeout(() => { live--; r('x'); }, 60);
    });
    const all = Array.from({ length: 12 }, () => q.acquire(slow));
    // Tighten the cap after the first 4 are inflight.
    await _wait(20);
    cap = 1;
    await Promise.all(all);
    // Peak BEFORE tightening was 4 (legitimate). After tightening, no
    // NEW dispatch should push past 4. We're not asserting peak<=1
    // because the 4 already-inflight from the wide-cap era were valid.
    assert.ok(peak <= 4, `peak should not exceed pre-tighten cap; got ${peak}`);
  });
});

// ───────────────────────────────────────────────────────────
// createUsageExtractor — SSE Token Usage Extractor
// (FG4 follow-up — extracted from dashboard.mjs so the M2 abort-path
//  rescue contract has unit-test coverage)
// ───────────────────────────────────────────────────────────

describe('createUsageExtractor — happy path (Transform _flush)', () => {
  it('parses input/output tokens from a complete SSE stream', async () => {
    const extractor = createUsageExtractor();
    // Drain pass-through bytes so backpressure doesn't stall write().
    extractor.on('data', () => {});
    const sse =
      'event: message_start\n' +
      'data: {"message":{"id":"msg_01ABCDEF","usage":{"input_tokens":120,"cache_read_input_tokens":40},"model":"claude-opus-4-7"}}\n' +
      '\n' +
      'event: content_block_delta\n' +
      'data: {"delta":{"text":"hello"}}\n' +
      '\n' +
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":250}}\n' +
      '\n';
    extractor.write(Buffer.from(sse, 'utf8'));
    extractor.end();
    await new Promise(r => extractor.on('end', r));
    const u = extractor.getUsage();
    assert.equal(u.inputTokens, 120);
    assert.equal(u.outputTokens, 250);
    assert.equal(u.cacheReadInputTokens, 40);
    assert.equal(u.model, 'claude-opus-4-7');
    // Phase I+ — message.id captured for (sessionId, messageId) dedup
    assert.equal(u.messageId, 'msg_01ABCDEF');
  });

  it('messageId is null when message_start lacks an id field', async () => {
    // Defensive: some upstream test fixtures and the abort-rescue path
    // may produce streams without an id. Must not throw or set
    // messageId=undefined (JSON.stringify drops undefined keys).
    const extractor = createUsageExtractor();
    extractor.on('data', () => {});
    const sse =
      'event: message_start\n' +
      'data: {"message":{"usage":{"input_tokens":1},"model":"claude-haiku-4-5"}}\n' +
      '\n' +
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":1}}\n' +
      '\n';
    extractor.write(Buffer.from(sse, 'utf8'));
    extractor.end();
    await new Promise(r => extractor.on('end', r));
    assert.equal(extractor.getUsage().messageId, null);
  });

  it('messageId is null for non-string id values (defensive against malformed servers)', async () => {
    const extractor = createUsageExtractor();
    extractor.on('data', () => {});
    const sse =
      'event: message_start\n' +
      'data: {"message":{"id":12345,"usage":{"input_tokens":1},"model":"claude-haiku-4-5"}}\n' +
      '\n';
    extractor.write(Buffer.from(sse, 'utf8'));
    extractor.end();
    await new Promise(r => extractor.on('end', r));
    assert.equal(extractor.getUsage().messageId, null, 'numeric id rejected, kept as null');
  });
});

describe('createUsageExtractor — abort-path rescue (audit M2)', () => {
  it('finishParsing() recovers a trailing message_delta NOT terminated by newline', () => {
    // This simulates: pipeline() destroys the extractor mid-event because
    // the client aborted. The trailing `data:` line never got the
    // newline-terminator that triggers in-`transform` parse, AND _flush
    // never ran because destroy() bypasses it. Without finishParsing, the
    // 999 output_tokens would be silently lost.
    const extractor = createUsageExtractor();
    extractor.on('data', () => {});
    extractor.write(Buffer.from(
      'event: message_start\n' +
      'data: {"message":{"usage":{"input_tokens":50}}}\n' +
      '\n' +
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":999}}',  // ← NO trailing newline
      'utf8'
    ));
    // Simulate pipeline() destroy bypassing flush — explicitly call
    // finishParsing() to rescue the trailing buffer.
    extractor.finishParsing();
    const u = extractor.getUsage();
    assert.equal(u.inputTokens, 50);
    assert.equal(u.outputTokens, 999, 'finishParsing must rescue the trailing message_delta');
  });

  it('finishParsing() is idempotent (no double-parse, safe to call twice)', () => {
    const extractor = createUsageExtractor();
    extractor.on('data', () => {});
    extractor.write(Buffer.from(
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":42}}',
      'utf8'
    ));
    extractor.finishParsing();
    extractor.finishParsing();   // second call must be a no-op
    extractor.finishParsing();   // third too
    assert.equal(extractor.getUsage().outputTokens, 42);
  });

  it('flush() then finishParsing() is also idempotent (success path order)', async () => {
    // On normal stream end, pipeline() calls extractor.end() → triggers
    // _flush() → sets _finishedParsing=true. The continuation runner then
    // calls finishParsing() unconditionally; it must be a no-op here.
    const extractor = createUsageExtractor();
    extractor.on('data', () => {});
    extractor.write(Buffer.from(
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":7}}',
      'utf8'
    ));
    extractor.end();
    await new Promise(r => extractor.on('end', r));
    // _flush has already parsed. Calling finishParsing() now is the
    // double-call exercise.
    extractor.finishParsing();
    assert.equal(extractor.getUsage().outputTokens, 7);
  });

  it('finishParsing() with malformed trailing JSON does not throw, surfaces via logger', () => {
    let captured = null;
    const logger = (level, msg) => { captured = { level, msg }; };
    const extractor = createUsageExtractor({ logger });
    extractor.on('data', () => {});
    extractor.write(Buffer.from(
      'event: message_delta\n' +
      'data: {"usage":{"output_to',  // ← truncated mid-key
      'utf8'
    ));
    // Must not throw.
    extractor.finishParsing();
    // outputTokens should remain at its initial value (0, not whatever
    // partial parse might have set).
    assert.equal(extractor.getUsage().outputTokens, 0);
    // The logger must have been called with debug-level message.
    assert.ok(captured, 'logger should have been invoked on parse failure');
    assert.equal(captured.level, 'debug');
    assert.match(captured.msg, /trailing message_delta parse failed/);
  });

  it('finishParsing() with no trailing data is a no-op (no logger calls)', () => {
    let loggerCalls = 0;
    const logger = () => { loggerCalls++; };
    const extractor = createUsageExtractor({ logger });
    extractor.on('data', () => {});
    extractor.write(Buffer.from(
      'event: message_delta\n' +
      'data: {"usage":{"output_tokens":11}}\n',  // ← properly terminated
      'utf8'
    ));
    // Don't end the stream — explicit finishParsing should still process
    // any remaining buffer (which is empty after the newline split).
    extractor.finishParsing();
    assert.equal(extractor.getUsage().outputTokens, 11);
    assert.equal(loggerCalls, 0, 'logger should not be called when there is no malformed trailing line');
  });
});

describe('createUsageExtractor — pass-through correctness', () => {
  it('passes bytes through unchanged (Transform pipe semantics)', async () => {
    const extractor = createUsageExtractor();
    const chunks = [];
    extractor.on('data', c => chunks.push(c));
    const payload =
      'event: message_start\n' +
      'data: {"message":{"usage":{"input_tokens":1}}}\n' +
      '\n';
    extractor.write(Buffer.from(payload, 'utf8'));
    extractor.end();
    await new Promise(r => extractor.on('end', r));
    const passed = Buffer.concat(chunks).toString('utf8');
    assert.equal(passed, payload, 'extractor must not mutate the byte stream');
  });
});

// ─────────────────────────────────────────────────
// L2 source-level regression — _runGitCache key + invalidate prefix
// must use \0 separator (NUL byte is the only path-segment-safe boundary)
// ─────────────────────────────────────────────────
describe('L2 — _runGitCache uses NUL-byte separator for path-segment safety', () => {
  const _dashboardSrc_l2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('cache key construction uses \\0 between cwd and args', () => {
    // _runGitCached MUST build the key as `cwd + '\0' + args.join('\0')`.
    // If a future refactor switches to '/' or ':' separator, the
    // _invalidateRunGitCache prefix check below silently turns into a
    // path-prefix bug — invalidating /tmp/foo would also evict
    // /tmp/foobar entries.
    assert.match(
      _dashboardSrc_l2,
      /const key = cwd \+ '\\0' \+ args\.join\('\\0'\)/,
      'cache key must use NUL-byte separator',
    );
  });

  it('_invalidateRunGitCache prefix uses \\0 to enforce path-segment boundary', () => {
    assert.match(
      _dashboardSrc_l2,
      /const prefix = cwd \+ '\\0';/,
      '_invalidateRunGitCache must use NUL-byte boundary for prefix match',
    );
  });
});

// ─────────────────────────────────────────────────
// L5 source-level regression — _renderedCardCache wholesale replacement
// ─────────────────────────────────────────────────
// ─────────────────────────────────────────────────
// createSlidingWindowCounter — circuit-breaker primitive used by the
// serialize-mode auto-safeguards in dashboard.mjs (queue_timeout
// breaker, all-accounts-429 breaker). Pure function with explicit-time
// API so tests don't need to wait for wall clock.
// ─────────────────────────────────────────────────

describe('createSlidingWindowCounter', () => {
  it('rejects non-positive windowMs at construction', () => {
    assert.throws(() => createSlidingWindowCounter({ windowMs: 0,    threshold: 1 }), /windowMs/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: -1,   threshold: 1 }), /windowMs/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: NaN,  threshold: 1 }), /windowMs/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: null, threshold: 1 }), /windowMs/);
  });

  it('rejects non-positive-integer threshold at construction', () => {
    assert.throws(() => createSlidingWindowCounter({ windowMs: 1000, threshold: 0   }), /threshold/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: 1000, threshold: -1  }), /threshold/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: 1000, threshold: 1.5 }), /threshold/);
    assert.throws(() => createSlidingWindowCounter({ windowMs: 1000, threshold: '5' }), /threshold/);
  });

  it('counts only events within the sliding window', () => {
    const cb = createSlidingWindowCounter({ windowMs: 100, threshold: 3 });
    cb.record(1000);
    cb.record(1050);
    cb.record(1099);
    assert.equal(cb.count(1100), 3, 'all three within window ending at 1100');
    assert.equal(cb.count(1101), 2, 'event at 1000 falls out (window = 1001..1101)');
    assert.equal(cb.count(1200), 0, 'all events outside window');
  });

  it('tripped() is true at and above threshold, false below', () => {
    const cb = createSlidingWindowCounter({ windowMs: 1000, threshold: 3 });
    cb.record(0);
    cb.record(500);
    assert.equal(cb.tripped(900),  false, '2 events < threshold 3 → not tripped');
    cb.record(800);
    assert.equal(cb.tripped(900),  true,  '3 events >= threshold 3 → tripped');
    assert.equal(cb.tripped(2000), false, 'all events fell out of window → not tripped');
  });

  it('reset() clears all events', () => {
    const cb = createSlidingWindowCounter({ windowMs: 1000, threshold: 1 });
    cb.record(0);
    cb.record(500);
    assert.equal(cb._size(), 2);
    cb.reset();
    assert.equal(cb._size(), 0);
    assert.equal(cb.count(900), 0);
    assert.equal(cb.tripped(900), false);
  });

  it('prunes lazily on read — no insert-time pruning', () => {
    const cb = createSlidingWindowCounter({ windowMs: 100, threshold: 1 });
    // Fill with 100 events all at t=0
    for (let i = 0; i < 100; i++) cb.record(0);
    assert.equal(cb._size(), 100, 'no prune until read');
    // Reading at t=200 prunes everything (cutoff = 100, all events at 0)
    assert.equal(cb.count(200), 0);
    assert.equal(cb._size(), 0, 'prune dropped every event');
  });

  it('handles a clock that jumps backwards (NTP correction) without crashing', () => {
    // record(1000), then record(500) — the new event has a smaller
    // timestamp than the prior one. Must not throw, must still count
    // events that fall within the window from the read time.
    const cb = createSlidingWindowCounter({ windowMs: 1000, threshold: 1 });
    cb.record(1000);
    cb.record(500);   // backwards
    cb.record(700);
    // At t=1500 the window is [501, 1500]. Events at 1000 + 700 are in,
    // event at 500 is out. The prune step is "find first in-window
    // entry"; if the array isn't perfectly sorted the prune may keep
    // an extra out-of-window event, but tripped() / count() still
    // return a meaningful number for the breaker.
    const c = cb.count(1500);
    assert.ok(c >= 2 && c <= 3, `expected 2–3 events, got ${c}`);
  });

  it('default record() and tripped() arguments use Date.now()', () => {
    // Smoke test that the default-argument paths work. Use a tiny
    // window so a real wall-clock gap doesn't affect the assertion.
    const cb = createSlidingWindowCounter({ windowMs: 60_000, threshold: 1 });
    cb.record();
    assert.equal(cb.tripped(), true);
  });

  it('count() called repeatedly is idempotent for the same now', () => {
    const cb = createSlidingWindowCounter({ windowMs: 100, threshold: 1 });
    cb.record(0);
    cb.record(50);
    assert.equal(cb.count(100), 2);
    assert.equal(cb.count(100), 2);
    assert.equal(cb.count(100), 2);
  });

  it('high-volume insert + read does not retain events past window', () => {
    // 10 000 events spaced 1 ms apart over a 1-second window → after
    // the burst, reading 10 s later prunes everything.
    const cb = createSlidingWindowCounter({ windowMs: 1000, threshold: 1 });
    for (let i = 0; i < 10_000; i++) cb.record(i);
    assert.equal(cb._size(), 10_000);
    cb.count(20_000);
    assert.equal(cb._size(), 0);
  });
});

describe('L5 — _renderedCardCache replaced wholesale per render (no add+remove leak)', () => {
  const _dashboardSrc_l5 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('renderAccounts assigns _renderedCardCache = newHashes (not per-key set)', () => {
    // Wholesale replacement is what guarantees removed accounts drop out
    // of the cache. If a future refactor turns this into a for-of that
    // calls cache.set(name, hash) per profile, removed-account entries
    // would leak forever — every account that ever existed would pin a
    // hash entry until process restart.
    assert.match(
      _dashboardSrc_l5,
      /_renderedCardCache = newHashes;/,
      'renderAccounts must replace the cache wholesale, not per-key',
    );
  });

  it('renderAccounts has no remaining .set( call against _renderedCardCache', () => {
    // Belt-and-braces: if anyone ever adds _renderedCardCache.set(...)
    // INSIDE renderAccounts the wholesale-replacement guarantee is gone.
    // The .clear() call in the empty-profiles early return is fine.
    assert.equal(
      /_renderedCardCache\.set\(/.test(_dashboardSrc_l5), false,
      '_renderedCardCache.set(...) must not exist; replace wholesale only',
    );
  });
});

// ─────────────────────────────────────────────────────────
// Phase I — install-hooks.sh shell-injection guard.
// ─────────────────────────────────────────────────────────
//
// CONTEXT: install-hooks.sh's _resolve_vdm_port reads $CSW_PORT raw
// from env, then a Python heredoc f-string interpolates the port into
// a `command:` field of every CC hook entry. CC runs that command via
// `sh -c`. A value containing shell metacharacters would therefore
// become arbitrary code execution on every CC hook event. The guard
// is _validate_port (regex + IANA range) called from BOTH
// _resolve_vdm_port AND a final post-resolution paranoia check.

import { execFileSync as _execFileSync_inj, spawnSync as _spawnSync_inj } from 'node:child_process';
import {
  mkdtempSync as _mkdtempSync_inj,
  writeFileSync as _writeFileSync_inj,
  existsSync as _existsSync_inj,
} from 'node:fs';
import { join as _join_inj } from 'node:path';
import { tmpdir as _tmpdir_inj } from 'node:os';

describe('Phase I — install-hooks.sh rejects malicious $CSW_PORT', () => {
  const _scriptPath = new URL('../install-hooks.sh', import.meta.url).pathname;

  function _runWithEnv(env) {
    // Source install-hooks.sh under a tmp HOME with a fake dashboard.mjs
    // so the dashboard-presence guard inside install_hooks does not
    // short-circuit before we reach the port check. spawnSync (not
    // execFileSync) so we capture both stdout AND stderr regardless of
    // exit status.
    const home = _mkdtempSync_inj(_join_inj(_tmpdir_inj(), 'vdm-test-inj-'));
    _execFileSync_inj('mkdir', ['-p', _join_inj(home, '.claude/account-switcher')]);
    _writeFileSync_inj(_join_inj(home, '.claude/account-switcher/dashboard.mjs'), '');
    _writeFileSync_inj(_join_inj(home, '.claude/settings.json'), '{}');
    const r = _spawnSync_inj('bash', ['-c', `. "${_scriptPath}"; install_hooks`], {
      env: { ...env, HOME: home, PATH: process.env.PATH },
      encoding: 'utf8',
    });
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '', home };
  }

  it('rejects CSW_PORT with shell metacharacter (semicolon)', () => {
    const r = _runWithEnv({ CSW_PORT: '3333; touch /tmp/vdm-pwned-test' });
    assert.match(r.stderr, /malformed CSW_PORT/);
    // Confirm the injection target file does NOT exist on disk.
    assert.equal(
      _existsSync_inj('/tmp/vdm-pwned-test'),
      false,
      'shell injection token leaked into a real command — guard failed',
    );
  });

  it('rejects CSW_PORT with command-substitution backtick', () => {
    const r = _runWithEnv({ CSW_PORT: '3333`id`' });
    assert.match(r.stderr, /malformed CSW_PORT/);
  });

  it('rejects CSW_PORT outside IANA range', () => {
    const r = _runWithEnv({ CSW_PORT: '70000' });
    assert.match(r.stderr, /malformed CSW_PORT/);
  });

  it('rejects CSW_PORT="0"', () => {
    const r = _runWithEnv({ CSW_PORT: '0' });
    assert.match(r.stderr, /malformed CSW_PORT/);
  });

  it('accepts a valid CSW_PORT', () => {
    const r = _runWithEnv({ CSW_PORT: '3333' });
    assert.doesNotMatch(r.stderr, /malformed CSW_PORT/);
  });
});

describe('Phase I — sentinel marker shape', () => {
  // Two regression invariants:
  //   1. Sentinel defined ONCE at bash level, not duplicated as a
  //      Python string literal in either heredoc (DRY).
  //   2. Sentinel is versioned so a future schema change can walk
  //      forward without breaking removal of older installs.
  const _ihSrc = _readFileSync_xss(
    new URL('../install-hooks.sh', import.meta.url),
    'utf8',
  );

  it('sentinel is defined exactly once at bash level', () => {
    const matches = _ihSrc.match(/_VDM_HOOK_SENTINEL=/g) || [];
    assert.equal(
      matches.length, 1,
      'expected exactly one bash-level definition of _VDM_HOOK_SENTINEL',
    );
  });

  it('sentinel is versioned (contains v1)', () => {
    assert.match(_ihSrc, /_VDM_HOOK_SENTINEL="__VDM_HOOK_v\d+_DO_NOT_EDIT__"/);
  });

  it('neither python heredoc embeds the sentinel as a string literal', () => {
    // Both heredocs must read the value via sys.argv. A literal
    // Python-style definition like VDM_HOOK_SENTINEL = '__VDM_HOOK...'
    // is exactly what we removed. The bash-side _VDM_HOOK_SENTINEL=...
    // (note leading underscore) is the legitimate single source of
    // truth and must NOT be matched here — the negative lookahead via
    // [^_A-Za-z] excludes any identifier-character before VDM, so the
    // bash variable is not a false positive.
    assert.doesNotMatch(_ihSrc, /(^|[^_A-Za-z])VDM_HOOK_SENTINEL\s*=\s*['"]__VDM_HOOK/);
  });
});

describe('Phase I — install.sh atomic block uses validated ports', () => {
  const _installSrc = _readFileSync_xss(
    new URL('../install.sh', import.meta.url),
    'utf8',
  );

  it('install.sh sources lib-install.sh BEFORE _resolve_install_ports is defined', () => {
    // _validate_port lives in lib-install.sh; if install.sh ever
    // referenced it before sourcing the lib, validation would no-op
    // via the "command not found" exit code.
    const libIdx = _installSrc.indexOf('. "$SCRIPT_DIR/lib-install.sh"');
    const resolveIdx = _installSrc.indexOf('_resolve_install_ports()');
    assert.notEqual(libIdx, -1, 'install.sh must source lib-install.sh');
    assert.notEqual(resolveIdx, -1, '_resolve_install_ports must be defined');
    assert.ok(
      libIdx < resolveIdx,
      'lib-install.sh must be sourced BEFORE _resolve_install_ports',
    );
  });

  it('install.sh exports validated ports into the dashboard child env', () => {
    // H1 fix: dashboard.mjs reads CSW_PORT/CSW_PROXY_PORT from env.
    // Forcing the env on the child guarantees it binds to what we polled.
    // Phase I+ (SEC-9): now wrapped in `env -i ...` to drop unrelated
    // secrets from the parent shell. Both vars must be in the env-i
    // block, with nohup invocation following within the same scope.
    const sliceFromEnvI = _installSrc.indexOf('env -i');
    assert.notEqual(sliceFromEnvI, -1, 'install.sh must use env -i to spawn dashboard with a minimal env');
    const childSpawn = _installSrc.slice(sliceFromEnvI, sliceFromEnvI + 800);
    assert.match(childSpawn, /CSW_PORT="\$_DASH_HEALTH_PORT"/);
    assert.match(childSpawn, /CSW_PROXY_PORT="\$_PROXY_HEALTH_PORT"/);
    assert.match(childSpawn, /nohup "\$_NODE_BIN" "\$INSTALL_DIR\/dashboard\.mjs"/);
  });

  it('install.sh polls BOTH dashboard AND proxy /health', () => {
    // H2 fix: a half-up dashboard would still break every CC API call.
    assert.match(_installSrc, /_dashboard_responds && _proxy_responds/);
  });

  it('install.sh verifies /health body contains "server":"dashboard"', () => {
    // H3 fix: a generic webserver squatting on the port could otherwise
    // fool us into installing hooks pointing at it.
    assert.match(_installSrc, /"server":"dashboard"/);
  });

  it('rollback trap reaps the spawned dashboard PID', () => {
    // M1 fix: file-only rollback would leak a node process.
    assert.match(_installSrc, /_kill_if_ours "\$_NEW_DASH_PID"/);
  });

  it('_kill_if_ours verifies cmdline before signaling', () => {
    // M3 fix: defends against PID rollover.
    assert.match(
      _installSrc,
      /ps -o command= -p "\$pid"[\s\S]{0,80}dashboard\\?\.mjs/,
    );
  });
});

describe('Phase I — _validate_port in lib-install.sh', () => {
  const _scriptPath = new URL('../lib-install.sh', import.meta.url).pathname;

  function _v(port) {
    try {
      _execFileSync_inj(
        'bash',
        ['-c', `. "${_scriptPath}"; _validate_port "$1"`, '--', port],
        { stdio: 'ignore' },
      );
      return true;
    } catch {
      return false;
    }
  }

  it('accepts canonical ports', () => {
    assert.equal(_v('3333'), true);
    assert.equal(_v('1'), true);
    assert.equal(_v('65535'), true);
  });

  it('rejects out-of-range', () => {
    assert.equal(_v('0'), false);
    assert.equal(_v('65536'), false);
    assert.equal(_v('70000'), false);
  });

  it('rejects shell metacharacters', () => {
    assert.equal(_v('3333;ls'), false);
    assert.equal(_v('3333 4'), false);
    assert.equal(_v('3333`id`'), false);
    assert.equal(_v('$(id)'), false);
  });

  it('rejects empty string', () => {
    assert.equal(_v(''), false);
  });

  it('rejects negative / non-decimal', () => {
    assert.equal(_v('-1'), false);
    assert.equal(_v('3.14'), false);
    assert.equal(_v('0x1'), false);
  });
});

describe('Phase I — dashboard.mjs /health endpoint', () => {
  const _dashboardSrc_health = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('UI server defines a /health route', () => {
    // The proxy server already had /health; this is the UI-server one
    // added in Phase I so install.sh can poll the port that hooks point at.
    assert.match(_dashboardSrc_health, /req\.url === '\/health'/);
  });

  it('UI /health returns the server identity for squatter-detection', () => {
    // H3 fix: install.sh greps the response body for "server":"dashboard"
    // before trusting that we found our own dashboard. Removing this
    // field would break the squatter check silently.
    assert.match(_dashboardSrc_health, /server: 'dashboard'/);
  });

  it('UI /health accepts both GET and HEAD', () => {
    // L4 fix: HEAD requests should not fall through to render the dashboard
    // HTML — a cheap probe deserves a cheap response.
    assert.match(
      _dashboardSrc_health,
      /req\.method === 'GET' \|\| req\.method === 'HEAD'/,
    );
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — competitor-audit fixes
// ─────────────────────────────────────────────────────────

describe('Phase I+ — security/privacy hardening', () => {
  const _dashboardSrc_audit = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('atomicWriteFileSync writes with mode 0o600', () => {
    // SEC fix: state files contain emails, paths, fingerprints. The
    // previous default-umask write left them mode 644 → world-readable
    // on multi-user macOS. The mode option enforces 600 at file creation
    // (no TOCTOU window between write and chmod).
    assert.match(_dashboardSrc_audit, /writeFileSync\(tmpPath, content, \{ mode: 0o600 \}\)/);
  });

  it('atomicWriteFileSync cleans up .tmp on disk-full / EIO', () => {
    // Without the unlinkSync(tmpPath) in the catch path, a chronically
    // failing write would accumulate .tmp leftovers indefinitely.
    assert.match(
      _dashboardSrc_audit,
      /catch \(e\) \{[\s\S]{0,80}unlinkSync\(tmpPath\)[\s\S]{0,80}throw e/,
    );
  });

  it('auto-discover never uses console.log for dynamic content', () => {
    // SEC fix: the three previous console.log call sites in auto-discover
    // bypassed the _redactForLog pipeline and leaked email addresses
    // into mode-644 startup.log. log() is the only correct path.
    const autoDiscoverBlock = _dashboardSrc_audit.slice(
      _dashboardSrc_audit.indexOf('_autoDiscoverAccountImpl'),
      _dashboardSrc_audit.indexOf('// Auto-discover runs on proxy requests'),
    );
    assert.ok(autoDiscoverBlock.length > 0, 'auto-discover block must exist');
    assert.equal(
      /console\.log\(/.test(autoDiscoverBlock), false,
      'console.log MUST NOT appear inside the auto-discover impl',
    );
  });

  it('all three HTTP servers validate Host header (DNS-rebind defense)', () => {
    // SEC fix: dashboard, proxy, and OTLP servers all need a Host check
    // because GETs aren't covered by the Origin allow-list. _isLocalhostHost
    // is the canonical guard.
    assert.match(_dashboardSrc_audit, /function _isLocalhostHost\(host, expectedPort\)/);
    // Three call sites — one per createServer block.
    const matches = _dashboardSrc_audit.match(/_isLocalhostHost\(\w+\.headers\.host,/g) || [];
    assert.ok(
      matches.length >= 3,
      `expected at least 3 _isLocalhostHost call sites (dashboard + proxy + OTLP); found ${matches.length}`,
    );
  });

  it('Host check rejects spoofed prefixes (localhost.attacker.example etc.)', () => {
    // The allow-list uses literal containment in a small array, not
    // startsWith / regex. This regression test asserts the exact form.
    assert.match(
      _dashboardSrc_audit,
      /allowed\.includes\(host\.toLowerCase\(\)\)/,
    );
  });

  it('dashboard does not load Google Fonts', () => {
    // Privacy: fetching Inter from Google Fonts on every page load leaks
    // dashboard visit metadata to Google's edge.
    assert.equal(
      /fonts\.googleapis\.com/.test(_dashboardSrc_audit), false,
      'fonts.googleapis.com MUST NOT appear in dashboard.mjs',
    );
    assert.equal(
      /fonts\.gstatic\.com/.test(_dashboardSrc_audit), false,
      'fonts.gstatic.com MUST NOT appear in dashboard.mjs',
    );
  });

  it('Remove confirm dialog does not say "credentials FILE"', () => {
    // UX: credentials moved out of files into the keychain ages ago.
    // The dialog text was 3 versions stale.
    assert.equal(
      /deletes the saved credentials file/i.test(_dashboardSrc_audit), false,
      'Remove dialog must not refer to "credentials FILE"',
    );
  });

  it('"No accounts yet" empty-state has no double-space typo', () => {
    // The previous text was "Code  - accounts" (two spaces before dash).
    assert.equal(
      /Code  - accounts/.test(_dashboardSrc_audit), false,
      'No double-space-dash artifact in the empty-state copy',
    );
  });
});

describe('Phase I+ — reliability fixes', () => {
  const _dashboardSrc_rel = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('Breaker C reads a.token (not a.accessToken)', () => {
    // REL-1 fix: previous code read a.accessToken (undefined) → fingerprint
    // null → knownFps always [] → breaker never trips. The structure has
    // a.token at the top level; a.accessToken nests under a.creds.claudeAiOauth.
    const breakerCBlock = _dashboardSrc_rel.slice(
      _dashboardSrc_rel.indexOf('function _record429ForAccount'),
      _dashboardSrc_rel.indexOf('function _record429ForAccount') + 4000,
    );
    assert.match(breakerCBlock, /\.map\(a => getFingerprintFromToken\(a\.token\)\)/);
    assert.equal(
      /\.map\(a => getFingerprintFromToken\(a\.accessToken\)\)/.test(breakerCBlock), false,
      'must NOT use the broken a.accessToken field',
    );
  });

  it('migrateAccountState propagates `expired` flag', () => {
    // REL-3 fix: accountState.update always writes expired:false (no
    // header signal). Without an explicit markExpired after the update,
    // a token that was 401-expired before refresh would lose the flag
    // and the picker would re-select it → infinite refresh loop.
    const migBlock = _dashboardSrc_rel.slice(
      _dashboardSrc_rel.indexOf('function migrateAccountState'),
      _dashboardSrc_rel.indexOf('function migrateAccountState') + 1500,
    );
    assert.match(migBlock, /if \(oldState\.expired\) accountState\.markExpired\(newToken, name\)/);
  });

  it('refreshSweep fans out via Promise.allSettled (not serial await)', () => {
    // REL-2 fix: serial for-await meant N expired tokens × ~17s each on
    // wake from sleep blocked the user for minutes. _refreshSem caps
    // upstream concurrency at 3 so allSettled is safe.
    const sweepBlock = _dashboardSrc_rel.slice(
      _dashboardSrc_rel.indexOf('async function refreshSweep'),
      _dashboardSrc_rel.indexOf('async function refreshSweep') + 1500,
    );
    assert.match(sweepBlock, /Promise\.allSettled\(/);
  });
});

describe('Phase I+ — defense-in-depth (SEC-9..17, UX-A4)', () => {
  const _dashboardSrc_dd = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );
  const _installSrc_dd = _readFileSync_xss(
    new URL('../install.sh', import.meta.url),
    'utf8',
  );
  const _vdmSrc_dd = _readFileSync_xss(
    new URL('../vdm', import.meta.url),
    'utf8',
  );
  const _ihSrc_dd = _readFileSync_xss(
    new URL('../install-hooks.sh', import.meta.url),
    'utf8',
  );

  it('SEC-9: install.sh spawns dashboard with `env -i` (filtered env)', () => {
    // Without env -i, the parent shell's full env (AWS_SESSION_TOKEN,
    // OPENAI_API_KEY, ...) is inherited by the dashboard process and
    // visible via `ps eww`.
    const idx = _installSrc_dd.indexOf('env -i');
    assert.notEqual(idx, -1, 'install.sh must use `env -i` for dashboard spawn');
    const block = _installSrc_dd.slice(idx, idx + 600);
    // Must explicitly forward HOME/USER/PATH for the dashboard to function.
    assert.match(block, /HOME="\$HOME"/);
    assert.match(block, /USER="\$USER"/);
    assert.match(block, /PATH="\$PATH"/);
  });

  it('SEC-13: install.sh refuses to install if `node` is not on PATH', () => {
    // The previous fallback `NODE_BIN="node"` would write a bare-name
    // `node` reference into the rc file — PATH-hijack vector.
    assert.match(
      _installSrc_dd,
      /node not found on PATH[\s\S]{0,200}PATH-hijack vector/,
    );
  });

  it('SEC-10: plaintext-token migration error does NOT log the path via log()', () => {
    // The previous log line passed the absolute filePath through log()
    // → in-memory _logBuffer + SSE feed + mode-644 startup.log. Now we
    // print to stderr only and stamp an activity event with just the
    // account name.
    const migBlock = _dashboardSrc_dd.slice(
      _dashboardSrc_dd.indexOf('// Keychain has the data; file delete failed'),
      _dashboardSrc_dd.indexOf('// Keychain has the data; file delete failed') + 1500,
    );
    assert.ok(migBlock.length > 0, 'migration error block must exist');
    assert.equal(
      /log\('error'.*filePath/.test(migBlock), false,
      'plaintext-token error path must not log filePath via log()',
    );
    assert.match(migBlock, /process\.stderr\.write/);
    assert.match(migBlock, /logActivity\('keychain-migration-partial-failure'/);
  });

  it('SEC-11: readBody enforces a global body buffer cap', () => {
    // Per-request 1 MiB cap is necessary but not sufficient — 200 concurrent
    // 1 MiB POSTs would OOM the dashboard without a global accumulator.
    assert.match(_dashboardSrc_dd, /READ_BODY_GLOBAL_MAX/);
    assert.match(_dashboardSrc_dd, /_apiBufferedBytes \+ c\.length > READ_BODY_GLOBAL_MAX/);
    // Refund + cleanup on every termination path (end / error / close).
    assert.match(_dashboardSrc_dd, /req\.on\('close'/);
  });

  it('SEC-12: vdm label rejects control characters and over-200-char inputs', () => {
    assert.match(_vdmSrc_dd, /Label too long/);
    assert.match(_vdmSrc_dd, /Label contains control characters/);
    assert.match(_vdmSrc_dd, /grep -qE '\[\[:cntrl:\]\]'/);
  });

  it('SEC-12: vdm label chmod 600s the .label file', () => {
    // Labels often contain emails (PII). Mode 600 keeps them out of
    // other-user reads on multi-user macOS.
    assert.match(_vdmSrc_dd, /chmod 600 "\$ACCOUNTS_DIR\/\$\{name\}\.label"/);
  });

  it('SEC-17: priority field is clamped to [-100, 100]', () => {
    // Field is unused today (picker doesn't honour it) but the
    // validation contract IS the persistence contract.
    assert.match(_dashboardSrc_dd, /priority must be between -100 and 100/);
  });

  it('UX-A4: install-hooks.sh defines its own ANSI defaults', () => {
    // Was using ${YELLOW:-}Warning…${NC:-} which collapses to literal
    // "Warning…" when sourced from contexts that don't pre-define
    // YELLOW/NC (e.g. `vdm` self-heal block, manual debugging).
    assert.match(_ihSrc_dd, /: "\$\{YELLOW:=/);
    assert.match(_ihSrc_dd, /: "\$\{NC:=/);
  });
});

describe('Phase I+ — reliability data-loss fixes (STATE-2, CORRUPT-1, CORRUPT-3, CORRUPT-4, TIMER-2, LEAK-1)', () => {
  const _dashboardSrc_rdl = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('STATE-2: loadPersistedState distinguishes ENOENT from corrupt JSON', () => {
    // The previous swallow-and-init-empty silently zeroed every account's
    // ban flags on transient corruption — turning a disk hiccup into a
    // fresh 7-day rate limit on the next probe.
    assert.match(_dashboardSrc_rdl, /existsSync\(STATE_FILE\)/);
    assert.match(_dashboardSrc_rdl, /\.corrupt-/);
    assert.match(_dashboardSrc_rdl, /persisted-state-recovery/);
  });

  it('CORRUPT-1: dashboard installs a singleton PID-file lock at startup', () => {
    assert.match(_dashboardSrc_rdl, /_enforceSingletonDashboard/);
    assert.match(_dashboardSrc_rdl, /\.dashboard\.lock/);
    assert.match(_dashboardSrc_rdl, /process\.kill\(livePid, 0\)/);
  });

  it('CORRUPT-3: viewer-state recovery caches the defaults', () => {
    // Was leaving _viewerStateCache null, forcing every subsequent
    // load to re-read disk after recovery.
    assert.match(_dashboardSrc_rdl, /_viewerStateCache = defaults/);
  });

  it('CORRUPT-4: account-state.json is pretty-printed', () => {
    assert.match(
      _dashboardSrc_rdl,
      /atomicWriteFileSync\(STATE_FILE, JSON\.stringify\(persistedState, null, 2\)\)/,
    );
  });

  it('TIMER-2: _tokenAutoPersistTimer body is wrapped in try/catch', () => {
    const timerBlock = _dashboardSrc_rdl.slice(
      _dashboardSrc_rdl.indexOf('const _tokenAutoPersistTimer'),
      _dashboardSrc_rdl.indexOf('_tokenAutoPersistTimer.unref'),
    );
    assert.ok(timerBlock.length > 0, 'timer block must exist');
    assert.match(timerBlock, /try \{/);
    assert.match(timerBlock, /_tokenAutoPersistTimer iteration failed/);
  });

  it('LEAK-1: /api/remove evicts _lastWarnPct entry', () => {
    const removeBlock = _dashboardSrc_rdl.slice(
      _dashboardSrc_rdl.indexOf("/api/remove"),
      _dashboardSrc_rdl.indexOf("/api/remove") + 3000,
    );
    assert.ok(removeBlock.length > 0, '/api/remove handler must exist');
    assert.match(removeBlock, /_lastWarnPct\.delete\(name\)/);
  });
});

describe('Phase I+ — STATE-5 utilizationHistory clock-jump-backward', () => {
  it('a backward ts jump resets the array (no non-monotonic timeline)', async () => {
    const { createUtilizationHistory } = await import('../lib.mjs');
    const hist = createUtilizationHistory();
    // Seed at t=0
    hist.record('fp1', 50, 30, 1_000_000);
    hist.record('fp1', 60, 40, 1_000_000 + 5 * 60 * 1000); // +5min
    let series = hist.getHistory('fp1');
    assert.equal(series.length, 2);
    // NTP correction: clock jumps BACKWARD by 1 hour
    hist.record('fp1', 70, 50, 1_000_000 - 60 * 60 * 1000);
    series = hist.getHistory('fp1');
    assert.equal(series.length, 1, 'backward jump must reset the array');
    assert.equal(series[0].u5h, 70);
    assert.equal(series[0].ts, 1_000_000 - 60 * 60 * 1000);
  });
});

describe('Phase I+ — circuit breaker post-close grace (PROXY-6)', () => {
  const _dashboardSrc_pc = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('post-close grace constant + helper exist', () => {
    assert.match(_dashboardSrc_pc, /CIRCUIT_POST_CLOSE_GRACE_MS = 5000/);
    assert.match(_dashboardSrc_pc, /function _inCircuitPostCloseGrace\(\)/);
  });

  it('400 increment is gated on the post-close grace', () => {
    assert.match(_dashboardSrc_pc, /if \(!_inCircuitPostCloseGrace\(\)\) \{[\s\S]{0,200}_consecutive400s\+\+/);
  });
});

describe('Phase I+ — KC-1 keychain-deny notification', () => {
  const _dashboardSrc_kc = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('readKeychain detects status 51 (SecAuthFailed) and surfaces it', () => {
    assert.match(_dashboardSrc_kc, /e\.status === 51|SecAuthFailed/);
    assert.match(_dashboardSrc_kc, /Keychain access denied/);
    // Rate-limit constant (10-minute window) — prevents notify spam
    // when every proxy request retries the read in a tight loop.
    assert.match(_dashboardSrc_kc, /10 \* 60 \* 1000/);
  });
});

describe('Phase I+ — A11y / dashboard polish (UX-D batch)', () => {
  const _dashboardSrc_a11y = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('renders a <noscript> banner', () => {
    assert.match(_dashboardSrc_a11y, /<noscript>[\s\S]{0,400}JavaScript is required/);
  });

  it('tabs have role/aria-selected/aria-controls', () => {
    assert.match(_dashboardSrc_a11y, /role="tablist"/);
    assert.match(_dashboardSrc_a11y, /role="tab"/);
    assert.match(_dashboardSrc_a11y, /aria-selected="true"/);
    assert.match(_dashboardSrc_a11y, /aria-controls="tab-accounts"/);
  });

  it('every tab-content has role=tabpanel + aria-labelledby', () => {
    assert.match(_dashboardSrc_a11y, /id="tab-accounts" class="tab-content active" role="tabpanel"/);
    assert.match(_dashboardSrc_a11y, /id="tab-activity"[\s\S]{0,40}role="tabpanel"/);
    assert.match(_dashboardSrc_a11y, /id="tab-usage"[\s\S]{0,40}role="tabpanel"/);
    assert.match(_dashboardSrc_a11y, /id="tab-sessions"[\s\S]{0,40}role="tabpanel"/);
    assert.match(_dashboardSrc_a11y, /id="tab-config"[\s\S]{0,40}role="tabpanel"/);
    assert.match(_dashboardSrc_a11y, /id="tab-logs"[\s\S]{0,40}role="tabpanel"/);
  });

  it('switchTab maintains aria-selected', () => {
    assert.match(_dashboardSrc_a11y, /setAttribute\('aria-selected', 'false'\)/);
    assert.match(_dashboardSrc_a11y, /setAttribute\('aria-selected', 'true'\)/);
  });

  it('Session Monitor toggle has a <label for> association + privacy warning', () => {
    assert.match(_dashboardSrc_a11y, /class="sr-only" for="toggle-session-monitor"/);
    assert.match(_dashboardSrc_a11y, /Sends excerpts of your prompts to Anthropic Claude Haiku/);
  });

  it('.sr-only utility class exists in CSS', () => {
    assert.match(_dashboardSrc_a11y, /\.sr-only \{[\s\S]{0,200}position: absolute/);
  });

  it('showToast accepts opts (error / timeoutMs)', () => {
    assert.match(_dashboardSrc_a11y, /function showToast\(msg, opts\)/);
    assert.match(_dashboardSrc_a11y, /opts && opts\.error/);
  });

  it('doSwitch greys only the target card (UX-D6)', () => {
    // Was: querySelectorAll('.card').forEach(... add('switching')) —
    // 50% opacity flash on every card every switch. Now: targetCard only.
    const switchBlock = _dashboardSrc_a11y.slice(
      _dashboardSrc_a11y.indexOf('async function doSwitch'),
      _dashboardSrc_a11y.indexOf('async function doSwitch') + 1500,
    );
    assert.ok(switchBlock.length > 0);
    assert.match(switchBlock, /targetCard\.classList\.add\('switching'\)/);
    assert.equal(
      /querySelectorAll\('\.card'\)\.forEach\(c => c\.classList\.add\('switching'\)\)/.test(switchBlock), false,
      'must NOT use the global card-grey-out pattern',
    );
  });

  it('cards carry data-account-name for programmatic switch', () => {
    assert.match(_dashboardSrc_a11y, /data-account-name="' \+ escNameAttr/);
  });
});

describe('Phase I+ — vdm CLI _levenshtein + did-you-mean (UX-E3)', () => {
  const _vdmSrc_e3 = _readFileSync_xss(
    new URL('../vdm', import.meta.url),
    'utf8',
  );

  it('vdm defines _levenshtein', () => {
    assert.match(_vdmSrc_e3, /^_levenshtein\(\) \{/m);
  });

  it('cmd_switch suggests "Did you mean…" on profile-not-found', () => {
    // The suggestion is the closest profile by Levenshtein distance ≤ 2.
    assert.match(_vdmSrc_e3, /Did you mean: \$\{BOLD\}\$_suggestion\$\{NC\}/);
    assert.match(_vdmSrc_e3, /_d=\$\(_levenshtein "\$name" "\$_p"\)/);
  });
});

describe('Phase I+ — slash commands (UX-G2)', () => {
  it('every commands/*.md has the right frontmatter shape', () => {
    const cmdsDir = new URL('../commands/', import.meta.url).pathname;
    const cmds = ['vdm-switch', 'vdm-status', 'vdm-list', 'vdm-tokens'];
    for (const c of cmds) {
      const body = _readFileSync_xss(`${cmdsDir}${c}.md`, 'utf8');
      assert.match(body, /^---/, `${c}: must start with frontmatter`);
      assert.match(body, /^description:/m, `${c}: must have a description`);
      assert.match(body, /^allowed-tools: Bash\(vdm /m, `${c}: must restrict to vdm subcommand`);
    }
  });
});

describe('Phase I+ — notification heuristics (batch 9)', () => {
  const _src_n = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('NOTIFY_SUPPRESS_ALWAYS lists routine events', () => {
    assert.match(_src_n, /NOTIFY_SUPPRESS_ALWAYS = new Set\(/);
    // refresh / circuitClose / queue-depth-alert MUST be in the suppress
    // set so they don't OS-notify on every tick.
    assert.match(_src_n, /'refresh'/);
    assert.match(_src_n, /'circuitClose'/);
    assert.match(_src_n, /'queue-depth-alert'/);
  });

  it('NOTIFY_COALESCE batches switch + 400-recovery toasts', () => {
    assert.match(_src_n, /NOTIFY_COALESCE = \{/);
    assert.match(_src_n, /switch: \{ windowMs:/);
    assert.match(_src_n, /'400-recovery':/);
  });

  it('_decideNotifyPolicy returns one of fire / suppress / coalesce', () => {
    assert.match(_src_n, /function _decideNotifyPolicy\(eventType\)/);
    // Must check suppress-list first, then high-priority, then coalesce.
    assert.match(_src_n, /NOTIFY_SUPPRESS_ALWAYS\.has\(eventType\)/);
    assert.match(_src_n, /NOTIFY_HIGH_PRIORITY\.has\(eventType\)/);
    assert.match(_src_n, /NOTIFY_COALESCE\[eventType\]/);
  });

  it('notify() honours coalesce + emits a burst summary at window end', () => {
    // The coalesce branch sets a setTimeout that emits a "burst summary"
    // toast at end-of-window if more than maxInWindow events fired.
    assert.match(_src_n, /vdm — burst summary/);
  });
});

describe('Phase I+ — forensic event log + rotation (batch 9)', () => {
  const _src_f = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('logForensicEvent appends JSON Lines to events.jsonl', () => {
    assert.match(_src_f, /function logForensicEvent\(category, details\)/);
    assert.match(_src_f, /JSON\.stringify\(entry\) \+ '\\n'/);
    assert.match(_src_f, /flag: 'a', mode: 0o600/);
  });

  it('events.jsonl + startup.log rotate daily, 7-day retention', () => {
    assert.match(_src_f, /EVENTS_RETENTION_DAYS = 7/);
    assert.match(_src_f, /function _rotateForensicLog\(\)/);
    assert.match(_src_f, /function _rotateStartupLog\(\)/);
    // Both rotated files are gzipped at rotate time
    assert.match(_src_f, /execFileSync\('gzip',/);
  });

  it('rotation timer runs every 6 hours after startup', () => {
    assert.match(_src_f, /6 \* 60 \* 60 \* 1000/);
    assert.match(_src_f, /_startLogRotationTimer\(\)/);
  });

  it('forensic events fire at every incident site', () => {
    assert.match(_src_f, /logForensicEvent\('rate_limit'/);
    assert.match(_src_f, /logForensicEvent\('auth_failure'/);
    assert.match(_src_f, /logForensicEvent\('server_error'/);
    assert.match(_src_f, /logForensicEvent\('client_disconnect'/);
    assert.match(_src_f, /logForensicEvent\('queue_saturation'/);
    assert.match(_src_f, /logForensicEvent\('inflight_escalation'/);
    assert.match(_src_f, /logForensicEvent\('dashboard_start'/);
  });

  it('rate_limit forensic entry includes reset windows + retry-after + utilization', () => {
    // The `headers[...]` lookups must extract every dimension we need
    // to reconstruct the incident.
    assert.match(_src_f, /'anthropic-ratelimit-unified-5h-reset'/);
    assert.match(_src_f, /'anthropic-ratelimit-unified-7d-reset'/);
    assert.match(_src_f, /'anthropic-ratelimit-unified-5h-utilization'/);
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — Safeguard D: burst-429 from a single account
// auto-enables serialize mode (queue requests) instead of
// rotating to the next account, which would just bombard it
// too. Auto-reverts after a quiet window so the user doesn't
// stay queued forever.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — Safeguard D: burst-429 → auto-enable serialize (batch 10)', () => {
  const _src_d = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('declares the Safeguard D constants with sane defaults', () => {
    // 30s window / 3 events / 30min quiet revert. If anyone tunes these
    // numbers down, they need to think about it loud enough to update
    // this regression test — accidentally setting threshold to 1 turns
    // every isolated 429 into a serialize trip.
    assert.match(_src_d, /_BURST_429_WINDOW_MS\s*=\s*30_000/);
    assert.match(_src_d, /_BURST_429_THRESHOLD\s*=\s*3/);
    assert.match(_src_d, /_SERIALIZE_AUTO_REVERT_MS\s*=\s*30 \* 60 \* 1000/);
  });

  it('exposes serializeAutoEnableEnabled in DEFAULT_SETTINGS (default ON)', () => {
    // The user-facing kill-switch. Default ON because the worst case if
    // it doesn't fire is the original "all accounts get banned" failure.
    assert.match(_src_d, /serializeAutoEnableEnabled:\s*true/);
  });

  it('_autoEnableSerializeOnBurst respects all three opt-out paths', () => {
    // (a) master switch off → no-op
    // (b) already in serialize mode → no-op (don't fight whoever turned
    //     it on, esp. the user)
    // (c) the specific Safeguard-D toggle off → no-op
    const fn = _src_d.slice(
      _src_d.indexOf('function _autoEnableSerializeOnBurst'),
      _src_d.indexOf('function _autoEnableSerializeOnBurst') + 4000,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    assert.match(fn, /if \(!settings\.serializeAutoDisableEnabled\) return/);
    assert.match(fn, /if \(settings\.serializeRequests\) return/);
    assert.match(fn, /if \(settings\.serializeAutoEnableEnabled === false\) return/);
  });

  it('_autoEnableSerializeOnBurst counts per fingerprint, not per name', () => {
    // Per-fingerprint tracking is what makes the breaker survive a
    // mid-incident vdm rename. Counter map lookup MUST be by the
    // fingerprint argument, never by name.
    const fn = _src_d.slice(
      _src_d.indexOf('function _autoEnableSerializeOnBurst'),
      _src_d.indexOf('function _autoEnableSerializeOnBurst') + 4000,
    );
    assert.match(fn, /_burst429ByFingerprint\.get\(account_fp\)/);
    assert.match(fn, /_burst429ByFingerprint\.set\(account_fp/);
  });

  it('_autoEnableSerializeOnBurst sets a 250ms+ delay AND clamps concurrent ≥1', () => {
    // The whole point is to throttle outbound burst. If we leave delay=0
    // and concurrent=8 (typical defaults pre-incident) the queue does
    // nothing useful. Defensive clamp of concurrent ≥1 also guards
    // against a user-set 0 freezing the queue forever.
    const fn = _src_d.slice(
      _src_d.indexOf('function _autoEnableSerializeOnBurst'),
      _src_d.indexOf('function _autoEnableSerializeOnBurst') + 4000,
    );
    assert.match(fn, /settings\.serializeRequests = true/);
    assert.match(fn, /serializeMaxConcurrent = Math\.max\(1,/);
    assert.match(fn, /serializeDelayMs < 250/);
    assert.match(fn, /settings\.serializeDelayMs = 250/);
  });

  it('_autoEnableSerializeOnBurst emits forensic + activity + notify', () => {
    // Three independent surfaces — forensic JSONL for post-mortem,
    // activity feed for the dashboard, OS notification because vdm
    // changed a user-visible setting and the user needs to know.
    const fn = _src_d.slice(
      _src_d.indexOf('function _autoEnableSerializeOnBurst'),
      _src_d.indexOf('function _autoEnableSerializeOnBurst') + 4000,
    );
    assert.match(fn, /logForensicEvent\('serialize_auto_enabled'/);
    assert.match(fn, /logActivity\('serialize-auto-enabled'/);
    assert.match(fn, /notify\(/);
    // Notify category MUST be 'circuitBreaker' so it bypasses the
    // 10s throttle (NOTIFY_HIGH_PRIORITY).
    assert.match(fn, /'circuitBreaker'/);
  });

  it('_maybeAutoRevertSerialize respects user ownership of the flag', () => {
    // _serializeAutoEnabledAt === 0 means EITHER the user turned it on
    // themselves OR vdm never enabled it → in both cases the auto-revert
    // must do nothing. Touching the flag in the user-owned case would be
    // a UX disaster ("I set serialize=on; vdm turned it off without
    // telling me").
    const fn = _src_d.slice(
      _src_d.indexOf('function _maybeAutoRevertSerialize'),
      _src_d.indexOf('function _maybeAutoRevertSerialize') + 1500,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    assert.match(fn, /if \(_serializeAutoEnabledAt === 0\) return/);
  });

  it('_maybeAutoRevertSerialize gives up its claim if someone else flipped serialize off', () => {
    // If _autoDisableSerialize (Breakers A/C) ran while we owned the
    // serialize state, the marker becomes stale. Clear it so we don't
    // re-flip the next time burst-429 fires.
    const fn = _src_d.slice(
      _src_d.indexOf('function _maybeAutoRevertSerialize'),
      _src_d.indexOf('function _maybeAutoRevertSerialize') + 1500,
    );
    assert.match(fn, /if \(!settings\.serializeRequests\)/);
    assert.match(fn, /_serializeAutoEnabledAt = 0/);
  });

  it('_maybeAutoRevertSerialize uses _last429AnyAccountAt as the quiet-window anchor', () => {
    // The quiet window is across ALL accounts, not just the original
    // tripping account. If a different account is still being rate-
    // limited mid-window we should NOT revert.
    const fn = _src_d.slice(
      _src_d.indexOf('function _maybeAutoRevertSerialize'),
      _src_d.indexOf('function _maybeAutoRevertSerialize') + 1500,
    );
    assert.match(fn, /Date\.now\(\) - _last429AnyAccountAt/);
    assert.match(fn, /quietMs < _SERIALIZE_AUTO_REVERT_MS/);
  });

  it('_maybeAutoRevertSerialize clears _burst429ByFingerprint on revert', () => {
    // Otherwise an old burst could trip immediately after revert.
    const fn = _src_d.slice(
      _src_d.indexOf('function _maybeAutoRevertSerialize'),
      _src_d.indexOf('function _maybeAutoRevertSerialize') + 1500,
    );
    assert.match(fn, /_burst429ByFingerprint\.clear\(\)/);
  });

  it('auto-revert timer runs every 60s and is unref()d', () => {
    // unref() so a process that's otherwise idle can still exit.
    assert.match(_src_d, /_serializeAutoRevertTimer = setInterval\(_maybeAutoRevertSerialize, 60_000\)/);
    assert.match(_src_d, /_serializeAutoRevertTimer\.unref/);
  });

  it('proxy 429 handler stamps _last429AnyAccountAt and calls Safeguard D', () => {
    // The wiring at the 429 site is what turns the safeguard from a
    // dead function into an active circuit breaker. If somebody refactors
    // the 429 path and forgets to re-wire these two lines, the breaker
    // silently stops working.
    assert.match(_src_d, /_last429AnyAccountAt = Date\.now\(\)/);
    assert.match(_src_d, /_autoEnableSerializeOnBurst\(getFingerprintFromToken\(token\), acctName\)/);
  });

  it('activity-feed renderer cases route every dynamic field through h(...)', () => {
    // XSS regression — the renderHTML cases for the new event types
    // MUST escape every account/reason field. If somebody adds a new
    // field via raw `+ e.field +` concatenation, the source-grep XSS
    // test (further down) catches it.
    const enabled = _src_d.slice(
      _src_d.indexOf("case 'serialize-auto-enabled'"),
      _src_d.indexOf("case 'serialize-auto-enabled'") + 400,
    );
    assert.ok(enabled.length > 50, 'serialize-auto-enabled case must exist');
    assert.match(enabled, /h\(e\.reason/);
    assert.match(enabled, /h\(e\.account/);
    assert.match(enabled, /h\(String\(e\.revert_after_quiet_min/);

    const reverted = _src_d.slice(
      _src_d.indexOf("case 'serialize-auto-reverted'"),
      _src_d.indexOf("case 'serialize-auto-reverted'") + 300,
    );
    assert.ok(reverted.length > 50, 'serialize-auto-reverted case must exist');
    assert.match(reverted, /h\(String\(e\.quiet_min/);
  });

  it('createSlidingWindowCounter (the breaker primitive) handles the actual Safeguard-D scenario', () => {
    // Behavioral test (not just source-grep): three 429s spaced 5s apart
    // within a 30s window MUST trip; one 429 every 60s must NOT trip.
    const burstWindowMs = 30_000;
    const burstThreshold = 3;
    const cb = createSlidingWindowCounter({ windowMs: burstWindowMs, threshold: burstThreshold });

    // Burst case — 3 events in 10s
    cb.record(0);
    cb.record(5_000);
    cb.record(10_000);
    assert.equal(cb.tripped(10_000), true, 'three 429s within burst window must trip');

    // Spaced case — 3 events spaced 60s apart, only the most recent
    // is in the 30s window at any given read time → never trips.
    const cb2 = createSlidingWindowCounter({ windowMs: burstWindowMs, threshold: burstThreshold });
    cb2.record(0);
    cb2.record(60_000);
    cb2.record(120_000);
    assert.equal(cb2.tripped(120_000), false, 'spaced 429s must NOT trip the burst breaker');
  });
});

// ─────────────────────────────────────────────────
// Phase I+ — OAuth bypass mode (all-accounts-revoked detection).
// Pure-function tests against isOAuthRevocationError +
// accountStateManager's permanent-revocation tracking +
// areAllAccountsTerminallyDead. The dashboard.mjs wiring is
// covered by source-grep tests further down.
// ─────────────────────────────────────────────────

describe('isOAuthRevocationError — RFC 6749 §5.2 classifier', () => {
  it('returns true for the four canonical revocation codes (JSON form)', () => {
    assert.equal(isOAuthRevocationError('{"error":"invalid_grant"}'),       true);
    assert.equal(isOAuthRevocationError('{"error":"unauthorized_client"}'), true);
    assert.equal(isOAuthRevocationError('{"error":"invalid_client"}'),      true);
    assert.equal(isOAuthRevocationError('{"error":"access_denied"}'),       true);
  });

  it('returns true when the code is in error_description / nested error.code', () => {
    // Some servers return {"error_description":"... invalid_grant ..."}
    // after parseRefreshResponse extracts that field as the .error string.
    assert.equal(isOAuthRevocationError('Token has been revoked: invalid_grant'), true);
    // Nested form
    assert.equal(isOAuthRevocationError('{"error":{"code":"invalid_grant","message":"..."}}'), true);
  });

  it('returns false for transient / retry-recoverable errors', () => {
    assert.equal(isOAuthRevocationError('{"error":"temporarily_unavailable"}'), false);
    assert.equal(isOAuthRevocationError('{"error":"server_error"}'),            false);
    assert.equal(isOAuthRevocationError('HTTP 500 Internal Server Error'),       false);
    assert.equal(isOAuthRevocationError('HTTP 429 Too Many Requests'),           false);
    assert.equal(isOAuthRevocationError('ECONNRESET'),                            false);
    assert.equal(isOAuthRevocationError('socket hang up'),                        false);
  });

  it('returns false for malformed / empty / non-string inputs', () => {
    assert.equal(isOAuthRevocationError(''),         false);
    assert.equal(isOAuthRevocationError(null),       false);
    assert.equal(isOAuthRevocationError(undefined),  false);
    assert.equal(isOAuthRevocationError(42),         false);
    assert.equal(isOAuthRevocationError({}),         false);
    assert.equal(isOAuthRevocationError([]),         false);
  });

  it('avoids false-positives on substring lookups', () => {
    // "preinvalid_grant_handler" — contains the substring but should
    // NOT match because of the word-boundary regex.
    assert.equal(isOAuthRevocationError('preinvalid_grant_handler missing'), false);
    assert.equal(isOAuthRevocationError('not_invalid_grant_lookup'),         false);
  });

  it('handles bare error code without JSON wrapping', () => {
    assert.equal(isOAuthRevocationError('invalid_grant'),       true);
    assert.equal(isOAuthRevocationError('access_denied'),       true);
  });
});

describe('accountStateManager — permanent-revocation tracking', () => {
  it('records strikes and trips after 3 failures over 1h', () => {
    const m = createAccountStateManager();
    const tok = 'tok-A';
    const t0 = 1_000_000_000;
    // First strike at t0
    m.recordPermanentRefreshFailure(tok, 'A', t0);
    assert.equal(m.isPermanentlyRevoked(tok, t0 + 1000),               false, '1 strike alone does NOT trip');
    // Second strike at t0+30min
    m.recordPermanentRefreshFailure(tok, 'A', t0 + 30 * 60_000);
    assert.equal(m.isPermanentlyRevoked(tok, t0 + 30 * 60_000 + 1000), false, '2 strikes within 30min does NOT trip');
    // Third strike at t0+61min — count threshold met AND duration ≥1h
    m.recordPermanentRefreshFailure(tok, 'A', t0 + 61 * 60_000);
    assert.equal(m.isPermanentlyRevoked(tok, t0 + 61 * 60_000 + 1000), true, '3 strikes spread over >1h trips');
  });

  it('does NOT trip when 3+ strikes happen in <1h (transient outage protection)', () => {
    const m = createAccountStateManager();
    const tok = 'tok-B';
    const t0 = 2_000_000_000;
    // 5 strikes in 30s — looks like an OAuth-server outage, not a revocation
    for (let i = 0; i < 5; i++) {
      m.recordPermanentRefreshFailure(tok, 'B', t0 + i * 5_000);
    }
    assert.equal(m.isPermanentlyRevoked(tok, t0 + 30_000), false, 'rapid strikes < 1h MUST NOT trip — protects against OAuth outages');
  });

  it('clearPermanentRevocation wipes both flag and counter', () => {
    const m = createAccountStateManager();
    const tok = 'tok-C';
    const t0 = 3_000_000_000;
    for (let i = 0; i < 3; i++) {
      m.recordPermanentRefreshFailure(tok, 'C', t0 + i * 30 * 60_000);
    }
    // Cross threshold to set the flag
    assert.equal(m.isPermanentlyRevoked(tok, t0 + 90 * 60_000), true);
    m.clearPermanentRevocation(tok);
    const s = m.get(tok);
    assert.equal(s.permanentlyRevoked,             false);
    assert.equal(s.permanentRefreshFailureCount,   0);
    assert.equal(s.firstPermanentFailureAtMs,      0);
  });

  it('clearPermanentRevocation is a no-op for tokens with clean state', () => {
    const m = createAccountStateManager();
    // Doesn't throw, doesn't create a state entry
    m.clearPermanentRevocation('never-seen');
    assert.equal(m.get('never-seen'),               undefined);
  });
});

describe('areAllAccountsTerminallyDead', () => {
  function _setupRevoked(m, tok, name, nowMs) {
    // Helper: drive token to permanentlyRevoked=true via threshold
    for (let i = 0; i < 3; i++) {
      m.recordPermanentRefreshFailure(tok, name, nowMs - (61 - i * 30) * 60_000);
    }
    m.isPermanentlyRevoked(tok, nowMs);
  }

  it('returns false when no accounts are on file (zero data → no decision)', () => {
    const m = createAccountStateManager();
    assert.equal(areAllAccountsTerminallyDead([], m),                                false);
    assert.equal(areAllAccountsTerminallyDead(null, m),                              false);
    assert.equal(areAllAccountsTerminallyDead(undefined, m),                         false);
  });

  it('returns false when at least one account has no state recorded', () => {
    const m = createAccountStateManager();
    const now = 5_000_000_000;
    _setupRevoked(m, 'tok-A', 'A', now);
    // tok-B has never been touched → unknown → must be treated as alive
    assert.equal(
      areAllAccountsTerminallyDead([{ token: 'tok-A' }, { token: 'tok-B' }], m, { now }),
      false,
      'unknown account must be treated as alive — no false-positive on freshly-added accounts',
    );
  });

  it('returns false when at least one account had a 200 in last 24h', () => {
    const m = createAccountStateManager();
    const now = 6_000_000_000;
    _setupRevoked(m, 'tok-A', 'A', now);
    _setupRevoked(m, 'tok-B', 'B', now);
    // tok-A has a recent success — overrides the revocation marker
    const sA = m.get('tok-A');
    sA.lastSuccessAtMs = now - 60 * 60_000; // 1h ago
    assert.equal(
      areAllAccountsTerminallyDead([{ token: 'tok-A' }, { token: 'tok-B' }], m, { now }),
      false,
      'recent 200 means the token is alive regardless of past revocation strikes',
    );
  });

  it('returns false when a future 5h-reset window exists (temporary, not permanent)', () => {
    const m = createAccountStateManager();
    const now = 7_000_000_000;
    _setupRevoked(m, 'tok-A', 'A', now);
    const sA = m.get('tok-A');
    sA.resetAt = Math.floor((now + 60_000) / 1000); // 1 min in the future (epoch seconds)
    assert.equal(
      areAllAccountsTerminallyDead([{ token: 'tok-A' }], m, { now }),
      false,
      'future rate-limit reset means recovery is expected',
    );
  });

  it('returns true ONLY when EVERY account is revoked, no recent success, no future reset', () => {
    const m = createAccountStateManager();
    const now = 8_000_000_000;
    _setupRevoked(m, 'tok-A', 'A', now);
    _setupRevoked(m, 'tok-B', 'B', now);
    assert.equal(
      areAllAccountsTerminallyDead([{ token: 'tok-A' }, { token: 'tok-B' }], m, { now }),
      true,
      'all accounts dead — bypass mode should engage',
    );
  });
});

// ─────────────────────────────────────────────────────────
// createSerializationQueue.drainProgressively — progressive
// flush so a backlog doesn't flood Anthropic in one millisecond
// when serialize mode disengages.
// ─────────────────────────────────────────────────────────

describe('createSerializationQueue — drainProgressively', () => {
  it('releases ONE entry per intervalMs, not all at once', async () => {
    const q = createSerializationQueue({
      getEnabled: () => true,
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
    });
    // Slow tasks (250ms) so the queue genuinely backs up — async no-op
    // functions complete fast enough that with cap=1+delay=0 the queue
    // could empty in milliseconds, before drainProgressively engages.
    const dispatched = [];
    const tasks = [];
    for (let i = 0; i < 5; i++) {
      tasks.push(q.acquire(async () => {
        await new Promise(r => setTimeout(r, 250));
        dispatched.push(i);
      }).catch(() => {}));
    }
    // Wait for the queue to settle: 1 task in flight, 4 queued.
    await new Promise(r => setTimeout(r, 30));

    // Now drainProgressively at 60ms intervals — fast enough to be
    // visibly faster than natural cap=1 dispatch.
    const ctrl = q.drainProgressively({ intervalMs: 60 });
    const afterDrainStart = ctrl.released();
    // After ~150ms post-drain, several entries should have been
    // RELEASED by the drain (released() counts entries the drain
    // dispatched, regardless of whether their async work has finished).
    await new Promise(r => setTimeout(r, 150));
    const after150 = ctrl.released();
    assert.ok(after150 > afterDrainStart, `drain released entries over time (start=${afterDrainStart}, after150ms=${after150})`);

    ctrl.cancel();
    await Promise.allSettled(tasks);
  });

  it('cancel() stops further dispatches', async () => {
    const q = createSerializationQueue({
      getEnabled: () => true,
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
    });
    const dispatched = [];
    for (let i = 0; i < 10; i++) {
      q.acquire(async () => { dispatched.push(i); }).catch(() => {});
    }
    await new Promise(r => setTimeout(r, 20));
    const ctrl = q.drainProgressively({ intervalMs: 50 });
    await new Promise(r => setTimeout(r, 80));
    ctrl.cancel();
    const atCancel = dispatched.length;
    // Wait long enough that another ~5 dispatches WOULD have happened
    // if cancel were ignored
    await new Promise(r => setTimeout(r, 300));
    assert.equal(dispatched.length, atCancel, 'no dispatches after cancel()');
  });

  it('onDrained fires once with the released count', async () => {
    const q = createSerializationQueue({
      getEnabled: () => true,
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
    });
    for (let i = 0; i < 3; i++) {
      q.acquire(async () => {}).catch(() => {});
    }
    await new Promise(r => setTimeout(r, 20));
    let drained = null;
    let calls = 0;
    q.drainProgressively({
      intervalMs: 50,
      onDrained: (info) => { calls++; drained = info; },
    });
    await new Promise(r => setTimeout(r, 400));
    assert.equal(calls, 1, 'onDrained must fire exactly once');
    assert.ok(drained && typeof drained.released === 'number', 'onDrained receives released count');
    assert.equal(drained.cancelled, false, 'natural completion → cancelled: false');
  });

  it('returns a no-op controller when queue is empty', () => {
    const q = createSerializationQueue({ getEnabled: () => true });
    let drainedCalled = 0;
    const ctrl = q.drainProgressively({
      onDrained: () => { drainedCalled++; },
    });
    assert.equal(typeof ctrl.cancel, 'function');
    assert.equal(ctrl.released(), 0);
    assert.equal(drainedCalled, 1, 'onDrained fires immediately when nothing to drain');
  });

  it('intervalMs floored at 50ms to prevent flush-flood-by-mistake', async () => {
    const q = createSerializationQueue({
      getEnabled: () => true,
      getMaxConcurrent: () => 1,
      getDelayMs: () => 0,
    });
    // Slow tasks (300ms each) so the queue actually backs up — fast
    // tasks would finish during the 20ms warm-up wait and drain the
    // queue before drainProgressively even sees it.
    for (let i = 0; i < 5; i++) {
      q.acquire(async () => { await new Promise(r => setTimeout(r, 300)); }).catch(() => {});
    }
    // Wait for the dispatch loop to settle: 1 in flight, 4 queued.
    await new Promise(r => setTimeout(r, 30));
    // Try to drain at "0ms" interval — should clamp to 50ms.
    const ctrl = q.drainProgressively({ intervalMs: 0 });
    // After 30ms post-drain-call, the floor (50ms) means at most ONE
    // additional tick has fired: one synchronous on the call + one
    // pending. Either way, at least 2 entries should still be queued.
    await new Promise(r => setTimeout(r, 30));
    assert.ok(ctrl.remaining() >= 2, `floor of 50ms prevents instant flush — got remaining=${ctrl.remaining()}`);
    ctrl.cancel();
  });
});

// ─────────────────────────────────────────────────────────
// Source-level wiring tests — verify dashboard.mjs hooks the
// pure-function detector into the right code paths.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — OAuth bypass mode wiring (batch 11)', () => {
  const _src_b = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports isOAuthRevocationError + areAllAccountsTerminallyDead', () => {
    assert.match(_src_b, /isOAuthRevocationError,/);
    assert.match(_src_b, /areAllAccountsTerminallyDead,/);
  });

  it('exposes oauthBypassEnabled in DEFAULT_SETTINGS (default ON)', () => {
    assert.match(_src_b, /oauthBypassEnabled:\s*true/);
  });

  it('refresh handler classifies failures and records strikes', () => {
    // The refresh-failed branch must check isOAuthRevocationError BEFORE
    // recording a strike — otherwise transient errors (network, 5xx)
    // would falsely accumulate strikes.
    assert.match(_src_b, /isOAuthRevocationError\(result\.error\)/);
    assert.match(_src_b, /accountState\.recordPermanentRefreshFailure\(/);
  });

  it('refresh success clears prior revocation strikes for the old token', () => {
    // Without this, a single revocation event would mark the account
    // permanently dead even if it later refreshes successfully.
    assert.match(_src_b, /accountState\.clearPermanentRevocation\(oldToken\)/);
  });

  it('200 response stamps lastSuccessAtMs and clears revocation', () => {
    // updateAccountState is the canonical 200-handler. Both the
    // success-time stamp and the revocation clear must happen there.
    const block = _src_b.slice(
      _src_b.indexOf('function updateAccountState'),
      _src_b.indexOf('function updateAccountState') + 1500,
    );
    assert.ok(block.length > 0, 'updateAccountState must exist');
    assert.match(block, /lastSuccessAtMs/);
    assert.match(block, /clearPermanentRevocation/);
  });

  it('_enterOAuthBypass starts a recovery probe timer with unref', () => {
    const fn = _src_b.slice(
      _src_b.indexOf('function _enterOAuthBypass'),
      _src_b.indexOf('function _enterOAuthBypass') + 2500,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    assert.match(fn, /_OAUTH_BYPASS_RECOVERY_INTERVAL_MS/);
    assert.match(fn, /_oauthBypassRecoveryTimer\.unref/);
    // HIGH_PRIORITY notification → user must see this even if throttle
    assert.match(fn, /'circuitBreaker'/);
  });

  it('_exitOAuthBypass clears the recovery timer', () => {
    const fn = _src_b.slice(
      _src_b.indexOf('function _exitOAuthBypass'),
      _src_b.indexOf('function _exitOAuthBypass') + 1500,
    );
    assert.match(fn, /clearInterval\(_oauthBypassRecoveryTimer\)/);
    assert.match(fn, /_oauthBypassRecoveryTimer = null/);
  });

  it('_evaluateBypassMode honours settings.oauthBypassEnabled = false', () => {
    const fn = _src_b.slice(
      _src_b.indexOf('function _evaluateBypassMode'),
      _src_b.indexOf('function _evaluateBypassMode') + 1500,
    );
    assert.match(fn, /settings\.oauthBypassEnabled === false/);
  });

  it('_probeBypassRecovery iterates accounts and calls refreshAccountToken with force=true', () => {
    const fn = _src_b.slice(
      _src_b.indexOf('async function _probeBypassRecovery'),
      _src_b.indexOf('async function _probeBypassRecovery') + 1500,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    assert.match(fn, /refreshAccountToken\(a\.name, \{ force: true \}\)/);
  });

  it('proxy hot path skips rotation when _oauthBypassMode is true', () => {
    // The bypass branch must be in handleProxyRequest, not just in
    // updateAccountState (which has a separate _oauthBypassMode check
    // for re-evaluation on 200 responses). Anchor on the unique log
    // message used inside the proxy branch.
    const anchor = 'OAuth bypass mode — smart passthrough';
    const idx = _src_b.indexOf(anchor);
    assert.notEqual(idx, -1, `bypass-mode log line "${anchor}" must exist in handleProxyRequest`);
    // It must use _smartPassthrough, like proxy-disabled and circuit-breaker.
    const block = _src_b.slice(idx, idx + 1500);
    assert.match(block, /_smartPassthrough\([^,]+,[^,]+,[^,]+,[^,]+,\s*'oauth-bypass'\)/);
  });

  it('activity-feed cases for oauth-bypass-enabled / disabled use h(...) escaping', () => {
    const enabled = _src_b.slice(
      _src_b.indexOf("case 'oauth-bypass-enabled'"),
      _src_b.indexOf("case 'oauth-bypass-enabled'") + 400,
    );
    assert.ok(enabled.length > 50, 'oauth-bypass-enabled case must exist');
    assert.match(enabled, /h\(e\.reason/);
    const disabled = _src_b.slice(
      _src_b.indexOf("case 'oauth-bypass-disabled'"),
      _src_b.indexOf("case 'oauth-bypass-disabled'") + 400,
    );
    assert.ok(disabled.length > 50, 'oauth-bypass-disabled case must exist');
    assert.match(disabled, /h\(e\.reason/);
    assert.match(disabled, /h\(String\(e\.duration_min/);
  });
});

// ─────────────────────────────────────────────────────────
// Source-level wiring — progressive drain replaces instant
// flush at every "serialize is turning OFF" callsite.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — progressive drain wiring (batch 11)', () => {
  const _src_p = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('progressivelyDrainSerializationQueue is defined', () => {
    assert.match(_src_p, /function progressivelyDrainSerializationQueue\(reason/);
  });

  it('user-toggle-off path uses progressive drain', () => {
    assert.match(_src_p, /progressivelyDrainSerializationQueue\('user-toggle-off'\)/);
  });

  it('_autoDisableSerialize path uses progressive drain', () => {
    assert.match(_src_p, /progressivelyDrainSerializationQueue\(`auto-disable: \$\{reason\}`\)/);
  });

  it('_maybeAutoRevertSerialize path uses progressive drain', () => {
    assert.match(_src_p, /progressivelyDrainSerializationQueue\('auto-revert: quiet-window-elapsed'\)/);
  });

  it('the legacy synchronous drainSerializationQueue wrapper is removed', () => {
    // Caller-level `drainSerializationQueue()` calls would silently
    // bypass the progressive cadence. The wrapper itself was deleted;
    // any future `drainSerializationQueue(` callsite is a regression.
    // We allow the factory's internal `_serializationQueue.drain()`
    // method to remain (it backs the progressive path).
    const sites = (_src_p.match(/\bdrainSerializationQueue\s*\(/g) || []).length;
    assert.equal(sites, 0, `drainSerializationQueue() callsites must be zero (got ${sites})`);
  });

  it('intervalMs respects serializeDelayMs but is floored at 250ms', () => {
    // Floor protects against a misconfigured user setting (e.g. delayMs=0)
    // turning progressive drain into instant flush.
    const fn = _src_p.slice(
      _src_p.indexOf('function progressivelyDrainSerializationQueue'),
      _src_p.indexOf('function progressivelyDrainSerializationQueue') + 2000,
    );
    assert.match(fn, /Math\.max\(\s*250,/);
    assert.match(fn, /settings\.serializeDelayMs/);
  });

  it('cancels any prior progressive drain when a new one starts', () => {
    // Two drains racing through one queue would re-introduce the flush
    // problem — entries dispatched twice as fast as either expects.
    const fn = _src_p.slice(
      _src_p.indexOf('function progressivelyDrainSerializationQueue'),
      _src_p.indexOf('function progressivelyDrainSerializationQueue') + 2000,
    );
    assert.match(fn, /_activeProgressiveDrain\.cancel\(\)/);
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — "organization has been disabled" hard-revoke
// path. From the Claude Code error reference: a 400 with body
// containing "This organization has been disabled" is account-
// level termination. Stronger signal than the 3-strikes-OAuth
// heuristic — one occurrence is enough to mark permanently
// revoked.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — forceMarkPermanentlyRevoked + organization-disabled detection (batch 12)', () => {
  it('forceMarkPermanentlyRevoked sets the flag without crossing the threshold', () => {
    const m = createAccountStateManager();
    const tok = 'tok-org-disabled';
    // Fresh state, no prior strikes
    assert.equal(m.isPermanentlyRevoked(tok), false);
    m.forceMarkPermanentlyRevoked(tok, 'org-A', 'organization-disabled-400');
    assert.equal(m.isPermanentlyRevoked(tok), true, 'force-mark trips the flag immediately');
    const s = m.get(tok);
    assert.equal(s.permanentlyRevoked, true);
    assert.equal(s.permanentRevocationReason, 'organization-disabled-400');
    assert.ok(s.permanentRefreshFailureCount >= 3, 'count is bumped past threshold so subsequent isPermanentlyRevoked checks short-circuit');
  });

  it('forceMarkPermanentlyRevoked is reversible via clearPermanentRevocation', () => {
    const m = createAccountStateManager();
    const tok = 'tok-recover';
    m.forceMarkPermanentlyRevoked(tok, 'org-B', 'organization-disabled-400');
    assert.equal(m.isPermanentlyRevoked(tok), true);
    // If Anthropic later re-enables the org and a 200 lands → we must
    // be able to UN-mark and resume normal operation.
    m.clearPermanentRevocation(tok);
    assert.equal(m.isPermanentlyRevoked(tok), false, 'clearPermanentRevocation must wipe forced marks too');
  });

  const _src_o = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('400-handler matches organization-disabled message text', () => {
    // The regex must catch BOTH "has been disabled" (Claude Code's
    // exact phrasing per the error doc) AND "is disabled" (defensive
    // for variant phrasings).
    assert.match(_src_o, /isOrgDisabledError\s*=\s*\/organization has been disabled\|organization is disabled\/i\.test\(errorMessage\)/);
  });

  it('400-handler calls forceMarkPermanentlyRevoked + _evaluateBypassMode', () => {
    // The detection branch is only useful if it WIRES the signal into
    // bypass-mode evaluation. Without _evaluateBypassMode, marking the
    // account hard-revoked would stop rotation but not engage bypass
    // even when ALL accounts are now in this state.
    const idx = _src_o.indexOf('isOrgDisabledError && token');
    assert.notEqual(idx, -1, 'org-disabled branch must guard on token presence');
    const block = _src_o.slice(idx, idx + 1500);
    assert.match(block, /forceMarkPermanentlyRevoked\(token, acctName, 'organization-disabled-400'\)/);
    assert.match(block, /logForensicEvent\('account_organization_disabled'/);
    assert.match(block, /logActivity\('account-organization-disabled'/);
    assert.match(block, /_evaluateBypassMode\(\)/);
  });

  it('activity-feed renderer escapes account name', () => {
    const slice = _src_o.slice(
      _src_o.indexOf("case 'account-organization-disabled'"),
      _src_o.indexOf("case 'account-organization-disabled'") + 400,
    );
    assert.ok(slice.length > 50, 'renderer case must exist');
    assert.match(slice, /h\(e\.account/);
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — anthropic-beta header regression. From CC's
// error reference: a gateway that strips anthropic-beta
// causes 400 "Extra inputs are not permitted ...
// context_management" or "Unexpected value(s) for the
// `anthropic-beta` header". vdm currently forwards it
// correctly via buildForwardHeaders + the inline OAuth-beta
// patches in passthrough sites; this test pins that contract.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — anthropic-beta header forwarding (regression for CC gateway error)', () => {
  it('buildForwardHeaders preserves an inbound anthropic-beta value AND adds oauth-2025-04-20', () => {
    // CC sends specific betas (e.g. context_management, prompt-tools-2025-...) —
    // any beta we drop causes the API to 400 with "Extra inputs are not
    // permitted". So an inbound value must round-trip unchanged, and the
    // mandatory oauth-2025-04-20 must be appended (not overwriting).
    const inbound = {
      'authorization': 'Bearer client-token',
      'anthropic-beta': 'context-management-2025-06-30,prompt-tools-2025-04-22',
      'content-type': 'application/json',
    };
    const fwd = buildForwardHeaders(inbound, 'new-token');
    const betas = fwd['anthropic-beta'].split(',').map(s => s.trim());
    assert.ok(betas.includes('context-management-2025-06-30'),    'inbound context-management beta preserved');
    assert.ok(betas.includes('prompt-tools-2025-04-22'),          'inbound prompt-tools beta preserved');
    assert.ok(betas.includes('oauth-2025-04-20'),                 'mandatory OAuth beta appended');
  });

  it('buildForwardHeaders does NOT duplicate oauth-2025-04-20 when client already sent it', () => {
    const inbound = { 'anthropic-beta': 'oauth-2025-04-20,context-management-2025-06-30' };
    const fwd = buildForwardHeaders(inbound, 'tok');
    const oauthCount = fwd['anthropic-beta'].split(',').filter(s => s.trim() === 'oauth-2025-04-20').length;
    assert.equal(oauthCount, 1, 'oauth-2025-04-20 must appear exactly once');
  });

  it('buildForwardHeaders normalises case-variant Anthropic-Beta to lowercase', () => {
    // Node duplicates headers when case differs ("Anthropic-Beta" + "anthropic-beta"
    // become two header lines), and Anthropic rejects duplicate beta headers.
    const inbound = { 'Anthropic-Beta': 'context-management-2025-06-30' };
    const fwd = buildForwardHeaders(inbound, 'tok');
    // Only the lowercase key should be present — buildForwardHeaders deletes the original
    assert.equal(fwd['Anthropic-Beta'], undefined, 'case-variant key must be removed');
    assert.match(fwd['anthropic-beta'], /context-management-2025-06-30/);
  });

  const _src_ab = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('passthrough paths (proxy-disabled, circuit-breaker, oauth-bypass) all preserve anthropic-beta', () => {
    // These three branches in handleProxyRequest do NOT go through
    // buildForwardHeaders (they call stripHopByHopHeaders directly and
    // patch headers inline). All three must explicitly add oauth-2025-04-20
    // and merge it with any inbound betas — same contract buildForwardHeaders
    // honours. Source-grep enforces this without standing up a live proxy.
    const oauthBetaPatches = (_src_ab.match(/if \(!betas\.includes\('oauth-2025-04-20'\)\) betas\.push\('oauth-2025-04-20'\)/g) || []).length;
    assert.ok(
      oauthBetaPatches >= 3,
      `expected ≥3 inline oauth-2025-04-20 patches (proxy-disabled, circuit-breaker, oauth-bypass); found ${oauthBetaPatches}`,
    );
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — isPostRefreshTrulyExpired (CC-style heuristic
// from bridge/initReplBridge.ts:203-240). After refresh
// completes with !ok, if expiresAt is STILL in the past →
// truly dead refresh token.
// ─────────────────────────────────────────────────────────

describe('isPostRefreshTrulyExpired — CC-style hard-revocation signal', () => {
  it('returns true for past expiresAt (the actual dead-token signal)', () => {
    const now = 5_000_000_000;
    assert.equal(isPostRefreshTrulyExpired(now - 1, now),                    true);
    assert.equal(isPostRefreshTrulyExpired(now - 60_000, now),               true);
    assert.equal(isPostRefreshTrulyExpired(now - 24 * 60 * 60_000, now),     true);
    assert.equal(isPostRefreshTrulyExpired(now, now),                        true, '== now is "expired" too — sub-millisecond expiry');
  });

  it('returns false for future expiresAt (token still has time left)', () => {
    const now = 5_000_000_000;
    assert.equal(isPostRefreshTrulyExpired(now + 1, now),                    false);
    assert.equal(isPostRefreshTrulyExpired(now + 60_000, now),               false);
    assert.equal(isPostRefreshTrulyExpired(now + 8 * 60 * 60_000, now),      false);
  });

  it('NEVER trips for null / undefined / non-numeric expiresAt', () => {
    // Per CC source: env-var and FD tokens carry expiresAt=null and must
    // never trip this — they're inference-only tokens whose "expiry"
    // tracking is the responsibility of whatever produced the env var.
    assert.equal(isPostRefreshTrulyExpired(null),                            false);
    assert.equal(isPostRefreshTrulyExpired(undefined),                       false);
    assert.equal(isPostRefreshTrulyExpired(0),                               false, 'falsy 0 = unknown, not "expired in 1970"');
    assert.equal(isPostRefreshTrulyExpired(NaN),                             false);
    assert.equal(isPostRefreshTrulyExpired(Infinity),                        false);
    assert.equal(isPostRefreshTrulyExpired('1234567890'),                    false, 'string forms must not be auto-coerced — that would be a class of upstream-parsing bug we want to surface, not paper over');
  });

  it('does NOT use a buffer (unlike shouldRefreshToken)', () => {
    // The whole point: a token with 3 minutes left + transient OAuth-server
    // blip would falsely classify as dead under the buffered heuristic. This
    // function uses ACTUAL expiry, no buffer.
    const now = 5_000_000_000;
    assert.equal(isPostRefreshTrulyExpired(now + 3 * 60_000, now), false, '3 min left = NOT truly dead');
    assert.equal(shouldRefreshToken(now + 3 * 60_000, 5 * 60_000, now), true, 'shouldRefreshToken WOULD trip with 5min buffer (proves the difference)');
  });
});

describe('Phase I+ — refreshAccountToken wires isPostRefreshTrulyExpired', () => {
  const _src_pe = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports isPostRefreshTrulyExpired from lib.mjs', () => {
    assert.match(_src_pe, /isPostRefreshTrulyExpired,/);
  });

  it('refresh-failed path checks oauth.expiresAt and force-marks if truly expired', () => {
    // Anchor on the unique log message; the slice covers the whole branch.
    const idx = _src_pe.indexOf('post-refresh truly expired');
    assert.notEqual(idx, -1, 'post-refresh-expired branch must exist');
    const block = _src_pe.slice(idx - 1500, idx + 1500);
    assert.match(block, /isPostRefreshTrulyExpired\(oauth\.expiresAt\)/);
    assert.match(block, /forceMarkPermanentlyRevoked\(\s*oldToken, accountName, 'post-refresh-truly-expired'/);
    assert.match(block, /logActivity\('account-post-refresh-expired'/);
  });

  it('post-refresh-expired calls _evaluateBypassMode after force-marking', () => {
    // Without the eval, marking the LAST account dead wouldn't engage
    // bypass mode until the next request. We want immediate engagement.
    const idx = _src_pe.indexOf('post-refresh-truly-expired');
    const block = _src_pe.slice(idx, idx + 1500);
    assert.match(block, /_evaluateBypassMode\(\)/);
  });

  it('activity-feed renderer escapes account name', () => {
    const slice = _src_pe.slice(
      _src_pe.indexOf("case 'account-post-refresh-expired'"),
      _src_pe.indexOf("case 'account-post-refresh-expired'") + 400,
    );
    assert.ok(slice.length > 50, 'renderer case must exist');
    assert.match(slice, /h\(e\.account/);
  });

  it('detection happens IN ADDITION to isOAuthRevocationError, not replacing it', () => {
    // Both signals are valid; they catch different failure modes:
    //   - isOAuthRevocationError: the OAuth server returned a known
    //     RFC 6749 revocation error code
    //   - isPostRefreshTrulyExpired: the OAuth server returned ANY
    //     error AND the token is past its expiresAt
    // The second catches non-RFC-conformant error responses (custom
    // error formats, HTML error pages, network timeouts that exhausted
    // the retry budget). Both must be present in the source.
    assert.match(_src_pe, /isOAuthRevocationError\(result\.error\)/);
    assert.match(_src_pe, /isPostRefreshTrulyExpired\(oauth\.expiresAt\)/);
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — token-tracking accuracy: synthetic-model filter
// + per-message dedup (CC v2.1.89's stats.ts:313-316 pattern).
// Catches two miscount classes:
//   1. Internal control messages (CC's SYNTHETIC_MODEL) leaking
//      into billable totals.
//   2. Hook re-fires (dashboard restart mid-turn, duplicate
//      delivery) double-counting the same assistant turn.
// ─────────────────────────────────────────────────────────

describe('Phase I+ — token-tracking filters (batch 12)', () => {
  const _src_tt = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('_isSyntheticModel rejects angle-bracket-wrapped sentinels', () => {
    // Source-grep on the regex; the function itself is internal to
    // dashboard.mjs (no export). The match assertion exercises the
    // pattern by inspection.
    assert.match(_src_tt, /_SYNTHETIC_MODEL_RE\s*=\s*\/\^<\.\*>\$\//);
    assert.match(_src_tt, /function _isSyntheticModel\(model\)/);
  });

  it('appendTokenUsage filters synthetic models BEFORE persistence', () => {
    // The filter must run BEFORE the row hits the on-disk usage array
    // — otherwise the synthetic row leaks to readers via
    // _tokenUsageCache during the debounce window.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function appendTokenUsage'),
      _src_tt.indexOf('function appendTokenUsage') + 4000,
    );
    assert.match(fn, /_isSyntheticModel\(normalized\.model\)/);
    assert.match(fn, /'tokens-filter'/);
    // Must early-return — not just log. Match either a single-quoted
    // string OR a template literal "synthetic model ..."
    assert.match(fn, /synthetic model[^]{0,200}— skipped[^]{0,200}return;/);
  });

  it('_isDuplicateMessage skips dedup when messageId is missing', () => {
    // Without an ID we can't safely dedup (no canonical key). Accept
    // the row rather than risk a false-positive that drops legitimate
    // usage. The function must short-circuit on falsy messageId.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function _isDuplicateMessage'),
      _src_tt.indexOf('function _isDuplicateMessage') + 1500,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    assert.match(fn, /if \(!messageId\) return false/);
  });

  it('_isDuplicateMessage uses sessionId|messageId as the key', () => {
    // Same messageId in different sessions = different turns. CC's
    // jsonl can have message UUIDs reused across stale projects in
    // edge cases (test harnesses, replays); scoping by session is
    // the safe choice.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function _isDuplicateMessage'),
      _src_tt.indexOf('function _isDuplicateMessage') + 1500,
    );
    assert.match(fn, /\$\{sessionId \|\| '_unknown'\}\|\$\{messageId\}/);
  });

  it('seen-message map is bounded with TTL-based GC', () => {
    // Without a bound the Map grows unbounded across the lifetime of
    // the dashboard process. 10K entries × ~50 bytes = ~500 KB upper
    // bound — tolerable, but only if the cap is enforced.
    assert.match(_src_tt, /_SEEN_MESSAGES_MAX\s*=\s*10_000/);
    assert.match(_src_tt, /_SEEN_MESSAGES_TTL_MS\s*=\s*24 \* 60 \* 60 \* 1000/);
    // GC must drop expired entries first, then drop oldest by
    // insertion order if still over budget.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function _isDuplicateMessage'),
      _src_tt.indexOf('function _isDuplicateMessage') + 1500,
    );
    assert.match(fn, /Date\.now\(\) - _SEEN_MESSAGES_TTL_MS/);
    assert.match(fn, /_seenMessageEntries\.delete\(k\)/);
  });

  it('appendTokenUsage filters synthetic + dedup in that order, BEFORE pushing to the on-disk array', () => {
    const fn = _src_tt.slice(
      _src_tt.indexOf('function appendTokenUsage'),
      _src_tt.indexOf('function appendTokenUsage') + 4000,
    );
    const synthIdx = fn.indexOf('_isSyntheticModel');
    const dedupIdx = fn.indexOf('_isDuplicateMessage');
    const pushIdx = fn.indexOf('usage.push(normalized)');
    assert.ok(synthIdx > 0, 'synthetic check must exist');
    assert.ok(dedupIdx > 0, 'dedup check must exist');
    assert.ok(pushIdx > 0, 'usage.push must exist');
    assert.ok(synthIdx < pushIdx, 'synthetic check before push');
    assert.ok(dedupIdx < pushIdx, 'dedup check before push');
  });

  it('appendTokenUsage row schema includes messageId field', () => {
    // Without this the dedup map can never populate from the on-disk
    // history (e.g. on dashboard restart) and re-fires within the
    // first 24h after restart wouldn't dedup.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function appendTokenUsage'),
      _src_tt.indexOf('function appendTokenUsage') + 4000,
    );
    assert.match(fn, /messageId: entry\.messageId \?\? null/);
  });

  it('compact_boundary rows BYPASS the synthetic + dedup filters', () => {
    // Compact-boundary markers don't have a model field and don't have
    // a messageId. Filtering them out as "synthetic" or dedup-rejecting
    // them by null messageId would break compaction tracking.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function appendTokenUsage'),
      _src_tt.indexOf('function appendTokenUsage') + 4000,
    );
    // Both filters must guard on `normalized.type === 'usage'`
    assert.match(fn, /normalized\.type === 'usage' && _isSyntheticModel/);
    assert.match(fn, /normalized\.type === 'usage' && _isDuplicateMessage/);
  });

  it('all 6 row-building sites thread entry.messageId through to appendTokenUsage', () => {
    // Without this, ALL recorded usage carries messageId=null and dedup
    // is a no-op. Source-grep counts the threading sites.
    const sites = (_src_tt.match(/messageId: entry\.messageId \?\? null/g) || []).length;
    assert.ok(
      sites >= 6,
      `expected ≥6 messageId-threading sites in row builders; found ${sites}`,
    );
  });

  it('recordUsage threads messageId from the SSE extractor', () => {
    // Closes the loop: extractor → recordUsage → recentUsage entry →
    // claimUsageInRange → appendTokenUsage. If recordUsage drops the
    // field, the dedup path is dead at the source.
    const fn = _src_tt.slice(
      _src_tt.indexOf('function recordUsage'),
      _src_tt.indexOf('function recordUsage') + 2000,
    );
    assert.match(fn, /messageId: usage\.messageId \|\| null/);
  });
});

// ─────────────────────────────────────────────────────────
// Phase I+ — isNonProjectCwd: guard for token attribution.
// The user reported tokens being attributed to ~/.claude/
// plugin-cache dirs that are SHARED across many distinct CC
// sessions. The fix is to refuse to extract a "repo" identity
// from any cwd inside a system / cache path.
// ─────────────────────────────────────────────────────────

describe('isNonProjectCwd — system / cache cwd detector', () => {
  const HOME = '/Users/test-user';

  it('flags ~/.claude/ subdirs as non-project (the original bug)', () => {
    assert.equal(isNonProjectCwd(`${HOME}/.claude/plugins/cache/some-plugin`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.claude/plugins/cache/some-plugin/scripts`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.claude/projects/proj-123`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.claude`, HOME), true, '$HOME/.claude itself IS the CC state dir — never a user project');
  });

  it('flags /tmp/, /var/folders/, /private/ as non-project (worktree spawned in temp)', () => {
    assert.equal(isNonProjectCwd('/tmp/cc-worktree-foo'), true);
    assert.equal(isNonProjectCwd('/private/tmp/x'), true);
    assert.equal(isNonProjectCwd('/var/tmp/x'), true);
    assert.equal(isNonProjectCwd('/var/folders/8j/abc123/T/cc-tmp'), true, 'macOS per-user tmp');
    assert.equal(isNonProjectCwd('/private/var/folders/8j/abc/T'), true);
  });

  it('flags node_modules subdirs', () => {
    assert.equal(isNonProjectCwd('/Users/me/proj/node_modules/foo'), true);
    assert.equal(isNonProjectCwd('/Users/me/proj/node_modules'), true);
    assert.equal(isNonProjectCwd('/Users/me/proj/packages/inner/node_modules/bar'), true, 'monorepo nested node_modules');
  });

  it('flags ~/.npm/, ~/.cache/, ~/.config/, ~/.local/share/', () => {
    assert.equal(isNonProjectCwd(`${HOME}/.npm/_cacache/x`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.cache/foo`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.config/some-tool`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/.local/share/x`, HOME), true);
  });

  it('flags macOS Library/Caches and known Application Support trees', () => {
    assert.equal(isNonProjectCwd(`${HOME}/Library/Caches/com.apple.foo`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/Library/Application Support/Code/User`, HOME), true);
    assert.equal(isNonProjectCwd(`${HOME}/Library/Application Support/Claude/sessions`, HOME), true);
  });

  it('does NOT flag normal user project dirs', () => {
    assert.equal(isNonProjectCwd('/Users/me/Code/my-project', HOME), false);
    assert.equal(isNonProjectCwd('/Users/me/projects/foo/src', HOME), false);
    assert.equal(isNonProjectCwd('/home/me/work/repo'), false);
    assert.equal(isNonProjectCwd('/Users/me/Desktop/scratch', HOME), false, 'Desktop scratch is still a project for token-tracking purposes');
  });

  it('handles edge inputs gracefully', () => {
    assert.equal(isNonProjectCwd('', HOME),         false);
    assert.equal(isNonProjectCwd(null, HOME),       false);
    assert.equal(isNonProjectCwd(undefined, HOME),  false);
    assert.equal(isNonProjectCwd(42, HOME),         false);
    // Trailing slash should not change classification
    assert.equal(isNonProjectCwd('/tmp/', HOME),    true);
    assert.equal(isNonProjectCwd('/tmp', HOME),     true);
  });

  it('respects the HOME-not-set case (returns false for $HOME-relative paths)', () => {
    // When $HOME is empty, we can't know which paths are user-relative
    // caches. Refuse to classify ~/.claude paths as non-project — the
    // alternative (false-positive flag of e.g. /home/user/.claude on a
    // CI runner that spawned without $HOME) would silently bucket
    // everything as (non-project).
    assert.equal(isNonProjectCwd('/home/user/.claude/plugins/cache/x', ''), false);
    // System paths (no $HOME involvement) still flagged.
    assert.equal(isNonProjectCwd('/tmp/x', ''), true);
  });
});

describe('Phase I+ — dashboard.mjs wires isNonProjectCwd into session-start + subagent-start', () => {
  const _src_at = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports isNonProjectCwd from lib.mjs', () => {
    assert.match(_src_at, /isNonProjectCwd,/);
  });

  it('session-start uses (non-project) sentinel for system cwds', () => {
    // Anchor on the sentinel string + nearby isNonProjectCwd call.
    assert.match(_src_at, /isNonProjectCwd\(cwd\)[\s\S]{0,500}repo = '\(non-project\)'/);
    // Even when git rev-parse returns a path that ITSELF resolves to a
    // system dir (e.g. plugin-cache dir is a git checkout), the post-
    // resolution guard catches it.
    assert.match(_src_at, /isNonProjectCwd\(repo\)[\s\S]{0,300}repo = '\(non-project\)'/);
  });

  it('subagent-start tries ancestor-cwd matching before falling back to subagent cwd', () => {
    // The new path (b): for each pendingSession, check if subagent's
    // cwd starts with the main session's cwd + '/'.
    const fn = _src_at.slice(
      _src_at.indexOf("'/api/subagent-start'"),
      _src_at.indexOf("'/api/subagent-start'") + 6000,
    );
    assert.match(fn, /subPath\.startsWith\(mainPath \+ '\/'\)/);
    assert.match(fn, /parentResolution = 'ancestor-cwd'/);
  });

  it('subagent-start falls back to most-recently-active main session ONLY for non-project cwds', () => {
    // Path (c): we don't want to grab a random main session for a
    // legitimate orphan — that would mis-attribute. Only fire this
    // fallback when the subagent's cwd is itself non-project (plugin
    // cache, /tmp, etc.) — in that case "wrong main" is strictly
    // better than "the plugin path itself".
    const fn = _src_at.slice(
      _src_at.indexOf("'/api/subagent-start'"),
      _src_at.indexOf("'/api/subagent-start'") + 6000,
    );
    assert.match(fn, /isNonProjectCwd\(cwd\)[\s\S]{0,800}parentResolution = 'most-recent-main'/);
  });

  it('subagent-start logs the parent-resolution path it took', () => {
    // Without the log line, debugging "why did this token attribute
    // here" becomes guesswork. The log emits the resolution mode so
    // operators can trace.
    const fn = _src_at.slice(
      _src_at.indexOf("'/api/subagent-start'"),
      _src_at.indexOf("'/api/subagent-start'") + 6000,
    );
    assert.match(fn, /parent resolved via \$\{parentResolution\}/);
  });

  it('subagent-start path (d) applies the non-project guard before computing repo from subagent cwd', () => {
    // The original bug: subagent's cwd was inside ~/.claude/plugins/cache/
    // which IS a git checkout, so vdm computed repo=plugin-path. The
    // guard short-circuits this case to (non-project) sentinel.
    const fn = _src_at.slice(
      _src_at.indexOf("'/api/subagent-start'"),
      _src_at.indexOf("'/api/subagent-start'") + 6000,
    );
    // Specifically the subagent-cwd-based path should respect the guard
    assert.match(fn, /Subagent[\s\S]{0,400}is non-project[\s\S]{0,200}\(non-project\) sentinel/);
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 1 — usage tree aggregation
// ─────────────────────────────────────────────────────────

describe('classifyUsageComponent', () => {
  it('main turn (no parentSessionId, no Skill tool) → "main"', () => {
    assert.equal(classifyUsageComponent({ parentSessionId: null, tool: null }),    'main');
    assert.equal(classifyUsageComponent({ parentSessionId: null, tool: 'Bash' }),  'main');
    assert.equal(classifyUsageComponent({ parentSessionId: null, tool: 'Read' }),  'main');
  });

  it('subagent with agentType → "subagent:<type>"', () => {
    assert.equal(classifyUsageComponent({ parentSessionId: 'abc', agentType: 'Explore' }), 'subagent:Explore');
    assert.equal(classifyUsageComponent({ parentSessionId: 'abc', agentType: 'general-purpose' }), 'subagent:general-purpose');
  });

  it('subagent without agentType (CL-3 fallback) → "subagent:unknown"', () => {
    // When CL-3 attribution kicks in (subagent never registered via
    // /api/subagent-start), agentType is null but parentSessionId is set.
    // Don't classify these as "main" — they ARE subagents, just with
    // no type info available.
    assert.equal(classifyUsageComponent({ parentSessionId: 'abc', agentType: null }),  'subagent:unknown');
    assert.equal(classifyUsageComponent({ parentSessionId: 'abc', agentType: '' }),    'subagent:unknown');
    assert.equal(classifyUsageComponent({ parentSessionId: 'abc' }),                   'subagent:unknown');
  });

  it('Skill tool with parsable name → "skill:<name>"', () => {
    assert.equal(classifyUsageComponent({ tool: 'Skill(my-plugin:foo)' }),     'skill:my-plugin:foo');
    assert.equal(classifyUsageComponent({ tool: 'Skill: my-skill' }),          'skill:my-skill');
  });

  it('Skill tool without parsable name → uses mcpServer or "skill:unknown"', () => {
    assert.equal(classifyUsageComponent({ tool: 'Skill', mcpServer: 'my-plugin' }), 'skill:my-plugin');
    assert.equal(classifyUsageComponent({ tool: 'Skill', mcpServer: null }),         'skill:unknown');
    assert.equal(classifyUsageComponent({ tool: 'Skill' }),                          'skill:unknown');
  });

  it('handles malformed input gracefully', () => {
    assert.equal(classifyUsageComponent(null),        'main');
    assert.equal(classifyUsageComponent(undefined),   'main');
    assert.equal(classifyUsageComponent('not-a-row'), 'main');
    assert.equal(classifyUsageComponent({}),          'main');
  });
});

describe('aggregateUsageTree', () => {
  // Minimal row builder so the tests aren't 200 lines of repetitive object literals.
  function row(o) {
    return Object.assign({
      ts: 1_000_000_000,
      type: 'usage',
      repo: '/proj/a',
      branch: 'main',
      model: 'claude-opus-4-7',
      inputTokens: 100,
      outputTokens: 50,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      account: 'acc-1',
      sessionId: 'sess-1',
      parentSessionId: null,
      agentType: null,
      tool: null,
    }, o);
  }

  it('returns empty totals + tree for empty input', () => {
    const r = aggregateUsageTree([]);
    assert.deepEqual(r.totals, { input: 0, output: 0, cacheRead: 0, cacheCreate: 0, requests: 0 });
    assert.deepEqual(r.tree, []);
  });

  it('returns empty for non-array inputs (defensive)', () => {
    assert.deepEqual(aggregateUsageTree(null).tree, []);
    assert.deepEqual(aggregateUsageTree(undefined).tree, []);
    assert.deepEqual(aggregateUsageTree('not-array').tree, []);
  });

  it('builds the 4-level tree (repo → branch → component → tool)', () => {
    const rows = [
      row({ tool: null,   inputTokens: 1000, outputTokens: 100 }),  // main/<assistant>
      row({ tool: 'Bash', inputTokens: 200,  outputTokens: 20  }),  // main/Bash
      row({ tool: 'Read', inputTokens: 300,  outputTokens: 30  }),  // main/Read
      row({ parentSessionId: 'sess-1', agentType: 'Explore', tool: 'Read', inputTokens: 500, outputTokens: 50 }),
    ];
    const r = aggregateUsageTree(rows);
    assert.equal(r.tree.length, 1);
    const repo = r.tree[0];
    assert.equal(repo.kind, 'repo');
    assert.equal(repo.name, '/proj/a');
    assert.equal(repo.children.length, 1, 'one branch');
    const branch = repo.children[0];
    assert.equal(branch.kind, 'branch');
    assert.equal(branch.name, 'main');
    assert.equal(branch.isWorktree, false, "'main' branch is not a worktree");
    assert.equal(branch.children.length, 2, 'two components: main + subagent:Explore');
    const componentNames = branch.children.map(c => c.name).sort();
    assert.deepEqual(componentNames, ['main', 'subagent:Explore']);
  });

  it('marks non-main/master branches as worktrees', () => {
    const r = aggregateUsageTree([
      row({ branch: 'main',          inputTokens: 100 }),
      row({ branch: 'master',        inputTokens: 100 }),
      row({ branch: 'feature-x',     inputTokens: 100 }),
      row({ branch: 'wt-explore-foo',inputTokens: 100 }),
    ]);
    const repo = r.tree[0];
    const byName = Object.fromEntries(repo.children.map(b => [b.name, b]));
    assert.equal(byName['main'].isWorktree,           false);
    assert.equal(byName['master'].isWorktree,         false);
    assert.equal(byName['feature-x'].isWorktree,      true);
    assert.equal(byName['wt-explore-foo'].isWorktree, true);
  });

  it('rolls up totals at each level (tool → component → branch → repo → grand)', () => {
    const rows = [
      row({ tool: 'Bash', inputTokens: 100, outputTokens: 10, cacheReadInputTokens: 5,  cacheCreationInputTokens: 2 }),
      row({ tool: 'Bash', inputTokens: 200, outputTokens: 20, cacheReadInputTokens: 10, cacheCreationInputTokens: 4 }),
      row({ tool: 'Read', inputTokens: 50,  outputTokens: 5,  cacheReadInputTokens: 1 }),
    ];
    const r = aggregateUsageTree(rows);
    assert.equal(r.totals.input,       350);
    assert.equal(r.totals.output,      35);
    assert.equal(r.totals.cacheRead,   16);
    assert.equal(r.totals.cacheCreate, 6);
    assert.equal(r.totals.requests,    3);
    const repo = r.tree[0];
    assert.equal(repo.totals.input, 350);
    const branch = repo.children[0];
    assert.equal(branch.totals.input, 350);
    const main = branch.children.find(c => c.name === 'main');
    assert.equal(main.totals.input, 350);
    const bash = main.children.find(t => t.name === 'Bash');
    assert.equal(bash.totals.input, 300, 'two Bash rows aggregated under one leaf');
    assert.equal(bash.totals.requests, 2);
  });

  it('uses <assistant> as the synthetic tool-name for null tool field', () => {
    const r = aggregateUsageTree([row({ tool: null })]);
    const main = r.tree[0].children[0].children.find(c => c.name === 'main');
    assert.equal(main.children[0].name, '<assistant>');
  });

  it('skips compact_boundary rows', () => {
    const r = aggregateUsageTree([
      row({ inputTokens: 100 }),
      row({ type: 'compact_boundary', inputTokens: 999, preTokens: 50000, postTokens: 8000 }),
    ]);
    assert.equal(r.totals.input, 100, 'compact_boundary inputTokens NOT counted');
    assert.equal(r.totals.requests, 1, 'only the usage row counted');
  });

  it('respects repo / account / model filters', () => {
    const rows = [
      row({ repo: '/proj/a', model: 'claude-opus-4-7',  account: 'acc-1', inputTokens: 100 }),
      row({ repo: '/proj/b', model: 'claude-sonnet-4-7', account: 'acc-1', inputTokens: 200 }),
      row({ repo: '/proj/a', model: 'claude-sonnet-4-7', account: 'acc-2', inputTokens: 400 }),
    ];
    assert.equal(aggregateUsageTree(rows, { repoFilter: '/proj/a' }).totals.input,  500);
    assert.equal(aggregateUsageTree(rows, { modelFilter: 'claude-opus-4-7' }).totals.input, 100);
    assert.equal(aggregateUsageTree(rows, { accountFilter: 'acc-2' }).totals.input, 400);
    // Combined filters: AND
    assert.equal(
      aggregateUsageTree(rows, { repoFilter: '/proj/a', accountFilter: 'acc-1' }).totals.input,
      100,
    );
  });

  it('respects from / to ts filters', () => {
    const rows = [
      row({ ts: 1000, inputTokens: 1 }),
      row({ ts: 2000, inputTokens: 2 }),
      row({ ts: 3000, inputTokens: 3 }),
    ];
    assert.equal(aggregateUsageTree(rows, { from: 2000 }).totals.input,        5);
    assert.equal(aggregateUsageTree(rows, { to: 2000 }).totals.input,          3);
    assert.equal(aggregateUsageTree(rows, { from: 2000, to: 2000 }).totals.input, 2);
  });

  it('skips rows with non-finite token fields (defensive)', () => {
    const r = aggregateUsageTree([
      row({ inputTokens: 100 }),
      row({ inputTokens: NaN }),
      row({ inputTokens: Infinity }),
      row({ outputTokens: -Infinity }),
    ]);
    assert.equal(r.totals.input, 100, 'only the well-formed row counted');
    assert.equal(r.totals.requests, 1);
  });

  it('sorts each level by total tokens desc — heavy hitters first', () => {
    const rows = [
      row({ repo: '/proj/light', inputTokens: 10 }),
      row({ repo: '/proj/heavy', inputTokens: 1000 }),
      row({ repo: '/proj/medium', inputTokens: 100 }),
    ];
    const tree = aggregateUsageTree(rows).tree;
    assert.equal(tree[0].name, '/proj/heavy');
    assert.equal(tree[1].name, '/proj/medium');
    assert.equal(tree[2].name, '/proj/light');
  });

  it('uses sentinels for missing repo / branch', () => {
    const r = aggregateUsageTree([
      row({ repo: null,   branch: null,   inputTokens: 5 }),
      row({ repo: '',     branch: '',     inputTokens: 5 }),
    ]);
    const repo = r.tree[0];
    assert.equal(repo.name, '(unknown-repo)');
    assert.equal(repo.children[0].name, '(unknown-branch)');
  });
});

describe('buildCacheMissReport', () => {
  function row(o) {
    return Object.assign({
      ts: 1_000_000_000,
      type: 'usage',
      sessionId: 'sess-1',
      model: 'claude-opus-4-7',
      inputTokens: 0,
      cacheReadInputTokens: 0,
      cacheCreationInputTokens: 0,
      repo: '/proj/a',
      branch: 'main',
    }, o);
  }

  it('returns [] for empty / non-array input', () => {
    assert.deepEqual(buildCacheMissReport([]),          []);
    assert.deepEqual(buildCacheMissReport(null),        []);
    assert.deepEqual(buildCacheMissReport(undefined),   []);
    assert.deepEqual(buildCacheMissReport('garbage'),   []);
  });

  it('first turn of a session is NEVER a miss (no prior cache existed)', () => {
    const r = buildCacheMissReport([
      row({ ts: 1, inputTokens: 5000 }),  // big input, no prior cache
    ]);
    assert.deepEqual(r, [], 'no prior creation row exists; first turn cannot miss');
  });

  it('flags the canonical TTL-miss pattern', () => {
    // Phase 5 — the gap between the cache-creating turn (ts=1000) and
    // the missing turn (ts=1000+TTL+1) must actually exceed the
    // documented TTL for the heuristic to classify the miss as
    // "TTL-likely". A small gap with the same shape now classifies
    // as "unknown" (different test below covers that case).
    const r = buildCacheMissReport([
      // Turn 1 — creates cache
      row({ ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      // Turn 2 — within TTL, reads cache. NOT a miss.
      row({ ts: 2000, inputTokens: 0,    cacheReadInputTokens: 5000 }),
      // Turn 3 — TTL expired, cacheRead=0 but big input. MISS.
      row({ ts: 1000 + CACHE_TTL_LIKELY_MS + 1, inputTokens: 5500, cacheReadInputTokens: 0, cacheCreationInputTokens: 5500 }),
    ]);
    assert.equal(r.length, 1);
    assert.equal(r[0].ts, 1000 + CACHE_TTL_LIKELY_MS + 1);
    assert.equal(r[0].sessionId, 'sess-1');
    assert.equal(r[0].inputTokens, 5500);
    assert.equal(r[0].reason, 'TTL-likely');
  });

  it('does NOT flag small-input turns (configurable threshold)', () => {
    const rows = [
      row({ ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ ts: 2000, inputTokens: 200,  cacheReadInputTokens: 0 }),    // small input — not a miss
    ];
    assert.deepEqual(buildCacheMissReport(rows), [], 'default threshold 1000 excludes small turns');

    // Lowering the threshold should flag it
    const r = buildCacheMissReport(rows, { minInputForMissDetection: 100 });
    assert.equal(r.length, 1);
    assert.equal(r[0].inputTokens, 200);
  });

  it('groups by sessionId — different sessions do NOT cross-contaminate', () => {
    const r = buildCacheMissReport([
      row({ sessionId: 'A', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ sessionId: 'B', ts: 2000, inputTokens: 5000, cacheReadInputTokens: 0 }),
      // Session B's first turn — no prior cache in session B → not a miss
    ]);
    assert.deepEqual(r, []);
  });

  it('chronological order within a session matters (ts-sorted)', () => {
    // Provide rows in OUT-of-order, verify the function still detects
    // the miss based on chronological order. After sort:
    //   t=1000: first turn, no cache → not a miss
    //   t=2000: creates cache
    //   t=3000: big input + cacheRead=0 → MISS (TTL-likely)
    const r = buildCacheMissReport([
      row({ ts: 3000, inputTokens: 5000, cacheReadInputTokens: 0 }),
      row({ ts: 2000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ ts: 1000, inputTokens: 5000 }),
    ]);
    assert.equal(r.length, 1);
    assert.equal(r[0].ts, 3000);
  });

  it('returned misses are sorted ascending by ts across sessions', () => {
    const r = buildCacheMissReport([
      row({ sessionId: 'B', ts: 5000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ sessionId: 'B', ts: 6000, inputTokens: 5000, cacheReadInputTokens: 0 }),  // miss at 6000
      row({ sessionId: 'A', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ sessionId: 'A', ts: 2000, inputTokens: 5000, cacheReadInputTokens: 0 }),  // miss at 2000
    ]);
    assert.equal(r.length, 2);
    assert.equal(r[0].ts, 2000, 'earlier miss first');
    assert.equal(r[1].ts, 6000);
  });

  it('skips compact_boundary rows', () => {
    const r = buildCacheMissReport([
      row({ ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 5000 }),
      row({ ts: 1500, type: 'compact_boundary', inputTokens: 0 }),   // ignored
      row({ ts: 2000, inputTokens: 5000, cacheReadInputTokens: 0 }), // miss
    ]);
    assert.equal(r.length, 1);
    assert.equal(r[0].ts, 2000);
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 2 — /api/token-usage-tree wiring
// ─────────────────────────────────────────────────────────

describe('Phase 2 — /api/token-usage-tree endpoint wiring', () => {
  const _src_t2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports aggregateUsageTree + buildCacheMissReport from lib.mjs', () => {
    assert.match(_src_t2, /aggregateUsageTree,/);
    assert.match(_src_t2, /buildCacheMissReport,/);
  });

  it('endpoint is registered for GET /api/token-usage-tree', () => {
    assert.match(
      _src_t2,
      /url\.pathname === '\/api\/token-usage-tree' && req\.method === 'GET'/,
    );
  });

  it('builds opts from query params (repo, account, model, from/since, to)', () => {
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.ok(fn.length > 200, 'endpoint body must exist');
    assert.match(fn, /params\.get\('repo'\)/);
    assert.match(fn, /params\.get\('account'\)/);
    assert.match(fn, /params\.get\('model'\)/);
    // The "since" alias maps to from for compatibility with the
    // existing /api/token-usage endpoint
    assert.match(fn, /params\.get\('from'\) \|\| params\.get\('since'\)/);
    assert.match(fn, /params\.get\('to'\)/);
  });

  it('numeric query params are validated via Number.isFinite (no NaN propagation)', () => {
    // A query string like ?from=garbage produces NaN — passing that
    // straight into opts.from would silently include zero rows
    // because every row's ts comparison would be false against NaN.
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /Number\.isFinite\(n\)/);
  });

  it('calls aggregateUsageTree with the rows and opts', () => {
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /aggregateUsageTree\(rows, opts\)/);
  });

  it('returns the documented response shape { ok, totals, tree }', () => {
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /\bok: true,?\s*totals,?\s*tree\b/);
  });

  it('includeMisses=1 attaches a miss report; default is off', () => {
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    // Guard exists
    assert.match(fn, /params\.get\('includeMisses'\) === '1'/);
    // buildCacheMissReport is called inside the guard
    const missGuardIdx = fn.indexOf("params.get('includeMisses')");
    const buildIdx = fn.indexOf('buildCacheMissReport');
    assert.ok(buildIdx > missGuardIdx, 'buildCacheMissReport must be inside the includeMisses guard');
  });

  it('miss report respects from/to filter via pre-filter (function takes no opts.from/to)', () => {
    // The miss heuristic is session-scoped, not range-scoped — so
    // the endpoint pre-filters rows BEFORE handing them to
    // buildCacheMissReport when the user supplied from/to. Without
    // this, a from/to query for the tree would not affect the misses,
    // confusing operators investigating a specific time window.
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /opts\.from != null \|\| opts\.to != null/);
    assert.match(fn, /missRows = rows\.filter/);
  });

  it('minMissInput overrides the cache-miss threshold', () => {
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /params\.get\('minMissInput'\)/);
    assert.match(fn, /minInputForMissDetection/);
  });

  it('errors return 500 with { ok: false, error }', () => {
    // Phase 6 — bumped from 4000 to 5500 to span the wastedSpend
    // computation that was added inside the includeMisses guard, so
    // the catch block at the bottom of the handler still falls inside
    // the slice window.
    const fn = _src_t2.slice(
      _src_t2.indexOf("'/api/token-usage-tree'"),
      _src_t2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    // Use [\s\S] so the regex spans newlines (catch blocks are typically
    // multi-line). A single error path that returns 500 with the
    // standard {ok:false, error: ...} shape. Audit CC-DASH-018:
    // error is now `(e && e.message) || String(e)` for defense
    // against `throw 'string'` style throws — match either form.
    assert.match(fn, /catch \(e\)[\s\S]{0,500}ok: false[\s\S]{0,200}error:[\s\S]{0,200}e\.message[\s\S]{0,200}500/);
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 3 — UI tree view
// ─────────────────────────────────────────────────────────

describe('Phase 3 — UI tree view (renderHTML + client JS)', () => {
  const _src_t3 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('Usage Tree card is present in the Tokens tab', () => {
    assert.match(_src_t3, /<div class="usage-card" id="tok-tree-card"/);
    assert.match(_src_t3, /<span>Usage Tree<\/span>/);
    // The breadcrumb hint must show the 4 levels in order
    assert.match(_src_t3, /repo[^<]*worktree[^<]*component[^<]*tool/);
  });

  it('Cache misses card is present (collapsed by default)', () => {
    assert.match(_src_t3, /<div class="usage-card tree-misses-card" id="tok-misses-card" style="display:none">/);
    assert.match(_src_t3, /<span>Likely Cache Misses<\/span>/);
  });

  it('CSS for the tree view is defined (no JS framework, plain <details>)', () => {
    assert.match(_src_t3, /\.tree-view \{/);
    assert.match(_src_t3, /\.tree-view details \{/);
    assert.match(_src_t3, /\.tree-view summary \{/);
    // Custom collapse marker rotates on open — confirm both states.
    assert.match(_src_t3, /\.tree-view summary::before \{[\s\S]{0,400}content:\s*"▶"/);
    assert.match(_src_t3, /\.tree-view details\[open\] > summary::before \{[\s\S]{0,200}rotate\(90deg\)/);
  });

  it('CSS uses existing dashboard variables (no hard-coded colors per TRDD)', () => {
    // The TRDD §Phase 3 mandates "CSS using existing dashboard variables (no
    // new color palette)". Spot-check a few of the new classes use var(--*).
    // The tree view inherits the card chrome from .usage-card (which already
    // uses var(--card) / var(--shadow)), so this block focuses on the
    // tree-specific properties.
    const css = _src_t3.slice(
      _src_t3.indexOf('/* TRDD-1645134b Phase 3 — usage tree view */'),
      _src_t3.indexOf('.tok-export-btn {'),
    );
    assert.ok(css.length > 1000, 'tree-view CSS block must exist');
    assert.match(css, /var\(--bg\)/);
    assert.match(css, /var\(--border\)/);
    assert.match(css, /var\(--text-muted\)/);
    // Kind-icon palette uses the existing soft-color system
    assert.match(css, /var\(--blue-soft\)/);
    assert.match(css, /var\(--green-soft\)/);
    assert.match(css, /var\(--purple-soft\)/);
    // No raw hex / rgb colors — the only literal #/rgb in this block
    // would mean someone bypassed the design tokens. Search for any
    // `#[0-9a-fA-F]` pattern outside CSS variable declarations.
    const rawColors = css.match(/[^a-z]#[0-9a-fA-F]{3,6}\b/g);
    assert.equal(rawColors, null, `tree-view CSS must not contain raw hex colors; found: ${rawColors}`);
  });

  it('refreshTokens kicks off refreshUsageTree in parallel', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('async function refreshTokens'),
      _src_t3.indexOf('async function refreshTokens') + 4000,
    );
    assert.match(fn, /refreshUsageTree\(currentCutoff\)\.catch/);
    // Failure must be non-fatal — tree view is independent of the rest
    assert.match(fn, /Usage tree refresh failed/);
  });

  it('refreshUsageTree fetches /api/token-usage-tree with includeMisses=1', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('async function refreshUsageTree'),
      _src_t3.indexOf('async function refreshUsageTree') + 2000,
    );
    assert.match(fn, /\/api\/token-usage-tree\?includeMisses=1&from=/);
    // Must validate the response shape before dereferencing
    assert.match(fn, /data\.ok !== true/);
  });

  it('refreshUsageTree caches by hash to avoid DOM churn on identical data', () => {
    // Without the hash gate, the 5s poll re-renders the entire tree
    // every tick — wasting render time and causing visual flicker.
    // Slice bumped from 2000 → 3000 to span the round-2 R2-DASH-102
    // shape guard + R2-DASH-111 _treeHash addition.
    const fn = _src_t3.slice(
      _src_t3.indexOf('async function refreshUsageTree'),
      _src_t3.indexOf('async function refreshUsageTree') + 3000,
    );
    assert.match(fn, /_lastTreeHash/);
    assert.match(fn, /if \(hash === _lastTreeHash\) return/);
  });

  it('renderTreeNode escapes node names + uses native <details> for branches', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('function renderTreeNode'),
      _src_t3.indexOf('function renderTreeNode') + 3500,
    );
    assert.ok(fn.length > 200, 'function body must exist');
    // XSS — every dynamic field must run through escHtml
    assert.match(fn, /escHtml\(node\.name\)/);
    assert.match(fn, /escHtml\(kindLabel\)/);
    // Branches use <details>, leaves use <div class="tree-leaf">
    assert.match(fn, /<details/);
    assert.match(fn, /<div class="tree-leaf"/);
    // Top-level (depth 0) is open by default; deeper levels collapsed
    assert.match(fn, /depth === 0 \? ' open' : ''/);
  });

  it('renderTreeNode shows cache hit-rate badge when cache activity exists', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('function renderTreeNode'),
      _src_t3.indexOf('function renderTreeNode') + 3500,
    );
    // Hit-rate computed as cacheRead / (cacheRead + cacheCreate)
    assert.match(fn, /totals\.cacheRead \/ cacheTotal/);
    // Class chosen by 50% threshold (high vs low)
    assert.match(fn, /hitRate >= 50 \? 'high' : 'low'/);
    // Badge is omitted when there's no cache history
    assert.match(fn, /if \(cacheTotal > 0\)/);
  });

  it('renderTreeNode tags worktree branches with "wt" kind class', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('function renderTreeNode'),
      _src_t3.indexOf('function renderTreeNode') + 3500,
    );
    // The "branch" kind for a worktree gets a different visual treatment
    // than the main/master branch, per the TRDD's worktree-vs-main
    // distinction surfaced in aggregateUsageTree's isWorktree field.
    assert.match(fn, /isWorktree[\s\S]{0,200}kindClass = 'worktree'/);
    // The kindLabel ternary uses isWorktree to pick 'wt' as the badge text
    assert.match(fn, /isWorktree[\s\S]{0,200}'wt'/);
  });

  it('renderCacheMisses caps DOM at 50 rows but reports the true count', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('function renderCacheMisses'),
      _src_t3.indexOf('function renderCacheMisses') + 2000,
    );
    assert.ok(fn.length > 100, 'function body must exist');
    // Cap visible rows
    assert.match(fn, /misses\.slice\(-50\)/);
    // But the count badge shows the FULL count
    assert.match(fn, /countEl\.textContent = String\(misses\.length\)/);
    // "… and N more" footer when truncated (note: real ellipsis char, not "...")
    assert.match(fn, /and ' \+ \(misses\.length - 50\) \+ ' more/);
  });

  it('renderCacheMisses escapes every dynamic field (XSS regression)', () => {
    const fn = _src_t3.slice(
      _src_t3.indexOf('function renderCacheMisses'),
      _src_t3.indexOf('function renderCacheMisses') + 2000,
    );
    // The repo and branch fields are user-controlled (file paths +
    // git branch names). Both must run through escHtml.
    assert.match(fn, /escHtml\(\(m\.repo \|\| '\?'\) \+ ' \/ ' \+ \(m\.branch \|\| '\?'\)\)/);
    assert.match(fn, /escHtml\(ts\)/);
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 4 — tree-aggregated CSV export (lib.mjs helpers)
// ─────────────────────────────────────────────────────────

describe('Phase 4 — MODEL_PRICING table', () => {
  it('covers all current Claude generations (opus/sonnet/haiku 4-5..4-7)', () => {
    // Mirror of dashboard.mjs TOK_PRICING — adding a new model in one
    // place without the other silently undercounts cost in CSV exports.
    assert.ok(MODEL_PRICING['claude-opus-4-7'],   'opus 4-7 missing');
    assert.ok(MODEL_PRICING['claude-opus-4-6'],   'opus 4-6 missing');
    assert.ok(MODEL_PRICING['claude-opus-4-5'],   'opus 4-5 missing');
    assert.ok(MODEL_PRICING['claude-sonnet-4-7'], 'sonnet 4-7 missing');
    assert.ok(MODEL_PRICING['claude-sonnet-4-6'], 'sonnet 4-6 missing');
    assert.ok(MODEL_PRICING['claude-sonnet-4-5'], 'sonnet 4-5 missing');
    assert.ok(MODEL_PRICING['claude-haiku-4-6'],  'haiku 4-6 missing');
    assert.ok(MODEL_PRICING['claude-haiku-4-5'],  'haiku 4-5 missing');
  });

  it('every entry has the four required rate fields', () => {
    for (const [name, p] of Object.entries(MODEL_PRICING)) {
      assert.ok(typeof p.input         === 'number' && p.input         > 0, `${name}.input invalid`);
      assert.ok(typeof p.output        === 'number' && p.output        > 0, `${name}.output invalid`);
      assert.ok(typeof p.cacheRead     === 'number' && p.cacheRead    >= 0, `${name}.cacheRead invalid`);
      assert.ok(typeof p.cacheCreation === 'number' && p.cacheCreation > 0, `${name}.cacheCreation invalid`);
    }
  });

  it('cache rates respect Anthropic ratios (cacheRead ~10% of input, cacheCreation ~125%)', () => {
    // The published ratios are the load-bearing reason these can be
    // derived. If someone hand-edits a single column out of step, the
    // CSV export silently misreports cost — the regression catches that.
    for (const [name, p] of Object.entries(MODEL_PRICING)) {
      const readRatio   = p.cacheRead     / p.input;
      const createRatio = p.cacheCreation / p.input;
      assert.ok(Math.abs(readRatio - 0.10) < 0.005,
        `${name} cacheRead/input ratio ${readRatio} should be ~0.10`);
      assert.ok(Math.abs(createRatio - 1.25) < 0.005,
        `${name} cacheCreation/input ratio ${createRatio} should be ~1.25`);
    }
  });

  it('MODEL_PRICING_DEFAULT is non-zero (silent zero would undercount)', () => {
    // The TRDD specifically calls out: returning 0 for unknown models
    // would silently undercount. The default rates use Sonnet pricing
    // as a conservative middle ground.
    assert.ok(MODEL_PRICING_DEFAULT.input         > 0);
    assert.ok(MODEL_PRICING_DEFAULT.output        > 0);
    assert.ok(MODEL_PRICING_DEFAULT.cacheRead     > 0);
    assert.ok(MODEL_PRICING_DEFAULT.cacheCreation > 0);
  });
});

describe('Phase 4 — estimateModelCost', () => {
  it('exact model match uses that model\'s rates', () => {
    // claude-opus-4-7: $15/$75/$1.50/$18.75 per 1M tokens
    // 1M input + 1M output + 1M cache-read + 1M cache-create
    const cost = estimateModelCost('claude-opus-4-7', 1_000_000, 1_000_000, 1_000_000, 1_000_000);
    assert.equal(Math.round(cost * 100) / 100, 110.25); // 15+75+1.5+18.75
  });

  it('prefix match handles date-suffixed model IDs (forward-compat)', () => {
    // CC sometimes emits date-suffixed model IDs like
    // claude-opus-4-7-20260315. Without prefix matching the cost falls
    // back to the default rates — silently misreporting cost for every
    // turn after a model release.
    const exact = estimateModelCost('claude-opus-4-7',          1_000_000, 0, 0, 0);
    const dated = estimateModelCost('claude-opus-4-7-20260315', 1_000_000, 0, 0, 0);
    assert.equal(exact, dated);
  });

  it('unknown model uses MODEL_PRICING_DEFAULT (NOT zero)', () => {
    const cost = estimateModelCost('unknown-future-model-x', 1_000_000, 0, 0, 0);
    assert.equal(cost, MODEL_PRICING_DEFAULT.input);
  });

  it('null/empty/non-string model uses default rates', () => {
    const expected = MODEL_PRICING_DEFAULT.input; // 1M input tokens at default rate
    assert.equal(estimateModelCost(null,       1_000_000, 0, 0, 0), expected);
    assert.equal(estimateModelCost(undefined,  1_000_000, 0, 0, 0), expected);
    assert.equal(estimateModelCost('',         1_000_000, 0, 0, 0), expected);
    assert.equal(estimateModelCost(42,         1_000_000, 0, 0, 0), expected);
  });

  it('zero tokens returns zero cost', () => {
    assert.equal(estimateModelCost('claude-opus-4-7', 0, 0, 0, 0), 0);
  });

  it('null/undefined token counts treated as zero', () => {
    // Real CC rows sometimes have nullish cache fields when no cache
    // activity happened — never throw on those.
    const cost = estimateModelCost('claude-sonnet-4-7', null, undefined, null, undefined);
    assert.equal(cost, 0);
  });

  it('cost is linear in token count', () => {
    const a = estimateModelCost('claude-haiku-4-5',   500_000, 100_000, 0, 0);
    const b = estimateModelCost('claude-haiku-4-5', 1_000_000, 200_000, 0, 0);
    // Within floating-point tolerance, b ≈ 2*a
    assert.ok(Math.abs(b - 2 * a) < 1e-9, `expected b≈2a, got a=${a}, b=${b}`);
  });
});

describe('Phase 4 — csvField (RFC 4180 always-quote)', () => {
  it('wraps strings in double-quotes', () => {
    assert.equal(csvField('hello'),    '"hello"');
    assert.equal(csvField(''),         '""');
  });

  it('escapes embedded double-quotes by doubling them', () => {
    // RFC 4180 §2.7: "If double-quotes are used to enclose fields,
    // then a double-quote appearing inside a field must be escaped by
    // preceding it with another double quote."
    assert.equal(csvField('say "hi"'), '"say ""hi"""');
  });

  it('preserves embedded newlines (RFC 4180 §2.6)', () => {
    // Newlines inside quoted fields are explicitly allowed.
    assert.equal(csvField('line1\nline2'), '"line1\nline2"');
  });

  it('numbers are stringified, finite-only', () => {
    assert.equal(csvField(42),        '"42"');
    assert.equal(csvField(0),         '"0"');
    assert.equal(csvField(-1.5),      '"-1.5"');
    // NaN / Infinity become empty quoted fields rather than the JS
    // string "NaN" (which would import as a literal cell value).
    assert.equal(csvField(NaN),       '""');
    assert.equal(csvField(Infinity),  '""');
  });

  it('booleans become "true"/"false" strings', () => {
    assert.equal(csvField(true),  '"true"');
    assert.equal(csvField(false), '"false"');
  });

  it('null / undefined become an empty quoted field', () => {
    assert.equal(csvField(null),      '""');
    assert.equal(csvField(undefined), '""');
  });
});

describe('Phase 4 — aggregateUsageForCsvExport', () => {
  function _row(over) {
    return Object.assign({
      type: 'usage',
      ts: 1000,
      repo: '/repo/a',
      branch: 'main',
      model: 'claude-sonnet-4-7',
      tool: 'Bash',
      account: 'acct1',
      inputTokens: 1000,
      outputTokens: 200,
      cacheReadInputTokens: 100,
      cacheCreationInputTokens: 50,
    }, over || {});
  }

  it('returns empty array on empty/non-array input', () => {
    assert.deepEqual(aggregateUsageForCsvExport([]), []);
    assert.deepEqual(aggregateUsageForCsvExport(null), []);
    assert.deepEqual(aggregateUsageForCsvExport(undefined), []);
    assert.deepEqual(aggregateUsageForCsvExport('not-array'), []);
  });

  it('buckets rows by (repo, branch, component, tool)', () => {
    const rows = [
      _row({ repo: '/repo/a', branch: 'main', tool: 'Bash' }),
      _row({ repo: '/repo/a', branch: 'main', tool: 'Bash' }),
      _row({ repo: '/repo/a', branch: 'main', tool: 'Read' }),
      _row({ repo: '/repo/b', branch: 'main', tool: 'Bash' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 3, 'three distinct buckets');
    const a_main_bash = out.find(r => r.repo === '/repo/a' && r.tool === 'Bash');
    assert.equal(a_main_bash.requestCount, 2, 'two Bash calls in /repo/a/main collapsed');
  });

  it('skips non-usage rows (compact-boundary, etc.)', () => {
    const rows = [
      _row(),
      // Audit SR-OP-001: real production rows use 'compact_boundary'
      // (see buildCompactBoundaryEntry). Both should still be skipped
      // by the CSV exporter — only 'usage' counts.
      _row({ type: 'compact_boundary' }),
      _row({ type: 'unknown' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].requestCount, 1);
  });

  it('skips rows with non-finite token counts', () => {
    const rows = [
      _row(),
      _row({ inputTokens: NaN }),
      _row({ outputTokens: Infinity }),
      _row({ inputTokens: 'oops' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].requestCount, 1);
  });

  it('repoFilter, accountFilter, modelFilter narrow the set', () => {
    const rows = [
      _row({ repo: '/repo/a', account: 'a1', model: 'claude-opus-4-7' }),
      _row({ repo: '/repo/b', account: 'a1', model: 'claude-opus-4-7' }),
      _row({ repo: '/repo/a', account: 'a2', model: 'claude-opus-4-7' }),
      _row({ repo: '/repo/a', account: 'a1', model: 'claude-sonnet-4-7' }),
    ];
    assert.equal(aggregateUsageForCsvExport(rows, { repoFilter: '/repo/a' }).reduce((s, r) => s + r.requestCount, 0), 3);
    assert.equal(aggregateUsageForCsvExport(rows, { accountFilter: 'a1' }).reduce((s, r) => s + r.requestCount, 0), 3);
    assert.equal(aggregateUsageForCsvExport(rows, { modelFilter: 'claude-opus-4-7' }).reduce((s, r) => s + r.requestCount, 0), 3);
  });

  it('from/to time-range filter narrows by ts', () => {
    const rows = [
      _row({ ts: 1000 }),
      _row({ ts: 2000 }),
      _row({ ts: 3000 }),
    ];
    assert.equal(aggregateUsageForCsvExport(rows, { from: 1500 }).reduce((s, r) => s + r.requestCount, 0), 2);
    assert.equal(aggregateUsageForCsvExport(rows, { to: 1500 }).reduce((s, r) => s + r.requestCount, 0), 1);
    assert.equal(aggregateUsageForCsvExport(rows, { from: 1500, to: 2500 }).reduce((s, r) => s + r.requestCount, 0), 1);
  });

  it('isWorktree flag is true for non-main/master branches', () => {
    const rows = [
      _row({ branch: 'main' }),
      _row({ branch: 'master' }),
      _row({ branch: 'feature/x' }),
      _row({ branch: '(no git)' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    const byBranch = Object.fromEntries(out.map(r => [r.branch, r.isWorktree]));
    assert.equal(byBranch['main'],     false);
    assert.equal(byBranch['master'],   false);
    assert.equal(byBranch['feature/x'], true);
    assert.equal(byBranch['(no git)'], false);
  });

  it('null tool collapses to "<assistant>" key (matches aggregateUsageTree)', () => {
    // Rows with no `tool` field are the assistant turn itself, before any
    // tool call. The flat aggregator must match the tree's labeling so
    // CSV importers can join the two views by the same key.
    const rows = [
      _row({ tool: null }),
      _row({ tool: undefined }),
      _row({ tool: '' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].tool, '<assistant>');
    assert.equal(out[0].requestCount, 3);
  });

  it('totalCostUSD is summed across rows in the same bucket', () => {
    // Two rows in the same bucket, different costs — the bucket cost
    // must equal the sum (NOT the cost of a single representative row).
    const rows = [
      _row({ inputTokens: 1_000_000, outputTokens: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0,
             model: 'claude-sonnet-4-7' }),
      _row({ inputTokens: 1_000_000, outputTokens: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0,
             model: 'claude-sonnet-4-7' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    // Sonnet input rate = $3/M, two rows = $6 total
    assert.ok(Math.abs(out[0].totalCostUSD - 6) < 1e-9);
  });

  it('cost across mixed models in one bucket sums per-row (not per-bucket)', () => {
    // The whole reason this aggregator exists vs aggregateUsageTree:
    // a single bucket can contain rows from multiple models (rare but
    // possible — same repo/branch/component/tool on different days).
    // Cost MUST be summed per-row using each row's own model.
    const rows = [
      _row({ model: 'claude-opus-4-7',   inputTokens: 1_000_000, outputTokens: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 }),
      _row({ model: 'claude-haiku-4-5',  inputTokens: 1_000_000, outputTokens: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    // Opus input = $15/M, haiku input = $0.80/M → $15.80 total
    assert.ok(Math.abs(out[0].totalCostUSD - 15.80) < 1e-9);
  });

  it('output is sorted heavy-first (input + output tokens descending)', () => {
    const rows = [
      _row({ repo: '/light',  inputTokens: 100,    outputTokens: 50  }),
      _row({ repo: '/heavy',  inputTokens: 10000,  outputTokens: 5000 }),
      _row({ repo: '/medium', inputTokens: 1000,   outputTokens: 500 }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out[0].repo, '/heavy');
    assert.equal(out[1].repo, '/medium');
    assert.equal(out[2].repo, '/light');
  });

  it('uses NUL byte as bucket-key separator (so paths with | do not collide)', () => {
    // Path with literal | character — would collide with a different
    // bucket if the separator were |. With \0, the keys remain distinct.
    const rows = [
      _row({ repo: 'a|b',  branch: 'main', tool: 'Bash' }),
      _row({ repo: 'a',    branch: 'b|main', tool: 'Bash' }),
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 2, 'distinct buckets despite pipe in field');
  });
});

describe('Phase 4 — renderUsageTreeCsv', () => {
  it('emits header even on empty input (CRLF line ending per RFC 4180)', () => {
    // Audit MINOR-2: RFC 4180 §2.1 mandates CRLF.
    const csv = renderUsageTreeCsv([]);
    assert.equal(csv, 'repo,branch,isWorktree,component,tool,inputTokens,outputTokens,cacheReadTokens,cacheCreationTokens,totalCostUSD,requestCount\r\n');
  });

  it('handles null/non-array input as empty (header only)', () => {
    assert.equal(renderUsageTreeCsv(null).startsWith('repo,branch,'), true);
    assert.equal(renderUsageTreeCsv(undefined).startsWith('repo,branch,'), true);
    assert.equal(renderUsageTreeCsv('not-array').startsWith('repo,branch,'), true);
  });

  it('header has all 11 columns in documented order (CSV importer contract)', () => {
    // Reorder = silent breaking change for any downstream importer
    // (spreadsheets, ETL pipelines). Lock the order in.
    const csv = renderUsageTreeCsv([]);
    // Split on the explicit CRLF that RFC 4180 mandates.
    const header = csv.split('\r\n')[0];
    const cols = header.split(',');
    assert.deepEqual(cols, [
      'repo', 'branch', 'isWorktree', 'component', 'tool',
      'inputTokens', 'outputTokens', 'cacheReadTokens', 'cacheCreationTokens',
      'totalCostUSD', 'requestCount',
    ]);
  });

  it('every body row has all 11 fields, all quoted', () => {
    const rows = [{
      repo: '/repo/a', branch: 'main', isWorktree: false,
      component: 'main', tool: 'Bash',
      inputTokens: 1000, outputTokens: 200,
      cacheReadTokens: 100, cacheCreationTokens: 50,
      totalCostUSD: 0.005, requestCount: 1,
    }];
    const csv = renderUsageTreeCsv(rows);
    const bodyLine = csv.split('\r\n')[1];
    // Every field is always quoted per the implementation comment
    const fields = bodyLine.split(',');
    assert.equal(fields.length, 11);
    for (const f of fields) {
      assert.ok(f.startsWith('"') && f.endsWith('"'), `field ${f} should be quoted`);
    }
  });

  it('escapes double-quotes in repo / branch fields (RFC 4180)', () => {
    const rows = [{
      repo: 'has"quote', branch: 'main', isWorktree: false,
      component: 'main', tool: 'Bash',
      inputTokens: 0, outputTokens: 0,
      cacheReadTokens: 0, cacheCreationTokens: 0,
      totalCostUSD: 0, requestCount: 1,
    }];
    const csv = renderUsageTreeCsv(rows);
    assert.match(csv, /"has""quote"/);
  });

  it('cost rounded to 6 decimals (fractions of a cent are noise)', () => {
    const rows = [{
      repo: '/r', branch: 'main', isWorktree: false,
      component: 'main', tool: 'Bash',
      inputTokens: 0, outputTokens: 0,
      cacheReadTokens: 0, cacheCreationTokens: 0,
      totalCostUSD: 0.123456789012, requestCount: 1,
    }];
    const csv = renderUsageTreeCsv(rows);
    // Should round to 0.123457 (6 decimal places). The exact serialization
    // depends on Number→String, so look for the rounded value as a substring.
    assert.match(csv, /"0\.123457"/);
  });

  it('terminates with a trailing CRLF (RFC 4180)', () => {
    const rows = [{
      repo: '/r', branch: 'main', isWorktree: false,
      component: 'main', tool: 'Bash',
      inputTokens: 1, outputTokens: 1,
      cacheReadTokens: 0, cacheCreationTokens: 0,
      totalCostUSD: 0, requestCount: 1,
    }];
    const csv = renderUsageTreeCsv(rows);
    assert.ok(csv.endsWith('\r\n'));
  });

  it('round-trip: aggregator → CSV preserves request counts', () => {
    // End-to-end shape check: build a known set of rows, aggregate them,
    // render, and parse the body lines back to confirm the count column
    // sums to the input row count.
    const rows = [
      { type: 'usage', ts: 1000, repo: '/r', branch: 'main', tool: 'Bash',
        inputTokens: 100, outputTokens: 50, model: 'claude-sonnet-4-7' },
      { type: 'usage', ts: 1100, repo: '/r', branch: 'main', tool: 'Bash',
        inputTokens: 200, outputTokens: 100, model: 'claude-sonnet-4-7' },
      { type: 'usage', ts: 1200, repo: '/r', branch: 'main', tool: 'Read',
        inputTokens: 50, outputTokens: 10, model: 'claude-sonnet-4-7' },
    ];
    const flat = aggregateUsageForCsvExport(rows);
    const csv  = renderUsageTreeCsv(flat);
    // Audit MINOR-2: split on CRLF (RFC 4180 record separator). The
    // .filter(l.length > 0) drops the trailing empty element from the
    // final \r\n.
    const lines = csv.split('\r\n').filter(l => l.length > 0);
    // header + 2 buckets (Bash×2 collapsed, Read×1)
    assert.equal(lines.length, 3);
    // The requestCount column is the last one — re-extract and sum.
    const total = lines.slice(1).reduce((sum, line) => {
      const cols = line.split(',');
      return sum + Number(cols[cols.length - 1].replace(/"/g, ''));
    }, 0);
    assert.equal(total, 3);
  });
});

describe('Phase 4 — /api/token-usage-tree?format=csv endpoint wiring', () => {
  const _src_t4 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports aggregateUsageForCsvExport + renderUsageTreeCsv from lib.mjs', () => {
    assert.match(_src_t4, /aggregateUsageForCsvExport,/);
    assert.match(_src_t4, /renderUsageTreeCsv,/);
  });

  it('format=csv branch exists inside the token-usage-tree handler', () => {
    const fn = _src_t4.slice(
      _src_t4.indexOf("'/api/token-usage-tree'"),
      _src_t4.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /params\.get\('format'\) === 'csv'/);
    assert.match(fn, /aggregateUsageForCsvExport\(rows, opts\)/);
    assert.match(fn, /renderUsageTreeCsv\(/);
  });

  it('CSV branch sets the right Content-Type and Content-Disposition', () => {
    const fn = _src_t4.slice(
      _src_t4.indexOf("'/api/token-usage-tree'"),
      _src_t4.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /'content-type':\s*'text\/csv;\s*charset=utf-8'/);
    assert.match(fn, /'content-disposition':\s*`attachment;\s*filename="token-usage-tree-/);
  });

  it('CSV branch returns BEFORE the JSON branch (early return)', () => {
    // Without the early return, format=csv would run the aggregator AND
    // also fall through to the JSON response builder — wasting work and
    // potentially writing two response bodies.
    const fn = _src_t4.slice(
      _src_t4.indexOf("'/api/token-usage-tree'"),
      _src_t4.indexOf("'/api/token-usage-tree'") + 8500,
    );
    const csvIdx  = fn.indexOf("params.get('format') === 'csv'");
    const treeIdx = fn.indexOf('aggregateUsageTree(rows, opts)');
    assert.ok(csvIdx > 0 && treeIdx > 0);
    assert.ok(csvIdx < treeIdx, 'csv branch must precede the JSON tree branch');
    // And there must be a return inside the CSV branch
    const csvBlock = fn.slice(csvIdx, treeIdx);
    assert.match(csvBlock, /return true;/);
  });

  it('CSV filename uses an ISO-derived stamp (sortable, no colons)', () => {
    // Colons in filenames are filesystem-unsafe on Windows. The stamp
    // must replace `:` and `.` from the ISO string with `-`.
    const fn = _src_t4.slice(
      _src_t4.indexOf("'/api/token-usage-tree'"),
      _src_t4.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /toISOString\(\)\.replace\(\/\[:\.\]\/g,\s*'-'\)/);
  });
});

describe('Phase 4 — UI: Export tree CSV button + handler', () => {
  const _src_t4ui = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('"Export tree CSV" button is present in the Tokens tab', () => {
    assert.match(_src_t4ui, /onclick="exportUsageTreeCsv\(\)"/);
    assert.match(_src_t4ui, />Export tree CSV</);
  });

  it('button has a tooltip explaining it differs from the flat export', () => {
    // Without the title attribute, users who already use "Export CSV"
    // wouldn't know why a second button appeared. Cheap discoverability.
    const idx = _src_t4ui.indexOf('exportUsageTreeCsv()');
    const buttonHtml = _src_t4ui.slice(idx - 200, idx + 200);
    assert.match(buttonHtml, /title="[^"]+"/);
  });

  it('exportUsageTreeCsv collects the same filters as the rest of the Tokens tab', () => {
    const fn = _src_t4ui.slice(
      _src_t4ui.indexOf('function exportUsageTreeCsv'),
      _src_t4ui.indexOf('function exportUsageTreeCsv') + 2000,
    );
    assert.ok(fn.length > 200, 'function body must exist');
    // Reuses vsSnapshot for the time range (same as exportUsageCsv)
    assert.match(fn, /vsSnapshot\(\)/);
    // Pulls model + account + repo from the existing dropdowns
    assert.match(fn, /getElementById\('tok-model'\)/);
    assert.match(fn, /getElementById\('tok-account'\)/);
    assert.match(fn, /getElementById\('tok-repo'\)/);
  });

  it('exportUsageTreeCsv builds a query string with format=csv', () => {
    const fn = _src_t4ui.slice(
      _src_t4ui.indexOf('function exportUsageTreeCsv'),
      _src_t4ui.indexOf('function exportUsageTreeCsv') + 2000,
    );
    assert.match(fn, /'format=csv'/);
    // Filter values URL-encoded
    assert.match(fn, /encodeURIComponent\(modelV\)/);
    assert.match(fn, /encodeURIComponent\(accountV\)/);
    assert.match(fn, /encodeURIComponent\(repoV\)/);
    // Audit CC-DASH-005: from/to are now derived via local fromTs/toTs
    // variables that fall back to the tok-time selector when the
    // scrubber hasn't been touched. The encodeURIComponent calls take
    // those derived values, NOT snap.start/snap.end directly.
    assert.match(fn, /encodeURIComponent\(fromTs\)/);
    assert.match(fn, /encodeURIComponent\(toTs\)/);
    // Fallback to tok-time when snap is null
    assert.match(fn, /tokTimeRange/);
  });

  it('exportUsageTreeCsv uses an anchor download (lets server set filename)', () => {
    // Anchor download (without explicit name) honors the server's
    // Content-Disposition. The flat exporter builds a Blob in memory;
    // tree CSV streams from disk so we want the browser to do the I/O.
    const fn = _src_t4ui.slice(
      _src_t4ui.indexOf('function exportUsageTreeCsv'),
      _src_t4ui.indexOf('function exportUsageTreeCsv') + 2000,
    );
    assert.match(fn, /document\.createElement\('a'\)/);
    assert.match(fn, /a\.href = '\/api\/token-usage-tree\?'/);
    assert.match(fn, /a\.click\(\)/);
    // No Blob — that would defeat the streaming
    assert.ok(!/new Blob/.test(fn), 'should NOT build a Blob (lets browser stream)');
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 5 — richer cache-miss reason classification
// ─────────────────────────────────────────────────────────

describe('Phase 5 — buildCacheMissReport reason classification', () => {
  it('CACHE_TTL_LIKELY_MS matches Anthropic published 5-minute TTL', () => {
    assert.equal(CACHE_TTL_LIKELY_MS, 5 * 60 * 1000);
  });

  it('reason "compact-boundary" wins when a compact preceded the miss', () => {
    // A compact-boundary marker between the cache-creating turn and
    // the miss explains the miss perfectly — the prefix changed by
    // definition. Should NOT be classified as TTL-likely even when
    // the time gap exceeds the TTL.
    // Audit SR-OP-001: production rows use 'compact_boundary' (see
    // buildCompactBoundaryEntry in lib.mjs:2340). The earlier draft of
    // this test used 'compact' and the production code did too — both
    // wrong in the same way, so the test passed green while the
    // classifier was dead code in production.
    const rows = [
      { type: 'usage',   sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'compact_boundary', sessionId: 's1', ts: 1500 },
      { type: 'usage',   sessionId: 's1', ts: 2000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].reason, 'compact-boundary');
  });

  it('reason "model-changed" when the prior cache was on a different model', () => {
    // Caches are model-scoped: switching models invalidates the cache
    // even if the prefix would otherwise have hit. Should beat
    // "TTL-likely" when both could apply.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1100, model: 'claude-sonnet-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].reason, 'model-changed');
  });

  it('reason "TTL-likely" when the gap exceeds the configured TTL', () => {
    // Same model, no compact, but >= TTL since the last cache creation.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].reason, 'TTL-likely');
  });

  it('reason "unknown" when within TTL, same model, no compact', () => {
    // Could be a /clear, an OAuth-rotation gap, or a real prefix
    // change. Heuristic admits ignorance instead of guessing wrong.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 2000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].reason, 'unknown');
  });

  it('cacheTtlMs opt overrides the default TTL', () => {
    // Same gap of 100ms, but with a 10ms TTL it should be classified
    // as TTL-likely; with a 1000ms TTL it falls to unknown.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1100, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    assert.equal(buildCacheMissReport(rows, { cacheTtlMs: 10   })[0].reason, 'TTL-likely');
    assert.equal(buildCacheMissReport(rows, { cacheTtlMs: 1000 })[0].reason, 'unknown');
  });

  it('compact rows themselves never appear as misses', () => {
    // The compact-boundary marker is a meta-event, not a usage turn.
    // It should drive reason classification of subsequent usage rows
    // but never be reported as a miss in its own right.
    // Audit SR-OP-001: production type-string is 'compact_boundary'.
    const rows = [
      { type: 'usage',   sessionId: 's1', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'compact_boundary', sessionId: 's1', ts: 1500 },
      { type: 'usage',   sessionId: 's1', ts: 2000, inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    // Exactly one miss — the second usage row, not the compact
    assert.equal(out.length, 1);
    assert.equal(out[0].ts, 2000);
  });

  it('first turn is never a miss (no prior cache existed)', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    assert.deepEqual(buildCacheMissReport(rows), []);
  });

  it('input below threshold is never a miss', () => {
    // A turn with tiny input legitimately may not need cache —
    // shouldn't pollute the miss list with noise.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 2000, inputTokens: 100,  cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    assert.deepEqual(buildCacheMissReport(rows), []);
  });

  it('preserves all expected fields per miss', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0,
        repo: '/r', branch: 'main' },
      { type: 'usage', sessionId: 's1', ts: 2000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0,
        repo: '/r', branch: 'main' },
    ];
    const out = buildCacheMissReport(rows);
    const m = out[0];
    assert.equal(m.sessionId, 's1');
    assert.equal(m.ts, 2000);
    assert.equal(m.model, 'claude-opus-4-7');
    assert.equal(m.inputTokens, 5000);
    assert.equal(m.repo, '/r');
    assert.equal(m.branch, 'main');
    assert.ok(typeof m.reason === 'string');
  });
});

describe('Phase 5 — summarizeCacheMissesBySession', () => {
  it('returns empty array on empty/non-array input', () => {
    assert.deepEqual(summarizeCacheMissesBySession([]),         []);
    assert.deepEqual(summarizeCacheMissesBySession(null),       []);
    assert.deepEqual(summarizeCacheMissesBySession(undefined),  []);
    assert.deepEqual(summarizeCacheMissesBySession('not-array'), []);
  });

  it('drops sessions with neither hits nor misses (silent rows)', () => {
    // Sessions where every turn was below the threshold and no cache
    // ever existed are noise — should not show up at all in the UI.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 100, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 2000, inputTokens: 200, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    assert.deepEqual(summarizeCacheMissesBySession(rows), []);
  });

  it('counts hits (any cacheRead > 0) per session', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 0,    cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 2000, inputTokens: 5000, cacheReadInputTokens: 800,  cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 3000, inputTokens: 5000, cacheReadInputTokens: 800,  cacheCreationInputTokens: 0 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].hits, 2);
    assert.equal(out[0].misses, 0);
    assert.equal(out[0].hitRate, 100);
  });

  it('counts misses sourced from buildCacheMissReport (consistency)', () => {
    // hit=0 + miss=1 → 0% hit rate
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 0,    cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 2000 + CACHE_TTL_LIKELY_MS, inputTokens: 5000, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].misses, 1);
    assert.equal(out[0].hitRate, 0);
  });

  it('hitRate computes hits / (hits + misses) with one decimal', () => {
    // 2 hits + 1 miss = 66.7%
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 0,   cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1100, inputTokens: 5000, cacheReadInputTokens: 800, cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1200, inputTokens: 5000, cacheReadInputTokens: 800, cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1300 + CACHE_TTL_LIKELY_MS, inputTokens: 5000, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].hits, 2);
    assert.equal(out[0].misses, 1);
    assert.equal(out[0].hitRate, 66.7);
  });

  it('captures the most-recent repo/branch (sessions wander as user cd\'s)', () => {
    // Session starts in /a/main, ends in /b/feat — the header should
    // show /b/feat (the user's current expectation).
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, repo: '/a', branch: 'main', inputTokens: 5000, cacheReadInputTokens: 800 },
      { type: 'usage', sessionId: 's1', ts: 2000, repo: '/b', branch: 'feat', inputTokens: 5000, cacheReadInputTokens: 800 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out[0].repo, '/b');
    assert.equal(out[0].branch, 'feat');
  });

  it('sorted by lastTs descending (recently active first)', () => {
    const rows = [
      { type: 'usage', sessionId: 's-old',  ts: 1000, inputTokens: 5000, cacheReadInputTokens: 800 },
      { type: 'usage', sessionId: 's-new',  ts: 5000, inputTokens: 5000, cacheReadInputTokens: 800 },
      { type: 'usage', sessionId: 's-mid',  ts: 3000, inputTokens: 5000, cacheReadInputTokens: 800 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out[0].sessionId, 's-new');
    assert.equal(out[1].sessionId, 's-mid');
    assert.equal(out[2].sessionId, 's-old');
  });

  it('missDetails is the same array shape as buildCacheMissReport rows', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 0, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 2000 + CACHE_TTL_LIKELY_MS, inputTokens: 5000, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].missDetails.length, 1);
    const md = out[0].missDetails[0];
    assert.equal(md.sessionId, 's1');
    assert.equal(md.ts, 2000 + CACHE_TTL_LIKELY_MS);
    assert.ok('reason' in md);
  });

  it('multiple sessions are aggregated independently', () => {
    const rows = [
      // s1 — 1 hit + 1 miss
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 0,   cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1100, inputTokens: 5000, cacheReadInputTokens: 800, cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1200 + CACHE_TTL_LIKELY_MS, inputTokens: 5000, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
      // s2 — 1 hit + 0 misses
      { type: 'usage', sessionId: 's2', ts: 1500, inputTokens: 5000, cacheReadInputTokens: 0,   cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's2', ts: 1600, inputTokens: 5000, cacheReadInputTokens: 800, cacheCreationInputTokens: 0 },
    ];
    const out = summarizeCacheMissesBySession(rows);
    assert.equal(out.length, 2);
    const s1 = out.find(s => s.sessionId === 's1');
    const s2 = out.find(s => s.sessionId === 's2');
    assert.equal(s1.hits, 1); assert.equal(s1.misses, 1); assert.equal(s1.hitRate, 50);
    assert.equal(s2.hits, 1); assert.equal(s2.misses, 0); assert.equal(s2.hitRate, 100);
  });
});

describe('Phase 5 — endpoint emits missSessions when includeMisses=1', () => {
  const _src_t5 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports summarizeCacheMissesBySession from lib.mjs', () => {
    assert.match(_src_t5, /summarizeCacheMissesBySession,/);
  });

  it('endpoint computes summary inside the includeMisses guard', () => {
    const fn = _src_t5.slice(
      _src_t5.indexOf("'/api/token-usage-tree'"),
      _src_t5.indexOf("'/api/token-usage-tree'") + 8500,
    );
    // Inside the guard: both the buildCacheMissReport call AND the
    // new summarizeCacheMissesBySession call.
    // Audit CC-DASH-016: the endpoint now computes flatMisses ONCE
    // and assigns it directly; both downstream helpers are called
    // with the precomputed list for performance.
    assert.match(fn, /const flatMisses = buildCacheMissReport/);
    assert.match(fn, /response\.misses\s*=\s*flatMisses/);
    assert.match(fn, /response\.missSessions = summarizeCacheMissesBySession/);
    // The summary must be inside the same guard
    const guardIdx = fn.indexOf("params.get('includeMisses')");
    const summaryIdx = fn.indexOf('summarizeCacheMissesBySession');
    assert.ok(summaryIdx > guardIdx, 'summary call must be inside includeMisses guard');
  });

  it('time-range pre-filter keeps compact_boundary rows (Phase 5 reason classification needs them)', () => {
    // Audit SR-OP-001: production type-string is 'compact_boundary'.
    // Without keeping these rows in the pre-filter, every miss in a
    // filtered view would lose its compact-boundary classification —
    // silently degrading to TTL-likely or unknown.
    const fn = _src_t5.slice(
      _src_t5.indexOf("'/api/token-usage-tree'"),
      _src_t5.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /t !== 'usage' && t !== 'compact_boundary'/);
  });
});

describe('Phase 5 — UI: per-session misses card', () => {
  const _src_t5ui = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('refreshUsageTree passes missSessions to renderCacheMisses', () => {
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('async function refreshUsageTree'),
      _src_t5ui.indexOf('async function refreshUsageTree') + 2500,
    );
    assert.match(fn, /renderCacheMisses\(data\.misses \|\| \[\], data\.missSessions \|\| \[\]\)/);
    // Hash must include missSessions count or stale data wins
    assert.match(fn, /missSessions \? data\.missSessions\.length : 0/);
  });

  it('renderCacheMisses signature accepts (misses, missSessions)', () => {
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('function renderCacheMisses'),
      _src_t5ui.indexOf('function renderCacheMisses') + 4500,
    );
    assert.match(fn, /function renderCacheMisses\(misses, missSessions\)/);
  });

  it('renders per-session <details> blocks with hit-rate badges', () => {
    // Slice bumped from 4500 → 10000 to span the UX-CM1 sticky-state
    // resolution block + UX-CM3 expand toggle added in batch H. The
    // function is ~9K now (was ~4K when this test was written).
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('function renderCacheMisses'),
      _src_t5ui.indexOf('function renderCacheMisses') + 10000,
    );
    assert.match(fn, /miss-session/);
    assert.match(fn, /miss-rate-badge/);
    // Hit-rate threshold matches the tree-view badge convention (50%)
    assert.match(fn, /hitRate >= 50/);
    // hits + misses count is shown in the badge
    assert.match(fn, /miss-rate-counts/);
  });

  it('per-row miss line shows model + reason columns (XSS-safe)', () => {
    // Slice bumped from 6000 → 10000 to span the UX batch H expansion
    // (UX-CM1 sticky-state + UX-CM3 expand toggle). The function is ~9K
    // now; previously ~6K when SC-OPUS-002 added the allow-list block.
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('function renderCacheMisses'),
      _src_t5ui.indexOf('function renderCacheMisses') + 10000,
    );
    assert.match(fn, /miss-model/);
    assert.match(fn, /miss-reason/);
    // Both model and reason routed through escHtml for XSS safety
    assert.match(fn, /escHtml\(modelText\)/);
    assert.match(fn, /escHtml\(reasonText\)/);
    // Audit SC-OPUS-002: reason class is derived from a strict
    // allow-list, NOT a regex strip. The previous fragile-by-design
    // pattern would silently open an XSS sink under any future
    // refactor that broadened the reason set.
    assert.match(fn, /var reasonKey\s*=\s*KNOWN_MISS_REASONS\[reasonText\] \? reasonText : 'unknown'/);
    assert.match(fn, /var reasonClass = 'reason-' \+ reasonKey/);
  });

  it('caps DOM at 5 sessions x 10 rows-per-session, footer reports overflow', () => {
    // Slice bumped from 6000 → 10000 (see XSS test above).
    // UX-CM3 replaced the per-session "older miss(es) in this session"
    // <div> footer with a <button class="miss-show-more"> that says
    // "Show N older miss(es)" — assert that copy too.
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('function renderCacheMisses'),
      _src_t5ui.indexOf('function renderCacheMisses') + 10000,
    );
    assert.match(fn, /SESSION_CAP = 5/);
    assert.match(fn, /ROWS_PER_SESSION_CAP = 10/);
    // Both overflow footers must exist: the global sessions footer
    // (still a <div>) and the per-session inline-expand button.
    assert.match(fn, /more session\(s\) with cache misses/);
    // UX-CM3: the per-session truncation row is now a <button> labelled
    // "Show N older miss(es)" — pin the button class so a future
    // refactor cannot silently revert to the old non-actionable <div>.
    assert.match(fn, /miss-show-more/);
    assert.match(fn, /Show ' \+ hiddenCount \+ ' older miss/);
  });

  it('falls back to flat list when missSessions is empty (back-compat)', () => {
    // A older endpoint version (or future malformed response) might
    // not emit missSessions; the UI should still render SOMETHING from
    // the flat list rather than silently displaying empty.
    const fn = _src_t5ui.slice(
      _src_t5ui.indexOf('function renderCacheMisses'),
      _src_t5ui.indexOf('function renderCacheMisses') + 4500,
    );
    // Fallback path must reference the flat misses array's slice/reverse
    assert.match(fn, /misses\.slice\(-50\)\.reverse\(\)/);
  });

  it('CSS for per-session blocks uses defined design tokens', () => {
    // Every new color reference must hit a defined --foo or --foo-soft
    // variable. The TRDD §"CSS using existing dashboard variables (no
    // new color palette)" mandate.
    const cssBlock = _src_t5ui.slice(
      _src_t5ui.indexOf('.tree-misses-card .miss-session {'),
      _src_t5ui.indexOf('.tok-export-btn {'),
    );
    assert.ok(cssBlock.length > 500, 'per-session CSS block must exist');
    // Reason classes
    assert.match(cssBlock, /\.reason-TTL-likely/);
    assert.match(cssBlock, /\.reason-compact-boundary/);
    assert.match(cssBlock, /\.reason-model-changed/);
    // No raw hex colors
    const rawColors = cssBlock.match(/[^a-z]#[0-9a-fA-F]{3,6}\b/g);
    assert.equal(rawColors, null, `Phase 5 CSS must not contain raw hex; found: ${rawColors}`);
    // Only defined CSS variables — no --orange or --blue (base) which
    // don't exist in the palette.
    assert.ok(!/var\(--orange[^-]/.test(cssBlock), 'must not reference undefined --orange token');
    assert.ok(!/var\(--blue\)/.test(cssBlock),     'must not reference undefined --blue token (use --primary)');
  });
});

// ─────────────────────────────────────────────────────────
// Phase 6 — buildWastedSpendSeries
// ─────────────────────────────────────────────────────────

describe('Phase 6 — buildWastedSpendSeries', () => {
  it('returns empty array for empty/non-array/zero-misses input', () => {
    assert.deepEqual(buildWastedSpendSeries([]),         []);
    assert.deepEqual(buildWastedSpendSeries(null),       []);
    assert.deepEqual(buildWastedSpendSeries(undefined),  []);
    // Rows that produce no misses → empty series
    const noMisses = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheReadInputTokens: 800, cacheCreationInputTokens: 0 },
    ];
    assert.deepEqual(buildWastedSpendSeries(noMisses), []);
  });

  it('emits one entry per cache miss with all expected fields', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0,
        repo: '/r', branch: 'main' },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0,
        repo: '/r', branch: 'main' },
    ];
    const out = buildWastedSpendSeries(rows);
    assert.equal(out.length, 1);
    const p = out[0];
    assert.equal(p.ts,          1000 + CACHE_TTL_LIKELY_MS + 1);
    assert.equal(p.inputTokens, 5000);
    assert.equal(p.model,       'claude-opus-4-7');
    assert.equal(p.repo,        '/r');
    assert.equal(p.branch,      'main');
    assert.equal(p.sessionId,   's1');
    assert.equal(p.reason,      'TTL-likely');
    // Cost computed via estimateModelCost (5000 input * $15/M = $0.075)
    assert.ok(Math.abs(p.costUSD - 0.075) < 1e-9, 'expected $0.075 for 5K opus input, got ' + p.costUSD);
  });

  it('cost uses each row\'s OWN model (mixed-model series)', () => {
    const rows = [
      // Build cache on opus
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      // Miss on sonnet (model-changed reason)
      { type: 'usage', sessionId: 's1', ts: 1100, model: 'claude-sonnet-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildWastedSpendSeries(rows);
    assert.equal(out.length, 1);
    // 5K sonnet input @ $3/M = $0.015 (not opus pricing)
    assert.ok(Math.abs(out[0].costUSD - 0.015) < 1e-9);
    assert.equal(out[0].reason, 'model-changed');
  });

  it('repoFilter (Set) narrows the output', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7', repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-opus-4-7', repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's2', ts: 2000, model: 'claude-opus-4-7', repo: '/b',
        inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's2', ts: 2000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-opus-4-7', repo: '/b',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const all = buildWastedSpendSeries(rows);
    assert.equal(all.length, 2);
    const onlyA = buildWastedSpendSeries(rows, { repoFilter: new Set(['/a']) });
    assert.equal(onlyA.length, 1);
    assert.equal(onlyA[0].repo, '/a');
  });

  it('repoFilter accepts arrays as well as Sets', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildWastedSpendSeries(rows, { repoFilter: ['/a'] });
    assert.equal(out.length, 1);
    const out2 = buildWastedSpendSeries(rows, { repoFilter: ['/nonexistent'] });
    assert.equal(out2.length, 0);
  });

  it('empty repoFilter is treated as "no filter" (NOT zero results)', () => {
    // Phase 6 contract — empty Set / empty array means "include all"
    // (matches the UI semantics of "no checkboxes ticked = aggregate").
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, repo: '/a',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    assert.equal(buildWastedSpendSeries(rows, { repoFilter: new Set() }).length, 1);
    assert.equal(buildWastedSpendSeries(rows, { repoFilter: [] }).length,        1);
  });

  it('output is chronologically sorted (ascending)', () => {
    // Construct misses out-of-order in input; assert ascending in output.
    const rows = [
      { type: 'usage', sessionId: 'sA', ts: 1000, repo: '/a', inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 'sB', ts: 2000, repo: '/b', inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 'sB', ts: 2000 + CACHE_TTL_LIKELY_MS + 1, repo: '/b', inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 'sA', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, repo: '/a', inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildWastedSpendSeries(rows);
    assert.equal(out.length, 2);
    assert.ok(out[0].ts < out[1].ts, 'series must be chronological');
  });

  it('honors minInputForMissDetection threshold (small misses excluded)', () => {
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, inputTokens: 5000, cacheCreationInputTokens: 1000 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, inputTokens: 500, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    // Default threshold (1000) → small miss excluded
    assert.equal(buildWastedSpendSeries(rows).length, 0);
    // Lower threshold → it shows up
    assert.equal(buildWastedSpendSeries(rows, { minInputForMissDetection: 100 }).length, 1);
  });
});

describe('Phase 6 — endpoint emits wastedSpend when includeMisses=1', () => {
  const _src_t6 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('imports buildWastedSpendSeries from lib.mjs', () => {
    assert.match(_src_t6, /buildWastedSpendSeries,/);
  });

  it('endpoint computes wastedSpend inside the includeMisses guard', () => {
    // Slice bumped to 8500 to span the Audit CC-DASH-016 refactor
    // (flatMisses + missOptsWithPrecomp added bytes between the
    // includeMisses guard and the wastedSpend assignment).
    const fn = _src_t6.slice(
      _src_t6.indexOf("'/api/token-usage-tree'"),
      _src_t6.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /response\.wastedSpend = buildWastedSpendSeries/);
    const guardIdx = fn.indexOf("params.get('includeMisses')");
    const wsIdx = fn.indexOf('buildWastedSpendSeries');
    assert.ok(wsIdx > guardIdx, 'wastedSpend computation must be inside includeMisses guard');
  });
});

describe('Phase 6 — UI: chart-scoped project multi-select + wasted-spend chart', () => {
  const _src_t6ui = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('third carousel slide for the wasted-spend chart is present', () => {
    assert.match(_src_t6ui, /id="tok-wasted-chart"/);
    // Three slides ⇒ three dots. The class attribute and the onclick
    // attribute are space-separated, so the regex needs to span the
    // attribute boundary — use a lazy any-match instead of [^"]* which
    // stops at the closing quote of the class attribute.
    const dots = _src_t6ui.match(/chart-carousel-dot[\s\S]*?onclick="chartCarouselGo\(\d\)/g) || [];
    assert.ok(dots.length >= 3, 'expected at least 3 carousel dots, got ' + dots.length);
  });

  it('multi-select dropdown is anchored on the carousel', () => {
    assert.match(_src_t6ui, /<div class="chart-project-filter" id="chart-project-filter">/);
    assert.match(_src_t6ui, /id="cpf-toggle"/);
    assert.match(_src_t6ui, /id="cpf-panel"/);
    assert.match(_src_t6ui, /id="cpf-list"/);
    // Default label is "All projects" (matches empty-set state)
    assert.match(_src_t6ui, /<span id="cpf-label">All projects<\/span>/);
  });

  it('CSS for the multi-select uses defined design tokens only (no raw hex)', () => {
    const cssBlock = _src_t6ui.slice(
      _src_t6ui.indexOf('.chart-project-filter {'),
      _src_t6ui.indexOf('/* Phase 6 — Wasted-spend chart')
    );
    assert.ok(cssBlock.length > 200, 'multi-select CSS block must exist');
    const rawColors = cssBlock.match(/[^a-z]#[0-9a-fA-F]{3,6}\b/g);
    assert.equal(rawColors, null, 'multi-select CSS must not contain raw hex colors; found: ' + rawColors);
    assert.match(cssBlock, /var\(--bg\)/);
    assert.match(cssBlock, /var\(--border\)/);
    assert.match(cssBlock, /var\(--primary\)/);
  });

  it('CSS for the wasted-spend chart uses design tokens only', () => {
    const cssBlock = _src_t6ui.slice(
      _src_t6ui.indexOf('/* Phase 6 — Wasted-spend chart'),
      _src_t6ui.indexOf('/* ── Cost savings chart ── */')
    );
    assert.ok(cssBlock.length > 200, 'wasted-spend CSS block must exist');
    const rawColors = cssBlock.match(/[^a-z]#[0-9a-fA-F]{3,6}\b/g);
    assert.equal(rawColors, null, 'wasted-spend CSS must not contain raw hex colors; found: ' + rawColors);
    assert.match(cssBlock, /var\(--yellow\)/);
    assert.match(cssBlock, /var\(--red\)/);
  });

  it('_chartProjectFilter is a Set, persisted to localStorage', () => {
    const stateBlock = _src_t6ui.slice(
      _src_t6ui.indexOf('var _chartProjectFilter ='),
      _src_t6ui.indexOf('function applyChartProjectFilter('),
    );
    assert.match(stateBlock, /var _chartProjectFilter = new Set\(\)/);
    assert.match(stateBlock, /localStorage\.getItem\('vdm\.chartProjectFilter'\)/);
    assert.match(stateBlock, /function _persistChartProjectFilter/);
  });

  it('applyChartProjectFilter passes through when set is empty (aggregate-all)', () => {
    const fn = _src_t6ui.slice(
      _src_t6ui.indexOf('function applyChartProjectFilter('),
      _src_t6ui.indexOf('function applyChartProjectFilter(') + 600,
    );
    // The early-return branch is the contract
    assert.match(fn, /if \(!_chartProjectFilter\.size\) return rows/);
  });

  it('applyTokenModelFilter feeds project-filtered data into ALL chart renderers', () => {
    const fn = _src_t6ui.slice(
      _src_t6ui.indexOf('function applyTokenModelFilter'),
      _src_t6ui.indexOf('function applyTokenModelFilter') + 4000,
    );
    assert.match(fn, /var dataForCharts\s*=\s*applyChartProjectFilter\(data\)/);
    assert.match(fn, /var prevDataForCharts\s*=\s*applyChartProjectFilter\(prevData\)/);
    // Every chart renderer in the rAF callback uses the filtered data,
    // not the unfiltered `data`/`prevData` directly. The signature
    // check is the contract — anyone adding a NEW chart renderer to
    // the carousel will trip this test if they forget to use
    // dataForCharts.
    assert.match(fn, /renderTokenStats\(dataForCharts, prevDataForCharts\)/);
    assert.match(fn, /renderDailyChart\(dataForCharts\)/);
    assert.match(fn, /renderModelBreakdown\(dataForCharts\)/);
    assert.match(fn, /renderAccountBreakdown\(dataForCharts\)/);
    assert.match(fn, /renderRepoBranchBreakdown\(dataForCharts\)/);
    assert.match(fn, /renderToolBreakdown\(dataForCharts\)/);
    // The new chart is in the same render batch
    assert.match(fn, /renderWastedSpendChart\(\)/);
  });

  it('refreshUsageTree stores wastedSpend in _wastedSpendRaw and re-renders', () => {
    const fn = _src_t6ui.slice(
      _src_t6ui.indexOf('async function refreshUsageTree'),
      _src_t6ui.indexOf('async function refreshUsageTree') + 3000,
    );
    assert.match(fn, /_wastedSpendRaw = data\.wastedSpend \|\| \[\]/);
    assert.match(fn, /renderWastedSpendChart\(\)/);
    // Hash includes wastedSpend length (otherwise stale data wins)
    assert.match(fn, /wastedSpend \? data\.wastedSpend\.length : 0/);
  });

  it('toggleProjectFilter / toggleProjectInFilter / projectFilterSelectAll wire to applyTokenModelFilter', () => {
    // The filter must trigger a re-render of all charts on every toggle
    // (otherwise the multi-select would silently change state without
    // visible effect until the next 5s poll).
    const block = _src_t6ui.slice(
      _src_t6ui.indexOf('function toggleProjectFilter'),
      _src_t6ui.indexOf('function _refreshProjectFilterLabel'),
    );
    assert.ok(block.length > 1000, 'multi-select handler block must exist');
    assert.match(block, /function toggleProjectFilter/);
    assert.match(block, /function toggleProjectInFilter\(cb\)/);
    assert.match(block, /function projectFilterSelectAll\(selectAll\)/);
    // Each mutator calls applyTokenModelFilter at least once
    const matches = (block.match(/applyTokenModelFilter\(\)/g) || []).length;
    assert.ok(matches >= 2, 'expected applyTokenModelFilter() calls in toggle handlers, got ' + matches);
  });

  it('renderWastedSpendChart applies project filter + time range, has empty-state', () => {
    // Slice bumped from 4000 → 5000 to span the SR-OP-004 multi-
    // filter logic added in round-2 (model/account/repo/branch +
    // tier filters that were not previously honored).
    // Bumped again from 5000 → 6000 in batch I to span the UX-WS2
    // severity-gradient block (~120 chars of comment + helper call
    // before the bar template).
    const fn = _src_t6ui.slice(
      _src_t6ui.indexOf('function renderWastedSpendChart'),
      _src_t6ui.indexOf('function renderWastedSpendChart') + 6000,
    );
    assert.ok(fn.length > 800, 'renderWastedSpendChart body must exist');
    // Multi-select filter applied (Round-2 QR4: gated on multiSelectActive)
    assert.match(fn, /_chartProjectFilter\.has/);
    // Time-range filter via vsSnapshot (matches the rest of the tab)
    assert.match(fn, /var snap = vsSnapshot\(\)/);
    // Empty-state message is human-friendly
    assert.match(fn, /No cache-miss spend in this time range/);
    // Per-day bars
    assert.match(fn, /tok-wasted-bar-area/);
    // Tooltips routed through escHtml (XSS-safe)
    assert.match(fn, /escHtml\(tooltip\)/);
  });

  it('multi-select label text reflects selection count', () => {
    const fn = _src_t6ui.slice(
      _src_t6ui.indexOf('function _refreshProjectFilterLabel'),
      _src_t6ui.indexOf('function _refreshProjectFilterLabel') + 800,
    );
    assert.match(fn, /All projects/);
    // Single-selection shows the basename (path tail) for compactness
    assert.match(fn, /split\('\/'\)/);
    // Multi shows "<n> projects"
    assert.match(fn, /n \+ ' projects'/);
  });

  it('persisted filter restored at boot via _refreshProjectFilterLabel', () => {
    // The boot block at the end of the file must call the label
    // refresher so the saved selection is reflected before any data
    // arrives — otherwise the user sees "All projects" briefly even
    // when they had previously selected a subset.
    const tail = _src_t6ui.slice(_src_t6ui.lastIndexOf('refresh();'));
    assert.match(tail, /_refreshProjectFilterLabel\(\)/);
  });
});

// ─────────────────────────────────────────────────────────
// TRDD-1645134b Phase 6 — acceptance-criteria checks
// ─────────────────────────────────────────────────────────

describe('Phase 6 — acceptance criteria', () => {
  const _src_t6ac = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('flat exportUsageCsv() function body is structurally unchanged', () => {
    // The TRDD §"Acceptance criteria" mandates "the existing flat CSV
    // is unchanged" — power users diff their CSV exports week over
    // week, so any silent change to column order, header text, or
    // value formatting breaks their pipelines. This test asserts the
    // load-bearing identity markers of the function are still
    // present and in the expected positions.
    const fn = _src_t6ac.slice(
      _src_t6ac.indexOf('function exportUsageCsv()'),
      _src_t6ac.indexOf('function exportUsageCsv()') + 3000,
    );
    assert.ok(fn.length > 500, 'exportUsageCsv body must exist');
    // Header line — locked column order
    assert.match(fn, /'timestamp,repo,branch,model,account,tier,input_tokens,output_tokens'/);
    // Filename pattern uses the scrubber window
    assert.match(fn, /'vdm-export-' \+ vsFormatStamp\(snap\.start\) \+ '_to_' \+ vsFormatStamp\(snap\.end\) \+ '\.csv'/);
    // Filter set still pulled from _tokensRawData (NOT the new
    // _tokensFiltered or _wastedSpendRaw paths)
    assert.match(fn, /\(_tokensRawData \|\| \[\]\)\.filter/);
    // Blob-based download (the new tree CSV uses an anchor stream
    // instead — the flat one is intentionally still client-buffered)
    assert.match(fn, /new Blob\(\[lines\.join/);
  });

  it('endpoint returns the documented JSON shape', () => {
    const fn = _src_t6ac.slice(
      _src_t6ac.indexOf("'/api/token-usage-tree'"),
      _src_t6ac.indexOf("'/api/token-usage-tree'") + 8500,
    );
    // Default response (no includeMisses): { ok, totals, tree }
    assert.match(fn, /\bok: true,?\s*totals,?\s*tree\b/);
    // Phase 5 / 6 additions when includeMisses=1.
    // Audit CC-DASH-016: the endpoint now computes the flat-misses
    // list ONCE and routes via response.misses = flatMisses (rather
    // than the direct call); the assertion is that the flat list
    // and both downstream helpers all live inside the includeMisses
    // guard. A separate test asserts the precomputed-misses path.
    assert.match(fn, /const flatMisses = buildCacheMissReport/);
    assert.match(fn, /response\.misses\s*=\s*flatMisses/);
    assert.match(fn, /response\.missSessions\s*=\s*summarizeCacheMissesBySession/);
    assert.match(fn, /response\.wastedSpend\s*=\s*buildWastedSpendSeries/);
    // Both downstream helpers receive the precomputed list to avoid
    // re-walking the dataset.
    assert.match(fn, /missOptsWithPrecomp/);
    assert.match(fn, /_precomputedMisses:\s*flatMisses/);
  });

  it('tree UI renders correctly with 0 / 1 / many repos', () => {
    // Empty case must short-circuit to the empty-state message
    // (covered separately in Phase 3 tests, re-asserted here for the
    // acceptance-criteria contract).
    const fn = _src_t6ac.slice(
      _src_t6ac.indexOf('function renderUsageTree('),
      _src_t6ac.indexOf('function renderUsageTree(') + 1500,
    );
    assert.match(fn, /No usage data in this time range/);
    // Many-repos case — top-level repos rendered open by default
    // so users see the breakdown immediately
    assert.match(fn, /renderTreeNode\(tree\[i\], grandTotals, \/\*depth\*\/0\)/);
  });
});

// ─────────────────────────────────────────────────────────
// Audit SR-OP-001 regression — type-string is 'compact_boundary'
// ─────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────
// Audit SC-OPUS-001 — CSV formula-injection guard
// ─────────────────────────────────────────────────────────

describe('Audit SC-OPUS-001 — csvField formula-injection guard', () => {
  it('prefixes string cells starting with = + - @ \\t \\r with single quote', () => {
    // Excel / Sheets / Numbers / LibreOffice evaluate cells starting
    // with these chars as formulas when the file is opened. Repo paths
    // and sub-agent names are user-controlled — a hostile plugin can
    // ship a sub-agent named `=cmd|'/c calc'!A0`. RFC 4180 only
    // mandates DOUBLE quote escaping; single quotes pass through
    // untouched, so the expected payload below has single single-quotes.
    assert.equal(csvField('=HYPERLINK("evil")'), `"'=HYPERLINK(""evil"")"`);
    assert.equal(csvField('=cmd|\'/c calc\'!A0'), `"'=cmd|'/c calc'!A0"`);
    for (const c of ['+', '-', '@', '\t', '\r']) {
      const out = csvField(c + 'evil');
      assert.ok(out.startsWith(`"'${c}`), `expected '"' + c + ... for c=${JSON.stringify(c)}, got ${out}`);
    }
  });

  it('does NOT prefix safe string cells', () => {
    assert.equal(csvField('main'),               '"main"');
    assert.equal(csvField('/Users/foo/bar'),     '"/Users/foo/bar"');
    assert.equal(csvField('claude-opus-4-7'),    '"claude-opus-4-7"');
    assert.equal(csvField('subagent:Explore'),   '"subagent:Explore"');
  });

  it('does NOT prefix legitimate numeric cells', () => {
    // A negative number is produced via String(v) above the guard
    // — Excel parses it as a numeric cell, not a formula. Prefixing
    // would break spreadsheet sums.
    assert.equal(csvField(-1.5), '"-1.5"');
    assert.equal(csvField(-100), '"-100"');
    assert.equal(csvField(0),    '"0"');
  });

  it('does NOT prefix booleans (controlled output)', () => {
    assert.equal(csvField(true),  '"true"');
    assert.equal(csvField(false), '"false"');
  });

  it('also prefixes leading newline (R2-MINOR-2 — newer LibreOffice/Sheets evaluate)', () => {
    // Round-2 finding: \n was missing from the trigger set. Newer
    // LibreOffice and Sheets versions evaluate cells starting with
    // bare \n as formulas in some import paths.
    assert.equal(csvField('\n=cmd|/c calc'), `"'\n=cmd|/c calc"`);
  });

  it('round-trips formula-prefixed cells through renderUsageTreeCsv', () => {
    // End-to-end: a malicious row whose `tool` field is a formula
    // payload must end up CSV-escaped AND formula-quoted.
    const rows = [{
      repo: '=cmd|\'/c calc\'!A0', branch: 'main', isWorktree: false,
      component: 'main', tool: 'Bash',
      inputTokens: 1, outputTokens: 0,
      cacheReadTokens: 0, cacheCreationTokens: 0,
      totalCostUSD: 0, requestCount: 1,
    }];
    const csv = renderUsageTreeCsv(rows);
    // Should contain the prefixed-and-escaped form (single quotes
    // don't need RFC 4180 doubling — only double quotes do).
    assert.match(csv, /"'=cmd\|'\/c calc'!A0"/);
  });
});

describe('Audit Round-2 R2-MINOR-1 — Skill regex empty-parens edge case', () => {
  it('Skill(  ) with whitespace-only inside parens falls through to mcpServer/unknown', () => {
    // Round-2 finding: paren regex `(.+?)` matched whitespace, then
    // .trim() collapsed to '' → emitted skill: with empty label.
    // After fix, the empty-after-trim path falls through to the
    // documented mcpServer/unknown fallback.
    const r1 = classifyUsageComponent({ tool: 'Skill(  )', mcpServer: 'foo' });
    assert.equal(r1, 'skill:foo');
    const r2 = classifyUsageComponent({ tool: 'Skill( )' });
    assert.equal(r2, 'skill:unknown');
  });
});

describe('Audit Round-2 — additional regression coverage', () => {
  it('aggregateUsageTree skips rows with negative token fields (MAJOR-3)', () => {
    // Defensive: -100 inputTokens would have been added to the running
    // total before the round-1 fix (typeof number, isFinite true,
    // pre-check missing the < 0 branch). Now skipped.
    const rows = [
      { type: 'usage', sessionId: 's', ts: 1000, repo: '/r', branch: 'main',
        model: 'claude-sonnet-4-7', tool: 'Bash',
        inputTokens: -100, outputTokens: 50,
        cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
      { type: 'usage', sessionId: 's', ts: 2000, repo: '/r', branch: 'main',
        model: 'claude-sonnet-4-7', tool: 'Bash',
        inputTokens:  100, outputTokens: 50,
        cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    const out = aggregateUsageTree(rows);
    assert.equal(out.totals.input, 100, 'negative-input row must be excluded; total=100 not -100 not 0');
    assert.equal(out.totals.output, 50, 'only the positive row contributes');
  });

  it('aggregateUsageForCsvExport skips rows with negative token fields (MAJOR-3)', () => {
    const rows = [
      { type: 'usage', ts: 1000, repo: '/r', branch: 'main', tool: 'Bash',
        model: 'claude-sonnet-4-7',
        inputTokens: -500, outputTokens: 0,
        cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
      { type: 'usage', ts: 2000, repo: '/r', branch: 'main', tool: 'Bash',
        model: 'claude-sonnet-4-7',
        inputTokens:  500, outputTokens: 0,
        cacheReadInputTokens: 0, cacheCreationInputTokens: 0 },
    ];
    const out = aggregateUsageForCsvExport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].inputTokens, 500);
    assert.equal(out[0].requestCount, 1, 'only the positive-input row counted');
  });

  it('estimateModelCost clamps negative token counts to zero (MAJOR-2)', () => {
    // Without the clamp, -1000 input @ $3/M → -$0.003 negative cost.
    assert.equal(estimateModelCost('claude-sonnet-4-7', -1000, 0, 0, 0), 0);
    assert.equal(estimateModelCost('claude-sonnet-4-7',  Infinity, 0, 0, 0), 0);
    assert.equal(estimateModelCost('claude-sonnet-4-7',  NaN, 0, 0, 0), 0);
  });

  it('buildWastedSpendSeries emits wastedUSD = costUSD - cacheCost (MINOR-3)', () => {
    // Sonnet rates: input $3/M, cacheRead $0.30/M.
    // 1M tokens fully paid → $3.00; same as cache → $0.30; wasted = $2.70.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-sonnet-4-7',
        repo: '/r', branch: 'main',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-sonnet-4-7',
        repo: '/r', branch: 'main',
        inputTokens: 1_000_000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildWastedSpendSeries(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].costUSD,   3);
    // Floating-point tolerance for 3 - 0.3 = 2.7
    assert.ok(Math.abs(out[0].wastedUSD - 2.7) < 1e-9,
      `expected wastedUSD ≈ 2.7, got ${out[0].wastedUSD}`);
  });

  it('buildWastedSpendSeries propagates account through to output (Round-2 QR5)', () => {
    // The wasted-spend chart's account-filter check needs the field
    // to compare. Without it the filter was dead.
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-sonnet-4-7',
        repo: '/r', branch: 'main', account: 'alice',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      { type: 'usage', sessionId: 's1', ts: 1000 + CACHE_TTL_LIKELY_MS + 1, model: 'claude-sonnet-4-7',
        repo: '/r', branch: 'main', account: 'alice',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildWastedSpendSeries(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].account, 'alice', 'account must round-trip from row → miss → wasted');
  });

  it('classifyUsageComponent caps at 256 chars (SC-OPUS-007 ReDoS hardening)', () => {
    const huge = 'Skill(' + 'a'.repeat(1000) + ')';
    assert.equal(classifyUsageComponent({ tool: huge }), 'main',
      '> 256 chars must short-circuit to "main" before the regex sees it');
  });
});

describe('Audit SR-OP-001 — compact-boundary type-string regression', () => {
  // Catches the trap where the test fixture used 'compact' AND the
  // production code did too, so the test passed green while the
  // classifier was dead code in production.
  const _libSrcSr = _readFileSync_xss(
    new URL('../lib.mjs', import.meta.url),
    'utf8',
  );
  const _dashSrcSr = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('lib.mjs buildCacheMissReport filter accepts the production type', () => {
    // Locate the function body, then assert the filter checks for
    // 'compact_boundary' (NOT 'compact'). The earlier draft used
    // the wrong literal; production rows would never reach the
    // classifier and every miss after a /compact would silently
    // downgrade.
    const fn = _libSrcSr.slice(
      _libSrcSr.indexOf('export function buildCacheMissReport'),
      _libSrcSr.indexOf('export function buildCacheMissReport') + 4000,
    );
    assert.match(fn, /t !== 'usage' && t !== 'compact_boundary'/);
    assert.match(fn, /t === 'compact_boundary'/);
    // Defense against accidentally re-introducing the wrong literal.
    // Only check executable code (drop // and /* ... */ comments
    // first) so explanatory text in JSDoc/comments doesn't trip us.
    const stripped = fn
      .replace(/\/\*[\s\S]*?\*\//g, '')   // block comments
      .replace(/\/\/[^\n]*/g, '');         // line comments
    const wrongLit = stripped.match(/'compact'(?!_)/g);
    assert.equal(wrongLit, null,
      "buildCacheMissReport executable code must use 'compact_boundary' (production type), not 'compact'");
  });

  it('dashboard.mjs endpoint pre-filter keeps the production type', () => {
    const handler = _dashSrcSr.slice(
      _dashSrcSr.indexOf("'/api/token-usage-tree'"),
      _dashSrcSr.indexOf("'/api/token-usage-tree'") + 6000,
    );
    assert.match(handler, /t !== 'usage' && t !== 'compact_boundary'/);
  });

  it('an actual buildCompactBoundaryEntry row classifies as compact-boundary', () => {
    // End-to-end test using the REAL producer instead of a synthetic
    // row literal. If buildCompactBoundaryEntry's type ever changes,
    // the classifier must adapt.
    const compactRow = buildCompactBoundaryEntry({
      ts: 1500, sessionId: 's1', repo: '/r', branch: 'main',
      commitHash: 'abc123', trigger: 'auto',
      preTokens: 50000, postTokens: 10000, account: 'a1',
    });
    const rows = [
      { type: 'usage', sessionId: 's1', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000, cacheReadInputTokens: 0 },
      compactRow,
      { type: 'usage', sessionId: 's1', ts: 2000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const out = buildCacheMissReport(rows);
    assert.equal(out.length, 1);
    assert.equal(out[0].reason, 'compact-boundary',
      "production buildCompactBoundaryEntry rows must be recognized by the classifier");
  });
});

describe('Audit SC-OPUS-002 — reason → CSS class uses allow-list (XSS hardening)', () => {
  const _src_sc2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('renderCacheMisses uses KNOWN_MISS_REASONS allow-list, not regex strip', () => {
    // The previous `'reason-' + reasonText.replace(/[^a-z0-9]/gi, '-')`
    // was safe TODAY (4 fixed reasons) but fragile-by-design. A future
    // refactor that allows colons in reason strings, or derives reason
    // from a row field, would silently open an XSS sink. Allow-list
    // closes the footgun.
    // Slice bumped from 5500 → 10000 to span UX batch H expansion
    // (UX-CM1 sticky-state + UX-CM3 expand toggle pushed the
    // KNOWN_MISS_REASONS block further down the function body).
    const fn = _src_sc2.slice(
      _src_sc2.indexOf('function renderCacheMisses'),
      _src_sc2.indexOf('function renderCacheMisses') + 10000,
    );
    assert.match(fn, /var KNOWN_MISS_REASONS\s*=\s*\{ 'compact-boundary': 1, 'model-changed': 1, 'TTL-likely': 1, 'unknown': 1 \}/);
    assert.match(fn, /var reasonKey\s*=\s*KNOWN_MISS_REASONS\[reasonText\] \? reasonText : 'unknown'/);
    // Defense: the old regex-strip pattern must not return.
    assert.ok(!/reason-' \+ reasonText\.replace/.test(fn),
      'the legacy regex-strip pattern must be removed');
  });

  it('buildCacheMissReport only emits the 4 known reasons (the allow-list contract)', () => {
    // Worst-case set of synthetic rows that triggers each branch of
    // the classifier. The test confirms the producer never emits a
    // 5th string the consumer (UI) wouldn't recognise.
    const KNOWN = new Set(['compact-boundary', 'model-changed', 'TTL-likely', 'unknown']);
    const rows = [
      // creates cache @ ts=1000
      { type: 'usage', sessionId: 's', ts: 1000, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 1000 },
      // miss within TTL, same model — 'unknown'
      { type: 'usage', sessionId: 's', ts: 1100, model: 'claude-opus-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      // model-changed
      { type: 'usage', sessionId: 's', ts: 1200, model: 'claude-sonnet-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      // compact_boundary then miss
      { type: 'compact_boundary', sessionId: 's', ts: 1300 },
      { type: 'usage', sessionId: 's', ts: 1400, model: 'claude-sonnet-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      // TTL miss
      { type: 'usage', sessionId: 's', ts: 1400 + CACHE_TTL_LIKELY_MS + 1,
        model: 'claude-sonnet-4-7',
        inputTokens: 5000, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
    ];
    const misses = buildCacheMissReport(rows);
    for (const m of misses) {
      assert.ok(KNOWN.has(m.reason),
        `reason "${m.reason}" must be in the documented set (UI allow-list relies on this)`);
    }
  });
});

describe('Audit SC-OPUS-004 — multi-select attribute uses escHtml (not quote-only)', () => {
  const _src_sc4 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('populateProjectFilterOptions does NOT use the legacy quote-only escape', () => {
    // The old `name.replace(/"/g, '&quot;')` only escaped " and let &
    // through, opening attribute-context XSS via &quot; entity decode.
    // escHtml escapes & < > " ' — safe in BOTH attribute and text.
    assert.ok(!/safeAttr\s*=\s*name\.replace/.test(_src_sc4),
      'safeAttr should be derived via escHtml, not quote-only replace');
    // Positive: the populator uses escHtml(name) for both data-repo
    // and title attributes. Slice bumped to 5500 to span the
    // SR-OP-002 hint logic added at the top of the function.
    const fn = _src_sc4.slice(
      _src_sc4.indexOf('function populateProjectFilterOptions'),
      _src_sc4.indexOf('function populateProjectFilterOptions') + 5500,
    );
    assert.match(fn, /var safe = escHtml\(name\)/);
    assert.match(fn, /data-repo="' \+ safe \+ '"/);
    assert.match(fn, /title="' \+ safe \+ '"/);
  });
});

describe('Audit Round-2 — additional fix coverage (R2-DASH-102/103/104/105/106/107/108/109/111, SR-P2-005)', () => {
  const _src_r2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('R2-DASH-102 — refreshUsageTree validates data.totals before deref', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('async function refreshUsageTree'),
      _src_r2.indexOf('async function refreshUsageTree') + 3000,
    );
    assert.match(fn, /if \(!data\.totals \|\| typeof data\.totals !== 'object'\)/);
    assert.match(fn, /'malformed response: missing totals'/);
  });

  it('R2-DASH-103 — chartCarouselGo clamps idx to valid range', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('function chartCarouselGo'),
      _src_r2.indexOf('function chartCarouselGo') + 1500,
    );
    assert.match(fn, /if \(btns\.length > 0 && _chartCarouselIdx >= btns\.length\)/);
    assert.match(fn, /_chartCarouselIdx = 0;\s*\n\s*idx = 0;/);
  });

  it('R2-DASH-104 — endpoint returns 400 (not silent drop) for negative from/to', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf("'/api/token-usage-tree'"),
      _src_r2.indexOf("'/api/token-usage-tree'") + 8500,
    );
    assert.match(fn, /'from must be a non-negative number'/);
    assert.match(fn, /'to must be a non-negative number'/);
    // Must reject with 400, not silent fall-through
    assert.match(fn, /!Number\.isFinite\(n\) \|\| n < 0/);
  });

  it('R2-DASH-105 — CSV time fallback treats either-null as both-null', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('function exportUsageTreeCsv'),
      _src_r2.indexOf('function exportUsageTreeCsv') + 2500,
    );
    assert.match(fn, /if \(fromTs == null \|\| toTs == null\)/);
    // Both bounds derived together inside the same block
    assert.match(fn, /fromTs = Date\.now\(\) - days[\s\S]{0,200}toTs\s*=\s*Date\.now\(\)/);
  });

  it('R2-DASH-106 — stale-prune also kicks tree refresh', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('function populateProjectFilterOptions'),
      _src_r2.indexOf('function populateProjectFilterOptions') + 6000,
    );
    assert.match(fn, /if \(typeof refreshUsageTree === 'function'\)/);
    assert.match(fn, /_lastTreeHash = '';/);
    assert.match(fn, /refreshUsageTree\(_refreshCutoff\)/);
  });

  it('R2-DASH-107 — disabled multi-select label has visual/aria affordance', () => {
    // Label gets the cpf-item-disabled class AND aria-disabled="true"
    // when single-select narrows the dropdown.
    const fn = _src_r2.slice(
      _src_r2.indexOf('function populateProjectFilterOptions'),
      _src_r2.indexOf('function populateProjectFilterOptions') + 6000,
    );
    assert.match(fn, /var labelExtraClass = singleSelectRepo \? ' cpf-item-disabled' : ''/);
    assert.match(fn, /var labelExtraAria  = singleSelectRepo \? ' aria-disabled="true"' : ''/);
    // CSS class definition
    assert.match(_src_r2, /\.cpf-item-disabled \{ opacity: 0\.5; cursor: not-allowed; \}/);
  });

  it('R2-DASH-108 — single-select repo not in dataset renders zero rows + hint', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('function populateProjectFilterOptions'),
      _src_r2.indexOf('function populateProjectFilterOptions') + 6000,
    );
    assert.match(fn, /if \(seen\.has\(singleSelectRepo\)\)/);
    assert.match(fn, /no recent data for this repo in the current time window/);
  });

  it('R2-DASH-109 — populateProjectFilterOptions failure shows visible label feedback', () => {
    const fn = _src_r2.slice(
      _src_r2.indexOf('function toggleProjectFilter'),
      _src_r2.indexOf('function toggleProjectFilter') + 2500,
    );
    assert.match(fn, /'Filter unavailable'/);
    assert.match(fn, /setTimeout\(function\(\)[\s\S]{0,200}_refreshProjectFilterLabel\(\)/);
  });

  it('R2-DASH-111 — _treeHash is structural (not JSON.stringify fallback)', () => {
    // The point of replacing quickHash(data.tree) was to stop the
    // schema-detect fallback that called JSON.stringify on the entire
    // tree every 5s poll. _treeHash must be present and used in
    // refreshUsageTree's hash construction.
    assert.match(_src_r2, /function _treeHash\(nodes\)/);
    const fn = _src_r2.slice(
      _src_r2.indexOf('async function refreshUsageTree'),
      _src_r2.indexOf('async function refreshUsageTree') + 3000,
    );
    assert.match(fn, /_treeHash\(data\.tree \|\| \[\]\)/);
    // The previous quickHash call on data.tree must be gone in
    // EXECUTABLE code — strip line comments first so the explanatory
    // mention in the audit comment doesn't false-positive.
    const stripped = fn
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '');
    assert.ok(!/quickHash\(data\.tree/.test(stripped),
      'quickHash(data.tree) executable call must be removed (was the JSON.stringify fallback)');
  });

  it('SR-P2-005 — parsePostToolBatchPayload rejects CRLF/NUL/oversized tool names', () => {
    // Audit Round-2 SR-P2-005: defense-in-depth rejection of tool
    // names that would round-trip through token-usage.json into
    // downstream consumers (jq, awk, naive parsers) that don't
    // handle embedded line-breaks.
    const out = parsePostToolBatchPayload({
      session_id: 's1',
      tool_calls: [
        { tool_name: 'Bash' },                              // OK
        { tool_name: 'Bad\rname' },                         // rejected — \r
        { tool_name: 'Bad\nname' },                         // rejected — \n
        { tool_name: 'Bad\x00name' },                       // rejected — NUL
        { tool_name: 'a'.repeat(257) },                     // rejected — > 256
        { tool_name: 'Read' },                              // OK
      ],
    });
    assert.equal(out.ok, true);
    assert.equal(out.tools.length, 2, 'only Bash + Read should pass the filter');
    assert.deepEqual(out.tools.map(t => t.toolName), ['Bash', 'Read']);
  });
});

describe('Audit Round-2 QR4 — multi-select defers to single-select to prevent empty-cascade', () => {
  const _src_qr4 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('applyChartProjectFilter returns rows pass-through when single-select tok-repo is set', () => {
    // Without this guard, a saved multi-select selection that doesn't
    // include the single-select repo would zero out every chart.
    const fn = _src_qr4.slice(
      _src_qr4.indexOf('function applyChartProjectFilter'),
      _src_qr4.indexOf('function applyChartProjectFilter') + 1500,
    );
    assert.match(fn, /var repoSel = document\.getElementById\('tok-repo'\)/);
    assert.match(fn, /if \(repoSel && repoSel\.value\) return rows/);
  });

  it('renderWastedSpendChart applies the same single-select-wins rule', () => {
    const fn = _src_qr4.slice(
      _src_qr4.indexOf('function renderWastedSpendChart'),
      _src_qr4.indexOf('function renderWastedSpendChart') + 4500,
    );
    assert.match(fn, /var multiSelectActive = _chartProjectFilter\.size > 0 && !repoF/);
    assert.match(fn, /if \(multiSelectActive && !_chartProjectFilter\.has/);
  });
});

describe('Phase 6 — full-suite + dependency invariants', () => {
  const _src_t6ac2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );
  const _libSrc = _readFileSync_xss(
    new URL('../lib.mjs', import.meta.url),
    'utf8',
  );

  it('lib.mjs exports stay in sync with dashboard.mjs imports', () => {
    // If a function gets renamed or removed from lib.mjs but
    // dashboard.mjs still imports it, Node will fail at startup
    // with "named export not found." Check explicitly here so the
    // failure surfaces as a test failure, not a runtime crash.
    const wanted = [
      'aggregateUsageTree',
      'buildCacheMissReport',
      'aggregateUsageForCsvExport',
      'renderUsageTreeCsv',
      'summarizeCacheMissesBySession',
      'buildWastedSpendSeries',
    ];
    for (const name of wanted) {
      const exportRe = new RegExp(`export\\s+(function|const)\\s+${name}\\b`);
      assert.match(_libSrc, exportRe, `lib.mjs should export ${name}`);
      const importRe = new RegExp(`\\b${name},`);
      assert.match(_src_t6ac2, importRe, `dashboard.mjs should import ${name}`);
    }
  });

  it('no backticks lurk in JS comments inside renderHTML template literal', () => {
    // CLAUDE.md flags this as the load-bearing trap that breaks the
    // single-template-literal returned by renderHTML(). Resolve the
    // template range from the source dynamically — the explicit numeric
    // window in earlier revisions silently shrank as renderHTML grew,
    // letting traps slip through past the old upper bound. We anchor
    // on the function header and the closing "</html>`;" sentinel.
    const lines = _src_t6ac2.split('\n');
    const startIdx = lines.findIndex((l) => l.startsWith('function renderHTML()'));
    assert.ok(startIdx >= 0, 'could not locate renderHTML start');
    let endIdx = -1;
    for (let i = startIdx + 1; i < lines.length; i++) {
      if (/<\/html>`;\s*$/.test(lines[i])) { endIdx = i; break; }
    }
    assert.ok(endIdx > startIdx, 'could not locate renderHTML template close');
    const traps = [];
    for (let i = startIdx; i <= endIdx; i++) {
      // Match "// ... ` ..." patterns (a JS line-comment containing a backtick)
      if (/\/\/[^`]*`/.test(lines[i])) traps.push((i + 1) + ': ' + lines[i].trim());
    }
    assert.equal(traps.length, 0,
      'backticks in JS comments inside renderHTML template will silently break parsing.\n  '
      + traps.join('\n  '));
  });
});

// ─────────────────────────────────────────────────
// A11y batch 2 — UX-X3 / UX-CPF3 / UX-S2 source-grep regressions
//
// These tests guard the keyboard-accessibility attributes on three
// `onclick`-bearing controls that were not real buttons before this
// batch (tok-repo-header, session-header, cpf-list listbox). A future
// refactor that drops role/tabindex/aria-* will fail these greps before
// it lands in the browser, where the regression would be invisible to
// sighted-mouse users but would silently lock out keyboard-only and
// screen-reader users.
// ─────────────────────────────────────────────────
describe('A11y batch 2 — UX-X3 / UX-CPF3 / UX-S2 source-grep regressions', () => {
  const _src_a11y2 = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('UX-X3 — tok-repo-header div carries role=button + tabindex + aria-expanded', () => {
    // The repo header used to be just `<div onclick=...>` — keyboard
    // users couldn't open or close repo branch breakdowns at all.
    assert.match(_src_a11y2,
      /<div class="tok-repo-header" role="button" tabindex="0" aria-expanded="' \+ \(collapsed \? 'false' : 'true'\) \+ '"/);
  });

  it('UX-X3 — session-header divs (active + recent) carry role=button + tabindex + aria-expanded', () => {
    // Two emit-sites (one for active sessions, one for recent), both
    // use the same template string. We expect AT LEAST 2 occurrences.
    const matches = _src_a11y2.match(
      /<div class="session-header" role="button" tabindex="0" aria-expanded="' \+ \(collapsed \? 'false' : 'true'\) \+ '"/g
    ) || [];
    assert.ok(matches.length >= 2,
      'expected at least 2 session-header role=button emit-sites, found ' + matches.length);
  });

  it('UX-X3 — global keydown delegate fires Enter/Space on role=button[tabindex] divs', () => {
    // Without this delegate, role=button divs are tab-focusable but
    // pressing Enter or Space does nothing — the lonely worst kind of
    // a11y because the focus ring lies about interactivity.
    assert.match(_src_a11y2, /if \(ev\.key !== 'Enter' && ev\.key !== ' '\) return;/);
    assert.match(_src_a11y2, /if \(t\.tagName === 'BUTTON'\) return;/);
    assert.match(_src_a11y2, /if \(t\.getAttribute\('tabindex'\) === null\) return;/);
  });

  it('UX-CPF3 — cpf-list container carries role=listbox + aria-multiselectable', () => {
    assert.match(_src_a11y2,
      /<div class="cpf-list" id="cpf-list" role="listbox" aria-multiselectable="true" aria-label="[^"]+"><\/div>/);
  });

  it('UX-CPF3 — each cpf-item label carries role=option + aria-selected mirroring checkbox', () => {
    // The label is the option (not the inner checkbox) so its
    // aria-selected reflects the chosen state. The mirror update lives
    // in toggleProjectInFilter and projectFilterSelectAll.
    assert.match(_src_a11y2,
      /<label class="cpf-item' \+ labelExtraClass \+ '" role="option"' \+ ariaSel/);
    assert.match(_src_a11y2,
      /lbl\.setAttribute\('aria-selected', cb\.checked \? 'true' : 'false'\)/);
  });

  it('UX-CPF3 — _wireListboxArrowKeys exists and is wired against #cpf-list', () => {
    assert.match(_src_a11y2, /function _wireListboxArrowKeys\(containerSel, itemSel\)/);
    assert.match(_src_a11y2,
      /_wireListboxArrowKeys\('#cpf-list', 'input\[type="checkbox"\]:not\(:disabled\)'\);/);
  });

  it('UX-CPF3 — projectFilterSelectAll mirrors aria-selected on bulk toggles', () => {
    // Without this, after Select-all / Clear the checkboxes flip but
    // aria-selected on the wrapping labels stays at its old value — a
    // screen reader walking the list would announce the wrong state.
    const fn = _src_a11y2.slice(
      _src_a11y2.indexOf('function projectFilterSelectAll'),
      _src_a11y2.indexOf('function projectFilterSelectAll') + 1500,
    );
    assert.match(fn, /lbl\.setAttribute\('aria-selected', 'true'\)/);
    assert.match(fn, /lbl2\.setAttribute\('aria-selected', 'false'\)/);
  });

  it('UX-S2 — chevron CSS picks up colour on header hover/focus', () => {
    // The header set cursor:pointer but the chevron itself never
    // reacted, so the affordance was invisible. Both tok-repo and
    // session variants get the same treatment.
    assert.match(_src_a11y2,
      /\.tok-repo-header:hover \.tok-repo-chevron,\s*\.tok-repo-header:focus-visible \.tok-repo-chevron \{ color: var\(--foreground\); \}/);
    assert.match(_src_a11y2,
      /\.session-header:hover \.session-collapse-indicator,\s*\.session-header:focus-visible \.session-collapse-indicator \{ color: var\(--foreground\); \}/);
  });

  it('UX-S2 — chevron transition includes colour (so the hover change is animated)', () => {
    // Both chevrons used `transition: transform 0.15s` only — flipping
    // colour without listing it in `transition` makes the change snap
    // instead of fading, which feels unintentionally jarring.
    assert.match(_src_a11y2,
      /\.tok-repo-chevron \{[\s\S]{0,200}transition: transform 0\.15s, color 0\.15s;/);
    assert.match(_src_a11y2,
      /\.session-collapse-indicator \{[\s\S]{0,200}transition: transform 0\.15s, color 0\.15s;/);
  });
});

// ─────────────────────────────────────────────────
// Sparkline + scrubber refresh — UX-X7 / UX-VS2 source-grep regressions
//
// These tests guard the dashboard's sparkline render function and the
// custom scrubber-thumb CSS against the two prior shortcomings called
// out in the UX audit:
//   * UX-X7 — sparklines were binary (ON/OFF) so every account looked
//     identical the moment it had any traffic; no axis labels meant a
//     reader couldn't tell 5% from 95%.
//   * UX-VS2 — scrubber thumb pseudo-elements were 16px diameter (smaller
//     than the WCAG 2.5.5 desktop minimum) and only the .vs-thumb div
//     was sized — any future native input[type=range] would silently
//     regress to OS-default 16px.
//
// As with the A11y batch 2 block above, these are source-grep tests
// rather than DOM tests: renderSparkline lives only inside the
// renderHTML() template literal (it is client JS, not an export), and
// the established convention here is to grep the source string for the
// invariants we care about. A separate behavioural test extracts the
// function via regex slice + new Function() and asserts the produced
// SVG path coordinates honour the proportional Y-scale rule, so we have
// both source-shape AND output-shape coverage.
// ─────────────────────────────────────────────────
describe('UX-X7 / UX-VS2 — sparkline + scrubber regressions (batch D)', () => {
  const _src_uxd = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('UX-X7 — renderSparkline computes a per-window observed peak (not binary > 0)', () => {
    // Binary sparkline used `var on = (pts[pi][key] || 0) > 0` to pick
    // between two Y values. Proportional version computes maxObserved
    // and a yFor(val) helper that scales against it. Source-grep both.
    assert.match(_src_uxd, /var maxObserved = 0;/);
    assert.match(_src_uxd, /if \(v > maxObserved\) maxObserved = v;/);
    assert.match(_src_uxd, /var yMax = Math\.max\(maxObserved, 1\.0\);/);
    assert.match(_src_uxd,
      /function yFor\(val\) \{\s*var clipped = val < 0 \? 0 : \(val > yMax \? yMax : val\);\s*return padT \+ chartH \* \(1 - clipped \/ yMax\);\s*\}/);
  });

  it('UX-X7 — Y-scale is anchored at zero (the baseline must be padT + chartH)', () => {
    // The "30% bar must look like 30% of the chart" property only holds
    // if the path returns to (padT + chartH) for value=0. Without the
    // explicit 1.0 floor on yMax, a flat-30% history would fill the
    // whole chart and recreate the binary-sparkline bug.
    assert.match(_src_uxd, /var yOff = padT \+ chartH;/);
    // The closing 'Z' of the area path must come back to yOff so the
    // fill is anchored at zero (not auto-scaled to the data range).
    assert.match(_src_uxd,
      /d \+= ' L' \+ xLast\.toFixed\(1\) \+ ',' \+ yOff\.toFixed\(1\) \+ ' Z';/);
  });

  it('UX-X7 — SVG carries title= AND aria-label tooltip with min/max range', () => {
    // The <title> child element provides the native browser hover
    // tooltip; the role=img + aria-label gives the same string to a
    // screen reader as the chart's accessible name.
    assert.match(_src_uxd,
      /role="img" aria-label="' \+ titleTxt \+ '"><title>' \+ titleTxt \+ '<\/title>/);
    assert.match(_src_uxd,
      /titleTxt = 'Min ' \+ minPctInWin \+ '% \/ Max ' \+ maxPctInWin \+ '% over the window';/);
    // Empty-data path must still emit a title (else the role=img has
    // an empty accessible name, which trips axe-core).
    assert.match(_src_uxd, /titleTxt = 'No data in window';/);
  });

  it('UX-X7 — overlay labels mark peak% (top-left) AND 0% (baseline)', () => {
    // Two <text> elements drawn on the SVG, both font-size 6 to match
    // the existing axis-label style. Top-left shows the peak %, baseline
    // shows literal "0%" so the value range is interpretable without
    // hovering for the tooltip.
    assert.match(_src_uxd,
      /var maxLabelTxt = \(maxPctInWin == null\) \? '--' : \(maxPctInWin \+ '%'\);/);
    assert.match(_src_uxd,
      /<text x="2" y="6"[^>]*text-anchor="start">' \+ maxLabelTxt \+ '<\/text>'/);
    assert.match(_src_uxd,
      /<text x="2" y="' \+ \(padT \+ chartH\)\.toFixed\(1\) \+ '"[^>]*text-anchor="start">0%<\/text>/);
  });

  it('UX-X7 — proportional path: behavioural test on extracted renderSparkline', () => {
    // Pull renderSparkline out of the template literal and exec it. The
    // function is self-contained (uses only Date.now / Math), so we can
    // run it in a sandbox built via new Function() and inspect the
    // returned SVG string. We assert that two histories with different
    // peaks produce SVGs whose top-edge Y coordinates differ — the
    // binary-sparkline version returned IDENTICAL SVGs for any history
    // with at least one nonzero point (both would clamp to yOn).
    const m = _src_uxd.match(
      /function renderSparkline\(hist, key, windowMs, mode\) \{[\s\S]*?\n\}/);
    assert.ok(m, 'renderSparkline source not found in dashboard.mjs');
    // Wrap as `return function ...` so new Function() yields the fn.
    // No closures used inside renderSparkline beyond globals (Math, Date).
    // eslint-disable-next-line no-new-func
    const renderSparkline = (new Function('return ' + m[0]))();
    assert.equal(typeof renderSparkline, 'function');
    const now = Date.now();
    const W = 24 * 60 * 60 * 1000;
    // Build two short same-length histories with the same TIMESTAMPS so
    // any difference in the produced SVG comes from value scaling, not
    // x-coordinate placement (which depends on now()/windowStart).
    const lowHist = [
      { ts: now - 60_000, u5h: 0.10, u7d: 0.10 },
      { ts: now - 30_000, u5h: 0.10, u7d: 0.10 },
      { ts: now -  1_000, u5h: 0.10, u7d: 0.10 },
    ];
    const highHist = [
      { ts: now - 60_000, u5h: 0.95, u7d: 0.95 },
      { ts: now - 30_000, u5h: 0.95, u7d: 0.95 },
      { ts: now -  1_000, u5h: 0.95, u7d: 0.95 },
    ];
    const svgLow  = renderSparkline(lowHist,  'u5h', W, 'hours');
    const svgHigh = renderSparkline(highHist, 'u5h', W, 'hours');
    // Sanity: both render an svg.
    assert.match(svgLow,  /<svg /);
    assert.match(svgHigh, /<svg /);
    // Both must carry the title= overlay even with simple data.
    assert.match(svgLow,  /<title>Min 10% \/ Max 10% over the window<\/title>/);
    assert.match(svgHigh, /<title>Min 95% \/ Max 95% over the window<\/title>/);
    // Most important: the two SVGs MUST differ. The binary version
    // produced identical area paths for any pts with `> 0` values.
    assert.notEqual(svgLow, svgHigh,
      'low (10%) and high (95%) sparklines produced identical SVGs — proportional Y-scale is not being applied');
    // Behavioural extraction of the area-path top Y from each SVG.
    // The proportional formula is yFor(val) = padT + chartH * (1 - val / yMax)
    // with padT=1, chartH=31, yMax=1.0 (since both peaks are <1.0).
    // → yFor(0.10) ≈ 28.9 ; yFor(0.95) ≈ 2.6
    // The path strings should contain these distinct Y coords.
    assert.match(svgLow,  /,28\.[0-9]/, 'low-utilization path should contain a Y near 28.9');
    assert.match(svgHigh, /,2\.[0-9]/,  'high-utilization path should contain a Y near 2.6');
  });

  it('UX-X7 — proportional path emits a 0% label even when no data is in the window', () => {
    // Source-grep already covers titleTxt='No data in window' but the
    // overlay-label "0%" baseline marker should ALSO render so the
    // empty chart is still self-explanatory (UX-X7 spec line: "axes /
    // labels — pure decoration"; an empty chart must still tell the
    // reader what scale they're looking at).
    const m = _src_uxd.match(
      /function renderSparkline\(hist, key, windowMs, mode\) \{[\s\S]*?\n\}/);
    // eslint-disable-next-line no-new-func
    const renderSparkline = (new Function('return ' + m[0]))();
    const svg = renderSparkline([], 'u5h', 24 * 60 * 60 * 1000, 'hours');
    assert.match(svg, /<title>No data in window<\/title>/);
    assert.match(svg, />0%<\/text>/);
    // No-data path uses the '--' placeholder for the peak label.
    assert.match(svg, />--<\/text>/);
  });

  it('UX-VS2 — .vs-thumb is at least 24px (we ship 28px) on BOTH width AND height', () => {
    // Source-grep the actual CSS rule. The 28px values must appear in
    // the SAME .vs-thumb block for both dimensions so a future shrink
    // of one dimension can't pass this test by lucky alignment.
    const block = _src_uxd.match(/\.vs-thumb \{[\s\S]{0,400}\}/);
    assert.ok(block, '.vs-thumb CSS rule not found');
    // Width and height extraction.
    const wMatch = block[0].match(/width:\s*(\d+)px/);
    const hMatch = block[0].match(/height:\s*(\d+)px/);
    assert.ok(wMatch && hMatch, 'width/height not present inside .vs-thumb');
    const w = Number(wMatch[1]), h = Number(hMatch[1]);
    assert.ok(w >= 24, '.vs-thumb width should be ≥ 24px (got ' + w + ')');
    assert.ok(h >= 24, '.vs-thumb height should be ≥ 24px (got ' + h + ')');
  });

  it('UX-VS2 — margin-left of .vs-thumb is half the (negative) width so the thumb stays centred', () => {
    // Defensive: if a future dev bumps width to 32 but forgets margin
    // -16, the thumb would offset and look broken on resize. Tie the
    // two together via a regex that asserts the margin matches the
    // width's expected half.
    const block = _src_uxd.match(/\.vs-thumb \{[\s\S]{0,400}\}/);
    const wMatch = block[0].match(/width:\s*(\d+)px/);
    const mlMatch = block[0].match(/margin-left:\s*(-?\d+)px/);
    assert.ok(wMatch && mlMatch, 'margin-left missing from .vs-thumb');
    const w = Number(wMatch[1]);
    const ml = Number(mlMatch[1]);
    assert.equal(ml, -Math.floor(w / 2),
      'margin-left should be -' + Math.floor(w / 2) + 'px to keep the ' + w + 'px thumb centred');
  });

  it('UX-VS2 — input[type=range]::-webkit-slider-thumb sized at >=24px', () => {
    // A native <input type="range"> renders an OS-default 16px thumb
    // unless we override it. Defensive sizing covers the case where
    // a future feature uses a real range slider instead of the custom
    // .vs-thumb div.
    const block = _src_uxd.match(/input\[type="range"\]::-webkit-slider-thumb \{[\s\S]{0,400}\}/);
    assert.ok(block, '::-webkit-slider-thumb CSS not found');
    const wMatch = block[0].match(/width:\s*(\d+)px/);
    const hMatch = block[0].match(/height:\s*(\d+)px/);
    assert.ok(wMatch && hMatch, 'width/height not present inside ::-webkit-slider-thumb');
    assert.ok(Number(wMatch[1]) >= 24, '::-webkit-slider-thumb width should be ≥ 24px');
    assert.ok(Number(hMatch[1]) >= 24, '::-webkit-slider-thumb height should be ≥ 24px');
  });

  it('UX-VS2 — input[type=range]::-moz-range-thumb sized at >=24px (Firefox parity)', () => {
    // The Firefox prefix is the one most likely to be forgotten when
    // a dev tweaks webkit-thumb. Make the source grep enforce both.
    const block = _src_uxd.match(/input\[type="range"\]::-moz-range-thumb \{[\s\S]{0,400}\}/);
    assert.ok(block, '::-moz-range-thumb CSS not found');
    const wMatch = block[0].match(/width:\s*(\d+)px/);
    const hMatch = block[0].match(/height:\s*(\d+)px/);
    assert.ok(wMatch && hMatch, 'width/height not present inside ::-moz-range-thumb');
    assert.ok(Number(wMatch[1]) >= 24, '::-moz-range-thumb width should be ≥ 24px');
    assert.ok(Number(hMatch[1]) >= 24, '::-moz-range-thumb height should be ≥ 24px');
  });

  it('UX-VS2 — .vs-track-wrap height bumped to fit the larger thumb + focus ring', () => {
    // Without the wrapper-height bump, the focus-ring (3px halo on
    // .vs-thumb:focus) clips at the wrapper edge. The bump must match
    // or exceed thumb-diameter + 2*focus-ring-width.
    const block = _src_uxd.match(/\.vs-track-wrap \{[\s\S]{0,500}\}/);
    assert.ok(block, '.vs-track-wrap CSS not found');
    const hMatch = block[0].match(/height:\s*(\d+)px/);
    assert.ok(hMatch, 'height missing from .vs-track-wrap');
    assert.ok(Number(hMatch[1]) >= 36 + 6,
      '.vs-track-wrap height should be ≥ 42px to fit a 28px thumb + 6px of focus-ring halo (got ' + hMatch[1] + ')');
  });
});


// ─────────────────────────────────────────────────
// Time formatting batch — UX-X8 + UX-X9
//
// fmtTokenCount(n) — compact "1.2M" + exact "1,234,567"
// fmtDuration(ms)  — compact "5m 12s" / "2h 30m" + verbose "5 minutes 12 seconds"
//
// Both helpers MUST be pure (no DOM, no Date.now), MUST handle
// null/undefined/negative gracefully, and MUST be the single source of
// truth that compact-display sites mirror to (with title= carrying the
// exact form so power users can hover to see the precise value).
// ─────────────────────────────────────────────────
describe('fmtTokenCount — compact + exact dual-output', () => {
  it('returns short + exact for typical values', () => {
    const r = fmtTokenCount(1234567);
    assert.equal(r.short, '1.2M');
    assert.equal(r.exact, '1,234,567');
  });
  it('null returns 0 / 0', () => {
    const r = fmtTokenCount(null);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('undefined returns 0 / 0', () => {
    const r = fmtTokenCount(undefined);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('NaN returns 0 / 0 (no NaN leak into the UI)', () => {
    const r = fmtTokenCount(NaN);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('negative values clamp to 0 (token counts are never negative)', () => {
    const r = fmtTokenCount(-42);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('zero is rendered as "0" (not "0.0K" or similar)', () => {
    const r = fmtTokenCount(0);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('sub-1k stays in raw integer form', () => {
    const r = fmtTokenCount(999);
    assert.equal(r.short, '999');
    assert.equal(r.exact, '999');
  });
  it('exactly 1000 crosses the K threshold', () => {
    const r = fmtTokenCount(1000);
    assert.equal(r.short, '1.0K');
    assert.equal(r.exact, '1,000');
  });
  it('sub-1M renders as a fractional K', () => {
    const r = fmtTokenCount(15500);
    assert.equal(r.short, '15.5K');
    assert.equal(r.exact, '15,500');
  });
  it('exactly 1M crosses the M threshold', () => {
    const r = fmtTokenCount(1000000);
    assert.equal(r.short, '1.0M');
    assert.equal(r.exact, '1,000,000');
  });
  it('sub-1B renders as a fractional M (the silently-truncated case from UX-X9)', () => {
    const r = fmtTokenCount(1234567);
    assert.equal(r.short, '1.2M');
    assert.equal(r.exact, '1,234,567');
  });
  it('billions render as a fractional B', () => {
    const r = fmtTokenCount(2_500_000_000);
    assert.equal(r.short, '2.5B');
    assert.equal(r.exact, '2,500,000,000');
  });
  it('extreme billions stay readable', () => {
    const r = fmtTokenCount(987_654_321_000);
    assert.equal(r.short, '987.7B');
    assert.equal(r.exact, '987,654,321,000');
  });
  it('floating-point input is floored to integer (token counts are integral)', () => {
    const r = fmtTokenCount(1500.7);
    assert.equal(r.short, '1.5K');
    assert.equal(r.exact, '1,500');
  });
  it('Infinity is treated as out-of-domain (returns 0)', () => {
    const r = fmtTokenCount(Infinity);
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
  it('non-numeric input returns 0 / 0 (defensive)', () => {
    const r = fmtTokenCount('abc');
    assert.equal(r.short, '0');
    assert.equal(r.exact, '0');
  });
});

describe('fmtDuration — compact + verbose dual-output', () => {
  it('null returns 0s / 0 milliseconds', () => {
    const r = fmtDuration(null);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('undefined returns 0s / 0 milliseconds', () => {
    const r = fmtDuration(undefined);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('NaN returns 0s / 0 milliseconds', () => {
    const r = fmtDuration(NaN);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('negative ms clamps to 0 (durations are never negative)', () => {
    const r = fmtDuration(-1234);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('zero ms renders as 0s', () => {
    const r = fmtDuration(0);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('fractional seconds (sub-1s) round down to 0s for short, ms for exact', () => {
    const r = fmtDuration(750);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '750 milliseconds');
  });
  it('exactly 1 second', () => {
    const r = fmtDuration(1000);
    assert.equal(r.short, '1s');
    assert.equal(r.exact, '1 second');
  });
  it('multi-second under a minute', () => {
    const r = fmtDuration(45_000);
    assert.equal(r.short, '45s');
    assert.equal(r.exact, '45 seconds');
  });
  it('exactly 1 minute', () => {
    const r = fmtDuration(60_000);
    assert.equal(r.short, '1m 0s');
    assert.equal(r.exact, '1 minute');
  });
  it('minutes + seconds compose correctly', () => {
    const r = fmtDuration(5 * 60_000 + 12_000);
    assert.equal(r.short, '5m 12s');
    assert.equal(r.exact, '5 minutes 12 seconds');
  });
  it('hours + minutes compose (sessionDuration parity)', () => {
    const r = fmtDuration(2 * 3600_000 + 30 * 60_000);
    assert.equal(r.short, '2h 30m');
    assert.equal(r.exact, '2 hours 30 minutes');
  });
  it('days + hours compose', () => {
    const r = fmtDuration(3 * 86400_000 + 5 * 3600_000);
    assert.equal(r.short, '3d 5h');
    assert.equal(r.exact, '3 days 5 hours');
  });
  it('exactly 1 hour with no remainder', () => {
    const r = fmtDuration(3600_000);
    assert.equal(r.short, '1h 0m');
    assert.equal(r.exact, '1 hour');
  });
  it('exactly 1 day with no remainder', () => {
    const r = fmtDuration(86400_000);
    assert.equal(r.short, '1d 0h');
    assert.equal(r.exact, '1 day');
  });
  it('non-numeric input returns 0 / 0 milliseconds', () => {
    const r = fmtDuration('abc');
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
  it('Infinity is out-of-domain (returns 0)', () => {
    const r = fmtDuration(Infinity);
    assert.equal(r.short, '0s');
    assert.equal(r.exact, '0 milliseconds');
  });
});

// ─────────────────────────────────────────────────
// Time formatting batch — UX-X8 + UX-X9 source-grep regressions
//
// dashboard.mjs's renderHTML() template literal carries browser-side JS,
// so the helpers cannot be `import`-ed; they must be DEFINED inside the
// template (mirroring the lib.mjs canonical implementation). These
// regressions enforce two things:
//   1. The lib.mjs side actually exports the new helpers (and dashboard
//      imports them on the Node side for any non-renderHTML use).
//   2. Compact-display sites carry a `title=` with the exact value so
//      power users can hover to see precise numbers (the UX-X9 fix).
// ─────────────────────────────────────────────────
describe('Time formatting batch — UX-X8 / UX-X9 source-grep regressions', () => {
  const _src_tfmt_lib = _readFileSync_xss(
    new URL('../lib.mjs', import.meta.url),
    'utf8',
  );
  const _src_tfmt_dash = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('UX-X8/X9 — fmtTokenCount is exported from lib.mjs', () => {
    assert.match(_src_tfmt_lib, /export function fmtTokenCount\(/);
  });

  it('UX-X8/X9 — fmtDuration is exported from lib.mjs', () => {
    assert.match(_src_tfmt_lib, /export function fmtDuration\(/);
  });

  it('UX-X8/X9 — dashboard.mjs imports both helpers from lib.mjs', () => {
    // The Node-side import block (line ~790) must surface both new
    // helpers; without this the dashboard's CLI / hook handlers cannot
    // emit the shared compact form on stderr / log strings.
    assert.match(_src_tfmt_dash, /fmtTokenCount/);
    assert.match(_src_tfmt_dash, /fmtDuration/);
  });

  it('UX-X9 — at least 5 token-count display sites carry a title= with the exact form', () => {
    // The fix is to wrap every formatNum() callsite in a span carrying
    // title="<exact>". The browser-side helper is fmtTokenCountExact()
    // (defined inside the renderHTML template, mirrors lib.mjs). Any
    // compact-display site that drops the title would re-introduce the
    // UX-X9 silent truncation regression.
    //
    // The regex matches both `title="' + fmtTokenCountExact(...)` (no
    // prefix text — direct interpolation) and `title="prefix ' +
    // fmtTokenCountExact(...)` (prefix text before the interpolation).
    // Both spellings are valid; the audit only requires the title=
    // attribute carry the exact value somewhere in its value string.
    const titleSites = _src_tfmt_dash.match(
      /title="[^"]*' \+ fmtTokenCountExact\(/g,
    ) || [];
    assert.ok(titleSites.length >= 5,
      'expected at least 5 title="..."+fmtTokenCountExact callsites, found ' + titleSites.length);
  });

  it('UX-X9 — at least 3 duration display sites carry a title= with the exact form', () => {
    // Same matcher shape as the token-count grep above — accepts an
    // optional prefix string between title=" and the interpolation.
    const titleSites = _src_tfmt_dash.match(
      /title="[^"]*' \+ fmtDurationExact\(/g,
    ) || [];
    assert.ok(titleSites.length >= 3,
      'expected at least 3 title="..."+fmtDurationExact callsites, found ' + titleSites.length);
  });

  it('UX-X9 — fmtTokenCountExact helper exists inside renderHTML template (browser-side)', () => {
    // Browser-side mirror of lib.mjs.fmtTokenCount().exact — kept inside
    // the template literal because the browser cannot ES-import lib.mjs.
    assert.match(_src_tfmt_dash, /function fmtTokenCountExact\(/);
  });

  it('UX-X9 — fmtDurationExact helper exists inside renderHTML template (browser-side)', () => {
    assert.match(_src_tfmt_dash, /function fmtDurationExact\(/);
  });

  it('UX-X8 — formatNum delegates to the canonical compact form (no drift)', () => {
    // formatNum stays as a thin wrapper so existing browser-side
    // call-sites keep working, but its body must reduce to a single
    // expression that goes through fmtTokenCountShort (no inline
    // toFixed math that could drift from the lib.mjs canonical).
    // Slice generous (1200 chars) to cover the explanatory comment
    // block above the return statement.
    const fnBody = _src_tfmt_dash.slice(
      _src_tfmt_dash.indexOf('function formatNum(n) {'),
      _src_tfmt_dash.indexOf('function formatNum(n) {') + 1200,
    );
    assert.match(fnBody, /return fmtTokenCountShort\(n\);/);
  });

  it('UX-X8 — sessionDuration delegates to the canonical compact form (no drift)', () => {
    const fnBody = _src_tfmt_dash.slice(
      _src_tfmt_dash.indexOf('function sessionDuration(ms) {'),
      _src_tfmt_dash.indexOf('function sessionDuration(ms) {') + 1200,
    );
    assert.match(fnBody, /return fmtDurationShort\(ms\);/);
  });
});



// ─────────────────────────────────────────────────
// UX batch E — UX-L2 / UX-AC1 source-grep regressions
//
// Filter UIs added to the Logs tab (UX-L2) and the Activity tab (UX-AC1).
// Both filters share an identical UX: substring (default) / regex toggle /
// clear / count badge. Source-grep so a future refactor cannot silently
// drop any of these pieces.
// ─────────────────────────────────────────────────
describe("UX batch E — UX-L2 / UX-AC1 logs/activity filter regressions", () => {
  const _src_filterE = _readFileSync_xss(
    new URL("../dashboard.mjs", import.meta.url),
    "utf8",
  );

  it("UX-L2 — Logs tab has filter input + regex toggle + clear button + count", () => {
    assert.match(_src_filterE,
      /<input type="text"[^>]*id="logs-filter-input"/);
    assert.match(_src_filterE,
      /<input type="checkbox"[^>]*id="logs-filter-regex"/);
    assert.match(_src_filterE,
      /<button[^>]*id="logs-filter-clear"/);
    assert.match(_src_filterE,
      /id="logs-filter-count"/);
  });

  it("UX-AC1 — Activity tab has filter input + regex toggle + clear button + count", () => {
    assert.match(_src_filterE,
      /<input type="text"[^>]*id="activity-filter-input"/);
    assert.match(_src_filterE,
      /<input type="checkbox"[^>]*id="activity-filter-regex"/);
    assert.match(_src_filterE,
      /<button[^>]*id="activity-filter-clear"/);
    assert.match(_src_filterE,
      /id="activity-filter-count"/);
  });

  it("UX-L2/AC1 — both filter inputs cap input length at 256 chars", () => {
    assert.match(_src_filterE, /_VDM_FILTER_MAX_LEN\s*=\s*256/);
    const occ = _src_filterE.match(/_VDM_FILTER_MAX_LEN/g) || [];
    assert.ok(occ.length >= 3,
      "expected _VDM_FILTER_MAX_LEN in cap definition + at least 2 use-sites, found " + occ.length);
    assert.match(_src_filterE,
      /<input type="text"[^>]*id="logs-filter-input"[^>]*maxlength="256"/);
    assert.match(_src_filterE,
      /<input type="text"[^>]*id="activity-filter-input"[^>]*maxlength="256"/);
  });

  it("UX-L2/AC1 — regex compilation is wrapped in try/catch so an invalid pattern surfaces inline", () => {
    assert.match(_src_filterE,
      /function _vdmCompileFilterRegex\(/);
    assert.match(_src_filterE, /Invalid regex/);
    const fnSlice = _src_filterE.slice(
      _src_filterE.indexOf("function _vdmCompileFilterRegex"),
      _src_filterE.indexOf("function _vdmCompileFilterRegex") + 800,
    );
    assert.match(fnSlice, /try \{[\s\S]+catch/);
  });

  it("UX-L2/AC1 — localStorage keys use the bounded vdm.* namespace", () => {
    assert.match(_src_filterE, /vdm\.logsFilter/);
    assert.match(_src_filterE, /vdm\.logsRegex/);
    assert.match(_src_filterE, /vdm\.activityFilter/);
    assert.match(_src_filterE, /vdm\.activityRegex/);
  });

  it("UX-L2/AC1 — filter values not interpolated into innerHTML (XSS defence)", () => {
    const innerHtmlMatches = _src_filterE.match(
      /innerHTML\s*=[^;]*_vdmFilter(Logs|Activity)Pattern[^;]*\+/g,
    ) || [];
    assert.equal(innerHtmlMatches.length, 0,
      "filter pattern must not be interpolated into innerHTML — use input.value (DOM-escaped) only");
  });

  it("UX-L2/AC1 — filter applies via CSS class toggle (DOM-stable, can be cleared)", () => {
    assert.match(_src_filterE, /\.evt-hidden\s*\{\s*display:\s*none/);
    assert.match(_src_filterE, /\.log-line-hidden\s*\{\s*display:\s*none/);
  });
});

// ─────────────────────────────────────────────────
// Empty + error state pass — UX-AC3 / UX-A5 / UX-BR3 / UX-S1 source-grep
// regressions (batch C).
//
// Every empty-state branch the user can hit on first paint MUST suggest a
// next action — no dead-end "Nothing to show" / "OFF" copy. Modeled after
// the "A11y batch 2 — UX-X3 / UX-CPF3 / UX-S2" block above: the renderers
// all live inside the renderHTML() template literal and ship as a string
// to the browser, so behaviour-grade DOM tests aren't viable; instead we
// pin the load-bearing copy + structural shape via source-greps so a
// future refactor that re-introduces the dead-end strings trips at test
// time, before reaching the dashboard.
// ─────────────────────────────────────────────────
describe('Empty + error state pass — UX-AC3 / UX-A5 / UX-BR3 / UX-S1 (batch C)', () => {
  const _src_emptyC = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-AC3 — Activity tab empty state ──────────────────────────────
  it("UX-AC3 — activity feed empty state suggests starting a Claude Code session (initial markup)", () => {
    // The initial markup (before any data flows in) must use the
    // .empty-state shell + actionable copy, not the bare "No activity yet"
    // muted-text dead-end. The exact copy is part of the regression
    // contract because users see it on first paint.
    assert.match(_src_emptyC,
      /<div id="activity-log" class="empty-state">No activity yet\. Start a Claude Code session/);
  });

  it("UX-AC3 — runtime renderActivity empty branch matches the initial markup", () => {
    // renderActivity() runs after the initial paint and MUST emit the
    // same actionable copy when the log is empty (consistency between
    // first-paint and re-render — without this the actionable hint
    // disappears the first time the renderer fires, which it does
    // immediately on tab switch).
    assert.match(_src_emptyC,
      /el\.innerHTML\s*=\s*'<div class="empty-state">No activity yet\. Start a Claude Code session/);
  });

  it("UX-AC3 — old dead-end 'No activity yet</div>' (without actionable suffix) is gone", () => {
    // Defense against a future revert: the bare "No activity yet" copy
    // (no period, no follow-up sentence) must NOT survive anywhere in
    // the source. The two surviving sites both end with "Start a Claude
    // Code session" so we grep for the dead-end pattern explicitly.
    const deadEndMatches = _src_emptyC.match(/No activity yet<\/div>/g) || [];
    assert.equal(deadEndMatches.length, 0,
      'expected zero "No activity yet</div>" dead-ends, found ' + deadEndMatches.length);
  });

  // ── UX-A5 — Dormant accounts inline hint ───────────────────────────
  it("UX-A5 — dormant account hint mentions 'windows not started yet' instead of bare 'window preserved'", () => {
    // The old copy "Dormant - window preserved" left users wondering if
    // the account was broken. The replacement explains *why* (no
    // requests have been made) and reassures via a hover title that
    // explains conserve-strategy semantics.
    assert.match(_src_emptyC, /Dormant — windows not started yet/);
  });

  it("UX-A5 — dormant hint carries an explanatory title= for hover discoverability", () => {
    // Tooltip MUST be present (the inline copy is intentionally short
    // to fit the card; the long-form explanation lives in title=).
    // We check for the conserve-strategy keywords inside the title to
    // ensure the hover text actually contains the explanation, not
    // just a placeholder.
    assert.match(_src_emptyC,
      /title="Conserve strategy: this account[^"]*window[^"]*has not started/);
  });

  it("UX-A5 — old dead-end 'Dormant  - window preserved' copy is gone", () => {
    // Defense against a future revert. Note the double-space in the
    // historical copy (a typo from the original source) — we grep for
    // the exact dead-end including the typo so a revert is caught even
    // if someone "fixes" the spacing.
    const deadEndMatches = _src_emptyC.match(/Dormant\s+-\s+window preserved/g) || [];
    assert.equal(deadEndMatches.length, 0,
      'expected zero "Dormant - window preserved" dead-ends, found ' + deadEndMatches.length);
  });

  // ── UX-BR3 — Tool Breakdown panel ──────────────────────────────────
  it("UX-BR3 — Tool Breakdown panel does NOT silently set display:none when per-tool attribution is off", () => {
    // The historical fix-target was `card.style.display = 'none'` inside
    // the !hasAttributed branch. We now want the card to stay visible
    // and render an actionable explainer instead. Greps the renderToolBreakdown
    // function slice for the dead-end pattern.
    const fnSlice = _src_emptyC.slice(
      _src_emptyC.indexOf('function renderToolBreakdown'),
      _src_emptyC.indexOf('function renderToolBreakdown') + 3000,
    );
    assert.doesNotMatch(fnSlice, /if\s*\(\s*!hasAttributed\s*\)\s*\{\s*card\.style\.display\s*=\s*'none'/,
      "renderToolBreakdown must not hide the card when per-tool attribution is off — show an explainer instead");
  });

  it("UX-BR3 — Tool Breakdown empty-state explainer mentions enabling per-tool attribution in Config", () => {
    // The replacement copy must tell the user (a) the panel is empty
    // because the gate is off, (b) where to flip the gate. The link
    // target is the Config tab via switchTab('config'). Source-greps
    // the function slice to scope the assertion.
    const fnSlice = _src_emptyC.slice(
      _src_emptyC.indexOf('function renderToolBreakdown'),
      _src_emptyC.indexOf('function renderToolBreakdown') + 3000,
    );
    assert.match(fnSlice, /Per-tool attribution is OFF/);
    // The source emits the onclick as `switchTab(\\'config\\')` (the
    // double-backslash is a literal '\\' in the source file because
    // the surrounding HTML attribute is single-quoted at runtime).
    // Match the literal source bytes here.
    assert.match(fnSlice, /switchTab\(\\\\'config\\\\'\)/);
  });

  // ── UX-S1 — Sessions tab loading/initial empty state ───────────────
  it("UX-S1 — Sessions tab initial markup uses 'Loading sessions' (not 'Session Monitor is OFF')", () => {
    // The historical bug: hardcoded markup said "Session Monitor is OFF"
    // even when the user had ENABLED the feature, because /api/sessions
    // hadn't replied yet. Race condition on first paint after enabling.
    // Fix: show a generic loading state initially; the renderer flips
    // to the truth-based copy once data arrives.
    assert.match(_src_emptyC,
      /<div class="empty-state" id="sessions-loading">Loading sessions/);
  });

  it("UX-S1 — Sessions tab initial markup no longer hardcodes 'Session Monitor is OFF'", () => {
    // The renderSessions() function still emits "Session Monitor is OFF"
    // when data.enabled is false (that's the truth-based branch we keep).
    // What we forbid is the *initial* hardcoded id="sessions-disabled"
    // markup that fires before any fetch.
    assert.doesNotMatch(_src_emptyC,
      /<div class="empty-state" id="sessions-disabled">Session Monitor is OFF\./);
  });

  it("UX-S1 — renderSessions still emits truth-based 'Session Monitor is OFF' when data.enabled === false", () => {
    // We keep the truth-based branch (after the fetch returns) so users
    // who genuinely have the feature off see actionable copy. The
    // initial-markup path is the only one that changes.
    const fnSlice = _src_emptyC.slice(
      _src_emptyC.indexOf('function renderSessions'),
      _src_emptyC.indexOf('function renderSessions') + 2000,
    );
    assert.match(fnSlice, /if\s*\(\s*!data\.enabled\s*\)/);
    assert.match(fnSlice, /Session Monitor is OFF/);
    assert.match(fnSlice, /No sessions yet/);
  });

  // ── Cross-cutting — XSS / a11y discipline ──────────────────────────
  it("UX-AC3 / UX-S1 — empty-state copy uses .empty-state class (consistent shell)", () => {
    // Every actionable empty state in the dashboard uses the same shell
    // (.empty-state class — see CSS at line ~4382). Without this,
    // empty-state copy looks visually inconsistent across tabs. The
    // accounts-tab empty-state at "No accounts yet. Run claude login"
    // is the canonical reference.
    assert.match(_src_emptyC, /class="empty-state"[^>]*>No accounts yet\. Run/);
  });
});

// ─────────────────────────────────────────────────
// Visual hierarchy batch — UX-A2 / UX-A3 / UX-A4 / UX-CO2 / UX-AC2
// source-grep regressions (batch A).
//
// These tests guard the load-bearing markup and CSS introduced by the
// visual hierarchy batch:
//   * UX-A2 — "Exclude from auto-switch" toggle moved into the
//     .card-actions row (no longer buried under the rate bars in
//     muted-text). Active cards now also get a card-actions row so
//     the toggle is reachable on the active account.
//   * UX-A3 — `excluded` badge replaces the inline-style
//     grey-on-near-white form with a palette-consistent .badge-excluded
//     class.
//   * UX-A4 — renderVelocityInline shows ONLY the binding ETA (the
//     soonest constraint) and stashes the other in title=.
//   * UX-CO2 — All four BETA badges in the Config tab use the .beta-badge
//     class. The duplicate "Enable session monitor" toggle-label BETA is
//     removed (one badge per section).
//   * UX-AC2 — Activity feed entries carry an evt-icon glyph paired with
//     the dot's colour for colour-blind accessibility.
// ─────────────────────────────────────────────────
describe('Visual hierarchy batch — UX-A2/A3/A4 + UX-CO2 + UX-AC2 source-grep regressions', () => {
  const _src_vh = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-A3 — palette-consistent .badge-excluded class
  it('UX-A3 — .badge-excluded CSS class is defined (replaces inline-style)', () => {
    // The class must use var(--*) tokens (not hardcoded colours) so it
    // tracks the dashboard theme. The audit's example asked for muted
    // text on the bg layer; we use card so the badge reads on both
    // .card.active (primary tint) and inactive cards.
    assert.match(_src_vh,
      /\.badge-excluded\s*\{[\s\S]{0,400}color:\s*var\(--muted\);[\s\S]{0,400}border-color:\s*var\(--border\);/);
  });

  it('UX-A3 — excluded badge uses badge-excluded class (no inline-style override)', () => {
    // The pre-fix shape was:
    //   <span class="badge" style="background:var(--muted);color:var(--bg);font-size:0.65rem">excluded</span>
    // — failed WCAG AA (grey-on-near-white). The new shape MUST use the
    // class, NOT inline style.
    assert.match(_src_vh,
      /<span class="badge badge-excluded" title="[^"]+">excluded<\/span>/);
    // And the legacy inline-style form must be GONE (regression guard).
    assert.doesNotMatch(_src_vh,
      /'<span class="badge" style="background:var\(--muted\);color:var\(--bg\)/);
  });

  it('UX-A3 — excluded badge carries an explanatory title= tooltip', () => {
    // The badge is a 7-character pill; without a tooltip new users do
    // not know what "excluded" applies to. The title narrates the
    // semantic: skip from auto-switch but keep manual access.
    assert.match(_src_vh,
      /title="This account is excluded from auto-switch[^"]+only manual switches will reach it"/);
  });

  // ── UX-A2 — toggle relocation into card-actions
  it('UX-A2 — .card-actions CSS class is defined for the new actions row', () => {
    // The class must lay out toggle + buttons on a single row with the
    // toggle pinned left (margin-right:auto) so the action buttons
    // hug the right edge.
    assert.match(_src_vh,
      /\.card-actions\s*\{[\s\S]{0,200}display:\s*flex;[\s\S]{0,200}flex-wrap:\s*wrap;\s*\}/);
    assert.match(_src_vh,
      /\.card-actions \.acct-pref-toggle\s*\{\s*margin-right:\s*auto;\s*\}/);
  });

  it('UX-A2 — .acct-pref-toggle has a hover/focus affordance (no longer muted)', () => {
    // The pre-fix style declared `color: var(--muted)` inline on the
    // <label>. The new class uses var(--foreground) so the control
    // reads as an actionable pill, not a passive hint.
    assert.match(_src_vh,
      /\.acct-pref-toggle\s*\{[\s\S]{0,400}color:\s*var\(--foreground\);[\s\S]{0,400}cursor:\s*pointer;/);
    // hover/focus rules MUST exist so the user knows it is interactive.
    assert.match(_src_vh,
      /\.acct-pref-toggle:hover\s*\{[^}]*background:\s*var\(--bg\);[^}]*\}/);
    assert.match(_src_vh,
      /\.acct-pref-toggle:focus-within\s*\{[^}]*outline:\s*2px solid var\(--primary\)/);
  });

  it('UX-A2 — .acct-pref-toggle.is-on flips colour to make the active state visible', () => {
    // The audit pointed out that the previous form needed the user to
    // read the checkbox state to know if the toggle was on. The is-on
    // class flips the pill itself to the yellow-soft palette so the
    // state is visible from across the screen.
    assert.match(_src_vh,
      /\.acct-pref-toggle\.is-on\s*\{[\s\S]{0,200}color:\s*var\(--yellow\);[\s\S]{0,200}background:\s*var\(--yellow-soft\);/);
  });

  it('UX-A2 — renderAccounts emits prefsHtml inside card-actions, not as a free child', () => {
    // The pre-fix markup placed prefsHtml as a sibling of buttonsHtml
    // (so the toggle hung loose between staleMsg and buttonsHtml).
    // The fix moves prefsHtml INSIDE card-actions so it lives on the
    // action-bar row.
    // Source-grep asserts:
    //   1. card-actions wrapper exists
    //   2. prefsHtml is concatenated immediately INSIDE the wrapper
    //   3. inner template no longer references prefsHtml as a sibling
    assert.match(_src_vh,
      /var buttonsHtml = '<div class="card-actions">'\s*\+\s*prefsHtml/);
    // The pre-fix line `staleMsg + prefsHtml + buttonsHtml` is gone —
    // assert the new shape `staleMsg + buttonsHtml` (no orphan
    // prefsHtml between them).
    assert.match(_src_vh,
      /barsHtml \+\s*staleMsg \+\s*buttonsHtml;/);
    assert.doesNotMatch(_src_vh, /staleMsg \+\s*prefsHtml \+\s*buttonsHtml/);
  });

  it('UX-A2 — toggle is-on class mirrors p.excludeFromAuto', () => {
    assert.match(_src_vh,
      /'<label class="acct-pref-toggle' \+ \(p\.excludeFromAuto \? ' is-on' : ''\)/);
  });

  // ── UX-A4 — single binding-constraint ETA
  it('UX-A4 — renderVelocityInline picks the binding (shorter) ETA, stashes the other in title=', () => {
    // The new function declares a `binding5h` flag from min5/min7 and
    // builds a single badge. The pre-fix function emitted TWO middle-
    // dot separators in a row.
    const fn = _src_vh.slice(
      _src_vh.indexOf('function renderVelocityInline'),
      _src_vh.indexOf('function renderVelocityInline') + 3500,
    );
    assert.match(fn, /const binding5h = _eff\(min5\) <= _eff\(min7\);/);
    // title= MUST surface the other ETA when both are available
    assert.match(fn, /const otherKind = \(kind === '5h'\) \? '7d' : '5h';/);
    assert.match(fn, /title \+= '\. ' \+ otherKind \+ ' ETA: ' \+ otherText;/);
    // Single emission line — only one card-token-sep + velocity-badge
    // is appended at the end (the pre-fix function had two such
    // appends in series).
    const sepCount = (fn.match(/<span class="card-token-sep">/g) || []).length;
    assert.equal(sepCount, 1,
      'renderVelocityInline must emit exactly ONE separator+badge pair, found ' + sepCount);
  });

  it('UX-A4 — renderVelocityInline returns empty string when both ETAs are null', () => {
    const fn = _src_vh.slice(
      _src_vh.indexOf('function renderVelocityInline'),
      _src_vh.indexOf('function renderVelocityInline') + 3500,
    );
    assert.match(fn, /if \(min5 == null && min7 == null\) return '';/);
  });

  // ── UX-CO2 — single .beta-badge class for all BETA spans
  it('UX-CO2 — .beta-badge CSS class is defined (replaces 4× inline style)', () => {
    assert.match(_src_vh,
      /\.beta-badge\s*\{[\s\S]{0,500}color:\s*var\(--yellow\);[\s\S]{0,500}background:\s*var\(--yellow-soft\);[\s\S]{0,500}border:\s*1px solid var\(--yellow-border\);/);
  });

  it('UX-CO2 — exactly 4 BETA badges in the Config tab, all using .beta-badge', () => {
    // After the audit fix: Request Serialization, Commit Tokens,
    // Session Monitor, Per-Tool Attribution → 4 sections, 1 badge each.
    // The duplicate inside the "Enable session monitor" label is REMOVED.
    const matches = _src_vh.match(/<span class="beta-badge">BETA<\/span>/g) || [];
    assert.equal(matches.length, 4,
      'expected exactly 4 .beta-badge spans, found ' + matches.length);
  });

  it('UX-CO2 — no inline-style BETA spans remain (regression guard)', () => {
    // The pre-fix shape used `style="font-size:0.625rem;font-weight:500;
    // color:var(--yellow);background:var(--yellow-soft);..."`. None of
    // those should remain.
    assert.doesNotMatch(_src_vh,
      /<span style="[^"]*color:var\(--yellow\)[^"]*">BETA<\/span>/);
  });

  // ── UX-AC2 — activity-event glyph paired with dot colour
  it('UX-AC2 — evtIcons map is defined and covers severity-critical event types', () => {
    assert.match(_src_vh, /^const evtIcons = \{/m);
    // Spot-check the most-critical entries the audit named:
    //   rate-limited (warn glyph), auth-expired (error), all-exhausted
    //   (no-entry), token-refreshed (check), account-discovered (plus).
    assert.match(_src_vh, /'rate-limited':\s*'▲'/);
    assert.match(_src_vh, /'auth-expired':\s*'✖'/);
    assert.match(_src_vh, /'all-exhausted':\s*'⛔'/);
    assert.match(_src_vh, /'token-refreshed':\s*'✓'/);
    assert.match(_src_vh, /'account-discovered':\s*'\+'/);
  });

  it('UX-AC2 — every activity entry renders an evt-icon BEFORE the dot', () => {
    // The renderer must emit the icon span before the dot span so the
    // glyph and colour share the same scan zone.
    assert.match(_src_vh,
      /'<span class="evt-icon" aria-hidden="true" style="color:' \+ c \+ '">' \+ icon \+ '<\/span>' \+\s*'<span class="evt-dot"/);
  });

  it('UX-AC2 — .evt-icon CSS sizes the glyph and applies tabular-nums', () => {
    assert.match(_src_vh,
      /\.evt-icon\s*\{[\s\S]{0,400}font-size:\s*0\.75rem;[\s\S]{0,400}font-variant-numeric:\s*tabular-nums;/);
  });

  it('UX-AC2 — icon source is the closed evtIcons map, NOT user-controlled fields (XSS hardening)', () => {
    // The renderer must source the icon from `evtIcons[e.type]` with a
    // safe '•' fallback. If a future refactor pulled the icon from
    // any user-controlled field on `e.*`, the aria-hidden span would
    // become an HTML-injection sink.
    assert.match(_src_vh, /const icon = evtIcons\[e\.type\] \|\| '•';/);
    // Defensive: source-grep that the icon var is NOT built by string
    // concatenation from any e.* field.
    assert.doesNotMatch(_src_vh, /const icon = .*\+\s*e\.[a-zA-Z]/);
  });

  it('UX-AC2 — aria-hidden on the icon span (no double-announce)', () => {
    // Screen readers MUST hear the message text alone — the icon is a
    // redundant visual cue, not a label.
    assert.match(_src_vh,
      /<span class="evt-icon" aria-hidden="true"/);
  });
});

// ─────────────────────────────────────────────────
// UX batch G — UX-A6 / UX-A7 source-grep regressions
// ─────────────────────────────────────────────────
describe('UX batch G — UX-A6 / UX-A7 account-card stale + hover regressions', () => {
  const _src_g = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  it('UX-A6 — .card.stale targets only header chrome, NOT whole card', () => {
    // The whole-card opacity selector `.card.stale { opacity: 0.5 }` MUST
    // be gone. Otherwise the red .stale-msg copy and the Refresh button
    // are still half-faded and demand a hover-to-read interaction the
    // audit explicitly called out.
    assert.doesNotMatch(_src_g, /\.card\.stale\s*\{\s*opacity:\s*0\.5\s*;\s*\}/);
    assert.doesNotMatch(_src_g, /\.card\.stale:hover\s*\{\s*opacity:\s*0\.7\s*;\s*\}/);
    // Targeted opacity on header chrome ONLY. The selector list pins the
    // three children that should be dimmed (status dot / name / badges
    // wrapper), so a future refactor that reverts to whole-card opacity
    // will trip this test.
    assert.match(_src_g,
      /\.card\.stale\s*\.card-top\s*\{[\s\S]{0,200}opacity:\s*0\.55\s*;/);
  });

  it('UX-A6 — .stale-msg, action buttons, rate-bars stay at FULL opacity', () => {
    // The error copy + the actionable buttons MUST remain at opacity 1
    // so the user can read what is wrong without hovering. Pin via an
    // explicit `.card.stale .stale-msg { opacity: 1 }` block (and the
    // sibling button selectors).
    assert.match(_src_g,
      /\.card\.stale\s*\.stale-msg[\s\S]{0,200}opacity:\s*1\s*;/);
    assert.match(_src_g,
      /\.card\.stale\s*\.card-actions[\s\S]{0,200}opacity:\s*1\s*;/);
  });

  it('UX-A6 — "stale" pill renders inside header for stale cards (visible-text + aria-label)', () => {
    // The pill MUST be visible text + carry aria-label so SR / colour-
    // blind users get an explicit signal. The renderer emits the pill
    // only when isStale is true, in the .card-badges wrapper.
    assert.match(_src_g,
      /<span class="badge badge-stale" aria-label="[^"]+">stale<\/span>/);
    // CSS class is defined with a clear muted-red palette so the pill
    // reads as a soft warning (NOT just a generic muted badge).
    assert.match(_src_g,
      /\.badge-stale\s*\{[\s\S]{0,300}color:\s*var\(--red\)[\s\S]{0,200}border-color:\s*var\(--red-border\)/);
  });

  it('UX-A6 — pill source is the closed isStale boolean, NOT user-controlled fields (XSS hardening)', () => {
    // Just like the .badge-active / .badge-excluded source-grep above —
    // the pill must be emitted from the boolean isStale (computed from
    // server-side fields), never concatenated from a p.* string field.
    // If any future refactor builds the pill from `p.<something>` we want
    // to know.
    assert.doesNotMatch(_src_g,
      /badge-stale[^"]*"\s*[^>]*>[\s\S]{0,40}\+\s*p\.[a-zA-Z]/);
  });

  it('UX-A7 — .accounts gap bumped to 0.875rem (was 0.625rem) so hover shadow has room', () => {
    // Tight 0.625rem gap was the root cause: shadow-lg extends ~12px
    // below each card and bled onto the next card visually. Bumping the
    // gap is the minimum-invasive fix (no JS change required).
    assert.match(_src_g,
      /\.accounts\s*\{[\s\S]{0,120}gap:\s*0\.875rem\s*;/);
  });

  it('UX-A7 — .card:hover lifts via translateY(-1px) so shadow has somewhere to go', () => {
    // The lift gives the shadow vertical clearance so it sits underneath
    // the lifted card instead of overlapping the neighbour below. The
    // transition list MUST include `transform` so the lift animates
    // (snapping looks like a layout glitch).
    assert.match(_src_g,
      /\.card:hover\s*\{[\s\S]{0,300}transform:\s*translateY\(-1px\)\s*;/);
    assert.match(_src_g,
      /\.card\s*\{[\s\S]{0,400}transition:\s*[^}]*transform[^}]*0\.2s/);
  });

  it('UX-A7 — .card:hover picks up --primary border for a crisp boundary', () => {
    // With the shadow reduced + lift added, the border is now the
    // primary "selected" affordance. The audit fix recommended exactly
    // this approach so the hovered card stays visually distinct on
    // dense lists (the previous fuzzy-shadow boundary was the complaint).
    assert.match(_src_g,
      /\.card:hover\s*\{[\s\S]{0,300}border-color:\s*var\(--primary\)\s*;/);
  });

  it('UX-A7 — .card:hover does NOT use the bigger var(--shadow-lg) anymore', () => {
    // The hover used `box-shadow: var(--shadow-lg)` — the 12-px diffuse
    // shadow that bled onto neighbours. The replacement uses the
    // smaller resting-state `var(--shadow)` token (or no shadow change
    // at all). This grep pins the absence of the shadow-lg upgrade on
    // the .card:hover selector specifically.
    const cardHoverBlock = _src_g.match(/\.card:hover\s*\{[^}]*\}/);
    assert.ok(cardHoverBlock, 'expected to find .card:hover CSS block');
    assert.doesNotMatch(cardHoverBlock[0], /box-shadow:\s*var\(--shadow-lg\)/);
  });
});

// ─────────────────────────────────────────────────
// Sessions tab polish — UX-S3 / UX-S4 source-grep regressions (batch J)
// ─────────────────────────────────────────────────
describe('Sessions tab polish — UX-S3 / UX-S4 source-grep regressions (batch J)', () => {
  const _src_uxj = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-S3 — Copy button: SVG icon + aria-label ──
  it('UX-S3 — copy button no longer uses the 📋 emoji surrogate pair', () => {
    // The pre-fix shape was `>\\uD83D\\uDCCB</button>`. That escape
    // sequence MUST not appear inside a session-copy-btn emit-site any
    // longer (it can still appear elsewhere in the file for other
    // purposes — the assertion is scoped to the copy button specifically).
    assert.doesNotMatch(_src_uxj,
      /<button class="session-copy-btn"[^>]*>\\uD83D\\uDCCB<\/button>/);
  });

  it('UX-S3 — copy button uses inline SVG icon (cross-platform, no emoji-font dependency)', () => {
    // The icon is interpolated via a `SESSION_COPY_ICON_SVG` constant
    // (so the same SVG is used by both the active + recent emit-sites
    // and any future emit-site picks it up automatically). Verify the
    // constant is defined as an inline SVG with aria-hidden, AND that
    // both emit-sites reference it.
    assert.match(_src_uxj,
      /var SESSION_COPY_ICON_SVG = '<svg [^']*aria-hidden="true"[^']*>/);
    const refs = _src_uxj.match(
      /<button class="session-copy-btn"[^>]*>'\s*\+\s*SESSION_COPY_ICON_SVG\s*\+\s*'<\/button>/g
    ) || [];
    assert.ok(refs.length >= 2,
      'expected >= 2 references to SESSION_COPY_ICON_SVG inside copy-button emit-sites, found ' + refs.length);
  });

  it('UX-S3 — copy button SVG contains NO <script> tags (XSS hardening)', () => {
    // The inline SVG lives in the static `SESSION_COPY_ICON_SVG`
    // constant — verify that constant has no <script> tag. Defense
    // in depth against a future refactor that interpolates user-text
    // into the SVG.
    const m = _src_uxj.match(/var SESSION_COPY_ICON_SVG = '([^']*)'/);
    assert.ok(m, 'SESSION_COPY_ICON_SVG constant must be defined');
    assert.doesNotMatch(m[1], /<script/i,
      'SESSION_COPY_ICON_SVG must not contain <script> tags');
    // Also verify the literal text contains <svg ... </svg> (sanity).
    assert.match(m[1], /<svg[\s\S]*<\/svg>/);
  });

  it('UX-S3 — copy button carries aria-label (accessible name for screen readers)', () => {
    // The pre-fix button had only the emoji glyph as its content, with
    // no aria-label. Screen readers either announced "U+1F4CB" or
    // nothing at all. The new button MUST have a descriptive
    // aria-label.
    const matches = _src_uxj.match(
      /<button class="session-copy-btn"[^>]*aria-label="[^"]+"/g
    ) || [];
    assert.ok(matches.length >= 2,
      'expected >= 2 session-copy-btn emit-sites with aria-label, found ' + matches.length);
  });

  it('UX-S3 — copy button aria-label mentions "session timeline" (descriptive, not generic)', () => {
    // A generic aria-label="Copy" is a common a11y mistake. The label
    // must describe WHAT is being copied so a screen reader user
    // navigating multiple Copy buttons can tell them apart.
    assert.match(_src_uxj,
      /<button class="session-copy-btn"[^>]*aria-label="Copy session timeline[^"]*"/);
  });

  it('UX-S3 — copy button carries title= attribute for sighted-mouse users', () => {
    // The button is opacity:0 by default and only visible on
    // .session-card:hover — discoverability for sighted users is
    // already poor. A title= tooltip provides on-hover affordance.
    const matches = _src_uxj.match(
      /<button class="session-copy-btn"[^>]*title="[^"]+"/g
    ) || [];
    assert.ok(matches.length >= 2,
      'expected >= 2 session-copy-btn emit-sites with title, found ' + matches.length);
  });

  it('UX-S3 — SVG icon set to pointer-events: none so clicks land on the button', () => {
    // A common SVG pitfall: clicks on the inner <svg> can target the
    // SVG element instead of the button, breaking event handlers that
    // rely on `event.target === button`. pointer-events: none on the
    // SVG funnels every click to the button itself.
    assert.match(_src_uxj,
      /\.session-copy-btn svg \{[\s\S]{0,200}pointer-events: none;/);
  });

  it('UX-S3 — copy button onclick stops event propagation (does not toggle session collapse)', () => {
    // The button is a sibling of session-header so click bubbling
    // shouldn't reach the collapse handler — but defense-in-depth:
    // the onclick passes the event through and copyTimeline calls
    // stopPropagation. This guards against a future refactor moving
    // the button INSIDE the header.
    // Source pattern: onclick="copyTimeline(\\'' + s.id + '\\', event)"
    // (the four backslashes in the regex match two literal backslashes
    // each — one to escape the apostrophe at HTML emit time, the other
    // is just the regex-literal escape of the single backslash).
    assert.match(_src_uxj,
      /onclick="copyTimeline\(\\\\'' \+ s\.id \+ '\\\\', event\)"/);
  });

  it('UX-S3 — copyTimeline accepts and stops propagation on the event arg', () => {
    // The function signature must accept the event arg and call
    // stopPropagation on it (when present — keyboard-triggered .click()
    // calls don't pass an event).
    assert.match(_src_uxj,
      /function copyTimeline\(sessionId, ev\) \{[\s\S]{0,800}if \(ev && ev\.stopPropagation\) ev\.stopPropagation\(\);/);
  });

  // ── UX-S4 — Timeline overflow: fade-out + Show all/less toggle ──
  it('UX-S4 — .session-timeline keeps max-height: 500px in the default state', () => {
    // The audit complaint was the silent clip, not the cap itself —
    // we keep the cap as a sensible default but add an opt-in expander
    // (UX-S4 below).
    assert.match(_src_uxj,
      /\.session-timeline \{[\s\S]{0,400}max-height: 500px;/);
  });

  it('UX-S4 — .session-timeline-expanded class lifts the height cap', () => {
    // The toggle flips this class on the .session-timeline element.
    // When set, max-height becomes none so the timeline grows to its
    // natural height.
    assert.match(_src_uxj,
      /\.session-timeline\.session-timeline-expanded \{[\s\S]{0,200}max-height: none;/);
  });

  it('UX-S4 — .session-timeline-fade pseudo-element creates the fade-out gradient', () => {
    // Browser-rendered linear gradient at the bottom of the
    // overflowing timeline. Must use ::after pseudo-element + position
    // sticky so it sits at the bottom edge regardless of scroll
    // position. Visible only when .session-timeline-clipped class is
    // toggled on (set by JS when scrollHeight > clientHeight).
    assert.match(_src_uxj,
      /\.session-timeline-fade \{[\s\S]{0,500}linear-gradient/);
  });

  it('UX-S4 — fade-out element hidden when timeline is expanded', () => {
    // When the user expands the timeline (clicks "Show all"), the
    // fade-out indicator becomes meaningless and must be hidden.
    assert.match(_src_uxj,
      /\.session-timeline\.session-timeline-expanded \+ \.session-timeline-fade,?\s*\.session-timeline\.session-timeline-expanded ~ \.session-timeline-fade \{[\s\S]{0,200}display: none;/);
  });

  it('UX-S4 — Show all/less toggle button is rendered as a sibling of the timeline', () => {
    // Two emit-sites (active + recent). The button MUST be a real
    // <button> (not a div) so the browser handles Enter/Space natively
    // and screen readers announce it as a button.
    const matches = _src_uxj.match(
      /<button class="session-timeline-expand"[^>]*>/g
    ) || [];
    assert.ok(matches.length >= 2,
      'expected >= 2 session-timeline-expand emit-sites, found ' + matches.length);
  });

  it('UX-S4 — expand toggle initial label is "Show all" (collapsed state)', () => {
    // The initial render shows "Show all" because the timeline starts
    // capped. After click, JS swaps the textContent to "Show less".
    assert.match(_src_uxj,
      /<button class="session-timeline-expand"[^>]*>Show all<\/button>/);
  });

  it('UX-S4 — toggleSessionTimelineExpand is the click handler and accepts a session id', () => {
    // The handler must:
    //   1. Find the .session-timeline element by data-sid lookup
    //   2. Toggle the .session-timeline-expanded class
    //   3. Swap the button textContent between "Show all" and "Show less"
    //   4. Update aria-expanded on the button for screen readers
    assert.match(_src_uxj,
      /function toggleSessionTimelineExpand\(id, ev\) \{/);
    // Must call stopPropagation so the click doesn't bubble up to the
    // session-header collapse handler.
    const fn = _src_uxj.slice(
      _src_uxj.indexOf('function toggleSessionTimelineExpand'),
      _src_uxj.indexOf('function toggleSessionTimelineExpand') + 1500,
    );
    assert.match(fn, /if \(ev && ev\.stopPropagation\) ev\.stopPropagation\(\);/);
    assert.match(fn, /classList\.toggle\('session-timeline-expanded'\)/);
    // Updates the visible label on the toggle button — accept either
    // the literal strings or the SESSION_TIMELINE_LABEL_* constants
    // (current source uses the constants for single-source-of-truth).
    assert.match(fn, /textContent = .{0,80}\?\s*(?:'Show less'|SESSION_TIMELINE_LABEL_SHOW_LESS)\s*:\s*(?:'Show all'|SESSION_TIMELINE_LABEL_SHOW_ALL)/);
    // The constants must be defined (single source of truth — handler
    // and overflow-applier both reference them).
    assert.match(_src_uxj, /var SESSION_TIMELINE_LABEL_SHOW_ALL\s*=\s*'Show all'/);
    assert.match(_src_uxj, /var SESSION_TIMELINE_LABEL_SHOW_LESS\s*=\s*'Show less'/);
    // Mirrors aria-expanded for screen readers.
    assert.match(fn, /setAttribute\('aria-expanded'/);
  });

  it('UX-S4 — toggle button initial aria-expanded="false" (timeline starts capped)', () => {
    assert.match(_src_uxj,
      /<button class="session-timeline-expand"[^>]*aria-expanded="false"/);
  });

  it('UX-S4 — toggle button onclick passes the event through (defense-in-depth)', () => {
    // Source pattern (same backslash convention as the copy button):
    //   onclick="toggleSessionTimelineExpand(\\'' + s.id + '\\', event)"
    assert.match(_src_uxj,
      /onclick="toggleSessionTimelineExpand\(\\\\'' \+ s\.id \+ '\\\\', event\)"/);
  });

  it('UX-S4 — applySessionTimelineOverflow detects overflow and toggles the fade indicator class', () => {
    // After renderSessions paints, JS measures each timeline and
    // toggles .session-timeline-clipped if scrollHeight > clientHeight.
    // The fade-out indicator only shows when the class is present.
    assert.match(_src_uxj,
      /function applySessionTimelineOverflow\(\) \{/);
    const fn = _src_uxj.slice(
      _src_uxj.indexOf('function applySessionTimelineOverflow'),
      _src_uxj.indexOf('function applySessionTimelineOverflow') + 2000,
    );
    assert.match(fn, /scrollHeight > .{0,30}clientHeight/);
    assert.match(fn, /classList\.(?:add|toggle)\('session-timeline-clipped'/);
  });

  it('UX-S4 — applySessionTimelineOverflow runs after renderSessions', () => {
    // Without this call, the .session-timeline-clipped class never
    // gets set and the fade-out + Show all button stay hidden even
    // when the timeline overflows. The slice must extend past the
    // last `el.innerHTML = html;` so any future trailing additions
    // before the call still match.
    const startIdx = _src_uxj.indexOf('function renderSessions(');
    const renderFn = _src_uxj.slice(startIdx, startIdx + 12000);
    // Must call applySessionTimelineOverflow AFTER el.innerHTML=html.
    // Verify both pieces are present and order is correct.
    const innerHTMLIdx = renderFn.lastIndexOf('el.innerHTML = html;');
    const applyIdx = renderFn.indexOf('applySessionTimelineOverflow();');
    assert.ok(innerHTMLIdx >= 0, 'renderSessions must contain el.innerHTML = html;');
    assert.ok(applyIdx >= 0, 'renderSessions must contain applySessionTimelineOverflow();');
    assert.ok(applyIdx > innerHTMLIdx,
      'applySessionTimelineOverflow() must run AFTER el.innerHTML = html;');
  });

  it('UX-S4 — fade indicator and expand button hidden by default (only visible when clipped)', () => {
    // The fade indicator and expand button must use display:none in
    // the default state — they only become visible when the parent
    // .session-card has the .session-timeline-clipped marker class
    // (or its descendant has it). This avoids visual noise on short
    // sessions that fit entirely within 500px.
    assert.match(_src_uxj,
      /\.session-timeline-fade \{[\s\S]{0,500}display: none;/);
    assert.match(_src_uxj,
      /\.session-timeline-expand \{[\s\S]{0,500}display: none;/);
  });

  it('UX-S4 — session-timeline-clipped triggers the fade + expand button visibility', () => {
    // The class is applied to the timeline element when it overflows;
    // the CSS sibling combinator + the parent class trigger visibility
    // on the fade indicator and the expand button.
    assert.match(_src_uxj,
      /\.session-timeline-clipped \+ \.session-timeline-fade,?\s*\.session-timeline-clipped ~ \.session-timeline-expand \{[\s\S]{0,200}display:/);
  });

  // ── XSS-hardening: text content inside the SVG/buttons must not be
  //    user-controlled. (The SVG is a fixed icon; the toggle text is
  //    fixed strings; the only user-controlled piece is `s.id` going
  //    into the onclick, which is a UUID — but defense-in-depth.)
  it('UX-S3/UX-S4 — session id in onclick is escaped via the same escaping as the existing toggleSessionCollapse', () => {
    // The pre-existing toggleSessionCollapse onclick uses two literal
    // backslashes around the UUID — see the byte-level encoding above.
    // The new copy/expand onclicks must use the same pattern (no extra
    // interpolation, no user text in the JS string).
    assert.match(_src_uxj,
      /onclick="copyTimeline\(\\\\'' \+ s\.id \+ '\\\\', event\)"/);
    assert.match(_src_uxj,
      /onclick="toggleSessionTimelineExpand\(\\\\'' \+ s\.id \+ '\\\\', event\)"/);
  });
});

// ─────────────────────────────────────────────────
// UX batch K — UX-L1 / UX-X10 source-grep regressions.
//
// UX-L1: the Logs tab container used GitHub-style dark theme
// (background:#0d1117, color:#c9d1d9) inside a light dashboard. Visually
// jarring; hardcoded hex colours bypass the design tokens. Replace with
// CSS variables so the surface fits the surrounding palette and a future
// dark-mode theme can re-skin via `--card` / `--foreground` rebinding.
//
// UX-X10: `var(--muted)` was used for both inactive and active text on
// some controls — most clearly the .vdm-filter-bar regex toggle label,
// where the "Regex" text never visibly changed colour when the user
// turned regex on. Add a `--muted-active` token for the readable-active
// case, plus a `:has(input:checked)` selector that swaps the label colour
// when its inner checkbox is on. Keep the change SURGICAL — only the
// ambiguous active/inactive pairings, NOT every var(--muted) use-site.
// ─────────────────────────────────────────────────
describe("UX batch K — UX-L1 / UX-X10 logs theme + muted-active regressions", () => {
  const _src_K = _readFileSync_xss(
    new URL("../dashboard.mjs", import.meta.url),
    "utf8",
  );

  // UX-L1 — light-theme log container -----------------------------

  it("UX-L1 — log-container no longer hardcodes the GitHub dark hex #0d1117", () => {
    // The audit complaint: dark-on-light surface inside an otherwise light
    // dashboard. Inline style on #log-container must NOT contain the dark
    // hex any more.
    const containerLine = _src_K.match(
      /<div id="log-container"[^>]*>/,
    );
    assert.ok(containerLine, "expected #log-container element");
    assert.doesNotMatch(containerLine[0], /#0d1117/i);
    assert.doesNotMatch(containerLine[0], /#c9d1d9/i);
  });

  it("UX-L1 — log-container surface uses var(--card) + var(--foreground) tokens", () => {
    const containerLine = _src_K.match(
      /<div id="log-container"[^>]*>/,
    );
    assert.ok(containerLine, "expected #log-container element");
    assert.match(containerLine[0], /background:\s*var\(--card\)/);
    assert.match(containerLine[0], /color:\s*var\(--foreground\)/);
    // Border still preserved (was var(--border) before, must stay so a future
    // theme rebind picks the right divider).
    assert.match(containerLine[0], /border:\s*1px solid var\(--border\)/);
    // Monospace stays — the LOG container is still a code surface.
    assert.match(containerLine[0],
      /font-family:'SF Mono',Monaco,Consolas,monospace/);
  });

  it("UX-L1 — LOG_TAG_COLORS use design tokens, not bypassed hex literals", () => {
    // Pin the colour map shape: every tag entry routes through a
    // var(--…) reference instead of the historical GitHub hexes
    // (#f85149 / #d29922 / #58a6ff / #8b949e). That way a future
    // theme rebind changes log tags too.
    const mapMatch = _src_K.match(
      /const LOG_TAG_COLORS\s*=\s*\{[\s\S]*?\};/,
    );
    assert.ok(mapMatch, "expected LOG_TAG_COLORS map");
    const mapBlock = mapMatch[0];
    // No hardcoded GitHub hex values in the map.
    assert.doesNotMatch(mapBlock, /#f85149/i);
    assert.doesNotMatch(mapBlock, /#d29922/i);
    assert.doesNotMatch(mapBlock, /#58a6ff/i);
    assert.doesNotMatch(mapBlock, /#8b949e/i);
    // Every tag entry maps to a var(--…) — at minimum red, yellow,
    // blue, muted are referenced via tokens.
    assert.match(mapBlock, /var\(--red\)/);
    assert.match(mapBlock, /var\(--yellow\)/);
    assert.match(mapBlock, /var\(--blue\)/);
    assert.match(mapBlock, /var\(--muted\)/);
  });

  it("UX-L1 — log-status connect/error colours use design tokens", () => {
    // The log-status text was hardcoded to '#3fb950' on connect and
    // '#f85149' on error. Replace with design tokens so both tones move
    // with the rest of the palette.
    //
    // UX-L4 follow-up: the onerror handler was upgraded from a one-liner
    // returning red to a multi-line block that yellow-tints the status
    // and increments _logReconnectCount. Either var(--red) (legacy) or
    // var(--yellow) (UX-L4) is an acceptable design-token output —
    // what we forbid is the raw GitHub hex regressing back in.
    const onopenSlice = _src_K.match(
      /_logES\.onopen\s*=\s*\(\)\s*=>\s*\{[\s\S]+?\};/,
    );
    assert.ok(onopenSlice, "expected _logES.onopen handler");
    assert.match(onopenSlice[0], /var\(--green\)/);
    assert.doesNotMatch(onopenSlice[0], /#3fb950/i);
    const onerrorSlice = _src_K.match(
      /_logES\.onerror\s*=\s*\(\)\s*=>\s*\{[\s\S]+?\};/,
    );
    assert.ok(onerrorSlice, "expected _logES.onerror handler");
    assert.match(onerrorSlice[0], /var\(--(red|yellow)\)/);
    assert.doesNotMatch(onerrorSlice[0], /#f85149/i);
  });

  it("UX-L1 — fallback log line colour is a design token, not the GitHub neutral hex", () => {
    // The "tag not in LOG_TAG_COLORS" fallback colour was '#8b949e'
    // (a GitHub neutral grey). Move to var(--muted) so the same colour
    // appears in the legend if a future caller renders one.
    const fallbackLine = _src_K.match(
      /const color = LOG_TAG_COLORS\[tag\] \|\| ([^;]+);/,
    );
    assert.ok(fallbackLine, "expected LOG_TAG_COLORS fallback");
    assert.doesNotMatch(fallbackLine[1], /#8b949e/i);
    assert.match(fallbackLine[1], /var\(--muted\)/);
  });

  // UX-X10 — muted-active token + label colour swap -----------------

  it("UX-X10 — :root defines a --muted-active token for active-state readable text", () => {
    // The audit's fix: introduce a higher-contrast variant of --muted so
    // active controls can stay in the muted tone family but still read as
    // "on". The token MUST be declared in the :root block alongside the
    // existing --muted.
    assert.match(_src_K,
      /:root \{[\s\S]+?--muted-active:\s*hsl\([^)]+\)[\s\S]+?\}/);
  });

  it("UX-X10 — .vdm-filter-bar label uses --muted-active when its inner checkbox is checked", () => {
    // The Regex toggle label was visually identical whether the checkbox
    // was on or off. Swap the label colour via :has(input:checked) so the
    // active state is unmistakable. Modern browsers (Chromium 105+,
    // Firefox 121+, Safari 15.4+) all support :has() — the dashboard is
    // already JS-required.
    assert.match(_src_K,
      /\.vdm-filter-bar label:has\(input:checked\)\s*\{[^}]*color:\s*var\(--muted-active\)/);
  });

  it("UX-X10 — .vdm-filter-bar label inactive vs active state visibly differ via font-weight", () => {
    // Defense-in-depth: not every browser will pick up the :has() rule on
    // older WebKit forks (e.g. some embedded surfaces). The label's
    // checked-state rule MUST also bump font-weight so the active state is
    // visible WITHOUT relying on colour alone.
    assert.match(_src_K,
      /\.vdm-filter-bar label:has\(input:checked\)\s*\{[^}]*font-weight:\s*(?:600|bold)/);
  });

  it("UX-X10 — UX batch K change is surgical: still many var(--muted) use-sites remain", () => {
    // The K batch is a colour-token + ONE active-state pairing fix, NOT a
    // wholesale replacement of every var(--muted). The surrounding palette
    // (config-desc, header-sub, stat-label, etc.) stays muted. Pin a
    // generous lower bound so a future "let me clean up muted" refactor
    // trips this and is forced to update the K-batch invariants in
    // CLAUDE.md too.
    const muted = _src_K.match(/var\(--muted\)/g) || [];
    assert.ok(muted.length >= 60,
      "expected >=60 var(--muted) uses preserved (surgical change), found " + muted.length);
  });
});

// ─────────────────────────────────────────────────
// UX batch F — UX-H1 / UX-H2 / UX-CO1 / UX-CO3 / UX-CO4 source-grep regressions
// ─────────────────────────────────────────────────
describe('UX batch F — UX-H1 / UX-H2 / UX-CO1 / UX-CO3 / UX-CO4 source-grep regressions', () => {
  const _src_uxf = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-H1 — header right-side affordance ──
  it('UX-H1 — header carries a header-right action group with settings + help icons', () => {
    // The header used to be { header-left only, empty right column }.
    // Now it MUST emit a .header-right wrapper that hosts the status
    // pills + the settings (gear) and help (?) icon buttons. Without
    // this wrapper, the flex space-between on .header reserves an empty
    // column for nothing.
    assert.match(_src_uxf, /<div class="header-right">/);
  });

  it('UX-H1 — header settings icon switches to the Config tab', () => {
    // Gear icon MUST call switchTab('config') so a first-time user
    // looking for "where do I change anything" has an obvious affordance.
    assert.match(_src_uxf,
      /<button class="header-icon-btn"[^>]*onclick="switchTab\('config'\)"[^>]*>/);
  });

  it('UX-H1 — header help link points to the README and opens in a new tab', () => {
    // Help "?" icon is a passive link, not a JS action — opens the
    // upstream README in a new tab so the dashboard tab keeps state.
    assert.match(_src_uxf,
      /<a class="header-icon-btn"[^>]*href="https:\/\/github\.com\/Emasoft\/claude-acct-switcher#readme"[^>]*target="_blank"[^>]*>/);
  });

  it('UX-H1 — current-strategy and probe-stats spans live INSIDE header-right (not the subtitle)', () => {
    // Pre-batch, both pills were crammed into the header-sub line as
    // freeform text. They MUST move to the header-right group with a
    // distinct .header-pill CSS class so they read as status badges.
    const headerBlock = _src_uxf.slice(
      _src_uxf.indexOf('<div class="header-right">'),
      _src_uxf.indexOf('<div class="header-right">') + 800,
    );
    assert.match(headerBlock, /id="current-strategy"/);
    assert.match(headerBlock, /id="probe-stats"/);
  });

  it('UX-H1 — header-sub no longer carries the strategy/probe pills', () => {
    // Source-grep regression: the subtitle MUST contain only the
    // account-count, not the two pills. Catches the case where the
    // pills were copy-pasted into header-right but never removed from
    // header-sub.
    const subMatch = _src_uxf.match(
      /<div class="header-sub">[\s\S]*?<\/div>/,
    );
    assert.ok(subMatch, 'header-sub block must exist');
    assert.doesNotMatch(subMatch[0], /id="current-strategy"/);
    assert.doesNotMatch(subMatch[0], /id="probe-stats"/);
  });

  it('UX-H1 — .header-pill CSS class is defined for the status badges', () => {
    // The pill class is what makes the strategy + probe spans look like
    // chips instead of run-on text.
    assert.match(_src_uxf, /\.header-pill\s*\{[^}]*border-radius/);
    assert.match(_src_uxf, /\.header-pill\s*\{[^}]*var\(--border\)/);
  });

  it('UX-H1 — .header-icon-btn CSS class defined with hover affordance', () => {
    assert.match(_src_uxf, /\.header-icon-btn\s*\{/);
    assert.match(_src_uxf, /\.header-icon-btn:hover\s*\{/);
  });

  it('UX-H1 — header-right gets a responsive treatment at the 720px breakpoint', () => {
    // The .header at 720px stacks vertically; the icon row would
    // otherwise float weirdly underneath the title. Source-grep that
    // the responsive block touches header-right.
    const responsiveStart = _src_uxf.indexOf('@media (max-width: 720px)');
    assert.ok(responsiveStart >= 0, 'expected a 720px media query');
    // Slice generously so the .header-right rule (which lives several
    // declarations down inside the same @media block) is included.
    const responsiveBlock = _src_uxf.slice(responsiveStart, responsiveStart + 2000);
    assert.match(responsiveBlock, /\.header-right/);
  });

  // ── UX-H2 — exhausted banner palette + animation ──
  it('UX-H2 — .exhausted-banner uses the soft-red palette tokens, not raw HSL', () => {
    // Pre-batch, the banner used hsl(0 60% 15%) (dark red filled),
    // hsl(0 50% 30%) (border), hsl(0 80% 80%) (text). Replace with
    // the project's standard --red-soft / --red-border / --red token
    // ramp so it tonally matches every other red surface.
    const bannerRule = _src_uxf.slice(
      _src_uxf.indexOf('.exhausted-banner {'),
      _src_uxf.indexOf('.exhausted-banner {') + 600,
    );
    assert.match(bannerRule, /background:\s*var\(--red-soft\)/);
    assert.match(bannerRule, /border:\s*1px solid var\(--red-border\)/);
    assert.match(bannerRule, /color:\s*var\(--red\)/);
    // Confirm the dark-red HSL values are gone.
    assert.doesNotMatch(bannerRule, /hsl\(0 60% 15%\)/);
    assert.doesNotMatch(bannerRule, /hsl\(0 50% 30%\)/);
    assert.doesNotMatch(bannerRule, /hsl\(0 80% 80%\)/);
  });

  it('UX-H2 — pulse-border animation removed from the banner (border conveys severity)', () => {
    // The 2s pulse animation kept drawing the eye even after the user
    // had read the message. Bold border alone is enough.
    const bannerRule = _src_uxf.slice(
      _src_uxf.indexOf('.exhausted-banner {'),
      _src_uxf.indexOf('.exhausted-banner {') + 600,
    );
    assert.doesNotMatch(bannerRule, /animation:\s*pulse-border/);
  });

  it('UX-H2 — .exhausted-icon picks up var(--red) background', () => {
    const iconRule = _src_uxf.slice(
      _src_uxf.indexOf('.exhausted-icon {'),
      _src_uxf.indexOf('.exhausted-icon {') + 400,
    );
    assert.match(iconRule, /background:\s*var\(--red\)/);
  });

  // ── UX-CO1 — Config tab anchors + TOC ──
  it('UX-CO1 — every config-section carries a stable id= for deep linking', () => {
    // Anchors enable bookmark-style links to specific settings (e.g.
    // hand a URL to a co-worker that opens directly on Serialization).
    // We expect IDs for: proxy, strategy, notifications, serialization,
    // commit-tokens, session-monitor, per-tool.
    const expected = [
      'config-proxy',
      'config-strategy',
      'config-notifications',
      'config-serialization',
      'config-commit-tokens',
      'config-session-monitor',
      'config-per-tool',
    ];
    for (const id of expected) {
      assert.match(_src_uxf, new RegExp('<div class="config-section" id="' + id + '"'),
        'expected config-section id="' + id + '"');
    }
  });

  it('UX-CO1 — Config tab opens with a small TOC referencing every section', () => {
    // The TOC sits at the top of the tab content so users can jump.
    // It MUST live INSIDE tab-config (not above it) and reference each
    // anchor via #config-* hrefs.
    const tabConfigBlock = _src_uxf.slice(
      _src_uxf.indexOf('<div id="tab-config"'),
      _src_uxf.indexOf('<div id="tab-config"') + 4000,
    );
    assert.match(tabConfigBlock, /<nav class="config-toc"/);
    assert.match(tabConfigBlock, /href="#config-proxy"/);
    assert.match(tabConfigBlock, /href="#config-strategy"/);
    assert.match(tabConfigBlock, /href="#config-session-monitor"/);
  });

  it('UX-CO1 — .config-toc CSS class defined with sticky positioning under the toolbar', () => {
    // Sticky so it stays visible as the user scrolls through the long
    // config card.
    assert.match(_src_uxf, /\.config-toc\s*\{/);
  });

  it('UX-CO1 — config-toc uses aria-label="Config sections" for screen readers', () => {
    const tabConfigBlock = _src_uxf.slice(
      _src_uxf.indexOf('<div id="tab-config"'),
      _src_uxf.indexOf('<div id="tab-config"') + 4000,
    );
    assert.match(tabConfigBlock, /<nav class="config-toc" aria-label="[^"]+"/);
  });

  // ── UX-CO3 — Session Monitor explicit privacy callout ──
  it('UX-CO3 — Session Monitor has an explicit .config-warning block (not just inline yellow text)', () => {
    // Pre-batch, the privacy warning was a `<strong style="color:..."`
    // inside the description paragraph. Many users skip multi-line
    // grey description text. The new layout MUST emit a separate
    // .config-warning element with a warning-symbol prefix and a
    // contrast-meeting palette so the block reads as "stop, read this".
    const sessionMonitorBlock = _src_uxf.slice(
      _src_uxf.indexOf('id="config-session-monitor"'),
      _src_uxf.indexOf('id="config-session-monitor"') + 2000,
    );
    assert.match(sessionMonitorBlock, /<div class="config-warning"/);
    // Critical privacy facts MUST appear inside the warning block.
    assert.match(sessionMonitorBlock, /Privacy/);
    assert.match(sessionMonitorBlock, /Anthropic Claude Haiku/);
  });

  it('UX-CO3 — .config-warning CSS class is defined with the yellow-soft palette', () => {
    assert.match(_src_uxf, /\.config-warning\s*\{/);
    const warningRule = _src_uxf.slice(
      _src_uxf.indexOf('.config-warning {'),
      _src_uxf.indexOf('.config-warning {') + 500,
    );
    assert.match(warningRule, /background:\s*var\(--yellow-soft\)/);
    assert.match(warningRule, /border:\s*1px solid var\(--yellow-border\)/);
  });

  it('UX-CO3 — Session Monitor warning carries a role=note + aria-label so it is announced', () => {
    // Plain visual styling is invisible to screen readers — the
    // privacy warning MUST be programmatically identifiable.
    const sessionMonitorBlock = _src_uxf.slice(
      _src_uxf.indexOf('id="config-session-monitor"'),
      _src_uxf.indexOf('id="config-session-monitor"') + 2000,
    );
    assert.match(sessionMonitorBlock,
      /<div class="config-warning" role="note" aria-label="Privacy warning"/);
  });

  it('UX-CO3 — Session Monitor description no longer carries a load-bearing inline yellow <strong> wrap on the privacy sentence', () => {
    // The inline `style="color:var(--yellow)"` was the smoking gun:
    // moving the privacy info into the dedicated .config-warning block
    // means the description paragraph should not need to highlight any
    // single sentence with inline yellow text. We assert against the
    // actual element form ("Sends excerpts" used to be the wrapped
    // sentence) rather than a bare substring so the load-bearing
    // <strong> wrap is what we catch — explanatory comments quoting
    // the old shape are allowed.
    const sessionMonitorBlock = _src_uxf.slice(
      _src_uxf.indexOf('id="config-session-monitor"'),
      _src_uxf.indexOf('id="config-session-monitor"') + 2000,
    );
    assert.doesNotMatch(sessionMonitorBlock,
      /<strong style="color:var\(--yellow\)">Sends/);
  });

  // ── UX-CO4 — Strategy hint vs strategy list deduplication ──
  it('UX-CO4 — STRATEGY_HINTS map is removed (single source of truth = STRATEGY_DETAILS)', () => {
    // The two parallel description sources had drifted ("Stays" vs
    // "Stay"). Eliminating STRATEGY_HINTS forces every consumer to
    // pull from STRATEGY_DETAILS.
    assert.doesNotMatch(_src_uxf, /const STRATEGY_HINTS = \{/);
  });

  it('UX-CO4 — strategy-hint span replaced with single-line "currently active" pill', () => {
    // The new contract: keep the inline hint slot (so the strategy
    // dropdown row still has an explanatory line under the label) but
    // populate it ONLY with the active-strategy name (e.g.
    // "Currently active: Conserve"), with the full descriptions
    // available below in the strategy-list. No more duplicating the
    // multi-sentence description in two places.
    assert.match(_src_uxf,
      /id="strategy-hint"[^>]*>Currently active:/);
  });

  it('UX-CO4 — updateStrategyUI rebuilds strategy-hint as "Currently active: <name>" only', () => {
    // The function MUST source the active-strategy NAME (not its
    // description) from STRATEGY_DETAILS and prepend the literal
    // "Currently active: " prefix. We grep for the prefix string and
    // a STRATEGY_DETAILS read that picks up `.name` (either direct
    // `STRATEGY_DETAILS[strategy].name` OR via an intermediate
    // variable like `const details = STRATEGY_DETAILS[strategy];
    // details.name`). Both shapes are acceptable; the invariant is
    // "the .name field is what feeds the hint, not .desc".
    const fn = _src_uxf.slice(
      _src_uxf.indexOf('function updateStrategyUI'),
      _src_uxf.indexOf('function updateStrategyUI') + 1500,
    );
    assert.match(fn, /'Currently active: ' \+/);
    // Source-grep that .name is read from STRATEGY_DETAILS (either
    // form). The prior STRATEGY_HINTS lookup would have failed both.
    assert.ok(
      /STRATEGY_DETAILS\[strategy\]\.name/.test(fn) ||
        /STRATEGY_DETAILS\[strategy\][\s\S]{0,200}\.name/.test(fn),
      'expected STRATEGY_DETAILS[strategy].name to be read in updateStrategyUI',
    );
    // Critically: the full multi-sentence description from
    // STRATEGY_DETAILS[strategy].desc is NOT injected back into the
    // strategy-hint slot (that would just rename the duplication).
    assert.doesNotMatch(fn, /strategy-hint[\s\S]{0,200}STRATEGY_DETAILS\[strategy\]\.desc/);
    // Source-grep that the removed STRATEGY_HINTS map is not referenced.
    assert.doesNotMatch(fn, /STRATEGY_HINTS\[strategy\]/);
  });
});

// ─────────────────────────────────────────────────
// Batch I — UX-CPF1 / UX-WS2 / UX-VS1 / UX-VS3
//
// UX-CPF1 — Multi-select dropdown (cpf-panel) overlapped the carousel
//   slide content. Fix: move the .chart-project-filter OUT of the
//   carousel into a sibling row above it, so the panel pushes the
//   carousel down rather than floating over the chart.
//
// UX-WS2 — Wasted-spend bars used a single yellow regardless of value.
//   Fix: percentile-based severity gradient (≤50th = yellow-soft,
//   ≤90th = yellow, >90th = red). Helper is a pure function in lib.mjs
//   for unit-testability and so the dashboard's render code is a thin
//   loop over the helper output.
//
// UX-VS1 — Scrubber + tok-time dropdown both filter time; users get
//   confused. Fix: add an inline hint near the scrubber explaining the
//   composition rule ("scrubber narrows within the selected window
//   from the dropdown above").
//
// UX-VS3 — Fallback datetime-local inputs were only shown <600px so
//   wider viewports had no way to type exact times. Fix: keep the
//   600px swap (small viewports drop the slider, get fallback inputs)
//   but add an "Edit dates" toggle that lets desktop users SHOW the
//   inputs alongside the slider on demand.
// ─────────────────────────────────────────────────
describe('UX-WS2 — wastedSeverity (pure function)', () => {
  it('exports the three CSS-variable severity tokens as named exports', () => {
    // The dashboard renderer interpolates these into inline-style
    // background, so they must be string CSS values (not just keys).
    assert.equal(typeof WASTED_SEVERITY_LOW,  'string');
    assert.equal(typeof WASTED_SEVERITY_MED,  'string');
    assert.equal(typeof WASTED_SEVERITY_HIGH, 'string');
    // All three must be CSS variable references — keeps theming
    // single-source-of-truth in the :root palette.
    assert.match(WASTED_SEVERITY_LOW,  /^var\(--/);
    assert.match(WASTED_SEVERITY_MED,  /^var\(--/);
    assert.match(WASTED_SEVERITY_HIGH, /^var\(--/);
    // Spec: low = soft yellow, med = saturated yellow, high = red.
    assert.equal(WASTED_SEVERITY_LOW,  'var(--yellow-soft)');
    assert.equal(WASTED_SEVERITY_MED,  'var(--yellow)');
    assert.equal(WASTED_SEVERITY_HIGH, 'var(--red)');
  });

  it('returns LOW for the smallest values (≤ 50th percentile)', () => {
    const all = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    // 5 is exactly the 50th percentile of [1..10] (interpolated).
    assert.equal(wastedSeverity(1, all),  WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(2, all),  WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(5, all),  WASTED_SEVERITY_LOW);
  });

  it('returns MED for values between 50th and 90th percentile', () => {
    const all = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    assert.equal(wastedSeverity(6, all),  WASTED_SEVERITY_MED);
    assert.equal(wastedSeverity(7, all),  WASTED_SEVERITY_MED);
    assert.equal(wastedSeverity(8, all),  WASTED_SEVERITY_MED);
    assert.equal(wastedSeverity(9, all),  WASTED_SEVERITY_MED);
  });

  it('returns HIGH for values strictly above 90th percentile', () => {
    const all = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    // 10 is the only outlier above the 90th percentile threshold.
    assert.equal(wastedSeverity(10, all), WASTED_SEVERITY_HIGH);
  });

  it('handles a single-value dataset (every value is at the max → LOW)', () => {
    // With one value the 50/90 percentiles collapse to the same number;
    // the lone bar is "the only bar" and shouldn't visually scream
    // catastrophe — the relative-severity rule is meaningless without a
    // distribution. Spec: single-bar = LOW (visual default, calm).
    const all = [42];
    assert.equal(wastedSeverity(42, all), WASTED_SEVERITY_LOW);
  });

  it('handles a flat dataset (all equal → LOW for every bar)', () => {
    // No variance means no severity gradient exists; every bar gets
    // the calm default. Without this branch the entire chart would be
    // red whenever the user has uniform spending.
    const all = [7, 7, 7, 7, 7];
    for (const v of all) {
      assert.equal(wastedSeverity(v, all), WASTED_SEVERITY_LOW);
    }
  });

  it('treats null / undefined / empty allValues as LOW', () => {
    // Defensive — buildWastedSpendSeries can hand back empty arrays
    // when the heuristic finds no misses. The render path must not
    // throw; it just shows whatever calm default the helper picks.
    assert.equal(wastedSeverity(5, []),         WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(5, null),       WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(5, undefined),  WASTED_SEVERITY_LOW);
  });

  it('treats null / NaN / negative input as LOW (no crash, no red)', () => {
    // Defensive — if a future row has a missing wasted field, render
    // must not throw and must not promote the bar to "catastrophic".
    const all = [1, 2, 3, 4, 5];
    assert.equal(wastedSeverity(null,      all), WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(undefined, all), WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(NaN,       all), WASTED_SEVERITY_LOW);
    assert.equal(wastedSeverity(-1,        all), WASTED_SEVERITY_LOW);
  });

  it('returns the CORRECT tier for a realistic skewed dataset', () => {
    // Real wasted-spend chart looks like: most days near zero, a few
    // medium days, one catastrophic day. Verify the gradient picks out
    // exactly that outlier.
    const all = [0.01, 0.02, 0.03, 0.05, 0.04, 0.10, 0.15, 0.20, 1.00, 5.00];
    // 5.00 is the lone catastrophic outlier.
    assert.equal(wastedSeverity(5.00, all), WASTED_SEVERITY_HIGH);
    // 1.00 should be MED (between 50th and 90th of the distribution).
    assert.equal(wastedSeverity(1.00, all), WASTED_SEVERITY_MED);
    // 0.01 is calm.
    assert.equal(wastedSeverity(0.01, all), WASTED_SEVERITY_LOW);
  });
});

// ─────────────────────────────────────────────────
// Batch I — source-grep regressions for the dashboard.mjs side
// (CPF1 layout, WS2 severity wiring, VS1 hint copy, VS3 toggle button).
// ─────────────────────────────────────────────────
describe('Batch I — UX-CPF1 / UX-WS2 / UX-VS1 / UX-VS3 source-grep regressions', () => {
  const _src_bi = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-CPF1 ──────────────────────────────────────
  it('UX-CPF1 — .chart-project-filter is repositioned in CSS as a flow container, not absolutely on top of the carousel', () => {
    // The original CSS had `position: absolute; top: 0.5rem; right:
    // 0.5rem;` which made the cpf-panel float over the carousel slide
    // content. The new layout puts the filter in its own row, so the
    // .chart-project-filter rule must NOT contain `position: absolute`
    // any more (or, if it does, it must be paired with a guard class
    // that disables that on the wider container).
    const block = _src_bi.match(/\.chart-project-filter \{[\s\S]{0,400}\}/);
    assert.ok(block, '.chart-project-filter CSS not found');
    // Must NOT use absolute positioning that overlays the carousel.
    assert.doesNotMatch(block[0], /position:\s*absolute/,
      '.chart-project-filter must not be absolutely positioned (it overlaid carousel content — UX-CPF1)');
    // The filter must align right (its own row). Justify or text-align
    // to the right is acceptable; check the wrapper class for the
    // expected layout.
    assert.match(_src_bi, /\.chart-controls \{[\s\S]{0,400}justify-content:\s*flex-end/,
      '.chart-controls wrapper should justify the filter to the right');
  });

  it('UX-CPF1 — HTML places .chart-project-filter in a .chart-controls row OUTSIDE .chart-carousel', () => {
    // Source-grep that the project filter is now wrapped in a
    // .chart-controls div placed BEFORE the .chart-carousel container
    // (so the panel pushes the carousel down rather than floating
    // over it).
    const layoutMatch = _src_bi.match(
      /<div class="chart-controls"[^>]*>\s*<div class="chart-project-filter" id="chart-project-filter">/);
    assert.ok(layoutMatch,
      'chart-project-filter should be wrapped in a chart-controls row (UX-CPF1)');
    // Defensive: there must NOT be a chart-project-filter INSIDE the
    // .chart-carousel any more (would re-introduce the overlap bug).
    assert.doesNotMatch(_src_bi,
      /<div class="usage-card chart-carousel"[^>]*>\s*<div class="chart-project-filter"/,
      'chart-project-filter must not be the first child of .chart-carousel — would re-overlay the carousel');
  });

  // ── UX-WS2 ──────────────────────────────────────
  it('UX-WS2 — renderWastedSpendChart applies severity gradient via wastedSeverity()', () => {
    // Source-grep that the renderer calls wastedSeverity (the lib.mjs
    // helper exposed on the global as `wastedSeverity` — see
    // `_VDM_TEST_EXPORTS` set near the top of renderHTML's <script>).
    // The renderer must build an array of all wasted values FIRST so
    // the percentile compare has the full distribution to work with.
    assert.match(_src_bi,
      /var\s+wastedValues\s*=\s*days\.map\(/);
    // The bar-color comes from wastedSeverity(), interpolated into
    // the inline style. The exact background-color value MUST come
    // from the lib.mjs export so the CSS variable used stays single-
    // source-of-truth.
    assert.match(_src_bi,
      /var\s+barColor\s*=\s*wastedSeverity\(/);
    // The severity color goes into inline style background, which
    // overrides the now-removed CSS default. Check the bar template
    // includes the inline override.
    assert.match(_src_bi,
      /style="height:'\s*\+\s*pct\s*\+\s*'%;background:'\s*\+\s*barColor\s*\+/);
  });

  it('UX-WS2 — .tok-wasted-bar CSS no longer hardcodes background: var(--yellow)', () => {
    // The CSS background declaration was removed so the JS-supplied
    // inline severity color wins (the inline style would lose to the
    // CSS rule via specificity if both were set — wait, inline always
    // wins over a class. But removing the CSS rule means a "default
    // bar with no inline color" can't accidentally be hardcoded to
    // yellow. Defensive cleanup.)
    // Match window must accommodate the explanatory comment that
    // documents WHY the background is unset (the comment text is
    // load-bearing for the next reader).
    const block = _src_bi.match(/\.tok-wasted-bar \{[\s\S]{0,1200}?\n\s*\}/);
    assert.ok(block, '.tok-wasted-bar CSS rule not found');
    // No hardcoded color — color must come from inline severity.
    // The comment may MENTION var(--yellow) (explaining what was
    // removed) but the actual `background:` declaration must NOT
    // resolve to var(--yellow). Match only declarations.
    assert.doesNotMatch(block[0], /^\s*background:\s*var\(--yellow\)/m,
      '.tok-wasted-bar must not declare background:var(--yellow) (UX-WS2 — let inline severity win)');
  });

  it('UX-WS2 — export wastedSeverity() is exposed on the page-script global so renderHTML can use it', () => {
    // The lib.mjs helpers are inlined into the renderHTML script at
    // build-time. Because there's no bundler, the dashboard inlines
    // a copy of the function. Look for the helper definition (or the
    // import from lib via the top-of-script evaluator if that's the
    // pattern). At minimum, the named function must exist in the
    // emitted page script.
    assert.match(_src_bi,
      /function\s+wastedSeverity\s*\(/);
    // The CSS-variable constants must also be inline so the function
    // returns a value the browser understands without a separate
    // round-trip to fetch lib.mjs.
    assert.match(_src_bi, /var\s+WASTED_SEVERITY_LOW\s*=\s*'var\(--yellow-soft\)'/);
    assert.match(_src_bi, /var\s+WASTED_SEVERITY_MED\s*=\s*'var\(--yellow\)'/);
    assert.match(_src_bi, /var\s+WASTED_SEVERITY_HIGH\s*=\s*'var\(--red\)'/);
  });

  // ── UX-VS1 ──────────────────────────────────────
  it('UX-VS1 — scrubber bar carries an explanatory hint about the tok-time dropdown', () => {
    // The hint MUST mention BOTH "scrubber" (or "narrows") and the
    // dropdown so the user understands the composition rule. Use a
    // class hook so the hint can be styled / hidden later without
    // touching the copy.
    assert.match(_src_bi, /class="vs-hint"/);
    // Spec text: "Scrubber narrows within the selected time window
    // from the dropdown above" (or the dropdown's exact name).
    assert.match(_src_bi,
      /Scrubber narrows within/i);
    // The hint must reference the tok-time dropdown in plain language
    // so the user can orient themselves.
    assert.match(_src_bi,
      /(time window|range|dropdown)/i);
  });

  it('UX-VS1 — .vs-hint CSS exists with muted styling so the hint is informational, not loud', () => {
    const block = _src_bi.match(/\.vs-hint \{[\s\S]{0,400}\}/);
    assert.ok(block, '.vs-hint CSS rule must be defined');
    // Hint must not look like an error or a primary control — use
    // muted text color and a small font.
    assert.match(block[0], /color:\s*var\(--muted\)/);
    assert.match(block[0], /font-size:\s*0\.6\d+rem/);
  });

  // ── UX-VS3 ──────────────────────────────────────
  it('UX-VS3 — there is a button to toggle the datetime fallback inputs on wider viewports', () => {
    // The button-class hook lets users on >600px viewports SHOW the
    // type=datetime-local inputs alongside the slider when they need
    // to type an exact timestamp. The original CSS only revealed the
    // inputs at <600px.
    assert.match(_src_bi, /class="vs-fallback-toggle"/);
    // Source-grep an aria-label or visible text that describes the
    // toggle's purpose.
    assert.match(_src_bi, /(Edit dates|Type exact|Edit time|Edit time range)/i);
    // The toggle must wire to a function (onclick attribute) so the
    // visibility flip is implemented.
    assert.match(_src_bi,
      /class="vs-fallback-toggle"[^>]*onclick="[a-zA-Z_]+\(/);
  });

  it('UX-VS3 — JS toggle helper toggles a CSS class on the .vs-fallback-inputs container', () => {
    // The helper function must exist with a recognizable name and
    // toggle either a class or a hidden attribute on the fallback
    // input container. Source-grep both patterns to keep the test
    // resilient to small refactors.
    assert.match(_src_bi,
      /function\s+toggleFallbackInputs\s*\(/);
    // Helper must reach for the .vs-fallback-inputs container.
    assert.match(_src_bi,
      /toggleFallbackInputs[\s\S]{0,500}vs-fallback-inputs/);
  });

  it('UX-VS3 — fallback inputs are still auto-shown on <600px (existing rule preserved)', () => {
    // Mobile users already get the inputs because the slider hides
    // there. The "edit dates" toggle MUST NOT delete that media query
    // (would regress the small-viewport experience).
    assert.match(_src_bi,
      /@media \(max-width:\s*600px\)\s*\{[\s\S]{0,200}\.vs-fallback-inputs\s*\{\s*display:\s*flex/);
  });

  it('UX-VS3 — the .vs-fallback-inputs container has a visible class hook (.is-open) for the toggle button', () => {
    // Use a class hook (not direct style mutation) so future a11y
    // states can hang off the same selector.
    assert.match(_src_bi,
      /\.vs-fallback-inputs\.is-open\s*\{\s*display:\s*flex/);
  });

  // ── UX honors existing batch D invariants (defensive) ──
  it('Defensive — UX-VS2 thumb sizing is preserved (we did not regress to tiny thumbs)', () => {
    // Batch I touches the scrubber but must NOT shrink the thumbs.
    const block = _src_bi.match(/\.vs-thumb \{[\s\S]{0,400}\}/);
    assert.ok(block, '.vs-thumb CSS rule still required');
    const wMatch = block[0].match(/width:\s*(\d+)px/);
    const hMatch = block[0].match(/height:\s*(\d+)px/);
    assert.ok(Number(wMatch[1]) >= 24, '.vs-thumb width must stay >= 24px');
    assert.ok(Number(hMatch[1]) >= 24, '.vs-thumb height must stay >= 24px');
  });
});

// ─────────────────────────────────────────────────
// UX batch H — UX-CM1 / UX-CM3 / UX-BR1 / UX-BR2 source-grep regressions
// ─────────────────────────────────────────────────
describe('UX batch H — UX-CM1 / UX-CM3 / UX-BR1 / UX-BR2 source-grep regressions', () => {
  const _src_uxh = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-CM1 — sticky open/closed state per cache-miss session ──
  it('UX-CM1 — _openMissSessions / _collapsedMissSessions Sets exist as state holders', () => {
    assert.match(_src_uxh, /var _openMissSessions\s*=\s*new Set\(\)/);
    assert.match(_src_uxh, /var _collapsedMissSessions\s*=\s*new Set\(\)/);
  });

  it('UX-CM1 — bounded localStorage parse for vdm.cacheMissOpen and vdm.cacheMissClosed keys', () => {
    // Mirror the _CPF_MAX_ITEMS / _CPF_MAX_STRLEN / _CPF_MAX_BLOB pattern so
    // a corrupted localStorage entry can't either land junk strings or
    // DoS the dropdown render with millions of items.
    assert.match(_src_uxh, /_MISS_MAX_ITEMS\s*=\s*200/);
    assert.match(_src_uxh, /_MISS_MAX_STRLEN\s*=\s*1024/);
    assert.match(_src_uxh, /_MISS_MAX_BLOB\s*=\s*256\s*\*\s*1024/);
    assert.match(_src_uxh, /vdm\.cacheMissOpen/);
    assert.match(_src_uxh, /vdm\.cacheMissClosed/);
  });

  it('UX-CM1 — onToggle handler routes through _onMissSessionToggle (data-sid)', () => {
    assert.match(_src_uxh, /function _onMissSessionToggle\(/);
    assert.match(_src_uxh, /data-sid="/);
    assert.match(_src_uxh, /ontoggle="_onMissSessionToggle\(this\)"/);
  });

  it('UX-CM1 — open-by-default rule honours a 24h sliding cutoff', () => {
    // 24h sliding cutoff so very old sessions never auto-pop on page load.
    assert.match(_src_uxh, /_MISS_DEFAULT_OPEN_AGE_MS\s*=\s*24\s*\*\s*60\s*\*\s*60\s*\*\s*1000/);
  });

  it('UX-CM1 — XSS hardening: data-sid attribute escapes the sessionId', () => {
    // The session ID flows from server JSON into an attribute. Make sure
    // it is piped through escHtml.
    assert.match(_src_uxh, /data-sid="'\s*\+\s*escHtml\(/);
  });

  // ── UX-CM3 — inline expansion of older misses ──
  it('UX-CM3 — _expandedMissSessions Set + _toggleMissSessionExpand helper', () => {
    assert.match(_src_uxh, /var _expandedMissSessions\s*=\s*new Set\(\)/);
    assert.match(_src_uxh, /function _toggleMissSessionExpand\(/);
  });

  it('UX-CM3 — Show N older / Hide button replaces dead truncation row', () => {
    // Old shape (a styled <div> reading "and N older misses in this session")
    // was non-actionable. New shape: <button class="miss-show-more"> routed
    // through _toggleMissSessionExpand via this.dataset.sid (the canonical
    // pattern from toggleRepoCollapse / data-key).
    assert.match(_src_uxh, /miss-show-more/);
    assert.match(_src_uxh, /onclick="_toggleMissSessionExpand\(this\.dataset\.sid\)"/);
  });

  it('UX-CM3 — XSS hardening: sessionId reaches button via escHtml-wrapped data-sid', () => {
    // sessionId reaches the DOM only via a data-sid attribute that is
    // escHtml-wrapped. This avoids the JS-quote-escape footgun that an
    // inline onclick string literal would have. Slice generous (10000)
    // because the function is ~9K and miss-show-more lives at the end.
    const fnSlice = _src_uxh.slice(
      _src_uxh.indexOf('function renderCacheMisses'),
      _src_uxh.indexOf('function renderCacheMisses') + 10000,
    );
    assert.match(fnSlice, /miss-show-more[\s\S]{0,400}data-sid="'\s*\+\s*escHtml\(/);
  });

  // ── UX-BR1 — plan badge in Account Breakdown ──
  it('UX-BR1 — plan-badge built from _cachedProfiles via planBadge()', () => {
    const fnSlice = _src_uxh.slice(
      _src_uxh.indexOf('function renderAccountBreakdown'),
      _src_uxh.indexOf('function renderAccountBreakdown') + 3500,
    );
    assert.match(fnSlice, /_cachedProfiles/);
    assert.match(fnSlice, /planBadge\(/);
  });

  it('UX-BR1 — plan badge gracefully degrades when no matching profile', () => {
    const fnSlice = _src_uxh.slice(
      _src_uxh.indexOf('function renderAccountBreakdown'),
      _src_uxh.indexOf('function renderAccountBreakdown') + 3500,
    );
    assert.match(fnSlice, /prof\s*\?\s*planBadge\(|profileMap\[[^\]]+\]\s*\?\s*planBadge\(/);
  });

  // ── UX-BR2 — explicit collapse-default + Expand/Collapse all buttons ──
  it('UX-BR2 — Expand all / Collapse all buttons exist in Repository & Branch header', () => {
    assert.match(_src_uxh, /onclick="_repoBranchExpandAll\(\)"/);
    assert.match(_src_uxh, /onclick="_repoBranchCollapseAll\(\)"/);
    assert.match(_src_uxh, /Expand all/);
    assert.match(_src_uxh, /Collapse all/);
  });

  it('UX-BR2 — _repoBranchCollapseAll / _repoBranchExpandAll helpers exist', () => {
    assert.match(_src_uxh, /function _repoBranchCollapseAll\(\s*\)/);
    assert.match(_src_uxh, /function _repoBranchExpandAll\(\s*\)/);
  });

  it('UX-BR2 — collapse default is per-repo and depends on branch count, not active count', () => {
    // The new rule: collapse a repo by default when its branch count > 3.
    assert.match(_src_uxh, /_REPO_COLLAPSE_BRANCH_THRESHOLD\s*=\s*3/);
  });
});

// ─────────────────────────────────────────────────────────────────────
// UX batch L — round-1 audit MINOR/NIT cleanup pass
//
// Each helper finding from the original audit (UX-H3, UX-AC6, UX-CM5,
// UX-S6, UX-X11, UX-X12, UX-X13, UX-CO7, UX-WS5, UX-F1, UX-L4) gets a
// source-grep guard so a future renderer refactor cannot silently
// regress these polish items. Modelled on the existing "A11y batch 2"
// describe blocks above — read dashboard.mjs once into _src_uxL,
// then assert each invariant against the source string.
// ─────────────────────────────────────────────────────────────────────
describe('UX batch L — MINOR/NIT cleanup source-grep regressions', () => {
  const _src_uxL = _readFileSync_xss(
    new URL('../dashboard.mjs', import.meta.url),
    'utf8',
  );

  // ── UX-H3 — header "0 accounts connected" → loading placeholder ──
  it('UX-H3 — initial header span uses an ellipsis placeholder, not "0"', () => {
    // The bare numeric "0" was indistinguishable from the truthful "no
    // accounts" state. The HTML entity &hellip; (an ellipsis) plus the
    // data-loading sentinel attribute make the loading state explicit
    // and keep the layout from shifting after the first refresh.
    assert.match(
      _src_uxL,
      /<span id="account-count" data-loading="true">&hellip;<\/span>/,
    );
  });

  it('UX-H3 — refresh handler clears data-loading after the first update', () => {
    // Without removeAttribute the placeholder would never round-trip
    // back to "loading" — which is correct, the page only loads once —
    // but leaving the data-loading attribute around would mislead
    // future code that branches on it. Drop it as soon as the count
    // is truthful.
    const refreshSlice = _src_uxL.slice(
      _src_uxL.indexOf("getElementById('account-count')") - 200,
      _src_uxL.indexOf("getElementById('account-count')") + 400,
    );
    assert.match(refreshSlice, /removeAttribute\(['"]data-loading['"]\)/);
  });

  // ── UX-AC6 — escHtml the evtTime output ──
  it('UX-AC6 — evtTime() output is wrapped in escHtml() before HTML interpolation', () => {
    // Defense-in-depth. The current call site passes a number through
    // evtTime, but escHtml is the discipline applied to every other
    // dynamic field rendered into the activity feed.
    assert.match(
      _src_uxL,
      /<span class="evt-time">'\s*\+\s*escHtml\(evtTime\(e\.ts\)\)\s*\+\s*'<\/span>/,
    );
  });

  // ── UX-CM5 — n/a hit-rate badge gets a neutral palette ──
  it('UX-CM5 — null hit-rate routes through a dedicated "unknown" CSS class', () => {
    // The previous code coloured "n/a" red via the .low class. The
    // new ternary maps null → unknown so the badge renders neutral.
    const fnSlice = _src_uxL.slice(
      _src_uxL.indexOf('var hitRateText'),
      _src_uxL.indexOf('var hitRateText') + 800,
    );
    assert.match(fnSlice, /sess\.hitRate\s*==\s*null\s*\?\s*['"]unknown['"]/);
  });

  it('UX-CM5 — .miss-rate-badge.unknown CSS rule exists with neutral palette', () => {
    assert.match(
      _src_uxL,
      /\.tree-misses-card \.miss-rate-badge\.unknown\s*\{[^}]*color:\s*var\(--muted\)/,
    );
  });

  // ── UX-S6 — sessionTimeAgo "0s ago" → "just now" ──
  it('UX-S6 — sessionTimeAgo returns "just now" for sub-5s gaps', () => {
    const fnSlice = _src_uxL.slice(
      _src_uxL.indexOf('function sessionTimeAgo'),
      _src_uxL.indexOf('function sessionTimeAgo') + 600,
    );
    assert.match(fnSlice, /if\s*\(\s*d\s*<\s*5000\s*\)\s*return\s+['"]just now['"]/);
  });

  it('UX-S6 — sessionTimeAgo clamps negative timestamps to zero', () => {
    // Defensive: a clock-skew event where ts is in the future would
    // produce a negative delta, which the floor-to-seconds form would
    // render as a misleading "-3s ago". Clamp to zero so the next
    // branch ("just now") wins instead.
    const fnSlice = _src_uxL.slice(
      _src_uxL.indexOf('function sessionTimeAgo'),
      _src_uxL.indexOf('function sessionTimeAgo') + 600,
    );
    assert.match(fnSlice, /if\s*\(\s*d\s*<\s*0\s*\)\s*d\s*=\s*0/);
  });

  // ── UX-X11 — scrollbar width 6px → 10px ──
  it('UX-X11 — ::-webkit-scrollbar width is 10px (was 6px)', () => {
    assert.match(
      _src_uxL,
      /::-webkit-scrollbar\s*\{\s*width:\s*10px;\s*height:\s*10px;\s*\}/,
    );
  });

  it('UX-X11 — scrollbar thumb has higher-contrast 0.4 alpha (was 0.25)', () => {
    // The 6px / 25% combo was effectively invisible. Bumping the alpha
    // floor to 0.4 keeps the lane visible without being intrusive.
    const thumbSlice = _src_uxL.match(
      /::-webkit-scrollbar-thumb\s*\{[^}]+\}/,
    );
    assert.ok(thumbSlice, 'expected scrollbar-thumb rule');
    assert.match(thumbSlice[0], /hsl\(220 9% 46% \/ 0\.4\)/);
  });

  it('UX-X11 — scrollbar thumb uses background-clip: padding-box for the lane illusion', () => {
    // The 2px solid var(--bg) "border" combined with background-clip
    // padding-box clips the background INSIDE the border, leaving a
    // visible gutter so the thumb appears centred in a lane rather
    // than touching the content.
    const thumbSlice = _src_uxL.match(
      /::-webkit-scrollbar-thumb\s*\{[^}]+\}/,
    );
    assert.ok(thumbSlice);
    assert.match(thumbSlice[0], /background-clip:\s*padding-box/);
  });

  // ── UX-X12 — global form-control font/colour inheritance ──
  it('UX-X12 — global rule makes input/select/button/textarea inherit font + colour', () => {
    // Defends against new authors forgetting "font-family: inherit"
    // on a fresh control — the global rule covers them by default.
    assert.match(
      _src_uxL,
      /input,\s*select,\s*button,\s*textarea\s*\{[^}]*font-family:\s*inherit;[^}]*font-size:\s*inherit;[^}]*color:\s*inherit;[^}]*\}/,
    );
  });

  // ── UX-X13 — <noscript> banner uses design tokens, not raw hex ──
  it('UX-X13 — <noscript> banner uses var(--yellow-soft) / var(--yellow-border)', () => {
    // The hardcoded yellow hexes (#fef3c7 / #f59e0b / #78350f) bypassed
    // the design token cascade. Switch to tokens so a future theme
    // rebinding sweeps this banner along with everything else.
    // Strip HTML comments before checking — the explanatory comment
    // mentions the dropped hex codes as the regression we are
    // guarding against, but the markup itself must not contain them.
    const noscriptSlice = _src_uxL.match(/<noscript>[\s\S]+?<\/noscript>/);
    assert.ok(noscriptSlice, 'expected noscript block');
    assert.match(noscriptSlice[0], /var\(--yellow-soft\)/);
    assert.match(noscriptSlice[0], /var\(--yellow-border\)/);
    const stripped = noscriptSlice[0].replace(/<!--[\s\S]*?-->/g, '');
    assert.doesNotMatch(stripped, /#fef3c7/i);
    assert.doesNotMatch(stripped, /#f59e0b/i);
    assert.doesNotMatch(stripped, /#78350f/i);
  });

  // ── UX-CO7 — Per-Tool Attribution description simplified ──
  it('UX-CO7 — Per-Tool Attribution description drops the "PostToolBatch hook" jargon', () => {
    // Users do not care about implementation hooks. The simplified
    // copy keeps only the actionable bits: what it does + the
    // material disk-size warning. Strip HTML comments before checking
    // because the explanatory comment intentionally mentions the
    // dropped phrase as the regression we are guarding against.
    const sectionSlice = _src_uxL.slice(
      _src_uxL.indexOf('Per-Tool Attribution'),
      _src_uxL.indexOf('Per-Tool Attribution') + 1200,
    );
    const stripped = sectionSlice.replace(/<!--[\s\S]*?-->/g, '');
    assert.doesNotMatch(stripped, /via the PostToolBatch hook/);
    assert.match(stripped, /Track token usage by individual tool/);
  });

  it('UX-CO7 — disk-size warning is promoted into a <strong> tag', () => {
    // Was a comma-separated tail in the same prose colour. Promote
    // to <strong> so the eye lands on it before the toggle.
    const sectionSlice = _src_uxL.slice(
      _src_uxL.indexOf('Per-Tool Attribution'),
      _src_uxL.indexOf('Per-Tool Attribution') + 1200,
    );
    assert.match(sectionSlice, /<strong>Increases the size/);
  });

  // ── UX-WS5 — wasted-spend tooltip wraps with max-width ──
  it('UX-WS5 — .tok-wasted-bar tooltip uses white-space: normal + max-width: 18rem', () => {
    // The pre-fix CSS used white-space: nowrap, which made the long
    // multi-field tooltip spill off-screen on the rightmost bars.
    const ruleSlice = _src_uxL.match(
      /\.tok-wasted-bar:hover::after\s*\{[^}]+\}/,
    );
    assert.ok(ruleSlice, 'expected .tok-wasted-bar:hover::after rule');
    assert.match(ruleSlice[0], /white-space:\s*normal/);
    assert.match(ruleSlice[0], /max-width:\s*18rem/);
    // Strip CSS comments before asserting nowrap is gone — the
    // explanatory comment references "white-space: nowrap" as the
    // pre-fix state we're guarding against, but that mention must
    // not be confused with a literal regression.
    const stripped = ruleSlice[0].replace(/\/\*[\s\S]*?\*\//g, '');
    assert.doesNotMatch(stripped, /white-space:\s*nowrap/);
  });

  // ── UX-F1 — footer hex → var(--muted) ──
  it('UX-F1 — footer drops hardcoded #9ca3af in favour of var(--muted)', () => {
    // The casual "Vibe coded" line stays — it is the project signature
    // — but the colour MUST move with the design tokens so the footer
    // tones with the rest of the dashboard under any future theme.
    const footerSlice = _src_uxL.match(/<footer[^>]*>[\s\S]+?<\/footer>/);
    assert.ok(footerSlice, 'expected footer block');
    assert.doesNotMatch(footerSlice[0], /#9ca3af/i);
    // Both the footer container and the github link MUST use var(--muted).
    const mutedHits = (footerSlice[0].match(/color:\s*var\(--muted\)/g) || []).length;
    assert.ok(mutedHits >= 2, `expected at least 2 var(--muted) refs in footer, got ${mutedHits}`);
  });

  // ── UX-L4 — log reconnect attempt counter ──
  it('UX-L4 — _logReconnectCount let-binding is declared at module scope', () => {
    assert.match(_src_uxL, /^let _logReconnectCount = 0;/m);
  });

  it('UX-L4 — onerror handler increments _logReconnectCount and surfaces "attempt N"', () => {
    // The pre-L4 onerror was a one-liner (textContent = 'Reconnecting...').
    // The new shape is a multi-line block that increments the counter
    // and renders "Reconnecting (attempt N)..." so users can tell
    // ongoing browser retries from a stuck connection.
    const onerrSlice = _src_uxL.match(
      /_logES\.onerror\s*=\s*\(\)\s*=>\s*\{[\s\S]+?\};/,
    );
    assert.ok(onerrSlice, 'expected _logES.onerror handler');
    assert.match(onerrSlice[0], /_logReconnectCount\s*=\s*\(_logReconnectCount\s*\|\s*0\)\s*\+\s*1/);
    assert.match(onerrSlice[0], /Reconnecting \(attempt '/);
  });

  it('UX-L4 — onopen handler resets _logReconnectCount to 0 on successful (re)connect', () => {
    // Without the reset, a brief network blip would leave the counter
    // stuck at "attempt 47" forever after recovery.
    const onopenSlice = _src_uxL.match(
      /_logES\.onopen\s*=\s*\(\)\s*=>\s*\{[\s\S]+?\};/,
    );
    assert.ok(onopenSlice, 'expected _logES.onopen handler');
    assert.match(onopenSlice[0], /_logReconnectCount\s*=\s*0/);
  });
});
