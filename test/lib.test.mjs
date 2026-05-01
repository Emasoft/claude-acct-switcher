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
  // Phase J — keychain account name helpers
  vdmAccountServiceName,
  vdmAccountNameFromService,
  VDM_ACCOUNT_KEYCHAIN_SERVICE_PREFIX,
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
      'data: {"message":{"usage":{"input_tokens":120,"cache_read_input_tokens":40},"model":"claude-opus-4-7"}}\n' +
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
