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
  pickBestAccount,
  pickAnyUntried,
  pickByStrategy,
  createProbeTracker,
  createUtilizationHistory,
  buildRefreshRequestBody,
  parseRefreshResponse,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  createPerAccountLock,
  getEarliestReset,
  createSemaphore,
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
      // These should survive:
      'content-type': 'application/json',
      'authorization': 'Bearer tok',
      'x-custom': 'value',
    };
    const result = stripHopByHopHeaders(input);
    for (const h of HOP_BY_HOP) {
      assert.ok(!(h in result), `${h} should be stripped`);
    }
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
    // Pick a time three minutes from now — guaranteed same calendar day.
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
    assert.match(r.error, /tools/);
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
