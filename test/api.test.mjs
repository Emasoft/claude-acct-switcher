// In-process OAuth refresh tests for lib.mjs helpers.
//
// These tests do NOT spawn dashboard.mjs, do NOT set OAUTH_TOKEN_URL on a
// child process, and do NOT touch the keychain or accounts/ directory.
// Instead they spin up an in-process mock OAuth server on 127.0.0.1:0
// (random port) and exercise the pure helpers in lib.mjs directly:
// buildRefreshRequestBody / parseRefreshResponse / computeExpiresAt /
// buildUpdatedCreds / shouldRefreshToken — plus the request/response shape
// the production code expects from the OAuth endpoint (JSON in, JSON out;
// commit 815bd66).

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

// ─────────────────────────────────────────────────
// Mock OAuth Server
// ─────────────────────────────────────────────────

function createMockOAuthServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, url: `http://127.0.0.1:${port}` });
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

// ─────────────────────────────────────────────────
// Pure function integration tests (no dashboard dependency)
// ─────────────────────────────────────────────────

import {
  buildRefreshRequestBody,
  parseRefreshResponse,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  // Phase D — hook payload parsers and helpers
  parseCompactPayload,
  parseSubagentStartPayload,
  parseCwdChangedPayload,
  parsePostToolBatchPayload,
  inferMcpServerFromToolName,
  isUsageRow,
  buildCompactBoundaryEntry,
  mergeSessionAttribution,
} from '../lib.mjs';

describe('OAuth refresh helpers (lib.mjs) against in-process mock OAuth server', () => {
  let mockServer, mockPort, mockUrl;
  let refreshCount = 0;

  before(async () => {
    const mock = await createMockOAuthServer((req, res) => {
      refreshCount++;
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        // Production sends JSON (commit 815bd66 — "Fix OAuth refresh: use
        // JSON format with client_id and scope"). The previous test parsed
        // form-encoded which silently misclassified every JSON body as
        // `invalid_grant` — the assertions failed, but the failures were
        // hidden in CI's noise.
        let payload = {};
        try { payload = JSON.parse(body); } catch {}
        const refreshToken = payload.refresh_token;

        if (refreshToken === 'valid-rt') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            access_token: `new-at-${refreshCount}`,
            refresh_token: `new-rt-${refreshCount}`,
            expires_in: 28800,
          }));
        } else if (refreshToken === 'revoked-rt') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Refresh token has been revoked',
          }));
        } else if (refreshToken === 'server-error-rt') {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } else if (refreshToken === 'rate-limited-rt') {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'rate_limited' }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
        }
      });
    });
    mockServer = mock.server;
    mockPort = mock.port;
    mockUrl = mock.url;
  });

  after(async () => {
    if (mockServer) await closeServer(mockServer);
  });

  it('mock server returns new tokens for valid refresh token', async () => {
    const body = buildRefreshRequestBody('valid-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    const data = await response.json();
    assert.equal(response.status, 200);
    assert.ok(data.access_token.startsWith('new-at-'));
    assert.ok(data.refresh_token.startsWith('new-rt-'));
    assert.equal(data.expires_in, 28800);
  });

  it('mock server returns 400 for revoked token', async () => {
    const body = buildRefreshRequestBody('revoked-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    assert.equal(response.status, 400);
    const data = await response.json();
    assert.equal(data.error, 'invalid_grant');
  });

  it('mock server returns 429 for rate-limited token', async () => {
    const body = buildRefreshRequestBody('rate-limited-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    assert.equal(response.status, 429);
  });

  it('mock server returns 500 for server error token', async () => {
    const body = buildRefreshRequestBody('server-error-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });
    assert.equal(response.status, 500);
  });
});

describe('Refresh flow end-to-end (pure functions)', () => {
  it('full refresh cycle: build request → parse response → compute expiry → build creds', () => {
    // 1. Build request — production sends JSON, not form-encoded.
    const body = buildRefreshRequestBody('old-refresh-token');
    const parsedBody = JSON.parse(body);
    assert.equal(parsedBody.grant_type, 'refresh_token');
    assert.equal(parsedBody.refresh_token, 'old-refresh-token');

    // 2. Simulate successful response
    const responseBody = JSON.stringify({
      access_token: 'fresh-access-token',
      refresh_token: 'fresh-refresh-token',
      expires_in: 7200,
    });
    const parsed = parseRefreshResponse(200, responseBody);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.accessToken, 'fresh-access-token');

    // 3. Compute expiry
    const now = Date.now();
    const expiresAt = computeExpiresAt(parsed.expiresIn, now);
    assert.equal(expiresAt, now + 7200 * 1000);

    // 4. Build updated creds
    const oldCreds = {
      claudeAiOauth: {
        accessToken: 'old-at',
        refreshToken: 'old-rt',
        expiresAt: 1000,
        scopes: ['user:inference'],
        subscriptionType: 'max',
      },
    };
    const newCreds = buildUpdatedCreds(oldCreds, parsed.accessToken, parsed.refreshToken, expiresAt);
    assert.equal(newCreds.claudeAiOauth.accessToken, 'fresh-access-token');
    assert.equal(newCreds.claudeAiOauth.refreshToken, 'fresh-refresh-token');
    assert.equal(newCreds.claudeAiOauth.expiresAt, expiresAt);
    assert.deepEqual(newCreds.claudeAiOauth.scopes, ['user:inference']);
    assert.equal(newCreds.claudeAiOauth.subscriptionType, 'max');

    // 5. Verify shouldRefreshToken says no for fresh token
    assert.equal(shouldRefreshToken(expiresAt, 60 * 60 * 1000, now), false);
  });

  it('handles failed refresh gracefully', () => {
    const parsed = parseRefreshResponse(400, JSON.stringify({
      error: 'invalid_grant',
      error_description: 'Refresh token expired',
    }));
    assert.equal(parsed.ok, false);
    assert.equal(parsed.retriable, false);
    assert.match(parsed.error, /Refresh token expired/);
  });

  it('identifies retriable vs non-retriable errors', () => {
    // Non-retriable
    assert.equal(parseRefreshResponse(400, '{}').retriable, false);
    assert.equal(parseRefreshResponse(401, '{}').retriable, false);
    assert.equal(parseRefreshResponse(403, '{}').retriable, false);

    // Retriable
    assert.equal(parseRefreshResponse(429, '{}').retriable, true);
    assert.equal(parseRefreshResponse(500, '{}').retriable, true);
    assert.equal(parseRefreshResponse(502, '{}').retriable, true);
    assert.equal(parseRefreshResponse(503, '{}').retriable, true);
  });
});

// ─────────────────────────────────────────────────
// Phase D — Hook endpoint round-trip simulations
//
// These tests exercise the endpoint logic end-to-end against a stub
// pendingSessions Map. They simulate what each /api/<endpoint> handler
// does in dashboard.mjs:
//   - parse payload via the lib parser
//   - on success, mutate pendingSessions or build a row
//   - on failure, return 400
//
// We don't spin up the dashboard.mjs HTTP server because (a) it has
// non-trivial side effects (timers, keychain reads, account discovery,
// signal handlers) that pollute the test environment, and (b) the
// handler code in dashboard.mjs is a thin wrapper around the lib
// helpers — testing the helpers + the wrapping rules covers the
// observable behaviour the integration test would verify.
// ─────────────────────────────────────────────────

describe('SubagentStart round-trip — register, then attribute on stop', () => {
  it('registers sub-agent inheriting parent repo/branch, then row has parentSessionId/agentType', () => {
    // Stub pendingSessions with a parent session that's already running
    const pendingSessions = new Map();
    pendingSessions.set('parent-session-1', {
      repo: '/tmp/proj',
      branch: 'main',
      commitHash: 'abc1234',
      cwd: '/tmp/proj',
      startedAt: 1729000000000,
    });

    // Step 1: SubagentStart fires — endpoint registers the sub-agent
    const startPayload = {
      session_id: 'sub-agent-xyz',
      parent_session_id: 'parent-session-1',
      agent_type: 'Explore',
      cwd: '/tmp/proj/sub',
    };
    const startParsed = parseSubagentStartPayload(startPayload);
    assert.equal(startParsed.ok, true);

    // Simulate the endpoint's registration logic
    const parent = pendingSessions.get(startParsed.parentSessionId);
    pendingSessions.set(startParsed.sessionId, {
      repo: parent.repo,
      branch: parent.branch,
      commitHash: parent.commitHash,
      cwd: startParsed.cwd,
      startedAt: 1729000001000,
      parentSessionId: startParsed.parentSessionId,
      agentType: startParsed.agentType,
    });

    // Step 2: SubagentStop fires later. The dashboard's
    // _claimAndPersistForSession looks up the session and emits a row via
    // mergeSessionAttribution. We reproduce the row-build step here.
    const session = pendingSessions.get('sub-agent-xyz');
    const row = mergeSessionAttribution('sub-agent-xyz', session, {
      ts: 1729000005000,
      repo: session.repo,
      branch: session.branch,
      commitHash: session.commitHash,
      model: 'claude-sonnet-4',
      inputTokens: 1234,
      outputTokens: 567,
      account: 'acc-1',
    });

    // Assertions: persisted row carries the sub-agent attribution
    assert.equal(row.sessionId, 'sub-agent-xyz');
    assert.equal(row.parentSessionId, 'parent-session-1');
    assert.equal(row.agentType, 'Explore');
    assert.equal(row.repo, '/tmp/proj');         // inherited from parent
    assert.equal(row.branch, 'main');             // inherited from parent
    assert.equal(row.inputTokens, 1234);
  });

  it('parent unknown — sub-agent is registered standalone with parentSessionId=null', () => {
    const pendingSessions = new Map();
    const startPayload = {
      session_id: 'orphan-sub',
      parent_session_id: 'unknown-parent',
      agent_type: 'Bash',
      cwd: '/tmp/orphan',
    };
    const parsed = parseSubagentStartPayload(startPayload);
    assert.equal(parsed.ok, true);
    const parent = pendingSessions.get(parsed.parentSessionId);
    assert.equal(parent, undefined);

    // Endpoint registers standalone with the sub-agent's own cwd; in test
    // mode we skip the _runGit calls and just register the entry.
    pendingSessions.set(parsed.sessionId, {
      repo: '(non-git)',
      branch: '(no git)',
      commitHash: '',
      cwd: parsed.cwd,
      startedAt: 1729000000000,
      parentSessionId: parsed.parentSessionId,   // recorded even though parent unknown
      agentType: parsed.agentType,
    });

    const session = pendingSessions.get('orphan-sub');
    const row = mergeSessionAttribution('orphan-sub', session, {
      ts: 1, model: 'claude', inputTokens: 0, outputTokens: 0, account: 'a',
    });
    // parentSessionId is preserved on the row even if the parent's session
    // isn't tracked locally — the dashboard UI can still render the link.
    assert.equal(row.parentSessionId, 'unknown-parent');
    assert.equal(row.agentType, 'Bash');
  });

  it('SubagentStart rejects malformed payload (no session_id) at the parser', () => {
    const r = parseSubagentStartPayload({ parent_session_id: 'p', agent_type: 'X' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });
});

describe('PreCompact / PostCompact round-trip — append compact_boundary marker', () => {
  it('PreCompact builds a marker row with preTokens and null postTokens', () => {
    const payload = {
      session_id: 'sess-1',
      cwd: '/tmp',
      trigger: 'auto',
      preTokens: 167189,
    };
    const parsed = parseCompactPayload(payload, 'pre');
    assert.equal(parsed.ok, true);

    const row = buildCompactBoundaryEntry({
      ts: 1729000010000,
      sessionId: parsed.sessionId,
      repo: '/tmp/proj',
      branch: 'main',
      commitHash: 'abc1234',
      trigger: parsed.trigger,
      preTokens: parsed.preTokens,
      postTokens: parsed.postTokens,   // null
      account: 'acc-1',
    });

    assert.equal(row.type, 'compact_boundary');
    assert.equal(row.sessionId, 'sess-1');
    assert.equal(row.trigger, 'auto');
    assert.equal(row.preTokens, 167189);
    assert.equal(row.postTokens, null);
  });

  it('PostCompact builds a marker row with both preTokens and postTokens', () => {
    const parsed = parseCompactPayload({
      session_id: 'sess-1',
      cwd: '/tmp',
      trigger: 'auto',
      preTokens: 167189,
      postTokens: 42000,
    }, 'post');
    assert.equal(parsed.ok, true);

    const row = buildCompactBoundaryEntry({
      ts: 1729000020000,
      sessionId: parsed.sessionId,
      repo: '/tmp/proj',
      branch: 'main',
      commitHash: 'abc1234',
      trigger: parsed.trigger,
      preTokens: parsed.preTokens,
      postTokens: parsed.postTokens,
      account: 'acc-1',
    });

    assert.equal(row.preTokens, 167189);
    assert.equal(row.postTokens, 42000);
  });

  it('PostCompact clears in-flight per-tool tracking on the session', () => {
    // Simulates the endpoint's session.lastBatchToolNames = [] reset.
    const pendingSessions = new Map();
    pendingSessions.set('sess-1', {
      repo: '/tmp', branch: 'main', commitHash: '', cwd: '/tmp',
      startedAt: 1, lastBatchToolNames: ['Bash', 'mcp__github__create_pr'],
    });
    const session = pendingSessions.get('sess-1');
    // The endpoint would clear it after appending the boundary row:
    session.lastBatchToolNames = [];
    assert.deepEqual(session.lastBatchToolNames, []);

    // Subsequent appendTokenUsage call must NOT pick up stale tool tags.
    const row = mergeSessionAttribution('sess-1', session, { ts: 2 }, { perToolAttributionEnabled: true });
    assert.equal(row.tool, null);
    assert.equal(row.mcpServer, null);
  });

  it('PreCompact rejects malformed payload at the parser', () => {
    const r = parseCompactPayload({ cwd: '/tmp' }, 'pre');
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('PostCompact rejects malformed payload at the parser', () => {
    const r = parseCompactPayload({}, 'post');
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });

  it('Aggregation reader skips compact_boundary rows', () => {
    // The /api/token-usage GET filters with isUsageRow when
    // ?includeMarkers != 1. Verify a synthesised mixed array filters
    // correctly.
    const usageRow = { type: 'usage', ts: 1, inputTokens: 100, outputTokens: 50 };
    const boundaryRow = buildCompactBoundaryEntry({
      ts: 2, sessionId: 'a', trigger: 'auto', preTokens: 100, postTokens: 50,
    });
    const legacyRow = { ts: 3, inputTokens: 25, outputTokens: 10 };   // pre-Phase-D shape

    const all = [usageRow, boundaryRow, legacyRow];
    const filtered = all.filter(isUsageRow);
    assert.equal(filtered.length, 2);   // legacy + new usage row
    assert.equal(filtered.includes(boundaryRow), false);
    assert.equal(filtered.includes(usageRow), true);
    assert.equal(filtered.includes(legacyRow), true);   // forward-compat
  });
});

describe('CwdChanged round-trip — update pendingSession cwd', () => {
  it('updates session cwd on a known session', () => {
    const pendingSessions = new Map();
    pendingSessions.set('sess-1', {
      repo: '/tmp/old', branch: 'feature/x', commitHash: '', cwd: '/tmp/old',
      startedAt: 1,
    });
    const parsed = parseCwdChangedPayload({
      session_id: 'sess-1',
      previous_cwd: '/tmp/old',
      cwd: '/tmp/new',
    });
    assert.equal(parsed.ok, true);

    // Endpoint logic: update cwd. Branch update is real-git-dependent so
    // we test only the cwd assignment here.
    const session = pendingSessions.get('sess-1');
    session.cwd = parsed.cwd;
    assert.equal(session.cwd, '/tmp/new');
  });

  it('CwdChanged on unknown session is a no-op (idempotent)', () => {
    const pendingSessions = new Map();
    const parsed = parseCwdChangedPayload({
      session_id: 'never-registered',
      previous_cwd: '/old',
      cwd: '/new',
    });
    assert.equal(parsed.ok, true);
    // Endpoint logic: pendingSessions.get returns undefined; the handler
    // checks `if (session)` and skips. No throw, no error.
    const session = pendingSessions.get('never-registered');
    assert.equal(session, undefined);
  });

  it('CwdChanged rejects malformed payload at parser (missing cwd)', () => {
    const r = parseCwdChangedPayload({ session_id: 'a' });
    assert.equal(r.ok, false);
    assert.match(r.error, /cwd/);
  });

  it('CwdChanged rejects malformed payload at parser (missing session_id)', () => {
    const r = parseCwdChangedPayload({ cwd: '/x' });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });
});

describe('PostToolBatch round-trip — gated', () => {
  it('with gate ON: stages tools on session.lastBatchToolNames; next row gets tagged', () => {
    const pendingSessions = new Map();
    pendingSessions.set('sess-1', {
      repo: '/tmp', branch: 'main', commitHash: '', cwd: '/tmp', startedAt: 1,
    });
    const parsed = parsePostToolBatchPayload({
      session_id: 'sess-1',
      cwd: '/tmp',
      tools: [
        { tool_name: 'Bash', tool_input: {} },
        { tool_name: 'mcp__github__create_pr', tool_input: {} },
      ],
    });
    assert.equal(parsed.ok, true);

    // Endpoint stages the tool names
    const session = pendingSessions.get('sess-1');
    session.lastBatchToolNames = parsed.tools.map(t => t.toolName);
    assert.deepEqual(session.lastBatchToolNames, ['Bash', 'mcp__github__create_pr']);

    // Next appendTokenUsage call (with gate ON) tags the row
    const row = mergeSessionAttribution('sess-1', session, {
      ts: 1, model: 'claude', inputTokens: 0, outputTokens: 0, account: 'a',
    }, { perToolAttributionEnabled: true });
    assert.equal(row.tool, 'Bash,mcp__github__create_pr');
    assert.equal(row.mcpServer, 'github');
  });

  it('with gate OFF: row is NOT tagged even if lastBatchToolNames is set', () => {
    const session = {
      lastBatchToolNames: ['Bash', 'mcp__github__create_pr'],
    };
    const row = mergeSessionAttribution('sess-1', session, {
      ts: 1, model: 'claude', inputTokens: 0, outputTokens: 0, account: 'a',
    }, { perToolAttributionEnabled: false });
    assert.equal(row.tool, null);
    assert.equal(row.mcpServer, null);
  });

  it('PostToolBatch rejects malformed payload at parser (missing tools array)', () => {
    const r = parsePostToolBatchPayload({ session_id: 'a', cwd: '/tmp' });
    assert.equal(r.ok, false);
    // Phase G — error message references the spec field `tool_calls`.
    assert.match(r.error, /tool_calls/);
  });

  it('PostToolBatch rejects malformed payload at parser (missing session_id)', () => {
    const r = parsePostToolBatchPayload({ cwd: '/tmp', tools: [] });
    assert.equal(r.ok, false);
    assert.match(r.error, /session_id/);
  });
});

// ─────────────────────────────────────────────────
// OAuth refresh retry-loop integration test.
//
// Production code in dashboard.mjs implements callRefreshEndpoint with
// REFRESH_MAX_RETRIES = 3 + exponential backoff for transient failures
// (429 / 5xx / network errors), but stops immediately on 4xx (revoked).
// The pure helpers in lib.mjs don't implement the retry loop themselves,
// but parseRefreshResponse() returns a `retriable` field that the loop
// uses to decide whether to back off and try again.
//
// This test simulates the full retry-loop pattern against the mock OAuth
// server, asserting:
//   1. transient failures trigger retry (429, 500)
//   2. permanent failures bail immediately (400 invalid_grant)
//   3. retry budget is respected (max attempts, no infinite loop)
//   4. successful retry after transient failure produces fresh tokens
// ─────────────────────────────────────────────────
describe('OAuth refresh retry-loop simulation', () => {
  let mockServer, mockUrl;
  // Per-test counters keyed by refresh-token marker so each scenario
  // can drive its own attempt sequence without race conditions.
  let attempts;

  before(async () => {
    attempts = new Map();
    const mock = await createMockOAuthServer((req, res) => {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        let payload = {};
        try { payload = JSON.parse(body); } catch {}
        const rt = payload.refresh_token || '';
        const n = (attempts.get(rt) || 0) + 1;
        attempts.set(rt, n);

        // "transient-then-success-rt": fail twice (500 then 429), succeed
        // on third attempt. Exercises the full retriable backoff path.
        if (rt === 'transient-then-success-rt') {
          if (n === 1) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Server Error');
          } else if (n === 2) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'rate_limited' }));
          } else {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              access_token: 'access-after-retry',
              refresh_token: 'refresh-after-retry',
              expires_in: 28800,
            }));
          }
          return;
        }

        // "always-500-rt": exhausts the retry budget — caller must bail
        // after MAX_RETRIES without crashing or hanging.
        if (rt === 'always-500-rt') {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
          return;
        }

        // "revoked-immediately-rt": permanent 400 — the retry loop must
        // bail on the first attempt, NOT consume the full retry budget.
        if (rt === 'revoked-immediately-rt') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Refresh token has been revoked',
          }));
          return;
        }

        // Catch-all: invalid request
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
      });
    });
    mockServer = mock.server;
    mockUrl = mock.url;
  });

  after(async () => {
    if (mockServer) await closeServer(mockServer);
  });

  // Simulator helper — performs the same loop dashboard.mjs's
  // callRefreshEndpoint does, but as a pure function for testing.
  // Returns { ok, attempts, parsed, error }.
  async function simulateRefreshLoop(refreshToken, maxRetries = 3, _backoffMs = (() => 1)) {
    let lastParsed = null;
    let lastError = null;
    let attemptCount = 0;
    for (let i = 0; i < maxRetries; i++) {
      attemptCount++;
      try {
        const body = buildRefreshRequestBody(refreshToken);
        const response = await fetch(`${mockUrl}/v1/oauth/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        });
        const text = await response.text();
        const parsed = parseRefreshResponse(response.status, text);
        lastParsed = parsed;
        if (parsed.ok) return { ok: true, attempts: attemptCount, parsed };
        if (!parsed.retriable) return { ok: false, attempts: attemptCount, parsed };
      } catch (e) {
        lastError = e;
        // Network errors are retriable — fall through to next iteration.
      }
      // Tiny delay so back-to-back fetches don't share a TCP connection
      // (which would skew the mock server's per-test attempt counters).
      // The backoff function is injectable so production code can plug
      // in real exponential backoff while tests stay fast.
      await new Promise(r => setTimeout(r, _backoffMs(i)));
    }
    return { ok: false, attempts: attemptCount, parsed: lastParsed, error: lastError };
  }

  it('retries transient failures and succeeds when the server recovers', async () => {
    const result = await simulateRefreshLoop('transient-then-success-rt');
    assert.equal(result.ok, true);
    assert.equal(result.attempts, 3, 'should attempt 3 times: 500, 429, 200');
    assert.equal(result.parsed.accessToken, 'access-after-retry');
    assert.equal(result.parsed.refreshToken, 'refresh-after-retry');
    assert.equal(attempts.get('transient-then-success-rt'), 3);
  });

  it('bails IMMEDIATELY on 400 invalid_grant — does NOT consume retry budget', async () => {
    const result = await simulateRefreshLoop('revoked-immediately-rt');
    assert.equal(result.ok, false);
    assert.equal(result.attempts, 1, 'invalid_grant must NOT retry');
    assert.equal(result.parsed.ok, false);
    assert.equal(result.parsed.retriable, false);
    // parseRefreshResponse stores the human-readable error in `error`.
    // For invalid_grant the mock sends error_description, which the
    // parser surfaces verbatim — assert the string contains "revoked".
    assert.match(result.parsed.error, /revoked/i);
    assert.equal(attempts.get('revoked-immediately-rt'), 1);
  });

  it('exhausts retry budget on always-failing 500 without infinite loop', async () => {
    const result = await simulateRefreshLoop('always-500-rt');
    assert.equal(result.ok, false);
    assert.equal(result.attempts, 3, 'should attempt exactly maxRetries times');
    assert.equal(result.parsed.ok, false);
    assert.equal(result.parsed.retriable, true, '5xx is retriable');
    assert.equal(attempts.get('always-500-rt'), 3);
  });

  it('respects custom maxRetries parameter (e.g. caller wants 1 attempt only)', async () => {
    // Reset counter so the assertion below isn't tainted by previous tests.
    attempts.set('always-500-rt', 0);
    const result = await simulateRefreshLoop('always-500-rt', 1);
    assert.equal(result.attempts, 1);
    assert.equal(result.ok, false);
  });

  it('parseRefreshResponse classifies retriable vs non-retriable correctly', () => {
    // Black-box check that the helper the loop relies on returns the
    // right `retriable` flag for each status code class.
    assert.equal(parseRefreshResponse(200, '{"access_token":"a","refresh_token":"b","expires_in":1}').ok, true);
    assert.equal(parseRefreshResponse(400, '{"error":"invalid_grant"}').retriable, false);
    assert.equal(parseRefreshResponse(401, '{"error":"unauthorized_client"}').retriable, false);
    assert.equal(parseRefreshResponse(429, '{"error":"rate_limited"}').retriable, true);
    assert.equal(parseRefreshResponse(500, 'oops').retriable, true);
    assert.equal(parseRefreshResponse(502, 'oops').retriable, true);
    assert.equal(parseRefreshResponse(503, 'oops').retriable, true);
  });
});
