# TRDD-08df5425 — Investigate apiKeyHelper-based architecture (proxy-less vdm)

**TRDD ID:** `08df5425-93d7-4949-8c3d-27e05f905e43`
**Filename:** `design/tasks/TRDD-08df5425-93d7-4949-8c3d-27e05f905e43-apikeyhelper-architecture.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** Researched-and-rejected (Decision A from §Decision criteria)
**Created:** 2026-05-01
**Investigated:** 2026-05-01 (against CC v2.1.89 source mirror)
**Owner:** unassigned
**Estimated effort:** done — 2 hours of source reading; no prototype needed because the rejection was unambiguous

## TL;DR (read this first)

Source-code investigation against
`github.com/chauncygu/collection-claude-code-source-code`
(CC v2.1.89, which is a few versions behind the current v2.1.126 but
the auth-resolution code is stable across recent versions per surface
inspection) produced a **definitive rejection** for the proxy-less
architecture under apiKeyHelper.

The four decision criteria that this TRDD itself laid out (§Decision
criteria below) all FAIL for an OAuth-subscriber user — the typical
vdm target. Specifically:

1. ❌ **Configuring `apiKeyHelper` disables OAuth subscriber mode
   entirely.** `isAnthropicAuthEnabled()` in `utils/auth.ts:100-149`
   returns `false` whenever an external API-key source (including
   apiKeyHelper) is configured. Downstream, `isClaudeAISubscriber()`
   then returns `false`, and the SDK is constructed with
   `apiKey: <helper-output>` instead of `authToken: <oauth-bearer>`
   (`services/api/client.ts:300-313`). The user effectively switches
   from subscription billing to API-key billing — different pricing,
   different quotas, different /usage semantics. Not acceptable.

2. ❌ **The helper output is sent in BOTH `Authorization: Bearer`
   AND `X-Api-Key` headers.** Confirmed in
   `services/api/client.ts:318-328` (`configureApiKeyHeaders` sets
   `Authorization: Bearer ${token}`) plus the SDK constructor on
   line 302 setting `apiKey` from the same source. An OAuth bearer
   token sent as `X-Api-Key` is rejected by Anthropic with
   `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`
   (the literal message is in `services/api/claude.ts:579` as a known
   error pattern).

3. ❌ **Calling frequency is "stale-while-revalidate, 5-min default
   TTL"** — NOT per-request. `utils/auth.ts:81` defines
   `DEFAULT_API_KEY_HELPER_TTL = 5 * 60 * 1000`, tunable via
   `CLAUDE_CODE_API_KEY_HELPER_TTL_MS`. The cache returns a stale
   value immediately while a background refresh runs
   (`utils/auth.ts:469-499`). Even if criteria 1+2 didn't kill this,
   5-min staleness alone makes per-request rotation impossible.

4. ❌ **Zero observability.** apiKeyHelper is a unidirectional
   stdin→stdout pipe; the helper script never sees the response
   side. vdm couldn't read 5h/7d-utilization headers, 429 retry-
   after, or subscription quota state — losing every signal that
   currently drives rotation strategy.

**Decision: A.** Keep the current proxy architecture. apiKeyHelper is
designed for the API-key (Console) flow — vdm's OAuth (subscription)
users would be silently downgraded if they used it. Do not pursue.

## Findings — exact source citations (CC v2.1.89)

All paths below are relative to
`/tmp/cc-src-v2189/claude-code-source-code/src/` in the cloned
mirror; absolute repo path is
`https://github.com/chauncygu/collection-claude-code-source-code/tree/main/claude-code-source-code/src/`.

### 1. apiKeyHelper disables OAuth subscriber mode

`utils/auth.ts:120-148` — `isAnthropicAuthEnabled()`:
- Reads `settings.apiKeyHelper` (line 123) and combines it with
  `ANTHROPIC_AUTH_TOKEN`, FD tokens, and `ANTHROPIC_API_KEY` to
  compute `hasExternalAuthToken` and `hasExternalApiKey`.
- Returns `false` (i.e. "Anthropic OAuth auth is DISABLED") if any
  external source is present (line 143-148).

`utils/auth.ts:1564-1570` — `isClaudeAISubscriber()`:
- Calls `isAnthropicAuthEnabled()` first; returns `false` if disabled.
- This is the predicate downstream code uses to decide
  OAuth-bearer-vs-API-key behavior.

### 2. Helper output goes into BOTH headers

`services/api/client.ts:300-315` — Anthropic SDK construction:
```ts
const clientConfig = {
  apiKey: isClaudeAISubscriber() ? null : apiKey || getAnthropicApiKey(),
  authToken: isClaudeAISubscriber()
    ? getClaudeAIOAuthTokens()?.accessToken
    : undefined,
  // ...
}
```

When apiKeyHelper is configured, `isClaudeAISubscriber()` is `false`
(per finding #1), so:
- `apiKey = getAnthropicApiKey()` → resolves to the apiKeyHelper
  output (`utils/auth.ts:320-337`). The Anthropic SDK puts this in
  `X-Api-Key`.
- `authToken = undefined` → no Authorization header from the SDK.

But then `services/api/client.ts:135-137`:
```ts
if (!isClaudeAISubscriber()) {
  await configureApiKeyHeaders(defaultHeaders, getIsNonInteractiveSession())
}
```

`configureApiKeyHeaders` at lines 318-328:
```ts
async function configureApiKeyHeaders(headers, isNonInteractiveSession) {
  const token =
    process.env.ANTHROPIC_AUTH_TOKEN ||
    (await getApiKeyFromApiKeyHelper(isNonInteractiveSession))
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
}
```

So when apiKeyHelper runs:
- The helper's output goes into `X-Api-Key` (via SDK's `apiKey`)
- The same output ALSO goes into `Authorization: Bearer` (via
  `configureApiKeyHeaders`)

This is fine for an actual Console API key (which Anthropic accepts
in either header — they're equivalent identifiers). But an OAuth
bearer token sent as `X-Api-Key` produces the documented
`invalid x-api-key` error.

### 3. SWR caching with 5-minute TTL

`utils/auth.ts:80-81`:
```ts
/** Default TTL for API key helper cache in milliseconds (5 minutes) */
const DEFAULT_API_KEY_HELPER_TTL = 5 * 60 * 1000
```

`utils/auth.ts:435-449` — `calculateApiKeyHelperTTL()`:
- Reads `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` env var if set
- Falls back to `DEFAULT_API_KEY_HELPER_TTL` (5 min)
- Validates the env var; warns and falls back if non-numeric

`utils/auth.ts:469-499` — `getApiKeyFromApiKeyHelper`:
```ts
if (_apiKeyHelperCache) {
  if (Date.now() - _apiKeyHelperCache.timestamp < ttl) {
    return _apiKeyHelperCache.value     // fresh — return cached
  }
  // Stale — return stale value now, refresh in the background.
  if (!_apiKeyHelperInflight) {
    _apiKeyHelperInflight = { promise: _runAndCache(...), startedAt: null }
  }
  return _apiKeyHelperCache.value     // STALE returned
}
// Cold cache — wait for first fetch
```

The SWR semantics mean even if vdm could meaningfully manipulate the
helper output, CC would serve a 5-min-stale token before noticing.

### 4. Helper execution mechanics

`utils/auth.ts:538-574` — `_executeApiKeyHelper`:
- Spawns via `execa(apiKeyHelper, { shell: true, timeout: 600_000, reject: false })`
- `shell: true` means the command is interpreted by `/bin/sh`
- 10-minute timeout (way more than needed)
- Failure: throws Error; outer caller caches `' '` (space) sentinel
  and prints `apiKeyHelper failed: <stderr>` on stderr (line 517)
- Success: trims stdout; throws if empty; returns the trimmed string

A trust check (line 546-555) prevents the helper from running when
configured via project/local settings without workspace trust.

### 5. Auth precedence (definitive order)

From `utils/auth.ts:298-348` — `getAnthropicApiKeyWithSource`:

1. **Bare mode** (`--bare` / `CLAUDE_CODE_SIMPLE=1`) — only env vars.
2. **`ANTHROPIC_API_KEY`** — wins if it appears in
   `customApiKeyResponses.approved` (i.e. user explicitly approved
   it via `/login`-flow approval prompts).
3. **API key from file descriptor** (`CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR`).
4. **`apiKeyHelper`** (if configured) — uses sync cache; never blocks.
   If `skipRetrievingKeyFromApiKeyHelper` opt is set, returns
   `{key: null, source: 'apiKeyHelper'}` to signal "configured but
   not extracted." When the cache is cold, returns
   `{key: null, source: 'apiKeyHelper'}` — callers needing a real
   key MUST `await getApiKeyFromApiKeyHelper()` first. This is the
   dance `client.ts:136` does (awaits `configureApiKeyHeaders` →
   awaits `getApiKeyFromApiKeyHelper` → fills Authorization header
   before the SDK request goes out).
5. **OAuth keychain** (`getApiKeyFromConfigOrMacOSKeychain`) — only
   reached when ALL of the above are empty.

So apiKeyHelper sits ABOVE the keychain in priority. If a user
configures apiKeyHelper, the keychain entry vdm currently
manipulates becomes IRRELEVANT. This means an apiKeyHelper-based
vdm would have to abandon its current keychain-rotation model
entirely — vdm's CLAUDE.md "Credential storage — the load-bearing
detail" section becomes moot.

## Side findings (not acted on)

These are CC behaviors that the source review surfaced incidentally
and are worth knowing — but no vdm change is justified by them today
without testing against the user's actual CC version (v2.1.126).

1. **OAuth keychain memoization has NO TTL** in v2.1.89.
   `getClaudeAIOAuthTokens` (`utils/auth.ts:1255`) is wrapped in a
   bare `memoize(...)` with no expiry — the cache is cleared ONLY by
   internal events: token save (`saveOAuthTokens`), refresh
   (`utils/auth.ts:1474, 1519, 1542, 1548`), login, logout. There is
   no time-based invalidation. vdm's CLAUDE.md currently states
   "Claude Code's keychain-cache TTL is 30 seconds (raised from 5s
   in v2.1.86)" — this was likely true in some past version but is
   inaccurate as of v2.1.89. The practical implication: when vdm
   rotates an account by writing to the keychain, a running CC
   session may NEVER see the new token until something else
   triggers a cache-clear (a refresh, a /login, etc.). vdm's
   continued empirical success suggests SOMETHING is invalidating
   — likely the `Notification: auth_success` hook chain or the
   refresh sweep — but the CLAUDE.md statement should be re-tested
   against v2.1.126 and updated if confirmed wrong.

2. **`CLAUDE_CODE_REMOTE` and `CLAUDE_CODE_ENTRYPOINT=claude-desktop`**
   define a "managed OAuth context" (`utils/auth.ts:91-96`) that
   ignores user settings.json apiKeyHelper / ANTHROPIC_API_KEY
   entirely. Worth knowing if vdm ever adds a desktop integration.

3. **`shouldUseClaudeAIAuth(scopes)`** at line 1569 — subscriber
   detection requires the OAuth token's `scopes` to satisfy a
   policy. Env-var tokens (`CLAUDE_CODE_OAUTH_TOKEN`) hardcode
   scopes to `['user:inference']` (lines 1266, 1280) and DO NOT
   include `user:profile`. This is why vdm-style env-injected
   tokens can't call `/usage` etc. — see `hasProfileScope`
   (line 1580).

4. **The Notification:auth_success hook** is what vdm already uses
   to invalidate its keychain caches after `/login`. Looking at
   how CC fires its own auth-success events would tell us what
   vdm should hook into to detect external token writes.

## Acceptance check (decision criteria from this TRDD)

Proceed with proxy-less architecture ONLY IF all four hold:

- ☑ apiKeyHelper IS called per-request OR on-401 (not just at startup) → **NO**, 5-min SWR cache
- ☑ apiKeyHelper CAN return an OAuth bearer token without breaking request signatures → **NO**, sent as X-Api-Key too
- ☑ apiKeyHelper precedence beats both ANTHROPIC_API_KEY and the keychain entry → **PARTIAL**, beats keychain but not approved ANTHROPIC_API_KEY
- ☑ vdm can still observe enough state to drive rotation (5h/7d utilization headers SOMETIMES) → **NO**, helper is fire-and-forget

ALL FOUR FAIL. Per the TRDD's own logic: rejection.

## Decision (final)

**A. apiKeyHelper is API-key-only; OAuth tokens don't work.**
Abandon. Keep current proxy architecture. File this TRDD as
researched-and-rejected for future reference.

The architectural insight that motivated this investigation —
"could vdm be proxy-less?" — remains a fair question. But the
answer under the current Claude Code design is "not via
apiKeyHelper." If a future CC version adds a settings field
specifically for OAuth-bearer injection (e.g. `oauthTokenHelper`
returning a `{ accessToken, refreshToken, expiresAt }` JSON), this
TRDD should be revisited.

## Origin

User suggested 2026-05-01 that Claude Code's `apiKeyHelper` setting "may
solve many problems" after reading the Claude Code settings reference at
https://code.claude.com/docs/en/settings#available-settings.

The intuition: instead of vdm interposing as an HTTP proxy on port 3334
(via `ANTHROPIC_BASE_URL=http://localhost:3334`), vdm could ship a small
script that returns the active OAuth token, registered via
`settings.apiKeyHelper`. Claude Code would then call vdm directly for
the auth value and connect to api.anthropic.com without proxy
interception.

## Why this is non-trivial

The Claude Code docs are incomplete on the critical questions. From
WebFetch'd analysis 2026-05-01:

> **`apiKeyHelper`**: Custom script, to be executed in `/bin/sh`, to
> generate an auth value. This value will be sent as `X-Api-Key` and
> `Authorization: Bearer` headers for model requests

The docs do **not** specify:

- **Calling frequency** — per request? per session? on cache miss? once
  at startup?
- **Output format** — raw token string? JSON? must include
  `expires_in`?
- **Precedence** — vs `ANTHROPIC_API_KEY`, vs the macOS keychain
  `Claude Code-credentials` entry, vs `/login` OAuth flow
- **Error handling** — what does CC do if the script exits non-zero?
  prints garbage? times out?
- **Refresh interaction** — does CC re-run the script on 401? on
  scheduled interval? never?

The "sent as `X-Api-Key` AND `Authorization: Bearer`" detail is the
biggest red flag for vdm's use case. OAuth requires `Authorization:
Bearer <token>` ALONE; sending the same OAuth token as `X-Api-Key`
would either be ignored or cause an Anthropic-side header conflict.
This strongly suggests `apiKeyHelper` is designed for the **API-key
auth flow** (Console organisations using prepaid credits), NOT the
OAuth subscription flow (Pro / Max / Team plans) that vdm targets.

If that read is correct, `apiKeyHelper` cannot replace vdm's proxy for
the typical user without forcing them to switch from subscription
billing to API-key billing — different pricing model, different
quotas, different /usage semantics.

## Investigation plan

1. **Read the Claude Code source.** The CLI is shipped as a Node.js
   bundle (`@anthropic-ai/claude-code`); decompile / read the relevant
   auth-resolution code path. Specifically look for:
   - Where `apiKeyHelper` is read from settings.json
   - The function that calls it (spawn? exec? execFile?)
   - Where its output is consumed
   - How its output interacts with the OAuth keychain entry

2. **Empirical test — calling frequency.** Write a script that:
   - Logs every invocation timestamp + caller env to a file
   - Returns a valid OAuth token from the keychain
   Configure CC to use it. Run a CC session. Send 5 prompts. Trigger a
   401. Check the log: how many times was the script called, and when?

3. **Empirical test — auth mode.** With apiKeyHelper returning an OAuth
   bearer token (NOT an API key):
   - Does a basic prompt succeed?
   - Does `/usage` work (subscription quota)?
   - Or does it fail because the X-Api-Key header conflicts?

4. **Empirical test — refresh interaction.** With a token that's about
   to expire, configured via apiKeyHelper:
   - Does CC re-call the script when the token expires (we'd see this
     in the per-call log)?
   - Or does CC try to refresh via the OAuth endpoint (which would
     fail because apiKeyHelper bypasses the keychain entry where the
     refresh token lives)?

## Decision criteria

Proceed with proxy-less architecture ONLY IF all four hold:

- ☐ apiKeyHelper IS called per-request OR on-401 (not just at startup)
- ☐ apiKeyHelper CAN return an OAuth bearer token without breaking
  request signatures
- ☐ apiKeyHelper precedence beats both ANTHROPIC_API_KEY and the
  keychain entry (so vdm can authoritatively control which token is
  sent)
- ☐ vdm can still observe enough state to drive rotation (5h/7d
  utilization headers SOMETIMES — not always, but enough to populate
  the dashboard)

If criteria 1-3 hold but criterion 4 fails (no observability), keep
the proxy as the observability path AND use apiKeyHelper for the
authority path. This dual-control hybrid is more complex than either
end alone but recovers some benefits (auto permission mode, no port
conflicts).

## Pros / cons of the proxy-less architecture

### Pros if apiKeyHelper works

- **No proxy to maintain.** Drops dashboard.mjs proxy half (~5000
  LOC), port 3334 listener, all the `_smartPassthrough` /
  `_isCircuitOpen` / etc. logic.
- **No port conflicts.** Multiple vdm installs on one machine would
  Just Work; no `CSW_PROXY_PORT` collision dance.
- **No header-forwarding bugs.** The `anthropic-beta` regression risk
  (Phase I+ "Extra inputs are not permitted") goes away because CC
  builds the request directly.
- **`auto` permission mode works.** Currently disabled by ANTHROPIC_
  BASE_URL — see CLAUDE.md "What disables vdm". This alone is a real
  UX win for power users.
- **Server-managed settings respected.** Currently bypassed by
  ANTHROPIC_BASE_URL — managed-settings policies that admins want
  enforced would actually apply.
- **Lower latency.** No proxy hop; direct connection to api.anthropic.com.
- **No SSE buffering edge cases.** vdm's proxy currently has subtle
  bugs around mid-stream disconnects (PROXY-4/5 in batch 10 backlog).
  Going proxy-less eliminates that whole class.

### Cons if apiKeyHelper works

- **Lose observability.** vdm can't read the response, so:
  - No 5h/7d utilization tracking
  - No 429 detection / rotation feedback loop
  - No SSE token-usage extractor
  - No anthropic-ratelimit-unified-status header parsing
- **Account selection becomes a guess.** Without seeing responses,
  vdm picks an account based on stale data from previous sessions.
- **No mid-stream rotation.** Currently the proxy can swap accounts
  mid-flight on 429. apiKeyHelper-only architecture cannot intervene
  during a request.
- **No serialize queue.** Without proxy interception there's no
  layer to enforce request serialization across CC instances.
- **Dashboard becomes display-only.** Currently the dashboard surfaces
  per-account utilization, activity feed, queue stats — most of which
  is impossible without proxy observability.

### Hybrid (apiKeyHelper for auth, proxy for observability)

- Pros: keep all observability features, get auto-mode + managed-
  settings + no-port-conflict on the auth side.
- Cons: TWO control planes (settings.json + ANTHROPIC_BASE_URL); more
  failure modes; users have to configure both.
- Requires investigation: does CC use the apiKeyHelper'd token even
  when ANTHROPIC_BASE_URL is set? The two settings might conflict.

## Files likely affected

If we proceed with proxy-less:
- `dashboard.mjs` — proxy half deleted (~50% reduction in LOC)
- New: `apikey-helper.sh` (or `.mjs`) — small script that prints
  active token
- `install.sh` — register apiKeyHelper in settings.json instead of
  ANTHROPIC_BASE_URL in rc snippet
- `vdm` (the CLI) — `vdm switch` writes to a config file the
  apiKeyHelper script reads, instead of mutating the keychain entry
- All proxy-tests in `test/api.test.mjs` removed

If hybrid:
- New: `apikey-helper.sh` shipped alongside dashboard.mjs
- `install.sh` — register BOTH apiKeyHelper AND ANTHROPIC_BASE_URL
- Existing proxy code stays

## Test scenarios

For the empirical tests above, set up a clean test harness:

1. Fresh `~/.claude/settings.json` with only `apiKeyHelper` set
2. No `ANTHROPIC_API_KEY` in env
3. Empty keychain `Claude Code-credentials` entry
4. Logging script that records: call timestamp, working directory,
   env vars, stdin if any
5. Run `claude` in a fresh shell and capture the script's invocation log

Repeat with:
- token expired
- 401 response from API (mock or real)
- 429 response from API
- Multi-prompt session (does the script get re-called per prompt?)

## References

- Claude Code error reference (consulted 2026-05-01):
  https://code.claude.com/docs/en/errors
- Claude Code settings reference (consulted 2026-05-01):
  https://code.claude.com/docs/en/settings#available-settings
- Claude Code authentication precedence (mentioned in errors doc):
  https://code.claude.com/docs/en/authentication#authentication-precedence
- vdm's current architecture in `CLAUDE.md` § Architecture
- The "What disables vdm" section in `CLAUDE.md` documents the
  current ANTHROPIC_BASE_URL trade-offs

## Decision (after investigation)

To be filled in once empirical results land. Likely outcomes:

- **A.** apiKeyHelper is API-key-only; OAuth tokens don't work →
  abandon, keep current proxy architecture, file as researched-and-
  rejected.
- **B.** apiKeyHelper works for OAuth but only at session start →
  too rigid, abandon. Rotation requires per-request control.
- **C.** apiKeyHelper works per-request → proceed with proxy-less or
  hybrid.

Until investigation completes, NO code changes to the current proxy
architecture motivated by this idea.
