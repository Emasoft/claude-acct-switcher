# TRDD-08df5425 — Investigate apiKeyHelper-based architecture (proxy-less vdm)

**TRDD ID:** `08df5425-93d7-4949-8c3d-27e05f905e43`
**Filename:** `design/tasks/TRDD-08df5425-93d7-4949-8c3d-27e05f905e43-apikeyhelper-architecture.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** Not started
**Created:** 2026-05-01
**Owner:** unassigned
**Estimated effort:** 1-2 days investigation + prototype

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
