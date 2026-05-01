# TRDD-1645134b — 4-level tree breakdown for the USAGE page + cache-miss detection

**TRDD ID:** `1645134b-526c-4abe-abfc-e21f8da5b5f0`
**Filename:** `design/tasks/TRDD-1645134b-526c-4abe-abfc-e21f8da5b5f0-usage-tree-view.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** Not started
**Created:** 2026-05-01
**Owner:** unassigned
**Estimated effort:** 1.5-2 days (data layer ~4h, UI tree ~6h, CSV
export ~2h, cache-miss detection ~3h, tests + polish ~3h)

## Origin

User request 2026-05-01: "break down the usage of tokens reported in
the USAGE page by the actual claude code instance root dir. And then
further break down the usage of tokens of a specific claude code
instance into the components that consumed them, like main-agent,
sub-agents, worktrees, etc. And then a third expansion: breaking down
those components consumption into the tools they used (bash, read,
agent, skill, mcp, fetch, image read, etc.) Or maybe the worktrees
should be before the components, since worktrees can have their own
main-agent, sub-agents, etc. so its a 4 level system of break down,
with an expandable/collapsable tree UI view. Of course the raw token
consumption report (the one exportable as csv) can still keep just
listing each api request in order with the token usage got in the
response from the server direcly (maximum certainty), but we can add
a second exported file with the structured usage graph similar to the
one displayed in the bottom section of the usage page. And another
important thing would be the detection of cache resets and cache miss!
see if the source code can help with context cache reset/miss somehow."

Builds on the data-correctness fixes in commits 83dac0e (synthetic-
model filter + per-message dedup) and 162c049 (non-project-cwd guard
+ ancestor-cwd parent resolution) — both of which are PREREQUISITES
for the tree view to display sensible groupings. Without them the
tree would still show plugin caches, system dirs, and double-counted
turns.

## Tree-view design

### Hierarchy (top → bottom)

```
1. CC instance root dir         (= row.repo, after non-project-cwd guard)
   2. Worktree                   (= row.branch — each worktree has its own branch)
      3. Component               (= main | subagent:<type> | skill:<name>)
         4. Tool                 (= row.tool — e.g. Bash, Read, Edit, MCP servers)
            tokens (in/out/cacheR/cacheW)
```

Worktrees come BEFORE components (per user clarification) because a
single worktree hosts its own main-agent + subagents + skills.

### Mapping existing row fields to tree levels

The data is already there in `token-usage.json` rows — Phase D
schema includes everything we need:

| Tree level | Source field(s)                                      |
|------------|------------------------------------------------------|
| 1. Repo    | `repo` (post-guard, post-`--git-common-dir` resolution) |
| 2. Worktree| `branch`                                             |
| 3. Component | derived: `parentSessionId == null` → "main"; else `agentType` is set → `subagent:${agentType}`; else `tool === 'Skill'` and an inferred skill name → `skill:${name}`; else → "main" |
| 4. Tool    | `tool`, plus `mcpServer` for MCP tool calls (`mcp:${server}/${tool}`) |

`teamId` is reserved for a possible 5th-level grouping (agent-teams)
but not part of the initial implementation.

### New backend endpoint

`GET /api/token-usage-tree`

Query parameters (all optional):
- `from` — earliest ts to include (epoch ms)
- `to` — latest ts to include
- `repo` — single-repo filter (drill into one tree)
- `account` — single-account filter
- `model` — single-model filter

Response shape:
```json
{
  "totals": {
    "input": 1234567,
    "output": 234567,
    "cacheRead": 654321,
    "cacheCreate": 123456,
    "cost": 12.34
  },
  "tree": [
    {
      "name": "/Users/me/proj-1",
      "kind": "repo",
      "totals": { ... },
      "children": [
        {
          "name": "main",
          "kind": "branch",
          "isWorktree": false,
          "totals": { ... },
          "children": [
            {
              "name": "main",
              "kind": "component",
              "totals": { ... },
              "children": [
                { "name": "<assistant>", "kind": "tool", "totals": { ... } },
                { "name": "Bash",        "kind": "tool", "totals": { ... } },
                { "name": "Read",        "kind": "tool", "totals": { ... } }
              ]
            },
            {
              "name": "subagent:Explore",
              "kind": "component",
              "totals": { ... },
              "children": [ ... ]
            }
          ]
        },
        {
          "name": "wt-feature-x",
          "kind": "branch",
          "isWorktree": true,
          "totals": { ... },
          "children": [ ... ]
        }
      ]
    },
    { "name": "(non-project)", "kind": "repo", ...}
  ]
}
```

`<assistant>` is a synthetic tool-name used for rows where `tool` is
null — the parent assistant turn itself, before any tool call. This
is necessary so users can distinguish "tokens spent reasoning" from
"tokens spent in a Bash call."

### UI tree component

Plain HTML `<details>`/`<summary>` for collapse/expand — no JS
framework needed (vdm has zero dependencies). Each node renders:

- Total tokens (and % of parent) on the right
- Cache hit rate badge (% of input that was a cache read)
- Click to expand children

CSS: indent each level by 1.5em. Children rendered lazily via the
`<details>` `toggle` event — only fetch + render when first opened.
For the first paint, only level-1 (repos) is loaded; deeper levels
fetch on demand from `/api/token-usage-tree?repo=<x>`.

This keeps the page fast even when the user has 50 repos × 10
worktrees × 20 sessions × 30 tools ≈ 300K rows in `token-usage.json`.

### CSV exports

Two formats:

**Format A — flat (current)**: one row per API request, raw fields
from the API response. Maximum-certainty audit trail. Filename
`token-usage-flat-<ts>.csv`. (Already exists — keep as-is.)

**Format B — tree-aggregated (new)**: pre-aggregated rows matching
the tree's leaves. Filename `token-usage-tree-<ts>.csv`. Columns:

```
repo, branch, isWorktree, component, tool,
inputTokens, outputTokens, cacheReadTokens, cacheCreationTokens,
totalCostUSD, requestCount
```

One row per `(repo, branch, component, tool)` tuple. Importers can
re-build the tree by sorting on these columns.

### Path-based filter for unattributed buckets

Surface `(non-project)` and `(non-git)` rows as separate top-level
trees with their own collapsible expansion. The user should be able
to AT-A-GLANCE distinguish "real project tokens" from "system /
plugin / scratch tokens." (Currently they're mixed into the same
chart.)

## Cache-miss detection

### Problem statement

Anthropic's prompt cache stores prompt prefixes for ~5 minutes; a
turn that re-uses an existing cache pays ~10% the input-token rate.
A cache MISS happens when:

1. The prompt prefix matches a recent turn but the cache TTL elapsed
2. The prompt prefix changed (system message, files, etc.)
3. The cache was invalidated for any other reason

vdm currently records `cacheReadInputTokens` and
`cacheCreationInputTokens` per row but doesn't EXPLICITLY classify
turns as miss vs hit. The user wants a "cache hit rate" metric and a
list of likely-miss turns for diagnosis.

### Source-code investigation (CC v2.1.89)

CC's `cost-tracker.ts:266-269` aggregates the four token kinds
verbatim from the API response — no derived "miss" signal. The
spec/docs page on prompt caching does describe the behavior but not
a programmatic way to detect a miss. Our detection has to be heuristic.

### Proposed heuristic

For each session (grouped by `sessionId`), iterate rows in
chronological order. For each row N (turn N+1 in the session):

```
prevHadCache = (any prior row in same session has cacheCreationInputTokens > 0)
currInputTokens = row.inputTokens
currCacheRead = row.cacheReadInputTokens

isLikelyMiss =
  prevHadCache &&            // a cache existed
  currCacheRead === 0 &&     // but this turn didn't read it
  currInputTokens > MIN_INPUT_FOR_MISS_DETECTION  // and the input is non-trivial
```

`MIN_INPUT_FOR_MISS_DETECTION` defaults to 1000 (small turns might
legitimately have no cache read because the prompt is brief).

The heuristic has known limitations (documented in the UI):
- A new conversation thread legitimately has no prior cache → not a miss
- A `/clear` invalidates the cache → looks like a miss but is
  user-initiated
- TTL expiry is the most common true-miss case (the heuristic catches it)

### UI surface

Add a "Cache" subsection to each session-level node in the tree:

```
session-abc-12345
  Cache hit rate: 67% (4 hits, 2 misses)
  Misses:
    - 2026-04-30 14:32  (model: claude-opus-4-7,  input: 12450, miss reason: TTL likely)
    - 2026-05-01 09:15  (model: claude-sonnet-4-7, input:  8200, miss reason: TTL likely)
```

Click a miss to jump to the activity-feed entry at that timestamp.

## Implementation phases

### Phase 1 — data layer (4h)

- Add `_aggregateUsageTree(rows, opts)` to `lib.mjs` (pure function,
  testable). Returns the nested `{ totals, tree }` shape.
- Add `_classifyComponent(row)` helper — turns a row into its
  component string (main / subagent:type / skill:name).
- Add `_buildCacheMissReport(rows)` to `lib.mjs` — applies the
  heuristic and returns the per-session miss list.
- Tests for both pure functions.

### Phase 2 — backend endpoint (2h)

- New `GET /api/token-usage-tree` handler in `dashboard.mjs`.
- Wire it through `_aggregateUsageTree`.
- Accept the same query params as the existing `/api/token-usage`.

### Phase 3 — UI tree (6h)

- New section "Tree View" under the existing usage chart in the
  template literal returned by `renderHTML()`.
- Lazy-load children via `<details>` `toggle` event.
- CSS using existing dashboard variables (no new color palette).
- XSS-safe: every dynamic field through `h(...)` helper.

### Phase 4 — CSV export (2h)

- New "Export tree CSV" button next to the existing CSV export.
- New `GET /api/token-usage-tree?format=csv` handler that streams
  the tree-aggregated CSV.

### Phase 5 — cache-miss detection (3h)

- Add the heuristic.
- Surface in the tree view as per the design above.
- Test the heuristic against synthetic row sets.

### Phase 6 — tests + polish (3h)

- Source-grep regression tests for the wiring.
- Behavioral tests for the aggregator with realistic row mixes.
- Verify the existing flat CSV is unchanged.
- Run the full test suite to confirm 0 regressions.

## What to do next session

Start with Phase 1 (pure functions in lib.mjs). Once tested, the
backend endpoint is a thin wrapper. UI work comes last because the
data layer can be validated independently.

Do NOT start the UI before Phase 1 is complete — the aggregation
shape is the contract the UI builds on, and changing it later means
re-rendering the tree from scratch.

## Acceptance criteria

- [ ] `/api/token-usage-tree` returns the documented shape
- [ ] Tree UI renders correctly with 0 / 1 / many repos
- [ ] Lazy-loading: opening a repo node fetches its children only on
      first expand
- [ ] CSV tree export round-trips to the same totals as the JSON
      response
- [ ] Cache-miss heuristic surfaces miss events with at most 5%
      false-positive rate on a known-good session log
- [ ] All existing tests still pass
- [ ] No new file in `~/.claude/projects/` outside vdm's own state
      dir is created by the new endpoints (privacy)

## Out of scope (future work)

- Multi-user / multi-machine aggregation (vdm is single-user)
- Real-time streaming updates to the tree (refresh on tab visit is
  fine)
- Per-team rollups (`teamId` field reserved, not used)
- Pricing-tier-aware cost calculations (currently uses static rates
  in `TOK_PRICING`)
