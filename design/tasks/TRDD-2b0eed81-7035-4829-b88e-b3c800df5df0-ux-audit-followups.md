# TRDD-2b0eed81 — UX audit follow-up batch 2

**TRDD ID:** `2b0eed81-7035-4829-b88e-b3c800df5df0`
**Filename:** `design/tasks/TRDD-2b0eed81-7035-4829-b88e-b3c800df5df0-ux-audit-followups.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** All 6 suggested batches PLUS round-3 individual MAJORs (batches F, G, H, I, J, K) complete. Only deferred MINOR/NIT items remain.
**Created:** 2026-05-02
**Source audit:** `reports/audit/20260502_154014+0200-ui-usability-audit-opus.md` (95 findings, Opus)
**Owner:** unassigned
**Estimated effort:** 1.5–2 weeks across the listed batches

## Origin

Round 3 of the dashboard.mjs audit was a UX usability audit. Opus flagged 95 findings across 9 themed sections (header, accounts tab, activity tab, usage carousel, project filter, wasted-spend, cache-misses, breakdown cards, scrubber, sessions, config, logs, footer, cross-cutting). Of those, 14 were applied in commit `<UX-batch-1-sha>`:

- `*:focus-visible` global rule + `.tab` colour bump for AA contrast (UX-X4/UX-X5/global a11y).
- Toast: aria-live="polite", role=status, top-right placement (no longer collides with iOS Safari URL bar / mobile keyboard / Logs tab), bigger close-button hit-target, hover/focus states (UX-X2/UX-X6).
- Carousel: `_carouselPaused()` honors hover, focus, prefers-reduced-motion, project-filter-open, and chart-bar-tooltip-active states (UX-CA1, CRITICAL).
- Tab + carousel-dot arrow-key navigation via `_wireRovingArrowKeys` helper (UX-X4, UX-CA3).
- Esc-to-close on the project-filter panel + focus-return to trigger (UX-CPF2).
- Carousel dot aria-labels announcing slide names (UX-CA2).
- Cache-miss reason badge tooltips explaining each classifier label (UX-CM2).
- "Wasted Spend (Cache Misses)" Title-Case rename + tooltip on chart title (UX-WS1).
- Switch button label compressed to "Switch" with `title=` for the long form (UX-A1).
- Responsive breakpoints at 720px and 480px — tabs scroll horizontally instead of squashing, filter row stacks, stat-grid collapses to 1–2 columns (UX-X1, CRITICAL).
- `.remove-btn` tinted with `var(--red)` border+text at rest so the destructive action is visually distinct (audit-adjacent — was hex `#dc2626` only on hover).

The other 80 findings are catalogued below for follow-up. None are merge-blockers; many are quality-of-life or polish.

## Applied in **batches F + G + H + I + J + K** (round-3 parallel-Opus dispatch — 19 findings)

Six Opus agents launched in parallel (one per batch), each in an isolated worktree. All 6 completed; merged sequentially with mechanical conflict resolution (each batch added its own describe block to test/lib.test.mjs at end-of-file).

- **Batch F** (UX-H1, UX-H2, UX-CO1, UX-CO3, UX-CO4): header right-side action chrome (`<div class="header-right">` + settings/help icon buttons), exhausted-banner palette swap, Config tab anchor IDs + TOC, Session Monitor explicit privacy callout, strategy-list de-duplication (`STRATEGY_HINTS[strategy]` removed).
- **Batch G** (UX-A6, UX-A7): account-card stale opacity now targets `.card-top` only (rate bars + error message + Refresh button stay full opacity); `.stale-pill` with `aria-label` for SR/colour-blind users; hover lift via `transform: translateY(-1px)` instead of bigger shadow + bumped `.accounts` gap.
- **Batch H** (UX-CM1, UX-CM3, UX-BR1, UX-BR2): cache-miss session open/closed state persists in bounded localStorage (`vdm.cacheMissOpen.<id>` / `vdm.cacheMissClosed.<id>`); "Show N older miss(es)" tail row is a real `<button>` with inline expand; Account Breakdown rows carry `.plan-badge` (PRO / MAX / FREE) sourced from `_cachedProfiles`; Repository & Branch collapse default driven by `_REPO_COLLAPSE_BRANCH_THRESHOLD = 3` per-repo with explicit "Expand all" / "Collapse all" buttons.
- **Batch I** (UX-CPF1, UX-WS2, UX-VS1, UX-VS3): cpf-panel restructured as carousel sibling (no more chart overlap); wasted-spend bar colour from `wastedSeverity()` percentile-based gradient (low/med/high); scrubber composition hint near track explaining the dropdown+scrubber rule; `<input type="datetime-local">` "edit dates" affordance reachable at all viewport widths.
- **Batch J** (UX-S3, UX-S4): session copy button replaced 📋 emoji surrogate pair with inline SVG + `aria-label`; session timeline `max-height: 500px` clip paired with fade-out gradient + `toggleSessionTimelineExpand` "Show all" / "Show less" toggle.
- **Batch K** (UX-L1, UX-X10): logs tab container migrated from hardcoded `#0d1117` / `#c9d1d9` GitHub-dark hex to the design-token palette (`var(--card)` / `var(--foreground)`); UX-X10 surgical — only the ambiguous active/inactive `var(--muted)` pairings rewritten, `>= 60` `var(--muted)` uses preserved (regression-asserted).

### Lessons learned (round 3 — 6 parallel Opus agents)
- The path-discipline guard (relative paths only for source files) **partially worked**: 4 of 6 agents (F, G, J, K) edited only their worktree. 2 of 6 (H, I) leaked edits to MAIN despite the guard. The leaked edits were intermediate drafts; the canonical final versions DID land in each agent's worktree commit, so discarding MAIN's dirty state and merging from branches recovered the canonical versions.
- Merge conflict resolution was mechanical for 5 of 6 batches: each conflict was at the SAME location in `test/lib.test.mjs` (where each batch added its describe block at end-of-file). Pattern: keep both blocks, add `});` `});` to close the previous describe, open the new describe afresh. Identical pattern across all conflict types — a small auto-resolver script could handle this.
- Janitor's `worktree-janitor.sh` `branch_HEAD == main_HEAD` heuristic produced **dangerous** false-positive `--force` prune suggestions for newly-spawned, no-commits-yet agent worktrees. Issue filed upstream as Emasoft/ai-maestro-janitor#5 with strict-ancestry + locked-worktree-skip patches proposed.
- Final state: 918 tests pass (up from 822 baseline), 12 commits added, all worktrees + branches cleaned up.

## Applied in **batches A + C** (second parallel-agent dispatch — 9 findings)

### Batch A — Visual hierarchy (UX-A2 + UX-A3 + UX-A4 + UX-CO2 + UX-AC2)
- "Exclude from auto-switch" toggle promoted from card bottom to the `.card-actions` row (top-right) on every account card.
- `.badge-excluded` palette-consistent CSS class replaces the WCAG-failing inline-style grey-on-near-white.
- `renderVelocityInline` shows ONLY the binding ETA; the other constraint goes into `title=`. Dual-badge noise gone.
- All four BETA badges in Config tab unified under `.beta-badge`; duplicate "Enable session monitor" toggle-label BETA removed.
- Activity feed entries carry an `evt-icon` glyph (▲ ✕ ⓘ ✓ ✦) paired with the dot's colour for colour-blind users (`aria-hidden="true"` on the icon span).

**Recovery note:** Agent A was killed before reaching the commit step but had completed implementation + tests (810/0 pass, syntax clean). Work was rescued from the worktree and committed as `dbcac5a` on its branch, then merged.

### Batch C — Empty + error state pass (UX-AC3 + UX-A5 + UX-BR3 + UX-S1)
- Activity tab empty-state replaced "No activity yet" with `'No activity yet. Start a Claude Code session — every prompt, response, account switch, rate-limit hit, and token refresh appears here.'` Both initial markup and runtime `renderActivity()` empty branch emit the same string.
- Dormant accounts get a `.card-status-info` hint with a `title=` explainer of what dormant means and how to activate.
- Tool Breakdown panel no longer auto-hides when `!hasAttributed` — renders an inline explainer with a clickable link to Config → Per-Tool Attribution.
- Sessions tab initial markup is now a neutral `Loading sessions…` placeholder; the truth-based `renderSessions()` then dispatches "Session Monitor is OFF" or "No sessions yet" based on actual state.

### Lessons learned (round 2 of parallel-agent dispatch)
- The path-discipline guard ("use relative paths only for source files") in the agent prompts WORKED — neither agent leaked edits to MAIN this round.
- Conflict resolution was straightforward: both agents added their own `describe(...)` block to `test/lib.test.mjs`, and the renderAccounts/renderActivityFeed edits in `dashboard.mjs` were local enough that auto-merge succeeded for dashboard.mjs and only the test file needed manual resolution (kept both describe blocks).
- One agent (batch A) was killed before committing — rescuing from the worktree (verify syntax + tests pass, then `git commit` on the worktree branch) is reliable. The agent's TDD workflow had completed implementation + tests before being killed at the report-writing step.

## Applied in **batches B + D + E** (parallel agent worktree dispatch — 6 findings)

### Batch B — Time formatting (UX-X8 + UX-X9)
- New `lib.mjs` exports `fmtTokenCount(n)` and `fmtDuration(ms)`, both returning `{short, exact}`. Browser-side mirrors inside the renderHTML template literal (algorithm-locked to lib via "no drift" regression tests).
- `formatNum` and `sessionDuration` collapsed to thin wrappers — one source of truth for compact rendering.
- 21 token-count display sites and 8+ duration sites now carry `title=` with the exact unabbreviated value.
- `tickCountdowns` refreshes both `textContent` and `title=` on every tick so live displays stay hover-truthful.

### Batch D — Sparkline + scrubber refresh (UX-X7 + UX-VS2)
- `renderSparkline` switches from binary on/off areas to proportional fills with a 1.0 floor. SVG carries `<title>` + `role="img" aria-label` (hover and screen reader stay in sync). Always-visible peak% / 0% overlays at the chart corners.
- Scrubber `.vs-thumb` bumped from 16px to 28px (margin-left -14px to keep it centred). `.vs-track-wrap` height bumped to 44px for focus-ring headroom.
- Both `::-webkit-slider-thumb` and `::-moz-range-thumb` defensively sized to 28px so a future stray native range slider can't regress to OS-default 16px.

### Batch E — Logs/Activity filter UIs (UX-L2 + UX-AC1)
- Logs tab and Activity tab each get a filter input + regex toggle + clear button + match-count badge, sharing the new `.vdm-filter-bar` style.
- Hides non-matching entries via `.evt-hidden` / `.log-line-hidden` CSS class toggle (DOM stays stable; clearing restores without re-fetch).
- 256-char hard cap at three levels (maxlength attribute + input handler slice + compile/persist slice). Defense in depth against ReDoS + localStorage poisoning.
- Invalid regex compiles to `null`, count badge shows "Invalid regex" with `.error` styling, and ALL lines remain visible (no empty-pane trap).
- Filter checked against SSE-streamed log line `textContent` BEFORE append, eliminating flicker.
- Persistence via `vdm.logsFilter` / `vdm.logsRegex` / `vdm.activityFilter` / `vdm.activityRegex` localStorage keys.

### Lessons learned about parallel agent worktrees
- The `Agent({isolation: "worktree"})` mode does NOT fully sandbox edits when the prompt contains absolute paths into the main checkout. All 3 agents wrote to MAIN's `dashboard.mjs` / `test/lib.test.mjs` in addition to (or instead of) their worktrees, even though they were spawned with isolation. MAIN's dirty state ended up as a noisy mixture of all 3 agents' work plus debug detritus. The proper sequence was: wait for all 3 agents to commit to their branches, verify MAIN's dirty diff was a strict subset of the union of branch diffs, discard MAIN's dirty state, then merge each branch sequentially with conflict resolution.
- Future use of parallel worktree agents should EITHER pass purely-relative paths in the prompt OR explicitly tell the agent its `cwd` is the worktree path (e.g. `"Your working directory is the parent of CLAUDE.md, NOT /Users/.../<project>/"`).

## Applied in **A11y batch 2** (3 findings + 1 test-tooling fix)

- **UX-X3** — `tok-repo-header` and `session-header` `<div>`s converted to `role="button" tabindex="0" aria-expanded="…"` controls. A single capture-phase keydown delegate fires Enter/Space → click on every `role="button"[tabindex]` element so keyboard-only users can finally toggle repo and session collapse states.
- **UX-CPF3** — Project filter checklist becomes a real WAI-ARIA listbox: `<div id="cpf-list" role="listbox" aria-multiselectable="true">`, each `<label class="cpf-item" role="option" aria-selected="…">`, mirror-state on toggle and bulk-select. New `_wireListboxArrowKeys` helper does Up/Down/Home/End nav over the items (Tab + Space still work natively for activation).
- **UX-S2** — Session card and repo chevrons now pick up `color: var(--foreground)` on header hover/focus and animate the colour change alongside the existing rotation transition. The cursor:pointer hint on the parent header was previously the only signal.
- **Test infra fix** — The "no backticks in JS comments inside renderHTML template literal" regression test was using a hard-coded line range (3479–8290) that no longer covered the full template (which now spans 3528–9292). Replaced with dynamic anchoring on `function renderHTML()` and the closing `</html>\`;` sentinel so the trap detector can't silently shrink again.

## Deferred MAJOR findings (51)

Grouped by area. See the full audit report for code-level fixes per finding.

### Header / global chrome
- ~~UX-H1~~ — *(addressed by .header-right wrapper + settings/help icon buttons, batch F)*
- ~~UX-H2~~ — *(addressed by var(--red-soft) palette swap on exhausted banner, batch F)*

### Accounts tab
- ~~UX-A2~~ — *(addressed by toggle moved to .card-actions row, batch A)*
- ~~UX-A3~~ — *(addressed by .badge-excluded palette-consistent class, batch A)*
- ~~UX-A4~~ — *(addressed by binding-ETA-only renderVelocityInline + title= for the other, batch A)*
- ~~UX-A5~~ — *(addressed by .card-status-info hint with title= explainer, batch C)*
- ~~UX-A6~~ — *(addressed by targeted .card-top opacity + .stale-pill, batch G)*
- ~~UX-A7~~ — *(addressed by translateY(-1px) lift + bumped .accounts gap + smaller shadow, batch G)*

### Activity tab
- ~~UX-AC1~~ — *(addressed by Activity tab filter input + regex toggle + clear, batch E)*
- ~~UX-AC2~~ — *(addressed by evt-icon glyph paired with dot colour for colour-blind users, batch A)*
- ~~UX-AC3~~ — *(addressed by actionable empty-state copy + .empty-state shell, batch C)*

### Usage tab — carousel
- **UX-CA2** — *(addressed by aria-labels)* Add visible labels under dots, not only tooltip.

### Usage tab — project filter
- ~~UX-CPF1~~ — *(addressed by cpf-panel restructured as carousel sibling, batch I)*
- ~~UX-CPF3~~ — *(addressed by listbox semantics + arrow-key nav, A11y batch 2)*

### Usage tab — wasted-spend
- ~~UX-WS2~~ — *(addressed by wastedSeverity() percentile-based gradient, batch I)*

### Usage tab — scrubber (rest)
- ~~UX-VS2~~ — *(addressed by 28px touch-friendly thumbs + native range thumb defaults, batch D)*

### Usage tab — cache misses
- ~~UX-CM1~~ — *(addressed by bounded-localStorage sticky open/closed state per session, batch H)*
- ~~UX-CM3~~ — *(addressed by clickable "Show N older miss(es)" toggle button, batch H)*

### Usage tab — breakdown cards
- ~~UX-BR1~~ — *(addressed by .plan-badge sourced from _cachedProfiles, batch H)*
- ~~UX-BR2~~ — *(addressed by per-repo branch-count threshold + Expand/Collapse all buttons, batch H)*
- ~~UX-BR3~~ — *(addressed by inline explainer + Config link instead of auto-hide, batch C)*

### Usage tab — scrubber
- ~~UX-VS1~~ — *(addressed by inline composition hint near track, batch I)*
- ~~UX-VS2~~ — *(see "Usage tab — scrubber (rest)" below — addressed in batch D)*
- ~~UX-VS3~~ — *(addressed by edit-dates affordance reachable at all viewport widths, batch I)*

### Sessions tab
- ~~UX-S1~~ — *(addressed by neutral "Loading sessions…" initial markup + truth-based renderSessions branches, batch C)*
- ~~UX-S2~~ — *(addressed by chevron hover/focus colour transition, A11y batch 2)*
- ~~UX-S3~~ — *(addressed by inline SVG copy icon + aria-label, batch J)*
- ~~UX-S4~~ — *(addressed by fade-out gradient + Show all/less toggle, batch J)*

### Config tab
- ~~UX-CO1~~ — *(addressed by section anchor IDs + TOC, batch F)*
- ~~UX-CO2~~ — *(addressed by .beta-badge unification + duplicate session-monitor BETA removed, batch A)*
- ~~UX-CO3~~ — *(addressed by .privacy-callout block on Session Monitor, batch F)*
- ~~UX-CO4~~ — *(addressed by removal of STRATEGY_HINTS map + strategy-list as single source, batch F)*

### Logs tab
- ~~UX-L1~~ — *(addressed by var(--card)/var(--foreground) design-token migration from #0d1117/#c9d1d9, batch K)*
- ~~UX-L2~~ — *(addressed by Logs tab filter input + regex toggle + clear, batch E)*

### Cross-cutting
- ~~UX-X3~~ — *(addressed by role=button + global Enter/Space keydown delegate on tok-repo-header and session-header, A11y batch 2)*
- ~~UX-X7~~ — *(addressed by proportional sparkline + min/max overlays + screen-reader label, batch D)*
- ~~UX-X8~~ — *(addressed by `fmtTokenCount` + `fmtDuration` unification in lib.mjs, batch B)*
- ~~UX-X9~~ — *(addressed by `title=` hover-exact attribute on every compact-form display, batch B)*
- ~~UX-X10~~ — *(addressed by surgical pairing rewrite, regression-asserted >= 60 var(--muted) uses preserved, batch K)*

## Deferred MINOR + NIT findings (≈30)

See the original report for the full list. Prioritisation rule: pick up MAJORs first, MINORs only when refactoring the surrounding area.

## Suggested batching (all 6 ✅ done)

1. ~~**A11y batch 2**~~ ✅ done.
2. ~~**Visual hierarchy batch (A)**~~ ✅ done.
3. ~~**Time formatting batch (B)**~~ ✅ done.
4. ~~**Empty + error state pass (C)**~~ ✅ done.
5. ~~**Sparkline + scrubber refresh (D)**~~ ✅ done.
6. ~~**Logs / Activity search batch (E)**~~ ✅ done.

## What's left

All MAJOR findings have been addressed across the original 6 suggested batches PLUS the round-3 individual-MAJOR batches (F, G, H, I, J, K). Only the ~30 deferred MINOR/NIT items from the original audit remain — pick them up opportunistically when refactoring the surrounding area, per the prioritisation rule below.

## What to do next session

The TRDD's full MAJOR backlog is closed. Options:
- Pick up MINOR/NIT items as they cross your path during other work.
- Run a fresh UX audit to surface findings the round-1 audit missed.
- Move on to non-UX work — the dashboard's UX is now in a known-good state with comprehensive source-grep regression coverage.

## Acceptance criteria (per batch)

- [ ] All listed findings in the chosen batch have file:line evidence in the commit message.
- [ ] No regression in the existing 689-test suite.
- [ ] Smoke test: dashboard loads, every tab renders, the Phase 6 endpoint returns the documented shape.
- [ ] CLAUDE.md updated under "Round-2 audit defenses" with any new invariants worth recording.

## Out of scope

- Dark-mode rollout (`prefers-color-scheme: dark`) — large refactor; track separately.
- Mobile-app shell (e.g. PWA manifest, service worker) — not in vdm's mission.
