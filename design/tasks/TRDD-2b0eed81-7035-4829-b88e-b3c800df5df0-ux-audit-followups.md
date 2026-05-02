# TRDD-2b0eed81 — UX audit follow-up batch 2

**TRDD ID:** `2b0eed81-7035-4829-b88e-b3c800df5df0`
**Filename:** `design/tasks/TRDD-2b0eed81-7035-4829-b88e-b3c800df5df0-ux-audit-followups.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** In progress (batches 2, B, D, E of 6 done — 4/6 remaining)
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
- **UX-H1** — Header right-side empty; add settings/help affordance.
- **UX-H2** — Exhausted banner colour scheme clashes with light dashboard.

### Accounts tab
- **UX-A2** — "Exclude from auto-switch" toggle buried at card bottom.
- **UX-A3** — `excluded` badge contrast poor and unstyled.
- **UX-A4** — Two ETA badges (5h + 7d) on a single row become noise.
- **UX-A5** — Dormant accounts have no actionable hint.
- **UX-A6** — Stale account opacity hides info instead of dimming chrome.
- **UX-A7** — Card hover `box-shadow: var(--shadow-lg)` overlaps neighbour card.

### Activity tab
- ~~UX-AC1~~ — *(addressed by Activity tab filter input + regex toggle + clear, batch E)*
- **UX-AC2** — Activity dot colour is the only differentiator for event severity.
- **UX-AC3** — Empty state "No activity yet" provides no next action.

### Usage tab — carousel
- **UX-CA2** — *(addressed by aria-labels)* Add visible labels under dots, not only tooltip.

### Usage tab — project filter
- **UX-CPF1** — Multi-select dropdown overlaps carousel controls.
- ~~UX-CPF3~~ — *(addressed by listbox semantics + arrow-key nav, A11y batch 2)*

### Usage tab — wasted-spend
- **UX-WS2** — Bars use fixed yellow regardless of severity (no gradient by spend level).

### Usage tab — scrubber (rest)
- ~~UX-VS2~~ — *(addressed by 28px touch-friendly thumbs + native range thumb defaults, batch D)*

### Usage tab — cache misses
- **UX-CM1** — First session details auto-open on every page load (sticky preference?).
- **UX-CM3** — `… and N older miss(es)` truncation hides actionable detail.

### Usage tab — breakdown cards
- **UX-BR1** — `Account Breakdown` rows have no plan badge / tier indicator.
- **UX-BR2** — `Repository & Branch` collapse-all default depends on count, surprising users.
- **UX-BR3** — `Tool Breakdown` panel auto-hides without explaining "why empty".

### Usage tab — scrubber
- **UX-VS1** — Scrubber's role conflicts with `tok-time` dropdown — both filter time.
- ~~UX-VS2~~ — *(see "Usage tab — scrubber (rest)" below — addressed in batch D)*
- **UX-VS3** — Fallback `<input type="datetime-local">` only shown at <600px.

### Sessions tab
- ~~UX-S2~~ — *(addressed by chevron hover/focus colour transition, A11y batch 2)*
- **UX-S3** — Copy button uses 📋 emoji that won't render on all platforms.
- **UX-S4** — Session timeline `max-height: 500px` clips long sessions silently.

### Config tab
- **UX-CO1** — Config sections have no anchor links / search.
- **UX-CO2** — BETA badges are visually loud and repeated 4 times.
- **UX-CO3** — Session Monitor description hides serious privacy info.
- **UX-CO4** — Strategy hint + strategy-list duplicate the same information.

### Logs tab
- **UX-L1** — Log container uses dark theme inside light dashboard.
- ~~UX-L2~~ — *(addressed by Logs tab filter input + regex toggle + clear, batch E)*

### Cross-cutting
- ~~UX-X3~~ — *(addressed by role=button + global Enter/Space keydown delegate on tok-repo-header and session-header, A11y batch 2)*
- ~~UX-X7~~ — *(addressed by proportional sparkline + min/max overlays + screen-reader label, batch D)*
- ~~UX-X8~~ — *(addressed by `fmtTokenCount` + `fmtDuration` unification in lib.mjs, batch B)*
- ~~UX-X9~~ — *(addressed by `title=` hover-exact attribute on every compact-form display, batch B)*
- **UX-X10** — Many controls use `var(--muted)` for both placeholder text and active state.

## Deferred MINOR + NIT findings (≈30)

See the original report for the full list. Prioritisation rule: pick up MAJORs first, MINORs only when refactoring the surrounding area.

## Suggested batching (when work resumes)

1. ~~**A11y batch 2**~~ ✅ done — see "Applied in A11y batch 2" above.
2. **Visual hierarchy batch** (UX-A2/A3/A4 + UX-CO2 + UX-AC2): account-card layout polish, BETA badge consolidation, activity dot icon redesign.
3. ~~**Time formatting batch (B)**~~ ✅ done.
4. **Empty + error state pass** (UX-AC3 + UX-A5 + UX-BR3 + UX-S1): every empty state suggests a next action.
5. ~~**Sparkline + scrubber refresh (D)**~~ ✅ done.
6. ~~**Logs / Activity search batch (E)**~~ ✅ done.

## What to do next session

Two batches remain:
- **Visual hierarchy batch** (UX-A2/A3/A4 + UX-CO2 + UX-AC2) — highest-impact remaining: account-card noise, BETA badge spam, undifferentiated activity feed.
- **Empty + error state pass** (UX-AC3 + UX-A5 + UX-BR3 + UX-S1) — every empty state suggests a next action.

Both touch `renderAccounts` and `renderActivityFeed`, so they should run SEQUENTIALLY in main (not in parallel worktree branches) to avoid the merge-conflict + worktree-isolation-leak problems documented in "Lessons learned about parallel agent worktrees" above.

## Acceptance criteria (per batch)

- [ ] All listed findings in the chosen batch have file:line evidence in the commit message.
- [ ] No regression in the existing 689-test suite.
- [ ] Smoke test: dashboard loads, every tab renders, the Phase 6 endpoint returns the documented shape.
- [ ] CLAUDE.md updated under "Round-2 audit defenses" with any new invariants worth recording.

## Out of scope

- Dark-mode rollout (`prefers-color-scheme: dark`) — large refactor; track separately.
- Mobile-app shell (e.g. PWA manifest, service worker) — not in vdm's mission.
