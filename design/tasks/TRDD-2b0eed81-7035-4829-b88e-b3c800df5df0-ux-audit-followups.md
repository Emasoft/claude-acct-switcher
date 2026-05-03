# TRDD-2b0eed81 — UX audit follow-up batch 2

**TRDD ID:** `2b0eed81-7035-4829-b88e-b3c800df5df0`
**Filename:** `design/tasks/TRDD-2b0eed81-7035-4829-b88e-b3c800df5df0-ux-audit-followups.md`
**Tracked in:** this repo (design/tasks/ is git-tracked)

**Status:** All 6 suggested batches + round-3 individual MAJORs (F, G, H, I, J, K) + round-4 MINOR/NIT cleanup pass (batch L, 11 codes) complete. **Round-2 audit fully closed: spark M (12 code-quality codes incl. 2 CRITICALs), spark N (19 UX2 CRITICAL+MAJOR codes), spark O (10 UX2 MINOR/NIT codes) all merged.** Test suite: 1002/0 (up from 689 baseline → +313 new source-grep regressions across the full backlog). See "Round-2 audit deliverables" + "Applied in spark batches M + N + O" below.
**Created:** 2026-05-02
**Source audit:** `reports/audit/20260502_154014+0200-ui-usability-audit-opus.md` (round 1, 95 findings, Opus)
**Round-2 UX audit:** `reports/audit/20260503_015904+0200-ui-usability-audit-round2-opus.md` (54 findings, Opus)
**Code-quality audit:** `reports/audit/20260503_015914+0200-code-quality-audit-opus.md` (13 findings, 2 CRITICAL, Opus)
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

## Applied in **batch L** (round-1 audit MINOR/NIT cleanup — 11 codes)

One Opus agent in an isolated worktree picked up the high-leverage MINOR/NIT items deferred by all prior batches. Path-discipline guard worked: agent committed cleanly to its branch with no MAIN leak.

| Code | Severity | Area | Fix |
|---|---|---|---|
| UX-H3 | MINOR | Header | "0 accounts connected" → ellipsis placeholder + sentinel text |
| UX-AC6 | NIT | Activity tab | escHtml() the evtTime() output for defense-in-depth |
| UX-CM5 | MINOR | Cache-miss card | null hit-rate gets neutral .unknown class (was red .low) |
| UX-S6 | MINOR | Sessions tab | sessionTimeAgo "0s ago" → "just now" for sub-5s gaps |
| UX-X11 | MINOR | Cross-cutting | webkit-scrollbar 6px → 10px with higher-contrast lane |
| UX-X12 | MINOR | Cross-cutting | global form-control font/colour inheritance |
| UX-X13 | MINOR | Cross-cutting | `<noscript>` banner hex → design tokens |
| UX-CO7 | NIT | Config tab | Per-Tool Attribution drops "PostToolBatch hook" jargon |
| UX-WS5 | MINOR | Wasted-spend | tooltip white-space: normal + max-width: 18rem |
| UX-F1 | NIT | Footer | hardcoded `#9ca3af` → var(--muted) |
| UX-L4 | MINOR | Logs tab | log-status reconnect attempt counter + yellow tint |

937 tests pass (up from 918 baseline = +19 source-grep regressions).

## Round-2 audit deliverables (2026-05-03)

After all round-1 MAJORs + MINOR/NITs were closed, two fresh Opus auditors ran in parallel:

### Code-quality audit — `reports/audit/20260503_015914+0200-code-quality-audit-opus.md`
- **2 CRITICAL** — `require()` is undefined in ESM, so `_rotateForensicLog` and `_rotateStartupLog` ALWAYS throw silently. `events.jsonl` and `startup.log` grow forever instead of rotating daily / pruning to 7 days. Documented invariant from CLAUDE.md is FALSE in production. Tests don't catch it because they don't exercise the rotation timer paths.
- **3 MAJOR** — `/api/logs/stream` writes 200 headers BEFORE the cap check (then can't 503); per-account permit's release/acquire race lets inflight slip past `CSW_MAX_INFLIGHT_PER_ACCOUNT`; `_runGit` cache TTL not invalidated on settings change.
- **5 MINOR + 3 NIT**.
- **No CLAUDE.md invariant violations** — the prior batches' source-grep regression tests are doing their job.

### UX audit round 2 — `reports/audit/20260503_015904+0200-ui-usability-audit-round2-opus.md`
- **2 CRITICAL** — undefined CSS variables (`--surface`, `--text-muted`, `--mono`, `--text`, `--muted-foreground`) referenced ~50 times but never declared in `:root`; toast collides with batch-F header gear/help icons at ≤720px viewport.
- **17 MAJOR** — `vsFormatDuration` for the scrubber is a third format outside batch-B's unification (UX2-X8); `LOG_TAG_COLORS` maps `warn` to red (semantic inversion); `_repoBranchExpandAll` only iterates over already-known repos; cache-miss card still defaults to `.low` red badge for null hit-rate (note: batch L addressed this, audit ran on f645084 before L landed); activity icon vocabulary overloaded; etc.
- **26 MINOR + 9 NIT**.

These two audits gave a fresh backlog. All 4 CRITICAL findings (2 from each audit) plus all MAJORs and a 10-code MINOR/NIT pass were closed by sparks M + N + O — see next section.

## Applied in **spark batches M + N + O** (round-2 + code-quality audit cleanup — 41 codes)

Three Spark agents launched in parallel, each in an isolated worktree on a separate audit lane to avoid file collisions. Sequential merge with mechanical conflict resolution at the test-file describe-block boundary; one semantic conflict in `dashboard.mjs` (UX2-BR3 between sparks N and O — N's interactive uncap-button kept, O's CSS-class refactor kept, N's incomplete duplicate CSS rule + O's redundant inline style removed).

### Spark M — Code-quality audit (12 codes — 2 CRITICAL + 3 MAJOR + 5 MINOR + 2 NIT)

| Code | Severity | Area | Fix |
|---|---|---|---|
| CQ-001 | CRITICAL | Log rotation | `_rotateForensicLog` uses ESM `appendFileSync` / `statSync` import (was `require()` → undefined → swallowed throw → no rotation) |
| CQ-002 | CRITICAL | Log rotation | `_rotateStartupLog` same fix — `startup.log` actually rotates daily + prunes past 7d now |
| CQ-003 | MAJOR | `/api/logs/stream` | `MAX_LOG_SUBSCRIBERS = 16` hoisted to module scope; cap-check moved BEFORE `res.writeHead(200)` (no more `ERR_HTTP_HEADERS_SENT` + stuck stream) |
| CQ-004 | MAJOR | Per-account permits | `acquireAccountPermit` `inflight++` in else-branch; `releaseAccountPermit` hands directly to next waiter — closes race that let inflight slip past `CSW_MAX_INFLIGHT_PER_ACCOUNT` |
| CQ-005 | MAJOR | Settings cache | `/api/settings` POST clears `_runGitCached` when `commitTokenUsage` / `sessionMonitor` / `perToolAttribution` actually changed (was waiting up to 30s for cached "no git here") |
| CQ-006 | MINOR | `loadProfiles` | `_dedupAlreadyRan` flag — destructive `deleteAccountKeychain` + `unlinkSync` only fire on first poll |
| CQ-007 | MINOR | Plaintext recovery | New `/api/cleanup-plaintext` GET (status, no path leak) + POST (retry); migration warning points at it |
| CQ-008 | MINOR | Auto-claim races | `_safeAutoClaim` + `_recentlyAutoClaimedSessions` Map (1000-entry FIFO, 60s TTL) wraps both prune paths |
| CQ-009 | MINOR | Activity log writes | Debounced via `_activityLogDirty` + 1s setTimeout; `flushActivityLogSync()` wired into `shutdown()` |
| CQ-010 | MINOR | `fetchAccountEmail` | `_connectDeadline` renamed to `_bodyDeadline` (matches what the timer actually does) |
| CQ-011 | NIT | `/api/session-*` | Returns 400 (not 500) for malformed JSON via `e.name === 'SyntaxError'` check |
| CQ-013 | NIT | `logForensicEvent` | Dead `if/else` removed — single direct `appendFileSync` call |
| CQ-012 | NIT | macOS Keychain | INFORMATIONAL — Apple's `security` CLI doesn't accept stdin password; alternative is interactive prompts on every account write. No action. |

19 source-grep regression tests pin every fix. Source: `reports/audit/20260503_015914+0200-code-quality-audit-opus.md` (commit `d5d72b6`, merged as `9243019`).

### Spark N — UX round-2 CRITICAL + MAJOR (19 codes)

| Code | Severity | Area | Fix |
|---|---|---|---|
| UX2-CSS1 | CRITICAL | Design tokens | `:root` declares `--surface`, `--text-muted`, `--text`, `--mono` aliases (~50 references previously fell through to `inherit/initial`) |
| UX2-X1 | CRITICAL | Toast positioning | At ≤720px the toast moves to `bottom: 1.5rem` (≤480px → `bottom: 1rem`) so the gear/help icons stay clickable |
| UX2-L1 | MAJOR | Logs colour map | `LOG_TAG_COLORS.warn` → yellow (was red == error); switch/proactive → cyan to free yellow |
| UX2-L2 + UX2-AC1 | MAJOR | Filter empty state | `_vdmShowFilterEmptyState` / `_vdmHideFilterEmptyState` helpers render in-pane `.empty-state` when filter matches zero |
| UX2-AC2 | MAJOR | Activity icons | `rate-limited` / `queue-depth-alert` use ⚠ (U+26A0) instead of ▲ (U+25B2) |
| UX2-S1 | MAJOR | Conflicts banner | Routed through `var(--red-soft)` / `var(--red-border)` / `var(--red)` design tokens (was raw GitHub-red hex) |
| UX2-S2 | MAJOR | Conflicts icon | Inline 12x12 `SESSION_WARNING_ICON_SVG` replaces ⚠ (renders identically across macOS / Linux / fallback fonts) |
| UX2-S3 | MAJOR | session-meta layout | `flex-wrap: wrap` + `padding-right: 2rem` so absolute `.session-copy-btn` doesn't overlay meta on hover |
| UX2-BR1 | MAJOR | Bulk-collapse stickiness | `_tokRepoUserPrefersAllCollapsed` override survives across freshly-discovered repos in the next 5s poll |
| UX2-BR2 + UX2-BR3 | MAJOR | "N more branches" footer | Promoted from non-clickable italic div to `<button class="tok-branch-uncap-toggle">` with `_toggleRepoBranchUncap`; CSS class replaces inline style triplet |
| UX2-CO1 | MAJOR | Em-dashes | `STRATEGY_DETAILS.{sticky,conserve,spread}.desc` + proxyEnabled toggle use proper U+2014 (—), not double-space-hyphen |
| UX2-CO2 | MAJOR | Config TOC | `position: sticky` removed (TOC pinned alone with no relationship to page header) |
| UX2-CO3 | MAJOR | Strategy XSS | Strategy-list innerHTML routes `s.name` / `s.desc` through `escHtml()` (defense-in-depth for future i18n loads) |
| UX2-A1 | MAJOR | acct-pref toggle palette | `.acct-pref-toggle.is-on` retoned from yellow (conflicted with .beta-badge) to `.badge-excluded` palette (muted/bg/border) |
| UX2-VS1 | MAJOR | Scrubber labels | Detect overlap (<8% apart on track) and merge into combined `<start> – <end>` label on start thumb |
| UX2-CA1 | MAJOR | Carousel layout shift | `.chart-carousel-inner` gets `min-height: 220px` (worst-case slide footprint) — no more 10s height jiggle |
| UX2-X2 | MAJOR | Tab badge | `color: var(--foreground)` instead of hardcoded `#000` (tokenised for future dark-mode) |
| UX2-X8 | MAJOR | Scrubber duration | `vsFormatDuration` delegates to `fmtDurationShort` for sub-14d ranges so scrubber matches activity feed |

32 source-grep regression tests pin all 19 codes. Source: `reports/audit/20260503_015904+0200-ui-usability-audit-round2-opus.md` (commit `3488d13`, merged as `757e3f5`).

### Spark O — UX round-2 MINOR/NIT cleanup (10 codes)

| Code | Severity | Area | Fix |
|---|---|---|---|
| UX2-L6 | NIT | filter-bar palette | `.vdm-filter-bar input.invalid` + `.vdm-filter-count.error` use `var(--red)` (was `#f85149`) |
| UX2-S6 | NIT | Sessions OFF empty state | Clickable `switchTab('config')` link instead of flowing prose |
| UX2-S4 | MINOR | Session-overhead tooltip | `fmtTokenCountExact(oh) + ' tokens'` + scope hint (preserves UX-X9 invariant; drops duplicate `(Haiku)`) |
| UX2-CO5 | NIT | Config TOC scroll | `html { scroll-behavior: smooth }` + `prefers-reduced-motion` opt-out guard |
| UX2-X5 | MINOR | tok-chart-label font | 0.5625rem (~9px) → 0.6875rem (~11px) to clear WCAG 1.4.4 floor |
| UX2-BR4 | MINOR | tok-repo-header hover | `background: var(--bg)` tint replaces `opacity: 0.8` (which was cancelling UX-S2's chevron colour-bump) |
| UX2-CA3 | MINOR | Carousel pause selector | `.chart-bar:hover` removed from `_carouselPaused` (selector lives in legacy stats chart, not in carousel) |
| UX2-A3 | MINOR | card-actions row-gap | `row-gap: 0.5rem` so wrapped action layouts get vertical breathing room |
| UX2-BR3 | MINOR | hidden-branches CSS class | Inline-style triplet promoted to `.tok-branch-hidden-summary` class |
| UX2-CPF2 | MINOR | cpf-toggle no-data marker | `data-no-data="true"` + dotted-yellow border when single-select repo has no data in window |

13 source-grep regression tests pin all 10 codes. Same audit source. Commit `a454c40`, merged as `89fd276`.

### Lessons learned (Spark M/N/O parallel dispatch)
- The path-discipline guard from earlier rounds worked partially — Spark M still landed initial edits in MAIN due to absolute paths in the prompt. Recovered via `git checkout HEAD -- dashboard.mjs test/lib.test.mjs` then re-applied to the worktree using relative paths. Future spark dispatch prompts: pass relative paths only OR explicitly state `cwd` is the worktree root.
- Semantic conflicts between sibling agents (UX2-BR3) are recoverable when each agent independently arrives at a good outcome — keep the better implementation, discard the duplicate CSS/inline-style anti-patterns. Confidence comes from the source-grep regression tests both agents wrote — when both new tests pass after the merge resolution, the conflict is correctly resolved.
- Round-2 audit ran on f645084 (before batch L landed), so a few audit codes were already addressed (e.g. UX2-CM1 ≈ UX-CM5). Spark O recognised these and skipped them with a "What was deliberately skipped" section in its report.

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

**Both audits fully closed.** Round-1 audit (95 findings, batches A–L) and round-2 audit (54 UX findings + 13 code-quality findings, sparks M–O) are addressed. Remaining items are explicitly deferred:

- **Round-2 UX MINORs deliberately skipped by spark O** (8 items): UX2-AC4 (already addressed; audit was outdated), UX2-S5 (addressed by batch L UX-S6), UX2-X7 (batch L UX-X13), UX2-WS1 (batch L UX-WS5), UX2-AC3 (collision risk with sibling agent's UX2-AC1), UX2-X4 (cross-cutting; overlapped UX2-X8), UX2-X6 (~30 sites of inline-style cleanup; pull as surrounding code is refactored), UX2-X10 (speculative — "worth verifying if the animation actually flashes").
- **Round-1 deferred MINOR + NIT (~30)** still listed in `Deferred MINOR + NIT findings` — pick up opportunistically.
- **CQ-012** (informational only — macOS Keychain argv exposure unavoidable per Apple's API).

## What to do next session

The TRDD's full MAJOR backlog is closed across both audit rounds. Options:
- Pick up the ~30 round-1 MINOR/NIT items + the 8 round-2 MINORs above when refactoring touches their area.
- Run a fresh UX audit to surface findings the first two audits missed.
- Move on to non-UX work — the dashboard's UX is now in a known-good state with 1002 source-grep regressions guarding the invariants documented in CLAUDE.md.

## Acceptance criteria (per batch)

- [x] All listed findings in the chosen batch have file:line evidence in the commit message.
- [x] No regression in the existing test suite (689 baseline → 1002 final, +313 new tests, 0 fail).
- [x] Smoke test: dashboard loads, every tab renders, the Phase 6 endpoint returns the documented shape.
- [x] CLAUDE.md updated under "UX batch invariants" + "Code-quality batch M invariants" sections with all new invariants worth recording (M, N, O — see CLAUDE.md lines ~237 onward).

## Out of scope

- Dark-mode rollout (`prefers-color-scheme: dark`) — large refactor; track separately.
- Mobile-app shell (e.g. PWA manifest, service worker) — not in vdm's mission.
