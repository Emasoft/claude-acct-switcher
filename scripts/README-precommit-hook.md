# Pre-commit code-review hook

A git `pre-commit` hook that runs an AI code review on the staged diff and
**blocks the commit** if any MINOR-or-above finding is reported.

## What it does on every commit

1. Tries: `codex review --uncommitted -c model_reasoning_effort="high"`
2. If codex fails (rate-limited / out of credits / network / internal error):
   falls back to `claude --agent chk-review-opus-agent --dangerously-skip-permissions`
   (uses your Claude OAuth Pro/Max subscription — does **not** consume API tokens).
3. Blocks the commit if the reviewer flags any **CRITICAL / MAJOR / MINOR**
   finding. **NIT** findings do **not** block.
4. Writes the full review report to disk for inspection.

## Install on a single repo (recommended)

From any repo where you want the hook active (substitute the actual path to
your local clone of `claude-acct-switcher` for `<vdm-repo>`):

```bash
cd /path/to/your-repo
python3 <vdm-repo>/scripts/install-precommit-hook.py --local
```

If you keep the vdm clone in a known location, you can alias the path:

```bash
# Once, in your shell rc:
alias install-vdm-hook='python3 "$(git -C ~/Code/claude-acct-switcher rev-parse --show-toplevel)/scripts/install-precommit-hook.py"'
# Then in any repo:
cd /path/to/your-repo && install-vdm-hook --local
```

This:
- Copies the hook to `.git/hooks/pre-commit` (this clone only)
- Writes `~/.claude/agents/chk-review-opus-agent.md` if missing (shared by all
  repos that use the hook — never overwritten without `--force-replace-agent`)

If `~/.claude/agents/chk-review-opus-agent.md` is freshly written, **restart
Claude Code** so it picks up the new agent. Otherwise the Opus fallback won't
work (codex still works without a restart).

## Install globally (across all git repos)

Not recommended — the hook spends OAuth/codex tokens on every commit, in every
repo, regardless of how trivial the change is.

If you really want it everywhere:

```bash
python3 /path/to/claude-acct-switcher/scripts/install-precommit-hook.py --global
```

This sets `git config --global core.hooksPath ~/.config/git/hooks/` and drops
the hook there. **Warning:** if you already have a global `core.hooksPath` for
another tool (e.g. husky, lefthook), the installer prints an informational
warning explaining that the hook will be inert until you either (a) copy
`pre-commit` into your existing hooksPath dir, or (b) unset the override.
The install still proceeds (writes to the default location) so the hook is
ready to fire as soon as the override is cleared.

## Tunables (env vars, set per-shell or per-commit)

| Var | Default | Purpose |
|-----|---------|---------|
| `CODEX_TIMEOUT_SEC` | 1800 | Cap on codex review (seconds) |
| `OPUS_TIMEOUT_SEC` | 1800 | Cap on opus fallback (seconds) |
| `PRECOMMIT_REPORTS_DIR` | (auto) | Override codex report dir (absolute path) |
| `PRECOMMIT_OPUS_REPORTS_DIR` | (auto) | Override opus report dir (absolute path) |

### Default report locations

Three-tier resolution (first match wins):

1. `$PRECOMMIT_REPORTS_DIR` if set
2. `<repo-root>/reports/codex-review/pre-commit/` if `/reports/` is in this
   repo's `.gitignore` (e.g. `claude-acct-switcher` already gitignores
   `/reports/`, so reports stay inside the repo but never get committed)
3. `~/.cache/codex-precommit/<repo-name>/` (default — keeps the working tree
   clean of audit artefacts)

Same logic applies to the Opus fallback under
`reports/codex-review/pre-commit-opus/` or
`~/.cache/codex-precommit/<repo-name>/opus/`.

## Bypass an individual commit (emergency only)

```bash
git commit --no-verify
```

This skips the hook entirely. Use for genuine emergencies (broken upstream,
network outage with no codex *and* no claude reachable, hot-fix at 3am). Don't
make it a habit — the hook exists to catch bugs before they land.

## Other installer flags

| Flag | Purpose |
|------|---------|
| `--local` | Install for this repo only (default behaviour) |
| `--global` | Install across all git repos via `core.hooksPath` |
| `--hook-only` | Install/refresh the hook script but skip the agent file |
| `--force-replace-agent` | Overwrite an existing `chk-review-opus-agent.md` |
| `--emit-agent <path>` | Write the embedded agent .md to a file and exit |

## How to know it's working

After the next `git commit` on a repo where the hook is installed, you'll see:

```
[pre-commit] Running codex review (effort=high) on staged + untracked files…
[pre-commit] Report: /path/to/reports/codex-review/pre-commit/<timestamp>.md
[pre-commit] No MINOR-or-above findings. Commit allowed.
```

If codex is unavailable, you'll see:

```
[pre-commit] codex failed (exit=N) — falling back to Opus subagent…
[pre-commit] Opus report: /path/to/reports/.../opus/<timestamp>.md
[pre-commit] No MINOR-or-above findings. Commit allowed.
```

If a MINOR-or-above issue is found:

```
[pre-commit] BLOCKED — N MINOR-or-above findings:
| <file>:<line> | MINOR | <message> |
[pre-commit] Full report: /path/to/...
[pre-commit] Fix the findings or run `git commit --no-verify` to bypass.
```

## Uninstall

For a single repo:
```bash
rm /path/to/your-repo/.git/hooks/pre-commit
```

For a global install:
```bash
git config --global --unset core.hooksPath
rm ~/.config/git/hooks/pre-commit
```

Optionally remove the shared agent (only if no other repo's hook uses it):
```bash
rm ~/.claude/agents/chk-review-opus-agent.md
```

## Source files

| File | Purpose |
|------|---------|
| `scripts/install-precommit-hook.py` | Installer (Python, embeds the agent .md) |
| `scripts/git-hooks/pre-commit` | Source of truth for the hook script |
| `~/.claude/agents/chk-review-opus-agent.md` | Opus fallback subagent (auto-installed) |
