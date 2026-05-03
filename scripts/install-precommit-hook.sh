#!/usr/bin/env bash
# install-precommit-hook.sh
#
# Atomically installs scripts/git-hooks/pre-commit into .git/hooks/pre-commit.
# Run this once per fresh clone. Idempotent: re-running replaces any
# previous copy in place via a temp+rename swap so an in-progress commit
# can never observe a half-written hook.
#
# This is a per-clone install because .git/ is not version-controlled.
# An alternative would be to set `git config core.hooksPath scripts/git-hooks`
# but THAT would override the global core.hooksPath that vdm's own
# install-hooks.sh uses for the prepare-commit-msg Token-Usage trailer
# hook. Per-clone copy keeps both wired without conflict.
#
# Bypass any individual commit (emergency only):  git commit --no-verify

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "Not inside a git working tree." >&2
  exit 1
}

SRC="$ROOT/scripts/git-hooks/pre-commit"
DST="$ROOT/.git/hooks/pre-commit"

if [[ ! -f "$SRC" ]]; then
  echo "Source hook not found: $SRC" >&2
  exit 1
fi

# Atomic install: copy to a temp file in the same directory, set the
# executable bit, then rename over the destination. `install -m 755`
# does the same thing in a single call and is POSIX.
install -m 755 "$SRC" "$DST"

echo "Installed pre-commit hook -> $DST"
echo "Source of truth (git-tracked) -> $SRC"
echo
echo "What it does: on every commit, runs"
echo "  codex review --uncommitted -c model_reasoning_effort=\"high\""
echo "and BLOCKS the commit if the reviewer flags any MINOR / MAJOR /"
echo "CRITICAL finding. NIT findings do NOT block."
echo
echo "Fallback: if codex fails (out of credits / rate-limited / network /"
echo "internal error), the hook auto-falls back to a Claude Opus review"
echo "delivered via the custom subagent at"
echo "  ~/.claude/agents/review-opus-agent.md"
echo "launched with"
echo "  claude --agent review-opus-agent --dangerously-skip-permissions"
echo "(which uses the OAuth Pro/Max subscription, not metered API tokens)."
echo "The agent's review report lands at"
echo "  <repo>/reports/review-opus-agent/<ts>-pre-commit.md"
echo "Same severity rules apply to whichever reviewer produced the report."
echo
echo "Note: --worktree is intentionally NOT used. \`git worktree add\`"
echo "fails inside a pre-commit hook (the parent commit holds the index)."
echo "The agent runs in the main checkout cwd; safety comes from the"
echo "agent's tool list (no Edit) and explicit no-mutation instructions."
echo
echo "REQUIREMENT: ~/.claude/agents/review-opus-agent.md must exist AND"
echo "Claude Code must be restarted at least once after the agent file"
echo "was created — Claude Code only discovers new subagents at startup."
echo
echo "Tunables (env vars):"
echo "  CODEX_TIMEOUT_SEC  default 1800 (30 min cap on codex)"
echo "  OPUS_TIMEOUT_SEC   default 1800 (30 min cap on opus fallback)"
echo
echo "Bypass any individual commit (emergency only): git commit --no-verify"
