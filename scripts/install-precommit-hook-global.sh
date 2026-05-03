#!/usr/bin/env bash
# install-precommit-hook-global.sh
#
# GLOBAL install variant of the pre-commit Codex review gate. Drops the
# hook script into ~/.config/git/hooks/pre-commit and (only if needed)
# sets `git config --global core.hooksPath ~/.config/git/hooks` so EVERY
# git repo on this machine routes pre-commit through the gate.
#
# Compare to scripts/install-precommit-hook.sh which only installs into
# THIS clone's .git/hooks/pre-commit.
#
# Side-effects:
#   - Creates ~/.config/git/hooks/ if missing
#   - Copies (atomically, mode 755) scripts/git-hooks/pre-commit into it
#   - If `git config --global core.hooksPath` is unset, sets it
#   - Reports each step
#
# What this DOES NOT do:
#   - Touch any per-repo .git/hooks/  (per-repo overrides take precedence
#     over global core.hooksPath; you'll need to run the per-clone
#     installer in those repos too — printout below shows which repos
#     have a local override)
#   - Create or modify ~/.claude/agents/review-opus-agent.md  (you must
#     copy that file from this repo to ~/.claude/agents/ before the
#     fallback path can resolve the agent — Claude Code only discovers
#     subagents at startup)
#   - Touch reports gitignore in your other repos. The hook auto-routes
#     reports to ~/.cache/codex-precommit/<repo-basename>/ when the
#     target repo doesn't have /reports/ in .gitignore, so reports
#     never leak into commits.
#
# Bypass any individual commit (emergency only):  git commit --no-verify

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "Run this from inside the claude-acct-switcher (or any) git working tree." >&2
  exit 1
}

SRC="$ROOT/scripts/git-hooks/pre-commit"
DST_DIR="$HOME/.config/git/hooks"
DST="$DST_DIR/pre-commit"

if [[ ! -f "$SRC" ]]; then
  echo "Source hook not found: $SRC" >&2
  exit 1
fi

mkdir -p "$DST_DIR"

# Atomic install via `install -m 755` (single POSIX call).
install -m 755 "$SRC" "$DST"
echo "Installed pre-commit hook -> $DST"

# Decide whether to set core.hooksPath. We do NOT clobber an existing
# value because some users (and other plugins) have a deliberate path
# set; printing the conflict is less surprising than overwriting.
EXISTING="$(git config --global --get core.hooksPath 2>/dev/null || true)"
if [[ -z "$EXISTING" ]]; then
  git config --global core.hooksPath "$DST_DIR"
  echo "Set git config --global core.hooksPath = $DST_DIR"
elif [[ "$EXISTING" == "$DST_DIR" ]]; then
  echo "git config --global core.hooksPath already = $DST_DIR (no change)"
else
  echo
  echo "WARNING: git config --global core.hooksPath is already set to:"
  echo "    $EXISTING"
  echo "  not $DST_DIR"
  echo
  echo "Either:"
  echo "  (a) Move existing hooks from $EXISTING into $DST_DIR (preserves"
  echo "      both the codex pre-commit AND any other hooks living there)"
  echo "      and rerun:  git config --global core.hooksPath $DST_DIR"
  echo "  OR"
  echo "  (b) Copy the pre-commit hook into $EXISTING/pre-commit instead:"
  echo "      install -m 755 \"$SRC\" \"$EXISTING/pre-commit\""
  echo
fi

# Surface any repos that have a LOCAL core.hooksPath override that
# would BYPASS the global. We can't enumerate every repo on disk, but
# we can flag THIS clone if it overrides.
LOCAL="$(git -C "$ROOT" config --local --get core.hooksPath 2>/dev/null || true)"
if [[ -n "$LOCAL" && "$LOCAL" != "$DST_DIR" ]]; then
  echo "Note: this clone has a LOCAL core.hooksPath override:"
  echo "    $LOCAL"
  echo "  The global hook will NOT fire here. Use scripts/install-precommit-hook.sh"
  echo "  (the per-clone installer) for this repo specifically."
fi

cat <<'EOF'

What the hook does on every commit, in every repo:
  1. Tries: codex review --uncommitted -c model_reasoning_effort="high"
  2. If codex fails (rate-limited / out of credits / network /
     internal error): falls back to claude --agent review-opus-agent
     --dangerously-skip-permissions  (uses OAuth Pro/Max subscription).
  3. Blocks the commit if the reviewer flags any MINOR / MAJOR /
     CRITICAL finding. NIT findings do NOT block.
  4. Reports go to:
       - $REPO/reports/codex-review/pre-commit/   (when /reports/ is
         in that repo's .gitignore, e.g. claude-acct-switcher), OR
       - ~/.cache/codex-precommit/<repo-basename>/  (default — keeps
         the working tree clean of audit artefacts)

REQUIREMENT: ~/.claude/agents/review-opus-agent.md must exist.
Copy it once from this repo:
    cp ~/.../claude-acct-switcher/.../review-opus-agent.md ~/.claude/agents/
Then RESTART Claude Code so the new agent is discovered at startup.

Tunables (env vars, set per-shell or per-commit):
  CODEX_TIMEOUT_SEC          default 1800 (30 min cap on codex)
  OPUS_TIMEOUT_SEC           default 1800 (30 min cap on opus fallback)
  PRECOMMIT_REPORTS_DIR      override codex report dir (absolute path)
  PRECOMMIT_OPUS_REPORTS_DIR override opus  report dir (absolute path)

Bypass any individual commit (emergency only): git commit --no-verify
EOF
