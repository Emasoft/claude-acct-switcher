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
echo "What it does: runs Codex review (--uncommitted, --effort high) on"
echo "every commit and BLOCKS the commit if Codex flags any MINOR / MAJOR"
echo "/ CRITICAL finding. NIT findings do NOT block."
echo
echo "Bypass any individual commit (emergency only): git commit --no-verify"
