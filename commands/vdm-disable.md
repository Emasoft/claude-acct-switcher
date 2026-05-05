---
description: Kill switch — make vdm behave as if it was never installed (files preserved)
allowed-tools: Bash(vdm disable)
---

Activates the kill-switch marker so:
- Every Claude Code hook in `~/.claude/settings.json` exits at byte 1, before any curl
- The git `prepare-commit-msg` hook stops appending `Token-Usage:` trailers
- The dashboard process is stopped and refuses to auto-start from new shells
- New shells skip exporting `ANTHROPIC_BASE_URL` (claude hits Anthropic directly)

Does NOT delete any files, accounts, hooks entries, or rc-block. Reversible
with `vdm enable`. Already-open shells still carry the env var — `unset
ANTHROPIC_BASE_URL` in each, or open new ones.

!`vdm disable`
