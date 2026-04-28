#!/usr/bin/env bash
# install-hooks.sh — Shared hook installer for token usage tracking
# Sourced by install.sh, uninstall.sh, and vdm upgrade.
# Provides: install_hooks(), uninstall_hooks()
#
# Two hooks are installed:
# 1. Claude Code hooks in ~/.claude/settings.json (UserPromptSubmit + Stop)
# 2. Global git prepare-commit-msg hook for token usage trailers

# Detect dashboard port (respect CSW_PORT env var)
_VDM_PORT="${CSW_PORT:-3333}"
_VDM_HOOKS_MARKER="# vdm-token-usage"
_VDM_HOOKS_PATH_MARKER=".vdm-set-hooks-path"

install_hooks() {
  _install_claude_code_hooks
  _install_git_hook
}

uninstall_hooks() {
  _uninstall_claude_code_hooks
  _uninstall_git_hook
}

# ─────────────────────────────────────────────────
# Claude Code hooks (~/.claude/settings.json)
# ─────────────────────────────────────────────────

_install_claude_code_hooks() {
  local settings_dir="$HOME/.claude"
  local settings_file="$settings_dir/settings.json"
  local lock_dir="$settings_dir/.vdm-settings.lock.d"

  mkdir -p "$settings_dir" 2>/dev/null || true

  # Stock macOS does NOT ship flock(1); a mkdir-based mutex is the
  # portable serialisation primitive. Spin up to ~30s, then bail. The
  # python rewriter writes to a .tmp and os.replace()s atomically so an
  # OOM/SIGKILL between read and write never leaves a half-written file.
  #
  # `trap RETURN` does NOT fire on SIGKILL (kill -9), OOM-killer, or a
  # power loss — the lock dir would be orphaned forever and every
  # subsequent install/upgrade would block for 30s and bail. Detect a
  # stale lock by mtime: any lock dir older than 60 seconds is treated
  # as an orphan and reaped. The legitimate critical section here is
  # one python3 invocation that finishes in well under a second on any
  # machine vdm targets, so 60s is a safely loose threshold.
  local _lock_tries=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    # Reap stale lock if the existing dir is older than 60s.
    if [[ -d "$lock_dir" ]] && [[ -z "$(find "$lock_dir" -maxdepth 0 -mmin -1 2>/dev/null)" ]]; then
      rmdir "$lock_dir" 2>/dev/null && continue
    fi
    _lock_tries=$((_lock_tries + 1))
    if [[ $_lock_tries -ge 300 ]]; then
      echo -e "  ${YELLOW:-}Warning: Timed out waiting for settings.json lock${NC:-}" >&2
      return 1
    fi
    sleep 0.1
  done
  trap 'rmdir "$lock_dir" 2>/dev/null' RETURN

  # Gate flag for the high-frequency PostToolBatch subscription. The
  # dashboard's settings UI / vdm CLI toggles this flag file. Default:
  # NOT subscribed. Computed in bash so the python heredoc can stay
  # closed-quoted (no shell interpolation inside, modulo argv).
  local _per_tool_flag="$HOME/.claude/account-switcher/per-tool-attribution.flag"
  local _per_tool_enabled=0
  [[ -f "$_per_tool_flag" ]] && _per_tool_enabled=1
  if ! python3 - "$settings_file" "$_VDM_PORT" "$_per_tool_enabled" <<'PYEOF'
import json, os, sys

settings_file = sys.argv[1]
port = sys.argv[2]
per_tool_enabled = sys.argv[3] == '1'

# Load existing settings
settings = {}
if os.path.exists(settings_file):
    try:
        with open(settings_file) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        # Corrupt file — backup and start fresh
        backup = settings_file + '.vdm-backup'
        try:
            import shutil
            shutil.copy2(settings_file, backup)
        except:
            pass
        settings = {}

if not isinstance(settings, dict):
    settings = {}

# Phase G — managed-settings preflight. If an enterprise admin has set
# allowManagedHooksOnly:true (or disableAllHooks:true), every user-level
# hook vdm writes will be silently dropped at session start. The proxy keeps
# working (it sits below Claude Code via ANTHROPIC_BASE_URL) but
# token-tracking, commit trailers, and session boundaries all stop firing.
# We can't override the policy — only emit a warning so users notice.
# allowedHttpHookUrls is a separate allowlist; if it's set and doesn't
# permit our localhost URL, hooks are also silently dropped.
def _peek_managed_settings():
    candidates = [
        '/Library/Application Support/ClaudeCode/managed-settings.json',  # macOS
        '/etc/claude-code/managed-settings.json',                         # Linux/WSL
    ]
    drop_dir = '/Library/Application Support/ClaudeCode/managed-settings.d'  # macOS drop-in
    for p in candidates:
        if not os.path.exists(p):
            continue
        try:
            with open(p) as f:
                m = json.load(f)
            if not isinstance(m, dict):
                continue
            if m.get('disableAllHooks') is True:
                print(f'  [vdm] WARNING: {p} has disableAllHooks:true — vdm hooks will not fire', file=sys.stderr)
            if m.get('allowManagedHooksOnly') is True:
                print(f'  [vdm] WARNING: {p} has allowManagedHooksOnly:true — vdm hooks will be silently dropped at session start. Proxy still works; token tracking disabled.', file=sys.stderr)
            allowed = m.get('allowedHttpHookUrls')
            if isinstance(allowed, list) and allowed:
                # Crude wildcard match (supports trailing *).
                target = f'http://localhost:{port}'
                ok = any(u.replace('*', '').startswith(target) for u in allowed if isinstance(u, str))
                if not ok:
                    print(f'  [vdm] WARNING: {p} allowedHttpHookUrls does not permit {target}/* — vdm hooks will be silently dropped', file=sys.stderr)
        except Exception:
            # Don't fail install on managed-settings parse errors.
            pass

_peek_managed_settings()

# Ensure hooks structure
if 'hooks' not in settings:
    settings['hooks'] = {}
hooks = settings['hooks']

def ensure_hook(event_name, url):
    if event_name not in hooks:
        hooks[event_name] = []
    event_hooks = hooks[event_name]
    if not isinstance(event_hooks, list):
        event_hooks = []
        hooks[event_name] = event_hooks
    # Filter at the INNER hook level: entries can group multiple hooks
    # (matcher + N hooks). Stripping the whole entry whenever ONE inner
    # hook matches our path would delete unrelated user/Husky/git-lfs
    # hooks bundled into the same entry. Drop only OUR inner hook; keep
    # the entry if any other inner hooks remain.
    from urllib.parse import urlparse
    target_path = urlparse(url).path
    keep = []
    for entry in event_hooks:
        if not isinstance(entry, dict):
            keep.append(entry)
            continue
        inner = entry.get('hooks', [])
        if not isinstance(inner, list):
            keep.append(entry)
            continue
        new_inner = [
            h for h in inner
            if not (isinstance(h, dict) and urlparse(h.get('url', '')).path == target_path)
        ]
        if new_inner:
            # Keep entry with our hook stripped — preserves siblings.
            new_entry = dict(entry)
            new_entry['hooks'] = new_inner
            keep.append(new_entry)
        elif not inner:
            # Entry had no inner hooks to begin with — preserve as-is.
            keep.append(entry)
        # else: entry contained ONLY our hook — drop it entirely.
    keep.append({'hooks': [{'type': 'http', 'url': url, 'timeout': 5}]})
    hooks[event_name] = keep

# Subscribe to the full session lifecycle so we capture usage in every
# scenario. Event-list driven so the loop stays DRY across install +
# uninstall (uninstall mirrors this list exactly):
#   * SessionStart       — opens a session window before the first turn.
#   * UserPromptSubmit   — additional turn boundary; idempotent if the
#                          session is already open.
#   * Stop               — normal turn end; persists claimed usage.
#   * StopFailure        — rate-limit / auth error end; otherwise the
#                          session would die mid-stream and lose tokens.
#   * SubagentStop       — sub-agent task end so spawned-agent usage
#                          gets attributed instead of being swallowed
#                          by the orchestrator's claim window.
#   * SessionEnd         — end-of-session signal that fires once when the
#                          user quits Claude Code (Cmd-Q, terminal close,
#                          /exit). Stop/StopFailure don't fire when the
#                          user quits mid-turn, so without SessionEnd
#                          that turn's usage would be silently dropped
#                          (eventually picked up by the 24h auto-claim
#                          sweep, but with no proper attribution).
#   * SubagentStart      — pre-registers the sub-agent's session_id with
#                          the parent's repo/branch so SubagentStop's
#                          usage attributes correctly. Without this, the
#                          claim handler sees an unknown session and
#                          silently drops the tokens.
#   * PreCompact         — marks compaction boundary so subsequent
#                          input-token deltas don't count post-compaction
#                          context as "new" input on top of pre-compaction.
#   * PostCompact        — records post-compaction context size; pairs
#                          with PreCompact for boundary math.
#   * CwdChanged         — re-resolves repo/branch when the session does
#                          a `cd` between prompts. Without this, the
#                          pre-cd branch is used for tokens accrued
#                          post-cd until the next UserPromptSubmit.
#   * PostToolBatch      — gated by per-tool-attribution.flag (default
#                          off because this fires once per tool batch
#                          and would flood the dashboard). Enabled via
#                          `touch ~/.claude/account-switcher/per-tool-attribution.flag`.
#   * WorktreeCreate     — log new worktree to activity feed; mostly for
#                          correlation with branch-attribution shifts.
#   * WorktreeRemove     — load-bearing: a session in a removed worktree
#                          must invalidate its branch attribution so
#                          subsequent token rows don't reference a path
#                          that no longer exists. Re-resolves via the
#                          session's current cwd.
#   * TaskCreated        — agent-team task lifecycle; links the task_id
#                          to the parent session for SubagentStart/Stop
#                          log correlation. Attribution still flows
#                          through Subagent events.
#   * TaskCompleted      — pairs with TaskCreated to close out the
#                          activeTaskIds set on the parent session.
#   * TeammateIdle       — agent-teams idle marker. Activity-feed-only.
#   * Notification       — Phase G: hooks "auth_success" to refresh keychain
#                          immediately (otherwise vdm picks up the new
#                          token only on the next proxy request via
#                          autoDiscoverAccount). Also surfaces "idle_prompt"
#                          and "permission_prompt" in activity feed.
#   * ConfigChange       — Phase G: detects external rewrites of
#                          ~/.claude/settings.json (e.g. devcontainer rebuild,
#                          another tool installing hooks). vdm logs the event
#                          so users notice when their hook block is stomped.
#   * UserPromptExpansion— Phase G: fires on /skill-name and @-mention
#                          expansion. Lets the activity feed show "skill X
#                          ran" alongside the regular prompt.
#
# Phase G note: SessionStart was REMOVED from this list. The hook spec only
# allows type: "command" or "mcp_tool" for SessionStart; vdm's HTTP-type
# entry was being silently rejected by Claude Code. The duplicate
# UserPromptSubmit subscription (which posts to the same /api/session-start
# URL) covers the session-anchor signal with at most one prompt of latency.
# Re-adding SessionStart would require a command-type hook (e.g. curl) which
# adds a per-session-startup process spawn for marginal benefit.
events = [
    ('UserPromptSubmit', f'http://localhost:{port}/api/session-start'),
    ('Stop',             f'http://localhost:{port}/api/session-stop'),
    ('StopFailure',      f'http://localhost:{port}/api/session-stop'),
    ('SubagentStop',     f'http://localhost:{port}/api/session-stop'),
    ('SessionEnd',       f'http://localhost:{port}/api/session-end'),
    ('SubagentStart',    f'http://localhost:{port}/api/subagent-start'),
    ('PreCompact',       f'http://localhost:{port}/api/pre-compact'),
    ('PostCompact',      f'http://localhost:{port}/api/post-compact'),
    ('CwdChanged',       f'http://localhost:{port}/api/cwd-changed'),
    # Phase G — auth + config + skill-expansion observability.
    ('Notification',     f'http://localhost:{port}/api/notification'),
    ('ConfigChange',     f'http://localhost:{port}/api/config-change'),
    ('UserPromptExpansion', f'http://localhost:{port}/api/user-prompt-expansion'),
    # Phase E — worktree + agent-team event coverage. WorktreeRemove is
    # the load-bearing one: a session in a removed worktree must invalidate
    # its branch attribution. The others are mostly for activity-feed
    # correlation but are subscribed unconditionally for completeness.
    ('WorktreeCreate',   f'http://localhost:{port}/api/worktree-create'),
    ('WorktreeRemove',   f'http://localhost:{port}/api/worktree-remove'),
    ('TaskCreated',      f'http://localhost:{port}/api/task-created'),
    ('TaskCompleted',    f'http://localhost:{port}/api/task-completed'),
    ('TeammateIdle',     f'http://localhost:{port}/api/teammate-idle'),
]
if per_tool_enabled:
    events.append(('PostToolBatch', f'http://localhost:{port}/api/post-tool-batch'))

for event_name, url in events:
    ensure_hook(event_name, url)

# Atomic write: tmp + os.replace
tmp_file = settings_file + '.tmp'
with open(tmp_file, 'w') as f:
    json.dump(settings, f, indent=2)
os.replace(tmp_file, settings_file)
PYEOF
  then
    echo -e "  ${YELLOW:-}Warning: Failed to install Claude Code hooks${NC:-}" >&2
  fi
}

_uninstall_claude_code_hooks() {
  local settings_dir="$HOME/.claude"
  local settings_file="$settings_dir/settings.json"
  local lock_dir="$settings_dir/.vdm-settings.lock.d"
  [[ -f "$settings_file" ]] || return 0

  # Same mkdir-based mutex as _install. The python rewriter writes to a
  # .tmp and os.replace()s atomically. Match by URL path (not full URL)
  # so a port change between install and uninstall doesn't strand
  # entries with the old port. Same stale-lock reap as _install (see
  # the comment block there for rationale).
  local _lock_tries=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    if [[ -d "$lock_dir" ]] && [[ -z "$(find "$lock_dir" -maxdepth 0 -mmin -1 2>/dev/null)" ]]; then
      rmdir "$lock_dir" 2>/dev/null && continue
    fi
    _lock_tries=$((_lock_tries + 1))
    if [[ $_lock_tries -ge 300 ]]; then
      echo -e "  ${YELLOW:-}Warning: Timed out waiting for settings.json lock${NC:-}" >&2
      return 1
    fi
    sleep 0.1
  done
  trap 'rmdir "$lock_dir" 2>/dev/null' RETURN

  if ! python3 - "$settings_file" "$_VDM_PORT" <<'PYEOF'
import json, os, sys

settings_file = sys.argv[1]
port = sys.argv[2]

try:
    with open(settings_file) as f:
        settings = json.load(f)
except:
    sys.exit(0)

if not isinstance(settings, dict) or 'hooks' not in settings:
    sys.exit(0)

hooks = settings['hooks']

def remove_hook(event_name, url):
    if event_name not in hooks:
        return
    event_hooks = hooks[event_name]
    if not isinstance(event_hooks, list):
        return
    from urllib.parse import urlparse
    target_path = urlparse(url).path
    # Same INNER-level filter as ensure_hook: strip OUR hook from each
    # entry's `hooks` list, but preserve the entry whenever sibling
    # hooks (Husky, git-lfs, user-defined) still remain. Removing the
    # whole entry on any match would silently delete unrelated hooks.
    filtered = []
    for entry in event_hooks:
        if not isinstance(entry, dict):
            filtered.append(entry)
            continue
        inner = entry.get('hooks', [])
        if not isinstance(inner, list):
            filtered.append(entry)
            continue
        new_inner = [
            h for h in inner
            if not (isinstance(h, dict) and urlparse(h.get('url', '')).path == target_path)
        ]
        if new_inner:
            new_entry = dict(entry)
            new_entry['hooks'] = new_inner
            filtered.append(new_entry)
        elif not inner:
            # Entry had no inner hooks to begin with — preserve as-is.
            filtered.append(entry)
        # else: entry contained ONLY our hook — drop it entirely.
    hooks[event_name] = filtered
    # Clean up empty arrays
    if not hooks[event_name]:
        del hooks[event_name]

# Mirror the install event list. Uninstall removes ALL subscriptions
# unconditionally, including PostToolBatch — even if the gate flag is
# absent now, a previous install with the flag enabled may have written
# the entry. Idempotent uninstall must clean up regardless.
events = [
    # Phase G note: SessionStart removed from install but we KEEP it in
    # uninstall in case a previous install (pre-Phase-G) wrote the entry.
    # Idempotent uninstall must clean up legacy state regardless.
    ('SessionStart',     f'http://localhost:{port}/api/session-start'),
    ('UserPromptSubmit', f'http://localhost:{port}/api/session-start'),
    ('Stop',             f'http://localhost:{port}/api/session-stop'),
    ('StopFailure',      f'http://localhost:{port}/api/session-stop'),
    ('SubagentStop',     f'http://localhost:{port}/api/session-stop'),
    ('SessionEnd',       f'http://localhost:{port}/api/session-end'),
    ('SubagentStart',    f'http://localhost:{port}/api/subagent-start'),
    ('PreCompact',       f'http://localhost:{port}/api/pre-compact'),
    ('PostCompact',      f'http://localhost:{port}/api/post-compact'),
    ('CwdChanged',       f'http://localhost:{port}/api/cwd-changed'),
    ('PostToolBatch',    f'http://localhost:{port}/api/post-tool-batch'),
    # Phase E — worktree + agent-team event coverage (must mirror install).
    ('WorktreeCreate',   f'http://localhost:{port}/api/worktree-create'),
    ('WorktreeRemove',   f'http://localhost:{port}/api/worktree-remove'),
    ('TaskCreated',      f'http://localhost:{port}/api/task-created'),
    ('TaskCompleted',    f'http://localhost:{port}/api/task-completed'),
    ('TeammateIdle',     f'http://localhost:{port}/api/teammate-idle'),
    # Phase G — auth + config + skill-expansion observability.
    ('Notification',     f'http://localhost:{port}/api/notification'),
    ('ConfigChange',     f'http://localhost:{port}/api/config-change'),
    ('UserPromptExpansion', f'http://localhost:{port}/api/user-prompt-expansion'),
]

for event_name, url in events:
    remove_hook(event_name, url)

# Clean up empty hooks dict
if not hooks:
    del settings['hooks']

# Atomic write: tmp + os.replace
tmp_file = settings_file + '.tmp'
with open(tmp_file, 'w') as f:
    json.dump(settings, f, indent=2)
os.replace(tmp_file, settings_file)
PYEOF
  then
    echo -e "  ${YELLOW:-}Warning: Failed to uninstall Claude Code hooks${NC:-}" >&2
  fi
}

# ─────────────────────────────────────────────────
# Global git prepare-commit-msg hook
# ─────────────────────────────────────────────────

_install_git_hook() {
  local hooks_dir=""

  # Determine hooks directory. The marker file (`_VDM_HOOKS_PATH_MARKER`)
  # is the single source of truth for "did we create this hooksPath" —
  # don't reintroduce a bash-local boolean for the same fact, it just
  # rots when the function gets refactored.
  hooks_dir=$(git config --global core.hooksPath 2>/dev/null) || true

  if [[ -z "$hooks_dir" ]]; then
    hooks_dir="$HOME/.config/git/hooks"
    mkdir -p "$hooks_dir" 2>/dev/null || true
    git config --global core.hooksPath "$hooks_dir" 2>/dev/null || true
    # Write marker so uninstall knows we set it
    touch "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" 2>/dev/null || true
  else
    # Expand ~ in path
    hooks_dir="${hooks_dir/#\~/$HOME}"
    mkdir -p "$hooks_dir" 2>/dev/null || true
  fi

  local hook_file="$hooks_dir/prepare-commit-msg"

  # If our hook is already installed, remove it so we can write the latest version
  if [[ -f "$hook_file" ]] && grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    rm -f "$hook_file" 2>/dev/null || true
  fi

  # If existing hook without our marker, move aside
  if [[ -f "$hook_file" ]] && ! grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    mv "$hook_file" "${hook_file}.vdm-original" 2>/dev/null || true
  fi

  # Write our hook
  cat > "$hook_file" << 'HOOKEOF'
#!/bin/bash
# vdm-token-usage
# Appends token usage trailer to commit messages.
# Part of claude-acct-switcher (https://github.com/loekj/claude-acct-switcher)

# IMPORTANT: even on merge/squash/amend we still run any chained hooks
# (Husky, git-lfs, project-local) — they are not specific to vdm and the
# user expects them to fire. We only skip OUR trailer for those events
# because the commit message there is computed/edited differently.

# Chain to repo-local hook (core.hooksPath disables .git/hooks/).
# Use --git-common-dir, NOT --git-dir: in a worktree the per-worktree
# git-dir is .git/worktrees/<name>/ which has no `hooks/` subdir, so the
# repo-local hook wouldn't be discovered. The common dir always points
# to the shared repo metadata where hooks/ actually lives.
LOCAL_GIT_DIR="$(git rev-parse --git-common-dir 2>/dev/null)"
if [[ -n "$LOCAL_GIT_DIR" ]]; then
  LOCAL_HOOK="$LOCAL_GIT_DIR/hooks/prepare-commit-msg"
  [[ -x "$LOCAL_HOOK" ]] && [[ "$LOCAL_HOOK" != "$0" ]] && { "$LOCAL_HOOK" "$@" || exit $?; }
fi

# Chain to pre-existing global hook we moved aside
[[ -x "${0}.vdm-original" ]] && { "${0}.vdm-original" "$@" || exit $?; }

# Skip OUR trailer for merge/squash/amend; chained hooks above always run.
[[ "$2" == "merge" || "$2" == "squash" || "$2" == "commit" ]] && exit 0

# Without python3 there is no safe way to URL-encode the repo path or
# parse the usage JSON, so the trailer is unreachable — exit cleanly
# instead of building a malformed URL or crashing the commit.
command -v python3 >/dev/null 2>&1 || exit 0

# Check if commitTokenUsage is enabled (disabled by default; silent fail = skip)
# `--connect-timeout 1` bounds the wait when the dashboard isn't running.
# macOS resolves `localhost` to BOTH ::1 and 127.0.0.1; if the dashboard
# binds to only one family, curl tries the other first and the kernel's
# v6→v4 fallback can stall the commit by several seconds. Without
# --connect-timeout, --max-time alone covers transfer time but not the
# pre-transfer connect phase on a dual-stack name.
VDM_PORT="${CSW_PORT:-3333}"
SETTINGS=$(curl -s --connect-timeout 1 --max-time 2 "http://localhost:${VDM_PORT}/api/settings" 2>/dev/null) || true
if echo "$SETTINGS" | python3 -c "import json,sys; s=json.load(sys.stdin); sys.exit(0 if s.get('commitTokenUsage',False) else 1)" 2>/dev/null; then
  : # enabled, continue
else
  exit 0
fi

# Query proxy for token usage since last commit (2s timeout, silent fail)
# Use --git-common-dir to resolve to main repo root (matches dashboard
# storage). The common dir typically ends in `/.git` or `/.git/`; strip
# the trailing /.git via dirname which handles both with no regex
# brittleness (the original sed `s|/\.git/*$||` failed on a bare `/.git`
# ending without a trailing slash because the `/` before `\.git` was
# anchored as required in the pattern).
LOCAL_GIT_DIR="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"
if [[ -n "$LOCAL_GIT_DIR" ]]; then
  # Trim trailing slashes, then if the basename is .git use its parent.
  LOCAL_GIT_DIR="${LOCAL_GIT_DIR%/}"
  if [[ "$(basename "$LOCAL_GIT_DIR")" == ".git" ]]; then
    REPO="$(dirname "$LOCAL_GIT_DIR")"
  else
    REPO="$LOCAL_GIT_DIR"
  fi
else
  REPO=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
fi
LAST_TS=$(( $(git log -1 --format=%ct 2>/dev/null || echo 0) * 1000 ))
# URL-encode the repo path. A path containing `&`, `?`, `#`, `=`, ` `, `+`,
# or non-ASCII bytes corrupts the query string when interpolated raw —
# `?repo=/foo/bar&baz` would parse as repo=`/foo/bar`, baz=``, hiding the
# repo's usage from the dashboard. argv-pass to python avoids any escape
# issues with the repo path itself. If python3 fails here we cannot fall
# back to the unencoded path (that would build a malformed URL); skip
# the trailer instead.
REPO_ENC=$(python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$REPO" 2>/dev/null) || exit 0
USAGE=$(curl -s --connect-timeout 1 --max-time 2 "http://localhost:${VDM_PORT}/api/token-usage?repo=${REPO_ENC}&since=${LAST_TS}" 2>/dev/null) || exit 0

# Parse JSON and append trailer if tokens > 0
python3 -c "
import json, sys

commit_msg_file = sys.argv[1]
try:
    usage = json.loads(sys.argv[2])
except:
    sys.exit(0)

if not usage:
    sys.exit(0)

# Group by model
models = {}
for e in usage:
    m = e.get('model', 'unknown')
    if m not in models:
        models[m] = {'in': 0, 'out': 0}
    models[m]['in'] += e.get('inputTokens', 0)
    models[m]['out'] += e.get('outputTokens', 0)

total = sum(v['in'] + v['out'] for v in models.values())
if total <= 0:
    sys.exit(0)

def fmt(n):
    return f'{n:,}'

# Shorten model names: claude-sonnet-4-6-20250514 -> sonnet 4.6
def short_model(m):
    import re
    s = re.sub(r'^claude-', '', m)
    s = re.sub(r'-\d{8}$', '', s)
    # Match name-major-minor pattern
    match = re.match(r'^([a-z]+(?:-[a-z]+)*)-(\d+(?:-\d+)*)$', s)
    if match:
        name = match.group(1)
        ver = match.group(2).replace('-', '.')
        return f'{name} {ver}'
    return s

lines = []
for model in sorted(models.keys()):
    v = models[model]
    lines.append(f'{short_model(model)}: {fmt(v[\"in\"])} / {fmt(v[\"out\"])}')
trailer = 'Token-Usage: ' + ', '.join(lines)

with open(commit_msg_file, 'r') as f:
    content = f.read()

# Don't duplicate
if 'Token-Usage:' in content:
    sys.exit(0)

with open(commit_msg_file, 'w') as f:
    f.write(content.rstrip() + '\n\n' + trailer + '\n')
" "$1" "$USAGE" 2>/dev/null || true
HOOKEOF

  chmod +x "$hook_file" 2>/dev/null || true

  # ─────────────────────────────────────────────────
  # Per-repo hook delegation stubs (CRITICAL: rescues git-lfs et al.)
  # ─────────────────────────────────────────────────
  # Setting `core.hooksPath` globally makes git STOP scanning each repo's
  # `.git/hooks/` directory entirely. Any tool that installs per-repo
  # hooks the standard way (`git lfs install` writes `.git/hooks/pre-push`,
  # Husky writes `.git/hooks/pre-commit`, lefthook, pre-commit framework,
  # `core.hooksPath`-unaware projects, etc.) becomes invisible the moment
  # vdm flips the global pointer. lfs's pre-push silently not running
  # = pushes succeed but actual blob upload never happens, breaking the
  # remote in a way the user finds days later.
  #
  # The fix is small: drop a delegating stub at our hooks_dir for each
  # standard event vdm doesn't otherwise touch. The stub re-enters the
  # repo-local hook (via `git rev-parse --git-common-dir` — same flag the
  # prepare-commit-msg hook uses to handle worktrees correctly) and exec()s
  # it, propagating exit code and arguments. If no per-repo hook exists,
  # the stub exits 0 (no-op).
  #
  # Stubs are tagged with `_VDM_HOOKS_MARKER` so uninstall knows which
  # files to remove. Existing user-installed files at these paths
  # (without our marker) are moved aside to `<event>.vdm-original` and
  # chained — same convention as prepare-commit-msg.
  local _vdm_passthrough_events=(
    pre-commit
    commit-msg
    pre-push
    post-checkout
    post-commit
    post-merge
    post-rewrite
  )
  local _evt _stub
  for _evt in "${_vdm_passthrough_events[@]}"; do
    _stub="$hooks_dir/$_evt"

    # If our stub is already there, refresh it (idempotent re-install).
    if [[ -f "$_stub" ]] && grep -q "$_VDM_HOOKS_MARKER" "$_stub" 2>/dev/null; then
      rm -f "$_stub" 2>/dev/null || true
    fi

    # Pre-existing user/tool hook (e.g. legacy globally-installed lfs
    # pre-push that lived here BEFORE vdm took over hooksPath): move it
    # aside so we can chain to it, mirroring prepare-commit-msg.
    if [[ -f "$_stub" ]] && ! grep -q "$_VDM_HOOKS_MARKER" "$_stub" 2>/dev/null; then
      mv "$_stub" "${_stub}.vdm-original" 2>/dev/null || true
    fi

    cat > "$_stub" << STUBEOF
#!/bin/bash
# vdm-token-usage
# vdm passthrough stub for: $_evt
# When vdm sets core.hooksPath globally, per-repo .git/hooks/$_evt would
# normally stop firing. This stub re-enters the per-repo hook (so
# git-lfs / Husky / pre-commit / lefthook / etc. keep working) and then
# chains to any pre-existing global hook we moved aside. It does NOT do
# any vdm-specific work itself.

LOCAL_GIT_DIR="\$(git rev-parse --git-common-dir 2>/dev/null)"
if [[ -n "\$LOCAL_GIT_DIR" ]]; then
  LOCAL_HOOK="\$LOCAL_GIT_DIR/hooks/$_evt"
  # Avoid recursing into ourselves if somehow LOCAL_HOOK == "\$0".
  if [[ -x "\$LOCAL_HOOK" ]] && [[ "\$LOCAL_HOOK" != "\$0" ]]; then
    "\$LOCAL_HOOK" "\$@" || exit \$?
  fi
fi

# Chain to a pre-existing global hook we moved aside on install.
[[ -x "\${0}.vdm-original" ]] && { "\${0}.vdm-original" "\$@" || exit \$?; }

exit 0
STUBEOF
    chmod +x "$_stub" 2>/dev/null || true
  done
}

_uninstall_git_hook() {
  local hooks_dir=""
  hooks_dir=$(git config --global core.hooksPath 2>/dev/null) || true

  if [[ -z "$hooks_dir" ]]; then
    hooks_dir="$HOME/.config/git/hooks"
  else
    hooks_dir="${hooks_dir/#\~/$HOME}"
  fi

  local hook_file="$hooks_dir/prepare-commit-msg"

  if [[ -f "$hook_file" ]] && grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    # Restore original if we moved one aside
    if [[ -f "${hook_file}.vdm-original" ]]; then
      mv "${hook_file}.vdm-original" "$hook_file" 2>/dev/null || true
    else
      rm -f "$hook_file" 2>/dev/null || true
    fi
  fi

  # Remove the per-repo-delegation passthrough stubs we wrote in
  # _install_git_hook. Same convention as prepare-commit-msg: only touch
  # files marked with `_VDM_HOOKS_MARKER`, and if we moved aside a
  # pre-existing global hook on install (`<event>.vdm-original`), put it
  # back. Without this loop, an uninstall would leave dead vdm stubs
  # behind in hooks_dir indefinitely AND lose any user-installed hook
  # that vdm originally moved aside on install.
  local _vdm_passthrough_events=(
    pre-commit
    commit-msg
    pre-push
    post-checkout
    post-commit
    post-merge
    post-rewrite
  )
  local _evt _stub
  for _evt in "${_vdm_passthrough_events[@]}"; do
    _stub="$hooks_dir/$_evt"
    if [[ -f "$_stub" ]] && grep -q "$_VDM_HOOKS_MARKER" "$_stub" 2>/dev/null; then
      if [[ -f "${_stub}.vdm-original" ]]; then
        mv "${_stub}.vdm-original" "$_stub" 2>/dev/null || true
      else
        rm -f "$_stub" 2>/dev/null || true
      fi
    fi
  done

  # If we set core.hooksPath and no other hooks remain, unset it.
  # Count BOTH regular files AND symlinks: many users symlink hooks
  # from a dotfiles repo or from a tool's own hook bundle. A bare
  # `-type f` test misses symlinks entirely and would `rm -rf` the
  # hooks_dir even though user hooks (as symlinks) still live there.
  if [[ -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" ]]; then
    local remaining
    remaining=$(find "$hooks_dir" -maxdepth 1 \( -type f -o -type l \) ! -name "$_VDM_HOOKS_PATH_MARKER" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$remaining" -eq 0 ]]; then
      git config --global --unset core.hooksPath 2>/dev/null || true
      rm -rf "$hooks_dir" 2>/dev/null || true
    else
      rm -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" 2>/dev/null || true
    fi
  fi
}
