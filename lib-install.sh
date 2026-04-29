#!/usr/bin/env bash
# lib-install.sh — Shared safety primitives + environment detectors.
# Sourced by install.sh and uninstall.sh. Provides atomic file ops,
# signal-safe cleanup, defensive process kill, and a battery of
# pre-flight detectors that surface remnants of prior installs,
# malformed config, dangling symlinks, port conflicts, etc.
#
# Design rules:
# - Pure functions whenever possible (no global side-effects beyond
#   the few documented arrays / cleanup stack).
# - Every disk write goes through _atomic_replace or _atomic_append_block
#   so a SIGKILL / Ctrl-C / power loss never leaves a half-written file.
# - Every long-running script that sources this MUST call _trap_signals
#   exactly once early in startup so the cleanup stack runs on
#   INT / TERM / HUP / EXIT — not just normal exit.
# - Detectors are read-only. They populate VDM_DETECTED_ISSUES (an
#   array of "category|severity|description|fix-hint" strings) so the
#   caller decides whether to prompt or auto-fix.
#
# Zero deps: pure bash + python3 (already a hard dep elsewhere).

# ─────────────────────────────────────────────────────────
# Colour constants — re-export safely if the caller didn't define them.
# ─────────────────────────────────────────────────────────
: "${RED:=$'\033[0;31m'}"
: "${GREEN:=$'\033[0;32m'}"
: "${YELLOW:=$'\033[1;33m'}"
: "${CYAN:=$'\033[0;36m'}"
: "${BOLD:=$'\033[1m'}"
: "${DIM:=$'\033[2m'}"
: "${NC:=$'\033[0m'}"

# ─────────────────────────────────────────────────────────
# Atomic file operations.
# ─────────────────────────────────────────────────────────

# _atomic_replace <src_or_content_file> <dst>
# Replace <dst> atomically. Writes <dst>.tmp.<pid>, fsyncs, then either:
#   - mv-renames the tmp into place (regular file destination), OR
#   - if <dst> is a symlink, writes the tmp content THROUGH the symlink
#     so the underlying target is updated and the symlink stays intact.
#
# Why the symlink branch: rc files in dotfile-manager-managed homes
# (chezmoi, yadm, stow, vcsh) are commonly symlinks pointing into a
# managed repo. A naive `mv -f tmp $dst` replaces the symlink with a
# regular file — silently breaking the dotfile manager and stranding
# every future edit outside the user's repo. The cat-through branch
# updates the managed file in place. Tradeoff: cat-redirect is NOT
# atomic at the byte level — a SIGKILL mid-write leaves a truncated
# managed file. We accept that for symlinked destinations because the
# alternative (silently breaking the dotfile chain) is worse.
# Regular-file destinations stay fully atomic via mv.
_atomic_replace() {
  local src="$1" dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "_atomic_replace: source missing: $src" >&2
    return 1
  fi
  local dst_dir; dst_dir="$(dirname "$dst")"
  if [[ ! -d "$dst_dir" ]]; then
    mkdir -p "$dst_dir" || return 1
  fi
  local tmp="${dst}.tmp.$$"
  # Preserve mode if dst exists, otherwise let umask govern.
  cp "$src" "$tmp" || { rm -f "$tmp"; return 1; }
  if [[ -e "$dst" ]]; then
    # Try GNU `chmod --reference` first; falls back to a portable mode
    # query (handles BSD `stat -f` and GNU `stat -c`) so this works
    # under stock macOS, macOS-with-coreutils, and Linux without changes.
    chmod --reference="$dst" "$tmp" 2>/dev/null \
      || _bsd_chmod_match "$dst" "$tmp" \
      || true
  fi
  # fsync the temp file so the bytes are on disk before the rename.
  # macOS lacks `dd ... oflag=fsync`; portable form: open + sync.
  python3 -c "import os,sys; f=os.open(sys.argv[1], os.O_RDONLY); os.fsync(f); os.close(f)" "$tmp" 2>/dev/null || true
  if [[ -L "$dst" ]]; then
    # Symlink: write through it so the dotfile-manager target stays
    # the source of truth. NOT atomic at byte level — see above.
    if cat "$tmp" > "$dst"; then
      rm -f "$tmp"
      return 0
    else
      rm -f "$tmp"
      return 1
    fi
  else
    mv -f "$tmp" "$dst"
  fi
}

# Portable chmod-match helper. Tries GNU `stat -c '%a'` first (works
# under GNU coreutils on Linux AND under brew's `coreutils` on macOS,
# where some users have `stat`→`gstat` shadowed); falls back to BSD
# `stat -f '%Lp'` (stock macOS). Both produce the octal mode bits.
_bsd_chmod_match() {
  local ref="$1" target="$2"
  local mode
  mode="$(stat -c '%a' "$ref" 2>/dev/null \
       || stat -f '%Lp' "$ref" 2>/dev/null)" || return 1
  [[ -z "$mode" ]] && return 1
  chmod "$mode" "$target"
}

# _portable_sed
# Centralised wrapper around sed for cases where we want to be explicit
# about which dialect features we use. Modern BSD sed (macOS 11+) and
# GNU sed both accept `-E` for ERE, so plain `sed -E …` is portable.
# This wrapper exists mostly to document the constraint and to make it
# easy to swap implementations should a future divergence appear.
# We DELIBERATELY avoid `sed -i` in any flavour: BSD requires `sed -i ''`
# (with empty backup-suffix arg) while GNU treats `''` as a filename and
# silently no-ops; pinning to one breaks the other. Always read from
# stdin / a file and write to a tmp via redirection — that's the only
# form both dialects honour identically.
_portable_sed() {
  sed -E "$@"
}

# _atomic_install <src> <dst> [mode]
# Like _atomic_replace but also chmod's after rename. Use for installing
# executables (mode=755) or config files (mode=600) in one call.
_atomic_install() {
  local src="$1" dst="$2" mode="${3:-}"
  _atomic_replace "$src" "$dst" || return 1
  if [[ -n "$mode" ]]; then
    chmod "$mode" "$dst" || return 1
  fi
}

# _atomic_write_string <dst> <content>
# Write <content> to <dst> atomically. Useful for tiny files like
# .version markers or single-value flag files.
_atomic_write_string() {
  local dst="$1" content="$2"
  local dst_dir; dst_dir="$(dirname "$dst")"
  mkdir -p "$dst_dir" 2>/dev/null || true
  local tmp="${dst}.tmp.$$"
  printf '%s' "$content" > "$tmp" || { rm -f "$tmp"; return 1; }
  python3 -c "import os,sys; f=os.open(sys.argv[1], os.O_RDONLY); os.fsync(f); os.close(f)" "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$dst"
}

# _atomic_append_block <dst> <begin_marker> <end_marker> <body_file>
# Append a marker-delimited block to <dst> atomically. If <dst> already
# contains <begin_marker>, no-op (idempotent). The whole new content is
# composed in <dst>.tmp.<pid> and renamed in one syscall — partial
# appends are impossible.
_atomic_append_block() {
  local dst="$1" begin="$2" end="$3" body_file="$4"
  if [[ ! -f "$body_file" ]]; then
    echo "_atomic_append_block: body file missing: $body_file" >&2
    return 1
  fi
  if [[ -f "$dst" ]] && grep -qF "$begin" "$dst" 2>/dev/null; then
    return 0  # already installed
  fi
  local dst_dir; dst_dir="$(dirname "$dst")"
  mkdir -p "$dst_dir" 2>/dev/null || true
  local tmp="${dst}.tmp.$$"
  {
    if [[ -f "$dst" ]]; then
      cat "$dst"
      # Trim sole trailing blank line check — match install.sh behaviour
      # by emitting a separator blank line before the block. Idempotent
      # against re-runs because the begin-marker check above guards us.
      [[ -s "$dst" ]] && [[ -n "$(tail -c1 "$dst")" ]] && echo ""
    fi
    echo ""
    echo "$begin"
    cat "$body_file"
    echo "$end"
  } > "$tmp" || { rm -f "$tmp"; return 1; }
  if [[ -e "$dst" ]]; then
    # Try GNU `chmod --reference` first; falls back to a portable mode
    # query (handles BSD `stat -f` and GNU `stat -c`) so this works
    # under stock macOS, macOS-with-coreutils, and Linux without changes.
    chmod --reference="$dst" "$tmp" 2>/dev/null \
      || _bsd_chmod_match "$dst" "$tmp" \
      || true
  fi
  python3 -c "import os,sys; f=os.open(sys.argv[1], os.O_RDONLY); os.fsync(f); os.close(f)" "$tmp" 2>/dev/null || true
  if [[ -L "$dst" ]]; then
    # Symlink: write through it (see _atomic_replace for the rationale).
    cat "$tmp" > "$dst" && rm -f "$tmp"
  else
    mv -f "$tmp" "$dst"
  fi
}

# _atomic_remove_block <dst> <begin_marker_pattern> <end_marker_pattern>
# Remove a marker-delimited block from <dst> atomically. Patterns are
# extended-regex anchored to a full line (with optional leading
# whitespace and trailing CR). On malformed markers (BEGIN without END
# or vice-versa), restores the original and returns 2 — caller decides
# whether to surface to the user. On success returns 0; if no markers
# present returns 1 (no-op).
_atomic_remove_block() {
  local dst="$1" begin_re="$2" end_re="$3"
  [[ -f "$dst" ]] || return 1
  # Quick existence check.
  if ! grep -Eq "$begin_re" "$dst" 2>/dev/null; then
    return 1
  fi
  local has_begin=0 has_end=0
  grep -Eq "$begin_re" "$dst" 2>/dev/null && has_begin=1
  grep -Eq "$end_re"   "$dst" 2>/dev/null && has_end=1
  if [[ "$has_begin$has_end" != "11" ]]; then
    # Malformed — refuse to auto-edit. Caller surfaces this.
    return 2
  fi
  local tmp="${dst}.tmp.$$"
  # Strip CRLF first (in tmp, not in place) so the END marker matches
  # `^[[:space:]]*<end_re>[[:space:]]*$`.
  LC_ALL=C tr -d '\r' < "$dst" \
    | sed -E "/$begin_re/,/$end_re/d" \
    > "$tmp" \
    || { rm -f "$tmp"; return 1; }
  # Trim a single trailing blank line, idempotent.
  if [[ -s "$tmp" ]] && [[ -z "$(tail -1 "$tmp")" ]]; then
    sed -e '$ {/^$/d;}' "$tmp" > "${tmp}.2" && mv -f "${tmp}.2" "$tmp"
  fi
  if [[ -e "$dst" ]]; then
    # Try GNU `chmod --reference` first; falls back to a portable mode
    # query (handles BSD `stat -f` and GNU `stat -c`) so this works
    # under stock macOS, macOS-with-coreutils, and Linux without changes.
    chmod --reference="$dst" "$tmp" 2>/dev/null \
      || _bsd_chmod_match "$dst" "$tmp" \
      || true
  fi
  python3 -c "import os,sys; f=os.open(sys.argv[1], os.O_RDONLY); os.fsync(f); os.close(f)" "$tmp" 2>/dev/null || true
  if [[ -L "$dst" ]]; then
    # Symlink: write through it (see _atomic_replace for the rationale).
    cat "$tmp" > "$dst" && rm -f "$tmp"
  else
    mv -f "$tmp" "$dst"
  fi
}

# ─────────────────────────────────────────────────────────
# Signal-safe cleanup stack.
#
# Usage:
#   _trap_signals
#   _register_cleanup 'rmdir "$LOCK"'
#   _register_cleanup 'rm -f "$TMP_FILE"'
# Cleanup actions run in LIFO order on EXIT, INT, TERM, HUP. Idempotent
# — actions that have already succeeded just no-op.
# ─────────────────────────────────────────────────────────

VDM_CLEANUP_ACTIONS=()
VDM_CLEANUP_RAN=0

_run_cleanup() {
  # Guard: only run once even if multiple signals arrive.
  if [[ "$VDM_CLEANUP_RAN" == "1" ]]; then return 0; fi
  VDM_CLEANUP_RAN=1
  local i
  for (( i=${#VDM_CLEANUP_ACTIONS[@]}-1; i>=0; i-- )); do
    eval "${VDM_CLEANUP_ACTIONS[$i]}" 2>/dev/null || true
  done
}

_trap_signals() {
  trap '_run_cleanup' EXIT
  trap '_run_cleanup; exit 130' INT
  trap '_run_cleanup; exit 143' TERM
  trap '_run_cleanup; exit 129' HUP
}

_register_cleanup() {
  VDM_CLEANUP_ACTIONS+=("$1")
}

# ─────────────────────────────────────────────────────────
# Defensive process kill.
# ─────────────────────────────────────────────────────────

# _safe_kill_pid <pid> <expected_cmdline_substring> [signal]
# Send <signal> (default TERM) to <pid> ONLY if its current command line
# contains <expected_cmdline_substring>. Guards against PID reuse: the
# kernel can recycle a dead PID to an unrelated process within
# microseconds, so a naive `kill $(lsof -t)` could end up killing the
# wrong thing on a busy machine.
# Returns 0 on successful kill, 1 if PID unrecognised, 2 if cmdline
# didn't match.
_safe_kill_pid() {
  local pid="$1" expect="$2" sig="${3:-TERM}"
  [[ -z "$pid" ]] && return 1
  # Snapshot the cmdline via ps. macOS ps `command` column is the full
  # argv joined by spaces, exactly what we need. -p <pid> filters first.
  local cmd
  cmd="$(ps -o command= -p "$pid" 2>/dev/null || true)"
  if [[ -z "$cmd" ]]; then
    return 1  # PID gone already
  fi
  if [[ "$cmd" != *"$expect"* ]]; then
    return 2  # PID belongs to something else now
  fi
  kill "-$sig" "$pid" 2>/dev/null
}

# ─────────────────────────────────────────────────────────
# JSON helpers — settings.json validation and surgical edits.
# ─────────────────────────────────────────────────────────

# _json_is_valid <file>
# Returns 0 if the file parses as valid JSON, 1 otherwise.
_json_is_valid() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" 2>/dev/null
}

# _json_get_int <file> <key>
# Print the value of a top-level numeric key, or empty if missing /
# malformed / not an int. Pure read, no writes.
_json_get_int() {
  local f="$1" key="$2"
  [[ -f "$f" ]] || return 1
  python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    v = d.get(sys.argv[2])
    print(v if isinstance(v, int) else '')
except Exception:
    pass
" "$f" "$key" 2>/dev/null
}

# ─────────────────────────────────────────────────────────
# Detectors — populate VDM_DETECTED_ISSUES.
#
# Each detector appends 0+ lines of `category|severity|description|fix_hint`
# to VDM_DETECTED_ISSUES. Severities: info, warn, error, blocker.
# Detectors are PURE READS. Caller decides whether to prompt or auto-fix.
# ─────────────────────────────────────────────────────────

VDM_DETECTED_ISSUES=()

_issue() {
  VDM_DETECTED_ISSUES+=("$1|$2|$3|$4")
}

# detect_old_install_remnants
# Looks for: install dir present but missing dashboard.mjs (partial
# install), accounts/*.json plaintext files (Phase J pre-migration),
# `.dashboard.pid` referring to a dead PID, `startup.log` > 10 MB.
detect_old_install_remnants() {
  local root="${1:-$HOME/.claude/account-switcher}"
  if [[ -d "$root" ]] && [[ ! -f "$root/dashboard.mjs" ]]; then
    _issue partial-install warn \
      "Install dir exists but dashboard.mjs is missing: $root" \
      "Run uninstall.sh to clean it, then re-run install.sh."
  fi
  if [[ -d "$root/accounts" ]]; then
    local n_json
    n_json=$(find "$root/accounts" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$n_json" -gt 0 ]]; then
      _issue legacy-accounts warn \
        "$n_json plaintext account file(s) in $root/accounts/ — pre-Phase-J storage" \
        "Run vdm or restart the dashboard to migrate them into the keychain."
    fi
  fi
  if [[ -f "$root/.dashboard.pid" ]]; then
    local pid; pid="$(cat "$root/.dashboard.pid" 2>/dev/null || true)"
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      _issue stale-pidfile info \
        "$root/.dashboard.pid points at dead PID $pid" \
        "Auto-removed by next dashboard start. Safe to delete."
    fi
  fi
  if [[ -f "$root/startup.log" ]]; then
    local sz
    sz=$(wc -c < "$root/startup.log" 2>/dev/null | tr -d ' ')
    if [[ -n "$sz" ]] && [[ "$sz" -gt 10485760 ]]; then
      _issue oversized-log info \
        "startup.log exceeds 10 MiB ($((sz / 1024 / 1024)) MiB) — disk pressure" \
        "Truncate it: : > $root/startup.log"
    fi
  fi
}

# detect_orphaned_settings_hooks
# Scans ~/.claude/settings.json for `localhost:<port>/api/<vdm-event>`
# hook URLs that point at a port no listener owns. These cause
# UserPromptSubmit ECONNREFUSED on every prompt.
detect_orphaned_settings_hooks() {
  local s="$HOME/.claude/settings.json"
  [[ -f "$s" ]] || return 0
  if ! _json_is_valid "$s"; then
    _issue settings-corrupt error \
      "$s is not valid JSON" \
      "Fix manually before installing — vdm will not edit a corrupt settings file."
    return 0
  fi
  local hooks_csv
  hooks_csv="$(python3 -c "
import json, sys
from urllib.parse import urlparse
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
hooks = d.get('hooks', {}) if isinstance(d, dict) else {}
for evt, lst in hooks.items():
    if not isinstance(lst, list): continue
    for entry in lst:
        if not isinstance(entry, dict): continue
        for h in entry.get('hooks', []):
            if not isinstance(h, dict): continue
            if h.get('type') != 'http': continue
            url = h.get('url', '')
            p = urlparse(url)
            if p.hostname in ('localhost', '127.0.0.1') and p.path.startswith('/api/'):
                print(f'{evt}|{p.port or 80}|{url}')
" "$s" 2>/dev/null)"
  [[ -z "$hooks_csv" ]] && return 0
  local n=0
  local dead_ports=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    n=$((n + 1))
    local port="${line#*|}"
    port="${port%%|*}"
    if ! lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
      dead_ports+=("$port")
    fi
  done <<< "$hooks_csv"
  local uniq_dead
  uniq_dead="$(printf '%s\n' "${dead_ports[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')"
  if [[ -n "$uniq_dead" ]]; then
    _issue orphaned-hooks error \
      "$n /api/* HTTP hook(s) in settings.json point at port(s) $uniq_dead with no listener" \
      "These cause ECONNREFUSED on every prompt. Run uninstall.sh to remove them, or run install.sh to replace them with a fresh dashboard."
  fi
}

# detect_malformed_rc_blocks
# Scans every shell rc file for BEGIN-without-END / END-without-BEGIN.
# These break the uninstaller's range-delete and indicate a half-written
# install.
detect_malformed_rc_blocks() {
  local rc has_begin has_end
  for rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" \
            "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    [[ -f "$rc" ]] || continue
    has_begin=0; has_end=0
    grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$' "$rc" 2>/dev/null && has_begin=1
    grep -Eq '^[[:space:]]*# END claude-account-switcher[[:space:]]*$'   "$rc" 2>/dev/null && has_end=1
    if [[ "$has_begin" == "1" && "$has_end" == "0" ]]; then
      _issue malformed-rc error \
        "$rc has BEGIN marker without matching END — partial install or manual edit" \
        "Open the file and either remove the BEGIN line or add the END line before re-installing."
    elif [[ "$has_begin" == "0" && "$has_end" == "1" ]]; then
      _issue malformed-rc error \
        "$rc has END marker without matching BEGIN — orphaned snippet remnant" \
        "Open the file and remove the orphaned END line."
    fi
  done
}

# detect_dangling_symlinks
# Looks for vdm/csw symlinks pointing at nonexistent targets. These
# silently break `vdm` invocations and confuse PATH lookup.
detect_dangling_symlinks() {
  local lnk target
  for lnk in "$HOME/.local/bin/vdm"     "$HOME/.local/bin/csw" \
             "/opt/homebrew/bin/vdm"    "/opt/homebrew/bin/csw" \
             "/usr/local/bin/vdm"       "/usr/local/bin/csw"; do
    if [[ -L "$lnk" ]]; then
      target="$(readlink "$lnk" 2>/dev/null || true)"
      if [[ -z "$target" ]] || [[ ! -e "$target" ]]; then
        _issue dangling-symlink warn \
          "$lnk → $target (target missing)" \
          "Run uninstall.sh to clean, or rm the symlink manually."
      fi
    fi
  done
}

# detect_port_holders <port> [port...]
# For each port, identify the holder if any. Distinguishes vdm's own
# dashboard.mjs (expected) from anything else (genuine conflict).
detect_port_holders() {
  local port pid cmd
  for port in "$@"; do
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      cmd="$(ps -o command= -p "$pid" 2>/dev/null || true)"
      [[ -z "$cmd" ]] && continue
      if [[ "$cmd" == *"dashboard.mjs"* ]] && [[ "$cmd" == *"account-switcher"* ]]; then
        _issue port-held-by-vdm info \
          "Port $port held by existing vdm dashboard (PID $pid)" \
          "Will be reused — install will not start a second instance."
      else
        _issue port-conflict error \
          "Port $port held by non-vdm process: PID $pid: $cmd" \
          "Free the port or set CSW_PORT/CSW_PROXY_PORT to alternative values before installing."
      fi
    done < <(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  done
}

# detect_orphan_keychain_entries
# Surfaces vdm-account-* entries when no install dir exists — they
# survived a prior uninstall (kept) but are otherwise unowned.
detect_orphan_keychain_entries() {
  local root="${1:-$HOME/.claude/account-switcher}"
  [[ -d "$root" ]] && return 0  # not an orphan — current install owns them
  local n
  n=$(security dump-keychain 2>/dev/null \
    | grep -cE '"svce"<blob>="vdm-account-' \
    || true)
  if [[ -n "$n" ]] && [[ "$n" -gt 0 ]]; then
    _issue orphan-keychain info \
      "$n vdm-account-* keychain entry(ies) survive without a vdm install" \
      "Reinstall to adopt them, or run uninstall.sh --purge-keychain to delete them."
  fi
}

# detect_truncated_config
# config.json must be valid JSON and the keys we read in the rc snippet
# (port, proxyPort) must be either absent or numeric. A truncated /
# corrupted config makes shell startup spew python tracebacks.
detect_truncated_config() {
  local cfg="${1:-$HOME/.claude/account-switcher/config.json}"
  [[ -f "$cfg" ]] || return 0
  if ! _json_is_valid "$cfg"; then
    _issue config-corrupt error \
      "$cfg is not valid JSON (truncated, partial-write, or hand-edited)" \
      "Restore from $cfg.example or delete the file (defaults will apply)."
    return 0
  fi
  local p
  for p in port proxyPort; do
    local v
    v="$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    v = d.get(sys.argv[2])
    if v is None:
        print('absent')
    elif isinstance(v, int):
        print('ok')
    else:
        print('bad-type')
except Exception:
    print('error')
" "$cfg" "$p" 2>/dev/null)"
    case "$v" in
      bad-type)
        _issue config-bad-type warn \
          "$cfg key '$p' is present but not an integer" \
          "Edit the file: remove the key (defaults apply) or set a numeric value." ;;
      error)
        : # already flagged by JSON validity check above
        ;;
    esac
  done
}

# detect_disabling_env_vars
# Five env vars cause Claude Code to bypass the keychain entirely; four
# more route to non-Anthropic backends. install.sh already warns for the
# first set — this detector centralises both for use from uninstall.sh's
# audit too.
detect_disabling_env_vars() {
  local v
  for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_OAUTH_TOKEN \
           CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_OAUTH_REFRESH_TOKEN; do
    if [[ -n "${!v:-}" ]]; then
      _issue env-bypass warn \
        "$v is set in the current shell — Claude Code will read it instead of the keychain" \
        "Unset it (e.g. \`unset $v\`) before running Claude Code if you want vdm rotation to work."
    fi
  done
  for v in CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX \
           CLAUDE_CODE_USE_FOUNDRY CLAUDE_CODE_USE_MANTLE; do
    if [[ -n "${!v:-}" ]]; then
      _issue env-cloud-route warn \
        "$v routes Claude Code to a non-Anthropic backend, bypassing vdm entirely" \
        "Unset it to route through vdm, or accept that the proxy is bypassed."
    fi
  done
}

# detect_managed_settings_restrictions
# allowManagedHooksOnly / disableAllHooks in macOS managed-settings.json
# silently drop every user-level hook. vdm hooks won't fire in that case.
detect_managed_settings_restrictions() {
  local ms="/Library/Application Support/ClaudeCode/managed-settings.json"
  [[ -f "$ms" ]] || return 0
  if ! _json_is_valid "$ms"; then
    return 0  # not vdm's problem to flag
  fi
  local flags
  flags="$(python3 -c "
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
out = []
if d.get('disableAllHooks') is True:
    out.append('disableAllHooks')
if d.get('allowManagedHooksOnly') is True:
    out.append('allowManagedHooksOnly')
print(','.join(out))
" "$ms" 2>/dev/null)"
  if [[ -n "$flags" ]]; then
    _issue managed-restriction warn \
      "Managed-settings sets: $flags — vdm hooks will be silently dropped" \
      "Ask your admin to add allowedHttpHookUrls: ['http://localhost:3333/*'] to managed-settings, or accept that token tracking is off."
  fi
}

# render_detected_issues
# Pretty-print VDM_DETECTED_ISSUES grouped by severity. Returns the
# count of error/blocker entries via stdout's last line so the caller
# can branch.
render_detected_issues() {
  local n_err=0 n_blk=0 n_warn=0 n_info=0
  local issue cat sev desc fix
  if (( ${#VDM_DETECTED_ISSUES[@]} == 0 )); then
    echo -e "  ${GREEN}✓${NC} No issues detected."
    return 0
  fi
  echo -e "  ${BOLD}Detected issues:${NC}"
  for issue in "${VDM_DETECTED_ISSUES[@]}"; do
    cat="${issue%%|*}"
    sev="${issue#*|}";  sev="${sev%%|*}"
    desc="${issue#*|*|}"; desc="${desc%%|*}"
    fix="${issue##*|}"
    local sym color
    case "$sev" in
      blocker) sym="✗"; color="$RED";    n_blk=$((n_blk + 1)) ;;
      error)   sym="!"; color="$RED";    n_err=$((n_err + 1)) ;;
      warn)    sym="⚠"; color="$YELLOW"; n_warn=$((n_warn + 1)) ;;
      *)       sym="ℹ"; color="$CYAN";   n_info=$((n_info + 1)) ;;
    esac
    echo -e "    ${color}${sym}${NC} [${cat}] ${desc}"
    echo -e "      ${DIM}fix:${NC} ${DIM}${fix}${NC}"
  done
  echo ""
  echo -e "  ${DIM}(${n_blk} blocker, ${n_err} error, ${n_warn} warn, ${n_info} info)${NC}"
  # Return non-zero count via the function's exit status so callers can
  # branch with `if ! render_detected_issues; then …`.
  return $(( n_blk + n_err ))
}
