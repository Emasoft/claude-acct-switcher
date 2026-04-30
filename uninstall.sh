#!/usr/bin/env bash
# Claude Account Switcher  - Uninstaller
# Safely removes vdm, the dashboard, shell config, and optionally saved accounts.
#
# Robustness contract (mirrors install.sh):
# - Every disk write is atomic via lib-install.sh helpers.
# - Process kills verify the target's cmdline before SIGKILL — no PID
#   reuse races. Dashboard gets a graceful SIGTERM + drain window
#   before the install dir is removed (so half-written state files
#   never escape to disk).
# - Cleanup stack runs on EXIT, INT, TERM, HUP via _trap_signals.
# - Section 9 audit ALWAYS runs, even if earlier sections crashed,
#   because it's wired into the cleanup stack.
# - Pre-flight detection (--detect) reports issues without modifying
#   anything; useful for "what would uninstall do?" inspection.

set -euo pipefail

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
# Preserve the original path for the section-9 audit (the variable can be
# blanked mid-script when the accounts/ backup fails — see section 5).
INSTALL_DIR_ORIG="$INSTALL_DIR"

# Resolve the dir containing THIS uninstall.sh so we can find the
# sibling lib-install.sh + commands/ + install-hooks.sh whether the
# user runs ./uninstall.sh from a checkout, from $INSTALL_DIR after a
# completed install, or from /usr/local/bin via symlink.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Source the shared safety primitives. Prefer the installed copy
# (matches the version that wrote the install) but fall back to the
# sibling copy in the source repo. If neither exists we run in
# degraded mode — no atomic helpers, no detectors. Continue rather
# than abort: a user trying to clean up a broken install needs the
# uninstaller to keep working even when half the helpers are missing.
_LIB=""
if [[ -f "$INSTALL_DIR/lib-install.sh" ]]; then
  _LIB="$INSTALL_DIR/lib-install.sh"
elif [[ -f "$SCRIPT_DIR/lib-install.sh" ]]; then
  _LIB="$SCRIPT_DIR/lib-install.sh"
fi
if [[ -n "$_LIB" ]]; then
  # shellcheck source=/dev/null
  . "$_LIB"
  _trap_signals
else
  echo -e "${YELLOW}Warning: lib-install.sh not found — running in degraded mode (no atomic helpers).${NC}" >&2
  # Provide minimal stubs so unconditional calls below don't crash.
  VDM_CLEANUP_ACTIONS=()
  _trap_signals() { :; }
  _register_cleanup() { :; }
  _safe_kill_pid() { kill "-${3:-TERM}" "$1" 2>/dev/null; }
  _atomic_remove_block() { return 1; }
  _atomic_write_string() { printf '%s' "$2" > "$1"; }
  render_detected_issues() { return 0; }
fi

# ── Flag parsing ──
# By default the script is interactive (4 prompts: main confirm, keychain
# purge/keep, backup-file cleanup, LaunchAgent removal). The flags below
# are the unattended path — useful for CI, scripted re-installs, and
# "I just want this gone" workflows.
NON_INTERACTIVE=false
PURGE_KEYCHAIN=false  # default: keep saved vdm-account-* entries
PURGE_BACKUPS=false   # default: keep .vdm-backup files
REMOVE_LAUNCHAGENT=false  # default: keep any vdm-shaped LaunchAgent

usage() {
  cat <<'EOF'
Usage: ./uninstall.sh [options]

Options:
  -y, --yes, --non-interactive
      Run without prompting. Defaults are conservative — saved keychain
      entries, backup files, and LaunchAgents are KEPT unless one of the
      flags below is also set.

  --purge-keychain
      With --non-interactive, also delete every "vdm-account-*"
      Keychain entry. Without this flag the entries are preserved so
      a future re-install picks them up automatically.

  --purge-backups
      With --non-interactive, also delete the .vdm-backup files left
      over from prior installs (settings.json.vdm-backup, the per-rc
      .vdm-backup files, and orphan backups).

  --remove-launchagent
      With --non-interactive, unload + delete any vdm-shaped LaunchAgent
      (~/Library/LaunchAgents/*claude*account*switcher*.plist or
      *vdm*.plist).

  --detect
      Read-only: run all detectors (orphaned hooks, dangling symlinks,
      malformed rc, port collisions, partial installs) and exit. Does
      not modify anything. Useful for "what's vdm's footprint right
      now?" inspection without committing to an uninstall.

  -h, --help
      Show this message.

Without --non-interactive, the script asks each question on stdin and
the above flags are ignored.
EOF
}

DETECT_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes|--non-interactive|--quiet)
      NON_INTERACTIVE=true; shift ;;
    --purge-keychain)
      PURGE_KEYCHAIN=true; shift ;;
    --purge-backups)
      PURGE_BACKUPS=true; shift ;;
    --remove-launchagent)
      REMOVE_LAUNCHAGENT=true; shift ;;
    --detect)
      DETECT_ONLY=true; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --) shift; break ;;
    *)
      echo "Unknown flag: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

# --detect: read-only sweep, then exit. Lets users inspect vdm's
# footprint without committing to a destructive uninstall.
if [[ "$DETECT_ONLY" == "true" ]]; then
  echo ""
  echo -e "${BOLD}  vdm footprint scan${NC}"
  echo -e "  ─────────────────────"
  if [[ -n "$_LIB" ]]; then
    detect_old_install_remnants "$INSTALL_DIR"
    detect_orphaned_settings_hooks
    detect_malformed_rc_blocks
    detect_dangling_symlinks
    detect_port_holders "${CSW_PORT:-3333}" "${CSW_PROXY_PORT:-3334}"
    detect_orphan_keychain_entries "$INSTALL_DIR"
    detect_truncated_config "$INSTALL_DIR/config.json"
    set +e
    render_detected_issues
    set -e
  else
    echo -e "  ${YELLOW}Detectors unavailable (lib-install.sh missing)${NC}"
  fi
  echo ""
  exit 0
fi

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Uninstaller${NC}"
echo -e "  ──────────────────────────────────────────"
if [[ "$NON_INTERACTIVE" == "true" ]]; then
  echo -e "  ${DIM}(non-interactive mode — purge_keychain=$PURGE_KEYCHAIN, purge_backups=$PURGE_BACKUPS, remove_launchagent=$REMOVE_LAUNCHAGENT)${NC}"
fi
echo ""

# ── Show what will be removed ──

echo -e "  ${BOLD}This will:${NC}"
echo -e "    1. Stop the running dashboard/proxy"
echo -e "    2. Remove the shell config block from your shell rc file"
echo -e "    3. Remove the ${CYAN}vdm${NC} symlink from PATH"
echo -e "    4. Remove ${CYAN}$INSTALL_DIR${NC}"
echo -e "    5. Optionally delete saved ${CYAN}vdm-account-*${NC} Keychain entries"
echo -e "    6. Remove vdm-installed slash commands from ${CYAN}~/.claude/commands/${NC}"
echo ""

# Track whether the user explicitly chose to KEEP saved account profiles.
# Saved accounts live in the macOS Keychain as `vdm-account-*` entries
# (no longer plaintext files). Default to preserve — these are user data,
# not vdm-owned scaffolding. The keychain cleanup step at section 5b
# honours this flag.
preserve_accounts=true
ACCT_COUNT=0

# Count saved keychain entries. `security dump-keychain` lists every
# generic-password entry in the user's login keychain; we filter by the
# vdm-account- prefix and count distinct names.
_VDM_ACCOUNT_NAMES_RAW="$(security dump-keychain 2>/dev/null \
  | grep -E '"svce"<blob>="vdm-account-' \
  | sed -E 's/.*"svce"<blob>="vdm-account-([^"]+)".*/\1/' \
  | grep -E '^[a-zA-Z0-9._@-]+$' \
  | sort -u || true)"
if [[ -n "$_VDM_ACCOUNT_NAMES_RAW" ]]; then
  ACCT_COUNT=$(printf '%s\n' "$_VDM_ACCOUNT_NAMES_RAW" | wc -l | tr -d ' ')
fi

if [[ "$ACCT_COUNT" -gt 0 ]]; then
  echo -e "  ${YELLOW}Note:${NC} You have ${BOLD}$ACCT_COUNT saved account profile(s)${NC} in the macOS Keychain"
  echo -e "  ${DIM}(stored as ${CYAN}vdm-account-*${DIM} entries — OAuth tokens cached for fast switching.${NC}"
  echo -e "  ${DIM} Your ACTIVE Keychain entry written by Claude Code itself is NOT touched.)${NC}"
  echo ""
fi

# `read` in a stand-alone statement under `set -e` exits the script on
# EOF (Ctrl-D / closed stdin). Wrap in `|| true` and force-cancel so the
# user gets a friendly message instead of an abrupt errexit.
if [[ "$NON_INTERACTIVE" != "true" ]]; then
  confirm=""
  read -rp "  Continue? [y/N] " confirm || { echo ""; echo -e "  ${DIM}Cancelled.${NC}"; exit 0; }
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo -e "  ${DIM}Cancelled.${NC}"
    echo ""
    exit 0
  fi
fi

# Second, separate prompt for the saved-profiles question. Default is
# PRESERVE (keep them). Only an explicit `purge` answer deletes them —
# any other input (including bare `y`, blank, EOF) keeps them. This is
# deliberately stricter than the main confirm so an autopilot-y user
# can't lose all their saved logins by reflexively typing y/Enter.
# In non-interactive mode the prompt is skipped — preserve_accounts is
# driven by --purge-keychain instead.
if [[ "$ACCT_COUNT" -gt 0 ]]; then
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ "$PURGE_KEYCHAIN" == "true" ]]; then
      preserve_accounts=false
      echo -e "  ${YELLOW}!${NC} Saved keychain entries will be DELETED (--purge-keychain)."
    else
      echo -e "  ${GREEN}✓${NC} Saved keychain entries will be kept (no --purge-keychain)."
    fi
  else
    echo ""
    echo -e "  ${BOLD}$ACCT_COUNT${NC} saved profile(s) live as ${CYAN}vdm-account-*${NC} entries in the macOS Keychain."
    echo -e "  ${DIM}They hold OAuth access + refresh tokens. Keychain entries are encrypted at rest${NC}"
    echo -e "  ${DIM}by macOS, but anything with the user's login keychain unlocked can read them.${NC}"
    echo ""
    echo -e "     ${BOLD}purge${NC}  delete the keychain entries (recommended on shared machines)"
    echo -e "     ${BOLD}keep${NC}   leave them in the Keychain (so a re-install picks them up automatically)"
    echo ""
    purge_input=""
    read -rp "  How should saved profiles be handled? [purge / keep] " purge_input || purge_input=""
    if [[ "$purge_input" == "purge" ]]; then
      preserve_accounts=false
      echo -e "  ${YELLOW}!${NC} Saved keychain entries will be DELETED."
    else
      echo -e "  ${GREEN}✓${NC} Saved keychain entries will be kept."
    fi
  fi
fi

echo ""

# ── 1. Stop running processes ──
# Honour CSW_PORT / CSW_PROXY_PORT overrides — a user who installed with
# custom ports also runs with custom ports, so hardcoding 3333/3334 here
# would silently fail to kill the listeners and leave stale processes.
# Defaults match install.sh. The actual kill logic (graceful → port-bound
# SIGTERM → cmdline pkill → drain → SIGKILL) lives in lib-install.sh's
# _kill_running_vdm so install.sh and uninstall.sh share one implementation.
_DASH_PORT="${CSW_PORT:-3333}"
_PROXY_PORT="${CSW_PROXY_PORT:-3334}"

if _kill_running_vdm "$_DASH_PORT" "$_PROXY_PORT"; then
  echo -e "  ${GREEN}✓${NC} Stopped dashboard/proxy"
else
  echo -e "  ${DIM}No running dashboard/proxy found${NC}"
fi

# ── 2. Remove shell config block ──
# Issues that bit prior versions:
#   (a) only `.zshrc/.bashrc/.bash_profile` were searched. On modern
#       macOS zsh the recommended location for env-var exports is
#       `.zprofile`, and some users keep snippets in `.zshenv` or
#       `.profile`. Now we scan all five.
#   (b) the search loop broke on the first match, so a user who had
#       reinstalled across shells or hand-copied the snippet ended up
#       with the block lingering in subsequent files. Now we clean
#       every file where the marker is found.
#   (c) the sed pattern was anchored at column 0 (`^# BEGIN ...`) but
#       the grep wasn't, so any indented snippet was "found but not
#       removed" — the unsolicited silent-failure bug. Now both grep
#       and sed allow optional leading whitespace.
#   (d) a stray CRLF line ending (file edited under Windows) made the
#       END marker fail to match `^# END$`, deleting from BEGIN to EOF.
#       We strip CRLF before sed touches the file.

# Helper: track every cleaned file so we can list backups + report.
CLEANED_RC_FILES=()
# Backups left behind after a malformed-marker abort. The file itself was
# RESTORED (not modified), so it doesn't go in CLEANED_RC_FILES — but the
# .vdm-backup copy we made in `cp "$rc" "${rc}.vdm-backup"` is now a
# stale on-disk artefact. Surface it in the section-6 cleanup prompt so
# the user is offered the chance to remove it instead of finding random
# `*.vdm-backup` files months later.
ORPHAN_BACKUPS=()

clean_one_rc() {
  local rc="$1"
  [[ -f "$rc" ]] || return 0
  # Permissive grep: any line that contains the marker (possibly indented,
  # possibly with trailing CR from a CRLF file).
  grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$' "$rc" 2>/dev/null || return 0

  # Backup BEFORE touching anything. _atomic_replace performs the
  # backup as tmp + rename so a Ctrl-C between cp's first byte and
  # last cannot leave a partial / truncated backup that could later
  # silently overwrite the original on restore.
  if ! _atomic_replace "$rc" "${rc}.vdm-backup" 2>/dev/null; then
    # Fallback to plain cp — the rc file contents are about to be
    # rewritten anyway, so a partial backup window is acceptable here.
    cp "$rc" "${rc}.vdm-backup"
  fi

  # _atomic_remove_block from lib-install.sh:
  #   - composes the new file in <rc>.tmp.<pid> (tr -d '\r' | sed delete)
  #   - rename(2)s atomically over the original (no half-written window)
  #   - returns 0 on success, 1 if no markers, 2 if BEGIN/END mismatch
  set +e
  _atomic_remove_block "$rc" \
    '^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$' \
    '^[[:space:]]*# END claude-account-switcher[[:space:]]*$'
  local rc_status=$?
  set -e

  case "$rc_status" in
    0)
      CLEANED_RC_FILES+=("$rc")
      echo -e "  ${GREEN}✓${NC} Removed auto-start block from ${CYAN}$rc${NC}"
      echo -e "    ${DIM}Backup: ${rc}.vdm-backup${NC}"
      ;;
    1)
      # No markers found after backup — implausible but not data-loss
      # (we backed up first). Drop the redundant backup.
      rm -f "${rc}.vdm-backup"
      ;;
    2)
      # Malformed: BEGIN without END, or vice versa. _atomic_remove_block
      # didn't write anything — the original file is unchanged. We restore
      # from backup as defence-in-depth (in case a future implementation
      # changes that contract) and surface it.
      cat "${rc}.vdm-backup" > "$rc" 2>/dev/null || true
      echo -e "  ${RED}!${NC} ${BOLD}${rc}${NC} has an unmatched BEGIN/END marker — refusing to auto-edit."
      echo -e "    ${DIM}Original preserved. Remove the claude-account-switcher block manually.${NC}"
      ORPHAN_BACKUPS+=("${rc}.vdm-backup")
      ;;
    *)
      # Any other status = unexpected; restore + surface.
      cat "${rc}.vdm-backup" > "$rc" 2>/dev/null || true
      echo -e "  ${RED}!${NC} Unexpected status $rc_status removing block from $rc — restored from backup"
      ORPHAN_BACKUPS+=("${rc}.vdm-backup")
      ;;
  esac
}

CHECKED_RCS=()
for rc in \
    "$HOME/.zshrc"         "$HOME/.zprofile"      "$HOME/.zshenv" \
    "$HOME/.bashrc"        "$HOME/.bash_profile"  "$HOME/.profile"; do
  CHECKED_RCS+=("$rc")
  clean_one_rc "$rc"
done

if (( ${#CLEANED_RC_FILES[@]} == 0 )); then
  echo -e "  ${DIM}No shell config block found in any of:${NC}"
  for rc in "${CHECKED_RCS[@]}"; do echo -e "    ${DIM}$rc${NC}"; done
  echo -e "  ${DIM}If you installed the snippet elsewhere, remove the BEGIN/END block manually.${NC}"
fi
# For the "Backups left behind" prompt below: pick the first cleaned
# file (any will do — backups exist for all of them).
SHELL_RC="${CLEANED_RC_FILES[0]:-}"

# ── 2b. Add defensive `unset ANTHROPIC_BASE_URL` cleanup block ──
# Removing the install BEGIN/END block stops FUTURE shells from re-setting
# ANTHROPIC_BASE_URL=http://localhost:<port>, but it does NOT unset values
# inherited from PARENT processes that were forked while the var was live
# (login shell, iTerm app, PM2 daemon, ai-maestro). Those parents carry
# the polluted env in memory until they themselves are restarted (logout +
# login, reboot, or `pm2 kill && pm2 resurrect`). Until then, every fresh
# shell descended from a polluted parent silently inherits the dead URL —
# every `claude` invocation gets ConnectionRefused, every `pm2 save` re-
# pollutes the dump, every iTerm tab is contaminated.
#
# Defensive fix: actively `unset` on every shell start. The cleanup block
# sits in the rc file independent of vdm being installed; when vdm is
# re-installed, install.sh strips this block before adding its own (so
# re-install is idempotent and the snippet's :- default fallback works).
# Block is self-documenting and safe for the user to delete manually once
# they have fully logged out + back in or rebooted.
CLEANUP_TARGET=""
for _rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.bashrc" "$HOME/.bash_profile"; do
  [[ -f "$_rc" ]] || continue
  # Skip if this rc already has the cleanup block (idempotent re-uninstall).
  if grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher-cleanup[[:space:]]*$' "$_rc" 2>/dev/null; then
    CLEANUP_TARGET="$_rc"
    echo -e "  ${DIM}Cleanup block already present in $_rc${NC}"
    break
  fi
  # Otherwise pick the first existing rc file as the install target.
  if [[ -z "$CLEANUP_TARGET" ]]; then
    CLEANUP_TARGET="$_rc"
  fi
done

if [[ -n "$CLEANUP_TARGET" ]] \
   && ! grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher-cleanup[[:space:]]*$' "$CLEANUP_TARGET" 2>/dev/null; then
  CLEANUP_BODY="$(mktemp -t vdm-cleanup.XXXXXX 2>/dev/null || echo '')"
  if [[ -n "$CLEANUP_BODY" ]]; then
    cat > "$CLEANUP_BODY" <<'CLEANUP_EOF'
# Defensive cleanup left by claude-account-switcher uninstall.
# vdm used to export ANTHROPIC_BASE_URL=http://localhost:<port> in this
# rc file. Removing that export stops future shells from re-setting it,
# but does NOT unset values inherited from parent processes that were
# forked while the var was still active (login shell, iTerm app, PM2
# daemon, ai-maestro). Actively unsetting on every shell start is the
# only way to keep new shells clean until those parents are themselves
# restarted (logout/login, reboot, or `pm2 kill && pm2 resurrect`).
#
# Safe to delete this block manually once you have fully logged out and
# back in, or rebooted — after that no parent process can carry the
# stale URL. A subsequent install of vdm removes this block automatically.
unset ANTHROPIC_BASE_URL
CLEANUP_EOF
    if _atomic_append_block "$CLEANUP_TARGET" \
        "# BEGIN claude-account-switcher-cleanup" \
        "# END claude-account-switcher-cleanup" \
        "$CLEANUP_BODY" 2>/dev/null; then
      echo -e "  ${GREEN}✓${NC} Added defensive ${CYAN}unset ANTHROPIC_BASE_URL${NC} block to ${CYAN}$CLEANUP_TARGET${NC}"
      echo -e "    ${DIM}Open new terminals (or run \`exec zsh\` in each tab) so the unset takes effect.${NC}"
      echo -e "    ${DIM}If PM2 was managing services that inherited the polluted env, run:${NC}"
      echo -e "    ${DIM}  unset ANTHROPIC_BASE_URL && pm2 kill && pm2 resurrect${NC}"
    fi
    rm -f "$CLEANUP_BODY"
  fi
fi

# ── 3. Remove vdm symlink (and legacy csw) ──

removed_link=false
# Strictly match the install path. The previous substring `*account-switcher*`
# was too lax: any unrelated symlink whose target merely contained that
# string (e.g. `/Users/dev/my-account-switcher-tool/bin/vdm`, or a forked
# project under a similarly-named directory, or `/opt/homebrew/bin/vdm`
# pointing at a homebrew-installed account-switcher) would be deleted by
# uninstall. Mirror install.sh's stricter `*"/.claude/account-switcher/"*`
# anchor so we only ever remove links we created. Also include the
# Apple-Silicon homebrew bindir which install.sh now writes to as well.
for link in \
    "$HOME/.local/bin/vdm"     "$HOME/.local/bin/csw" \
    "/opt/homebrew/bin/vdm"    "/opt/homebrew/bin/csw" \
    "/usr/local/bin/vdm"       "/usr/local/bin/csw"; do
  if [[ -L "$link" ]]; then
    target=$(readlink "$link" 2>/dev/null || true)
    if [[ "$target" == *"/.claude/account-switcher/"* ]]; then
      rm -f "$link"
      echo -e "  ${GREEN}✓${NC} Removed symlink ${DIM}$link${NC}"
      removed_link=true
    fi
  fi
done
if [[ "$removed_link" != "true" ]]; then
  echo -e "  ${DIM}No vdm symlink found${NC}"
fi

# ── 4. Remove token tracking hooks ──
# Source install-hooks.sh from the installed copy if it still exists,
# otherwise fall back to the copy that lives next to this uninstall.sh
# (the source repo). Without the fallback, a user who manually deleted
# $INSTALL_DIR before running uninstall.sh — or whose install was already
# partially-removed by a prior aborted uninstall — would leave Claude
# Code's settings.json with stale hook entries pointing at a dead port.
HOOKS_LIB=""
if [[ -f "$INSTALL_DIR/install-hooks.sh" ]]; then
  HOOKS_LIB="$INSTALL_DIR/install-hooks.sh"
else
  # Resolve the directory of THIS uninstall.sh (works when invoked via
  # symlink, $PATH, or directly) and look for a sibling install-hooks.sh.
  _UNINST_DIR="$(cd "$(dirname "$0")" && pwd -P 2>/dev/null || true)"
  if [[ -n "$_UNINST_DIR" && -f "$_UNINST_DIR/install-hooks.sh" ]]; then
    HOOKS_LIB="$_UNINST_DIR/install-hooks.sh"
  fi
fi

# Detect whether we set core.hooksPath ourselves (marker file written by
# install-hooks.sh's _install_git_hook). This affects the post-uninstall
# advice we print — git-lfs writes hooks INTO the active hooksPath, so a
# user who ran `git lfs install` after vdm took over the global hooksPath
# now has lfs hooks living in the dir vdm is about to clean up.
_VDM_OWNED_HOOKS_PATH=""
if [[ -n "$HOOKS_LIB" ]]; then
  # Resolve current global hooksPath BEFORE uninstall_hooks runs,
  # since uninstall unsets it.
  _CUR_HOOKS_PATH="$(git config --global core.hooksPath 2>/dev/null || true)"
  _CUR_HOOKS_PATH="${_CUR_HOOKS_PATH/#\~/$HOME}"
  if [[ -n "$_CUR_HOOKS_PATH" && -f "$_CUR_HOOKS_PATH/.vdm-set-hooks-path" ]]; then
    _VDM_OWNED_HOOKS_PATH="$_CUR_HOOKS_PATH"
  fi
fi

if [[ -n "$HOOKS_LIB" ]]; then
  # shellcheck source=/dev/null
  source "$HOOKS_LIB"
  uninstall_hooks && echo -e "  ${GREEN}✓${NC} Removed token tracking hooks" || true

  # If we owned the global hooksPath AND the user has git-lfs installed,
  # warn them that any LFS hooks they configured may now be orphaned —
  # `git lfs install` writes pre-push / post-checkout / post-commit /
  # post-merge hooks into whatever core.hooksPath was active at the time.
  # If the path was vdm's `~/.config/git/hooks/` and that dir survived
  # (because non-vdm files remained in it), the LFS hooks are still on
  # disk but no longer wired up via core.hooksPath. We don't auto-rerun
  # `git lfs install` because that's per-repo and out-of-scope; we just
  # tell the user what to do.
  if [[ -n "$_VDM_OWNED_HOOKS_PATH" ]] && command -v git-lfs >/dev/null 2>&1; then
    echo ""
    echo -e "  ${YELLOW}Note:${NC} git-lfs detected and vdm previously managed your global git hooks dir."
    echo -e "  ${DIM}If LFS hooks were auto-installed under that dir, rewire them with:${NC}"
    echo -e "    ${DIM}git lfs install --force --skip-repo${NC}    ${DIM}# global${NC}"
    echo -e "    ${DIM}# then in each LFS-tracked repo: git lfs install --force${NC}"
  fi
fi

# ── 5. Remove install directory ──
# Account credentials live in the macOS Keychain (vdm-account-*) so
# there is no plaintext-tokens dir to back up. The accounts/ directory
# may still hold *.label files (just email/display names — no secrets);
# those go away with the rest of $INSTALL_DIR.
#
# Defence-in-depth: refuse to rm -rf unless the path looks vdm-shaped.
# Three layers:
#   1. The path must end in `/.claude/account-switcher` (exact suffix).
#      Catches a corrupted INSTALL_DIR pointing at $HOME or `/`.
#   2. The path must be under $HOME — never delete a system path.
#   3. The dir must contain at least one of dashboard.mjs, vdm,
#      install-hooks.sh — i.e. look like a vdm install. If a previous
#      uninstall wiped the executables but the dir survived (say,
#      because of an open file on Finder), we still allow removal —
#      labels and state files are vdm-owned. So the check is "either
#      vdm files present, or only vdm-shaped state files present".
ACCOUNTS_BACKUP=""

_safe_to_rmrf() {
  local d="$1"
  [[ -z "$d" ]] && return 1
  [[ "$d" != *"/.claude/account-switcher" ]] && return 1
  [[ "$d" != "$HOME"* ]] && return 1
  [[ ! -d "$d" ]] && return 1
  # If the dir has vdm executables, it's clearly vdm-owned.
  if [[ -f "$d/dashboard.mjs" ]] || [[ -f "$d/vdm" ]] \
     || [[ -f "$d/install-hooks.sh" ]] || [[ -f "$d/lib.mjs" ]]; then
    return 0
  fi
  # Otherwise: every entry must be a vdm-shaped state file or the
  # accounts/ subdir. Any unrecognised entry → refuse (could be user
  # data we don't recognise).
  local entry name
  for entry in "$d"/* "$d"/.[!.]*; do
    [[ -e "$entry" ]] || continue
    name="$(basename "$entry")"
    case "$name" in
      accounts|config.json|account-state.json|activity-log.json \
      |utilization-history.json|probe-log.json|token-usage.json \
      |.dashboard.pid|.hooks-disabled|.version|startup.log \
      |per-tool-attribution.flag|*.tmp|*.tmp.*) ;;
      *) return 1 ;;
    esac
  done
  return 0
}

if [[ -n "$INSTALL_DIR" && -d "$INSTALL_DIR" ]]; then
  if _safe_to_rmrf "$INSTALL_DIR"; then
    rm -rf "$INSTALL_DIR"
    echo -e "  ${GREEN}✓${NC} Removed ${CYAN}$INSTALL_DIR${NC}"
  else
    echo -e "  ${RED}!${NC} ${BOLD}$INSTALL_DIR${NC} does not look like a vdm install dir — refusing to rm -rf."
    echo -e "    ${DIM}If this is correct, remove it manually: rm -rf \"$INSTALL_DIR\"${NC}"
  fi
elif [[ -n "$INSTALL_DIR" ]]; then
  echo -e "  ${DIM}$INSTALL_DIR does not exist (already clean)${NC}"
fi

# ── 5b. Remove vdm-account-* Keychain entries (when purge requested) ──
# The earlier prompt asked "purge / keep". Keep is the default and leaves
# every saved account intact in the keychain so a future re-install picks
# them up. Purge enumerates every vdm-account-<name> entry and deletes
# it. We deliberately do not touch the canonical Claude Code-credentials
# slot here — that's the active account written by Claude Code itself.
if [[ "$preserve_accounts" != "true" ]] && [[ "$ACCT_COUNT" -gt 0 ]]; then
  while IFS= read -r _vdm_acct; do
    [[ -z "$_vdm_acct" ]] && continue
    security delete-generic-password \
      -s "vdm-account-${_vdm_acct}" \
      -a "$USER" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}✓${NC} Removed Keychain entry ${CYAN}vdm-account-${_vdm_acct}${NC}" \
      || echo -e "  ${YELLOW}!${NC} Could not remove vdm-account-${_vdm_acct} (may already be gone)"
  done < <(printf '%s\n' "$_VDM_ACCOUNT_NAMES_RAW")
elif [[ "$ACCT_COUNT" -gt 0 ]]; then
  echo -e "  ${DIM}Saved Keychain entries kept (run with 'purge' to delete them).${NC}"
fi

# ── 5c. Remove vdm-installed slash commands ──
# install.sh copies every commands/*.md into ~/.claude/commands/. Remove
# only those copies — leave unrelated user commands untouched. We match
# by the source file basenames so no other commands are accidentally
# touched, regardless of what other plugins put in there.
_UNINST_DIR="$(cd "$(dirname "$0")" && pwd -P 2>/dev/null || true)"
COMMANDS_SRC_DIR=""
if [[ -d "$_UNINST_DIR/commands" ]]; then
  COMMANDS_SRC_DIR="$_UNINST_DIR/commands"
fi
if [[ -n "$COMMANDS_SRC_DIR" ]] && [[ -d "$HOME/.claude/commands" ]]; then
  for cmd_file in "$COMMANDS_SRC_DIR"/*.md; do
    [[ -f "$cmd_file" ]] || continue
    local_cmd_name="$(basename "$cmd_file")"
    target="$HOME/.claude/commands/$local_cmd_name"
    if [[ -f "$target" ]]; then
      rm -f -- "$target" \
        && echo -e "  ${GREEN}✓${NC} Removed slash command ${CYAN}/$(basename "$local_cmd_name" .md)${NC}" \
        || echo -e "  ${YELLOW}!${NC} Could not remove $target"
    fi
  done
fi

# ── 6. Offer to clean up backup files ──
# uninstall historically left these behind; they accumulate over repeated
# install/uninstall cycles. Offer to remove them at the end. Iterate
# every rc file we cleaned (not just SHELL_RC) so multi-file installs
# get every backup listed.
backup_candidates=()
# Guard the array dereference: under `set -u` an empty array expanded with
# `${arr[@]:-}` evaluates to a single empty string element, so the loop body
# would run once with `rc=""`. Test the length explicitly before iterating.
if (( ${#CLEANED_RC_FILES[@]} > 0 )); then
  for rc in "${CLEANED_RC_FILES[@]}"; do
    [[ -n "$rc" ]] && [[ -f "${rc}.vdm-backup" ]] && backup_candidates+=("${rc}.vdm-backup")
  done
fi
# Orphan backups from rc files we refused to auto-edit (malformed markers).
if (( ${#ORPHAN_BACKUPS[@]} > 0 )); then
  for f in "${ORPHAN_BACKUPS[@]}"; do
    [[ -n "$f" ]] && [[ -f "$f" ]] && backup_candidates+=("$f")
  done
fi
[[ -f "$HOME/.claude/settings.json.vdm-backup" ]] && backup_candidates+=("$HOME/.claude/settings.json.vdm-backup")
if (( ${#backup_candidates[@]} > 0 )); then
  echo ""
  echo -e "  ${BOLD}Backup files left behind:${NC}"
  for f in "${backup_candidates[@]}"; do echo -e "    ${DIM}$f${NC}"; done
  # Same EOF safety as the main confirm prompt — a closed stdin should
  # not crash the script just before the friendly footer.
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    rm_backups="$([[ "$PURGE_BACKUPS" == "true" ]] && echo y || echo n)"
  else
    rm_backups=""
    read -rp "  Remove these backups? [y/N] " rm_backups || rm_backups=""
  fi
  if [[ "$rm_backups" == "y" || "$rm_backups" == "Y" ]]; then
    for f in "${backup_candidates[@]}"; do rm -f "$f" 2>/dev/null && echo -e "    ${GREEN}✓${NC} Removed $f" || true; done
  else
    echo -e "    ${DIM}Backups kept. Remove manually if you don't need them.${NC}"
  fi
fi

# ── 7. Cleanup install/uninstall mutex lock dirs ──
# install.sh and install-hooks.sh use mkdir-based mutexes (no flock(1) on
# stock macOS). Their `trap RETURN` / `trap EXIT` cleans them up on normal
# exit, but a SIGKILL / OOM / power loss / Ctrl-C-during-rm can orphan the
# dir. After uninstall there's no install or settings-rewriter that could
# legitimately hold one, so any lock dir present is by definition stale.
# Remove unconditionally — they're vdm-owned and uninstall has just deleted
# everything that could legitimately depend on them.
for _lock in "$HOME/.claude/.vdm-install.lock.d" \
             "$HOME/.claude/.vdm-settings.lock.d"; do
  if [[ -d "$_lock" ]]; then
    rmdir "$_lock" 2>/dev/null && echo -e "  ${GREEN}✓${NC} Removed stale lock ${DIM}$_lock${NC}" || true
  fi
done

# ── 7b. Old vdm-accounts-backup-* dirs from prior uninstalls ──
# These accumulate across uninstall cycles. Listing them surfaces forgotten
# token caches; offering to delete them gives the user a one-stop way to
# wipe stale OAuth credentials. We never auto-delete — these contain
# plaintext tokens that the user explicitly chose to KEEP at some prior
# uninstall, so they're user data, not vdm scaffolding.
ORPHAN_BACKUPS_DIRS=()
for _bk in "$HOME/.claude"/vdm-accounts-backup-*; do
  [[ -d "$_bk" ]] || continue
  ORPHAN_BACKUPS_DIRS+=("$_bk")
done
# Don't list the backup we JUST created in this run as an "orphan".
# Guard the array expansion under bash 3.2 (stock macOS) which errors
# on empty-array references under `set -u`.
if [[ -n "${ACCOUNTS_BACKUP:-}" ]] && (( ${#ORPHAN_BACKUPS_DIRS[@]} > 0 )); then
  _filtered=()
  for _bk in "${ORPHAN_BACKUPS_DIRS[@]}"; do
    [[ "$_bk" == "$ACCOUNTS_BACKUP" ]] && continue
    _filtered+=("$_bk")
  done
  if (( ${#_filtered[@]} > 0 )); then
    ORPHAN_BACKUPS_DIRS=("${_filtered[@]}")
  else
    ORPHAN_BACKUPS_DIRS=()
  fi
fi
if (( ${#ORPHAN_BACKUPS_DIRS[@]} > 0 )); then
  echo ""
  echo -e "  ${YELLOW}Older backup directories from prior uninstalls:${NC}"
  for _bk in "${ORPHAN_BACKUPS_DIRS[@]}"; do
    _size="$(du -sh "$_bk" 2>/dev/null | awk '{print $1}')"
    _files="$(find "$_bk" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
    echo -e "    ${DIM}$_bk${NC} ${DIM}(${_files} profile(s), ${_size})${NC}"
  done
  echo -e "  ${DIM}Each contains plaintext OAuth tokens.${NC}"
  # --purge-backups also deletes the orphan accounts-backup directories
  # left over from prior interactive uninstalls. Without the flag, the
  # non-interactive default is to keep them (they're user-data, not
  # vdm-owned scaffolding).
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    rm_old_bks="$([[ "$PURGE_BACKUPS" == "true" ]] && echo y || echo n)"
  else
    rm_old_bks=""
    read -rp "  Delete these older backups too? [y/N] " rm_old_bks || rm_old_bks=""
  fi
  if [[ "$rm_old_bks" == "y" || "$rm_old_bks" == "Y" ]]; then
    for _bk in "${ORPHAN_BACKUPS_DIRS[@]}"; do
      rm -rf "$_bk" 2>/dev/null && echo -e "    ${GREEN}✓${NC} Removed $_bk" || true
    done
  else
    echo -e "    ${DIM}Older backups kept. Remove manually if you don't need them.${NC}"
  fi
fi

# ── 8. LaunchAgent (auto-cleanup if user agrees) ──
# Scan every plist that matches a vdm-shaped name pattern, not just the
# canonical com.loekj.vdm.dashboard.plist. Old installs, forks, or
# user-authored variants may use a different label (com.emasoft.vdm.plist,
# claude-account-switcher.plist, etc.) and a single hardcoded path would
# leave them behind on every uninstall. Each candidate is presented for
# removal individually so the user can keep one and discard another if
# they have multiple.
LAUNCHAGENT_CANDIDATES=()
for _plist in "$HOME/Library/LaunchAgents/"*; do
  [[ -f "$_plist" ]] || continue
  _bn="$(basename "$_plist")"
  case "$_bn" in
    *vdm*.plist|*claude*account*switcher*.plist|*claude-acct-switcher*.plist)
      LAUNCHAGENT_CANDIDATES+=("$_plist")
      ;;
  esac
done

if (( ${#LAUNCHAGENT_CANDIDATES[@]} > 0 )); then
  echo ""
  echo -e "  ${YELLOW}LaunchAgent(s) detected (${#LAUNCHAGENT_CANDIDATES[@]}):${NC}"
  for _plist in "${LAUNCHAGENT_CANDIDATES[@]}"; do
    echo -e "    ${DIM}$_plist${NC}"
  done
  for _plist in "${LAUNCHAGENT_CANDIDATES[@]}"; do
    _bn="$(basename "$_plist")"
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      rm_la="$([[ "$REMOVE_LAUNCHAGENT" == "true" ]] && echo y || echo n)"
    else
      rm_la=""
      read -rp "  Unload + remove ${_bn}? [y/N] " rm_la || rm_la=""
    fi
    if [[ "$rm_la" == "y" || "$rm_la" == "Y" ]]; then
      launchctl bootout "gui/$(id -u)" "$_plist" 2>/dev/null || true
      rm -f "$_plist" && echo -e "    ${GREEN}✓${NC} LaunchAgent removed: ${DIM}$_bn${NC}" || true
    else
      echo -e "    ${DIM}LaunchAgent kept: $_plist${NC}"
      echo -e "      ${DIM}launchctl bootout gui/\$(id -u) \"$_plist\" 2>/dev/null${NC}"
      echo -e "      ${DIM}rm -f \"$_plist\"${NC}"
    fi
  done
fi

# ── 9. Final verification audit ──
# Independently scan the system for anything vdm-shaped that might still be
# present. The user's main concern: hooks lingering in settings.json,
# auth tokens on disk, any other artefact uninstall didn't catch. We
# enumerate the same surfaces install touches and report any that still
# show vdm content. This is read-only and best-effort — we don't try to
# re-clean them automatically (the user just told us NOT to keep guessing
# what they want).
echo ""
echo -e "  ${BOLD}Verification — scanning for remaining vdm artefacts...${NC}"

LEFT_ARTIFACTS=()
# The install dir itself.
if [[ -d "$INSTALL_DIR_ORIG" ]] 2>/dev/null; then LEFT_ARTIFACTS+=("$INSTALL_DIR_ORIG"); fi
[[ -d "$HOME/.claude/account-switcher" ]] && LEFT_ARTIFACTS+=("$HOME/.claude/account-switcher")
# Lock dirs.
[[ -d "$HOME/.claude/.vdm-install.lock.d"  ]] && LEFT_ARTIFACTS+=("$HOME/.claude/.vdm-install.lock.d")
[[ -d "$HOME/.claude/.vdm-settings.lock.d" ]] && LEFT_ARTIFACTS+=("$HOME/.claude/.vdm-settings.lock.d")
# Settings.json residual hooks.
if [[ -f "$HOME/.claude/settings.json" ]]; then
  if grep -q "localhost:[0-9]*/api/\(session-start\|session-stop\|session-end\|subagent-start\|pre-compact\|post-compact\|cwd-changed\|post-tool-batch\|worktree-create\|worktree-remove\|task-created\|task-completed\|teammate-idle\|notification\|config-change\|user-prompt-expansion\)" \
        "$HOME/.claude/settings.json" 2>/dev/null; then
    LEFT_ARTIFACTS+=("$HOME/.claude/settings.json [contains vdm hook URL(s)]")
  fi
fi
# Symlinks.
for _lnk in "$HOME/.local/bin/vdm" "$HOME/.local/bin/csw" \
            "/opt/homebrew/bin/vdm" "/opt/homebrew/bin/csw" \
            "/usr/local/bin/vdm"    "/usr/local/bin/csw"; do
  if [[ -L "$_lnk" ]]; then
    _t="$(readlink "$_lnk" 2>/dev/null || true)"
    if [[ "$_t" == *"/.claude/account-switcher/"* ]]; then
      LEFT_ARTIFACTS+=("$_lnk -> $_t")
    fi
  fi
done
# Global git hooksPath still pointing at our dir + marker still present.
_gp="$(git config --global core.hooksPath 2>/dev/null || true)"
_gp="${_gp/#\~/$HOME}"
if [[ -n "$_gp" && -f "$_gp/.vdm-set-hooks-path" ]]; then
  LEFT_ARTIFACTS+=("git config --global core.hooksPath = $_gp (vdm-marker still present)")
fi
# Shell rc residual markers.
for _rc in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" \
           "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [[ -f "$_rc" ]] || continue
  if grep -q "claude-account-switcher" "$_rc" 2>/dev/null; then
    LEFT_ARTIFACTS+=("$_rc [contains 'claude-account-switcher' marker]")
  fi
done
# Slash commands installed by install.sh — anything we recognise from
# the source `commands/` dir that still exists under ~/.claude/commands/
# is a leftover.
if [[ -n "${COMMANDS_SRC_DIR:-}" ]] && [[ -d "$HOME/.claude/commands" ]]; then
  for _cmd in "$COMMANDS_SRC_DIR"/*.md; do
    [[ -f "$_cmd" ]] || continue
    _bn="$(basename "$_cmd")"
    if [[ -f "$HOME/.claude/commands/$_bn" ]]; then
      LEFT_ARTIFACTS+=("$HOME/.claude/commands/$_bn [vdm slash command not removed]")
    fi
  done
fi

if (( ${#LEFT_ARTIFACTS[@]} == 0 )); then
  echo -e "  ${GREEN}✓${NC} No vdm artefacts detected. Uninstall is clean."
else
  echo -e "  ${YELLOW}⚠${NC}  ${BOLD}${#LEFT_ARTIFACTS[@]} artefact(s) remain:${NC}"
  for _a in "${LEFT_ARTIFACTS[@]}"; do
    echo -e "    ${YELLOW}•${NC} $_a"
  done
  echo -e "  ${DIM}(These were not auto-removed — investigate and clean manually.)${NC}"
fi

# Apple Keychain — audit. Two distinct entry classes live here:
#   1. `Claude Code-credentials` — owned by Claude Code itself, holds the
#      ACTIVE account. We never touch this.
#   2. `vdm-account-*` — owned by vdm, one per saved profile. Section 5b
#      already removed these when the user asked to purge; otherwise they
#      stay. List anything still on disk so the user can audit.
KC_ENTRIES=()
for _svc in "Claude Code-credentials" "Claude" "Claude Code"; do
  if security find-generic-password -s "$_svc" -a "$USER" >/dev/null 2>&1; then
    KC_ENTRIES+=("$_svc")
  fi
done
if (( ${#KC_ENTRIES[@]} > 0 )); then
  echo ""
  echo -e "  ${DIM}Keychain entries (Claude Code-owned, NOT vdm — left intentionally):${NC}"
  for _svc in "${KC_ENTRIES[@]}"; do
    echo -e "    ${DIM}• \"$_svc\" (account: $USER)${NC}"
  done
  echo -e "  ${DIM}To remove: \`claude logout\` (then \`security delete-generic-password -s \"<service>\" -a \"$USER\"\` to verify).${NC}"
fi

# Re-enumerate vdm-account-* entries in case some survived (purge was
# declined, or a delete failed).
VDM_KC_REMAINING=()
while IFS= read -r _name; do
  [[ -z "$_name" ]] && continue
  VDM_KC_REMAINING+=("vdm-account-$_name")
done < <(security dump-keychain 2>/dev/null \
  | grep -E '"svce"<blob>="vdm-account-' \
  | sed -E 's/.*"svce"<blob>="vdm-account-([^"]+)".*/\1/' \
  | grep -E '^[a-zA-Z0-9._@-]+$' \
  | sort -u)
if (( ${#VDM_KC_REMAINING[@]} > 0 )); then
  echo ""
  if [[ "$preserve_accounts" == "true" ]]; then
    echo -e "  ${DIM}vdm-managed Keychain entries kept (run uninstall again with 'purge' to delete):${NC}"
  else
    echo -e "  ${YELLOW}⚠${NC}  ${BOLD}vdm-managed Keychain entries STILL PRESENT after purge:${NC}"
  fi
  for _e in "${VDM_KC_REMAINING[@]}"; do
    echo -e "    ${DIM}• \"$_e\" (account: $USER)${NC}"
  done
fi

echo ""
echo -e "  ${BOLD}${GREEN}Uninstall complete.${NC}"
echo ""
echo -e "  ${BOLD}To finish:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source \"${SHELL_RC:-$HOME/.zshrc}\"${NC})"
echo -e "    2. Your active Keychain credentials are untouched  - Claude Code will"
echo -e "       continue to work normally with whichever account was last active."
echo ""
