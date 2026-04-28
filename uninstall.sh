#!/usr/bin/env bash
# Claude Account Switcher  - Uninstaller
# Safely removes vdm, the dashboard, shell config, and optionally saved accounts.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
# Preserve the original path for the section-9 audit (the variable can be
# blanked mid-script when the accounts/ backup fails — see section 5).
INSTALL_DIR_ORIG="$INSTALL_DIR"

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

  -h, --help
      Show this message.

Without --non-interactive, the script asks each question on stdin and
the above flags are ignored.
EOF
}

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
    -h|--help)
      usage; exit 0 ;;
    --) shift; break ;;
    *)
      echo "Unknown flag: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

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

stopped=false

# Honour CSW_PORT / CSW_PROXY_PORT overrides — a user who installed with
# custom ports also runs with custom ports, so hardcoding 3333/3334 here
# would silently fail to kill the listeners and leave stale processes.
# The defaults match install.sh.
_DASH_PORT="${CSW_PORT:-3333}"
_PROXY_PORT="${CSW_PROXY_PORT:-3334}"

# Try vdm dashboard stop (graceful — uses the PID file when present)
if [[ -x "$INSTALL_DIR/vdm" ]]; then
  "$INSTALL_DIR/vdm" dashboard stop 2>/dev/null && stopped=true || true
fi

# Fallback: kill by port. Iterate over ALL listener PIDs (not just the
# first), because port-sharing or a stuck child can leave more than one
# process bound. `lsof -t` is one PID per line — read it line-by-line.
# We send SIGTERM first; the polite exit lets the dashboard atomic-rename
# any in-flight state writes (account-state.json, utilization-history.json,
# etc.) before we yank the install dir from under it.
if [[ "$stopped" != "true" ]]; then
  for port in "$_DASH_PORT" "$_PROXY_PORT"; do
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      kill -TERM "$pid" 2>/dev/null && stopped=true || true
    done < <(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  done
fi

# Fallback: kill by process name. pkill returns 0 when something matched,
# 1 when nothing did — flip that into the `stopped` flag so we don't lie
# to the user about whether anything was actually killed.
if [[ "$stopped" != "true" ]]; then
  if pkill -TERM -f "node.*account-switcher.*dashboard" 2>/dev/null; then
    stopped=true
  fi
fi

# If we sent SIGTERM, give the process up to ~3s to release the listening
# socket, then SIGKILL anything still bound. Without this, a stuck Node
# process (mid-libcurl, deadlocked, blocked on disk IO) survives the
# polite signal — and then `rm -rf $INSTALL_DIR` below pulls dashboard.mjs
# out from under a still-running process, which leaks PID and may corrupt
# state files mid-write. We poll instead of `sleep 3` blindly so the fast
# path stays fast.
if [[ "$stopped" == "true" ]]; then
  for _drain in 1 2 3 4 5 6; do
    local_listeners=""
    for port in "$_DASH_PORT" "$_PROXY_PORT"; do
      pids=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
      [[ -n "$pids" ]] && local_listeners="$local_listeners $pids"
    done
    [[ -z "$local_listeners" ]] && break
    sleep 0.5
  done
  # Anything still bound after ~3s gets the hard kill. -9 cannot be caught
  # so the listener releases the port even if the process is wedged.
  for port in "$_DASH_PORT" "$_PROXY_PORT"; do
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      kill -KILL "$pid" 2>/dev/null || true
    done < <(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true)
  done
fi

# Only claim success if at least one of the methods above actually killed
# something. Previously this echo printed unconditionally and led users to
# think the dashboard had been stopped when in fact every fallback no-oped.
if [[ "$stopped" == "true" ]]; then
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

# Portable in-place sed wrapper. The BSD `sed -i ''` form silently fails
# under GNU sed (which most homebrew-using Mac developers have shadowed
# `/usr/bin/sed` with): GNU sed's `-i` takes an optional GLUED suffix, so
# `''` is interpreted as a SEPARATE FILENAME arg, the script slides into
# what sed thinks is a filename, and the in-place edit silently no-ops.
# This bug has shipped with the project for its entire lifetime — every
# macOS user with `brew install gnu-sed` on PATH had a broken uninstall.
# Writing to .tmp and renaming sidesteps `-i` entirely; works under both
# BSD and GNU sed unchanged.
_sed_in_place() {
  local script="$1" file="$2"
  local tmp="${file}.vdm-sed-tmp"
  # NOTE: write tmp content back into the original file via `cat`, NOT `mv`.
  # `mv` replaces the inode and converts a symlinked rc file (common in dotfile
  # repos managed by stow/yadm/chezmoi) into a regular file, breaking the link.
  # `cat tmp > file` preserves the symlink target, the inode, and the file's
  # original permissions/ownership. Then rm the tmp.
  sed "$script" "$file" > "$tmp" && cat "$tmp" > "$file" && rm -f "$tmp"
}

clean_one_rc() {
  local rc="$1"
  [[ -f "$rc" ]] || return 0
  # Permissive grep: any line that contains the marker (possibly indented,
  # possibly with trailing CR from a CRLF file).
  grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$' "$rc" 2>/dev/null || return 0

  cp "$rc" "${rc}.vdm-backup"

  # Strip any CRLF line endings in-place so the END marker is reachable.
  # Same symlink-preservation reason as _sed_in_place: cat-redirect, never mv.
  if grep -q $'\r' "$rc" 2>/dev/null; then
    LC_ALL=C tr -d '\r' < "$rc" > "${rc}.vdm-tmp" \
      && cat "${rc}.vdm-tmp" > "$rc" \
      && rm -f "${rc}.vdm-tmp"
  fi

  # Range-delete the entire block, indent-tolerant on both ends.
  _sed_in_place \
    '/^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$/,/^[[:space:]]*# END claude-account-switcher[[:space:]]*$/d' \
    "$rc"

  # Verify the markers are actually gone. Two failure modes here:
  #   (a) BOTH markers still present — the range delete didn't match (unusual
  #       indentation or comment fragments inside the block). Safe to strip
  #       just the marker lines because the body between them was preserved
  #       intact and the user can decide what to keep.
  #   (b) ONLY ONE marker present — the file was already malformed before we
  #       touched it (BEGIN without matching END, or vice-versa). The range
  #       delete in case (a) above would have been a no-op or run to EOF.
  #       Stripping just the orphan marker would leave the body code orphaned
  #       in the rc file, AND silently writing might destroy user content.
  #       Restore from the backup we made above and tell the user to fix it
  #       by hand — auto-clean of an undocumented malformed state is data
  #       corruption waiting to happen.
  if grep -Eq '# BEGIN claude-account-switcher|# END claude-account-switcher' "$rc" 2>/dev/null; then
    local has_begin=0 has_end=0
    grep -Eq '# BEGIN claude-account-switcher' "$rc" 2>/dev/null && has_begin=1
    grep -Eq '# END claude-account-switcher'   "$rc" 2>/dev/null && has_end=1
    if [[ "$has_begin" == "1" && "$has_end" == "1" ]]; then
      _sed_in_place '/# BEGIN claude-account-switcher/d; /# END claude-account-switcher/d' "$rc"
      echo -e "  ${YELLOW}!${NC} Found indented or non-matching markers in ${CYAN}$rc${NC} — used permissive cleanup"
    else
      # Restore the pre-edit state so the user keeps their config intact.
      cat "${rc}.vdm-backup" > "$rc"
      echo -e "  ${RED}!${NC} ${BOLD}${rc}${NC} has an unmatched BEGIN/END marker — refusing to auto-edit."
      echo -e "    ${DIM}Original restored from ${rc}.vdm-backup. Remove the claude-account-switcher block manually.${NC}"
      # The backup copy we made above is now redundant (the file content
      # is identical to what we restored). Track it so section 6 offers to
      # delete it instead of leaving it orphaned on disk.
      ORPHAN_BACKUPS+=("${rc}.vdm-backup")
      return 0
    fi
  fi

  # Trim a single trailing blank line left behind by the heredoc's
  # leading `echo "" >>`. Avoids an unbounded loop on weird states.
  if [[ -s "$rc" ]] && [[ -z "$(tail -1 "$rc")" ]]; then
    _sed_in_place '$ d' "$rc"
  fi

  CLEANED_RC_FILES+=("$rc")
  echo -e "  ${GREEN}✓${NC} Removed auto-start block from ${CYAN}$rc${NC}"
  echo -e "    ${DIM}Backup: ${rc}.vdm-backup${NC}"
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
ACCOUNTS_BACKUP=""

if [[ -n "$INSTALL_DIR" && -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR"
  echo -e "  ${GREEN}✓${NC} Removed ${CYAN}$INSTALL_DIR${NC}"
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
if [[ -n "${ACCOUNTS_BACKUP:-}" ]]; then
  _filtered=()
  for _bk in "${ORPHAN_BACKUPS_DIRS[@]}"; do
    [[ "$_bk" == "$ACCOUNTS_BACKUP" ]] && continue
    _filtered+=("$_bk")
  done
  ORPHAN_BACKUPS_DIRS=("${_filtered[@]}")
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
LAUNCHAGENT_PLIST="$HOME/Library/LaunchAgents/com.loekj.vdm.dashboard.plist"
if [[ -f "$LAUNCHAGENT_PLIST" ]]; then
  echo ""
  echo -e "  ${YELLOW}LaunchAgent detected:${NC}"
  echo -e "    ${DIM}$LAUNCHAGENT_PLIST${NC}"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    rm_la="$([[ "$REMOVE_LAUNCHAGENT" == "true" ]] && echo y || echo n)"
  else
    rm_la=""
    read -rp "  Unload + remove this LaunchAgent? [y/N] " rm_la || rm_la=""
  fi
  if [[ "$rm_la" == "y" || "$rm_la" == "Y" ]]; then
    launchctl bootout "gui/$(id -u)" "$LAUNCHAGENT_PLIST" 2>/dev/null || true
    rm -f "$LAUNCHAGENT_PLIST" && echo -e "    ${GREEN}✓${NC} LaunchAgent removed" || true
  else
    echo -e "    ${DIM}LaunchAgent kept. Remove later with:${NC}"
    echo -e "      ${DIM}launchctl bootout gui/\$(id -u) \"$LAUNCHAGENT_PLIST\" 2>/dev/null${NC}"
    echo -e "      ${DIM}rm -f \"$LAUNCHAGENT_PLIST\"${NC}"
  fi
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
