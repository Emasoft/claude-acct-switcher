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

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Uninstaller${NC}"
echo -e "  ──────────────────────────────────────────"
echo ""

# ── Show what will be removed ──

echo -e "  ${BOLD}This will:${NC}"
echo -e "    1. Stop the running dashboard/proxy"
echo -e "    2. Remove the shell config block from your shell rc file"
echo -e "    3. Remove the ${CYAN}vdm${NC} symlink from PATH"
echo -e "    4. Remove ${CYAN}$INSTALL_DIR${NC}"
echo ""

# Track whether the user explicitly chose to KEEP saved account profiles
# (the cached refresh-token JSONs in $INSTALL_DIR/accounts/). Default to
# preserve — these files are user data, not vdm-owned scaffolding, and
# blowing them away as a side-effect of "uninstall the tool" loses every
# saved login. The `rm -rf $INSTALL_DIR` step at section 5 honours this
# flag by relocating accounts/ outside the install dir before deletion.
preserve_accounts=true
ACCT_COUNT=0

if [[ -d "$INSTALL_DIR/accounts" ]]; then
  ACCT_COUNT=$(find "$INSTALL_DIR/accounts" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$ACCT_COUNT" -gt 0 ]]; then
    echo -e "  ${YELLOW}Note:${NC} You have ${BOLD}$ACCT_COUNT saved account profile(s)${NC} in $INSTALL_DIR/accounts/"
    echo -e "  ${DIM}(These hold OAuth refresh tokens vdm cached for fast switching.${NC}"
    echo -e "  ${DIM} Your active Keychain entry written by Claude Code itself is not touched.)${NC}"
    echo ""
  fi
fi

# `read` in a stand-alone statement under `set -e` exits the script on
# EOF (Ctrl-D / closed stdin). Wrap in `|| true` and force-cancel so the
# user gets a friendly message instead of an abrupt errexit.
confirm=""
read -rp "  Continue? [y/N] " confirm || { echo ""; echo -e "  ${DIM}Cancelled.${NC}"; exit 0; }
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo -e "  ${DIM}Cancelled.${NC}"
  echo ""
  exit 0
fi

# Second, separate prompt for the saved-profiles question. Default is
# PRESERVE (keep them). Only an explicit `purge` answer deletes them —
# any other input (including bare `y`, blank, EOF) keeps them. This is
# deliberately stricter than the main confirm so an autopilot-y user
# can't lose all their saved logins by reflexively typing y/Enter.
if [[ "$ACCT_COUNT" -gt 0 ]]; then
  echo ""
  echo -e "  ${YELLOW}Saved account profiles:${NC} ${BOLD}$ACCT_COUNT${NC} file(s) in $INSTALL_DIR/accounts/"
  echo -e "  ${DIM}Type ${BOLD}purge${NC}${DIM} to delete them. Anything else keeps them${NC}"
  echo -e "  ${DIM}(they will be moved to ~/.claude/vdm-accounts-backup-<timestamp>/).${NC}"
  purge_input=""
  read -rp "  Delete saved profiles? [purge / keep] " purge_input || purge_input=""
  if [[ "$purge_input" == "purge" ]]; then
    preserve_accounts=false
    echo -e "  ${YELLOW}!${NC} Saved profiles will be deleted with the install dir."
  else
    echo -e "  ${GREEN}✓${NC} Saved profiles will be preserved."
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
# If the user chose to keep their saved profiles, relocate the accounts/
# directory (and only that directory) out of $INSTALL_DIR before the
# `rm -rf`. The relocated path is timestamped so multiple uninstall
# attempts don't clobber each other. We also copy the .label sidecar
# files alongside so the rename history survives a future re-install.
ACCOUNTS_BACKUP=""
if [[ "$preserve_accounts" == "true" ]] && [[ -d "$INSTALL_DIR/accounts" ]] && [[ "$ACCT_COUNT" -gt 0 ]]; then
  # Use UTC-free local timestamp + GMT offset so two runs in the same
  # second from different timezones don't collide. The directory lives
  # next to the install dir under ~/.claude/ so it's easy to find later.
  _BACKUP_TS="$(date +%Y%m%d_%H%M%S%z 2>/dev/null || date +%Y%m%d_%H%M%S)"
  ACCOUNTS_BACKUP="$HOME/.claude/vdm-accounts-backup-${_BACKUP_TS}"
  if mkdir -p "$ACCOUNTS_BACKUP" 2>/dev/null \
     && cp -R "$INSTALL_DIR/accounts/." "$ACCOUNTS_BACKUP/" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Saved profiles preserved at ${CYAN}$ACCOUNTS_BACKUP${NC}"
  else
    # Backup failed — DO NOT proceed to rm -rf, that would silently lose
    # the user's data. Tell them, leave $INSTALL_DIR intact, and let them
    # rescue manually. Subsequent steps still run; the dir simply isn't
    # removed this pass.
    echo -e "  ${RED}!${NC} Could not back up accounts/ to $ACCOUNTS_BACKUP — leaving $INSTALL_DIR in place."
    echo -e "    ${DIM}Move ${INSTALL_DIR}/accounts/ somewhere safe and re-run uninstall.sh.${NC}"
    ACCOUNTS_BACKUP=""
    INSTALL_DIR=""   # signal the next block to skip the rm
  fi
fi

if [[ -n "$INSTALL_DIR" && -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR"
  echo -e "  ${GREEN}✓${NC} Removed ${CYAN}$INSTALL_DIR${NC}"
elif [[ -n "$INSTALL_DIR" ]]; then
  echo -e "  ${DIM}$INSTALL_DIR does not exist (already clean)${NC}"
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
  rm_backups=""
  read -rp "  Remove these backups? [y/N] " rm_backups || rm_backups=""
  if [[ "$rm_backups" == "y" || "$rm_backups" == "Y" ]]; then
    for f in "${backup_candidates[@]}"; do rm -f "$f" 2>/dev/null && echo -e "    ${GREEN}✓${NC} Removed $f" || true; done
  else
    echo -e "    ${DIM}Backups kept. Remove manually if you don't need them.${NC}"
  fi
fi

# ── 7. Note about LaunchAgent + Keychain ──
LAUNCHAGENT_PLIST="$HOME/Library/LaunchAgents/com.loekj.vdm.dashboard.plist"
if [[ -f "$LAUNCHAGENT_PLIST" ]]; then
  echo ""
  echo -e "  ${YELLOW}Note:${NC} a LaunchAgent plist exists at"
  echo -e "    ${DIM}$LAUNCHAGENT_PLIST${NC}"
  echo -e "  If you previously enabled the supervisor mode, run:"
  echo -e "    ${DIM}launchctl bootout gui/\$(id -u) \"$LAUNCHAGENT_PLIST\" 2>/dev/null${NC}"
  echo -e "    ${DIM}rm -f \"$LAUNCHAGENT_PLIST\"${NC}"
fi

echo ""
echo -e "  ${BOLD}${GREEN}Uninstall complete.${NC}"
echo ""
echo -e "  ${BOLD}To finish:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source \"${SHELL_RC:-$HOME/.zshrc}\"${NC})"
echo -e "    2. Your Keychain credentials are untouched  - Claude Code will"
echo -e "       continue to work normally with whichever account was last active."
# Tell the user where their saved profiles ended up if we relocated them.
# They almost certainly want to know — these are the files the next vdm
# install would auto-discover from. Restoring is a single `cp -R` away.
if [[ -n "${ACCOUNTS_BACKUP:-}" ]] && [[ -d "$ACCOUNTS_BACKUP" ]]; then
  echo -e "    3. Saved profiles are at ${CYAN}$ACCOUNTS_BACKUP${NC}"
  echo -e "       ${DIM}Restore on re-install: cp -R \"$ACCOUNTS_BACKUP\"/. \"\$HOME/.claude/account-switcher/accounts/\"${NC}"
fi
echo ""
