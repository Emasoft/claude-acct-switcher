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

if [[ -d "$INSTALL_DIR/accounts" ]]; then
  ACCT_COUNT=$(find "$INSTALL_DIR/accounts" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$ACCT_COUNT" -gt 0 ]]; then
    echo -e "  ${YELLOW}Note:${NC} You have ${BOLD}$ACCT_COUNT saved account profile(s)${NC} in $INSTALL_DIR/accounts/"
    echo -e "  ${DIM}(These are cached credentials  - your Keychain entries are not affected.)${NC}"
    echo ""
  fi
fi

read -rp "  Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo -e "  ${DIM}Cancelled.${NC}"
  echo ""
  exit 0
fi

echo ""

# ── 1. Stop running processes ──

stopped=false

# Try vdm dashboard stop
if [[ -x "$INSTALL_DIR/vdm" ]]; then
  "$INSTALL_DIR/vdm" dashboard stop 2>/dev/null && stopped=true || true
fi

# Fallback: kill by port
if [[ "$stopped" != "true" ]]; then
  for port in 3333 3334; do
    pid=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1) || true
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null && stopped=true || true
    fi
  done
fi

# Fallback: kill by process name
if [[ "$stopped" != "true" ]]; then
  pkill -f "node.*account-switcher.*dashboard" 2>/dev/null || true
fi

echo -e "  ${GREEN}✓${NC} Stopped dashboard/proxy"

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
  sed "$script" "$file" > "$tmp" && mv "$tmp" "$file"
}

clean_one_rc() {
  local rc="$1"
  [[ -f "$rc" ]] || return 0
  # Permissive grep: any line that contains the marker (possibly indented,
  # possibly with trailing CR from a CRLF file).
  grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$' "$rc" 2>/dev/null || return 0

  cp "$rc" "${rc}.vdm-backup"

  # Strip any CRLF line endings in-place so the END marker is reachable.
  if grep -q $'\r' "$rc" 2>/dev/null; then
    LC_ALL=C tr -d '\r' < "$rc" > "${rc}.vdm-tmp" && mv "${rc}.vdm-tmp" "$rc"
  fi

  # Range-delete the entire block, indent-tolerant on both ends.
  _sed_in_place \
    '/^[[:space:]]*# BEGIN claude-account-switcher[[:space:]]*$/,/^[[:space:]]*# END claude-account-switcher[[:space:]]*$/d' \
    "$rc"

  # Verify the markers are actually gone — if not, fall back to a more
  # aggressive line-by-line removal so we don't leave the user wondering
  # why their shell still launches the dashboard.
  if grep -Eq '# BEGIN claude-account-switcher|# END claude-account-switcher' "$rc" 2>/dev/null; then
    _sed_in_place '/# BEGIN claude-account-switcher/d; /# END claude-account-switcher/d' "$rc"
    echo -e "  ${YELLOW}!${NC} Found indented or non-matching markers in ${CYAN}$rc${NC} — used permissive cleanup"
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
for link in "$HOME/.local/bin/vdm" "/usr/local/bin/vdm" "$HOME/.local/bin/csw" "/usr/local/bin/csw"; do
  if [[ -L "$link" ]]; then
    target=$(readlink "$link" 2>/dev/null || true)
    if [[ "$target" == *"account-switcher"* ]]; then
      rm -f "$link"
      echo -e "  ${GREEN}✓${NC} Removed symlink ${DIM}$link${NC}"
      removed_link=true
    fi
  fi
done
if [[ "$removed_link" != "true" ]]; then
  echo -e "  ${DIM}No vdm symlink found${NC}"
fi

# ── 4. Remove [BETA] hooks ──

if [[ -f "$INSTALL_DIR/install-hooks.sh" ]]; then
  source "$INSTALL_DIR/install-hooks.sh"
  uninstall_beta_hooks && echo -e "  ${GREEN}✓${NC} Removed [BETA] token tracking hooks" || true
fi

# ── 5. Remove install directory ──

if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR"
  echo -e "  ${GREEN}✓${NC} Removed ${CYAN}$INSTALL_DIR${NC}"
else
  echo -e "  ${DIM}$INSTALL_DIR does not exist (already clean)${NC}"
fi

# ── 6. Offer to clean up backup files ──
# uninstall historically left these behind; they accumulate over repeated
# install/uninstall cycles. Offer to remove them at the end. Iterate
# every rc file we cleaned (not just SHELL_RC) so multi-file installs
# get every backup listed.
backup_candidates=()
for rc in "${CLEANED_RC_FILES[@]:-}"; do
  [[ -n "$rc" ]] && [[ -f "${rc}.vdm-backup" ]] && backup_candidates+=("${rc}.vdm-backup")
done
[[ -f "$HOME/.claude/settings.json.vdm-backup" ]] && backup_candidates+=("$HOME/.claude/settings.json.vdm-backup")
if (( ${#backup_candidates[@]} > 0 )); then
  echo ""
  echo -e "  ${BOLD}Backup files left behind:${NC}"
  for f in "${backup_candidates[@]}"; do echo -e "    ${DIM}$f${NC}"; done
  read -rp "  Remove these backups? [y/N] " rm_backups
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
echo -e "    1. Restart your terminal (or run: ${DIM}source ${SHELL_RC:-~/.zshrc}${NC})"
echo -e "    2. Your Keychain credentials are untouched  - Claude Code will"
echo -e "       continue to work normally with whichever account was last active."
echo ""
