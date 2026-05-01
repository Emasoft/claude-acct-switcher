#!/usr/bin/env bash
# Claude Account Switcher  - Installer
# Installs vdm to ~/.claude/account-switcher/ and configures your shell.
#
# Robustness contract:
# - Every disk write is atomic (tmp + rename) via lib-install.sh helpers.
#   A SIGKILL / Ctrl-C / power loss never leaves a half-written file.
# - Pre-flight detection scans the system for stale installs, malformed
#   rc-file blocks, dangling symlinks, port conflicts, and corrupt
#   settings.json BEFORE writing anything. Errors block installation;
#   warnings are surfaced and proceed.
# - Cleanup stack runs on EXIT, INT, TERM, HUP — locks and temp files
#   are released even on signal-kill.
# - Steps register rollback actions so a mid-install failure backs out
#   the partial state instead of leaving the user broken.
# - --non-interactive / -y / --quiet runs unattended with safe defaults.
# - --auto-fix offers to auto-remediate detected issues; without it,
#   non-error issues are reported and the install proceeds.

set -euo pipefail

# ── Flag parsing ──
NON_INTERACTIVE=false
AUTO_FIX=false
SKIP_DETECT=false

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  -y, --yes, --non-interactive, --quiet
      Run without prompting. Errors detected pre-flight still block
      installation; warnings proceed silently.

  --auto-fix
      Attempt to auto-remediate detected issues (orphaned hooks,
      dangling symlinks, malformed rc blocks, partial prior installs)
      before installing. Without this flag, blocking issues abort and
      the user is told how to fix them manually.

  --skip-detect
      Skip pre-flight detection. Use only if a previous run flagged
      issues that are intentional / outside vdm's control.

  -h, --help
      Show this message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes|--non-interactive|--quiet)
      NON_INTERACTIVE=true; shift ;;
    --auto-fix)
      AUTO_FIX=true; shift ;;
    --skip-detect)
      SKIP_DETECT=true; shift ;;
    -h|--help)
      usage; exit 0 ;;
    --) shift; break ;;
    *)
      echo "Unknown flag: $1" >&2
      usage >&2
      exit 2 ;;
  esac
done

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
# POSIX-portable: resolve the directory containing this script. `pwd -P`
# canonicalises any symlink components in the path. This works whether
# install.sh is invoked directly, via a symlink, or via $PATH — and does
# not depend on GNU `readlink -f` / `realpath` being on PATH (BSD readlink
# on stock macOS lacks -f, and `realpath` ships only with newer macOS).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Source shared safety primitives + detectors. Hard requirement —
# without lib-install.sh the atomic writers and signal-safe cleanup
# stack don't exist and the install becomes non-robust.
if [[ ! -f "$SCRIPT_DIR/lib-install.sh" ]]; then
  echo -e "${RED}Missing required helper: lib-install.sh next to install.sh${NC}" >&2
  exit 1
fi
# shellcheck source=/dev/null
. "$SCRIPT_DIR/lib-install.sh"

# Wire up signal-safe cleanup BEFORE acquiring any lock or writing
# anything. INT/TERM/HUP/EXIT all flow through _run_cleanup which
# pops the cleanup stack in LIFO order. Without this, ^C between
# `mkdir LOCK` and the trap line below would leak the lock dir.
_trap_signals

# Concurrent-install mutex. Two `install.sh` invocations racing in
# parallel (rare but possible: two terminals, a shell hook, an editor's
# "post-clone" action) would both pass the BEGIN-marker check below and
# both append a block to the rc file — leaving the user with duplicated
# `if ! lsof ... fi` blocks and (more annoying) duplicated `export
# ANTHROPIC_BASE_URL=...` lines. mkdir is atomic on every POSIX
# filesystem; stock macOS ships no flock(1), so mkdir is the portable
# primitive. Stale-lock reaper: any lock dir older than 60s is treated
# as orphaned (the previous installer crashed before releasing it) so
# subsequent installs don't deadlock for the full 60s before bailing.
INSTALL_LOCK="$HOME/.claude/.vdm-install.lock.d"
mkdir -p "$HOME/.claude" 2>/dev/null || true
_lock_tries=0
while ! mkdir "$INSTALL_LOCK" 2>/dev/null; do
  if [[ -d "$INSTALL_LOCK" ]] \
     && [[ -z "$(find "$INSTALL_LOCK" -maxdepth 0 -mmin -1 2>/dev/null)" ]]; then
    rmdir "$INSTALL_LOCK" 2>/dev/null && continue
  fi
  _lock_tries=$((_lock_tries + 1))
  if [[ $_lock_tries -ge 600 ]]; then
    echo -e "${RED}Another install.sh appears to be running (lock held > 60s).${NC}"
    echo "  If no install is running, remove the stale lock and retry:"
    echo "    rmdir \"$INSTALL_LOCK\""
    exit 1
  fi
  sleep 0.1
done
_register_cleanup "rmdir \"$INSTALL_LOCK\" 2>/dev/null"

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Installer${NC}"
echo -e "  ────────────────────────────────────────"
if [[ "$NON_INTERACTIVE" == "true" ]]; then
  echo -e "  ${DIM}(non-interactive mode — auto_fix=$AUTO_FIX, skip_detect=$SKIP_DETECT)${NC}"
fi
echo ""

# ── Stop any previously-running dashboard/proxy ──
# Re-installing while the old dashboard is still serving on 3333/3334 is
# the classic "uninstall didn't take" complaint — the file install would
# succeed but the user keeps seeing the old behaviour because the old
# Node process holds the port. Worse, ripping dashboard.mjs out from
# under a running process can corrupt half-written state files. Always
# clear the slate first. Kill is idempotent and cmdline-validated (only
# signals processes whose argv contains "dashboard.mjs") so it can't
# snipe an unrelated listener.
#
# H6 fix — port resolution priority is config.json > env > default. Without
# the config.json read here, a user who changed `port` / `proxyPort` via
# the dashboard UI (which persists into ~/.claude/account-switcher/config.json)
# but did NOT set CSW_PORT in their shell would fall through to the 3333/3334
# defaults — _kill_running_vdm would scan the wrong ports and the live
# dashboard would survive while we rewrite its files underneath. Mirror
# the order used by the rc-snippet (config → env → default) for parity.
_resolve_install_ports() {
  local cfg="$INSTALL_DIR/config.json"
  local _cfg_dash="" _cfg_proxy=""
  if [[ -f "$cfg" ]]; then
    _cfg_dash="$(_json_get_int "$cfg" port 2>/dev/null || true)"
    _cfg_proxy="$(_json_get_int "$cfg" proxyPort 2>/dev/null || true)"
  fi
  _DASH_PORT_DEFAULT="${_cfg_dash:-${CSW_PORT:-3333}}"
  _PROXY_PORT_DEFAULT="${_cfg_proxy:-${CSW_PROXY_PORT:-3334}}"
}
_resolve_install_ports
if _kill_running_vdm "$_DASH_PORT_DEFAULT" "$_PROXY_PORT_DEFAULT"; then
  echo -e "  ${YELLOW}!${NC} Stopped a previously-running vdm dashboard/proxy."
fi

# ── Check prerequisites ──

# macOS-only check first — vdm uses the macOS Keychain, so there's no
# point in trying to install dependencies on Linux.
if [[ "$(uname)" != "Darwin" ]]; then
  echo -e "${RED}This tool requires macOS (uses Keychain for credential storage).${NC}"
  exit 1
fi

# _ensure_dep <command> <homebrew-formula> <human-friendly-name>
# Verifies that <command> is on PATH. If missing:
#   - In interactive mode: detect Homebrew, offer to install via brew.
#     User declines → print the manual command and exit 1.
#   - In --non-interactive mode WITH --auto-fix: install via brew
#     unattended (errors abort).
#   - In --non-interactive mode WITHOUT --auto-fix: print the manual
#     install command and exit 1 — never silently install something
#     under an automation account.
# We never attempt sudo or non-Homebrew package managers — too
# environment-specific. Users on Apple Silicon without Homebrew get a
# clear "install brew first" message rather than a partial install.
_ensure_dep() {
  local cmd="$1" formula="$2" name="$3"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  echo -e "  ${YELLOW}!${NC} Missing dependency: ${BOLD}$name${NC} (${DIM}$cmd${NC})"
  if ! command -v brew >/dev/null 2>&1; then
    echo -e "    ${DIM}Homebrew not found — cannot auto-install. Install $name manually:${NC}"
    echo -e "      ${CYAN}# Install Homebrew first:${NC}"
    echo -e "      ${DIM}/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"${NC}"
    echo -e "      ${CYAN}# Then install $name:${NC}"
    echo -e "      ${DIM}brew install $formula${NC}"
    return 1
  fi
  local _do_install=false
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ "$AUTO_FIX" == "true" ]]; then
      _do_install=true
      echo -e "    ${DIM}--non-interactive --auto-fix → installing via Homebrew...${NC}"
    else
      echo -e "    ${DIM}--non-interactive without --auto-fix → not installing automatically.${NC}"
      echo -e "    ${DIM}Run: ${CYAN}brew install $formula${DIM} OR re-run install.sh with --auto-fix.${NC}"
      return 1
    fi
  else
    local ans=""
    read -rp "  Install $name now via Homebrew (brew install $formula)? [Y/n] " ans || ans=""
    if [[ -z "$ans" ]] || [[ "$ans" == "y" ]] || [[ "$ans" == "Y" ]]; then
      _do_install=true
    else
      echo -e "    ${DIM}Skipped. Re-run install.sh after installing $name manually.${NC}"
      return 1
    fi
  fi
  if [[ "$_do_install" == "true" ]]; then
    if brew install "$formula"; then
      echo -e "    ${GREEN}✓${NC} Installed $name via Homebrew."
      # Re-check — homebrew installs may need a PATH reload depending
      # on shell + arch (Apple Silicon installs to /opt/homebrew/bin
      # which isn't on a vanilla PATH from a shell that pre-dates the
      # install). Use brew --prefix to find the bin dir and add it
      # to this script's PATH so the subsequent `node -v` check works.
      local _brew_bin
      _brew_bin="$(brew --prefix 2>/dev/null)/bin"
      if [[ -d "$_brew_bin" ]] && [[ ":$PATH:" != *":$_brew_bin:"* ]]; then
        export PATH="$_brew_bin:$PATH"
      fi
      if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "    ${RED}!${NC} $cmd still not on PATH after install. Restart your shell and re-run install.sh."
        return 1
      fi
      return 0
    else
      echo -e "    ${RED}!${NC} brew install $formula failed."
      return 1
    fi
  fi
  return 1
}

if ! _ensure_dep node     node    "Node.js"; then exit 1; fi
if ! _ensure_dep python3  python  "Python 3"; then exit 1; fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [[ "$NODE_VERSION" -lt 18 ]]; then
  echo -e "${YELLOW}Warning: Node.js v18+ recommended (found v$(node -v))${NC}"
fi

echo -e "  ${GREEN}✓${NC} Prerequisites OK (Node $(node -v), macOS, python3 $(python3 -V 2>&1 | awk '{print $2}'))"
echo ""

# ── Pre-flight detection ──
# Run a battery of read-only detectors that surface remnants of prior
# installs, malformed config, dangling symlinks, port conflicts, and
# env-var bypasses BEFORE we modify anything on disk. Errors block;
# warnings proceed.
# H6 fix — re-resolve via the same config-json-first helper so detection
# scans the ports the dashboard actually listens on (not the env/default
# pair) when the user persisted custom ports via the UI.
_resolve_install_ports

if [[ "$SKIP_DETECT" != "true" ]]; then
  echo -e "  ${BOLD}Running pre-flight checks...${NC}"
  detect_old_install_remnants "$INSTALL_DIR"
  detect_orphaned_settings_hooks
  detect_malformed_rc_blocks
  detect_dangling_symlinks
  detect_port_holders "$_DASH_PORT_DEFAULT" "$_PROXY_PORT_DEFAULT"
  detect_orphan_keychain_entries "$INSTALL_DIR"
  detect_truncated_config "$INSTALL_DIR/config.json"
  detect_disabling_env_vars
  detect_managed_settings_restrictions

  set +e
  render_detected_issues
  _detect_blocking=$?
  set -e

  if [[ "$_detect_blocking" -gt 0 ]]; then
    if [[ "$AUTO_FIX" != "true" ]]; then
      echo ""
      echo -e "  ${RED}${BOLD}Pre-flight detected $_detect_blocking blocking issue(s).${NC}"
      echo -e "  ${DIM}Re-run with --auto-fix to attempt automatic remediation, or fix the issues manually and re-run.${NC}"
      echo -e "  ${DIM}Bypass with --skip-detect (only if you know the issues are intentional).${NC}"
      exit 1
    fi
    echo ""
    echo -e "  ${YELLOW}--auto-fix${NC} ${BOLD}— attempting remediation...${NC}"
    # The detectors that have safe auto-fixes:
    #   orphaned-hooks → uninstall_hooks (defined by install-hooks.sh)
    #   dangling-symlink → rm the symlink
    # Everything else (malformed-rc, settings-corrupt, config-corrupt,
    # port-conflict) is left to the user — auto-editing those would
    # risk silent data loss.
    if [[ -f "$SCRIPT_DIR/install-hooks.sh" ]]; then
      # shellcheck source=/dev/null
      . "$SCRIPT_DIR/install-hooks.sh"
      uninstall_hooks 2>/dev/null \
        && echo -e "    ${GREEN}✓${NC} Removed orphaned settings.json hooks" \
        || echo -e "    ${YELLOW}!${NC} Hook removal returned non-zero — re-check manually after install"
    fi
    for _lnk in "$HOME/.local/bin/vdm"     "$HOME/.local/bin/csw" \
                "/opt/homebrew/bin/vdm"    "/opt/homebrew/bin/csw" \
                "/usr/local/bin/vdm"       "/usr/local/bin/csw"; do
      if [[ -L "$_lnk" ]]; then
        _t="$(readlink "$_lnk" 2>/dev/null || true)"
        if [[ -z "$_t" ]] || [[ ! -e "$_t" ]]; then
          rm -f "$_lnk" && echo -e "    ${GREEN}✓${NC} Removed dangling symlink ${DIM}$_lnk${NC}" || true
        fi
      fi
    done
    # Re-run detection so the user sees what's left.
    VDM_DETECTED_ISSUES=()
    detect_old_install_remnants "$INSTALL_DIR"
    detect_orphaned_settings_hooks
    detect_malformed_rc_blocks
    detect_dangling_symlinks
    detect_port_holders "$_DASH_PORT_DEFAULT" "$_PROXY_PORT_DEFAULT"
    detect_orphan_keychain_entries "$INSTALL_DIR"
    detect_truncated_config "$INSTALL_DIR/config.json"
    set +e
    render_detected_issues
    _detect_blocking=$?
    set -e
    if [[ "$_detect_blocking" -gt 0 ]]; then
      echo ""
      echo -e "  ${RED}${BOLD}$_detect_blocking blocking issue(s) remain after auto-fix. Aborting.${NC}"
      exit 1
    fi
  fi
  echo ""
fi

# ── Install files (atomic) ──
# Every file goes through _atomic_install: copy to tmp, fsync, rename
# in one syscall. If anything below fails or the user ^C's mid-run, the
# install dir is left with the OLD versions of every file (or no file
# at all if this is a first install). Never half-written content.

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/accounts"

# Track every newly-created file so a failure rolls them back.
_NEW_FILES=()
# M7 fix — snapshot directory for upgrade rollback. Before EACH
# _install_atomic on a pre-existing file, we copy the OLD bytes here.
# A SIGKILL between two _atomic_install calls would otherwise leave a
# version-mismatched install (e.g. new dashboard.mjs + old lib.mjs)
# that boots, fails on a missing helper, and looks like vdm corruption.
# On failure (`_INSTALL_OK != 1`) we restore each snapshotted file via
# _atomic_replace so the recovered state is itself crash-safe.
# On success the dir is removed.
_ROLLBACK_DIR="$INSTALL_DIR/.vdm-rollback"
_SNAPSHOTTED_FILES=()
# Tidy any leftover from a previous interrupted run BEFORE we use it.
rm -rf "$_ROLLBACK_DIR" 2>/dev/null || true
_install_atomic() {
  local src="$1" dst="$2" mode="${3:-644}"
  local was_present=0
  [[ -e "$dst" ]] && was_present=1
  # M7 fix — snapshot the existing file before overwriting. Use a flat
  # filename (basename) since every install destination is unique within
  # $INSTALL_DIR's top level. Snapshot creation ITSELF is best-effort:
  # if it fails we surface and abort BEFORE writing the new file, so a
  # disk-full failure leaves the existing install intact.
  if [[ $was_present -eq 1 ]]; then
    mkdir -p "$_ROLLBACK_DIR" 2>/dev/null || true
    local _snap="$_ROLLBACK_DIR/$(basename "$dst")"
    if cp -p "$dst" "$_snap" 2>/dev/null; then
      _SNAPSHOTTED_FILES+=("$dst")
    else
      echo -e "  ${RED}!${NC} Failed to snapshot $dst for rollback (disk full?). Aborting before overwrite." >&2
      return 1
    fi
  fi
  if ! _atomic_install "$src" "$dst" "$mode"; then
    echo -e "  ${RED}!${NC} Failed to install $dst" >&2
    return 1
  fi
  if [[ $was_present -eq 0 ]]; then
    _NEW_FILES+=("$dst")
  fi
}

# Roll back NEW files (not pre-existing ones) on failure. This means a
# failed first install leaves NO half-written files behind, while a
# failed upgrade preserves the old version of any file that already
# existed. Never destroys user data.
#
# M7 fix — rollback now restores each snapshotted file via _atomic_replace,
# so the recovered install is itself crash-safe (a SIGKILL during the
# rollback restores up to the last completed _atomic_replace, never a
# half-written file). Without snapshots, rolling back was impossible for
# pre-existing files — leaving a version-mismatched install instead.
_rollback_install_files() {
  # Restore snapshotted files first (LIFO so the most recent change
  # backs out cleanly), THEN remove brand-new files.
  if (( ${#_SNAPSHOTTED_FILES[@]} > 0 )); then
    local i
    for (( i=${#_SNAPSHOTTED_FILES[@]}-1; i>=0; i-- )); do
      local dst="${_SNAPSHOTTED_FILES[$i]}"
      local snap="$_ROLLBACK_DIR/$(basename "$dst")"
      if [[ -f "$snap" ]]; then
        _atomic_replace "$snap" "$dst" 2>/dev/null || true
      fi
    done
  fi
  # Guard the array expansion under bash 3.2 (stock macOS), which
  # treats `${empty_arr[@]}` as an unbound variable under `set -u`.
  # Bash 4.4+ tolerates it; we run on whatever bash the user has.
  if (( ${#_NEW_FILES[@]} > 0 )); then
    local f
    for f in "${_NEW_FILES[@]}"; do
      rm -f "$f" 2>/dev/null || true
    done
  fi
  rm -rf "$_ROLLBACK_DIR" 2>/dev/null || true
}
_register_cleanup '
if [[ "${_INSTALL_OK:-0}" != "1" ]]; then
  _rollback_install_files
else
  # M7 fix — clean snapshots on success. Done in the same cleanup
  # registration so we never leak the dir even if the script exits
  # via a non-error path between the success marker and EXIT trap.
  rm -rf "$_ROLLBACK_DIR" 2>/dev/null || true
fi
'

_install_atomic "$SCRIPT_DIR/dashboard.mjs"      "$INSTALL_DIR/dashboard.mjs"      644 || exit 1
_install_atomic "$SCRIPT_DIR/lib.mjs"            "$INSTALL_DIR/lib.mjs"            644 || exit 1
_install_atomic "$SCRIPT_DIR/vdm"                "$INSTALL_DIR/vdm"                755 || exit 1
_install_atomic "$SCRIPT_DIR/install-hooks.sh"   "$INSTALL_DIR/install-hooks.sh"   644 || exit 1
_install_atomic "$SCRIPT_DIR/lib-install.sh"     "$INSTALL_DIR/lib-install.sh"     644 || exit 1

# Create default config only if absent (don't clobber user's tuned ports
# / strategy / settings on a re-install).
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  _install_atomic "$SCRIPT_DIR/config.example.json" "$INSTALL_DIR/config.json"     644 || exit 1
fi

# Write version marker from git if available (prefer semver tag, fall
# back to hash). _atomic_write_string ensures a SIGKILL between truncate
# and the final byte never leaves an empty/partial .version file.
if command -v git &>/dev/null && git -C "$SCRIPT_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
  git -C "$SCRIPT_DIR" fetch --tags --quiet 2>/dev/null || true
  _vdm_version="$( git -C "$SCRIPT_DIR" describe --tags --abbrev=0 2>/dev/null \
    || git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null \
    || true )"
  if [[ -n "$_vdm_version" ]]; then
    _atomic_write_string "$INSTALL_DIR/.version" "$_vdm_version" || true
  fi
fi

echo -e "  ${GREEN}✓${NC} Installed to ${CYAN}$INSTALL_DIR${NC}"

# ── Symlink vdm to PATH ──

LINK_DIR=""
# Prefer a user-owned bindir so `ln -sf` doesn't trip `set -e` on Apple
# Silicon Macs where /usr/local/bin is root-owned (Homebrew lives in
# /opt/homebrew/bin there). Order: ~/.local/bin (always works) → an
# already-writable Homebrew bindir → /usr/local/bin only if writable.
if [[ -d "$HOME/.local/bin" && -w "$HOME/.local/bin" ]]; then
  LINK_DIR="$HOME/.local/bin"
elif [[ -d "/opt/homebrew/bin" && -w "/opt/homebrew/bin" ]]; then
  LINK_DIR="/opt/homebrew/bin"
elif [[ -d "/usr/local/bin" && -w "/usr/local/bin" ]]; then
  LINK_DIR="/usr/local/bin"
else
  mkdir -p "$HOME/.local/bin"
  LINK_DIR="$HOME/.local/bin"
fi

# Test whether $LINK_DIR is on PATH. The previous version only warned when
# the fallback `mkdir` branch ran, so a user whose `~/.local/bin` already
# existed but was NOT on PATH got the symlink with no warning — and `vdm`
# didn't work after install. Test PATH membership against the resolved
# LINK_DIR (covers all branches above) and only nag when truly missing.
# Use a bash regex with explicit `:` boundaries so `~/.local/bin` doesn't
# accidentally match `~/.local/bin-extra` or vice versa.
case ":$PATH:" in
  *":$LINK_DIR:"*) ;;  # already on PATH, nothing to do
  *)
    echo -e "  ${YELLOW}Note:${NC} ${DIM}$LINK_DIR${NC} is not on your \$PATH."
    echo -e "        Add this to your shell rc file:"
    echo -e "          ${DIM}export PATH=\"$LINK_DIR:\$PATH\"${NC}"
    ;;
esac

# Sweep stale `vdm` symlinks at every plausible location BEFORE creating
# the canonical one. On Apple-Silicon Macs migrated from Intel,
# /usr/local/bin/vdm could still point at an old install dir while
# `~/.local/bin/vdm` points at the new one — whichever wins on PATH
# decides which `vdm` actually runs. Do this on the install side too so
# the order doesn't depend on the user having previously uninstalled.
for candidate in \
    "$HOME/.local/bin/vdm" "$HOME/.local/bin/csw" \
    "/usr/local/bin/vdm"   "/usr/local/bin/csw"; do
  if [[ -L "$candidate" ]]; then
    target="$(readlink "$candidate" 2>/dev/null || true)"
    if [[ "$target" == *"/.claude/account-switcher/"* ]]; then
      rm -f "$candidate" 2>/dev/null || true
    fi
  fi
done

ln -sf "$INSTALL_DIR/vdm" "$LINK_DIR/vdm"
echo -e "  ${GREEN}✓${NC} Linked ${CYAN}vdm${NC} to ${DIM}$LINK_DIR${NC}"

# ── Configure shell ──

SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]]; then
  SHELL_RC="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
  SHELL_RC="$HOME/.bashrc"
elif [[ -f "$HOME/.bash_profile" ]]; then
  SHELL_RC="$HOME/.bash_profile"
fi

# Strip any defensive cleanup block left by a prior uninstall.sh run.
# That block contains `unset ANTHROPIC_BASE_URL`, which would unset the var
# every shell start and defeat the install snippet's `${VAR:-default}`
# logic — depending on rc-file ordering the proxy could end up unbound.
# Removing the cleanup block here makes re-install idempotent: clean
# slate, then add the regular BEGIN/END block below. We sweep ALL plausible
# rc files (not just SHELL_RC) because the cleanup block from uninstall is
# written to the FIRST rc file that exists, which may differ from the one
# install.sh chose (e.g. .zprofile on a fresh login-only shell).
for _rc in "$HOME/.zshrc"        "$HOME/.zprofile"     "$HOME/.zshenv" \
           "$HOME/.bashrc"       "$HOME/.bash_profile" "$HOME/.profile"; do
  [[ -f "$_rc" ]] || continue
  if grep -Eq '^[[:space:]]*# BEGIN claude-account-switcher-cleanup[[:space:]]*$' "$_rc" 2>/dev/null; then
    if _atomic_remove_block "$_rc" \
        '^[[:space:]]*# BEGIN claude-account-switcher-cleanup[[:space:]]*$' \
        '^[[:space:]]*# END claude-account-switcher-cleanup[[:space:]]*$' >/dev/null 2>&1; then
      echo -e "  ${GREEN}✓${NC} Removed prior uninstall cleanup block from ${CYAN}$_rc${NC}"
    fi
  fi
done

SNIPPET_MARKER="# BEGIN claude-account-switcher"

if [[ -n "$SHELL_RC" ]]; then
  if grep -q "$SNIPPET_MARKER" "$SHELL_RC" 2>/dev/null; then
    echo -e "  ${DIM}Shell config already present in $SHELL_RC${NC}"
  else
    # ANTHROPIC_BASE_URL clobber check. If the user already exports a
    # different proxy URL from this rc file (some users run their own
    # Anthropic-compatible relay), warn them so they don't lose it.
    # Detect EXISTING `export ANTHROPIC_BASE_URL=...` lines in the rc
    # before we add ours; the snippet below uses `${VAR:-default}` so a
    # user-set value from an EARLIER line in the rc still wins, but we
    # still want them to know vdm is now in the picture.
    if grep -Eq '^[[:space:]]*export[[:space:]]+ANTHROPIC_BASE_URL=' "$SHELL_RC" 2>/dev/null; then
      echo -e "  ${YELLOW}Note:${NC} ${CYAN}$SHELL_RC${NC} already exports ANTHROPIC_BASE_URL."
      echo -e "        ${DIM}vdm will NOT clobber that value (the snippet uses \${ANTHROPIC_BASE_URL:-...}).${NC}"
      echo -e "        ${DIM}If you want vdm's proxy to be used, remove the older export line.${NC}"
    fi
    # Resolve the absolute Node binary path at install time and write it
    # into the snippet. Bare `node` in a non-interactive shell (cron,
    # launchd, IDE-spawned subshells) often resolves to nothing or to
    # the wrong arch under Rosetta — silently bypassing the proxy
    # because $ANTHROPIC_BASE_URL would never get exported either.
    NODE_BIN="$(command -v node || true)"
    [[ -z "$NODE_BIN" ]] && NODE_BIN="node" # fallback to PATH lookup at run time
    # Pre-quote for safety (in case the path contains spaces)
    NODE_BIN_QUOTED="$(printf '%q' "$NODE_BIN")"
    # Build the snippet body in a tmp file FIRST, then atomically append
    # to the rc file via _atomic_append_block. This makes the rc-file
    # edit crash-safe: a SIGKILL / Ctrl-C between the heredoc emitting
    # the BEGIN line and the END line previously left a half-written
    # block that the uninstaller could not auto-clean. Now the file
    # composition happens in a tmp file (no partial state visible to
    # any reader), then mv-renames in one syscall.
    _SNIPPET_BODY="$(mktemp -t vdm-snippet.XXXXXX)" || {
      echo -e "  ${RED}!${NC} mktemp failed — refusing to edit rc file" >&2
      exit 1
    }
    _register_cleanup "rm -f \"$_SNIPPET_BODY\""
    cat > "$_SNIPPET_BODY" <<SHELL_EOF
# Uninstall-aware self-disable check. If dashboard.mjs is missing
# (vdm uninstalled, partial removal, manual rm of the install dir), the
# snippet must NOT export ANTHROPIC_BASE_URL — doing so would point every
# new shell at a port nothing is listening on, producing ConnectionRefused
# on every \`claude\` invocation. Defensively also strip any inherited
# ANTHROPIC_BASE_URL=http://localhost:* / 127.0.0.1:* (e.g. carried over
# from a parent process started while vdm WAS installed) so the new shell
# falls back to Anthropic's default endpoint.
if [ ! -x "\$HOME/.claude/account-switcher/dashboard.mjs" ]; then
  case "\${ANTHROPIC_BASE_URL:-}" in
    http*://localhost:*|http*://127.0.0.1:*)
      unset ANTHROPIC_BASE_URL
      ;;
  esac
else
  # Resolve dashboard + proxy ports. Priority order:
  #   1. Pre-existing env var (\$CSW_PORT / \$CSW_PROXY_PORT) wins — lets a user
  #      run \`CSW_PORT=4444 CSW_PROXY_PORT=4445 …\` in the SAME shell (or via a
  #      launchd plist that already exported the value) without this snippet
  #      stomping it back to 3333/3334.
  #   2. Else, parse ~/.claude/account-switcher/config.json for "port" /
  #      "proxyPort" — that's where the dashboard persists user-configured
  #      ports via the settings UI, so a setting saved last week is still
  #      honoured by every fresh shell this week.
  #   3. Else, fall back to the project defaults 3333 / 3334.
  # All python3 calls short-circuit silently on ANY failure (missing python3,
  # missing config.json, malformed JSON, missing key) — the \`|| true\` swallows
  # parse errors and the \`command -v python3\` guard handles a missing
  # interpreter, so the snippet stays inert on a broken-environment shell
  # instead of polluting stderr at every prompt.
  if [ -z "\${CSW_PORT:-}" ] && [ -r "\$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then
    CSW_PORT="\$(python3 -c 'import json,sys
try:
  d=json.load(open(sys.argv[1]))
  v=d.get("port","")
  print(v if isinstance(v,int) else "")
except Exception:
  pass' "\$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"
  fi
  if [ -z "\${CSW_PROXY_PORT:-}" ] && [ -r "\$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then
    CSW_PROXY_PORT="\$(python3 -c 'import json,sys
try:
  d=json.load(open(sys.argv[1]))
  v=d.get("proxyPort","")
  print(v if isinstance(v,int) else "")
except Exception:
  pass' "\$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"
  fi
  # Numeric default fallback runs unconditionally — covers the case where
  # python3 ran but returned an empty string (key missing / non-int value).
  CSW_PORT="\${CSW_PORT:-3333}"
  CSW_PROXY_PORT="\${CSW_PROXY_PORT:-3334}"
  export CSW_PORT CSW_PROXY_PORT
  # Auto-start the dashboard at most once per machine. Two terminals opened
  # the same instant would both pass an \`lsof\` check before either had
  # bound the port, so we use a mkdir-based mutex (atomic on every POSIX
  # filesystem) as the race-free "I'm starting it" guard. The dashboard
  # itself also handles EADDRINUSE cleanly (exits 0), so this is
  # defence-in-depth — the lock just avoids the wasted spawn + log noise.
  # Stale-lock cleanup: if the lock dir is older than 60s, the previous
  # starter must have crashed before releasing it; reclaim it.
  _vdm_lock="\${TMPDIR:-/tmp}/vdm-autostart-\$(id -u).lock.d"
  if [ -d "\$_vdm_lock" ]; then
    # -mmin +1 is portable across BSD (macOS) and GNU find. The -maxdepth 0
    # is needed so find tests the lock dir itself, not its (empty) contents.
    if find "\$_vdm_lock" -maxdepth 0 -mmin +1 2>/dev/null | grep -q .; then
      rmdir "\$_vdm_lock" 2>/dev/null
    fi
  fi
  if mkdir "\$_vdm_lock" 2>/dev/null; then
    # Rotate startup.log before spawn if it's grown past 1 MiB. Without
    # this the file is append-only and grows indefinitely (every shell
    # opens a fresh dashboard if no listener exists, every vdm restart
    # re-opens this stream). Cap at 1 MiB; rotated as .1 (one-deep
    # ring). On macOS \`stat -f '%z'\` is the BSD form; \`stat -c '%s'\`
    # works on GNU coreutils. We try both for portability.
    _vdm_log="\$HOME/.claude/account-switcher/startup.log"
    if [ -f "\$_vdm_log" ]; then
      _vdm_log_sz="\$(stat -f '%z' "\$_vdm_log" 2>/dev/null || stat -c '%s' "\$_vdm_log" 2>/dev/null || echo 0)"
      if [ "\${_vdm_log_sz:-0}" -gt 1048576 ]; then
        mv -f "\$_vdm_log" "\${_vdm_log}.1" 2>/dev/null || :
      fi
      unset _vdm_log_sz
    fi
    unset _vdm_log
    # Probe the RESOLVED dashboard port — not a hard-coded 3333. Otherwise a
    # user with \`CSW_PORT=4444\` already running would still get a second
    # dashboard.mjs spawned because lsof looked at the wrong port.
    if ! lsof -iTCP:"\$CSW_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then
      nohup ${NODE_BIN_QUOTED} ~/.claude/account-switcher/dashboard.mjs \\
        >>~/.claude/account-switcher/startup.log 2>&1 &
      disown
    fi
    rmdir "\$_vdm_lock" 2>/dev/null
  fi
  unset _vdm_lock
  # Use \`:-\` so a user-set ANTHROPIC_BASE_URL exported earlier in the rc
  # file (or inherited from the parent process) is preserved. Only set the
  # vdm proxy URL when nothing else is configured. Use the resolved
  # \$CSW_PROXY_PORT, not a literal 3334, so claude actually hits the proxy
  # on a non-default port instead of bypassing it.
  export ANTHROPIC_BASE_URL="\${ANTHROPIC_BASE_URL:-http://localhost:\$CSW_PROXY_PORT}"
fi
SHELL_EOF
    if ! _atomic_append_block "$SHELL_RC" \
        "# BEGIN claude-account-switcher" \
        "# END claude-account-switcher" \
        "$_SNIPPET_BODY"; then
      echo -e "  ${RED}!${NC} Failed to update $SHELL_RC" >&2
      exit 1
    fi
    rm -f "$_SNIPPET_BODY"
    echo -e "  ${GREEN}✓${NC} Added auto-start to ${CYAN}$SHELL_RC${NC}"
  fi
else
  echo -e "  ${YELLOW}Could not detect shell config file.${NC}"
  echo "  Add this to your shell profile manually:"
  echo ""
  echo '    # BEGIN claude-account-switcher'
  echo '    # Uninstall-aware self-disable — strip stale env if dashboard.mjs is gone.'
  echo '    if [ ! -x "$HOME/.claude/account-switcher/dashboard.mjs" ]; then'
  echo '      case "${ANTHROPIC_BASE_URL:-}" in'
  echo '        http*://localhost:*|http*://127.0.0.1:*) unset ANTHROPIC_BASE_URL ;;'
  echo '      esac'
  echo '    else'
  echo '      if [ -z "${CSW_PORT:-}" ] && [ -r "$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then'
  echo '        CSW_PORT="$(python3 -c '"'"'import json,sys'
  echo 'try:'
  echo '  d=json.load(open(sys.argv[1])); v=d.get("port",""); print(v if isinstance(v,int) else "")'
  echo 'except Exception: pass'"'"' "$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"'
  echo '      fi'
  echo '      if [ -z "${CSW_PROXY_PORT:-}" ] && [ -r "$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then'
  echo '        CSW_PROXY_PORT="$(python3 -c '"'"'import json,sys'
  echo 'try:'
  echo '  d=json.load(open(sys.argv[1])); v=d.get("proxyPort",""); print(v if isinstance(v,int) else "")'
  echo 'except Exception: pass'"'"' "$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"'
  echo '      fi'
  echo '      CSW_PORT="${CSW_PORT:-3333}"'
  echo '      CSW_PROXY_PORT="${CSW_PROXY_PORT:-3334}"'
  echo '      export CSW_PORT CSW_PROXY_PORT'
  echo '      _vdm_lock="${TMPDIR:-/tmp}/vdm-autostart-$(id -u).lock.d"'
  echo '      if [ -d "$_vdm_lock" ] && find "$_vdm_lock" -maxdepth 0 -mmin +1 2>/dev/null | grep -q .; then'
  echo '        rmdir "$_vdm_lock" 2>/dev/null'
  echo '      fi'
  echo '      if mkdir "$_vdm_lock" 2>/dev/null; then'
  echo '        if ! lsof -iTCP:"$CSW_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then'
  echo "          nohup $(command -v node) ~/.claude/account-switcher/dashboard.mjs \\"
  echo '            >>~/.claude/account-switcher/startup.log 2>&1 &'
  echo '          disown'
  echo '        fi'
  echo '        rmdir "$_vdm_lock" 2>/dev/null'
  echo '      fi'
  echo '      unset _vdm_lock'
  echo '      export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-http://localhost:$CSW_PROXY_PORT}"'
  echo '    fi'
  echo '    # END claude-account-switcher'
fi

# ── Install token tracking hooks ──
# Don't mask install_hooks failures — surface them. install_hooks is
# itself atomic (settings.json is rewritten via tmp + os.replace), so
# a failure here means JSON parsing / disk full / permissions, not
# corruption. Surface so the user knows their tokens won't be tracked.
if [[ -f "$INSTALL_DIR/install-hooks.sh" ]]; then
  # shellcheck source=/dev/null
  . "$INSTALL_DIR/install-hooks.sh"
  if install_hooks; then
    echo -e "  ${GREEN}✓${NC} Token tracking hooks installed"
  else
    echo -e "  ${YELLOW}!${NC} Hook install returned non-zero — token tracking may be off."
    echo -e "    ${DIM}Re-run ./install.sh later, or check ${CYAN}~/.claude/settings.json${DIM}.${NC}"
  fi
fi

# ── Install user slash commands (~/.claude/commands/) ──
# Each command is a single .md file with frontmatter + body. Install
# is atomic per-file (tmp + rename) and idempotent — re-running picks up
# the new content. Uninstall removes the files we copied here, leaving
# unrelated commands alone.
COMMANDS_SRC_DIR="$SCRIPT_DIR/commands"
COMMANDS_DST_DIR="$HOME/.claude/commands"
if [[ -d "$COMMANDS_SRC_DIR" ]]; then
  mkdir -p "$COMMANDS_DST_DIR"
  for cmd_file in "$COMMANDS_SRC_DIR"/*.md; do
    [[ -f "$cmd_file" ]] || continue
    _bn="$(basename "$cmd_file")"
    if _atomic_install "$cmd_file" "$COMMANDS_DST_DIR/$_bn" 644; then
      echo -e "  ${GREEN}✓${NC} Installed slash command ${CYAN}/$(basename "$_bn" .md)${NC}"
    else
      echo -e "  ${YELLOW}!${NC} Failed to install slash command $_bn"
    fi
  done
fi

# Mark the install as successful so the rollback trap is a no-op.
_INSTALL_OK=1

echo ""
echo -e "  ${BOLD}${GREEN}Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source $SHELL_RC${NC})"
echo -e "    2. Log in to your first account:  ${DIM}claude login${NC}"
echo -e "    3. Save it:                       ${DIM}vdm add account-1${NC}"
echo -e "    4. Switch accounts or open the dashboard: ${DIM}vdm dashboard${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:3333${NC}"
echo -e "  API Proxy:  ${CYAN}http://localhost:3334${NC}"
echo ""
