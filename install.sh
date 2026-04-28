#!/usr/bin/env bash
# Claude Account Switcher  - Installer
# Installs vdm to ~/.claude/account-switcher/ and configures your shell.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
# POSIX-portable: resolve the directory containing this script. `pwd -P`
# canonicalises any symlink components in the path. This works whether
# install.sh is invoked directly, via a symlink, or via $PATH — and does
# not depend on GNU `readlink -f` / `realpath` being on PATH (BSD readlink
# on stock macOS lacks -f, and `realpath` ships only with newer macOS).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Concurrent-install mutex. Two `install.sh` invocations racing in parallel
# (rare but possible: two terminals, a shell hook, an editor's "post-clone"
# action) would both pass the BEGIN-marker check below and both append a
# block to the rc file — leaving the user with duplicated `if !
# lsof ... fi` blocks and (more annoying) duplicated `export
# ANTHROPIC_BASE_URL=...` lines. mkdir is atomic on every POSIX filesystem
# (the kernel guarantees only one caller wins) — same pattern as
# install-hooks.sh's settings.json mutex. Stock macOS ships no flock(1),
# so mkdir is the portable primitive.
INSTALL_LOCK="$HOME/.claude/.vdm-install.lock.d"
mkdir -p "$HOME/.claude" 2>/dev/null || true
_we_own_lock=0
_lock_tries=0
while ! mkdir "$INSTALL_LOCK" 2>/dev/null; do
  _lock_tries=$((_lock_tries + 1))
  if [[ $_lock_tries -ge 600 ]]; then
    echo -e "${RED}Another install.sh appears to be running (lock held > 60s).${NC}"
    echo "  If no install is running, remove the stale lock and retry:"
    echo "    rm -rf $INSTALL_LOCK"
    exit 1
  fi
  sleep 0.1
done
_we_own_lock=1
# Release the lock on every exit path — including ^C and `set -e` aborts.
# Only release if WE acquired it (the timeout exit above never sets the
# flag, so we never accidentally rmdir another installer's lock).
trap '[[ $_we_own_lock -eq 1 ]] && rmdir "$INSTALL_LOCK" 2>/dev/null || true' EXIT

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Installer${NC}"
echo -e "  ────────────────────────────────────────"
echo ""

# ── Check prerequisites ──

if ! command -v node &>/dev/null; then
  echo -e "${RED}Node.js is required but not installed.${NC}"
  echo "  Install it from https://nodejs.org/ or via: brew install node"
  exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [[ "$NODE_VERSION" -lt 18 ]]; then
  echo -e "${YELLOW}Warning: Node.js v18+ recommended (found v$(node -v))${NC}"
fi

if [[ "$(uname)" != "Darwin" ]]; then
  echo -e "${RED}This tool requires macOS (uses Keychain for credential storage).${NC}"
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo -e "${RED}python3 is required but not installed.${NC}"
  exit 1
fi

echo -e "  ${GREEN}✓${NC} Prerequisites OK (Node $(node -v), macOS, python3)"
echo ""

# ── Phase G: env-var conflict preflight ──
# Five env vars silently bypass vdm's keychain rotation. If any of these is
# set in the user's shell, Claude Code will read it FIRST and never touch
# the keychain — vdm's whole credential-rotation model becomes a no-op.
# Four cloud-provider env vars route Claude Code to a different backend
# entirely (Bedrock / Vertex / Foundry / Mantle), bypassing the proxy.
# We can't fix any of these — only emit a clear warning so users notice.
_vdm_warned_envs=()
for _v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_OAUTH_TOKEN \
          CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_OAUTH_REFRESH_TOKEN; do
  if [[ -n "${!_v:-}" ]]; then
    _vdm_warned_envs+=("$_v")
  fi
done
if [[ ${#_vdm_warned_envs[@]} -gt 0 ]]; then
  echo -e "  ${YELLOW}⚠${NC} ${BOLD}Env vars set that bypass vdm's keychain rotation:${NC}"
  for _v in "${_vdm_warned_envs[@]}"; do
    echo -e "      ${YELLOW}$_v${NC} — Claude Code will read this token instead of the keychain"
  done
  echo -e "      ${DIM}vdm will still proxy traffic, but credential switching becomes a no-op.${NC}"
  echo -e "      ${DIM}Unset these to use vdm normally, or accept that the active account is fixed.${NC}"
  echo ""
fi

_vdm_cloud_envs=()
for _v in CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX \
          CLAUDE_CODE_USE_FOUNDRY CLAUDE_CODE_USE_MANTLE; do
  if [[ -n "${!_v:-}" ]]; then
    _vdm_cloud_envs+=("$_v")
  fi
done
if [[ ${#_vdm_cloud_envs[@]} -gt 0 ]]; then
  echo -e "  ${RED}⚠${NC} ${BOLD}Cloud-provider env vars set:${NC}"
  for _v in "${_vdm_cloud_envs[@]}"; do
    echo -e "      ${RED}$_v${NC} — Claude Code routes to a non-Anthropic backend, bypassing vdm entirely"
  done
  echo -e "      ${DIM}vdm targets api.anthropic.com only. Unset these to route through vdm.${NC}"
  echo ""
fi

# ── Install files ──

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/accounts"

cp "$SCRIPT_DIR/dashboard.mjs" "$INSTALL_DIR/dashboard.mjs"
cp "$SCRIPT_DIR/lib.mjs" "$INSTALL_DIR/lib.mjs"
cp "$SCRIPT_DIR/vdm" "$INSTALL_DIR/vdm"
cp "$SCRIPT_DIR/install-hooks.sh" "$INSTALL_DIR/install-hooks.sh"
chmod +x "$INSTALL_DIR/vdm"

# Create default config if it doesn't exist
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  cp "$SCRIPT_DIR/config.example.json" "$INSTALL_DIR/config.json"
fi

# Write version marker from git if available (prefer semver tag, fall back to hash)
if command -v git &>/dev/null && git -C "$SCRIPT_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
  git -C "$SCRIPT_DIR" fetch --tags --quiet 2>/dev/null || true
  ( git -C "$SCRIPT_DIR" describe --tags --abbrev=0 2>/dev/null \
    || git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null ) > "$INSTALL_DIR/.version" || true
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
    echo "" >> "$SHELL_RC"
    cat >> "$SHELL_RC" <<SHELL_EOF
# BEGIN claude-account-switcher
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
# END claude-account-switcher
SHELL_EOF
    echo -e "  ${GREEN}✓${NC} Added auto-start to ${CYAN}$SHELL_RC${NC}"
  fi
else
  echo -e "  ${YELLOW}Could not detect shell config file.${NC}"
  echo "  Add this to your shell profile manually:"
  echo ""
  echo '    # BEGIN claude-account-switcher'
  echo '    if [ -z "${CSW_PORT:-}" ] && [ -r "$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then'
  echo '      CSW_PORT="$(python3 -c '"'"'import json,sys'
  echo 'try:'
  echo '  d=json.load(open(sys.argv[1])); v=d.get("port",""); print(v if isinstance(v,int) else "")'
  echo 'except Exception: pass'"'"' "$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"'
  echo '    fi'
  echo '    if [ -z "${CSW_PROXY_PORT:-}" ] && [ -r "$HOME/.claude/account-switcher/config.json" ] && command -v python3 >/dev/null 2>&1; then'
  echo '      CSW_PROXY_PORT="$(python3 -c '"'"'import json,sys'
  echo 'try:'
  echo '  d=json.load(open(sys.argv[1])); v=d.get("proxyPort",""); print(v if isinstance(v,int) else "")'
  echo 'except Exception: pass'"'"' "$HOME/.claude/account-switcher/config.json" 2>/dev/null || true)"'
  echo '    fi'
  echo '    CSW_PORT="${CSW_PORT:-3333}"'
  echo '    CSW_PROXY_PORT="${CSW_PROXY_PORT:-3334}"'
  echo '    export CSW_PORT CSW_PROXY_PORT'
  echo '    _vdm_lock="${TMPDIR:-/tmp}/vdm-autostart-$(id -u).lock.d"'
  echo '    if [ -d "$_vdm_lock" ] && find "$_vdm_lock" -maxdepth 0 -mmin +1 2>/dev/null | grep -q .; then'
  echo '      rmdir "$_vdm_lock" 2>/dev/null'
  echo '    fi'
  echo '    if mkdir "$_vdm_lock" 2>/dev/null; then'
  echo '      if ! lsof -iTCP:"$CSW_PORT" -sTCP:LISTEN -t >/dev/null 2>&1; then'
  echo "        nohup $(command -v node) ~/.claude/account-switcher/dashboard.mjs \\"
  echo '          >>~/.claude/account-switcher/startup.log 2>&1 &'
  echo '        disown'
  echo '      fi'
  echo '      rmdir "$_vdm_lock" 2>/dev/null'
  echo '    fi'
  echo '    unset _vdm_lock'
  echo '    export ANTHROPIC_BASE_URL="${ANTHROPIC_BASE_URL:-http://localhost:$CSW_PROXY_PORT}"'
  echo '    # END claude-account-switcher'
fi

# ── Install token tracking hooks ──

if [[ -f "$INSTALL_DIR/install-hooks.sh" ]]; then
  source "$INSTALL_DIR/install-hooks.sh"
  install_hooks && echo -e "  ${GREEN}✓${NC} Token tracking hooks installed" || true
fi

# ── Install user slash commands (~/.claude/commands/) ──
# Each command is a single .md file with frontmatter + body. Install
# is idempotent: cp -f overwrites prior copies so an upgrade picks up
# the new content. Uninstall removes the files we copied here, leaving
# unrelated commands alone.
COMMANDS_SRC_DIR="$SCRIPT_DIR/commands"
COMMANDS_DST_DIR="$HOME/.claude/commands"
if [[ -d "$COMMANDS_SRC_DIR" ]]; then
  mkdir -p "$COMMANDS_DST_DIR"
  for cmd_file in "$COMMANDS_SRC_DIR"/*.md; do
    [[ -f "$cmd_file" ]] || continue
    cp -f "$cmd_file" "$COMMANDS_DST_DIR/"
    echo -e "  ${GREEN}✓${NC} Installed slash command ${CYAN}/$(basename "$cmd_file" .md)${NC}"
  done
fi

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
