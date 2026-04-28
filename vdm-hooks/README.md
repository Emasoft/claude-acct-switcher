# vdm-hooks (companion plugin)

Optional Claude Code plugin packaging for the [Van Damme-o-Matic](https://github.com/Emasoft/claude-acct-switcher) hook subscriptions.

## What this is

vdm's primary integration with Claude Code is the proxy on `localhost:3334` (intercepts API traffic via `ANTHROPIC_BASE_URL`). The proxy is a **system-level daemon** — it must be a singleton across all running `claude` sessions, mutate the macOS Keychain, and bind a stable host TCP port. None of that fits the plugin sandbox model, so the proxy is NOT and CANNOT be packaged as a plugin.

What CAN be a plugin: the **hook subscriptions**. Claude Code's session-tracking hooks (`UserPromptSubmit`, `Stop`, `SubagentStart`, etc.) live in `~/.claude/settings.json` by default — vdm's `install-hooks.sh` writes them there with a `_VDM_HOOKS_MARKER` block for idempotent re-install. This plugin moves those same 17 subscriptions into a plugin-scoped `hooks/hooks.json` so:

- `/plugin disable vdm-hooks@...` instantly removes them — no settings.json mutation.
- `/plugin enable vdm-hooks@...` re-adds them.
- Marketplace auto-update keeps the hook list current.
- No need for hand-rolled URL-marker idempotency.

The proxy daemon, the `vdm` shell CLI, the `accounts/` storage, and the global git `prepare-commit-msg` hook are **unaffected** — they all keep working as today via the existing `install.sh`.

## Install

vdm-hooks lives inside the `claude-acct-switcher` repo as a subdirectory. Two install paths:

### Path A — incremental (recommended for testing)

Keep using `install.sh` for the daemon + CLI + Keychain integration; add this plugin alongside for the hooks. This means the hooks fire **twice** per event (once via the plugin, once via `install-hooks.sh`'s `~/.claude/settings.json` entry) — which is harmless because vdm's endpoints are idempotent (they de-dupe by `session_id`), but inefficient. To avoid double-firing, run `./uninstall-hooks.sh` first (or the equivalent `vdm hooks uninstall`) to clear the user-settings hooks before installing the plugin.

```bash
# In a Claude Code session:
/plugin marketplace add <path-to-this-repo>/vdm-hooks
/plugin install vdm-hooks@vdm-hooks
```

### Path B — full plugin migration (future)

When the plugin install path is widely used, vdm's main `install.sh` could detect the plugin and skip the hook-write step entirely. Not implemented yet — current `install.sh` always writes to `~/.claude/settings.json`.

## What this plugin does NOT include

- **`PostToolBatch`** — gated by the `~/.claude/account-switcher/per-tool-attribution.flag` file; plugins can't conditionally register hooks at install time. Users who want per-tool attribution should install via `install-hooks.sh` (which honors the flag).
- **Global git `prepare-commit-msg` hook** — outside Claude Code's domain. Stays in `install-hooks.sh`.
- **The proxy daemon and `vdm` CLI** — system-level, can't be a plugin.

## Configuration

The hook URLs are hardcoded to `http://localhost:3333` (vdm's default `CSW_PORT`). If you've overridden `CSW_PORT`, you'll need to either:
- Set the dashboard back to port 3333, or
- Fork this plugin and edit `hooks/hooks.json`, or
- Stick with `install-hooks.sh` (which reads `CSW_PORT` at install time).

A future version will use plugin `userConfig` for the dashboard port — this MVP is hardcoded to keep the manifest simple.

## License

[The Unlicense](../LICENSE) — public domain. Same as the parent repo.
