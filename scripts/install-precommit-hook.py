#!/usr/bin/env python3
"""install-precommit-hook.py

Atomically installs the Codex / Opus pre-commit review gate into the
CURRENT git repo. Two pieces get installed:

  1. The pre-commit hook script -> <repo>'s git hooks dir
  2. The Opus subagent definition -> EITHER ~/.claude/agents/
     (default, --global) OR <repo>/.claude/agents/ (--local)

The agent is named ``chk-review-opus-agent`` (the ``chk-`` prefix marks
it as a "check" agent and avoids colliding with any user agent that
might already be called ``review-opus-agent``). The agent definition
is EMBEDDED below as the ``AGENT_MD`` constant — the installer is
self-contained for the agent half. The hook script itself lives at
``scripts/git-hooks/pre-commit`` next to this installer.

Per-repo manual install — no hidden global hook activation, no other
repos affected. Idempotent: re-running replaces the hook in place via
a temp+rename swap; NEVER overwrites an existing agent file with the
same name unless ``--force-replace-agent`` is passed.

Usage:

  python3 install-precommit-hook.py                     # --global agent (default)
  python3 install-precommit-hook.py --global            # explicit
  python3 install-precommit-hook.py --local             # agent into <repo>/.claude/agents/
  python3 install-precommit-hook.py --hook-only         # skip agent install entirely
  python3 install-precommit-hook.py --force-replace-agent
  python3 install-precommit-hook.py --emit-agent        # stream embedded agent .md to stdout
  python3 install-precommit-hook.py --help

Two ways to invoke from another repo:

  1. From inside claude-acct-switcher itself:
       python3 scripts/install-precommit-hook.py
  2. From inside ANY other git repo, pointing at this checkout:
       cd /path/to/some-other-repo
       python3 /path/to/claude-acct-switcher/scripts/install-precommit-hook.py

What this DOES NOT do:
  - Touch git config core.hooksPath (only warns if it's set away
    from the default — see below)
  - Touch the target repo's .gitignore. The hook auto-routes reports
    to ~/.cache/codex-precommit/<repo>/ when /reports/ isn't ignored
    in that repo, so reports never leak into commits.
  - Restart Claude Code (must be done manually after the agent file
    is dropped — Claude Code only discovers subagents at startup).

Bypass any individual commit (emergency only):  git commit --no-verify
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

AGENT_NAME = "chk-review-opus-agent"

AGENT_MD = """\
---
name: chk-review-opus-agent
description: Strict pre-commit code-review gate (Opus). Invoked by the project pre-commit hook when Codex is unavailable. Reads a pre-staged diff + untracked file list from /tmp, reads each untracked file's content, then writes a markdown findings report to the MAIN repo root.
tools: Read, Write, Bash, Glob, Grep
model: opus
---

# Pre-commit code-review agent (Opus)

You are a strict pre-commit code-review gate. You exist as the fallback for the project's pre-commit hook when OpenAI Codex is unavailable (out of credits, rate-limited, network unreachable, internal error). You are invoked autonomously by a shell script and must complete your review in a single turn.

## How you are invoked

The orchestrator's prompt gives you four absolute paths:

- **DIFF_PATH**: file containing `git diff HEAD` (= staged + unstaged changes)
- **UNTRACKED_LIST**: file with one untracked filename per line (paths are relative to MAIN_ROOT)
- **MAIN_ROOT**: absolute path to the main project root
- **REPORT_PATH**: absolute path where you MUST write your markdown report

You run in the main checkout cwd (NOT in a separate worktree — `git worktree add` cannot run from inside a pre-commit hook). REPORT_PATH points to MAIN_ROOT/reports/chk-review-opus-agent/<timestamp>.md so the report has a stable home alongside other audit artifacts.

## What to do (in order)

1. Use **Read** to read DIFF_PATH. This is the source of truth for staged + unstaged changes.
2. Use **Read** to read UNTRACKED_LIST. Each line is a file path relative to MAIN_ROOT.
3. For each untracked file path P:
   - Build the absolute path `$MAIN_ROOT/$P`
   - **Skip** if any of these apply (use Bash to check):
     - Binary (`file -I "$ABS"` charset is `binary` or `unknown-8bit`)
     - Larger than 200 KB (`stat -f%z "$ABS"` on macOS, or `stat -c%s "$ABS"` on Linux)
     - Path matches `node_modules/`, `.git/`, `dist/`, `build/`, `.venv/`, `__pycache__/`, `.cache/`, `*.lock`, `*.log`
   - Otherwise use **Read** with the absolute path to ingest the file's content
4. Review the staged/unstaged diff AND every readable untracked file for issues. Look for:
   - **CRITICAL** — data loss, security vulnerability, crash, severe bug
   - **MAJOR** — real bug, race condition, resource leak, broken contract, missing input validation at a trust boundary
   - **MINOR** — missed edge case, inconsistency, suboptimal logic with measurable impact, error swallowing
   - **NIT** — cosmetic, style-only, no behavioral impact (informational — does NOT block the commit)
5. Use **Write** to save your report to REPORT_PATH. Create parent directories first via Bash if needed (`mkdir -p`).
6. After Write returns success, output a single line: `REPORT_WRITTEN: <REPORT_PATH>` and end your turn.

## Output format (STRICT — the parser greps for severity tokens verbatim)

The calling shell script greps for `^| <code> | <SEVERITY> | <file:line> | ...`. Emit this exact shape:

```markdown
# Pre-commit review (Opus fallback agent)

## Findings

| Code | Severity | File:line | Summary |
|---|---|---|---|
| F-001 | CRITICAL | path/to/file.ext:42 | one-line description |
| F-002 | MAJOR | path/to/file.ext:88 | one-line description |
| F-003 | MINOR | path/to/file.ext:120 | one-line description |
| F-004 | NIT | path/to/file.ext:200 | one-line description |

## Rationale

One short paragraph explaining the verdict. OK to omit if no findings.
```

If you find **no issues at all**, still emit the `# Pre-commit review` header and the `## Findings` section with the table headers but no data rows. The parser sees zero blocking rows and passes.

## Rules — STRICT

- **Be terse.** Don't speculate beyond what the diff and the file contents show.
- **Review-only — no source mutation.** This is the load-bearing safety guarantee since you run in the main checkout (NOT a sandboxed worktree):
  - Your tool list does NOT include Edit. Don't try to use it.
  - The ONLY Write you perform is to REPORT_PATH. Do NOT Write to any source file in MAIN_ROOT.
  - Bash is permitted ONLY for read-only inspection: `file -I`, `stat`, `mkdir -p` (on REPORT_PATH's parent dir only), `wc -l`. Do NOT use Bash for mutation: no `>` redirect to source files, no `mv`, no `rm`, no `git add`/`commit`/`stash`/`reset`/`checkout`, no `chmod`, no `npm install`/`pip install`. If you find yourself wanting to mutate state, write a finding about it instead.
- **Auto-exit.** After Write succeeds and you print `REPORT_WRITTEN: <path>`, your turn is over. Do not continue, do not ask follow-up questions, do not wait for further input.
- **Single source of truth for paths.** All paths come from the orchestrator's prompt. Don't invent paths or rely on cwd assumptions.
- **Fatal-error fallback.** If something prevents you from completing the review (e.g., DIFF_PATH unreadable, REPORT_PATH unwritable, all candidate files binary/oversized), still write a report at REPORT_PATH containing a single MAJOR finding describing the error. The hook needs SOME report to parse — silent agent failure leaves the user staring at an opaque hook error.
- **Severity discipline.** Use the four severity tokens above EXACTLY. Do not invent variants like "warning" or "issue" — the parser is strict.
"""


def run_git(args: list[str], cwd: Path | None = None) -> str:
    """Run `git <args>` and return stdout (rstripped). Empty string on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.rstrip("\n")
    except FileNotFoundError:
        return ""


def atomic_install(src_text: str, dst: Path, mode: int) -> None:
    """Write src_text to dst atomically (temp file in same dir + rename) with mode."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(dst.parent), prefix=dst.name + ".tmp-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(src_text)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dst)
    except Exception:
        # Clean up the temp file on any failure path so we don't leak.
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def install_hook(src_hook: Path, target_root: Path) -> Path:
    """Install the pre-commit hook into the canonical hooks dir (worktree-safe).

    Uses `git rev-parse --git-common-dir` so this works inside linked
    worktrees (where `.git` is a gitdir-pointer FILE, not a directory)
    AND in the main checkout. Returns the destination path.
    """
    common_dir = run_git(["rev-parse", "--git-common-dir"], cwd=target_root)
    if not common_dir:
        sys.exit(f"git rev-parse --git-common-dir failed for {target_root}")
    common_path = Path(common_dir)
    if not common_path.is_absolute():
        common_path = (target_root / common_path).resolve()
    hooks_dir = common_path / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    dst = hooks_dir / "pre-commit"

    src_text = src_hook.read_text()
    atomic_install(src_text, dst, 0o755)
    return dst


def warn_hookspath_override(target_root: Path, expected_hooks_dir: Path) -> None:
    """Print a warning if core.hooksPath is set to something other than the default."""
    local = run_git(["-C", str(target_root), "config", "--local", "--get", "core.hooksPath"])
    glob = run_git(["config", "--global", "--get", "core.hooksPath"])
    active = local or glob
    if not active:
        return
    active_path = Path(active)
    if not active_path.is_absolute():
        active_path = (target_root / active_path).resolve()
    if active_path == expected_hooks_dir:
        return
    print()
    print("WARNING: core.hooksPath is set to a custom location:")
    print(f"    {active}")
    if local:
        print("    (set locally in this repo)")
    elif glob:
        print("    (set globally via git config --global)")
    print()
    print(f"  Writing to {expected_hooks_dir}/pre-commit will be silently inert — git looks at")
    print(f"  {active_path}/pre-commit instead. To activate this hook, either:")
    print(f"    (a) Copy the hook to that directory after this install completes:")
    print(f"        install -m 755 <pre-commit> {active_path}/pre-commit")
    print("    OR")
    print(f"    (b) Unset the override in this repo:")
    print(f"        git -C {target_root} config --local --unset core.hooksPath")
    print()
    print("  Continuing — writing to the default hooks dir for forward-compat;")
    print("  the hook will start firing the moment the override is cleared.")
    print()


def install_agent(scope: str, target_root: Path, force: bool) -> None:
    """Install the embedded AGENT_MD into ~/.claude/agents/ or <repo>/.claude/agents/.

    Skips silently if an identical file already exists. Refuses to
    overwrite a DIFFERENT existing file unless ``force`` is true,
    printing the diff/refresh recipe instead.
    """
    if scope == "none":
        print()
        print("Skipped agent install (--hook-only). The Opus fallback path will")
        print(f"fail until ~/.claude/agents/{AGENT_NAME}.md OR")
        print(f"<repo>/.claude/agents/{AGENT_NAME}.md exists. Re-run without")
        print("--hook-only to drop it in.")
        return

    if scope == "local":
        agent_dir = target_root / ".claude" / "agents"
        scope_label = "local (this repo only)"
    else:
        agent_dir = Path.home() / ".claude" / "agents"
        scope_label = "global (all Claude Code sessions)"

    agent_dst = agent_dir / f"{AGENT_NAME}.md"
    agent_dir.mkdir(parents=True, exist_ok=True)

    if agent_dst.exists() and not force:
        if agent_dst.read_text() == AGENT_MD:
            print(f"Agent file already in place at {agent_dst} (identical).")
            return
        print()
        print(f"WARNING: an agent file ALREADY exists at {agent_dst} and DIFFERS")
        print("from the embedded version this installer would write. NOT overwriting.")
        print()
        print("  To force-overwrite with this installer's version:")
        flags = ["--force-replace-agent"]
        if scope == "local":
            flags.append("--local")
        print(f"    python3 {sys.argv[0]} {' '.join(flags)}")
        print()
        print("  To diff this installer's version against what's on disk:")
        print(f"    diff {agent_dst} <(python3 {sys.argv[0]} --emit-agent)")
        print()
        print("  To dump the embedded version to a different path you control:")
        print(f"    python3 {sys.argv[0]} --emit-agent > /path/of/your/choice.md")
        print()
        print("  After ANY change to the agent file, RESTART Claude Code so")
        print("  the subagent registry picks it up at startup.")
        return

    atomic_install(AGENT_MD, agent_dst, 0o644)
    if force and agent_dst.exists():
        # Distinguish forced replacement from fresh install in the message.
        # (We can't easily detect "was new vs replaced" after atomic_install,
        # but FORCE implies the user knew there was something there.)
        print(f"Replaced Opus subagent -> {agent_dst}  ({scope_label}) — --force-replace-agent")
    else:
        print(f"Installed Opus subagent -> {agent_dst}  ({scope_label})")
    print("*** Restart Claude Code so the new subagent is discovered at startup. ***")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install the Codex/Opus pre-commit review gate in the current repo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument(
        "--global", dest="scope", action="store_const", const="global",
        help="Install agent at ~/.claude/agents/ (default)",
    )
    scope_group.add_argument(
        "--local", dest="scope", action="store_const", const="local",
        help="Install agent at <repo>/.claude/agents/",
    )
    scope_group.add_argument(
        "--hook-only", dest="scope", action="store_const", const="none",
        help="Install only the hook; skip the agent .md install",
    )
    parser.add_argument(
        "--force-replace-agent", action="store_true",
        help="Overwrite an existing agent file at the target path",
    )
    parser.add_argument(
        "--emit-agent", action="store_true",
        help="Print the embedded agent .md to stdout and exit (no file writes)",
    )
    parser.set_defaults(scope="global")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.emit_agent:
        sys.stdout.write(AGENT_MD)
        return 0

    script_dir = Path(__file__).resolve().parent
    src_hook = script_dir / "git-hooks" / "pre-commit"
    if not src_hook.is_file():
        sys.exit(f"Source hook not found: {src_hook}\n"
                 f"Make sure scripts/git-hooks/pre-commit exists alongside this installer.")

    target_root_str = run_git(["rev-parse", "--show-toplevel"])
    if not target_root_str:
        sys.exit("Not inside a git working tree.\n"
                 f"Run this from the repo you want to install the hook into:\n"
                 f"    cd /path/to/your-repo\n"
                 f"    python3 {sys.argv[0]}")
    target_root = Path(target_root_str)

    # Resolve the canonical hooks dir for the warning check before
    # actually installing. (install_hook recomputes; cheap & idempotent.)
    common_dir = run_git(["rev-parse", "--git-common-dir"], cwd=target_root)
    common_path = Path(common_dir)
    if not common_path.is_absolute():
        common_path = (target_root / common_path).resolve()
    expected_hooks_dir = common_path / "hooks"

    warn_hookspath_override(target_root, expected_hooks_dir)

    dst_hook = install_hook(src_hook, target_root)
    print(f"Installed pre-commit hook -> {dst_hook}")
    print(f"Source -> {src_hook}")
    print(f"Target repo -> {target_root}")

    install_agent(args.scope, target_root, args.force_replace_agent)

    print()
    print("What it does on every commit, ONLY in this repo:")
    print('  1. Tries: codex review --uncommitted -c model_reasoning_effort="high"')
    print("  2. If codex fails (rate-limited / out of credits / network /")
    print(f"     internal error): falls back to claude --agent {AGENT_NAME}")
    print("     --dangerously-skip-permissions  (uses OAuth Pro/Max subscription).")
    print("  3. Blocks the commit if the reviewer flags any MINOR / MAJOR /")
    print("     CRITICAL finding. NIT findings do NOT block.")
    print("  4. Reports go to:")
    print(f"       - {target_root}/reports/codex-review/pre-commit/  (when /reports/")
    print("         is in this repo's .gitignore, e.g. claude-acct-switcher), OR")
    print(f"       - ~/.cache/codex-precommit/{target_root.name}/  (default —")
    print("         keeps the working tree clean of audit artefacts)")
    print()
    print("Tunables (env vars, set per-shell or per-commit):")
    print("  CODEX_TIMEOUT_SEC          default 1800 (30 min cap on codex)")
    print("  OPUS_TIMEOUT_SEC           default 1800 (30 min cap on opus fallback)")
    print("  PRECOMMIT_REPORTS_DIR      override codex report dir (absolute path)")
    print("  PRECOMMIT_OPUS_REPORTS_DIR override opus  report dir (absolute path)")
    print()
    print("Bypass any individual commit (emergency only): git commit --no-verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
