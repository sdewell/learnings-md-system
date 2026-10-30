# LEARNINGS system for Codex

A thin Codex plugin that injects shared LEARNINGS context at session start
and runs the shared preflight advisory before relevant Bash calls.

The shared core is installed under `~/.local/share/learnings-md-system/`.
The plugin owns Codex hook schemas, packaging, and the `search-learnings`
skill. Corpus policy remains in the shared core. Nothing in the shared core
calls a model; the only corpus writer is `learn add`.

## Flow

`SessionStart` resolves the project corpus, runs the snapshot and
registration workers only for legacy or unenrolled projects, and injects
shared gotchas and corpus orientation. Compact- and fork-source starts use
the same injection path: a forked thread is a new thread and gets the full
orientation.

`PreToolUse` runs the shared `hooks/preflight-gate.py` advisory for Bash.

Session-start worker output is accepted only as one strict Codex
`hookSpecificOutput` object for `SessionStart`; malformed, wrong-event, and
oversized output is discarded and reported as a UI warning. The adapter reads
the learned-gotchas file through a size-capped, no-follow file descriptor and
adds its current contents directly to session context. That file is
hand-managed; the adapter's only contract with it is a header starting
`<!-- learned-gotchas:`.

Combined startup context is assembled part-aware under the registered
6000-byte `additionalContextLimit` from `hooks/hooks.json`: the project
block is reserved first so lower-priority parts can never starve it,
bullet-structured parts truncate at bullet boundaries (a header with no
surviving bullet is dropped whole), and unstructured parts fit whole or
are dropped whole — never split mid-string.

## Event mapping

| Codex event | Adapter behavior |
| --- | --- |
| `SessionStart` | Runs legacy commit/register workers when needed, injects shared gotchas, and orients to the resolved corpus. No model worker starts. |
| `PreToolUse` | Runs the shared Bash preflight advisory. |

All other events are unregistered and ignored without state writes or worker
spawns. Codex has no failure nudge. `learn add` and `learn search` remain
available; no adapter event starts review or maintenance.

Hook payloads are capped at 1 MiB; oversized input is drained and rejected.

The pre-flight gate is a direct bridge to the shared hook. A shell guard
skips startup when the shared hook is absent. When it is present, uv runs
offline with project discovery disabled and a dedicated user-scoped XDG
cache, so the gate neither reconciles the active project's Python
environment nor needs network access or a shared `/tmp` directory. The
command ends with `|| true`, extending the shared hook's fail-open contract
to process startup, so an unstartable deployment cannot block the Bash
command. A final drain consumes any unread hook payload after a missing or
early-failing worker. The hook is advisory: it adds context but never
returns a permission decision.

The class definitions live in the core's `bin/preflight-gate-classes.json`,
read only by `hooks/preflight-gate.py`; the shared deployment makes them
available to both Claude Code and Codex.

## Requirements

- Codex CLI with stable lifecycle hooks (`0.144.6` was verified).
- `uv` and Python 3.12 or newer, to run the dependency-free adapter and the
  shared Python hook.
- The neutral installed core, created by the core's `bin/deploy.sh`:
  - `~/.local/share/learnings-md-system/hooks/`
  - `~/.local/share/learnings-md-system/bin/`
  - `~/.local/share/learnings-md-system/templates/`
  - `~/.local/share/learnings-md-system/adapters/codex/codex-learnings-hook.py`

The adapter makes no OpenAI or Anthropic request.

## Install locally

A Codex-only machine needs only the neutral core:

```bash
git clone https://github.com/sdewell/learnings-md-system.git
cd learnings-md-system
bin/deploy.sh
codex plugin marketplace add "$PWD"
codex plugin add learnings-md-system-codex@learnings-md-system
```

The hook commands add `~/.local/bin`, `/opt/homebrew/bin`, and
`/usr/local/bin` to `PATH` before invoking `uv`. This supports desktop hosts
that inherit only the system executable directories.

After install, start a new thread and review and trust the `/hooks` command.
The command runs the packaged adapter while it exists, then falls back to
the stable adapter in the deployed core if the host points at a removed
package directory. If `LEARNINGS_CORE_HOME` is customized, the Codex host
must inherit the same value as the deployment shell.

The plugin's `hooks/hooks.json` loads alongside `~/.codex/hooks.json`. It
does not replace any other hook source.

## Runtime state

The default state directory is:

```text
~/.codex/learnings-adapter/sessions/
```

SessionStart keeps the complete session id, the corpus identity cache, and
its lock protection.

On `SessionStart`, one nonblocking cleanup pass removes session artifacts
inactive for 14 days. Each pass inspects at most 16,384 recognized
session-artifact entries and cleans at most 32 sessions; permanent lock
files do not consume the inspection budget. It excludes the active session,
matches complete session IDs rather than ambiguous filename prefixes,
rechecks freshness after acquiring the session's locks, and deliberately
keeps every lock file, so a later process cannot acquire a different inode
while an older descriptor is live.

`LEARNINGS_SESSION_CLASS=harness` marks a session as belonging to a test or
CI harness that must never touch a production corpus. The adapter then
returns immediately with no output, no state write, and no worker spawn.
`interactive` (default) and `automation` are unaffected. The Claude Code
hooks honor the same variable.

Environment overrides exist for tests and controlled deployments:

| Variable | Default |
| --- | --- |
| `LEARNINGS_SESSION_CLASS` | `interactive` |
| `LEARNINGS_ADAPTER_STATE_DIR` | `~/.codex/learnings-adapter/sessions` |
| `LEARNINGS_CORE_HOME` | `~/.local/share/learnings-md-system` |
| `LEARNINGS_HOOKS_DIR` | `$LEARNINGS_CORE_HOME/hooks` |
| `LEARNINGS_BIN_DIR` | `$LEARNINGS_CORE_HOME/bin` |
| `LEARNINGS_GOTCHAS_FILE` | `~/.claude/rules/learned-gotchas.md` |
| `LEARNINGS_ADAPTER_RETENTION_DAYS` | `14` days of inactivity |

The retrieval skill invokes the neutral core's `bin/learn`; it does not
create a Codex-specific CLI copy. Its commands set a temporary
`UV_CACHE_DIR` so the shared uv-shebang CLI also works inside Codex's
workspace sandbox.

## Boundaries

This plugin does not add a second corpus, parse raw Codex transcripts, or
run review on every `Stop`.
