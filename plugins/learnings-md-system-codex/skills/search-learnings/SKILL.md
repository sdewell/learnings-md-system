---
name: search-learnings
description: Search and update the project's shared LEARNINGS.md and LEARNINGS-{topic}.md corpus. Use when debugging something that may have happened before; before work in gotcha-prone areas such as concurrency, file locking, hook schemas, subprocesses, parsing, regex, validation, paths, or marker files; when checking an unfamiliar project convention; when a pattern sounds familiar; or when the user asks to remember, save, capture, or add a learning. Do not use for trivial file reads or generic questions with no useful search term.
---

# Search Learnings

Use the existing `learn` CLI and corpus shared intentionally by Claude and
Codex. Do not create a second Codex-only corpus or depend on `learn` being on
`PATH`.

## Search

Choose one or two specific terms, then invoke the shared CLI by its absolute,
cross-agent installation path. Give uv a temporary cache because Codex's
sandbox may not allow writes to uv's default cache under `~/.cache`:

```bash
UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "<query>"
```

Examples:

- `UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search fcntl`
- `UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "session marker"`
- `UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "hook output"`

Use `UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" status`
first when the available topics are unclear.
Treat matches as project prior art: apply relevant guidance, but verify it
against the current code and tests. A `No matches` result means only that the
corpus has no recorded match.

Before declaring a gotcha-prone fix complete, search once for prior failed-fix
notes in the same area.

## Add a learning

First contact with a resolved mistake gets one archive line through `learn add`; second contact is a `learn search` hit that saved you or the user saying "this keeps happening".
On second contact, load the bundled [route-learning](../route-learning/SKILL.md)
skill and route the existing lesson rather than adding another archive entry.

When the user asks to remember something, or the work reveals a durable project
lesson, add one focused entry through the shared writer:

```bash
UV_CACHE_DIR="${TMPDIR:-/tmp}/learnings-md-system-uv-cache" "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" add <topic-slug> "<section header>" "<entry text>"
```

Use one of the project's canonical section headers and state the observed
problem plus the proven fix. Let the CLI choose the destination and coordinate
concurrent writers; do not append directly when the CLI is available.

If the neutral `learn` CLI is missing, report that the shared LEARNINGS
deployment is unavailable. Do not silently create a replacement under
`~/.codex`.
