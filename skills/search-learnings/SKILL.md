---
name: search-learnings
description: Consult the project's LEARNINGS.md (and `LEARNINGS-{topic}.md` files) for prior lessons — captured patterns, pitfalls, conventions, and gotchas from past work. Use when DEBUGGING anything that might have been hit before, BEFORE writing code in pitfall-prone areas (concurrency, fcntl/file locking, hook output schemas, subprocess, parsing, regex, validation, marker files), when checking project conventions for an unfamiliar area, or when the user mentions a pattern that sounds familiar. ALSO use when the user asks to capture/save/remember/add something to LEARNINGS — including facts from outside the session (meetings, docs, prior conversations). Triggers include "have we seen this before?", "is there a gotcha with X?", "what's our convention for...", "remember this for next time", "add this to learnings", "save this". Do NOT use for trivial work (git status, file reads) or generic queries.
allowed-tools: 'Bash(learn:*), Bash("${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn":*)'
---

# Search Learnings

The `learn` CLI lets you query the per-project LEARNINGS files (the project's monolithic `LEARNINGS.md` and any `LEARNINGS-{topic}.md` topic subfiles) for prior captured lessons.

## Important: PATH-independent invocation

The CLI is deployed to the provider-neutral installed core. **Always invoke
through the installed-core expression** — do NOT rely on `learn` being on the
user's PATH:

```bash
"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "<query>"
```

The shell honors an explicit `LEARNINGS_CORE_HOME` and otherwise uses the
standard neutral core. Quoting the complete executable path preserves custom
locations containing spaces. This pattern applies to every `learn` invocation
in this skill.

## When to use

- About to write code touching a known-gotcha area: locking, subprocess, hook output schemas, parsing, regex, validation, marker files.
- The user mentions something that sounds like it might have been learned before.
- Debugging — a similar bug may already be documented.
- Before claiming a fix is complete, check whether the area has prior "this fix was wrong because..." notes.

## When NOT to use

- Trivial routine work (`git status`, `ls`, `cat`).
- The query is too generic to return useful matches (`function`, `error`).

## How to invoke

```bash
"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "<query>"
```

Use one or two key words — search is case-insensitive and ranks files by match count. Examples:

- `"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search fcntl` — locking patterns
- `"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search "session marker"` — marker-file patterns
- `"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" search regex` — known regex gotchas

To see what topics exist before searching:

```bash
"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" status
```

## Interpreting output

Each file with matches shows: `<filename> (N matches)` followed by `L<line>: <matched line>`. Files are ranked best-match-first. A "No matches" line means the search term isn't documented — proceed with normal caution; consider adding a learning *after* the work if you discover something new.

## Adding new learnings

If you discover something worth capturing during the work, use:

```bash
"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" add <topic-slug> "<section header>" "<entry text>"
```

The CLI appends to an existing matching topic subfile. For an unknown topic, it creates a new subfile in INDEX mode and appends to `LEARNINGS.md` in monolith mode. Writes use the checked corpus write session and its locks, so concurrent sessions in the same project cannot interleave their writes.

Creating a topic in INDEX mode also refreshes its catalog in the same write
session. To refresh an existing catalog explicitly, run `learn index` for a
preview, then `learn index --apply --yes` to write it, using the installed-core
path above. Add `--cwd <project>` to select another project. This preserves
existing metadata; it does not generate summaries or split a monolith.
Unrecognized catalog prose or stale summary text blocks refresh. A new-topic
add still saves the lesson, leaves the index unchanged, and warns about the
stale catalog. Reconcile the catalog before retrying `learn index`.

If the lesson is a repeat (the failure hook said `Recorded before`), load the `route-learning` skill instead of adding a second line.
