# learnings-md-system

A small system that helps AI coding agents (Claude Code and Codex) stop
repeating the same mistakes. It records a mistake once, notices when the
same mistake comes back, and then asks the agent to move the lesson
somewhere it will actually be read: a test, a hook, a project rule, or a
skill.

It is also a record of how that idea was reached. The first versions
captured everything automatically and used models to clean the pile up.
Usage counts later suggested that very little of it was read. The current version is much
smaller. [DESIGN-STORY.md](DESIGN-STORY.md) tells that story with the
numbers.

## How it works

1. **First contact.** A command fails. The failure hook (Claude Code) reminds
   the agent: after you fix it, write one line with
   `learn add <topic> "<section>" "<root cause + what works>"`.
2. **Second contact.** When a later failure matches an entry already
   recorded, the hook prints `Recorded before: <entry> [<id>]` and names the
   `route-learning` skill.
3. **Routing.** The skill asks one question: *who needs this, and when?*
   The answer picks one destination, enforcement first:

   | Who needs it | Where it goes |
   |---|---|
   | Nobody, if a check can make the mistake impossible | A test or a hook |
   | Every session in this repo | The repo's agent instructions file |
   | Anyone doing one kind of task | A repo skill |
   | Nobody yet | Stays in the archive |
   | Nobody: the model would not repeat it | Nothing |

   Every destination is a normal repo change, reviewed and merged by a
   person.

Nothing in the system calls a model, and nothing writes on a timer. The
only way an entry enters the archive is `learn add`.

## What is in the box

| Part | What it does |
|---|---|
| `bin/learn` | The CLI: `add`, `search`, `index`, `status`, `stats`, `cleanup`, and corpus management |
| `hooks/learning-on-start.py` | SessionStart: orients the agent to the project's archive and injects shared gotchas |
| `hooks/learning-on-failure.py` | PostToolUseFailure: the first-contact and `Recorded before` nudges |
| `hooks/preflight-gate.py` | PreToolUse on `gh pr create`: an advisory checklist of recurring bug classes (below) |
| `hooks/commit-learnings.sh` | SessionStart: optional Git snapshots of in-repo archive files; off unless enabled in settings (below) |
| `skills/route-learning/` | The router |
| `skills/search-learnings/` | How an agent searches and adds entries |
| `plugins/learnings-md-system-codex/` | The Codex adapter: same core, Codex hook schemas |

Claude Code and Codex are two hosts of one system. Each has a thin adapter
that translates its lifecycle events into the shared core.

In an indexed corpus, adding a new topic also refreshes the topic catalog.
To rebuild that catalog explicitly, run `learn index` to preview the result
and `learn index --apply --yes` to write it. Use `--cwd /path/to/project`
to select another project. This preserves existing summary and keywords
headers; it does not generate summaries or split a monolith.
Sections outside the catalog are preserved. Unrecognized catalog prose or
stale summary text must be reconciled before refresh can proceed.
A new-topic add still saves the lesson in that case and warns that its
catalog was left unchanged.

### The pre-flight gate

Before a pull request opens, the gate prints the bug classes that review
kept finding in this codebase, so the author checks for them first:

- **shared-dir I/O:** checked a file, then acted on it later; another
  process changed it in between.
- **enumerate writers:** a lock on one writer of a file, none on the other.
- **marker semantics:** a "done" marker written before the work it records.
- **model output contract:** treating "exit 0 and not empty" as valid output.
- **units and anchoring:** bytes compared with characters; a path relative
  to the wrong directory.
- **cache invalidation**, **test quality**, and **unfired detector** (a check
  nobody has watched fire on a known bad input and stay quiet on a known
  good one).

The list is data (`bin/preflight-gate-classes.json`); edit it for your own
codebase.

## Install

Requirements: macOS, `uv`, Python 3.11 or newer, and Git. Linux is not
tested.

```bash
git clone https://github.com/sdewell/learnings-md-system.git
cd learnings-md-system
bin/deploy.sh
```

`bin/deploy.sh` copies the core to `~/.local/share/learnings-md-system/`
(override with `LEARNINGS_CORE_HOME`). It does not edit your Claude Code
settings. To register the hooks, merge the `hooks` block from
`settings.snippet.json` into `~/.claude/settings.json`. For Codex, see the
plugin's README.

On a machine with no earlier state, the first deploy activates the central
store under `${XDG_STATE_HOME:-~/.local/state}/learnings-md-system/`
("Fresh neutral bootstrap activated"). Archives live there, outside your
repositories, so your checkouts do not change. A machine that already holds
state is left as it is. A machine with an older layout keeps it until you
migrate it yourself: `learn state import` prints the plan, and
`--apply --yes --offline-maintenance` performs it with every agent session
closed.

Each project gets its own archive, and only when you ask for one. Nothing
is enrolled automatically. Opt a project in once:

```bash
"${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn" corpus init --cwd /path/to/project --apply --yes
```

### Optional automation

With no settings file, nothing is automatic: no project is enrolled, no
snapshot is committed, nothing is pushed. To turn any of these on, create
`${XDG_CONFIG_HOME:-~/.config}/learnings-md-system/settings.json`:

```json
{
  "schema_version": 1,
  "auto_enroll": false,
  "auto_commit": false,
  "auto_push": false,
  "owned_remote_pattern": null,
  "snapshot_email": null
}
```

- `owned_remote_pattern`: a regular expression for Git remotes you own.
  For repositories with remotes, automatic enrollment requires a matching
  `origin`; pushes require a matching push URL. Explicitly enabled automatic
  enrollment also permits local-only repositories with no remotes.
- `snapshot_email`: the author for snapshot commits. Without it, snapshots
  are skipped with a visible reason; your Git email is never used in its
  place.
- `LEARNINGS_AUTO_COMMIT=0` and `LEARNINGS_AUTO_PUSH=0` turn an action off
  while they are set. No environment variable turns an action on.
- A settings file that does not parse, or has an unknown key, turns every
  automatic action off.

## Use

The CLI is installed in the core, not on your `PATH`:

```bash
LEARN="${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learn"
"$LEARN" search "file lock"     # has this been seen before?
"$LEARN" add locking "fcntl" "flock is advisory; every writer must take it"
"$LEARN" stats                  # entries, searches, repeats for this repo
```

Add the core's `bin/` to your `PATH` if you want to type `learn` directly.

## Status and limits

- Single user, single machine. Concurrent sessions on one machine are
  handled with file locks; multiple users are not a goal.
- The recurrence match is a conservative lexical cue: a contiguous diagnostic
  phrase must match an archived entry, and tied lessons cause abstention.
  Complete standard Python tracebacks use the final exception; other output
  uses its first non-empty line. Exception Groups and ambiguous traceback
  formats are skipped.
  It can still miss paraphrases or suggest a lesson with a different cause.
  Verify the cited lesson applies before routing it (see the design story).
- macOS only by test.

## License

See [LICENSE](LICENSE).
