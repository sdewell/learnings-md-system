# Runtime artifacts

> **What this is.** A field guide to the files the system writes outside the
> source tree. `bin/deploy.sh` copies this file to the root of the installed
> core. Edit the source copy; the next deploy replaces the installed one.

## Installed core

`${LEARNINGS_CORE_HOME:-~/.local/share/learnings-md-system}/`, written only
by `bin/deploy.sh`:

| Path | Contents |
|---|---|
| `bin/` | `learn` and the `learnings-*.sh` helpers |
| `hooks/` | The Claude Code hooks |
| `templates/` | The starting `LEARNINGS.md` template |
| `adapters/codex/codex-learnings-hook.py` | A stable copy of the Codex adapter, used if the packaged plugin path disappears |
| `backups/` | The previous copy of each file a deploy replaced |
| `ARTIFACTS.md` | This file |

Deploy also copies `skills/route-learning` and `skills/search-learnings` to
`~/.claude/skills/`. It never edits `~/.claude/settings.json`.

## Settings

`${XDG_CONFIG_HOME:-~/.config}/learnings-md-system/settings.json`, written
only by you (`LEARNINGS_SETTINGS_FILE` overrides the path). Absent means
every automatic action is off. Keys: `schema_version` (1), `auto_enroll`,
`auto_commit`, `auto_push` (booleans, default `false`),
`owned_remote_pattern`, and `snapshot_email` (default `null`). A file that
is not a plain regular file, is over 16 KB, or fails validation turns every
automatic action off. The README shows an example.

Deploy writes `install-settings-compatibility.json` to the installed core
under its lock, after validating the installation policy and before copying
runtime files. It records default-safe installation provenance, so an
interrupted fresh installation can retry; it is not a completion stamp.
An installation from before these defaults must have an explicit valid
settings file before deploy proceeds.

## State

`${XDG_STATE_HOME:-~/.local/state}/learnings-md-system/`. After a fresh
deploy, one `learn corpus init`, and one `learn add`, it holds:

```
activation.json                         names the active generation
cutover-deployment.json                 deploy's record of the bootstrap
deploy.lock                             serializes deploys
generations/<generation>/
  generation.json                       checked before activation is trusted
  import-manifest.json                  what the generation was built from
  projects/<key>/identity.json          which checkout owns this key
corpora/.epoch
corpora/<key>/
  active.json                           names the current revision
  projections/<id>.json                 projection records for the checkout
  revisions/rev-<id>/LEARNINGS.md       the archive itself
```

`<key>` is `<project name>-<16 hex digits of a hash>`. Lock files for
corpus writes live in the system temporary directory, not here.

The records depend on each other: `activation.json` is trusted only after
`generation.json` checks out, and an archive is found through its identity
record. **Back up the whole state directory**, not single parts of it.

## Beside the host's transcripts

For Claude Code, `~/.claude/projects/<project dir>/` also holds:

- `repeats.json` and `searches.json`, the counters `learn stats` reports;
- session markers, short-lived files that stop a hook from repeating
  itself within one session. `learn cleanup` removes stale ones; it is a
  dry run unless given `--apply --yes`.

## Older installations

A machine that ran an earlier version may still use the legacy layout:
global state under `~/.claude/learnings/` and `LEARNINGS*.md` files tracked
inside each repository. Deploy leaves such a machine alone.
`learn state status --mode-only` prints `neutral` or `legacy`;
`learn state import` plans the migration and
`learn state import --apply --yes --offline-maintenance` performs it. The
legacy tree is never deleted, and `learn state rollback --yes` reverses the
switch.
