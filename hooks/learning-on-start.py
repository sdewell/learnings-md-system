#!/usr/bin/env python3
"""SessionStart hook: deterministic orientation + notice delivery.

Design: docs/superpowers/specs/2026-08-03-deterministic-sessionstart-delivery-design.md

Replaces the race-prone PostToolUse relay for anything that depends only on
repo/disk state (orientation, cross-session notices) — those need zero
session context, so they're delivered here, at SessionStart, where there is
no transcript-flush race and no agent-identity puzzle. The structural spawns
that used to share hooks/learning-hook.py's PostToolUse cadence (review,
auto-split, reduce, cap-prune, currency) were all deleted in the 2026-09-06
trim PR (quiet corpus): writes now come only from `learn add` after a
resolved failure.

Pure injector: no background spawns, no locks, no corpus mutation. Builds ONE
`hookSpecificOutput.additionalContext`: orientation (mode-aware
FIRST_MESSAGE body), plus, in external mode, `_stale_portable_warning` (one
bounded `git ls-tree HEAD`) when git still tracks a root-level
`*-PORTABLE-LEARNINGS.md`. The prune/currency directive relay was deleted
2026-09-06 (quiet corpus). The review-retro FYI relay and the
project-rules projection were deleted 2026-09-07 together with their
producers (`learn review-retro`, `learn rules`): with corpora reduced to
archives, nothing writes those markers or `projects/<key>/rules.md`.

Standalone-file convention (no imports between hook scripts): every helper
below was duplicated from hooks/learning-hook.py rather than imported.
hooks/learning-hook.py was deleted in the 2026-09-06 trim PR (quiet
corpus), so this hook's `_is_index_mode` and `_first_message` are now
the sole surviving copies; `_is_index_mode` is
still parity-pinned, against learnings-write.sh's copy, in
tests/test_index_mode_parity.py. CENTRAL_STORE_NOTE and
`_stale_portable_warning` stay pinned against the Codex adapter (a separate
host) in tests/test_learning_on_start.py.
"""

import fcntl
import functools
import glob
import importlib.machinery
import importlib.util
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

# --- resolver / path-substitution chain (duplicated from
# hooks/learning-hook.py::_resolve_learnings_script and friends) ---


def _installed_code_paths() -> tuple[str, str]:
    adapter_bin = Path(__file__).resolve().parent.parent / "bin"
    if (adapter_bin / "deploy.sh").is_file():
        home = Path(os.environ.get("HOME") or Path.home())
        core = Path(os.environ.get("LEARNINGS_CORE_HOME") or home / ".local" / "share" / "learnings-md-system")
        core_bin = core / "bin"
        legacy_bin = home / ".claude" / "bin"
        # Installed code does not depend on which state generation is active.
        # Resolve helpers and CLI separately so a partial installation cannot
        # hide a working candidate in the other layout.
        helpers = core_bin if (core_bin / "learnings-write.sh").is_file() else legacy_bin / "learnings"
        cli = core_bin / "learn"
        if not _is_our_learn(str(cli)):
            cli = legacy_bin / "learn"
        return str(helpers), str(cli)
    helpers = adapter_bin if (adapter_bin / "learnings-write.sh").is_file() else adapter_bin / "learnings"
    return str(helpers), str(adapter_bin / "learn")


# Duplicated from hooks/learning-hook.py (standalone-file convention). A
# project-local pin of a state writer that predates the neutral state seam
# would write legacy paths, so with activation live an unbridged local copy
# falls through to the installed current copy; legacy mode and non-writer
# scripts keep plain local-first precedence. Contract pinned by
# tests/test_resolver_parity.py.
_STATE_WRITER_SCRIPTS = frozenset(
    {
        "learnings-write.sh",
        "learnings-retire.sh",
        "learnings-index.sh",
    }
)
_BRIDGE_SCAN_MAX_BYTES = 1 << 20
# Functional bridge marker: every bridged state writer defines its
# _load_state_module seam. A bare filename substring matched comments too
# (finding 4).
_BRIDGE_MARKER = b"def _load_state_module("


def _local_writer_needs_bridge_fallback(local_path: str, script_name: str) -> bool:
    if script_name not in _STATE_WRITER_SCRIPTS:
        return False
    if not _state_seam_active():
        return False
    try:
        with open(local_path, "rb") as fh:
            return _BRIDGE_MARKER not in fh.read(_BRIDGE_SCAN_MAX_BYTES)
    except OSError:
        return True  # unreadable local pin cannot prove it is bridged


@functools.cache
def _resolve_learnings_script(cwd: str, script_name: str) -> str | None:
    """Return the path to a `learnings-*.sh` script, or None if absent.

    Project-local `cwd/bin/{script_name}` takes precedence over the global
    `GLOBAL_BIN_DIR/{script_name}` — unless neutral mode is active and the
    local copy is an unbridged state writer (see above).
    """
    local = os.path.join(cwd, "bin", script_name)
    if os.path.isfile(local) and not _local_writer_needs_bridge_fallback(local, script_name):
        return local
    glb = os.path.join(GLOBAL_BIN_DIR, script_name)
    if os.path.isfile(glb):
        return glb
    return None


_BIN_SCRIPTS_IN_MESSAGES = (
    "learnings-write.sh",
    "learnings-index.sh",
)


_LEARN_SUBCOMMANDS_RE = re.compile(
    r"\blearn (add|search|index|status|stats|state|metrics|deploy|cleanup|corpus|migrate-ids)\b"
)


_LEARN_OWNERSHIP_MARKER = "learnings-system CLI"


def _is_our_learn(path: str | None) -> bool:
    """Check whether a candidate `learn` binary is our project's CLI (looks
    for the ownership marker in its header). False on any error/absence."""
    if path is None or not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(2048)
    except OSError:
        return False
    return _LEARN_OWNERSHIP_MARKER in head


def _resolve_learn_cli(cwd: str) -> str | None:
    """Resolve the user-facing `learn` CLI binary — OURS only. Project-local
    `cwd/bin/learn` first, then `GLOBAL_LEARN_CLI`. None when no owned
    candidate exists."""
    for candidate in (os.path.join(cwd, "bin", "learn"), GLOBAL_LEARN_CLI):
        if _is_our_learn(candidate):
            return candidate
    return None


def _inject_resolved_paths(text: str, cwd: str) -> str:
    """Replace `bin/learnings-X.sh` references AND bare `learn <subcmd>`
    references with their resolved absolute paths when needed."""
    if "bin/learnings-" in text:
        for name in _BIN_SCRIPTS_IN_MESSAGES:
            resolved = _resolve_learnings_script(cwd, name)
            if resolved is None or resolved == os.path.join(cwd, "bin", name):
                continue
            text = text.replace(f"bin/{name}", resolved)

    if _LEARN_SUBCOMMANDS_RE.search(text):
        path_learn = shutil.which("learn")
        if not _is_our_learn(path_learn):
            learn = _resolve_learn_cli(cwd)
            if learn is not None:
                text = _LEARN_SUBCOMMANDS_RE.sub(rf"{learn} \1", text)
    return text


# --- mode detection (duplicated from hooks/learning-hook.py::_is_index_mode
# and its supporting regexes/fingerprints — parity-pinned) ---

_THIN_INDEX_FINGERPRINT = (
    "Index of topic-specific learnings. Each subfile should stay under "
    "200 lines; split further with LEARNINGS-{topic}-{subtopic}.md "
    "if needed."
)
_RICH_INDEX_ENTRY = re.compile(r"^###\s+.+\s+→\s+LEARNINGS-.+\.md", re.MULTILINE)
_SUBFILE_LINK = re.compile(r"\[[^\]]*\]\((LEARNINGS-[^)]+\.md)\)")
_SUBTOPICS_LABEL = re.compile(r"(?m)^[ \t]*Subtopics:[ \t]*$")
_BULLET_LINE = re.compile(r"^\s*[-*]\s+")
_NESTED_CHILD_REF = re.compile(r"(?m)^\s*[-*]\s+.*→\s*(LEARNINGS-[^\s)]+--[^\s)]+\.md)")


def _subtopics_block_has_nested_child(content, exists) -> bool:
    """True if a `Subtopics:` label is directly followed by a bullet block
    that contains an arrow ref to an EXISTING nested child."""
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if not _SUBTOPICS_LABEL.match(line):
            continue
        for child in lines[i + 1 :]:
            if not _BULLET_LINE.match(child):
                break
            m = _NESTED_CHILD_REF.search(child)
            if m and exists(m.group(1)):
                return True
    return False


def _is_index_mode(learnings_path: str) -> bool:
    """True iff LEARNINGS.md is a RECOGNIZED index. Mirrors
    learnings-write.sh::_is_index_mode, learnings-auto-split.sh::
    is_recognized_index, and hooks/learning-hook.py::_is_index_mode."""
    learnings_dir = os.path.dirname(learnings_path) or "."
    try:
        with open(learnings_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return False
    if _THIN_INDEX_FINGERPRINT in content:
        return True
    if _RICH_INDEX_ENTRY.search(content):
        return True
    if any(os.path.exists(os.path.join(learnings_dir, m.group(1))) for m in _SUBFILE_LINK.finditer(content)):
        return True
    return _subtopics_block_has_nested_child(content, lambda ref: os.path.exists(os.path.join(learnings_dir, ref)))


# --- orientation body (duplicated from hooks/learning-hook.py's
# FIRST_MESSAGE_BODY_* / _first_message — this hook owns main-agent
# orientation now; a subagent has no SessionStart of its own, so its
# one-time orientation still fires from learning-hook.py's first
# PostToolUse) ---

# Appended (with `.format(corpus_root=...)`) to any agent-facing notice built
# in external-corpus mode, AFTER sanitizing that notice's local-filename
# imperatives — a trailing note contradicts a preceding "read LEARNINGS.md"
# sentence rather than fixing it. Byte-identical copy lives in
# hooks/learning-hook.py and the Codex adapter's codex-learnings-hook.py
# (parity-pinned by test) — this repo deliberately duplicates helpers between
# hook files rather than cross-importing.
CENTRAL_STORE_NOTE = (
    "Note: this project's corpus lives in the central store at {corpus_root} — "
    "not as files in this checkout. `learn` commands and the background workers "
    "read and write the central copy; absent local LEARNINGS files are expected "
    "and must not be created or restored."
)

FIRST_MESSAGE_BODY_MONOLITH = """\
This project has a LEARNINGS.md ({line_count} lines, monolith mode).

To consult before working on something gotcha-prone (locking, hooks, regex,
parsing, subprocess, validation), use the `search-learnings` skill or run
`learn search "<query>"` directly. Don't read the whole file up front —
pull what you need.

To add a new entry: `learn add <topic-slug> "<section>" "<entry>"` (or
`bin/learnings-write.sh ...` if the CLI isn't on PATH). Both are atomic
+ flock-safe against concurrent writes."""

FIRST_MESSAGE_BODY_INDEX = """\
This project has a LEARNINGS knowledge base ({subfile_count} topic \
subfiles, indexed in LEARNINGS.md).

To consult: use the `search-learnings` skill or run `learn search "<query>"` —
it ranks topic subfiles by relevance. Don't bulk-read every subfile up
front; pull just the relevant one on demand.

To add a new entry: read LEARNINGS.md FIRST (the index lists each topic with \
summary + keywords — that's your routing guide), then `learn add <topic-slug> \
"<section>" "<entry>"` (or `bin/learnings-write.sh ...` if the CLI isn't on \
PATH). Both route to the matching subfile; an unknown topic auto-creates a \
fresh LEARNINGS-<topic>.md. Keep subfiles under 40KB each (nothing trims \
them automatically; split a topic by hand when it grows past that). Prefer \
the closest existing topic over a new one: \
routing beats proliferation, and a new topic is only worth it when nothing \
existing fits."""


def _first_message(learnings_path: str, facts=None, project_root: str | None = None) -> str:
    """Build the orientation body: a short pointer, NOT a content dump.
    Auto-detects monolith vs index mode and path-substitutes bin/learn*
    references via `_inject_resolved_paths`."""
    cwd = project_root if facts is not None and project_root is not None else os.path.dirname(learnings_path) or "."
    if facts is not None:
        if facts.mode == "empty":
            body = "This project has a LEARNINGS corpus (currently empty)."
        elif facts.mode == "index":
            legacy_heading = (
                "This project has a LEARNINGS knowledge base ({subfile_count} topic subfiles, indexed in LEARNINGS.md)."
            )
            body = FIRST_MESSAGE_BODY_INDEX.replace(
                legacy_heading,
                "This project has a LEARNINGS corpus ({subfile_count} topic subfiles, index mode).",
            ).replace("read LEARNINGS.md FIRST", "read the corpus index FIRST")
            body = body.format(subfile_count=facts.topic_count)
        else:
            body = FIRST_MESSAGE_BODY_MONOLITH.replace(
                "This project has a LEARNINGS.md ({line_count} lines, monolith mode).",
                "This project has a LEARNINGS corpus ({line_count} lines, monolith mode).",
            ).format(line_count=facts.line_count)
        corpus_root = os.path.dirname(learnings_path) or "."
        body += "\n\n" + CENTRAL_STORE_NOTE.format(corpus_root=corpus_root)
        return _inject_resolved_paths(body, cwd)
    if _is_index_mode(learnings_path):
        subfiles = glob.glob(os.path.join(cwd, "LEARNINGS-*.md"))
        body = FIRST_MESSAGE_BODY_INDEX.format(subfile_count=len(subfiles))
    else:
        try:
            with open(learnings_path, encoding="utf-8") as f:
                line_count = sum(1 for _ in f)
        except OSError:
            line_count = 0
        body = FIRST_MESSAGE_BODY_MONOLITH.format(line_count=line_count)
    # Runtime adds <system-reminder> framing automatically — emit only the
    # body content, not literal tags.
    return _inject_resolved_paths(body, cwd)


# --- turnstate store (duplicated from hooks/learning-hook.py) ---

TURNSTATE_SUFFIX = ".turnstate.json"


def _turnstate_paths(transcript_dir: str, session_id: str) -> tuple[str, str]:
    data_path = os.path.join(transcript_dir, session_id + TURNSTATE_SUFFIX)
    lock_path = os.path.join(transcript_dir, session_id + ".turnstate.lock")
    return data_path, lock_path


def _empty_turnstate() -> dict:
    return {"agents": {}, "surfaced": []}


def _parse_turnstate(raw: str) -> dict:
    """Corrupt, partial (wrong-shaped), or non-dict JSON all reset to the
    empty schema rather than raising or propagating a malformed state."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _empty_turnstate()
    if not isinstance(data, dict):
        return _empty_turnstate()
    if not isinstance(data.get("agents"), dict) or not isinstance(data.get("surfaced"), list):
        return _empty_turnstate()
    return data


def load_turnstate(transcript_dir: str, session_id: str) -> dict:
    """Read the persisted turnstate. Missing file or malformed JSON both
    return the empty schema without writing anything."""
    data_path, _ = _turnstate_paths(transcript_dir, session_id)
    try:
        with open(data_path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return _empty_turnstate()
    return _parse_turnstate(raw)


def mutate_turnstate(transcript_dir: str, session_id: str, fn: Callable[[dict], None]) -> dict:
    """Read-modify-write the persisted turnstate under an exclusive flock on
    a SIBLING lock file — never the data file itself (flock pins to an
    inode; os.replace swaps it). fn receives the parsed state dict and
    mutates it in place."""
    data_path, lock_path = _turnstate_paths(transcript_dir, session_id)
    os.makedirs(transcript_dir, exist_ok=True)
    with open(lock_path, "a+") as lock_fd:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            try:
                with open(data_path, encoding="utf-8") as f:
                    raw = f.read()
            except OSError:
                raw = ""
            state = _parse_turnstate(raw)
            fn(state)
            tmp_path = f"{data_path}.tmp.{os.getpid()}"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(state))
            os.replace(tmp_path, data_path)
            return state
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)


def _resolve_corpus_location(cwd: str, transcript_dir: str, session_id: str):
    """Resolve and retain only a validated positive external record."""
    module = _load_optional_state_module()
    if module is None:
        return None
    cached = load_turnstate(transcript_dir, session_id).get("external_corpus_cache")
    location, replacement = module.resolve_project_corpus_cached(cwd, cached)

    def _store(state: dict) -> None:
        if replacement is not None:
            state["external_corpus_cache"] = replacement
        else:
            state.pop("external_corpus_cache", None)

    if replacement is not None or cached is not None:
        mutate_turnstate(transcript_dir, session_id, _store)
    return location


def _resolve_root(cwd: str) -> str:
    """Git toplevel from `cwd`, falling back to `cwd` itself when not a git
    repo (or git is unavailable). Used for the opt-in check — orientation
    has never required git before, so a plain, non-repo directory with a
    LEARNINGS.md still qualifies."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return cwd


_OPTIONAL_STATE_MODULE_UNSET = object()
_optional_state_module = _OPTIONAL_STATE_MODULE_UNSET


def _load_optional_state_module():
    """Load state for an optional notice without blocking SessionStart."""
    global _optional_state_module
    if _optional_state_module is not _OPTIONAL_STATE_MODULE_UNSET:
        return _optional_state_module
    here = Path(__file__).resolve()
    home = Path(os.environ.get("HOME") or Path.home())
    configured_core = os.environ.get("LEARNINGS_CORE_HOME")
    core = Path(configured_core).expanduser() if configured_core else home / ".local" / "share" / "learnings-md-system"
    candidates = (
        here.parent.parent / "bin" / "learnings-state.sh",
        core / "bin" / "learnings-state.sh",
        here.parent.parent / "bin" / "learnings" / "learnings-state.sh",
        home / ".claude" / "bin" / "learnings" / "learnings-state.sh",
    )
    for path in candidates:
        if not path.is_file():
            continue
        name = "learnings_state_start_notice"
        loader = importlib.machinery.SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        if spec is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        previous = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None)
            continue
        finally:
            sys.dont_write_bytecode = previous
        _optional_state_module = module
        return module
    _optional_state_module = None
    return _optional_state_module


def _state_seam_active() -> bool:
    module = _load_optional_state_module()
    if module is None:
        return False
    try:
        return module.activation_status().state == module.ACTIVATION_VALID
    except Exception:
        return False


GLOBAL_BIN_DIR, GLOBAL_LEARN_CLI = _installed_code_paths()


# --- fd-bound read-WITHOUT-delete, used by the Start-here block read ---


def _read_regular_body(marker: str, *, limit: int = 64 * 1024) -> tuple[bool, str | None]:
    """Return whether a file exists and its safely read body, if any."""
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(marker, flags)
    except FileNotFoundError:
        return False, None
    except OSError:
        return True, None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            return True, None
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
    except OSError:
        return True, None
    finally:
        os.close(fd)
    if (
        len(data) > limit
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(data) != after.st_size
    ):
        return True, None
    try:
        return True, data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return True, None


def _emit(parts: list[str]) -> None:
    """Print the combined SessionStart context, or nothing when `parts` is
    empty -- stdout stays strict-JSON-or-silent on every path."""
    if not parts:
        return
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "\n\n---\n\n".join(parts),
                }
            }
        )
    )


# Duplicated in the Codex adapter (standalone-file convention); pinned by
# tests/test_learning_on_start.py::test_stale_portable_warning_matches_codex_adapter.
STALE_PORTABLE_SUFFIX = "-PORTABLE-LEARNINGS.md"
STALE_PORTABLE_NOTE = (
    "Stale portable LEARNINGS copy: this project's corpus is external, but git "
    "still tracks {names}. Nothing reads it. Remove it on a branch with "
    "`git -C {root} rm -- {names_args}` and land the change through a PR."
)


def _stale_portable_warning(project_root: str) -> str | None:
    """Warn when an external-mode project still tracks a root-level
    `*-PORTABLE-LEARNINGS.md` at HEAD (ls-tree, not ls-files: a file deleted
    in the working tree but not yet committed must still be reported).
    Any failure returns None — a notice must never break session start."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        proc = subprocess.run(
            ["git", "ls-tree", "--name-only", "HEAD"],
            cwd=project_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    names = sorted(line for line in proc.stdout.splitlines() if line.endswith(STALE_PORTABLE_SUFFIX))
    if not names:
        return None
    # `-C <root>`: ls-tree names are root-relative, and a session may start in a subdirectory.
    return STALE_PORTABLE_NOTE.format(
        names=", ".join(names),
        names_args=" ".join(shlex.quote(name) for name in names),
        root=shlex.quote(project_root),
    )


def _session_class() -> str:
    """LEARNINGS_SESSION_CLASS: interactive (default) | automation | harness.
    Unknown values fall open to interactive with one stderr warning — this
    gate must never be able to block a session. Duplicated per-file by the
    standalone-hook-script convention (see CLAUDE.md)."""
    value = os.environ.get("LEARNINGS_SESSION_CLASS")
    if not value or value in ("interactive", "automation", "harness"):
        return value or "interactive"
    print(
        f"learnings: unknown LEARNINGS_SESSION_CLASS={value}, treating as interactive",
        file=sys.stderr,
    )
    return "interactive"


def _drain_stdin() -> None:
    """Consume the payload the runtime piped in before an early exit, so the
    host's write never sees a closed pipe (harness fast path only)."""
    try:
        sys.stdin.read()
    except (OSError, ValueError):
        pass


def main() -> None:
    if _session_class() == "harness":
        _drain_stdin()
        return
    try:
        input_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, ValueError, TypeError):
        return
    if not isinstance(input_data, dict):
        return

    session_id = input_data.get("session_id")
    transcript_path = input_data.get("transcript_path")
    cwd = input_data.get("cwd")
    if not (session_id and transcript_path and cwd):
        return
    source = input_data.get("source")

    if os.environ.get("LEARNINGS_REVIEW_NESTED") == "1":
        return

    parts: list[str] = []

    # Quiet corpus Stage 1: the PostToolUse hook that re-oriented after a
    # compact is unregistered, so a compact session gets the same
    # orientation as a fresh one (`source` no longer short-circuits).
    del source

    transcript_dir = os.path.dirname(transcript_path)
    root = _resolve_root(cwd)
    location = None
    try:
        location = _resolve_corpus_location(cwd, transcript_dir, session_id)
        if location is not None and location.mode == "external":
            index_path = str(location.corpus_root / "LEARNINGS.md")
            facts = _load_optional_state_module().read_corpus_orientation_facts(location)
            parts.append(_first_message(index_path, facts, str(location.project_root)))
            stale_portable = _stale_portable_warning(str(location.project_root))
            if stale_portable:
                parts.append(stale_portable)
        else:
            learnings_path = os.path.join(root, "LEARNINGS.md")
            if os.path.isfile(learnings_path):
                parts.append(_first_message(learnings_path))
    except Exception as exc:
        module = _load_optional_state_module()
        # Corpus authority damage degrades to silence, never to a crash
        # that would surface as a hook error at session start.
        if module is None or not isinstance(exc, module.CorpusResolutionError):
            raise

    _emit(parts)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 — a broken injector must never block session start
        # main() prints its JSON as the very last statement, so any
        # unexpected exception (e.g. an OSError from the turnstate mutate
        # path) is caught before anything reaches stdout. The traceback
        # still reaches /tmp/claude-hooks-error.log via the registration's
        # stderr redirect, for debugging.
        traceback.print_exc()
