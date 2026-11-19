#!/usr/bin/env python3
"""PostToolUseFailure hook: quiet on expected non-zero exits, remembers repeats.

Fires only if LEARNINGS.md exists in cwd (or an external corpus resolves).
Quiet corpus Stage 1 §3: most failures the hook used to nag about are the
caller's own expected non-zero exit (a `test` probe, `ls` checking for a
path, an rtk artifact) — those are silenced by a fixed list of predicates,
never a heuristic. A REAL failure gets a recurrence check: if the corpus
already has an entry with a matching ordered diagnostic phrase, the nudge
points at that entry (and counts the repeat in `repeats.json`) instead of
asking for a fresh one.

Main-agent-only: a payload carrying `agent_id` comes from a subagent (the same
identity rule `learning-hook.py` uses). Parallel implementation workers each
obeyed the reminder for the same failure, writing near-duplicate lessons the
maintenance lanes then had to fold (2026-09-03: one lesson five times in
fifteen minutes). The main agent sees the worker's result and records once.

The generic no-hit nudge prints once per session, keyed by
`{session_id}.failure-nudge-shown` in the project marker dir; the
"Recorded before" recurrence message is never throttled.
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

NO_HIT_MESSAGE = (
    'After you fix it: learn add <topic> "<section>" "<root cause + what '
    'works>" — one line to the archive, nothing more on first contact. Skip '
    "if this was a probe or an expected non-zero exit."
)

# Second contact: the archive line exists and the mistake happened again.
# This is the moment to route it (hook/test, CLAUDE.md, repo skill, or
# leave it); the route-learning skill holds the rubric.
RECORDED_BEFORE_SUFFIX = (
    "Second contact: say in one line why it was not applied, then route it "
    "with the route-learning skill — a hook or test if a check can prevent "
    "it, a CLAUDE.md line if it must shape every change, a repo skill if it "
    "is a procedure; otherwise leave it in the archive."
)

# Once-per-session throttle marker for the generic (no-hit) nudge only.
NUDGE_MARKER_SUFFIX = ".failure-nudge-shown"

_GREP_ENTRYPOINTS = frozenset({"grep", "rg", "ripgrep", "egrep", "fgrep"})
# `diff`/`cmp` exit 1 = "the inputs differ", the answer the caller asked for;
# exit 2 = trouble (missing file, bad flag) and still fires. Added 2026-09-05
# after a `diff -rq` comparing two review directories nagged for working.
_DIFF_ENTRYPOINTS = frozenset({"diff", "cmp"})
_COMPOUND_CHARS = ("&&", "||", "|", ";", "\n", "$(", "`")
_QUIET_FLAGS = frozenset({"-q", "--quiet"})
_CONTEXT_FLAGS = frozenset({"-A", "-B", "-C", "--after-context", "--before-context", "--context"})

# Stage 1 §3 additions to the silent list.
_TEST_ENTRYPOINTS = frozenset({"test", "["})
_NO_SUCH_FILE_ENTRYPOINTS = frozenset({"ls", "stat", "cat", "head", "tail", "sed", "wc", "find"})
_NO_SUCH_FILE_TEXT = "No such file or directory"

_EXIT_CODE_RE = re.compile(r"^Exit code (\d+)")


def _parse_exit(error: str) -> tuple[int | None, str]:
    """(exit_code, body) from the hook's `Exit code N\\n<body>` error text.
    exit_code is None when the text doesn't start with that preamble."""
    m = _EXIT_CODE_RE.match(error)
    if not m:
        return None, error
    return int(m.group(1)), error[m.end() :].lstrip("\n")


def _command_parts(command: str) -> list[str]:
    return command.strip().split()


def _first_entrypoint(parts: list[str]) -> str | None:
    """The command's real entrypoint, stripped of an rtk proxy prefix and of
    any directory (`/bin/ls` is `ls`: agents type the full path because `ls`
    is aliased to eza on this machine)."""
    if not parts:
        return None
    entry = os.path.basename(parts[0])
    if entry == "rtk" and len(parts) >= 2:
        entry = os.path.basename(parts[1])
    return entry


def _resolved_location(cwd: str):
    here = Path(__file__).resolve()
    home = Path(os.environ.get("HOME") or Path.home())
    core = Path(os.environ.get("LEARNINGS_CORE_HOME") or home / ".local" / "share" / "learnings-md-system")
    for path in (
        here.parent.parent / "bin" / "learnings-state.sh",
        core / "bin" / "learnings-state.sh",
        here.parent.parent / "bin" / "learnings" / "learnings-state.sh",
        home / ".claude" / "bin" / "learnings" / "learnings-state.sh",
    ):
        if not path.is_file():
            continue
        loader = importlib.machinery.SourceFileLoader("learnings_state_failure", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        if spec is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[loader.name] = module
        try:
            loader.exec_module(module)
        except Exception:
            sys.modules.pop(loader.name, None)
            continue
        return module.resolve_project_corpus_cached(cwd)[0]
    return None


def _is_benign_grep_no_match(tool_name: str, command: str, error: str) -> bool:
    """`grep` exit 1 = 'no match', which is a valid answer, not a failure.
    Suppress only when ALL of: tool_name==Bash, exit 1, single grep-family
    entrypoint, no compound operators, no -q/--quiet (assertion-style), no
    -A/-B/-C context flags (can echo file content as last line), and body is
    either empty OR its last line is an rtk '0 matches for ...' summary.
    Multi-line bodies are accepted when preceding lines are per-file counts.
    Compound commands and unrecognized output fall through to firing."""
    if tool_name != "Bash":
        return False
    if not error.startswith("Exit code 1\n") and error.strip() != "Exit code 1":
        return False
    if any(ch in command for ch in _COMPOUND_CHARS):
        return False
    parts = _command_parts(command)
    entry = _first_entrypoint(parts)
    if entry is None:
        return False
    if entry in _DIFF_ENTRYPOINTS:
        return True
    if entry not in _GREP_ENTRYPOINTS:
        return False
    if any(flag in parts for flag in _QUIET_FLAGS):
        return False
    if any(flag in parts for flag in _CONTEXT_FLAGS) or any(
        p[:2] in {"-A", "-B", "-C"} and p[2:].isdigit() for p in parts
    ):
        return False
    body = error[len("Exit code 1") :].lstrip("\n").rstrip()
    if body == "":
        return True
    # rtk multi-file greps end with "0 matches for ..." as the last line,
    # preceded by per-file counts. Check last line so both single-file and
    # multi-file summaries suppress, while trailing diagnostics still fire.
    last_line = body.splitlines()[-1]
    return last_line.startswith("0 matches for ")


def _is_benign_test_false(tool_name: str, command: str, error: str) -> bool:
    """`test`/`[` exit 1 = the condition was false, the caller's own probe
    answer — not a tool failure. Single command only (no compound chars): a
    compound command's exit 1 could come from any stage, not necessarily
    the test."""
    if tool_name != "Bash":
        return False
    exit_code, _body = _parse_exit(error)
    if exit_code != 1:
        return False
    if any(ch in command for ch in _COMPOUND_CHARS):
        return False
    return _first_entrypoint(_command_parts(command)) in _TEST_ENTRYPOINTS


def _is_benign_missing_path_probe(tool_name: str, command: str, error: str) -> bool:
    """exit 1 or 2 from `ls`/`stat`/`cat`/`head`/`tail`/`sed`/`wc`/`find`
    whose error body is a "No such file or directory" probe — the caller
    checking whether a path exists, not a tool failure. Single command only
    (no compound chars): a compound command's exit could come from any
    stage, not necessarily the missing-path check (e.g. `cat missing.json |
    jq .` — jq's own exit, not cat's, decides the code here, and the "No
    such file" text is cat's stderr riding along, not the actual verdict)."""
    if tool_name != "Bash":
        return False
    exit_code, body = _parse_exit(error)
    if exit_code not in (1, 2):
        return False
    if any(ch in command for ch in _COMPOUND_CHARS):
        return False
    if _first_entrypoint(_command_parts(command)) not in _NO_SUCH_FILE_ENTRYPOINTS:
        return False
    return _NO_SUCH_FILE_TEXT in body


def _is_benign_wc_summary_artifact(tool_name: str, command: str, error: str) -> bool:
    """`wc` exit 1 whose body's last non-empty line is a plain count is an
    rtk compression artifact (the real count reached stdout; only the exit
    code reads 1)."""
    if tool_name != "Bash":
        return False
    exit_code, body = _parse_exit(error)
    if exit_code != 1:
        return False
    if _first_entrypoint(_command_parts(command)) != "wc":
        return False
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return False
    return bool(re.match(r"^\s*\d+", lines[-1]))


def _is_benign_git_usage_exit(tool_name: str, command: str, error: str) -> bool:
    """`git` exit 129 is a usage error (bad flag/arg combination) the caller
    already sees spelled out in git's own usage text on stderr — not
    something a LEARNINGS entry adds value to. `git check-ignore` exit 1
    means "not ignored", the caller's own probe answer, mirroring
    `_is_benign_test_false`. Single command only (no compound chars): a
    compound command's exit could come from any stage, not necessarily
    git's. The 129 leg also requires git's own `usage: git` text in the
    body: a git alias (`!exit 129`) or a hook script can return 129 with
    no usage text, and that is a real failure."""
    if tool_name != "Bash":
        return False
    exit_code, body = _parse_exit(error)
    if exit_code not in (129, 1):
        return False
    if any(ch in command for ch in _COMPOUND_CHARS):
        return False
    parts = _command_parts(command)
    git_index = 1 if parts[:1] == ["rtk"] else 0
    if len(parts) <= git_index or os.path.basename(parts[git_index]) != "git":
        return False
    if exit_code == 129:
        return "usage: git" in body
    subcommand = parts[git_index + 1] if len(parts) > git_index + 1 else None
    return subcommand == "check-ignore"


_USAGE_PREFIX = "usage:"


def _is_benign_usage_error(tool_name: str, command: str, error: str) -> bool:
    """Exit 2 whose first body line opens with `usage:` is an argparse-style
    usage error (bad flag, missing argument) the caller already sees spelled
    out — the generic sibling of `_is_benign_git_usage_exit`'s 129 leg, for
    the `learn` CLI and every other Python tool. Single command only (no
    compound chars). Silencing it also keeps the recurrence check from
    token-matching the tool's own name words (`learn corpus ...`) against
    unrelated entries that mention the same tool: on 2026-10-22 a flagless
    `learn corpus status` was reported as a repeat of a `learn corpus
    retire` lesson and counted in repeats.json."""
    if tool_name != "Bash":
        return False
    exit_code, body = _parse_exit(error)
    if exit_code != 2:
        return False
    if any(ch in command for ch in _COMPOUND_CHARS):
        return False
    first_line = next((ln for ln in body.splitlines() if ln.strip()), "")
    return first_line.lstrip().lower().startswith(_USAGE_PREFIX)


_SILENT_PREDICATES = (
    _is_benign_grep_no_match,
    _is_benign_test_false,
    _is_benign_missing_path_probe,
    _is_benign_wc_summary_artifact,
    _is_benign_git_usage_exit,
    _is_benign_usage_error,
)


def _is_silent_failure(tool_name: str, command: str, error: str) -> bool:
    """True when any silent-list predicate matches — an expected non-zero
    exit, not a real failure."""
    return any(predicate(tool_name, command, error) for predicate in _SILENT_PREDICATES)


# --- recurrence check (Stage 1 §3): does the corpus already have this? -----

_STOPWORDS = frozenset(
    {"the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "not", "with", "from", "this", "that", "file"}
)
# These describe failure in general, rather than the particular diagnostic.
_DIAGNOSTIC_BOILERPLATE = frozenset(
    {
        "error",
        "errors",
        "warning",
        "fatal",
        "failed",
        "failure",
        "cannot",
        "could",
        "unable",
        "exception",
        "read",
        "find",
    }
)
_CORPUS_READ_CAP_BYTES = 1 << 20  # 1 MiB
_ENTRY_ID_TAG_RE = re.compile(r"<!--\s*id:([0-9a-z]{6})(?:\s+@\S+\s+\S+)?\s*-->\s*$")
# Full trailing-tag pattern (all shapes) — duplicated from
# bin/learnings-write.sh::_TAG_RE (standalone-hook-script convention).
_TAG_RE = re.compile(r"\s*<!--\s*(?:id:[0-9a-z]{6}(?:\s+@\S+\s+\S+)?|@\S+\s+\S+)\s*-->\s*$")


def _normalized_terms(text: str) -> list[str]:
    """Lowercase terms, keeping paths and dotted identifiers opaque."""
    return re.findall(r"(?:[~./\\]+)?[\w-]+(?:[./\\][\w.-]*\w)*", text.lower())


def _standard_traceback_diagnostic(lines: list[str]) -> str | None:
    """Accept complete standard tracebacks, never an arbitrary later line.

    Frame/source lines are structural evidence only. Notes, multiline messages,
    exception groups and incomplete frames remain ambiguous and are skipped.
    """
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    i = 0
    while i < len(lines) and lines[i] == "Traceback (most recent call last):":
        i += 1
        frames = 0
        while i < len(lines) and re.fullmatch(r'  File ".+", line [0-9]+(?:, in .+)?', lines[i]):
            frames += 1
            i += 1
            while i < len(lines) and lines[i].startswith("    "):
                i += 1
            if i < len(lines) and re.fullmatch(r"  \[Previous line repeated [1-9][0-9]* more times?\]", lines[i]):
                i += 1
        if not frames or i >= len(lines) or not re.fullmatch(r"(?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*(?::.*)?", lines[i]):
            return None
        diagnostic = lines[i]
        i += 1
        if i == len(lines):
            return diagnostic
        # Python renders a blank line on each side of either chain separator.
        if i + 2 >= len(lines) or lines[i] or lines[i + 2]:
            return None
        if lines[i + 1] not in (
            "During handling of the above exception, another exception occurred:",
            "The above exception was the direct cause of the following exception:",
        ):
            return None
        i += 3
    return None


def _diagnostic_terms(error: str) -> list[str]:
    """First diagnostic or a complete standard traceback's final exception."""
    _exit_code, body = _parse_exit(error)
    lines = body.splitlines()
    first = next((i for i, line in enumerate(lines) if line.strip()), len(lines))
    lines = lines[first:]
    first_line = lines[0] if lines else ""
    if first_line == "Traceback (most recent call last):":
        diagnostic = _standard_traceback_diagnostic(lines)
        return _normalized_terms(diagnostic) if diagnostic is not None else []
    # Decorated/exception-group headers do not identify a particular failure.
    if first_line.rstrip().endswith("Traceback (most recent call last):"):
        return []
    return _normalized_terms(first_line)


def _longest_diagnostic_span(diagnostic: list[str], entry: list[str]) -> int:
    """Longest shared contiguous phrase with three distinct meaningful terms.

    Keep short words, stopwords, failure boilerplate and paths in the sequence:
    dropping them would join words that were never adjacent. They do not satisfy
    the meaningful floor.
    Each cell counts the matching suffix ending at this pair of terms.
    """
    previous = [0] * (len(entry) + 1)
    best = 0
    for i, term in enumerate(diagnostic):
        current = [0] * (len(entry) + 1)
        for j, entry_term in enumerate(entry):
            if term != entry_term:
                continue
            size = current[j + 1] = previous[j] + 1
            if size > best:
                meaningful = {
                    word
                    for word in diagnostic[i + 1 - size : i + 1]
                    if len(word) >= 4
                    and not word.isdigit()
                    and word not in _STOPWORDS
                    and word not in _DIAGNOSTIC_BOILERPLATE
                    and "/" not in word
                    and "\\" not in word
                }
                if len(meaningful) >= 3:
                    best = size
        previous = current
    return best


def _safe_read_corpus_file(path: Path) -> str | None:
    """fd-bound read (O_NOFOLLOW, regular single-link file, 1 MiB cap) —
    duplicated per the standalone-hook-script convention. None on anything
    unsafe or unreadable — a skip, never a raise."""
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > _CORPUS_READ_CAP_BYTES:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            raw = f.read(_CORPUS_READ_CAP_BYTES + 1)
        if len(raw) > _CORPUS_READ_CAP_BYTES:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        if fd != -1:
            os.close(fd)


def _corpus_entry_lines(corpus_root: Path) -> list[str]:
    """`- `-prefixed lines from every `LEARNINGS-*.md` under corpus_root;
    falls back to `LEARNINGS.md` itself when no subfiles exist (a monolith
    corpus — 28 of 57 central-store corpora have no `LEARNINGS-*.md` at
    all, so a recurrence check that only scanned subfiles would silently
    never fire for them)."""
    lines: list[str] = []
    try:
        paths = sorted(corpus_root.glob("LEARNINGS-*.md"))
    except OSError:
        return lines
    if not paths:
        paths = [corpus_root / "LEARNINGS.md"]
    for path in paths:
        text = _safe_read_corpus_file(path)
        if text is None:
            continue
        lines.extend(line for line in text.split("\n") if line.startswith("- "))
    return lines


def _find_recorded_entry(corpus_root: Path, diagnostic: list[str]) -> tuple[str, str] | None:
    """Entry with the longest matching diagnostic phrase, excluding tags.

    Different entry ids tied for the longest span are ambiguous: return None.
    Otherwise return (entry text without its trailing tag, cut to 300 chars;
    entry id).
    """
    if not diagnostic:
        return None
    best_score = 0
    best_hits: dict[str, str] = {}
    for line in _corpus_entry_lines(corpus_root):
        tag = _ENTRY_ID_TAG_RE.search(line)
        if not tag:
            continue
        body = _TAG_RE.sub("", line[2:]).rstrip()
        score = _longest_diagnostic_span(diagnostic, _normalized_terms(body))
        if score > best_score:
            best_score = score
            best_hits.clear()
        if score and score == best_score:
            best_hits.setdefault(tag.group(1), body[:300])
    if len(best_hits) != 1:
        return None
    entry_id, entry_text = next(iter(best_hits.items()))
    return entry_text, entry_id


def _project_marker_dir(cwd: str) -> str:
    """`~/.claude/projects/<sanitized cwd>/` — the SAME sanitize bin/learn's
    own `_default_transcript_dir` uses (direct cwd, no git toplevel walk),
    so `learn stats`'s read of repeats.json lands in the directory this
    hook writes to. Deliberately no git-toplevel walk: repeats.json is
    keyed by the literal cwd both sides already agree on."""
    resolved = str(Path(cwd).resolve())
    sanitized = re.sub(r"[^A-Za-z0-9]", "-", resolved)
    return str(Path.home() / ".claude" / "projects" / sanitized)


def _nudge_already_shown(cwd: str, session_id: str) -> bool:
    """Touch-before-action cooldown: the marker file IS the throttle, not a
    record of a completed action. True if the generic no-hit nudge already
    printed for this session_id; otherwise creates the marker (so the next
    call in the same session sees it) and returns False. An existing-file
    race (two calls landing at once) counts as "already shown" either way.
    Fails open on any OSError — a throttle must never hide the nudge because
    of a disk error, so a create failure returns False and the nudge still
    prints (just without the marker recorded, so it may reprint next time)."""
    marker_dir = _project_marker_dir(cwd)
    marker_path = os.path.join(marker_dir, f"{session_id}{NUDGE_MARKER_SUFFIX}")
    if os.path.exists(marker_path):
        return True
    try:
        os.makedirs(marker_dir, exist_ok=True)
        fd = os.open(marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        return True
    except OSError:
        return False
    return False


def _increment_repeat(cwd: str, entry_id: str) -> None:
    """Atomic read-modify-write (temp-then-rename) of repeats.json. A read
    failure or malformed file is treated as empty and overwritten — best
    effort, never blocks the nudge itself."""
    marker_dir = _project_marker_dir(cwd)
    path = os.path.join(marker_dir, "repeats.json")
    try:
        os.makedirs(marker_dir, exist_ok=True)
    except OSError:
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.loads(f.read())
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        data = {}
    current = data.get(entry_id)
    data[entry_id] = (current + 1) if isinstance(current, int) else 1
    tmp_path = f"{path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(data))
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


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
    except (json.JSONDecodeError, ValueError):
        return
    if input_data.get("agent_id"):
        return
    cwd: str = input_data.get("cwd") or ""
    if not cwd:
        return
    try:
        location = _resolved_location(cwd)
    except Exception:
        return
    if location is None and not os.path.isfile(os.path.join(cwd, "LEARNINGS.md")):
        return
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input") or {}
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    error = input_data.get("error", "") or ""
    if _is_silent_failure(tool_name, command, error):
        return

    # External mode: scan the resolved corpus root. Legacy (no catalog
    # entry, a plain LEARNINGS.md in cwd): scan cwd itself.
    corpus_root = Path(location.corpus_root) if location is not None and location.mode == "external" else Path(cwd)
    diagnostic = _diagnostic_terms(error)
    hit = _find_recorded_entry(corpus_root, diagnostic)
    if hit is not None:
        entry_text, entry_id = hit
        message = f"Recorded before: {entry_text} [{entry_id}]. {RECORDED_BEFORE_SUFFIX}"
        try:
            _increment_repeat(cwd, entry_id)
        except OSError:
            pass
    else:
        session_id = input_data.get("session_id") or ""
        if session_id and _nudge_already_shown(cwd, session_id):
            return
        message = NO_HIT_MESSAGE

    # Runtime schema rejects hookSpecificOutput for PostToolUseFailure
    # (only PreToolUse/UserPromptSubmit/PostToolUse/PostToolBatch accepted).
    # `decision: "block"` + top-level `reason` is the working channel.
    print(json.dumps({"decision": "block", "reason": message}))


if __name__ == "__main__":
    main()
