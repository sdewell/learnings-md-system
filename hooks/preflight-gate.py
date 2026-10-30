"""PreToolUse advisory gate: surface the pre-flight root-cause classes when a
PR is about to be created.

Fires on Bash commands matching `gh pr create` — one firing per review unit
("one branch = one PR = one review unit"), which is why the trigger is PR
creation and not `git commit` (frequent WIP commits would make the gate noise,
and noisy gates get ignored). Hook-authored commits (SessionStart snapshots
etc.) call git via subprocess, not the Bash tool, and never run `gh pr create`
— so the never-fire-on-machine-commits constraint holds structurally.

The classes live in the installed core's bin directory
(`preflight-gate-classes.json`). `learn review-retro`, which once read the
same file, was deleted 2026-09-07; this gate is now its only reader.

FAIL OPEN, ALWAYS: this sits in the interactive path of every Bash call. A
missing, corrupt, oversized, or wrong-shape data file — or any other error —
degrades to silence (exit 0, no output), never to a block. Advisory only: it
raises the questions; it does not inspect the diff or adjudicate.

Composes with block-git-add-sweep.sh by chaining: both are PreToolUse/Bash
hooks with disjoint command patterns (`git add` sweeps vs `gh pr create`), so
on any given command at most one has something to say.

No once-per-session marker on purpose: firings are naturally rare (once per
PR), and a re-fire after fixing findings and re-running `gh pr create` is the
checklist working as intended — there is no marker lifecycle to get wrong.
"""

import json
import os
import re
import stat
import sys
from pathlib import Path

# Matches `gh pr create` at a command boundary (start, or after a separator /
# subshell open), tolerating env-var or wrapper prefixes earlier in the string
# and a path-qualified binary (/opt/homebrew/bin/gh). An occasional false
# positive (the phrase appearing as prose — a quoted string, a commit message
# mentioning it) is acceptable — the gate is advisory.
GH_PR_CREATE_RE = re.compile(r"(?:^|[\s;&|(])(?:\S*/)?gh\s+pr\s+create\b")

_ADAPTER_BIN = Path(__file__).resolve().parent.parent / "bin"
if (_ADAPTER_BIN / "deploy.sh").is_file():
    _ADAPTER_BIN = Path.home() / ".claude" / "bin"
CLASSES_PATH = (
    _ADAPTER_BIN / "preflight-gate-classes.json"
    if (_ADAPTER_BIN / "preflight-gate-classes.json").is_file()
    else _ADAPTER_BIN / "learnings" / "preflight-gate-classes.json"
)
BYTE_CAP = 65536  # ~30x the real file; anything bigger is not ours

MESSAGE_HEADER = "Pre-flight gate (this command creates a PR)."
MESSAGE_FOOTER = (
    "Advisory only — nothing is blocked. Review the PR's diff against these "
    "questions before creating it; if a commit in this PR fixes one of these "
    "classes, tag it with a `Class: <slug>` trailer (the review-fix commit "
    "convention)."
)


def _read_classes_file(path: Path) -> bytes | None:
    """Size-capped fd-bound read (O_NOFOLLOW/O_NONBLOCK + S_ISREG + nlink==1),
    mirroring the shared-dir read policy of bin/learn. None on any anomaly."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1 or st.st_size > BYTE_CAP:
            return None
        return os.read(fd, BYTE_CAP)
    except OSError:
        return None
    finally:
        os.close(fd)


def parse_classes(raw: bytes) -> dict | None:
    """Minimal wholesale shape gate: None on anything invalid."""
    try:
        obj = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(obj, dict) or obj.get("version") != 1:
        return None
    if not isinstance(obj.get("preamble"), str) or not obj["preamble"].strip():
        return None
    classes = obj.get("classes")
    if not isinstance(classes, list) or not classes:
        return None
    for c in classes:
        if not isinstance(c, dict):
            return None
        if not isinstance(c.get("slug"), str) or not c["slug"].strip():
            return None
        if not isinstance(c.get("question"), str) or not c["question"].strip():
            return None
    return obj


def build_message(obj: dict) -> str:
    lines = [MESSAGE_HEADER, "", obj["preamble"], ""]
    lines += [f"- {c['slug']}: {c['question']}" for c in obj["classes"]]
    lines += ["", MESSAGE_FOOTER]
    return "\n".join(lines)


def should_fire(input_data: object) -> bool:
    if not isinstance(input_data, dict) or input_data.get("tool_name") != "Bash":
        return False
    tool_input = input_data.get("tool_input")
    if not isinstance(tool_input, dict):
        return False
    command = tool_input.get("command")
    return isinstance(command, str) and bool(GH_PR_CREATE_RE.search(command))


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
    raw = sys.stdin.read()
    input_data = json.loads(raw)
    if not should_fire(input_data):
        return
    classes_path = Path(os.environ.get("LEARNINGS_PREFLIGHT_CLASSES_FILE") or CLASSES_PATH)
    raw = _read_classes_file(classes_path)
    if raw is None:
        return
    obj = parse_classes(raw)
    if obj is None:
        return
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": build_message(obj),
                }
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass  # fail open: the gate must never break a Bash call
    sys.exit(0)
