#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Atomic append to a LEARNINGS file with flock + session tag.

Usage:
  bin/learnings-write.sh <topic> <section> <entry>

Args:
  topic    Slug like "hooks", "deploy". Routes to LEARNINGS-{topic}.md if it
           exists, else falls back to LEARNINGS.md (in which case the topic
           value is ignored except as a routing hint).
  section  Section header text without the leading "## ", e.g.
           "Patterns that work". Created at end of file if missing.
  entry    Bullet text (no leading dash — script adds it).

Env:
  LEARNINGS_DIR         Directory to look for/write LEARNINGS files. Defaults
                        to current working directory.
  LEARNINGS_SESSION_ID  Session id to embed in the per-entry tag comment.
                        Defaults to "unknown" when not set (e.g. manual call).

Concurrency: one corpus write session serializes activity, corpus identity,
and the legacy target-file mutation.

Exit codes:
  0  appended successfully
  1  argument or filesystem error
  2  lock acquisition timed out
"""

from __future__ import annotations

import datetime as dt
import importlib.machinery
import importlib.util
import os
import re
import secrets
import sys
from collections.abc import Iterable
from pathlib import Path


def _load_state_module():
    """Load the trusted state sibling in source and deployed layouts."""
    name = "learnings_state"
    here = Path(__file__).resolve().parent
    candidates = (here / "learnings-state.sh", here / "learnings" / "learnings-state.sh")
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        raise RuntimeError("cannot load learnings-state.sh; run bin/deploy.sh")
    cached = sys.modules.get(name)
    if cached is not None and Path(getattr(cached, "__file__", None) or "").resolve() == path.resolve():
        return cached
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load state module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    finally:
        sys.dont_write_bytecode = previous
    return module


LOCK_TIMEOUT_SECONDS = 5
# Block for up to this long on the project-scoped structural lock (held by
# bin/learnings-auto-split.sh during split orchestration). Auto-split no longer
# caps each stage (no-kill-timeout policy); its hold is bounded only by the
# inner per-`claude -p` backstops, so a worst-case multi-subfile summarize can
# run for minutes. It typically completes in 30-60s, so 30s covers the common
# case; if a split is genuinely in flight the writer backs off and retries next
# turn. Override via LEARNINGS_PROJECT_LOCK_TIMEOUT env (used by tests).
PROJECT_LOCK_TIMEOUT_SECONDS = int(
    os.environ.get("LEARNINGS_PROJECT_LOCK_TIMEOUT") or 30
)

# --- Entry IDs (simplification design, 2026-08-01) -------------------------
#
# Every corpus entry carries a stable 6-char base36 id in its trailing tag
# comment: `- text <!-- id:a3f2k9 @session ts -->`. Deletion machinery
# addresses entries by this id (the model names ids it was shown — it never
# transcribes entry text), so the id must be minted here, at the single
# writer, and must be unique across the project's whole corpus. This module
# is the canonical home for the schema; `learn migrate-ids` and the pruner
# load these helpers via _resolve_helper rather than copying them.

ENTRY_ID_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
ENTRY_ID_LEN = 6
# An id token inside an HTML comment. Used both to collect existing ids and
# as the idempotency check when stamping (a line whose tag already carries
# `id:` is never re-stamped).
ENTRY_ID_RE = re.compile(r"\bid:([0-9a-z]{6})\b")
# A line's TRAILING session tag as the writer has always emitted it:
# `<!-- @session timestamp -->`. stamp_entry_ids upgrades this in place to
# `<!-- id:xxxxxx @session timestamp -->`.
_TRAILING_SESSION_TAG_RE = re.compile(r"<!--\s*@(\S+\s+\S+)\s*-->\s*$")

# The full trailing-tag pattern, all shapes. This is the CANONICAL copy:
# the pruner imports it via _load_sibling (helpers are deploy-time siblings),
# so entry canonicalization at judge time and delete time cannot drift.
_TAG_RE = re.compile(
    r"\s*<!--\s*(?:id:[0-9a-z]{6}(?:\s+@\S+\s+\S+)?|@\S+\s+\S+)\s*-->\s*$"
)

# Identity extraction: an entry's id comes ONLY from its trailing tag.
# ENTRY_ID_RE above stays deliberately broad — for mint-collision collection
# and stamp idempotency, over-matching is the fail-safe direction. Anything
# that ADDRESSES an entry by id (prune collection, apply-time matching) must
# use this anchored form instead, so an id-shaped token in bullet prose can
# never hijack the entry's identity or make one id appear on two lines.
ENTRY_ID_TAG_RE = re.compile(
    r"<!--\s*id:([0-9a-z]{6})(?:\s+@\S+\s+\S+)?\s*-->\s*$"
)

# The id tag's optional `@session <sid> <timestamp>` half, timestamp only —
# used by the tiers stage (self-regulation slice 2a) to recover an entry's
# write time. Anchored the same way as ENTRY_ID_TAG_RE (addressing, not
# collection) so a quoted illustration line can't be read as a real entry.
_ENTRY_TAG_SESSION_TS_RE = re.compile(
    r"<!--\s*id:[0-9a-z]{6}\s+@\S+\s+(\S+)\s*-->\s*$"
)


def strip_entry_tag(line: str) -> str:
    """Remove the trailing tag this writer appends, whatever its vintage."""
    return _TAG_RE.sub("", line).rstrip()


def parse_learnings_ts(value: str) -> float | None:
    """Parse this writer's own `YYYY-MM-DDTHH:MMZ` stamp (also the format
    `learn search`'s ref-count header uses for `last-ref`) into UTC epoch
    seconds. None on anything else — never a guess."""
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%MZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.UTC).timestamp()


def entry_write_ts(line: str) -> float | None:
    """Parse a corpus line's trailing `@session <sid> <YYYY-MM-DDTHH:MMZ>`
    timestamp into UTC epoch seconds. None when the tag carries no session
    timestamp (a pre-schema entry the id backfill stamped bare) or the
    timestamp does not parse as this writer's own format — either way the
    tiers stage (self-regulation slice 2a) treats the write time as absent
    and mints a `first-seen` record rather than guessing."""
    m = _ENTRY_TAG_SESSION_TS_RE.search(line)
    if not m:
        return None
    return parse_learnings_ts(m.group(1))


def _random_entry_id() -> str:
    return "".join(
        secrets.choice(ENTRY_ID_ALPHABET) for _ in range(ENTRY_ID_LEN)
    )


def mint_entry_id(existing: set[str]) -> str:
    """Mint an id not in `existing`, and add it to the set.

    Callers hold the project structural lock while minting, so the
    collect → mint → write window cannot race another writer.
    """
    while True:
        eid = _random_entry_id()
        if eid not in existing:
            existing.add(eid)
            return eid


def collect_entry_ids(learnings_dir: Path) -> set[str]:
    """Every id already present in the project's corpus files.

    Over-collection is harmless (an `id:xxxxxx` in prose merely shrinks the
    mint space); under-collection would risk a duplicate id, so this scans
    file text wholesale rather than parsing entry structure.
    """
    texts: list[str] = []
    names = ["LEARNINGS.md", *sorted(
        p.name for p in learnings_dir.glob("LEARNINGS-*.md")
    )]
    for name in names:
        try:
            text = (learnings_dir / name).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue
        texts.append(text)
    return collect_entry_ids_from_texts(texts)


def collect_entry_ids_from_texts(texts: Iterable[str]) -> set[str]:
    """Collect one corpus-wide ID namespace from already-validated text."""
    ids: set[str] = set()
    for text in texts:
        ids.update(ENTRY_ID_RE.findall(text))
    return ids


def stamp_entry_ids(content: str, existing: set[str]) -> tuple[str, int]:
    """Backfill ids onto entry lines that lack one (the migration transform).

    Pure function over one file's text. Stamps only top-level `- ` bullet
    lines outside code fences and HTML comment blocks. A line with a
    trailing session tag gets the id inserted into that tag; a bare line
    gets a minimal `<!-- id:xxxxxx -->` appended. Lines already carrying an
    `id:` token anywhere are left untouched (idempotent; the false-positive
    direction — prose that mentions an id — merely leaves that line
    unstamped, which is fail-safe: an id-less entry cannot be deleted).

    Returns (new_content, entries_stamped). Minted ids join `existing`.

    The fence/comment grammar mirrors learnings-prune.sh::
    _iter_corpus_entry_lines (CommonMark ``` and ~~~ fences with
    run-length closers, mid-line multi-line comment opens) — keep the
    two in sync, or a quoted illustration line gets stamped here while
    staying invisible to collection, and the untagged count misreports.
    """
    out_lines: list[str] = []
    stamped = 0
    in_fence = False
    fence_delim: str | None = None
    in_comment = False
    for line in content.split("\n"):
        stripped = line.lstrip()
        if in_comment:
            out_lines.append(line)
            if "-->" in line:
                in_comment = False
            continue
        if not in_fence and (stripped.startswith("```") or stripped.startswith("~~~")):
            in_fence = True
            # CommonMark: the closer is the same character with a run at
            # least the opener's length — record the FULL run, or a
            # 4-backtick fence would be closed early by an inner ``` line.
            ch = stripped[0]
            run = len(stripped) - len(stripped.lstrip(ch))
            fence_delim = ch * run
            out_lines.append(line)
            continue
        if in_fence and stripped.startswith(fence_delim):
            in_fence = False
            fence_delim = None
            out_lines.append(line)
            continue
        # A multi-line comment can open mid-line ("Notes: <!--"), not just
        # at line start: it opens whenever the line's LAST `<!--` has no
        # `-->` after it (an entry's trailing tag closes on the same line).
        idx = line.rfind("<!--")
        if not in_fence and idx != -1 and "-->" not in line[idx:]:
            in_comment = True
            out_lines.append(line)
            continue
        if (
            in_fence
            or not line.startswith("- ")
            or ENTRY_ID_RE.search(line)
        ):
            out_lines.append(line)
            continue
        eid = mint_entry_id(existing)
        m = _TRAILING_SESSION_TAG_RE.search(line)
        if m:
            line = (
                line[: m.start()]
                + f"<!-- id:{eid} @{m.group(1)} -->"
            )
        else:
            line = line.rstrip() + f" <!-- id:{eid} -->"
        stamped += 1
        out_lines.append(line)
    return "\n".join(out_lines), stamped


# A LEARNINGS.md is a RECOGNIZED INDEX iff it carries one of three positive
# structural signals the system ITSELF emits — the thin preamble from
# learnings-split.sh, the rich H3→arrow entries from learnings-index.sh
# (`### Foo → LEARNINGS-foo.md`), or markdown links to existing subfiles.
# The bare EXISTENCE of a LEARNINGS-*.md is deliberately NOT enough: a monolith
# sitting beside orphan subfiles must still route writes INTO the monolith, or
# one stray subfile snowballs every future topic-write into another orphan that
# auto-split can't recover from (the monolith-plus-orphan failure mode).
#
# A bullet+arrow line (`- foo → LEARNINGS-foo.md`) is deliberately NOT a signal:
# r2 added it to protect hand-rolled bullet indexes, but it false-positives on
# ordinary prose (a learning bullet like `- TODO: move foo → LEARNINGS-foo.md`
# beside a real orphan would route the next topic into a fresh subfile and
# restart the snowball), and r4 declared hand-rolled layouts out of scope (the
# fold is lossless). Reverted in r4 — recognize only what the system produces.
# Mirrors learnings-auto-split.sh::is_recognized_index (its thin/rich/link
# helpers) and hooks/learning-hook.py::_is_index_mode — keep all three in sync.
_THIN_INDEX_FINGERPRINT = (
    "Index of topic-specific learnings. Each subfile should stay under "
    "200 lines; split further with LEARNINGS-{topic}-{subtopic}.md "
    "if needed."
)
_RICH_INDEX_ENTRY = re.compile(r"^###\s+.+\s+→\s+LEARNINGS-.+\.md", re.MULTILINE)
_SUBFILE_LINK = re.compile(r"\[[^\]]*\]\((LEARNINGS-[^)]+\.md)\)")
# The subtopic-only index form learnings-index.sh emits for a parent with no own
# file (build_index's `record is None` path): a `### Display` heading (no arrow)
# followed by a `Subtopics:` label and a contiguous block of
# `- child → LEARNINGS-parent--child.md` rows DIRECTLY under it (no blank line
# between). Recognition requires the nested arrow ref to an EXISTING child to
# appear inside that block — the label and the rows must be POSITIONALLY tied,
# the way build_index always writes them. A whole-file `label AND bullet` search
# reopened the prose false-positive whenever an unrelated `Subtopics:` line (e.g.
# a monolith documenting this format) co-occurred with a stray nested-arrow
# bullet (Codex r5 [P2]; r4 had gated on the label's mere presence). The `--`
# nesting + existence are the further discriminators.
_SUBTOPICS_LABEL = re.compile(r"(?m)^[ \t]*Subtopics:[ \t]*$")
_BULLET_LINE = re.compile(r"^\s*[-*]\s+")
_NESTED_CHILD_REF = re.compile(
    r"(?m)^\s*[-*]\s+.*→\s*(LEARNINGS-[^\s)]+--[^\s)]+\.md)"
)


def _subtopics_block_has_nested_child(content, exists) -> bool:
    """True if a `Subtopics:` label is directly followed by a bullet block that
    contains an arrow ref to an EXISTING nested child. The label and the child
    rows must be POSITIONALLY tied — the way learnings-index.sh build_index emits
    them (rows directly under the label, no blank between) — so an unrelated
    `Subtopics:` line plus a stray nested-arrow bullet elsewhere in a content
    monolith no longer registers (Codex r5 [P2]). `exists(ref)` resolves the
    captured filename against the corpus dir."""
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


def _is_index_mode(learnings_dir: Path) -> bool:
    """True iff LEARNINGS.md is a RECOGNIZED index — the thin preamble, the rich
    H3→arrow entries, a markdown link to a subfile that ACTUALLY EXISTS, OR the
    subtopic-only form (a `Subtopics:` label plus a bullet arrow to an EXISTING
    nested child). NOT merely 'a subfile exists' (mis-fires on a monolith beside
    orphan subfiles), and NOT a link/child ref to a non-existent subfile (a stale
    ref in a plain monolith would otherwise recreate the orphan snowball — r3
    [P2]). Mirrors learnings-auto-split.sh::is_recognized_index and
    hooks/learning-hook.py::_is_index_mode."""
    try:
        content = (learnings_dir / "LEARNINGS.md").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return False
    if _THIN_INDEX_FINGERPRINT in content:
        return True
    if _RICH_INDEX_ENTRY.search(content):
        return True
    if any(
        (learnings_dir / m.group(1)).exists()
        for m in _SUBFILE_LINK.finditer(content)
    ):
        return True
    return _subtopics_block_has_nested_child(
        content, lambda ref: (learnings_dir / ref).exists()
    )


def _resolve_learnings_dir(
    start: Path, allowed_root: Path | None = None
) -> Path:
    """Walk up from `start` to find the project root.

    Project root = nearest ancestor (inclusive of `start`) carrying a
    `.git` entry, strictly below `allowed_root`. Mirrors the rule
    hooks/scaffold-learnings.sh already uses: `.git` is the authoritative
    project boundary; the presence/absence of LEARNINGS.md is not.

    Without this, two failure modes appeared:
    1. A subagent dispatched with cwd inside a project subdir (e.g.
       skills/<name>/) would O_CREAT a stray LEARNINGS.md there,
       fragmenting the corpus the index/split system is meant to unify.
    2. A `LEARNINGS.md`-based walk-up would mis-route writes from a
       fresh project to a category-level notes file (e.g. when
       ~/Code/<category>/LEARNINGS.md exists as hand-curated notes
       above multiple projects).

    `allowed_root` defaults to $LEARNINGS_SCAFFOLD_ROOT or ~/Code — the
    same boundary scaffold-learnings.sh uses. The walk:
    - returns the nearest `.git`-owning ancestor STRICTLY below
      `allowed_root` (LEARNINGS.md may not exist there yet — fresh
      projects still resolve to the project root, not the invocation
      subdir);
    - never crosses `allowed_root` (a `.git` AT the category dir would
      treat the category as a meta-repo — not our topology);
    - returns `start` unchanged when no `.git` ancestor is found below
      `allowed_root`, preserving cwd-based legacy behavior outside the
      managed tree.

    Note: `.git` may be a directory (normal repo) or a file (git
    worktrees) — `Path.exists()` accepts both.
    """
    start = start.resolve()
    if allowed_root is None:
        env_root = os.environ.get("LEARNINGS_SCAFFOLD_ROOT")
        allowed_root = Path(env_root) if env_root else Path.home() / "Code"
    allowed_root = allowed_root.resolve()

    try:
        start.relative_to(allowed_root)
    except ValueError:
        # `start` is outside the managed topology — preserve legacy
        # cwd-based behavior. Callers that opt out of the topology gate
        # (e.g. tests with LEARNINGS_DIR pointing at /tmp) still work.
        return start

    cur = start
    while True:
        rel = cur.relative_to(allowed_root)
        if rel.parts:  # cur is STRICTLY below allowed_root
            if (cur / ".git").exists():
                return cur
        if cur == allowed_root or cur.parent == cur:
            return start
        cur = cur.parent


# Slug must be a flat name component — no path separators, no dotdot,
# no leading dot. Mirrors bin/learnings-consolidate.sh::_topic_to_path
# and bin/learn-side validation. Codex round-23 [P2]: prior to F8, an
# unknown topic only ever produced LEARNINGS.md as the target, so a
# crafted slug couldn't escape the project. With F8 auto-create, the
# slug becomes part of the on-disk path that O_CREAT opens — so a
# slug like "foo/../../outside" combined with an existing LEARNINGS-foo/
# directory would create a file outside LEARNINGS_DIR before the
# realpath boundary check ran.
_SAFE_TOPIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _is_safe_topic(topic: str) -> bool:
    if not topic:
        return False
    if "/" in topic or "\\" in topic:
        return False
    if topic.startswith(".") or ".." in topic:
        return False
    return bool(_SAFE_TOPIC_RE.match(topic))


class AmbiguousTopicError(ValueError):
    """A child-slug alias matched more than one nested subfile.

    Subclasses ValueError so a caller that only guards the broad type still
    catches it.
    """


def _indexed_nested_children(learnings_dir: Path) -> set[str]:
    """Nested subfile names the index actually LINKS, from `Subtopics:` rows.

    Same positional grammar as _subtopics_block_has_nested_child: rows must sit
    directly under the label, so a stray arrow bullet elsewhere doesn't count.
    Names containing a path separator are dropped — the row is data, and a
    resolved path is not this function's job.
    """
    try:
        content = (learnings_dir / "LEARNINGS.md").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return set()
    found: set[str] = set()
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if not _SUBTOPICS_LABEL.match(line):
            continue
        for child in lines[i + 1:]:
            if not _BULLET_LINE.match(child):
                break
            m = _NESTED_CHILD_REF.search(child)
            if m and "/" not in m.group(1):
                found.add(m.group(1))
    return found


def child_alias_matches(topic: str, learnings_dir: Path) -> list[Path]:
    """Existing INDEX-LINKED nested subfiles whose CHILD slug equals `topic`.

    Restricted to children the index links, not every nested file on disk. The
    alias exists to serve a caller who copied a token FROM the index; if the
    index does not list that child, nobody could have copied it, and treating
    it as an alias would let a STALE orphan subfile (dead split wreckage, which
    the monolith self-heal exists to fold away) silently absorb new entries and
    shadow a legitimate new top-level topic of the same name.

    `LEARNINGS-{parent}--{child}.md` is the nested layout; the split mirrors
    learnings-index.sh::parse_topic_slug (first `--` wins, so a
    `LEARNINGS-a--b--c.md` has child `b--c`). Sorted for deterministic
    reporting when the match is ambiguous.
    """
    matches = []
    for name in sorted(_indexed_nested_children(learnings_dir)):
        p = learnings_dir / name
        if not p.exists():
            continue
        slug = name[len("LEARNINGS-"):-len(".md")]
        if "--" in slug and slug.split("--", 1)[1] == topic:
            matches.append(p)
    return matches


def resolve_target(topic: str, learnings_dir: Path) -> Path:
    """Pick the file an entry should land in.

    - Existing subfile → that subfile.
    - RECOGNIZED-INDEX mode + unambiguous CHILD-slug alias → the INDEX-LINKED
      nested subfile that owns it.

      learnings-index.sh now renders the FULL topic key as a subtopic row's
      leading token, so a reader copying the current index gets a key that
      needs no aliasing. This branch is compatibility, and it is not
      vestigial: every already-generated index on disk still shows the bare
      child slug until its next rebuild, and callers working from memory or an
      older transcript pass the short slug too. Without it, each of those
      silently mints an orphan subfile — the bug this whole change fixes.

      Index mode only, and index-LINKED children only (see
      child_alias_matches): those two limits keep the alias from reaching a
      case no reader could have copied from.

      Exact identity is checked FIRST, so a real top-level
      `LEARNINGS-testing.md` always beats a `...--testing` child. Ambiguous
      (two indexed parents own the same child slug) raises rather than
      guessing a parent — filing an entry under the wrong topic is silent
      misinformation.

      Known, accepted cost: a genuinely NEW top-level topic whose name equals
      an indexed child slug routes to that child instead of being created,
      since only existing files can win the exact-match branch. That is the
      "routing beats proliferation" trade this system already prefers, and the
      stderr note names the file that received the entry.
    - RECOGNIZED-INDEX mode + unknown topic → return the LEARNINGS-<topic>.md
      path so main() auto-creates it via O_CREAT. Prevents new-topic entries
      from spilling into the index file (which would otherwise require a
      re-split pass).
    - Otherwise (a true monolith, OR a monolith sitting beside orphan
      subfiles) + unknown topic → fall back to LEARNINGS.md. Routing on the
      bare presence of a subfile is the bug that snowballs orphans; auto-split
      reorganizes the monolith later.
    """
    subfile = learnings_dir / f"LEARNINGS-{topic}.md"
    if subfile.exists():
        return subfile
    if not _is_index_mode(learnings_dir):
        return learnings_dir / "LEARNINGS.md"
    # INDEX MODE ONLY, deliberately. The orphan this fixes can only be minted
    # here: in monolith mode an unknown topic already falls back to
    # LEARNINGS.md, so there is no orphan to prevent and no index rendering a
    # child slug for a caller to copy. Routing an alias in monolith mode would
    # divert a write into an orphan subfile and bypass the monolith+orphan
    # self-heal contract for no gain.
    aliases = child_alias_matches(topic, learnings_dir)
    if len(aliases) == 1:
        return aliases[0]
    if len(aliases) > 1:
        names = ", ".join(p.name[len("LEARNINGS-"):-len(".md")] for p in aliases)
        raise AmbiguousTopicError(
            f"topic {topic!r} is ambiguous — it is the child slug of: {names}. "
            "Re-run with the full topic key."
        )
    return subfile


def _new_subfile_header(topic: str) -> str:
    """Standard skeleton for a freshly-created topic subfile. The
    summary/keywords placeholders are filled in by
    bin/learnings-summarize.sh on its next run; until then they are
    empty strings — the index rebuilder treats them as 'pending'."""
    return (
        f"# {topic}\n"
        "\n"
        "<!--\n"
        "summary:\n"
        "\n"
        "keywords:\n"
        "-->\n"
        "\n"
    )


def insert_entry(content: str, section: str, entry_line: str) -> str:
    """Insert entry_line under `## section`. Create section if missing.

    Preserves trailing-blank-line convention before the next section.
    """
    # Defensive: a caller that passes the section WITH its "## " prefix
    # (or stray leading hashes/whitespace) must not create a "## ## X"
    # ghost section. Normalize to the bare section name; the matcher and
    # the header build both use the clean value.
    section = section.lstrip("#").strip()
    if not section:
        raise ValueError("section name is empty after stripping '#'/whitespace")
    lines = content.splitlines()
    section_header = f"## {section}"

    section_idx = -1
    for i, line in enumerate(lines):
        if line.strip() == section_header:
            section_idx = i
            break

    if section_idx < 0:
        result = lines[:]
        if result and result[-1].strip() != "":
            result.append("")
        result.append(section_header)
        result.append("")
        result.append(entry_line)
        return "\n".join(result) + "\n"

    end_idx = len(lines)
    for j in range(section_idx + 1, len(lines)):
        if lines[j].startswith("## "):
            end_idx = j
            break

    insert_idx = end_idx
    while insert_idx > section_idx + 1 and lines[insert_idx - 1].strip() == "":
        insert_idx -= 1

    to_insert: list[str] = []
    if insert_idx == section_idx + 1:
        to_insert.append("")
    to_insert.append(entry_line)
    result = lines[:insert_idx] + to_insert + lines[insert_idx:]
    return "\n".join(result) + "\n"


def _parse_args(argv: list[str]) -> tuple[Path | None, str, str, str] | None:
    """Parse the two direct invocation shapes without touching the filesystem."""
    values = argv[1:]
    if len(values) == 3:
        return None, values[0], values[1], values[2]
    if len(values) == 5 and values[0] == "--cwd":
        return Path(values[1]), values[2], values[3], values[4]
    return None


def _session_class() -> str:
    """LEARNINGS_SESSION_CLASS: interactive (default) | automation | harness.
    Unknown values fall open to interactive with one stderr warning — this
    gate must never be able to block a session. Duplicated per-file by the
    standalone-hook-script convention (see CLAUDE.md)."""
    value = os.environ.get("LEARNINGS_SESSION_CLASS")
    if not value or value in ("interactive", "automation", "harness"):
        return value or "interactive"
    sys.stderr.write(
        f"learnings: unknown LEARNINGS_SESSION_CLASS={value}, treating as interactive\n"
    )
    return "interactive"


def main() -> int:
    # The corpus write boundary: refuse BEFORE resolving the project root,
    # acquiring the corpus lock, or touching any file. Called directly and
    # via `learn add`'s subprocess (which inherits this env var).
    if _session_class() == "harness":
        sys.stderr.write(
            "learnings-write: refusing: LEARNINGS_SESSION_CLASS=harness\n"
        )
        return 2
    parsed = _parse_args(sys.argv)
    if parsed is None:
        sys.stderr.write("usage: learnings-write.sh [--cwd <project-root>] <topic> <section> <entry>\n")
        return 1
    requested_project_root, topic, section, entry = parsed

    # Codex round-23 [P2]: reject unsafe topic slugs BEFORE any path
    # construction or O_CREAT open. With F8's auto-create-on-INDEX-mode,
    # an unsafe slug like "foo/../../outside" combined with an existing
    # LEARNINGS-foo/ directory would let the OS resolve the target path
    # past LEARNINGS_DIR — creating a stray empty file outside the
    # project before the realpath boundary check could reject it.
    if not _is_safe_topic(topic):
        sys.stderr.write(
            f"error: invalid topic slug: {topic!r} — must be alphanumerics "
            "with `._-` only (no slashes, no `..`, no leading `.`)\n"
        )
        return 1

    try:
        state = _load_state_module()
    except Exception as exc:
        sys.stderr.write(f"error: cannot load learnings-state.sh: {exc}\n")
        return 1

    # Explicit LEARNINGS_DIR remains a legacy/test corpus override. Project
    # identity always comes from --cwd or the existing walk-up rule.
    explicit = os.environ.get("LEARNINGS_DIR")
    project_root = requested_project_root or _resolve_learnings_dir(Path(os.getcwd()))
    try:
        location = state.resolve_corpus_for_write(
            project_root,
            requested_root=Path(explicit) if explicit else None,
        )
    except (state.ProjectRootError, state.CorpusResolutionError, state.IdentityResolutionError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    learnings_dir = location.corpus_root

    # Set when the write minted a brand-new topic subfile, so the closing
    # message can distinguish that from appending to an existing topic. An
    # accidental new topic used to report the same "appended to X" as a
    # correct write, which reads as success.
    created_new_topic = False

    session_id = os.environ.get("LEARNINGS_SESSION_ID") or "unknown"
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%MZ")

    try:
        session = state.corpus_write_session(
            location, timeout_seconds=PROJECT_LOCK_TIMEOUT_SECONDS
        )
        session.__enter__()
    except state.CorpusLockTimeoutError:
        sys.stderr.write(
            f"error: could not acquire project lock within {PROJECT_LOCK_TIMEOUT_SECONDS}s "
            "— auto-split likely running. Entry dropped; next review will re-mine.\n"
        )
        return 2
    except (state.CorpusMutationError, state.CorpusResolutionError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    try:
        # One session owns collection, target routing, insertion, and commit.
        snapshots = ()
        if location.mode == "external":
            snapshots = tuple(session.read(path) for path in session.select_files())
        existing_ids = (
            collect_entry_ids_from_texts(snapshot.text for snapshot in snapshots)
            if location.mode == "external"
            else collect_entry_ids(learnings_dir)
        )
        eid = mint_entry_id(existing_ids)
        entry_line = f"- {entry} <!-- id:{eid} @{session_id} {timestamp} -->"

        # Re-resolve target AFTER acquiring the lock (issue #28). If we
        # waited behind an auto-split, the on-disk structure may have
        # changed (monolith → indexed). Resolving before the lock would
        # have us append to the stale target (now the rich index, where
        # the entry would corrupt the catalog and be lost on next rebuild).
        try:
            target = resolve_target(topic, learnings_dir)
        except AmbiguousTopicError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1
        # Tell the caller when the topic they passed was not the file's own
        # key. Routing silently would leave them believing the short slug is
        # the real one, and the next writer repeats the mistake.
        if target.name != f"LEARNINGS-{topic}.md" and target.name != "LEARNINGS.md":
            resolved_key = target.name[len("LEARNINGS-"):-len(".md")]
            sys.stderr.write(
                f"note: topic {topic!r} is a child slug; resolved to full "
                f"topic key {resolved_key!r} ({target.name})\n"
            )

        target_existed = target.exists()
        try:
            snapshot = next((item for item in snapshots if item.path == target), None)
            if snapshot is None and target_existed:
                snapshot = session.read(target)
            content = snapshot.text if snapshot is not None else ""
            if (
                not content.strip()
                and target.name.startswith("LEARNINGS-")
                and target.name.endswith(".md")
                and target.name != "LEARNINGS.md"
            ):
                content = _new_subfile_header(target.name[len("LEARNINGS-"):-len(".md")])
                created_new_topic = not target_existed
            new_content = insert_entry(content, section, entry_line)
            if snapshot is None:
                batch = state.CorpusMutationBatch(creations=((target.name, new_content),))
            else:
                batch = state.CorpusMutationBatch(replacements=((snapshot, new_content),))
            session.commit(batch)
        except state.CorpusLockTimeoutError as exc:
            if str(exc) == "legacy target lock timeout":
                sys.stderr.write(f"error: could not acquire lock within {LOCK_TIMEOUT_SECONDS}s\n")
            else:
                sys.stderr.write(f"error: {exc}\n")
            return 2
        except (state.CorpusMutationError, state.CorpusResolutionError, OSError) as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1
    except state.CorpusLockTimeoutError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except (state.CorpusMutationError, state.CorpusResolutionError, OSError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    finally:
        session.close()

    # In external mode learnings_dir is the central store, not a directory in
    # the checkout — name it so the caller doesn't go looking for target.name
    # under the project's own tree.
    central_store_suffix = f" (central store: {learnings_dir})" if location.mode == "external" else ""
    if created_new_topic:
        print(
            f"created new topic subfile {target.name} and appended under "
            f"'## {section}'{central_store_suffix}"
        )
    else:
        print(f"appended to {target.name} under '## {section}'{central_store_suffix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
