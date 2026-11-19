#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Regenerate LEARNINGS.md as a topic index from LEARNINGS-*.md subfiles.

For each LEARNINGS-{topic}.md, reads the H1 + the `<!-- summary: ...
keywords: ... -->` header block, builds a rich topic-list index, and
replaces only the identified catalog in LEARNINGS.md. Other sections stay
unchanged; ambiguous or stale catalog prose requires manual reconciliation.

Topics are listed alphabetically by H1 text. (Future: optional ordering via a
LEARNINGS.order file.)

Usage:
  bin/learnings-index.sh [--cwd <project-root>] [--dry-run]

Env:
  LEARNINGS_DIR  Directory containing LEARNINGS-*.md files. Defaults to cwd.

Exit codes:
  0  success
  1  unrecognized index, no topic files, or filesystem error
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import re
import sys
from pathlib import Path

LEARNINGS_DIR_ENV = "LEARNINGS_DIR"
CORPUS_LOCK_TIMEOUT_SECONDS = 30.0


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


HEADER_BLOCK_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
SLUG_RE = re.compile(r"^LEARNINGS-(.+)\.md$")


def parse_subfile(path: Path, content: str | None = None) -> dict[str, object]:
    if content is None:
        content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    h1 = lines[0].lstrip("# ").strip() if lines else path.stem

    summary = ""
    keywords = ""
    # Pick the summary-bearing comment block, not merely the FIRST comment:
    # a `learn search` ref-count bump inserts `<!-- ref-count: N ... -->`
    # right after the H1, ahead of the `<!-- summary/keywords -->` block.
    # Grabbing the first comment would read an empty summary and the index
    # would mark the subfile unsummarized (Codex review 2026-06-03).
    block = next(
        (
            m.group(1)
            for m in HEADER_BLOCK_PATTERN.finditer(content)
            if "summary:" in m.group(1)
        ),
        "",
    )
    if block:
        sm = re.search(
            r"summary:[ \t]*(.*?)(?=\n\s*keywords:|\Z)",
            block,
            re.DOTALL,
        )
        km = re.search(
            r"keywords:[ \t]*(.*?)(?=\n\s*source-hash:|\Z)",
            block,
            re.DOTALL,
        )
        if sm:
            summary = sm.group(1).strip()
        if km:
            keywords = km.group(1).strip()

    return {
        "topic": h1,
        "summary": summary,
        "keywords": keywords,
        "line_count": content.count("\n"),
        "filename": path.name,
    }


def parse_topic_slug(filename: str) -> tuple[str, str | None]:
    """Split a subfile name into (parent_slug, child_slug).

    A `--` (double hyphen) delimits a nested sub-subfile:
    `LEARNINGS-{parent}--{child}.md` (Phase 6 #4). Single hyphens are part of a
    slug (topics like `gotchas-and-edge-cases`), so only `--` starts a child.
    No `--` → top-level topic (child_slug is None)."""
    m = SLUG_RE.match(filename)
    if not m:
        return (filename, None)
    slug = m.group(1)
    if "--" in slug:
        parent, child = slug.split("--", 1)
        return (parent, child)
    return (slug, None)


def _slug_to_title(slug: str) -> str:
    """Fallback display name for a parent that has no own file."""
    return slug.replace("-", " ").strip().capitalize() or slug


def build_index(
    preamble: list[str],
    groups: list[dict[str, object]],
) -> str:
    out = list(preamble)
    if out and out[-1].strip() != "":
        out.append("")
    out.append("")
    out.append("## Topics")
    out.append("")

    for g in groups:
        rec = g["record"]
        children = g["children"]
        if rec is not None:
            out.append(
                f"### {rec['topic']}  →  {rec['filename']}  "
                f"({rec['line_count']} lines)"
            )
            out.append("")
            summary = rec["summary"]
            if summary:
                out.append(str(summary))
            else:
                out.append(
                    "*(no summary — add a `<!-- summary: ... -->` header to "
                    f"`{rec['filename']}` by hand)*"
                )
            out.append("")
            keywords = rec["keywords"]
            if keywords:
                out.append(f"Keywords: {keywords}")
                out.append("")
        else:
            # Parent has no own file (all entries live in children).
            out.append(f"### {g['display']}")
            out.append("")
        if children:
            out.append("Subtopics:")
            for c in children:
                csum = str(c["summary"]).strip()
                snippet = (csum[:157] + "…") if len(csum) > 158 else csum
                line = (
                    f"- {c['topic_key']}  →  {c['filename']}  "
                    f"({c['line_count']} lines)"
                )
                if snippet:
                    line += f": {snippet}"
                out.append(line)
            out.append("")

    while out and out[-1].strip() == "":
        out = out[:-1]
    return "\n".join(out) + "\n"


_CATALOG_HEADING = re.compile(r"^###\s+.+?\s+→\s+(LEARNINGS-[^\s]+\.md)(?:\s+\(\d+ lines\))?\s*$")
_CATALOG_LINK = re.compile(r"^[-*]\s+\[[^\]]*\]\((LEARNINGS-[^)]+\.md)\)(?:\s+\(\d+ lines\))?\s*$")
_CATALOG_CHILD = re.compile(r"^[-*]\s+[^\n]+?\s+→\s+(LEARNINGS-[^\s]+--[^\s]+\.md)(?:\s+\(\d+ lines\))?(?:: (.*))?\s*$")
_THIN_INDEX_FINGERPRINT = (
    "Index of topic-specific learnings. Each subfile should stay under "
    "200 lines; split further with LEARNINGS-{topic}-{subtopic}.md "
    "if needed."
)


class CatalogShapeError(ValueError):
    """The catalog cannot be replaced without discarding uncertain prose."""


def _catalog_body_is_supported(corpus_root: Path, body: str, contents: dict[str, str]) -> bool:
    """Admit emitted rows and current metadata, never arbitrary lesson prose."""
    lines = body.splitlines()
    index = 0
    heading = False
    metadata: list[list[str]] = []
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        rich = _CATALOG_HEADING.fullmatch(line)
        if rich:
            name = rich.group(1)
            if name not in contents:
                raise ValueError(f"catalog references missing corpus member {name}")
            record = parse_subfile(corpus_root / name, contents[name])
            summary = str(record["summary"]) or (
                f"*(no summary — add a `<!-- summary: ... -->` header to `{name}` by hand)*"
            )
            metadata = [summary.splitlines()]
            if not record["summary"]:
                metadata.append([f"*(no summary — run `bin/learnings-summarize.sh {name}`)*"])
            if record["keywords"]:
                metadata.append(f"Keywords: {record['keywords']}".splitlines())
            heading = True
            index += 1
            continue
        if line.startswith("### ") and "→" not in line:
            # A parent without its own file has only a child list.
            following = next((item for item in lines[index + 1 :] if item.strip()), None)
            if following != "Subtopics:":
                return False
            heading, metadata = True, []
            index += 1
            continue
        if link := _CATALOG_LINK.fullmatch(line):
            if link.group(1) not in contents:
                raise ValueError(f"catalog references missing corpus member {link.group(1)}")
            heading, metadata = False, []
            index += 1
            continue
        if line == "Subtopics:" and heading:
            index += 1
            start = index
            while index < len(lines) and (child := _CATALOG_CHILD.fullmatch(lines[index])):
                name, _snippet = child.groups()
                if name not in contents:
                    raise ValueError(f"catalog references missing corpus member {name}")
                # The suffix is an explicit catalog field, so old metadata is
                # safe to refresh. Free-standing prose below a row is not.
                index += 1
            if index == start:
                return False
            heading, metadata = False, []
            continue
        block = next((part for part in metadata if lines[index : index + len(part)] == part), None)
        if block is None:
            return False
        index += len(block)
        metadata.remove(block)
    return True


def _catalog_surroundings(corpus_root: Path, contents: dict[str, str]) -> tuple[str, str]:
    """Find the replaceable catalog, retaining every byte outside its span."""
    main = contents["LEARNINGS.md"]
    # Check all structural rows before classifying any unknown prose. A stale
    # shape may keep capture available; a missing member must remain an error.
    for line in main.splitlines():
        row = _CATALOG_HEADING.fullmatch(line) or _CATALOG_LINK.fullmatch(line) or _CATALOG_CHILD.fullmatch(line)
        if row and row.group(1) not in contents:
            raise ValueError(f"catalog references missing corpus member {row.group(1)}")
    sections = list(re.finditer(r"(?m)^##[ \t]+([^\r\n]+)\r?$", main))
    topics = [section for section in sections if section.group(1).strip() == "Topics"]
    if len(topics) == 1:
        section = topics[0]
        end = next((item.start() for item in sections if item.start() > section.start()), len(main))
        prefix, body, suffix = main[: section.start()], main[section.end() : end], main[end:]
    elif not sections:
        # Older rich and standalone-link indexes have no Topics H2 yet.
        rows = list(re.finditer(r"(?m)^.*(?:\n|$)", main))
        start = next(
            (
                row.start()
                for row in rows
                if row.group().startswith("### ") or _CATALOG_LINK.fullmatch(row.group().rstrip("\r\n"))
            ),
            None,
        )
        if start is None:
            # A thin preamble contains no catalog to discard; retain it all.
            if _THIN_INDEX_FINGERPRINT in main:
                return main, ""
            raise CatalogShapeError("catalog boundary is ambiguous; refusing to replace LEARNINGS.md")
        prefix, body, suffix = main[:start], main[start:], ""
    else:
        raise CatalogShapeError("catalog boundary is ambiguous; refusing to replace LEARNINGS.md")
    if not _catalog_body_is_supported(corpus_root, body, contents):
        raise CatalogShapeError(
            "unsupported or stale catalog text needs reconciliation; refusing to replace LEARNINGS.md"
        )
    return prefix, suffix


def render_index(corpus_root: Path, contents: dict[str, str]) -> tuple[str, int, int]:
    """Render checked corpus text without reading or writing any files."""
    by_parent: dict[str, dict[str, object]] = {}
    for name, content in contents.items():
        if not name.startswith("LEARNINGS-"):
            continue
        parent_slug, child_slug = parse_topic_slug(name)
        group = by_parent.setdefault(parent_slug, {"record": None, "children": []})
        record = parse_subfile(corpus_root / name, content)
        if child_slug is None:
            group["record"] = record
        else:
            record["child_slug"] = child_slug
            record["topic_key"] = f"{parent_slug}--{child_slug}"
            group["children"].append(record)
    groups: list[dict[str, object]] = []
    for parent_slug, group in by_parent.items():
        record = group["record"]
        display = str(record["topic"]) if record is not None else _slug_to_title(parent_slug)
        group["children"].sort(key=lambda child: str(child["child_slug"]).lower())
        groups.append({"display": display, "record": record, "children": group["children"]})
    groups.sort(key=lambda group: str(group["display"]).lower())
    prefix, suffix = _catalog_surroundings(corpus_root, contents)
    catalog = build_index([], groups).lstrip("\n")
    separator = "" if not prefix or prefix.endswith("\n\n") else "\n" if prefix.endswith("\n") else "\n\n"
    rendered = prefix + separator + catalog + ("\n" if suffix else "") + suffix
    return rendered, len(groups), sum(len(group["children"]) for group in groups)


def _select_index_paths(state, location) -> tuple[Path, ...]:
    """Select every corpus name; fd readers must reject unsafe matching files."""
    if location.mode == "external":
        return state.select_external_corpus_files(location)
    return tuple(
        sorted(
            (path for path in location.corpus_root.iterdir() if state.is_valid_corpus_filename(path.name)),
            key=lambda path: path.name,
        )
    )


def _read_preview(state, location) -> dict[str, str]:
    """Preview through fd-bound readers without locks or journal recovery."""
    paths = _select_index_paths(state, location)
    if location.mode == "external":
        return {path.name: state.read_external_corpus_snapshot(location, path).text for path in paths}
    return {path.name: state._read_legacy_corpus_snapshot(location, path).text for path in paths}


def _checked_index(state, location, contents: dict[str, str]) -> tuple[str, int, int]:
    if "LEARNINGS.md" not in contents:
        raise state.CorpusMutationError("LEARNINGS.md is missing")
    if not state._selected_corpus_is_index(contents["LEARNINGS.md"], set(contents)):
        raise state.CorpusMutationError("LEARNINGS.md is not a recognized index; refusing to replace monolith content")
    if not any(name.startswith("LEARNINGS-") for name in contents):
        raise state.CorpusMutationError("no LEARNINGS-*.md files to index")
    try:
        return render_index(location.corpus_root, contents)
    except CatalogShapeError:
        raise
    except ValueError as exc:
        raise state.CorpusMutationError(f"{exc}; refusing to replace LEARNINGS.md") from exc


def _parse_args(argv: list[str]) -> tuple[Path | None, bool] | None:
    requested_project_root: Path | None = None
    dry_run = False
    values = argv[1:]
    index = 0
    while index < len(values):
        value = values[index]
        if value == "--dry-run":
            if dry_run:
                return None
            dry_run = True
        elif value == "--cwd":
            if requested_project_root is not None or index + 1 >= len(values):
                return None
            index += 1
            requested_project_root = Path(values[index])
        else:
            return None
        index += 1
    return requested_project_root, dry_run


def main() -> int:
    parsed = _parse_args(sys.argv)
    if parsed is None:
        sys.stderr.write("usage: learnings-index.sh [--cwd <project-root>] [--dry-run]\n")
        return 1
    requested_project_root, dry_run = parsed
    try:
        state = _load_state_module()
    except RuntimeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    try:
        explicit = os.environ.get(LEARNINGS_DIR_ENV)
        project_root = requested_project_root or Path(os.getcwd())
        location = state.resolve_corpus_for_write(
            project_root,
            requested_root=Path(explicit) if explicit else None,
        )
        if dry_run:
            new_index, _topics, _children = _checked_index(state, location, _read_preview(state, location))
            print("WOULD write to LEARNINGS.md:")
            print()
            print(new_index)
            return 0
        with state.corpus_write_session(location, timeout_seconds=CORPUS_LOCK_TIMEOUT_SECONDS) as session:
            selected = _select_index_paths(state, location)
            snapshots = {path: session.read(path) for path in selected}
            main_file = location.corpus_root / "LEARNINGS.md"
            contents = {path.name: snapshot.text for path, snapshot in snapshots.items()}
            new_index, n_topics, n_children = _checked_index(state, location, contents)
            main_snapshot = snapshots[main_file]
            session.commit(state.CorpusMutationBatch(replacements=((main_snapshot, new_index),)))
            suffix = f" + {n_children} subtopics" if n_children else ""
            print(f"wrote {main_file.name} ({n_topics} topics{suffix}, {new_index.count(chr(10))} lines)")
        return 0
    except (
        state.ProjectRootError,
        state.IdentityResolutionError,
        state.CorpusResolutionError,
        state.CorpusMutationError,
        CatalogShapeError,
        OSError,
        UnicodeError,
    ) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
