#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Regenerate LEARNINGS.md as a topic index from LEARNINGS-*.md subfiles.

For each LEARNINGS-{topic}.md, reads the H1 + the `<!-- summary: ...
keywords: ... -->` header block, builds a rich topic-list index, and
overwrites LEARNINGS.md with it. Preserves the preamble (everything before
the first `## ` section) of the existing LEARNINGS.md.

Topics are listed alphabetically by H1 text. (Future: optional ordering via a
LEARNINGS.order file.)

Usage:
  bin/learnings-index.sh [--dry-run]

Env:
  LEARNINGS_DIR  Directory containing LEARNINGS-*.md files. Defaults to cwd.

Exit codes:
  0  success
  1  no LEARNINGS-*.md files, or filesystem error
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


def extract_preamble(main_file: Path, content: str | None = None) -> list[str]:
    if content is None:
        if not main_file.exists():
            return ["# Learnings"]
        content = main_file.read_text(encoding="utf-8")
    if not content:
        return ["# Learnings"]
    lines = content.splitlines()
    preamble: list[str] = []
    for line in lines:
        if line.startswith("## "):
            break
        preamble.append(line)
    while preamble and preamble[-1].strip() == "":
        preamble = preamble[:-1]
    return preamble


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
        with state.corpus_write_session(location, timeout_seconds=CORPUS_LOCK_TIMEOUT_SECONDS) as session:
            selected = session.select_files()
            snapshots = {path: session.read(path) for path in selected}
            subfiles = [path for path in selected if path.name.startswith("LEARNINGS-")]
            main_file = location.corpus_root / "LEARNINGS.md"
            if not subfiles:
                sys.stderr.write(
                    f"error: no LEARNINGS-*.md files in {location.corpus_root}\n"
                )
                return 1

            # Group nested sub-subfiles (LEARNINGS-{parent}--{child}.md) under their
            # parent topic; flat topics (no `--`) are their own group, no children.
            by_parent: dict[str, dict[str, object]] = {}
            for p in subfiles:
                content = snapshots[p].text
                parent_slug, child_slug = parse_topic_slug(p.name)
                grp = by_parent.setdefault(parent_slug, {"record": None, "children": []})
                rec = parse_subfile(p, content)
                if child_slug is None:
                    grp["record"] = rec
                else:
                    rec["child_slug"] = child_slug
                    rec["topic_key"] = f"{parent_slug}--{child_slug}"
                    grp["children"].append(rec)

            groups: list[dict[str, object]] = []
            for parent_slug, grp in by_parent.items():
                rec = grp["record"]
                display = str(rec["topic"]) if rec is not None else _slug_to_title(parent_slug)
                grp["children"].sort(key=lambda c: str(c["child_slug"]).lower())
                groups.append({"display": display, "record": rec, "children": grp["children"]})
            groups.sort(key=lambda g: str(g["display"]).lower())

            main_snapshot = snapshots.get(main_file)
            existing_text = main_snapshot.text if main_snapshot else None
            preamble = extract_preamble(main_file, existing_text)
            new_index = build_index(preamble, groups)

            if dry_run:
                print("WOULD write to LEARNINGS.md:")
                print()
                print(new_index)
            else:
                if main_snapshot is None:
                    if location.mode == "external":
                        raise state.CorpusMutationError("LEARNINGS.md is missing")
                    session.commit(state.CorpusMutationBatch(creations=(("LEARNINGS.md", new_index),)))
                else:
                    session.commit(state.CorpusMutationBatch(replacements=((main_snapshot, new_index),)))
                n_children = sum(len(g["children"]) for g in groups)
                suffix = f" + {n_children} subtopics" if n_children else ""
                print(
                    f"wrote {main_file.name} ({len(groups)} topics{suffix}, "
                    f"{new_index.count(chr(10))} lines)"
                )
        return 0
    except (
        state.ProjectRootError,
        state.IdentityResolutionError,
        state.CorpusResolutionError,
        state.CorpusMutationError,
        OSError,
        UnicodeError,
    ) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
