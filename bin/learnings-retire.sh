#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Repository-artifact retirement primitives for external LEARNINGS corpora."""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path

ROSTER_SCHEMA_VERSION = 1
ARCHIVE_SCHEMA_VERSION = 1
AUDIT_SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_ROSTER_ROWS = 4096
_PORTABLE_RE = re.compile(r"^(?:\.?[^/]+-)?PORTABLE-LEARNINGS\.md(?:\.prev)?$")
_REVISION_RE = re.compile(r"^rev-[0-9a-f]{16,64}$")
_PROJECTED_SYNC_STATES = frozenset({"clean", "external-only", "repository-only", "both"})
_ARTIFACT_KEYS = frozenset({"kind", "mode", "path", "sha256", "size_bytes", "tracked"})
_LEGACY_LINK_KEYS = frozenset({"path", "target", "target_artifact"})
_ROW_KEYS = frozenset(
    {
        "artifacts",
        "blockers",
        "branch",
        "canonical_identity",
        "disposition",
        "git_common_dir",
        "git_status",
        "head",
        "legacy_portable_symlinks",
        "notes",
        "observed_path_id",
        "origin",
        "project_key",
        "root",
        "row_sha256",
        "schema_version",
        "synchronization",
    }
)


def _load_state_module():
    name = "learnings_state"
    path = Path(__file__).resolve().with_name("learnings-state.sh")
    cached = sys.modules.get(name)
    if cached is not None and Path(getattr(cached, "__file__", "")).resolve() == path:
        return cached
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


STATE = _load_state_module()


def canonical_json_bytes(record: object) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(root: Path, *args: str, env: dict[str, str] | None = None, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        timeout=30,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"rc={result.returncode}"
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def artifact_kind(relative: str) -> str | None:
    if relative == "docs/review-retro-misses.md":
        return "review-retro"
    if "/" in relative:
        return None
    if relative == "LEARNINGS.md":
        return "core"
    if relative.startswith("LEARNINGS-"):
        return "core" if relative.endswith(".md") else None
    if _PORTABLE_RE.fullmatch(relative):
        return "portable"
    return None


def _tracked_paths(root: Path) -> set[str]:
    raw = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    if raw.returncode != 0:
        raise ValueError("cannot inventory tracked repository paths")
    return {item.decode("utf-8", "strict") for item in raw.stdout.split(b"\0") if item}


def _read_regular_single_link(
    path: Path, *, max_bytes: int = MAX_ARTIFACT_BYTES
) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"retirement artifact must be a regular single-link file: {path}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"retirement artifact must be a regular single-link file: {path}")
        if metadata.st_size > max_bytes:
            raise ValueError(f"retirement artifact exceeds {max_bytes} bytes: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"retirement artifact exceeds {max_bytes} bytes: {path}")
        return b"".join(chunks), stat.S_IMODE(metadata.st_mode)
    finally:
        os.close(fd)


def inventory_artifacts(project_root: Path | str) -> tuple[dict, ...]:
    root = Path(project_root).resolve()
    tracked = _tracked_paths(root)
    candidates: list[tuple[str, str]] = []
    for entry in root.iterdir():
        kind = artifact_kind(entry.name)
        if kind is not None:
            candidates.append((entry.name, kind))
    report = root / "docs" / "review-retro-misses.md"
    if os.path.lexists(report):
        candidates.append(("docs/review-retro-misses.md", "review-retro"))
    rows: list[dict] = []
    for relative, kind in sorted(candidates):
        data, mode = _read_regular_single_link(root / relative)
        rows.append(
            {
                "kind": kind,
                "mode": mode,
                "path": relative,
                "sha256": _sha256(data),
                "size_bytes": len(data),
                "tracked": relative in tracked,
            }
        )
    return tuple(rows)


def inventory_legacy_portable_symlinks(
    project_root: Path | str, artifacts: tuple[dict, ...]
) -> tuple[dict, ...]:
    root = Path(project_root).resolve()
    targets = {
        str((root / artifact["path"]).resolve(strict=False)): artifact["path"]
        for artifact in artifacts
        if artifact["kind"] == "portable"
    }
    directory = STATE.state_paths().legacy_root / "portable"
    try:
        entries = tuple(directory.iterdir())
    except OSError:
        return ()
    rows: list[dict] = []
    for entry in entries:
        try:
            metadata = os.lstat(entry)
        except OSError:
            continue
        if not stat.S_ISLNK(metadata.st_mode):
            continue
        target = os.readlink(entry)
        resolved = str((entry.parent / target).resolve(strict=False))
        artifact = targets.get(resolved)
        if artifact is not None:
            rows.append({"path": str(entry), "target": target, "target_artifact": artifact})
    return tuple(sorted(rows, key=lambda row: row["path"]))


# Copied from bin/learnings-write.sh (`_THIN_INDEX_FINGERPRINT`,
# `_RICH_INDEX_ENTRY`, `_SUBFILE_LINK`, `_SUBTOPICS_LABEL`, `_BULLET_LINE`,
# `_NESTED_CHILD_REF`, `_subtopics_block_has_nested_child`, `_is_index_mode`)
# — a recognized LEARNINGS.md index carries no lessons of its own
# (`learnings-write.sh::resolve_target` routes entries to subfiles in index
# mode), so its regenerated index rows must never be treated as lesson lines.
# Standalone-file convention (no imports between `.sh` modules) means this
# MUST be duplicated rather than shared; parity-pinned by
# tests/test_corpus_retirement.py against the learnings-write.sh originals.
_THIN_INDEX_FINGERPRINT = (
    "Index of topic-specific learnings. Each subfile should stay under "
    "200 lines; split further with LEARNINGS-{topic}-{subtopic}.md "
    "if needed."
)
_RICH_INDEX_ENTRY = re.compile(r"^###\s+.+\s+→\s+LEARNINGS-.+\.md", re.MULTILINE)
_SUBFILE_LINK = re.compile(r"\[[^\]]*\]\((LEARNINGS-[^)]+\.md)\)")
_SUBTOPICS_LABEL = re.compile(r"(?m)^[ \t]*Subtopics:[ \t]*$")
_BULLET_LINE = re.compile(r"^\s*[-*]\s+")
_NESTED_CHILD_REF = re.compile(
    r"(?m)^\s*[-*]\s+.*→\s*(LEARNINGS-[^\s)]+--[^\s)]+\.md)"
)


def _subtopics_block_has_nested_child(content: str, exists) -> bool:
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


def _is_recognized_index(text: str, learnings_dir: Path) -> bool:
    """True iff `text` (a LEARNINGS.md body) is a RECOGNIZED index — mirrors
    learnings-write.sh::_is_index_mode. See its docstring for the recognition
    rules (thin preamble, rich H3 entries, an existing-subfile markdown link,
    or the subtopic-only form)."""
    if _THIN_INDEX_FINGERPRINT in text:
        return True
    if _RICH_INDEX_ENTRY.search(text):
        return True
    if any(
        (learnings_dir / m.group(1)).exists()
        for m in _SUBFILE_LINK.finditer(text)
    ):
        return True
    return _subtopics_block_has_nested_child(
        text, lambda ref: (learnings_dir / ref).exists()
    )


# The shared no-lesson-lost parser's non-greedy `<!--.*?-->` stops at the
# FIRST literal `-->` it finds, so a header summary that quotes an example
# like `<!-- id:xxx -->` mid-sentence leaves the rest of the real header
# unstripped. Anchor removal to the fixed shape the header writer emits
# instead (bin/learnings-summarize.sh ~line 288:
# f"<!--\nsummary: {summary}\n\nkeywords: {keywords}\n\nsource-hash: sha1:{body_hash}\n-->\n").
_GENERATED_HEADER_RE = re.compile(
    r"^<!--\nsummary: .*?\nsource-hash: sha1:[^\n]+\n-->\n?",
    re.MULTILINE | re.DOTALL,
)


def _strip_generated_header(text: str) -> str:
    """Remove the learnings-summarize.sh generated header block, at most once,
    before lesson-line comparison. See `_GENERATED_HEADER_RE` for why this
    can't rely on the shared parser's own comment stripping."""
    return _GENERATED_HEADER_RE.sub("", text, count=1)


def _revision_core_union(revision: Path) -> Counter[str]:
    """Sum (Counter addition, not max) lesson lines across every top-level
    `LEARNINGS.md` / `LEARNINGS-*.md` file in one frozen external revision
    (portable exports excluded — they are not corpus lessons). External
    fold/reduce/auto-split can move a lesson between subfiles or rename a
    subfile entirely, so a live artifact's lessons must be checked against
    the revision's combined lesson set, not one same-path file."""
    union: Counter[str] = Counter()
    try:
        entries = tuple(revision.iterdir())
    except OSError:
        return union
    for entry in entries:
        if artifact_kind(entry.name) != "core":
            continue
        try:
            data, _mode = _read_regular_single_link(entry)
        except (OSError, ValueError):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # A recognized index carries no lessons of its own: its rows and
        # preamble are derived metadata and must never satisfy containment.
        if entry.name == "LEARNINGS.md" and _is_recognized_index(text, revision):
            continue
        union.update(STATE._transition_lesson_lines(_strip_generated_header(text)))
    return union


def _external_core_digest_present(
    project_key: str,
    artifact: dict,
    *,
    repo_root: Path | None = None,
    union_cache: dict[Path, Counter[str]] | None = None,
) -> bool:
    # `union_cache` is one roster-build snapshot's memo (revision dir -> lesson
    # union), threaded in by the caller so every artifact of a row reuses one
    # scan per revision; it is deliberately not process-wide.
    revisions = STATE.corpus_project_dir(project_key) / "revisions"
    try:
        candidates = tuple(revisions.iterdir())
    except OSError:
        return False
    # Knowledge-containment fallback: the external corpus has one revision that
    # `learn add` appends to in place, so after the first external write the
    # import-time bytes no longer exist verbatim anywhere. If the live repo
    # file's own bytes still match the roster artifact, a revision whose LESSON
    # lines (the house no-lesson-lost parser: comments/headings stripped,
    # duplicates kept), summed across every top-level `LEARNINGS*.md` file in
    # that revision, are a superset of the live file's lesson lines proves the
    # external corpus has not lost anything, even though the exact digest no
    # longer matches and external fold/split/reduce may have moved the lines to
    # a differently-named subfile. DERIVED metadata — the generated summary/
    # keywords/source-hash header — is not a lesson and must not block.
    live_lines: Counter[str] | None = None
    live_is_index = False
    if repo_root is not None:
        try:
            live_data, _mode = _read_regular_single_link(repo_root / artifact["path"])
        except (OSError, ValueError):
            live_data = None
        if (
            live_data is not None
            and len(live_data) == artifact["size_bytes"]
            and _sha256(live_data) == artifact["sha256"]
        ):
            try:
                live_text = live_data.decode("utf-8")
            except UnicodeDecodeError:
                live_text = None
            if live_text is not None:
                if artifact["path"] == "LEARNINGS.md" and _is_recognized_index(live_text, repo_root):
                    live_is_index = True
                else:
                    live_lines = Counter(
                        STATE._transition_lesson_lines(_strip_generated_header(live_text))
                    )
    for revision in candidates:
        if not _REVISION_RE.fullmatch(revision.name):
            continue
        candidate = revision / artifact["path"]
        try:
            data, _mode = _read_regular_single_link(candidate)
        except (OSError, ValueError):
            data = None
        if (
            data is not None
            and len(data) == artifact["size_bytes"]
            and _sha256(data) == artifact["sha256"]
        ):
            return True
        if live_is_index:
            # Recognized-index rows are derived metadata regenerated from the
            # subfiles; each subfile is its own roster "core" artifact and is
            # proven independently by the union check below, so this revision
            # only needs to still be a recognized index — not to reference the
            # same subfile names the live index does.
            if data is None:
                continue
            try:
                revision_text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if _is_recognized_index(revision_text, revision):
                return True
            continue
        if live_lines is None:
            continue
        if union_cache is None:
            union = _revision_core_union(revision)
        else:
            union = union_cache.get(revision)
            if union is None:
                union = union_cache[revision] = _revision_core_union(revision)
        if live_lines <= union:
            return True
    return False


def _tracked_artifacts_clean(root: Path, artifacts: tuple[dict, ...]) -> bool:
    paths = [artifact["path"] for artifact in artifacts if artifact["tracked"]]
    if not paths:
        return True
    result = subprocess.run(
        ["git", "-C", str(root), "diff", "--quiet", "HEAD", "--", *paths],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise ValueError("cannot compare tracked lifecycle artifacts with HEAD")
    return result.returncode == 0


def build_roster_row(
    project_root: Path | str,
    *,
    project_key: str | None = None,
    validate_external: bool = False,
    identity_lock_held: bool = False,
) -> dict:
    root = Path(project_root).resolve()
    head = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False) or None
    git_common_dir_raw = _git(root, "rev-parse", "--git-common-dir")
    git_common_dir = Path(git_common_dir_raw)
    if not git_common_dir.is_absolute():
        git_common_dir = (root / git_common_dir).resolve()
    origin = _git(root, "remote", "get-url", "origin", check=False) or None
    git_status = _git(root, "status", "--porcelain=v1", "--untracked-files=all").splitlines()
    identity = STATE.project_identity(root)
    key_mismatch: str | None = None
    paths = STATE.state_paths()
    authority_key = None
    if paths.active:
        authority_status = STATE.inspect_project_corpus_status(project_root=root)
        authority_key = authority_status.get("project_key")
    resolved_key = authority_key or STATE.resolve_or_derive_key(
        paths.root, root, identity=identity
    )
    if project_key is None:
        project_key = resolved_key
    elif validate_external and paths.active:
        if resolved_key != project_key:
            key_mismatch = f"manifest project key changed: expected {project_key}, found {resolved_key}"
    artifacts = inventory_artifacts(root)
    legacy_links = inventory_legacy_portable_symlinks(root, artifacts)
    blockers: list[str] = []
    if key_mismatch is not None:
        blockers.append(key_mismatch)
    notes: list[str] = []
    sync_error = ""
    try:
        if identity_lock_held:
            synchronization = STATE.inspect_corpus_synchronization(
                root, identity_lock_held=True
            ).state
        else:
            synchronization = STATE.inspect_corpus_synchronization(root).state
    except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
        synchronization = "unknown"
        sync_error = f" ({type(exc).__name__}: {exc})"
    if synchronization not in _PROJECTED_SYNC_STATES | {"unprojected", "pending-stale"}:
        blockers.append(f"retirement cannot proceed from synchronization state: {synchronization}{sync_error}")
    state_paths = STATE.state_paths()
    if validate_external and not state_paths.active:
        blockers.append("valid neutral activation is required for retirement")
    elif validate_external:
        if synchronization not in {"unprojected", "pending-stale"}:
            union_cache: dict[Path, Counter[str]] = {}
            for artifact in artifacts:
                if artifact["kind"] == "core" and not _external_core_digest_present(
                    project_key, artifact, repo_root=root, union_cache=union_cache
                ):
                    blockers.append(f"core digest is absent from frozen external revisions: {artifact['path']}")
        # No external-portable gate: `learn distill`, its only producer, was
        # deleted 2026-09-06, and neutral search reads only
        # projects/<key>/portable.md, so removing a checkout portable cannot
        # shrink the pool. archive_row keeps the departing bytes.
    if synchronization in {"unprojected", "pending-stale"} and not _tracked_artifacts_clean(root, artifacts):
        blockers.append("freeze-clean requires tracked lifecycle artifacts to match HEAD")
    if blockers:
        disposition = "blocked"
    elif synchronization in {"unprojected", "pending-stale"} and any(row["tracked"] for row in artifacts):
        disposition = "freeze-clean"
    else:
        disposition = "retiring" if any(row["tracked"] for row in artifacts) else "retire"
    payload = {
        "artifacts": list(artifacts),
        "blockers": blockers,
        "branch": branch,
        "canonical_identity": identity.canonical,
        "disposition": disposition,
        "head": head,
        "legacy_portable_symlinks": list(legacy_links),
        "git_common_dir": str(git_common_dir),
        "git_status": git_status,
        "notes": notes,
        "observed_path_id": STATE.observed_path_id(root),
        "project_key": project_key,
        "origin": origin,
        "root": str(root),
        "schema_version": ROSTER_SCHEMA_VERSION,
        "synchronization": synchronization,
    }
    return {**payload, "row_sha256": _sha256(canonical_json_bytes(payload))}


def _defunct_roster_row(root: Path, project_key: str | None) -> dict:
    payload = {
        "artifacts": [],
        "blockers": [],
        "branch": None,
        "canonical_identity": None,
        "disposition": "defunct",
        "head": None,
        "legacy_portable_symlinks": [],
        "git_common_dir": None,
        "git_status": [],
        "notes": [],
        "observed_path_id": hashlib.sha256(str(root).encode()).hexdigest()[:16],
        "project_key": project_key,
        "origin": None,
        "root": str(root),
        "schema_version": ROSTER_SCHEMA_VERSION,
        "synchronization": "defunct",
    }
    return {**payload, "row_sha256": _sha256(canonical_json_bytes(payload))}


def _blocked_roster_row(root: Path, project_key: str | None, reason: str) -> dict:
    payload = {
        "artifacts": [],
        "blockers": [reason],
        "branch": None,
        "canonical_identity": None,
        "disposition": "blocked",
        "git_common_dir": None,
        "git_status": [],
        "head": None,
        "legacy_portable_symlinks": [],
        "notes": [],
        "observed_path_id": hashlib.sha256(str(root).encode()).hexdigest()[:16],
        "origin": None,
        "project_key": project_key,
        "root": str(root),
        "schema_version": ROSTER_SCHEMA_VERSION,
        "synchronization": "unknown",
    }
    return {**payload, "row_sha256": _sha256(canonical_json_bytes(payload))}


def build_roster_from_manifest(
    manifest_path: Path | str, *, validate_external: bool = True
) -> dict:
    path = Path(manifest_path).resolve()
    raw, _mode = _read_regular_single_link(path, max_bytes=MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"migration manifest is not valid JSON: {exc}") from None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("migration manifest schema_version must be 1")
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list):
        raise ValueError("migration manifest repositories must be a list")
    if manifest.get("repository_count") != len(repositories):
        raise ValueError("migration manifest repository_count does not match repositories")
    if len(repositories) > MAX_ROSTER_ROWS:
        raise ValueError(f"migration manifest exceeds {MAX_ROSTER_ROWS} repositories")
    rows: list[dict] = []
    seen: set[str] = set()
    for source in repositories:
        if not isinstance(source, dict) or not isinstance(source.get("root"), str):
            raise ValueError("migration manifest repository row is malformed")
        root = Path(source["root"])
        if not root.is_absolute():
            raise ValueError("migration manifest root must be absolute")
        resolved = root.resolve()
        if str(resolved) in seen:
            raise ValueError(f"migration manifest repeats root: {resolved}")
        seen.add(str(resolved))
        preview = source.get("preview") if isinstance(source.get("preview"), dict) else {}
        project_key = preview.get("project_key") if isinstance(preview.get("project_key"), str) else None
        if not resolved.is_dir():
            rows.append(_defunct_roster_row(resolved, project_key))
            continue
        try:
            rows.append(
                build_roster_row(
                    resolved,
                    project_key=project_key,
                    validate_external=validate_external,
                )
            )
        except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
            rows.append(_blocked_roster_row(resolved, project_key, str(exc)))
    return {
        "rows": rows,
        "schema_version": ROSTER_SCHEMA_VERSION,
        "source_manifest": str(path),
        "source_manifest_sha256": _sha256(raw),
    }


def write_roster(roster: dict, output_path: Path | str) -> Path:
    output = Path(output_path).resolve()
    data = canonical_json_bytes(roster)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if output.read_bytes() != data:
            raise ValueError(f"retirement roster already exists with different bytes: {output}")
        return output
    _write_new_file(output, data)
    _fsync_dir(output.parent)
    return output


def load_roster(roster_path: Path | str) -> dict:
    path = Path(roster_path).resolve()
    raw, _mode = _read_regular_single_link(path, max_bytes=MAX_MANIFEST_BYTES)
    try:
        roster = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"retirement roster is not valid JSON: {exc}") from None
    if raw != canonical_json_bytes(roster):
        raise ValueError("retirement roster must use canonical JSON")
    if not isinstance(roster, dict) or roster.get("schema_version") != ROSTER_SCHEMA_VERSION:
        raise ValueError("retirement roster schema_version is invalid")
    rows = roster.get("rows")
    if not isinstance(rows, list):
        raise ValueError("retirement roster rows must be a list")
    if len(rows) > MAX_ROSTER_ROWS:
        raise ValueError(f"retirement roster exceeds {MAX_ROSTER_ROWS} rows")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != _ROW_KEYS or not isinstance(row.get("root"), str):
            raise ValueError("retirement roster row is malformed")
        artifacts = row.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) > MAX_ROSTER_ROWS:
            raise ValueError(f"retirement roster artifacts are malformed: {row['root']}")
        if not all(
            isinstance(artifact, dict)
            and set(artifact) == _ARTIFACT_KEYS
            and artifact.get("kind") in {"core", "portable", "review-retro"}
            and isinstance(artifact.get("path"), str)
            and artifact_kind(artifact["path"]) == artifact["kind"]
            and isinstance(artifact.get("size_bytes"), int)
            and 0 <= artifact["size_bytes"] <= MAX_ARTIFACT_BYTES
            and isinstance(artifact.get("tracked"), bool)
            for artifact in artifacts
        ):
            raise ValueError(f"retirement roster artifact is malformed: {row['root']}")
        links = row.get("legacy_portable_symlinks")
        legacy_portable_dir = (STATE.state_paths().legacy_root / "portable").resolve()
        if not isinstance(links, list) or not all(
            isinstance(link, dict)
            and set(link) == _LEGACY_LINK_KEYS
            and isinstance(link.get("path"), str)
            and Path(link["path"]).is_absolute()
            and Path(link["path"]).parent.resolve() == legacy_portable_dir
            and isinstance(link.get("target"), str)
            and isinstance(link.get("target_artifact"), str)
            for link in links
        ):
            raise ValueError(f"retirement roster legacy symlink is malformed: {row['root']}")
        row_digest = row.get("row_sha256")
        payload = {key: value for key, value in row.items() if key != "row_sha256"}
        if row_digest != _sha256(canonical_json_bytes(payload)):
            raise ValueError(f"retirement roster row digest is invalid: {row.get('root')}")
        if row["root"] in seen:
            raise ValueError(f"retirement roster repeats root: {row['root']}")
        seen.add(row["root"])
    return roster


def roster_row_for_root(roster: dict, project_root: Path | str) -> dict:
    root = str(Path(project_root).resolve())
    matches = [row for row in roster["rows"] if row["root"] == root]
    if len(matches) != 1:
        raise ValueError(f"retirement roster has no unique row for: {root}")
    return matches[0]


def _archive_manifest(row: dict) -> dict:
    return {
        "artifacts": row["artifacts"],
        "legacy_portable_symlinks": row["legacy_portable_symlinks"],
        "observed_path_id": row["observed_path_id"],
        "project_key": row["project_key"],
        "root": row["root"],
        "row_sha256": row["row_sha256"],
        "schema_version": ARCHIVE_SCHEMA_VERSION,
    }


def _archive_path(row: dict, neutral_root: Path) -> Path:
    run_id = row["row_sha256"][:16]
    return neutral_root / "retirements" / row["project_key"] / row["observed_path_id"] / run_id


def _mkdir_private(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not os.path.lexists(cursor):
        missing.append(cursor)
        cursor = cursor.parent
    existing = os.lstat(cursor)
    if not stat.S_ISDIR(existing.st_mode):
        raise ValueError(f"retirement archive ancestor must be a directory: {cursor}")
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)
        os.chmod(directory, 0o700)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"retirement archive path must be a directory: {path}")
    os.chmod(path, 0o700)


def _write_new_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_archive(row: dict, archive: Path) -> None:
    expected_manifest = canonical_json_bytes(_archive_manifest(row))
    try:
        archive_metadata = os.lstat(archive)
        if not stat.S_ISDIR(archive_metadata.st_mode):
            raise ValueError("retirement archive must be a directory")
        actual_manifest, _mode = _read_regular_single_link(archive / "manifest.json")
    except (OSError, ValueError) as exc:
        raise ValueError(f"retirement archive manifest is unreadable: {exc}") from None
    if actual_manifest != expected_manifest:
        raise ValueError("retirement archive manifest does not match the roster row")
    for artifact in row["artifacts"]:
        data, _mode = _read_regular_single_link(archive / "files" / artifact["path"])
        if len(data) != artifact["size_bytes"] or _sha256(data) != artifact["sha256"]:
            raise ValueError(f"retirement archive changed: {artifact['path']}")


def archive_row(row: dict, *, neutral_root: Path | str) -> Path:
    neutral = Path(neutral_root).resolve()
    destination = _archive_path(row, neutral)
    if destination.exists():
        verify_archive(row, destination)
        return destination
    _mkdir_private(destination.parent)
    temporary = destination.parent / f".{destination.name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    temporary.mkdir(mode=0o700)
    try:
        files = temporary / "files"
        files.mkdir(mode=0o700)
        root = Path(row["root"])
        for artifact in row["artifacts"]:
            source = root / artifact["path"]
            data, _mode = _read_regular_single_link(source)
            if len(data) != artifact["size_bytes"] or _sha256(data) != artifact["sha256"]:
                raise ValueError(f"retirement artifact changed since roster: {artifact['path']}")
            target = files / artifact["path"]
            _mkdir_private(target.parent)
            _write_new_file(target, data)
        _write_new_file(temporary / "manifest.json", canonical_json_bytes(_archive_manifest(row)))
        _fsync_dir(files)
        _fsync_dir(temporary)
        try:
            os.rename(temporary, destination)
        except FileExistsError:
            verify_archive(row, destination)
        _fsync_dir(destination.parent)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    verify_archive(row, destination)
    return destination


def _validate_live_artifact(root: Path, artifact: dict) -> None:
    data, _mode = _read_regular_single_link(root / artifact["path"])
    if len(data) != artifact["size_bytes"] or _sha256(data) != artifact["sha256"]:
        raise ValueError(f"retirement artifact changed since roster: {artifact['path']}")


def _live_row_matches_archived_cleanup(row: dict, current: dict) -> bool:
    # The deletion tree is built from live HEAD, and the artifact comparison
    # below already proves the tracked lifecycle files are unchanged — HEAD
    # moving from an unrelated commit and external-side synchronization
    # advancing are normal churn and must not freeze retirement. The live
    # lane must still match the archived row's lane (a genuine disposition
    # transition legitimately requires a fresh roster).
    if current["disposition"] != row["disposition"] or current["blockers"]:
        return False
    for field in (
        "root",
        "canonical_identity",
        "project_key",
        "branch",
        "git_common_dir",
        "origin",
        "notes",
    ):
        if current[field] != row[field]:
            return False
    expected = {artifact["path"]: artifact for artifact in row["artifacts"]}
    live = {artifact["path"]: artifact for artifact in current["artifacts"]}
    if set(live) - set(expected):
        return False
    for path, artifact in expected.items():
        if artifact["tracked"] and live.get(path) != artifact:
            return False
        if path in live and live[path] != artifact:
            return False
    expected_links = {link["path"]: link for link in row["legacy_portable_symlinks"]}
    live_links = {link["path"]: link for link in current["legacy_portable_symlinks"]}
    if set(live_links) - set(expected_links):
        return False
    if any(live_links[path] != link for path, link in expected_links.items() if path in live_links):
        return False
    return True


def cleanup_legacy_portable_symlinks(row: dict) -> tuple[str, ...]:
    removable: list[dict] = []
    for link in row["legacy_portable_symlinks"]:
        path = Path(link["path"])
        if not os.path.lexists(path):
            continue
        metadata = os.lstat(path)
        if not stat.S_ISLNK(metadata.st_mode) or os.readlink(path) != link["target"]:
            raise ValueError(f"legacy portable symlink changed since roster: {path}")
        removable.append(link)
    removed: list[str] = []
    for link in removable:
        os.unlink(link["path"])
    removed.extend(
        link["path"]
        for link in row["legacy_portable_symlinks"]
        if not os.path.lexists(link["path"])
    )
    return tuple(removed)


def validate_untracked_cleanup(row: dict, archive: Path | str) -> None:
    verify_archive(row, Path(archive))
    root = Path(row["root"])
    for artifact in row["artifacts"]:
        if not artifact["tracked"] and os.path.lexists(root / artifact["path"]):
            _validate_live_artifact(root, artifact)


def cleanup_untracked(row: dict, archive: Path | str) -> tuple[str, ...]:
    archive_path = Path(archive)
    verify_archive(row, archive_path)
    root = Path(row["root"])
    removable = [artifact for artifact in row["artifacts"] if not artifact["tracked"]]
    for artifact in removable:
        if os.path.lexists(root / artifact["path"]):
            _validate_live_artifact(root, artifact)
    removed: list[str] = []
    for artifact in removable:
        if not os.path.lexists(root / artifact["path"]):
            continue
        os.unlink(root / artifact["path"])
    removed.extend(
        artifact["path"]
        for artifact in removable
        if not os.path.lexists(root / artifact["path"])
    )
    return tuple(removed)


def _write_audit(
    row: dict,
    archive: Path,
    removed: tuple[str, ...],
    *,
    status: str,
    removed_legacy_symlinks: tuple[str, ...] = (),
) -> Path:
    record = {
        "archive": str(archive),
        "removed_untracked": list(removed),
        "removed_legacy_symlinks": list(removed_legacy_symlinks),
        "row_sha256": row["row_sha256"],
        "schema_version": AUDIT_SCHEMA_VERSION,
        "status": status,
    }
    path = archive / "audit.json"
    data = canonical_json_bytes(record)
    if path.exists():
        previous, _mode = _read_regular_single_link(path)
        if previous == data:
            return path
        try:
            prior = json.loads(previous)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("retirement audit is malformed") from None
        allowed_finalize = (
            status == "retired"
            and prior.get("status") == "retiring"
            and {key: value for key, value in prior.items() if key != "status"}
            == {key: value for key, value in record.items() if key != "status"}
        )
        if not allowed_finalize:
            raise ValueError("retirement audit conflicts with the completed transition")
        temporary = archive / f".audit.json.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        _write_new_file(temporary, data)
        os.replace(temporary, path)
        _fsync_dir(archive)
        return path
    _write_new_file(path, data)
    _fsync_dir(archive)
    return path


def _assert_artifacts_absent(row: dict) -> None:
    root = Path(row["root"])
    present = [artifact["path"] for artifact in row["artifacts"] if os.path.lexists(root / artifact["path"])]
    if present:
        raise ValueError(f"retirement artifact still exists: {', '.join(present)}")
    linked = [link["path"] for link in row["legacy_portable_symlinks"] if os.path.lexists(link["path"])]
    if linked:
        raise ValueError(f"legacy portable symlink still exists: {', '.join(linked)}")


def read_retirement_audit(row: dict, archive: Path | str) -> dict:
    archive_path = Path(archive)
    verify_archive(row, archive_path)
    path = archive_path / "audit.json"
    if not path.exists():
        raise ValueError("retirement audit is absent; run retirement apply first")
    try:
        raw, _mode = _read_regular_single_link(path)
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("retirement audit is malformed") from None
    if (
        not isinstance(record, dict)
        or record.get("schema_version") != AUDIT_SCHEMA_VERSION
        or record.get("row_sha256") != row["row_sha256"]
        or record.get("archive") != str(archive_path)
        or record.get("status") not in {"retiring", "retired", "freeze-clean"}
    ):
        raise ValueError("retirement audit is malformed")
    return record


def finalize_retirement(row: dict, archive: Path | str) -> Path:
    """Complete an archived `retiring` row after Git removed every artifact."""
    archive_path = Path(archive)
    _assert_artifacts_absent(row)
    prior = read_retirement_audit(row, archive_path)
    if prior.get("status") not in {"retiring", "retired"}:
        raise ValueError("retirement audit is not ready to finalize")
    removed = tuple(prior.get("removed_untracked") or ())
    removed_links = tuple(prior.get("removed_legacy_symlinks") or ())
    return _write_audit(
        row,
        archive_path,
        removed,
        status="retired",
        removed_legacy_symlinks=removed_links,
    )


def restore_untracked(row: dict, archive: Path | str) -> tuple[str, ...]:
    archive_path = Path(archive)
    verify_archive(row, archive_path)
    root = Path(row["root"])
    restored: list[str] = []
    for artifact in row["artifacts"]:
        if artifact["tracked"]:
            continue
        target = root / artifact["path"]
        if os.path.lexists(target):
            _validate_live_artifact(root, artifact)
            continue
        data, _mode = _read_regular_single_link(archive_path / "files" / artifact["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.parent / f".{target.name}.restore-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        _write_new_file(temporary, data, artifact["mode"])
        os.replace(temporary, target)
        _fsync_dir(target.parent)
        restored.append(artifact["path"])
    for link in row["legacy_portable_symlinks"]:
        path = Path(link["path"])
        if os.path.lexists(path):
            metadata = os.lstat(path)
            if not stat.S_ISLNK(metadata.st_mode) or os.readlink(path) != link["target"]:
                raise ValueError(f"legacy portable symlink changed since roster: {path}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link["target"], path)
    return tuple(restored)


class DeletionTreeBlocked(ValueError):
    """Raised when a tracked lifecycle artifact's committed bytes no longer match the roster."""


def _require_committed_artifact_bytes(root: Path, artifact: dict, base: str) -> None:
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", f"{base}:{artifact['path']}"],
        capture_output=True,
        env={**os.environ},
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise DeletionTreeBlocked(
            f"committed bytes changed since the retirement roster: {artifact['path']}"
        )
    data = result.stdout
    if len(data) != artifact["size_bytes"] or _sha256(data) != artifact["sha256"]:
        raise DeletionTreeBlocked(
            f"committed bytes changed since the retirement roster: {artifact['path']}"
        )


def build_deletion_tree(
    project_root: Path | str, index_path: Path | str, row: dict
) -> tuple[str, tuple[str, ...]]:
    root = Path(project_root).resolve()
    if row["root"] != str(root):
        raise ValueError("retirement row belongs to a different checkout")
    # One base OID resolved once: every per-artifact blob check and the tree
    # built below must all read the SAME commit, or HEAD could move between
    # the blob checks and read-tree and silently build a tree from bytes the
    # checks never verified.
    base = _git(root, "rev-parse", "HEAD")
    for artifact in row["artifacts"]:
        if artifact["tracked"]:
            _require_committed_artifact_bytes(root, artifact, base)
    index = Path(index_path).resolve()
    git_common_dir = Path(row["git_common_dir"]).resolve()
    if index == git_common_dir or git_common_dir in index.parents:
        raise ValueError("temporary Git index must be outside the repository Git directory")
    if index == root or root in index.parents:
        raise ValueError("temporary Git index must be outside the repository checkout")
    if not index.parent.is_dir():
        raise ValueError(f"temporary Git index parent does not exist: {index.parent}")
    if os.path.lexists(index):
        raise ValueError(f"temporary Git index already exists: {index}")
    tracked_now = _tracked_paths(root)
    tracked = sorted(
        artifact["path"]
        for artifact in row["artifacts"]
        if artifact["tracked"]
        and artifact["kind"] in {"core", "portable", "review-retro"}
        and artifact["path"] in tracked_now
    )
    env = {"GIT_INDEX_FILE": str(index)}
    try:
        _git(root, "read-tree", base, env=env)
        if tracked:
            _git(root, "update-index", "--force-remove", "--", *tracked, env=env)
        tree = _git(root, "write-tree", env=env)
    finally:
        try:
            index.unlink()
        except FileNotFoundError:
            pass
    return tree, tuple(tracked)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="archive and retire repository-local LEARNINGS artifacts")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--cwd")
    target.add_argument("--manifest")
    parser.add_argument("--write-roster")
    parser.add_argument("--roster")
    parser.add_argument("--deletion-index")
    parser.add_argument("--neutral-root")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--offline-maintenance", action="store_true")
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--finalize", action="store_true")
    args = parser.parse_args(argv)
    if args.deletion_index and (args.apply or args.restore or args.finalize or args.manifest):
        print("--deletion-index is a read-only checkout action", file=sys.stderr)
        return 2
    if args.manifest and args.roster:
        print("--manifest cannot be combined with --roster", file=sys.stderr)
        return 2
    if args.manifest:
        if args.apply or args.restore or args.finalize:
            print("roster generation is read-only; apply/restore/finalize are invalid", file=sys.stderr)
            return 2
        roster = build_roster_from_manifest(args.manifest)
        if args.write_roster:
            output = write_roster(roster, args.write_roster)
            print(f"retirement roster: {output}")
        else:
            print(json.dumps(roster, indent=2, sort_keys=True))
        return 0
    if args.write_roster:
        print("--write-roster requires --manifest", file=sys.stderr)
        return 2
    if (args.restore or args.finalize) and not args.apply:
        print("--restore/--finalize require --apply", file=sys.stderr)
        return 2
    if args.apply and not (args.yes and args.offline_maintenance):
        print("retire apply requires --apply --yes --offline-maintenance; nothing was written", file=sys.stderr)
        return 2
    if args.apply and not args.roster:
        print("retire apply requires --roster; nothing was written", file=sys.stderr)
        return 2
    try:
        roster = load_roster(args.roster) if args.roster else None
        row = (
            roster_row_for_root(roster, args.cwd)
            if roster is not None
            else build_roster_row(args.cwd, validate_external=True)
        )
    except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    neutral = (
        Path(args.neutral_root).resolve()
        if args.neutral_root
        else STATE.state_paths().neutral_root
    )
    print(json.dumps(row, indent=2, sort_keys=True))
    if not args.apply:
        current = None
        if roster is not None:
            try:
                current = build_roster_row(args.cwd, validate_external=True)
            except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if current["row_sha256"] != row["row_sha256"]:
                retirement_archive = _archive_path(row, neutral)
                if (
                    not args.deletion_index
                    or not os.path.lexists(retirement_archive)
                    or not _live_row_matches_archived_cleanup(row, current)
                ):
                    print("blocked: checkout changed since the retirement roster", file=sys.stderr)
                    return 2
        if args.deletion_index:
            if roster is None:
                print("blocked: --deletion-index requires --roster", file=sys.stderr)
                return 2
            if row["disposition"] != "retiring" or row["blockers"]:
                print("blocked: deletion tree requires one ready retiring row", file=sys.stderr)
                return 2
            if not STATE.state_paths().active:
                print("blocked: valid neutral activation is required for deletion planning", file=sys.stderr)
                return 2
            try:
                retirement_archive = _archive_path(row, neutral)
                audit = read_retirement_audit(row, retirement_archive)
                if audit["status"] != "retiring":
                    raise ValueError("retirement apply must complete before deletion planning")
                tree, removed = build_deletion_tree(args.cwd, args.deletion_index, row)
            except DeletionTreeBlocked as exc:
                print(f"blocked: {exc}", file=sys.stderr)
                return 2
            except (OSError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            print(json.dumps({"deletion_tree": tree, "removed": list(removed)}, sort_keys=True))
            return 0
        print("read-only retirement plan: nothing was written")
        return 2 if row["blockers"] or row["notes"] else 0
    if row["blockers"] and not args.finalize:
        for blocker in row["blockers"]:
            print(f"blocked: {blocker}", file=sys.stderr)
        return 2
    if row["notes"] and not args.finalize:
        for note in row["notes"]:
            print(f"blocked: {note}", file=sys.stderr)
        return 2
    if not STATE.state_paths().active:
        print("blocked: valid neutral activation is required for retirement", file=sys.stderr)
        return 2
    archive = _archive_path(row, neutral)
    if args.finalize:
        if row["disposition"] not in {"retiring", "retire"}:
            print(f"blocked: {row['disposition']} rows do not have a tracked deletion lane", file=sys.stderr)
            return 2
        try:
            existing_audit = read_retirement_audit(row, archive)
            _assert_artifacts_absent(row)
            if existing_audit["status"] == "retired":
                print(f"retirement already finalized: {archive / 'audit.json'}")
                return 0
            live_state = STATE.inspect_corpus_synchronization(Path(row["root"])).state
            if live_state != "unprojected":
                unpublish = STATE.plan_corpus_unpublish(
                    Path(row["root"]), replace_repository=True
                )
                if unpublish.blockers:
                    for blocker in unpublish.blockers:
                        print(f"blocked: {blocker}", file=sys.stderr)
                    return 2
                STATE.apply_corpus_unpublish(unpublish)
        except STATE._ProjectCorpusTransitionBlocked as exc:
            for blocker in exc.blockers:
                print(f"blocked: {blocker}", file=sys.stderr)
            return 2
        except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
            print(f"error: cannot finalize the external projection: {exc}", file=sys.stderr)
            return 1
    try:
        transition = STATE.plan_project_corpus_import(Path(row["root"]))
    except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
        print(f"error: cannot plan retirement lock scope: {exc}", file=sys.stderr)
        return 1
    try:
        with STATE.ProjectCorpusTransitionSession(transition):
            if args.finalize:
                audit = finalize_retirement(row, archive)
                print(f"retirement finalized: {audit}")
                return 0
            current = build_roster_row(
                args.cwd, validate_external=True, identity_lock_held=True
            )
            if current["row_sha256"] != row["row_sha256"]:
                if not os.path.lexists(archive):
                    raise ValueError("retirement row changed while acquiring locks; regenerate the roster")
                verify_archive(row, archive)
                if not _live_row_matches_archived_cleanup(row, current):
                    raise ValueError("retirement row changed outside archived cleanup; regenerate the roster")
            archive = archive_row(row, neutral_root=neutral)
            if args.restore:
                restored = restore_untracked(row, archive)
                print(f"restored {len(restored)} untracked artifact(s)")
                return 0
            validate_untracked_cleanup(row, archive)
            removed_links = cleanup_legacy_portable_symlinks(row)
            removed = cleanup_untracked(row, archive)
            tracked = [artifact["path"] for artifact in row["artifacts"] if artifact["tracked"]]
            needs_projection_finalize = (
                row["disposition"] == "retire"
                and row["synchronization"] in _PROJECTED_SYNC_STATES
            )
            audit_status = (
                "freeze-clean"
                if row["disposition"] == "freeze-clean"
                else "retiring"
                if tracked or needs_projection_finalize
                else "retired"
            )
            _write_audit(
                row,
                archive,
                removed,
                status=audit_status,
                removed_legacy_symlinks=removed_links,
            )
    except STATE._ProjectCorpusTransitionBlocked as exc:
        for blocker in exc.blockers:
            print(f"blocked: {blocker}", file=sys.stderr)
        return 2
    except (OSError, ValueError, STATE.IdentityResolutionError, STATE.CorpusResolutionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    tracked = [artifact["path"] for artifact in row["artifacts"] if artifact["tracked"]]
    print(f"archived: {archive}")
    print(f"removed {len(removed)} untracked artifact(s)")
    if tracked:
        print(f"retiring: {len(tracked)} tracked artifact(s) require a deletion PR")
    elif needs_projection_finalize:
        print("retiring: external projection finalization is required")
    else:
        print("retired: no tracked lifecycle artifacts remain")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
