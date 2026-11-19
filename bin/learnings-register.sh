#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Shared startup registration worker.

The compatibility hook delegates here.  It deliberately preserves the legacy
scaffold result while external-default registration creates only neutral state.
Both routes require an exact-depth Git root; non-Git scratch is not enrolled.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path


def _state():
    path = Path(__file__).resolve().with_name("learnings-state.sh")
    loader = SourceFileLoader("learnings_register_state", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("state loader is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def _approve(message: str | None = None) -> int:
    record: dict[str, str] = {"decision": "approve"}
    if message:
        record["systemMessage"] = message
    print(json.dumps(record, separators=(",", ":")))
    return 0


def _legacy_scaffold(project: Path, template: Path) -> int:
    target = project / "LEARNINGS.md"
    source = template / "LEARNINGS.md"
    if target.exists() or target.is_symlink() or not source.is_file():
        return _approve()
    payload = source.read_bytes()
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        return _approve()
    try:
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count == 0:
                raise OSError("zero-byte scaffold write")
            written += count
        os.fsync(fd)
    except OSError:
        try:
            target.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    return _approve(f"Scaffolded LEARNINGS.md into {project}")


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


def main(argv: list[str]) -> int:
    if _session_class() == "harness":
        return 0
    project_value = argv[1] if len(argv) == 2 else os.environ.get("CLAUDE_PROJECT_DIR", "")
    if not project_value:
        return _approve()
    project = Path(project_value)
    allowed = Path(os.environ.get("LEARNINGS_SCAFFOLD_ROOT") or Path.home() / "Code")
    template = Path(os.environ.get("LEARNINGS_TEMPLATE_DIR", Path(__file__).resolve().parent.parent / "templates"))
    try:
        state = _state()
    except Exception as exc:
        print(
            f"learnings: state module unavailable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        qualified = state.qualified_enrollment_root(project, allowed)
    except Exception as exc:
        print(
            f"learnings: enrollment qualification unavailable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return _approve()
    if qualified is None:
        return _approve()
    project = qualified
    try:
        location = state.resolve_project_corpus_strict(project)
        activation = state.activation_status()
    except Exception:
        print("learnings: corpus mode unavailable; skipping scaffold", file=sys.stderr)
        return _approve()
    if location is not None and location.mode in {"external", "legacy-repository"}:
        return _approve()
    deployment = state.cutover_deployment_status()
    if activation.state != state.ACTIVATION_VALID:
        if activation.state != state.ACTIVATION_ABSENT:
            print("learnings: neutral activation is unavailable; skipping scaffold", file=sys.stderr)
            return _approve()
        legacy_root = state.default_legacy_root()
        try:
            importable_legacy = legacy_root.is_dir() and any(
                entry.name != "ARTIFACTS.md" for entry in legacy_root.iterdir()
            )
        except OSError:
            importable_legacy = False
        try:
            deactivated = state.deactivated_generation() is not None
        except Exception:
            deactivated = False
        legacy_authority = importable_legacy or deactivated
        if deployment["status"] == "absent":
            return _legacy_scaffold(project, template)
        if deployment["status"] != "current" or not legacy_authority:
            print("learnings: neutral activation is unavailable; skipping scaffold", file=sys.stderr)
            return _approve()
        return _legacy_scaffold(project, template)
    result = state.register_project_corpus(project)
    if result.status != "registered":
        detail = result.blockers[0] if result.blockers else "registration unavailable"
        print(f"learnings: registration skipped: {detail}", file=sys.stderr)
    return _approve()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
