#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Codex lifecycle adapter for the shared LEARNINGS system."""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import select
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, NamedTuple

MAX_PAYLOAD_BYTES = 1024 * 1024
CORPUS_LOCATION_COMPAT_REVISION = 1
CORPUS_CUTOVER_COMPAT_REVISION = 1
SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
STARTUP_TIMEOUT_SECONDS = 30
STARTUP_OUTPUT_LIMIT_BYTES = 16 * 1024
GOTCHAS_LIMIT_BYTES = 16 * 1024
# Part 6E decision 15 [rev 3]: the GOVERNING budget is the REGISTERED host
# limit -- hooks.json's SessionStart `additionalContextLimit` is 6000 bytes,
# not a larger
# internal figure. Raising the registered limit toward 24KB is a deliberate
# host-config decision NOT taken in this slice.
ADDITIONAL_CONTEXT_LIMIT_BYTES = 6000
TEXT_LIMIT_BYTES = 8 * 1024
MAX_STATE_BYTES = 1024 * 1024
# Parts are RESERVED in priority order (lower sorts first), then fitted in
# list order within a priority. Every current part uses the default; the
# project-rules block that once took priority 0 was deleted 2026-09-07
# with its producer (`learn rules`).
DEFAULT_PART_PRIORITY = 1
DEFAULT_RETENTION_DAYS = 14
MAX_CLEANUP_ENTRIES = 16_384
MAX_CLEANUP_SESSIONS = 32
LEGACY_REJECTION_SUFFIX = ".review-rejects.jsonl"
MAX_REJECTION_RECORD_BYTES = 16 * 1024
SESSION_DATA_SUFFIXES = (
    ".state.json",
    ".jsonl",
    ".last-review",
    ".last-review-attempt",
    ".review-failures",
    ".review-stuck",
    ".review-stuck-done",
    ".review-unavailable",
    ".review-unavailable-done",
    ".split-done",
    ".split-stage-1-done",
    ".split-stage-2-done",
    ".split-stage-3-done",
    ".split-pending-notify",
    ".split-failed",
    ".section-warning",
    ".section-warning-done",
    ".too-many-sections-done",
    ".auto-fold-done",
    ".monolith-folded-notify",
    ".learnings-diverged-notify",
    ".subfile-oversize-notify",
    ".subfile-reduced-notify",
    ".prune-cap-tried",
    ".currency-tried",
    ".prune-report",
    ".currency-report",
    ".section-consolidation-report",
    ".compact-pending",
    ".compact-marker",
)
SESSION_DISCOVERY_SUFFIXES = SESSION_DATA_SUFFIXES


class PayloadError(ValueError):
    """The hook payload does not satisfy the documented Codex contract."""


class AdapterError(RuntimeError):
    """The adapter could not safely read or update its own runtime state."""


def _required_string(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise PayloadError(f"{field} must be a non-empty string")
    return value


def _load_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
    if not raw:
        raise PayloadError("hook payload is empty or oversized")
    if len(raw) > MAX_PAYLOAD_BYTES:
        while sys.stdin.buffer.read(64 * 1024):
            pass
        raise PayloadError("hook payload is empty or oversized")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PayloadError("hook payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise PayloadError("hook payload must be a JSON object")

    session_id = _required_string(payload, "session_id")
    if SESSION_ID_RE.fullmatch(session_id) is None:
        raise PayloadError("session_id is not a safe complete identifier")
    cwd = Path(_required_string(payload, "cwd"))
    if not cwd.is_absolute() or not cwd.is_dir():
        raise PayloadError("cwd must be an existing absolute directory")
    _required_string(payload, "hook_event_name")
    model = _required_string(payload, "model")
    if len(model.encode("utf-8")) > 256:
        raise PayloadError("model is oversized")
    transcript_path = payload.get("transcript_path")
    if transcript_path is not None and not isinstance(transcript_path, str):
        raise PayloadError("transcript_path must be a string or null")
    return payload


def _permission_mode(payload: dict[str, Any]) -> str:
    value = _required_string(payload, "permission_mode")
    if value not in {
        "default",
        "acceptEdits",
        "plan",
        "dontAsk",
        "bypassPermissions",
    }:
        raise PayloadError("permission_mode is unsupported")
    return value


def _bounded_text(value: str, limit: int = TEXT_LIMIT_BYTES) -> dict[str, Any]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        bounded = value
        truncated = False
    else:
        bounded = encoded[:limit].decode("utf-8", errors="ignore")
        truncated = True
    return {
        "value": bounded,
        "original_bytes": len(encoded),
        "truncated": truncated,
    }


def _state_dir() -> Path:
    configured = os.environ.get("LEARNINGS_ADAPTER_STATE_DIR")
    path = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".codex" / "learnings-adapter" / "sessions"
    )
    if not path.is_absolute():
        raise AdapterError("state directory must be absolute")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path.resolve()


def _core_dir() -> Path:
    configured = os.environ.get("LEARNINGS_CORE_HOME")
    path = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".local" / "share" / "learnings-md-system"
    )
    return path.resolve()


def _hooks_dir() -> Path:
    configured = os.environ.get("LEARNINGS_HOOKS_DIR")
    path = Path(configured).expanduser() if configured else _core_dir() / "hooks"
    return path.resolve()


def _bin_dir() -> Path:
    configured = os.environ.get("LEARNINGS_BIN_DIR")
    path = Path(configured).expanduser() if configured else _core_dir() / "bin"
    return path.resolve()


def _learn_cli_command() -> str:
    return shlex.quote(str(_bin_dir() / "learn"))


def _project_root(cwd: str) -> Path:
    current = Path(cwd).resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


_OPTIONAL_STATE_MODULE_UNSET = object()
_optional_state_module = _OPTIONAL_STATE_MODULE_UNSET


def _load_optional_state_module():
    """Load state for an optional notice without blocking a Codex hook."""
    global _optional_state_module
    if _optional_state_module is not _OPTIONAL_STATE_MODULE_UNSET:
        return _optional_state_module
    here = Path(__file__).resolve()
    home = Path(os.environ.get("HOME") or Path.home())
    configured_core = os.environ.get("LEARNINGS_CORE_HOME")
    core = (
        Path(configured_core).expanduser()
        if configured_core
        else home / ".local" / "share" / "learnings-md-system"
    )
    resolved_core = core.resolve()
    try:
        here.relative_to(resolved_core)
        installed_beneath_core = True
    except (AttributeError, ValueError):
        installed_beneath_core = False
    source_root = (
        here.parents[3]
        if not installed_beneath_core and len(here.parents) > 3
        else None
    )
    candidates = tuple(
        candidate
        for candidate in (
            source_root / "bin" / "learnings-state.sh"
            if source_root is not None
            else None,
            core / "bin" / "learnings-state.sh",
            source_root / "bin" / "learnings" / "learnings-state.sh"
            if source_root is not None
            else None,
            home / ".claude" / "bin" / "learnings" / "learnings-state.sh",
        )
        if candidate is not None
    )
    for path in candidates:
        if not path.is_file():
            continue
        name = "learnings_state_codex_notice"
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


def _cutover_state_module():
    """Return the state seam only when it can make cutover decisions safely.

    Optional consumers such as project-rule and notice delivery keep using the
    loader directly.  Host routing, however, must fail closed when a copied
    Codex adapter and the shared core disagree about the cutover record shape.
    """
    module = _load_optional_state_module()
    if module is None:
        return None
    if (
        getattr(module, "CORPUS_CUTOVER_COMPAT_REVISION", None)
        != CORPUS_CUTOVER_COMPAT_REVISION
    ):
        error = getattr(module, "CorpusResolutionError", AdapterError)
        raise error(
            "Codex adapter and shared core cutover compatibility revision differ"
        )
    return module


def _retention_days() -> int:
    raw = os.environ.get(
        "LEARNINGS_ADAPTER_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)
    )
    try:
        days = int(raw)
    except ValueError as exc:
        raise AdapterError("retention days must be an integer") from exc
    if not 1 <= days <= 3650:
        raise AdapterError("retention days must be between 1 and 3650")
    return days


def _session_id_from_runtime_name(name: str) -> str | None:
    for suffix in SESSION_DISCOVERY_SUFFIXES:
        if not name.endswith(suffix):
            continue
        session_id = name[: -len(suffix)]
        if SESSION_ID_RE.fullmatch(session_id) is not None:
            return session_id
    return None


def _session_data_paths(state_dir: Path, session_id: str) -> list[Path] | None:
    # Session IDs may contain periods. Prefix globs such as `<id>.*` can
    # therefore capture a different live session (`abc` versus `abc.def`).
    # Clean only exact, known artifact names. Dynamic reducer markers and stale
    # claims are intentionally left behind because their legacy filenames do
    # not encode an unambiguous session boundary.
    candidates = [
        state_dir / f"{session_id}{suffix}" for suffix in SESSION_DATA_SUFFIXES
    ]
    paths: list[Path] = []
    for path in candidates:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if not stat.S_ISREG(metadata.st_mode):
            return None
        paths.append(path)
    return paths


@contextmanager
def _session_cleanup_locks(state_dir: Path, session_id: str) -> Iterator[bool]:
    lock_paths = (
        state_dir / f"{session_id}.journal.lock",
        state_dir / f"{session_id}.worker-coordinator.lock",
        state_dir / f"{session_id}.workers.lock",
        state_dir / f"{session_id}.review-lock",
    )
    lock_fds: list[int] = []
    acquired = True
    try:
        for path in lock_paths:
            flags = os.O_CREAT | os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(path, flags, 0o600)
            except OSError:
                acquired = False
                break
            lock_fds.append(fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                acquired = False
                break
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                acquired = False
                break
        yield acquired
    finally:
        for fd in reversed(lock_fds):
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _classify_legacy_rejection_path(path: Path) -> tuple[str, str] | None:
    """Return (kind, base session id) for a legacy-ledger-shaped name.

    A legitimate journal for session `x.review-rejects` has the same flat
    filename as the 0.2.0 rejection ledger for session `x`. Valid rejection
    records distinguish the legacy ledger. Unreadable or malformed files are
    kept as ambiguous rather than made eligible for destructive cleanup.
    """
    if not path.name.endswith(LEGACY_REJECTION_SUFFIX):
        return None
    session_id = path.name[: -len(LEGACY_REJECTION_SUFFIX)]
    if SESSION_ID_RE.fullmatch(session_id) is None:
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError:
        return "ambiguous", session_id
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return "ambiguous", session_id
        prefix = os.read(fd, MAX_REJECTION_RECORD_BYTES + 1)
    finally:
        os.close(fd)
    if b"\n" not in prefix:
        return "ambiguous", session_id
    try:
        record = json.loads(prefix.split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return "ambiguous", session_id
    if isinstance(record, dict):
        if isinstance(record.get("event"), str):
            return "journal", session_id
        date = record.get("date")
        if (
            isinstance(record.get("reason"), str)
            and isinstance(record.get("raw"), str)
            and (date is None or isinstance(date, str))
        ):
            return "ledger", session_id
    return "ambiguous", session_id


def _migrate_legacy_rejection_ledger(state_dir: Path, session_id: str) -> None:
    source = state_dir / f"{session_id}{LEGACY_REJECTION_SUFFIX}"
    if _classify_legacy_rejection_path(source) != ("ledger", session_id):
        return

    destination_dir = state_dir / "review-rejects"
    destination_dir.mkdir(mode=0o700, exist_ok=True)
    destination = destination_dir / f"{session_id}.jsonl"
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        source.rename(destination)
        return
    if not stat.S_ISREG(metadata.st_mode):
        return

    source_flags = os.O_RDONLY
    destination_flags = os.O_RDWR | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        destination_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    try:
        destination_fd = os.open(destination, destination_flags)
        try:
            if not stat.S_ISREG(os.fstat(source_fd).st_mode) or not stat.S_ISREG(
                os.fstat(destination_fd).st_mode
            ):
                return
            original_size = os.fstat(destination_fd).st_size
            try:
                if (
                    original_size
                    and os.pread(destination_fd, 1, original_size - 1) != b"\n"
                ):
                    _write_all(destination_fd, b"\n")
                while chunk := os.read(source_fd, 64 * 1024):
                    _write_all(destination_fd, chunk)
                os.fsync(destination_fd)
            except OSError:
                try:
                    os.ftruncate(destination_fd, original_size)
                    os.fsync(destination_fd)
                except OSError:
                    pass
                raise
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    source.unlink()


def _cleanup_stale_sessions(state_dir: Path, current_session_id: str) -> None:
    cleanup_path = state_dir / "cleanup.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    cleanup_fd = os.open(cleanup_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(cleanup_fd).st_mode):
            raise AdapterError("cleanup lock is not a regular file")
        try:
            fcntl.flock(cleanup_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return

        cutoff = time.time() - _retention_days() * 24 * 60 * 60
        session_ids: list[str] = []
        seen: set[str] = set()
        candidate_entries = 0
        migration_attempts = 0
        with os.scandir(state_dir) as entries:
            for entry in entries:
                legacy = _classify_legacy_rejection_path(state_dir / entry.name)
                if legacy is not None:
                    kind, legacy_session_id = legacy
                    if kind != "journal":
                        candidate_entries += 1
                        if candidate_entries > MAX_CLEANUP_ENTRIES:
                            break
                        if (
                            kind == "ledger"
                            and migration_attempts < MAX_CLEANUP_SESSIONS
                        ):
                            migration_attempts += 1
                            with _session_cleanup_locks(
                                state_dir, legacy_session_id
                            ) as acquired:
                                if acquired:
                                    try:
                                        _migrate_legacy_rejection_ledger(
                                            state_dir, legacy_session_id
                                        )
                                    except OSError:
                                        pass
                        continue
                session_id = _session_id_from_runtime_name(entry.name)
                if session_id is None:
                    continue
                candidate_entries += 1
                if candidate_entries > MAX_CLEANUP_ENTRIES:
                    break
                if session_id == current_session_id or session_id in seen:
                    continue
                seen.add(session_id)
                session_ids.append(session_id)

        cleaned = 0
        for session_id in session_ids:
            if cleaned >= MAX_CLEANUP_SESSIONS:
                break
            paths = _session_data_paths(state_dir, session_id)
            if not paths:
                continue
            try:
                if max(path.stat().st_mtime for path in paths) >= cutoff:
                    continue
            except OSError:
                continue
            with _session_cleanup_locks(state_dir, session_id) as acquired:
                if not acquired:
                    continue
                paths = _session_data_paths(state_dir, session_id)
                if not paths:
                    continue
                try:
                    if max(path.stat().st_mtime for path in paths) >= cutoff:
                        continue
                except OSError:
                    continue
                complete = True
                # Keep the primary discovery artifacts until worker markers
                # are gone, so an interrupted cleanup remains discoverable.
                primary_paths = {
                    state_dir / f"{session_id}.state.json",
                    state_dir / f"{session_id}.jsonl",
                }
                ordered_paths = sorted(
                    paths,
                    key=lambda path: path in primary_paths,
                )
                for path in ordered_paths:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        complete = False
                        break
                if complete:
                    cleaned += 1
    finally:
        try:
            fcntl.flock(cleanup_fd, fcntl.LOCK_UN)
        finally:
            os.close(cleanup_fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short journal write")
        offset += written


@contextmanager
def _session_lock(session_id: str) -> Iterator[Path]:
    state_dir = _state_dir()
    lock_path = state_dir / f"{session_id}.journal.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
            raise AdapterError("session lock is not a regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield state_dir
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _new_state() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "completed_turns": [],
        "interesting_turns": [],
        "reviewed_interesting_turns": [],
        "reviewed_boundaries": [],
        "split_boundaries": [],
        "surfaced_project_directives": [],
        "maintenance_started": False,
    }


def _load_state_unlocked(state_dir: Path, session_id: str) -> dict[str, Any]:
    state_path = state_dir / f"{session_id}.state.json"
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(state_path, flags)
    except FileNotFoundError:
        return _new_state()
    try:
        data = os.read(fd, MAX_STATE_BYTES + 1)
    finally:
        os.close(fd)
    if not data or len(data) > MAX_STATE_BYTES:
        raise AdapterError("adapter state is empty or oversized")
    try:
        state = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdapterError("adapter state is corrupt") from exc
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        raise AdapterError("adapter state has an unsupported schema")
    state.setdefault("surfaced_project_directives", [])
    state.setdefault("maintenance_started", False)
    for field in (
        "completed_turns",
        "interesting_turns",
        "reviewed_interesting_turns",
        "surfaced_project_directives",
    ):
        values = state.get(field)
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise AdapterError(f"adapter state field {field} is corrupt")
    for field in ("reviewed_boundaries", "split_boundaries"):
        values = state.get(field)
        if not isinstance(values, list) or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in values
        ):
            raise AdapterError(f"adapter state field {field} is corrupt")
    if not isinstance(state["maintenance_started"], bool):
        raise AdapterError("adapter state field maintenance_started is corrupt")
    return state


def _resolve_corpus_location(
    cwd: str, state_dir: Path, session_id: str, state: dict[str, Any]
):
    """Resolve one event's corpus and retain only a shared positive record."""
    module = _cutover_state_module()
    if module is None:
        return None
    cached = state.get("external_corpus_cache")
    location, replacement = module.resolve_project_corpus_cached(cwd, cached)
    if replacement is not None:
        state["external_corpus_cache"] = replacement
    elif cached is not None:
        state.pop("external_corpus_cache", None)
    return location


def _save_state_unlocked(
    state_dir: Path, session_id: str, state: dict[str, Any]
) -> None:
    state_path = state_dir / f"{session_id}.state.json"
    temp_path = state_dir / (
        f".{session_id}.state.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp_path, flags, 0o600)
    try:
        encoded = json.dumps(state, separators=(",", ":")).encode("utf-8")
        _write_all(fd, encoded)
        os.fsync(fd)
    except BaseException:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    os.replace(temp_path, state_path)


def _run_startup_worker(
    path: Path,
    *,
    payload: bytes | None,
    env: dict[str, str],
) -> tuple[str | None, str | None]:
    if not path.is_file():
        return f"missing worker: {path}", None
    process: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.TemporaryFile() as worker_input:
            if payload is not None:
                worker_input.write(payload)
                worker_input.seek(0)
            process = subprocess.Popen(
                [str(path)],
                stdin=worker_input if payload is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            assert process.stdout is not None
            output_fd = process.stdout.fileno()
            raw_output = bytearray()
            deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
            while len(raw_output) <= STARTUP_OUTPUT_LIMIT_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(
                        [str(path)], STARTUP_TIMEOUT_SECONDS
                    )
                readable, _, _ = select.select([output_fd], [], [], remaining)
                if not readable:
                    raise subprocess.TimeoutExpired(
                        [str(path)], STARTUP_TIMEOUT_SECONDS
                    )
                chunk = os.read(
                    output_fd,
                    STARTUP_OUTPUT_LIMIT_BYTES + 1 - len(raw_output),
                )
                if not chunk:
                    break
                raw_output.extend(chunk)
            oversized = len(raw_output) > STARTUP_OUTPUT_LIMIT_BYTES
            if oversized and process.poll() is None:
                process.kill()
            remaining = max(0.001, deadline - time.monotonic())
            returncode = process.wait(timeout=remaining)
            process.stdout.close()
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if process is not None and process.stdout is not None:
            process.stdout.close()
        return f"could not run {path.name}: {exc}", None
    if oversized:
        return f"{path.name} produced oversized SessionStart context", None
    if returncode != 0:
        return f"{path.name} exited with status {returncode}", None
    if not raw_output.strip():
        return None, None
    try:
        worker_output = json.loads(raw_output)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return f"{path.name} produced invalid SessionStart context", None
    if path.name in {"scaffold-learnings.sh", "learnings-register.sh"}:
        if (
            not isinstance(worker_output, dict)
            or not set(worker_output) <= {"decision", "systemMessage"}
            or worker_output.get("decision") != "approve"
        ):
            return f"{path.name} produced invalid SessionStart context", None
        context = worker_output.get("systemMessage")
        if context is None:
            return None, None
        if (
            not isinstance(context, str)
            or not context.strip()
            or len(context.encode("utf-8")) > STARTUP_OUTPUT_LIMIT_BYTES
        ):
            return f"{path.name} produced invalid SessionStart context", None
        return None, context.strip()
    if not isinstance(worker_output, dict) or set(worker_output) != {
        "hookSpecificOutput"
    }:
        return f"{path.name} produced invalid SessionStart context", None
    hook_output = worker_output["hookSpecificOutput"]
    if not isinstance(hook_output, dict) or set(hook_output) != {
        "hookEventName",
        "additionalContext",
    }:
        return f"{path.name} produced invalid SessionStart context", None
    context = hook_output.get("additionalContext")
    if (
        hook_output.get("hookEventName") != "SessionStart"
        or not isinstance(context, str)
        or not context.strip()
    ):
        return f"{path.name} produced invalid SessionStart context", None
    if len(context.encode("utf-8")) > STARTUP_OUTPUT_LIMIT_BYTES:
        return f"{path.name} produced oversized SessionStart context", None
    return None, context.strip()


def _read_learned_gotchas() -> tuple[str | None, str | None]:
    configured = os.environ.get("LEARNINGS_GOTCHAS_FILE")
    path = (
        Path(configured).expanduser()
        if configured
        else Path.home() / ".claude" / "rules" / "learned-gotchas.md"
    )
    if not path.is_absolute():
        return None, "learned-gotchas path is not absolute"
    flags = os.O_RDONLY | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "learned-gotchas file is unreadable"
    try:
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > GOTCHAS_LIMIT_BYTES
            ):
                return None, "learned-gotchas file is irregular or oversized"
            chunks: list[bytes] = []
            remaining = GOTCHAS_LIMIT_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
        except OSError:
            return None, "learned-gotchas file is unreadable"
    finally:
        os.close(fd)
    if (
        len(data) > GOTCHAS_LIMIT_BYTES
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or len(data) != after.st_size
    ):
        return None, "learned-gotchas file changed while being read"
    try:
        body = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "learned-gotchas file is not valid UTF-8"
    # The file is hand-managed since 2026-09-07 (`learn rules` is gone); the
    # header only has to identify it as the learned-gotchas file.
    if not body.startswith("<!-- learned-gotchas:"):
        return None, "learned-gotchas file has an unsupported header"
    return body.strip(), None


def _has_project_learnings(cwd: str) -> bool:
    current = Path(cwd).resolve()
    project_root = current
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            project_root = candidate
            break
    if (project_root / "LEARNINGS.md").is_file():
        return True
    if any(path.is_file() for path in project_root.glob("LEARNINGS-*.md")):
        return True
    # A root portable export alone: current state in legacy mode, but a stale
    # artifact once the identity catalog owns portables (Task 6) — the primary
    # project corpus above remains the opt-in signal. Fail-open to legacy.
    module = _load_optional_state_module()
    if module is not None:
        try:
            if module.state_paths().active:
                return False
        except Exception:
            pass
    return any(path.is_file() for path in project_root.glob("*-PORTABLE-LEARNINGS.md"))


class ContextPart(NamedTuple):
    """One structured unit entering `_bounded_additional_context` (Part 6E
    decision 15 [rev 7]): the ONE concrete type the assembler accepts, so a
    heterogeneous flat-string mix can never silently misclassify a worker
    context as bullet-truncatable. `kind` is "bullet" (a header plus
    "- "-prefixed lines, fit at bullet boundaries) or "text" (no parseable
    interior boundary -- fit whole or dropped whole). `priority` orders the
    RESERVATION pass (lower first); every current part shares
    `DEFAULT_PART_PRIORITY` except the stale-portable warning
    (`STALE_PORTABLE_PRIORITY`)."""

    kind: str
    priority: int
    body: str


def _fit_bullet_block(body: str, budget: int) -> str | None:
    """Fit a bullet-structured block within `budget` encoded bytes: the
    header (everything before the first "- "-prefixed line) plus AT LEAST
    ONE complete bullet, or None when even that doesn't fit -- the whole
    block yields rather than emit a dangling header alone (Part 6E
    decision 15 [rev 6])."""
    lines = body.split("\n")
    split_at = next(
        (i for i, line in enumerate(lines) if line.startswith("- ")), len(lines)
    )
    header_lines, bullet_lines = lines[:split_at], lines[split_at:]
    if not bullet_lines:
        # No parseable bullet structure -- whole-or-drop, same as text.
        return body if len(body.encode("utf-8")) <= budget else None
    header = "\n".join(header_lines)
    kept: list[str] = []
    for line in bullet_lines:
        candidate_lines = ([header] if header else []) + kept + [line]
        if len("\n".join(candidate_lines).encode("utf-8")) > budget:
            break
        kept.append(line)
    if not any(line.startswith("- ") for line in kept):
        return None
    result_lines = ([header] if header else []) + kept
    return "\n".join(result_lines)


def _bounded_additional_context(parts: list[ContextPart]) -> str | None:
    """Part-aware assembly under SessionStart's registered 6000-byte cap.

    Two-pass: parts are considered in `priority` order (the project block
    is RESERVED first, so an oversized lower-priority prefix can never
    starve it out); a "bullet" part truncates at bullet boundaries (header
    plus >=1 bullet, else the whole block yields); a "text" part fits
    whole or is dropped whole. Kept parts are then re-joined in their
    ORIGINAL list order, not fit order, so unrelated content ordering is
    unaffected by the reservation pass."""
    if not parts:
        return None
    budget = ADDITIONAL_CONTEXT_LIMIT_BYTES
    order = sorted(range(len(parts)), key=lambda i: parts[i].priority)
    kept: dict[int, str] = {}

    def _joined(candidate: dict[int, str]) -> str:
        return "\n\n".join(candidate[i] for i in sorted(candidate))

    for i in order:
        part = parts[i]
        if not part.body.strip():
            continue
        used = len(_joined(kept).encode("utf-8")) if kept else 0
        separator = 2 if kept else 0  # "\n\n" between this part and a prior one
        remaining = budget - used - separator
        if remaining <= 0:
            continue
        if part.kind == "bullet":
            fitted = _fit_bullet_block(part.body, remaining)
        else:
            encoded = part.body.encode("utf-8")
            fitted = part.body if len(encoded) <= remaining else None
        if fitted is None or not fitted.strip():
            continue
        candidate = dict(kept)
        candidate[i] = fitted
        if len(_joined(candidate).encode("utf-8")) <= budget:
            kept = candidate
    if not kept:
        return None
    return _joined(kept)


def _shared_context_parts(
    cwd: str, *, corpus_location=None
) -> tuple[list[ContextPart], list[str]]:
    contexts: list[ContextPart] = []
    failures: list[str] = []
    gotchas, gotchas_failure = _read_learned_gotchas()
    if gotchas_failure is not None:
        failures.append(gotchas_failure)
    if gotchas is not None:
        contexts.append(
            ContextPart(
                "bullet",
                DEFAULT_PART_PRIORITY,
                (
                    "Shared learned gotchas (managed by the LEARNINGS system; "
                    + "apply only when relevant):\n"
                    + gotchas
                ),
            )
        )
    if corpus_location is not None or _has_project_learnings(cwd):
        learn_cli = _learn_cli_command()
        contexts.append(
            ContextPart(
                "text",
                DEFAULT_PART_PRIORITY,
                "This project has a shared LEARNINGS corpus. Before gotcha-prone "
                "work, use the bundled search-learnings skill or "
                f"`{learn_cli} search <terms>`; add durable observations with "
                f"`{learn_cli} add`.",
            )
        )
    return contexts, failures


# Appended (with `.format(corpus_root=...)`) to any agent-facing notice built
# in external-corpus mode, AFTER sanitizing that notice's local-filename
# imperatives — a trailing note contradicts a preceding "read LEARNINGS.md"
# sentence rather than fixing it. Byte-identical copy lives in
# hooks/learning-on-start.py (parity-pinned by
# test) — this repo deliberately duplicates helpers between hosts rather than
# cross-importing.
CENTRAL_STORE_NOTE = (
    "Note: this project's corpus lives in the central store at {corpus_root} — "
    "not as files in this checkout. `learn` commands and the background workers "
    "read and write the central copy; absent local LEARNINGS files are expected "
    "and must not be created or restored."
)

# Duplicated in hooks/learning-on-start.py (standalone-file convention); pinned by
# tests/test_learning_on_start.py::test_stale_portable_warning_matches_codex_adapter.
STALE_PORTABLE_SUFFIX = "-PORTABLE-LEARNINGS.md"
STALE_PORTABLE_NOTE = (
    "Stale portable LEARNINGS copy: this project's corpus is external, but git "
    "still tracks {names}. Nothing reads it. Remove it on a branch with "
    "`git -C {root} rm -- {names_args}` and land the change through a PR."
)
# Reserved before the default-priority parts so the shared gotchas block can
# never crowd it out of the SessionStart byte budget.
STALE_PORTABLE_PRIORITY = 0


def _stale_portable_warning(project_root: str) -> str | None:
    """Warn when an external-mode project still tracks a root-level
    `*-PORTABLE-LEARNINGS.md` at HEAD (ls-tree, not ls-files: a file deleted
    in the working tree but not yet committed must still be reported).
    Any failure returns None — a notice must never break session start."""
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
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
    names = sorted(
        line
        for line in proc.stdout.splitlines()
        if line.endswith(STALE_PORTABLE_SUFFIX)
    )
    if not names:
        return None
    # `-C <root>`: ls-tree names are root-relative, and a session may start
    # in a subdirectory.
    return STALE_PORTABLE_NOTE.format(
        names=", ".join(names),
        names_args=" ".join(shlex.quote(name) for name in names),
        root=shlex.quote(project_root),
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


def _inject_resolved_paths(text: str, _cwd: str) -> str:
    """Keep host guidance usable when the shared CLI is not on PATH."""
    return re.sub(
        r"\blearn (add|search|index|status|stats|state|metrics|deploy|cleanup|"
        r"corpus|migrate-ids)\b",
        lambda match: f"{_learn_cli_command()} {match.group(1)}",
        text,
    )


def _is_index_mode(learnings_path: str) -> bool:
    try:
        text = Path(learnings_path).read_text(encoding="utf-8")
    except OSError:
        return False
    return "Index of topic-specific learnings." in text or bool(
        re.search(r"^###\s+.+\s+→\s+LEARNINGS-.+\.md", text, re.MULTILINE)
    )


def _orientation_context(location) -> str:
    """Build fresh location-neutral orientation facts for one host event."""
    if location.mode == "external":
        module = _load_optional_state_module()
        assert module is not None
        facts = module.read_corpus_orientation_facts(location)
        cwd = str(location.project_root)
        if facts.mode == "empty":
            body = "This project has a LEARNINGS corpus (currently empty)."
        elif facts.mode == "index":
            heading = (
                "This project has a LEARNINGS knowledge base ({subfile_count} "
                + "topic subfiles, indexed in LEARNINGS.md)."
            )
            body = (
                FIRST_MESSAGE_BODY_INDEX.replace(
                    heading,
                    (
                        "This project has a LEARNINGS corpus ({subfile_count} "
                        + "topic subfiles, index mode)."
                    ),
                )
                .replace("read LEARNINGS.md FIRST", "read the corpus index FIRST")
                .format(subfile_count=facts.topic_count)
            )
        else:
            body = FIRST_MESSAGE_BODY_MONOLITH.replace(
                "This project has a LEARNINGS.md ({line_count} lines, monolith mode).",
                (
                    "This project has a LEARNINGS corpus ({line_count} lines, "
                    + "monolith mode)."
                ),
            ).format(line_count=facts.line_count)
        body += "\n\n" + CENTRAL_STORE_NOTE.format(
            corpus_root=str(location.corpus_root)
        )
        return _inject_resolved_paths(body, cwd)

    learnings_path = location.corpus_root / "LEARNINGS.md"
    if not learnings_path.is_file():
        return ""
    if _is_index_mode(str(learnings_path)):
        count = len(tuple(location.corpus_root.glob("LEARNINGS-*.md")))
        return _inject_resolved_paths(
            FIRST_MESSAGE_BODY_INDEX.format(subfile_count=count),
            str(location.project_root),
        )
    try:
        line_count = len(learnings_path.read_text(encoding="utf-8").splitlines())
    except OSError:
        return ""
    return _inject_resolved_paths(
        FIRST_MESSAGE_BODY_MONOLITH.format(line_count=line_count),
        str(location.project_root),
    )


def _is_corpus_resolution_error(exc: BaseException) -> bool:
    module = _load_optional_state_module()
    error_type = getattr(module, "CorpusResolutionError", None)
    return isinstance(error_type, type) and isinstance(exc, error_type)


def _corpus_routing_warning(event: str) -> str:
    return (
        f"LEARNINGS {event} was incomplete: shared corpus routing was "
        "unavailable; authority-sensitive workers were not run."
    )


def _startup_registration_worker(hooks_dir: Path) -> Path:
    """Prefer the common registration worker; retain the legacy wrapper only
    for incomplete rollback fixtures."""
    shared = _bin_dir() / "learnings-register.sh"
    if shared.is_file() and os.access(shared, os.X_OK):
        return shared
    return hooks_dir / "scaffold-learnings.sh"


def _handle_session_start(
    payload: dict[str, Any],
) -> tuple[str | None, str | None]:
    _permission_mode(payload)
    source = _required_string(payload, "source")
    # `fork` is a new thread cloned from an existing one; it gets the full
    # startup orientation. Rejecting it left forked threads with no shared
    # context (Codex runtime replay, 2026-10-22).
    if source not in {
        "startup",
        "resume",
        "clear",
        "compact",
        "fork",
    }:
        raise PayloadError("source is unsupported")

    hooks_dir = _hooks_dir()
    cwd = _required_string(payload, "cwd")
    state_dir = _state_dir()
    _cleanup_stale_sessions(state_dir, payload["session_id"])
    session_id = payload["session_id"]
    corpus_error = False
    routing_warning: str | None = None
    with _session_lock(session_id) as locked_state_dir:
        state = _load_state_unlocked(locked_state_dir, session_id)
        before_cache = state.get("external_corpus_cache")
        try:
            location = _resolve_corpus_location(
                cwd, locked_state_dir, session_id, state
            )
        except Exception as exc:
            if not _is_corpus_resolution_error(exc):
                raise
            location = None
            corpus_error = True
            routing_warning = _corpus_routing_warning("startup")
        if state.get("external_corpus_cache") != before_cache:
            _save_state_unlocked(locked_state_dir, session_id, state)
    worker_cwd = str(location.project_root) if location is not None else cwd
    env = os.environ.copy()
    env["CLAUDE_PROJECT_DIR"] = worker_cwd
    commit_payload = dict(payload)
    commit_payload["transcript_path"] = str(
        state_dir / f"{payload['session_id']}.jsonl"
    )
    commit_encoded = json.dumps(commit_payload, separators=(",", ":")).encode("utf-8")
    failures: list[str] = []
    contexts: list[ContextPart] = []
    # External corpora need neither checkout snapshots nor registration.
    if not corpus_error and (location is None or location.mode != "external"):
        workers = (
            (hooks_dir / "commit-learnings.sh", commit_encoded),
            (_startup_registration_worker(hooks_dir), None),
        )
    else:
        workers = ()
    for path, worker_input in workers:
        failure, context = _run_startup_worker(
            path,
            payload=worker_input,
            env=env,
        )
        if failure is not None:
            failures.append(failure)
        if context is not None:
            contexts.append(ContextPart("text", DEFAULT_PART_PRIORITY, context))

    # Registration may have created a fresh external authority record. Resolve
    # again under the session lock so this same SessionStart can orient the
    # model and persist the positive cache.
    if not corpus_error:
        with _session_lock(session_id) as locked_state_dir:
            state = _load_state_unlocked(locked_state_dir, session_id)
            before_cache = state.get("external_corpus_cache")
            try:
                location = _resolve_corpus_location(
                    cwd, locked_state_dir, session_id, state
                )
            except Exception as exc:
                if not _is_corpus_resolution_error(exc):
                    raise
                location = None
                corpus_error = True
                routing_warning = _corpus_routing_warning("startup")
            if state.get("external_corpus_cache") != before_cache:
                _save_state_unlocked(locked_state_dir, session_id, state)
        worker_cwd = str(location.project_root) if location is not None else cwd

    shared_contexts, shared_failures = _shared_context_parts(
        worker_cwd, corpus_location=location
    )
    contexts.extend(shared_contexts)
    failures.extend(shared_failures)
    if location is not None and not corpus_error:
        try:
            orientation = _orientation_context(location)
        except Exception as exc:
            if not _is_corpus_resolution_error(exc):
                raise
            corpus_error = True
            routing_warning = _corpus_routing_warning("startup")
        else:
            if orientation:
                contexts.insert(
                    0,
                    ContextPart("text", DEFAULT_PART_PRIORITY, orientation),
                )
            if location.mode == "external":
                stale_portable = _stale_portable_warning(str(location.project_root))
                if stale_portable:
                    contexts.append(
                        ContextPart("text", STALE_PORTABLE_PRIORITY, stale_portable)
                    )
    if source == "compact":
        contexts.append(
            ContextPart(
                "text",
                DEFAULT_PART_PRIORITY,
                "The conversation was compacted. Re-check active files and the "
                "project's shared LEARNINGS before relying on earlier context.",
            )
        )

    messages = []
    if routing_warning is not None:
        messages.append(routing_warning)
    if failures:
        messages.append("LEARNINGS startup was incomplete: " + "; ".join(failures))
    warning = "\n\n".join(messages) if messages else None
    contexts.sort(key=lambda part: part.priority)
    return warning, _bounded_additional_context(contexts)


def _emit_system_message(message: str) -> None:
    bounded = _bounded_text(message)["value"]
    print(json.dumps({"systemMessage": bounded}, separators=(",", ":")))


def _emit_hook_output(
    event: str, *, context: str | None, system_message: str | None
) -> None:
    output: dict[str, Any] = {}
    if system_message is not None:
        output["systemMessage"] = _bounded_text(system_message)["value"]
    if context is not None:
        output["hookSpecificOutput"] = {
            "hookEventName": event,
            "additionalContext": context,
        }
    if output:
        print(json.dumps(output, separators=(",", ":")))


def _session_class() -> str:
    """LEARNINGS_SESSION_CLASS: interactive (default) | automation | harness.
    Unknown values fall open to interactive with one stderr warning — this
    gate must never be able to block a session. Same contract as the Claude
    hooks' duplicated helper (see CLAUDE.md)."""
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


def main() -> int:
    # Harness sessions must not run startup workers or touch runtime state.
    if _session_class() == "harness":
        _drain_stdin()
        return 0
    if len(sys.argv) > 1:
        return 0
    if os.environ.get("LEARNINGS_REVIEW_NESTED") == "1":
        return 0
    event: str | None = None
    context: str | None = None
    try:
        payload = _load_payload()
        event = payload["hook_event_name"]
        if event == "SessionStart":
            message, context = _handle_session_start(payload)
        else:
            raise PayloadError(f"unsupported hook event: {event}")
    except PayloadError:
        return 0
    except (AdapterError, OSError, ValueError, RecursionError) as exc:
        if event is not None:
            _emit_system_message(f"LEARNINGS adapter could not process {event}: {exc}")
        return 0
    if context is not None:
        _emit_hook_output(event, context=context, system_message=message)
    elif message is not None:
        _emit_system_message(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
