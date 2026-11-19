#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Provider-neutral state, identity, corpus authority and install settings.

Activation selects the neutral generation; existing legacy state remains
available until an explicit transition changes its authority.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlparse

ACTIVATION_SCHEMA_VERSION = 1
GENERATION_SCHEMA_VERSION = 1
CORPUS_LOCATION_COMPAT_REVISION = 1
CORPUS_CUTOVER_COMPAT_REVISION = 1
CORPUS_DEPLOYMENT_STATE_SCHEMA_VERSION = 1
CORPUS_DEPLOYMENT_STATE_NAME = "cutover-deployment.json"
_ACTIVATION_NAME = "activation.json"
_GENERATION_NAME = "generation.json"
_GENERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

ACTIVATION_ABSENT = "absent"
ACTIVATION_VALID = "valid"
ACTIVATION_INVALID = "invalid"
_REMOTE_SCP_RE = re.compile(r"^(?:(?P<user>[^@/:]+)@)?(?P<host>[^/:]+):(?P<path>.+)$")
_SLUG_INVALID_RE = re.compile(r"[^a-z0-9-]+")
_DASH_RE = re.compile(r"-+")


class IdentityResolutionError(RuntimeError):
    pass


class InstallSettingsError(RuntimeError):
    """Invalid opt-in settings; callers must skip before writes or network."""


@dataclass(frozen=True)
class InstallSettings:
    configured: bool = False
    auto_enroll: bool = False
    auto_commit: bool = False
    auto_push: bool = False
    owned_remote_pattern: str | None = None
    snapshot_email: str | None = None


def install_settings_path() -> Path:
    override = os.environ.get("LEARNINGS_SETTINGS_FILE")
    if override is not None:
        path = Path(override)
    else:
        configured = os.environ.get("XDG_CONFIG_HOME")
        root = Path(configured) if configured else Path.home() / ".config"
        path = root / "learnings-md-system" / "settings.json"
    if not path.is_absolute():
        raise InstallSettingsError("settings:nonabsolute-path")
    return path


def _settings_email(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 254 or re.fullmatch(r"[^\s@]+@[^\s@]+", value) is None:
        raise InstallSettingsError("settings:invalid-snapshot-email")
    return value


def load_install_settings() -> InstallSettings:
    """Read one bounded regular file; absent settings mean no automation.

    Environment switches can disable actions, never enable them. Identity and
    owner overrides change only the corresponding explicitly enabled action.
    """
    path = install_settings_path()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return InstallSettings()
    except OSError as exc:
        raise InstallSettingsError("settings:unreadable-file") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise InstallSettingsError("settings:unsafe-file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise InstallSettingsError("settings:oversized-file")
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise InstallSettingsError("settings:invalid-json") from exc
    finally:
        if descriptor != -1:
            os.close(descriptor)
    keys = {"schema_version", "auto_enroll", "auto_commit", "auto_push", "owned_remote_pattern", "snapshot_email"}
    if (
        not isinstance(data, dict)
        or set(data) - keys
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or any(type(data.get(key, False)) is not bool for key in ("auto_enroll", "auto_commit", "auto_push"))
    ):
        raise InstallSettingsError("settings:invalid-schema")
    enroll = data.get("auto_enroll", False)
    commit = data.get("auto_commit", False) and os.environ.get("LEARNINGS_AUTO_COMMIT") != "0"
    push = data.get("auto_push", False) and os.environ.get("LEARNINGS_AUTO_PUSH") != "0"
    pattern = data.get("owned_remote_pattern")
    email = _settings_email(data.get("snapshot_email"))
    if (enroll or push) and "LEARNINGS_ENROLLMENT_OWNER_RE" in os.environ:
        pattern = os.environ["LEARNINGS_ENROLLMENT_OWNER_RE"]
    if pattern is not None:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 2048:
            raise InstallSettingsError("settings:invalid-owned-remote-pattern")
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise InstallSettingsError("settings:invalid-owned-remote-pattern") from exc
    if commit and "LEARNINGS_SNAPSHOT_EMAIL" in os.environ:
        email = _settings_email(os.environ["LEARNINGS_SNAPSHOT_EMAIL"])
    return InstallSettings(True, enroll, commit, push, pattern, email)


INSTALL_SETTINGS_COMPATIBILITY_NAME = "install-settings-compatibility.json"
INSTALL_SETTINGS_COMPATIBILITY = {"schema_version": 1, "defaults": "explicit-opt-in"}


def check_install_settings_upgrade(core_root: Path | str) -> None:
    """Refuse an implicit-policy upgrade before deploy changes any files."""
    settings = load_install_settings()
    core = Path(core_root)
    marker = core / INSTALL_SETTINGS_COMPATIBILITY_NAME
    if marker.exists() or marker.is_symlink():
        try:
            record = _read_json_record(marker)
        except (OSError, ValueError) as exc:
            raise InstallSettingsError("settings:invalid-install-compatibility") from exc
        if record != INSTALL_SETTINGS_COMPATIBILITY or type(record.get("schema_version")) is not int:
            raise InstallSettingsError("settings:invalid-install-compatibility")
        return
    if settings.configured:
        return
    neutral = _neutral_root()
    if neutral is None:
        raise InstallSettingsError("settings:invalid-state-root")
    legacy = default_legacy_root()
    try:
        legacy_state = legacy.is_dir() and any(legacy.iterdir()) and not _deployment_owned_legacy_artifacts_only(legacy)
    except OSError as exc:
        raise InstallSettingsError("settings:legacy-state-unreadable") from exc
    old_runtime = (
        (core / "bin" / "learn").exists()
        or (neutral / CORPUS_DEPLOYMENT_STATE_NAME).exists()
        or (Path.home() / ".claude" / "bin" / "learn").exists()
        or legacy_state
    )
    if old_runtime and not settings.configured:
        raise InstallSettingsError("settings:explicit-upgrade-profile-required")


def write_install_settings_compatibility(core_root: Path | str) -> None:
    """Record default-safe install provenance before deploy copies bytes.

    Deploy holds its machine lock and has already passed the read-only upgrade
    guard. The marker says which defaults the installation began with; it is
    not a completion stamp. Interrupted new installs may therefore retry.
    """
    root = Path(core_root)
    root.mkdir(parents=True, exist_ok=True)
    _replace_json_fsynced(root / INSTALL_SETTINGS_COMPATIBILITY_NAME, INSTALL_SETTINGS_COMPATIBILITY)


class ProjectRootError(ValueError):
    pass


class CorpusResolutionError(RuntimeError):
    """An authoritative external corpus cannot safely be consumed."""


class CorpusMutationError(CorpusResolutionError):
    """A checked corpus mutation could not be safely completed."""


class CorpusLockTimeoutError(CorpusMutationError):
    """The activity or identity leg exhausted a session's one deadline."""


@dataclass(frozen=True)
class StatePaths:
    """The current canonical root plus legacy and neutral locations.

    The small interface intentionally hides activation parsing and root safety
    from consumers; consumers only choose a named child under ``root``.
    """

    root: Path
    legacy_root: Path
    neutral_root: Path
    active: bool

    def child(self, *parts: str) -> Path:
        return self.root.joinpath(*parts)


@dataclass(frozen=True)
class ProjectIdentity:
    canonical: str
    display: str
    key: str
    project_root: Path | None = field(default=None, compare=False)


@dataclass(frozen=True)
class CorpusLocation:
    """One project's authoritative corpus without changing its code root."""

    project_root: Path
    project_key: str
    corpus_root: Path
    lock_path: Path
    mode: str


@dataclass(frozen=True)
class CorpusSnapshot:
    """Immutable fd-verified corpus bytes decoded for one consumer pass."""

    path: Path
    name: str
    text: str
    size_bytes: int
    st_dev: int
    st_ino: int


@dataclass(frozen=True)
class CorpusTransitionFile:
    """One fd-validated legacy corpus input selected for a cutover plan."""

    name: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class CorpusTransitionPlan:
    """Immutable, report-only description of one legacy corpus import.

    The plan deliberately carries names, digests, and paths only.  A later
    apply must recompute every value under its transition locks rather than
    trusting this preview.
    """

    project_root: str
    canonical_identity: str
    identity_key: str
    project_key: str
    primary_status: str
    source_files: tuple[CorpusTransitionFile, ...]
    target_digest: str
    target_revision: str
    lesson_multiset_digest: str
    lesson_count: int
    worktree_roots: tuple[str, ...]
    structural_lock_paths: tuple[str, ...]
    independent_clone_roots: tuple[str, ...]
    identity_lock_path: str
    projection_path: str
    projection_id: str
    deployment_status: str
    deployment_revision: int | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]
    # An empty roster preserves the ordinary strict import route.  These
    # fields are frozen again under the maintenance locks for the deliberately
    # narrow historic-corpus migration route.
    legacy_migration_roster_path: str | None = None
    legacy_migration_roster_sha256: str | None = None
    legacy_migration_row_sha256: str | None = None
    retained_archives: tuple[CorpusTransitionFile, ...] = ()
    legacy_migration_superseded_audit_sha256: str | None = None
    legacy_migration_archives_require_exact: bool = True
    legacy_migration_authority_recovery: bool = False
    legacy_migration_roster_accepted: bool = False


@dataclass(frozen=True)
class CorpusReimportPlan:
    """Immutable external-authority replacement plan for ``corpus import``.

    This is intentionally not a legacy ``CorpusTransitionPlan`` with a few
    optional fields.  Re-import has an existing mutable authority to freeze,
    a checkout projection baseline, and one explicitly authorized external
    loss decision.
    """

    project_root: str
    canonical_identity: str
    identity_key: str
    project_key: str
    active_revision: str
    previous_revision: str | None
    frozen_revision: str
    state: str
    source_files: tuple[CorpusTransitionFile, ...]
    repository_files: tuple[tuple[str, str], ...]
    corpus_files: tuple[tuple[str, str], ...]
    projection_repository_files: tuple[tuple[str, str], ...]
    projection_corpus_files: tuple[tuple[str, str], ...]
    projection_revision: str | None
    projection_sha256: str | None
    target_digest: str
    target_revision: str
    lesson_multiset_digest: str
    lesson_count: int
    worktree_roots: tuple[str, ...]
    structural_lock_paths: tuple[str, ...]
    independent_clone_roots: tuple[str, ...]
    identity_lock_path: str
    projection_path: str
    projection_id: str
    deployment_status: str
    deployment_revision: int | None
    replace_external: bool
    external_loss: tuple[str, ...]
    pending_projection_repair: bool
    blockers: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class CorpusTransitionOutcome:
    """The durable result of one offline project-corpus transition."""

    status: str
    revision: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]
    plan: CorpusTransitionPlan | CorpusReimportPlan | CorpusRelinkPlan | None


@dataclass(frozen=True)
class BootstrapOutcome:
    """Result of the one permitted empty-machine initialization path."""

    status: str
    generation: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class FreshNeutralStateCheck:
    """Freshness proof for bootstrap: expected conflict versus failed inspection."""

    status: str
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class RegistrationOutcome:
    """Bounded result for a startup registration attempt."""

    status: str
    project_root: str
    project_key: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class CorpusRelinkPlan:
    """Immutable, report-only description of one orphaned-checkout relink.

    Unlike ``CorpusTransitionPlan`` this never creates a revision: relink
    only adds the checkout's current root and canonical identity to an
    existing active record whose prior roots are all proven absent.
    """

    project_root: str
    canonical_identity: str | None
    project_key: str
    active_revision: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class CorpusRollbackPlan:
    """Immutable, report-only description of one project corpus escape."""

    project_root: str
    canonical_identity: str
    identity_key: str
    project_key: str
    active_revision: str | None
    previous_revision: str | None
    freeze_revision: str | None
    repository_files: tuple[tuple[str, str], ...]
    corpus_files: tuple[tuple[str, str], ...]
    projection_path: str
    projection_revision: str | None
    projection_repository_files: tuple[tuple[str, str], ...]
    projection_corpus_files: tuple[tuple[str, str], ...]
    worktree_roots: tuple[str, ...]
    structural_lock_paths: tuple[str, ...]
    identity_lock_path: str
    transaction_path: str
    target_kind: str | None
    source_authority_sha256: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]
    retained_archives: tuple[CorpusTransitionFile, ...] = ()


@dataclass(frozen=True)
class CorpusSynchronizationSnapshot:
    """One immutable, read-only comparison of a checkout and its authority.

    Callers receive the complete classification and deltas through this single
    seam; they do not select files or reproduce the synchronization matrix.
    """

    project_root: str
    projection_id: str
    project_key: str | None
    active_revision: str | None
    previous_revision: str | None
    repository_files: tuple[tuple[str, str], ...]
    corpus_files: tuple[tuple[str, str], ...]
    projection_repository_files: tuple[tuple[str, str], ...]
    projection_corpus_files: tuple[tuple[str, str], ...]
    projection_revision: str | None
    projection_sha256: str | None
    repository_added: tuple[str, ...]
    repository_removed: tuple[str, ...]
    repository_changed: tuple[str, ...]
    external_added: tuple[str, ...]
    external_removed: tuple[str, ...]
    external_changed: tuple[str, ...]
    deployment_status: str
    deployment_revision: int | None
    identity_lock_path: str | None
    state: str
    blockers: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class CorpusPublishPlan:
    project_root: str
    project_key: str | None
    active_revision: str | None
    state: str
    repository_files: tuple[tuple[str, str], ...]
    corpus_files: tuple[tuple[str, str], ...]
    projection_sha256: str | None
    blockers: tuple[str, ...]
    operation: str = "publish"
    replace_repository: bool = False
    modified_owned: tuple[str, ...] = ()
    obsolete_owned: tuple[str, ...] = ()
    foreign_unowned: tuple[str, ...] = ()
    recovery_target_files: tuple[tuple[str, str], ...] = ()
    pending_operation: str | None = None


@dataclass(frozen=True)
class AbandonExternalPlan:
    """Raw active authority records which machine break-glass would move."""

    records: tuple[tuple[str, str, str | None, int | None, tuple[str, ...], tuple[str, ...], str | None], ...]


@dataclass(frozen=True)
class SemanticCorpusSnapshot:
    """One complete, fd-verified corpus view for a semantic worker."""

    files: tuple[CorpusSnapshot, ...]
    digest: str


@dataclass(frozen=True)
class CorpusOrientationFacts:
    """Bounded host orientation without returning corpus text."""

    line_count: int
    mode: str
    topic_count: int


@dataclass(frozen=True)
class CorpusMutationBatch:
    """One ordered structural change, expressed only from checked snapshots."""

    replacements: tuple[tuple[CorpusSnapshot, str], ...] = ()
    creations: tuple[tuple[str, str], ...] = ()
    authority_replacement: tuple[CorpusSnapshot, str] | None = None
    removals: tuple[CorpusSnapshot, ...] = ()


@dataclass(frozen=True)
class CorpusMutationResult:
    """The exact post-commit corpus states, without an unlocked reread."""

    committed: Mapping[Path, CorpusSnapshot]


@dataclass(frozen=True)
class ActivationStatus:
    """Structured single reporter for the activation record (decision 4).

    ``state`` is ABSENT / VALID / INVALID; ``record_path`` names the record
    (None only when no neutral root exists to hold one); ``reason`` carries
    the exact validation failure (None when valid); ``root`` is the resolved
    current state root (legacy unless valid)."""

    state: str
    record_path: Path | None
    reason: str | None
    generation: str | None
    root: Path


def _home() -> Path:
    return Path(os.environ.get("HOME") or Path.home())


def _safe_absolute(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        return None
    return path


def _neutral_root() -> Path | None:
    configured = os.environ.get("XDG_STATE_HOME")
    base = _safe_absolute(configured) if configured else _home() / ".local" / "state"
    return base / "learnings-md-system" if base is not None else None


_ACTIVATION_MAX_BYTES = 64 * 1024


def _read_activation_capped(path: Path) -> bytes | None:
    """fd-bound activation read (O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG +
    nlink==1, size cap enforced on the fd) — the house shared-dir pattern.
    At most cap+1 bytes are ever materialized: an oversized record is
    rejected on the fd's fstat size before any body read, and the post-read
    length check covers a file grown between stat and read. Returns None for
    an oversized, non-regular, or multi-linked record; propagates
    FileNotFoundError/OSError from os.open."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_size > _ACTIVATION_MAX_BYTES
        ):
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(_ACTIVATION_MAX_BYTES + 1)
        if len(raw) > _ACTIVATION_MAX_BYTES:
            return None
        return raw
    finally:
        if fd != -1:
            os.close(fd)


def _valid_generation_id(generation: object) -> bool:
    return isinstance(generation, str) and bool(_GENERATION_ID_RE.match(generation))


def build_activation_record(generation: str) -> dict:
    """The ONE activation schema constructor; fixtures must come through it."""
    if not _valid_generation_id(generation):
        raise ValueError(f"invalid generation id: {generation!r}")
    return {
        "schema_version": ACTIVATION_SCHEMA_VERSION,
        "active": True,
        "generation": generation,
    }


def build_generation_record(
    generation: str, *, source_inventory_digest: str, staged_manifest_digest: str
) -> dict:
    """The ONE generation.json schema constructor (3C decision 4): both the
    source inventory digest and the staged-content manifest digest are
    REQUIRED, shape-checked 64-hex. Full digest re-verification (rehashing
    trees) happens only at the apply/adoption/reactivate transitions."""
    if not _valid_generation_id(generation):
        raise ValueError(f"invalid generation id: {generation!r}")
    for label, value in (
        ("source_inventory_digest", source_inventory_digest),
        ("staged_manifest_digest", staged_manifest_digest),
    ):
        if not isinstance(value, str) or not _SHA256_HEX_RE.match(value):
            raise ValueError(f"{label} must be 64 lowercase hex chars")
    return {
        "schema_version": GENERATION_SCHEMA_VERSION,
        "generation": generation,
        "source_inventory_digest": source_inventory_digest,
        "staged_manifest_digest": staged_manifest_digest,
    }


def _activation_is_valid(record: object) -> bool:
    return (
        isinstance(record, dict)
        and record.get("schema_version") == ACTIVATION_SCHEMA_VERSION
        and record.get("active") is True
        and _valid_generation_id(record.get("generation"))
    )


def _generation_is_valid(record: object, generation: str) -> bool:
    return (
        isinstance(record, dict)
        and record.get("schema_version") == GENERATION_SCHEMA_VERSION
        and record.get("generation") == generation
        and all(
            isinstance(record.get(field), str) and _SHA256_HEX_RE.match(record[field])
            for field in ("source_inventory_digest", "staged_manifest_digest")
        )
    )


def _read_json_record(path: Path) -> object:
    """Capped fd-bound read + JSON parse; raises ValueError with the exact
    failure for the structured reporter."""
    raw = _read_activation_capped(path)
    if raw is None:
        raise ValueError(
            f"{path.name} is not a plain regular single-link file within the "
            f"{_ACTIVATION_MAX_BYTES // 1024}KB cap"
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{path.name} is not valid JSON: {exc}") from None


def _evaluate_activation() -> tuple[StatePaths, ActivationStatus]:
    """Resolve current state without creating directories or records.

    The single evaluator behind both `state_paths()` and
    `activation_status()` — one reporter, one fallback semantics."""
    legacy = _home() / ".claude" / "learnings"
    neutral = _neutral_root()
    if neutral is None:
        status = ActivationStatus(
            ACTIVATION_ABSENT,
            None,
            "XDG_STATE_HOME is not a safe absolute path; neutral state is unavailable",
            None,
            legacy,
        )
        return StatePaths(legacy, legacy, legacy, False), status
    activation = neutral / _ACTIVATION_NAME
    fallback = StatePaths(legacy, legacy, neutral, False)

    def invalid(reason: str) -> tuple[StatePaths, ActivationStatus]:
        return fallback, ActivationStatus(
            ACTIVATION_INVALID, activation, reason, None, legacy
        )

    try:
        record = _read_json_record(activation)
    except FileNotFoundError:
        return fallback, ActivationStatus(
            ACTIVATION_ABSENT, activation, "no activation record", None, legacy
        )
    except OSError as exc:
        return invalid(f"cannot read activation record: {exc}")
    except ValueError as exc:
        return invalid(f"activation record: {exc}")
    if not _activation_is_valid(record):
        return invalid(
            "activation record schema is invalid (expected schema_version "
            f"{ACTIVATION_SCHEMA_VERSION}, active true, and a generation pointer)"
        )
    generation = record["generation"]
    gen_root = neutral / "generations" / generation
    gen_record_path = gen_root / _GENERATION_NAME
    try:
        gen_record = _read_json_record(gen_record_path)
    except FileNotFoundError:
        return invalid(
            f"activation names generation {generation!r} but "
            f"{gen_record_path} is missing"
        )
    except OSError as exc:
        return invalid(f"cannot read generation record for {generation!r}: {exc}")
    except ValueError as exc:
        return invalid(f"generation {generation!r}: {exc}")
    if not _generation_is_valid(gen_record, generation):
        return invalid(
            f"generation record for {generation!r} does not describe that generation"
        )
    active = StatePaths(gen_root, legacy, neutral, True)
    return active, ActivationStatus(
        ACTIVATION_VALID, activation, None, generation, gen_root
    )


def state_paths() -> StatePaths:
    """Resolve current state without creating directories or records.

    Emits at most ONE terse stderr line on an invalid record; the exact
    failure reason is `activation_status()`'s job (decision 4)."""
    paths, status = _evaluate_activation()
    if status.state == ACTIVATION_INVALID:
        print(
            "learnings-state: invalid activation record; staying on legacy "
            "state (see `learn state status`)",
            file=sys.stderr,
        )
    return paths


def activation_status() -> ActivationStatus:
    """Structured ABSENT / VALID / INVALID reporter — the single diagnostic
    authority for the activation record (decision 4). Never prints."""
    return _evaluate_activation()[1]


def active_generation_record() -> dict | None:
    """The validated generation.json of the ACTIVE generation, or None when
    activation is absent/invalid. Read-only accessor for status reporting."""
    paths, status = _evaluate_activation()
    if status.state != ACTIVATION_VALID:
        return None
    try:
        record = _read_json_record(paths.root / _GENERATION_NAME)
    except (FileNotFoundError, OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def activity_lock_path() -> Path:
    """The one state-transition lock inode; test override must be absolute."""
    override = os.environ.get("LEARNINGS_STATE_ACTIVITY_LOCK")
    if override:
        path = _safe_absolute(override)
        if path is None:
            raise ValueError("LEARNINGS_STATE_ACTIVITY_LOCK must be absolute")
        return path
    return Path(f"/tmp/learnings-md-system-{os.getuid()}-state-activity.lock")


def deployment_lock_path() -> Path:
    """Return the one deploy/transition coordination inode.

    ``deploy.sh`` owns this same path exclusively for its full machine
    transaction.  Corpus transitions take a shared hold, so they cannot plan
    against one executable revision and publish authority under another.
    """
    root = _neutral_root()
    if root is None:
        raise ValueError("neutral state root is unresolvable")
    return root / "deploy.lock"


class _ActivityLock:
    def __init__(self, fd: int):
        self._fd = fd

    def close(self) -> None:
        if self._fd < 0:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self) -> _ActivityLock:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _acquire_activity(*, exclusive: bool, nonblocking: bool) -> _ActivityLock | None:
    path = activity_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return None
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    if nonblocking:
        operation |= fcntl.LOCK_NB
    try:
        fcntl.flock(fd, operation)
    except BlockingIOError:
        os.close(fd)
        return None
    except OSError:
        os.close(fd)
        return None
    return _ActivityLock(fd)


def _acquire_deployment_lock(*, exclusive: bool, nonblocking: bool) -> _ActivityLock | None:
    """Acquire the deploy inode with the deployer's regular-file invariant.

    State callers request a shared lock; the machine deployer holds it
    exclusively.  The nonblocking transition path must leave no authority
    half-published when the deployment is active or the inode is unusable.
    """
    fd = -1
    acquired = False
    try:
        path = deployment_lock_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except (OSError, ValueError):
        return None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            return None
        if metadata.st_mode & 0o777 != 0o600:
            os.fchmod(fd, 0o600)
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if nonblocking:
            operation |= fcntl.LOCK_NB
        fcntl.flock(fd, operation)
        acquired = True
    except (BlockingIOError, OSError):
        return None
    finally:
        if not acquired and fd != -1:
            os.close(fd)
    return _ActivityLock(fd)


@contextlib.contextmanager
def activity_lock():
    """Blocking shared state activity guard for legacy-mode writers."""
    lock = _acquire_activity(exclusive=False, nonblocking=False)
    if lock is None:
        raise RuntimeError("cannot acquire shared state activity lock")
    try:
        yield lock
    finally:
        lock.close()


def try_activity_exclusive() -> _ActivityLock | None:
    """Non-blocking importer/cutover probe; no Part 3A caller uses it."""
    return _acquire_activity(exclusive=True, nonblocking=True)


def try_activity_shared() -> _ActivityLock | None:
    """Non-blocking shared activity probe for best-effort read-side updates."""
    return _acquire_activity(exclusive=False, nonblocking=True)


def structural_lock_path(worktree: Path | str) -> Path:
    """Byte-compatible legacy structural path, with a test-only root override."""
    resolved = Path(worktree).resolve()
    digest = hashlib.sha1(str(resolved).encode("utf-8")).hexdigest()[:16]
    configured = os.environ.get("LEARNINGS_STRUCTURAL_LOCK_DIR")
    if configured:
        lock_dir = _safe_absolute(configured)
        if lock_dir is None:
            raise ValueError("LEARNINGS_STRUCTURAL_LOCK_DIR must be absolute")
        return lock_dir / f"learnings-structure-{digest}.lock"
    return Path(f"/tmp/learnings-structure-{digest}.lock")


def legacy_slug(project_path: Path | str) -> str:
    resolved = Path(project_path).resolve()
    name = resolved.name.lower().replace("_", "-").replace(" ", "-")
    name = _DASH_RE.sub("-", _SLUG_INVALID_RE.sub("", name)).strip("-")
    if not name:
        raise ValueError(f"empty slug derived from {project_path!r}")
    return f"{name}-{hashlib.sha256(str(resolved).encode('utf-8')).hexdigest()[:8]}"


def portable_filename(project_path: Path | str) -> str:
    return f"{legacy_slug(project_path)}-PORTABLE-LEARNINGS.md"


def legacy_review_retro_slug(repo: Path | str) -> str:
    """Parity with `learnings-review-retro.sh::_repo_slug`: SHA1/8 of the
    path string AS GIVEN (never resolved), name with invalid runs REPLACED
    by "-" (not stripped), and a literal "repo" fallback for an empty name."""
    path = Path(repo)
    base = re.sub(r"[^a-z0-9]+", "-", path.name.lower()).strip("-") or "repo"
    return f"{base}-{hashlib.sha1(str(path).encode('utf-8')).hexdigest()[:8]}"


def legacy_currency_slug(project_root: Path | str) -> str | None:
    """Raw-path currency family: strip-sanitized basename + sha256/8 of the
    path string AS GIVEN. Callers pass an already-resolved repository root
    (`currency_project_root` / the Codex `_project_root` walk); this helper
    never resolves. Returns None when the name sanitizes empty — both live
    producers swallow that case rather than raising."""
    root = Path(project_root)
    name = root.name.lower().replace("_", "-").replace(" ", "-")
    name = _DASH_RE.sub("-", _SLUG_INVALID_RE.sub("", name)).strip("-")
    if not name:
        return None
    return f"{name}-{hashlib.sha256(str(root).encode('utf-8')).hexdigest()[:8]}"


def legacy_codex_key(project_root: Path | str) -> str:
    """Full sha256 of the path string AS GIVEN — the Codex adapter's
    per-project notification directory name (`_project_notification_dir`)."""
    return hashlib.sha256(str(project_root).encode("utf-8")).hexdigest()


# --- project catalog: frozen identity records under projects/<key>/ ---------

IDENTITY_RECORD_SCHEMA_VERSION = 1
_IDENTITY_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*-[0-9a-f]{16}$")
PORTABLE_SUFFIX = "-PORTABLE-LEARNINGS.md"
_PATH_DERIVED_PORTABLE_RE = re.compile(
    rf"^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-f]{{8}}{re.escape(PORTABLE_SUFFIX)}$"
)
_IDENTITY_NAME = "identity.json"


def identity_record_is_valid(record: object) -> bool:
    """Frozen `identity.json` schema gate. The key's 16-hex suffix MUST match
    sha256(canonical) — a matching short key with a different full identity is
    a collision and fails closed here rather than at a consumer."""
    if not isinstance(record, dict):
        return False
    if record.get("schema_version") != IDENTITY_RECORD_SCHEMA_VERSION:
        return False
    canonical = record.get("canonical")
    display = record.get("display")
    key = record.get("key")
    if not (isinstance(canonical, str) and canonical):
        return False
    if not (isinstance(display, str) and display):
        return False
    if not (isinstance(key, str) and _IDENTITY_KEY_RE.match(key)):
        return False
    if key.rsplit("-", 1)[1] != hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]:
        return False
    aliases = record.get("legacy_aliases")
    if not (isinstance(aliases, list) and all(isinstance(a, str) and a for a in aliases)):
        return False
    filename = record.get("portable_filename")
    if filename is not None and not (
        isinstance(filename, str)
        and filename.endswith(PORTABLE_SUFFIX)
        and len(filename) > len(PORTABLE_SUFFIX)
    ):
        return False
    roots = record.get("observed_roots")
    return isinstance(roots, list) and all(
        isinstance(r, str) and Path(r).is_absolute() for r in roots
    )


def build_identity_record(
    identity: ProjectIdentity,
    *,
    legacy_aliases: tuple[str, ...] | list[str] = (),
    portable_filename: str | None = None,
    observed_roots: tuple[str, ...] | list[str] = (),
) -> dict:
    """The ONE identity-record constructor. Only ProjectIdentity's three
    persisted identity fields enter this record; its ephemeral project_root
    remains runtime-only. Aliases and observed roots live only here."""
    record = {
        "schema_version": IDENTITY_RECORD_SCHEMA_VERSION,
        "canonical": identity.canonical,
        "display": identity.display,
        "key": identity.key,
        "legacy_aliases": sorted(set(legacy_aliases)),
        "portable_filename": portable_filename,
        "observed_roots": sorted({str(root) for root in observed_roots}),
    }
    if not identity_record_is_valid(record):
        raise ValueError(f"invalid identity record for {identity.canonical!r}")
    return record


def build_legacy_orphan_record(alias: str) -> dict:
    """Synthesized record preserving durable path-hash history whose project
    no longer resolves — keyed by its legacy alias, never folded into a
    global bucket, resolvable through resolve_project_reference()."""
    if not isinstance(alias, str) or not alias.strip():
        raise ValueError(f"invalid legacy-orphan alias: {alias!r}")
    alias = alias.strip()
    return build_identity_record(
        _identity(f"legacy-orphan:{alias}", alias), legacy_aliases=(alias,)
    )


def is_project_key(value: object) -> bool:
    """True only for a stable catalog key (`<sanitized-display>-<16 hex>`).
    A legacy slug's 8-hex suffix never matches, so consumers can discard
    slug-keyed content wholesale (mine's neutral cache contract)."""
    return isinstance(value, str) and bool(_IDENTITY_KEY_RE.match(value))


def iter_project_records(state_root: Path | str, *, on_invalid=None):
    """Yield `(key, record)` for every PUBLISHED project record, sorted by
    key. Hidden initializers are skipped. A published project directory
    without valid identity metadata is corruption: by default it raises
    IdentityResolutionError — the same fail-closed contract as
    resolve_project_reference(). Enumeration consumers that must not lose
    the whole catalog to one corrupt record (learn's pool, mine's neutral
    pool) pass `on_invalid(entry_dir, error)`, which is called once per
    corrupt record and the walk continues."""
    projects = Path(state_root) / "projects"
    try:
        entries = sorted(projects.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return
    for entry in entries:
        if entry.name.startswith(".") or not entry.is_dir():
            continue  # hidden initializers are never published records
        record = _published_identity_record(entry)
        if record is None:
            error = IdentityResolutionError(
                f"published project directory {entry} has no valid identity record"
            )
            if on_invalid is None:
                raise error
            on_invalid(entry, error)
            continue
        yield entry.name, record


# --- `learn state archive-records`: dead-catalog-record archival ------------
#
# Classification is pure string/existence inspection over an already-valid
# identity record (decision: the classifier never raises — an entry it
# cannot read is reported via `ArchiveUnreadable`, never crashes the plan).

ARCHIVE_CLASS_TEMP = "temp"
ARCHIVE_CLASS_GONE = "gone"
ARCHIVE_CLASS_ROOTLESS = "rootless"
ARCHIVE_CLASS_LIVE = "live"
ARCHIVE_CLASS_HAS_CORPUS = "has-corpus"
ARCHIVE_CLASS_CORPUS_NOT_TEMP = "corpus-not-temp"
ARCHIVE_CLASS_CORPUS_UNREADABLE = "corpus-unreadable"

_ARCHIVE_CANDIDATE_CLASSES = frozenset(
    {ARCHIVE_CLASS_TEMP, ARCHIVE_CLASS_GONE, ARCHIVE_CLASS_ROOTLESS}
)
_ARCHIVE_ATTACHMENT_FILES = (
    ("portable.md", "portable"),
    ("rules.md", "rules"),
    ("corpus-baseline.json", "baseline"),
    ("maintenance.json", "maintenance"),
    ("tiers.json", "tiers"),
)


@dataclass(frozen=True)
class ArchiveRecordEntry:
    """One classified `projects/<key>` catalog record (candidate or refused).

    `corpus_dir` is set whenever a corpus exists at `corpora/<key>`,
    whether or not it will be archived. `archive_corpus` is True only for
    a `temp`-classified candidate whose corpus passed the independent
    fingerprint check — the only case where `apply_archive_records` also
    moves `corpora/<key>`."""

    key: str
    display: str
    cls: str
    attachments: tuple[str, ...]
    project_dir: Path
    corpus_dir: Path | None = None
    archive_corpus: bool = False


@dataclass(frozen=True)
class ArchiveUnreadable:
    """A requested or enumerated key whose record could not be classified."""

    key: str
    reason: str


@dataclass(frozen=True)
class ArchiveRecordsPlan:
    candidates: tuple[ArchiveRecordEntry, ...]
    refused: tuple[ArchiveRecordEntry, ...]
    unreadable: tuple[ArchiveUnreadable, ...]


@dataclass(frozen=True)
class ArchivedRecord:
    key: str
    display: str
    cls: str
    attachments: tuple[str, ...]
    destination: Path
    corpus_destination: Path | None = None
    corpus_archived: bool = False


@dataclass(frozen=True)
class ArchiveApplyError:
    key: str
    reason: str


@dataclass(frozen=True)
class ArchiveApplyResult:
    applied: tuple[ArchivedRecord, ...]
    errors: tuple[ArchiveApplyError, ...]


_ARCHIVE_PATH_SCHEME_PREFIXES = ("path:", "git-common-dir:")
_ARCHIVE_ROOTLESS_CANONICAL_PREFIX = "legacy-orphan:"


def _archive_strip_path_scheme(value: str) -> str:
    """Strip a leading `path:`/`git-common-dir:` catalog-canonical scheme
    prefix, if present, so the temp-path checks below see the bare
    filesystem path either way (a prefixed value like
    `path:/tmp/scratch` must still match the bare-`/tmp/` startswith
    checks)."""
    for prefix in _ARCHIVE_PATH_SCHEME_PREFIXES:
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


def _archive_canonical_path_dir(canonical: object) -> Path | None:
    """The filesystem directory a path-form catalog canonical
    (`path:<dir>` / `git-common-dir:<dir>`) names, or None when `canonical`
    isn't that shape."""
    if not isinstance(canonical, str):
        return None
    stripped = _archive_strip_path_scheme(canonical)
    if stripped == canonical:
        return None
    return Path(stripped)


def _archive_strings_look_temp(values: Sequence[object]) -> bool:
    """String-only match (existence is irrelevant): pytest scratch fixtures,
    `/tmp`, `/private/tmp`, and macOS TMPDIR (`/var/folders/`)."""
    for value in values:
        if not isinstance(value, str):
            continue
        if "/pytest-of-" in value or "/var/folders/" in value:
            return True
        stripped = _archive_strip_path_scheme(value)
        if stripped.startswith("/tmp/") or stripped.startswith("/private/tmp/"):
            return True
    return False


def _archive_record_is_temp(record: Mapping[str, object]) -> bool:
    candidates = [record.get("canonical")]
    roots = record.get("observed_roots")
    if isinstance(roots, list):
        candidates.extend(roots)
    return _archive_strings_look_temp(candidates)


def _archive_corpus_active_record(corpora_root: Path, key: str) -> dict | None:
    """fd-bound, size-capped read of `<corpora_root>/<key>/active.json`
    against the PASSED-IN corpora root — never the global `corpora_root()`
    resolution, so a `--neutral-root` test override is honored. None on
    anything short of a valid, key-matching record (missing, non-regular,
    oversized, corrupt JSON, or schema-invalid); never raises."""
    path = corpora_root / key / _CORPUS_ACTIVE_NAME
    try:
        record = _read_corpus_record(path)
    except (FileNotFoundError, OSError, ValueError):
        return None
    if not corpus_active_record_is_valid(record, project_key=key):
        return None
    return record


def _archive_corpus_looks_temp(active_record: Mapping[str, object]) -> bool:
    """Second, independent confirmation: the corpus's OWN recorded
    `canonical_aliases` (never the catalog record being classified — that
    would make this check trivially always pass for a record already
    classified `temp`) must themselves look like test junk."""
    aliases = active_record.get("canonical_aliases")
    return isinstance(aliases, list) and _archive_strings_look_temp(aliases)


def _archive_record_attachments(project_dir: Path) -> tuple[str, ...]:
    attachments = [
        label for filename, label in _ARCHIVE_ATTACHMENT_FILES
        if (project_dir / filename).is_file()
    ]
    if (project_dir / "diagnostics").is_dir():
        attachments.append("diagnostics")
    # `maintenance/` (the headless scheduler's per-project report dir,
    # self-regulation slice 1) can coexist with the `maintenance.json`
    # authority record above — dedupe so a project carrying both doesn't
    # list the "maintenance" label twice.
    if (project_dir / "maintenance").is_dir() and "maintenance" not in attachments:
        attachments.append("maintenance")
    return tuple(attachments)


def _classify_archive_entry(
    key: str,
    record: Mapping[str, object],
    *,
    project_dir: Path,
    corpora_root: Path,
    explicit: bool,
) -> ArchiveRecordEntry:
    """Classify one record.

    Base classification (temp/gone/rootless/live) never consults the
    corpus. A corpus at `corpora_root/<key>` then gates the outcome:
    gone/rootless/live + corpus is an unconditional `has-corpus` refusal
    (a real corpus with no checkout is data worth keeping). temp + corpus
    requires a second, independent fingerprint of the corpus's OWN
    `canonical_aliases` before it is archived alongside the record — an
    unreadable/corrupt active.json or aliases that don't look like test
    junk refuse loudly (`corpus-unreadable` / `corpus-not-temp`), never
    silently archived. `explicit` (a `--key` run) only ever affects
    whether a `live`-classified entry with NO corpus is treated as a
    candidate — none of the corpus refusals are overridable, by `--key`
    or otherwise."""
    display = record.get("display") or key
    attachments = _archive_record_attachments(project_dir)
    canonical = record.get("canonical")
    observed_roots = [r for r in (record.get("observed_roots") or []) if isinstance(r, str)]
    if _archive_record_is_temp(record):
        base_cls = ARCHIVE_CLASS_TEMP
    elif not observed_roots:
        # Conservative default: a rootless record is only a `rootless`
        # candidate when its canonical is itself the `legacy-orphan:` shape
        # that produced it; any other canonical with no observed roots
        # refuses `live` rather than guessing.
        base_cls = (
            ARCHIVE_CLASS_ROOTLESS
            if isinstance(canonical, str) and canonical.startswith(_ARCHIVE_ROOTLESS_CANONICAL_PREFIX)
            else ARCHIVE_CLASS_LIVE
        )
    else:
        canonical_dir = _archive_canonical_path_dir(canonical)
        if any(Path(root).is_dir() for root in observed_roots) or (
            canonical_dir is not None and canonical_dir.is_dir()
        ):
            base_cls = ARCHIVE_CLASS_LIVE
        else:
            base_cls = ARCHIVE_CLASS_GONE

    corpus_dir = corpora_root / key
    if not corpus_dir.is_dir():
        return ArchiveRecordEntry(key, display, base_cls, attachments, project_dir)

    if base_cls != ARCHIVE_CLASS_TEMP:
        return ArchiveRecordEntry(key, display, ARCHIVE_CLASS_HAS_CORPUS, attachments, project_dir)

    active_record = _archive_corpus_active_record(corpora_root, key)
    if active_record is None:
        return ArchiveRecordEntry(
            key, display, ARCHIVE_CLASS_CORPUS_UNREADABLE, attachments, project_dir,
            corpus_dir=corpus_dir,
        )
    if not _archive_corpus_looks_temp(active_record):
        return ArchiveRecordEntry(
            key, display, ARCHIVE_CLASS_CORPUS_NOT_TEMP, attachments, project_dir,
            corpus_dir=corpus_dir,
        )
    return ArchiveRecordEntry(
        key, display, ARCHIVE_CLASS_TEMP, attachments, project_dir,
        corpus_dir=corpus_dir, archive_corpus=True,
    )


def plan_archive_records(
    catalog_root: Path | str,
    corpora_root: Path | str,
    *,
    keys: Sequence[str] | None = None,
) -> ArchiveRecordsPlan:
    """Read-only classification for `learn state archive-records`.

    With `keys=None`, every published `projects/<key>` record is enumerated
    and auto-classified (temp/gone/rootless are candidates; live/has-corpus
    are refused). With `keys` given, scope narrows to exactly those catalog
    keys and a `live` classification becomes a candidate too (the `--key`
    escape) — a `has-corpus` refusal is never overridable. A key with no
    published record, or an unreadable/invalid identity.json, is reported in
    `unreadable` and never raised.
    """
    root = Path(catalog_root)
    projects_dir = root / "projects"
    corpora = Path(corpora_root)
    explicit = keys is not None
    unreadable: list[ArchiveUnreadable] = []
    entries: list[tuple[str, dict]] = []
    if explicit:
        seen: set[str] = set()
        for key in keys:
            if key in seen:
                continue
            seen.add(key)
            project_dir = projects_dir / key
            record = _published_identity_record(project_dir) if project_dir.is_dir() else None
            if record is None:
                reason = (
                    "no such catalog record"
                    if not project_dir.is_dir()
                    else "unreadable or invalid identity.json"
                )
                unreadable.append(ArchiveUnreadable(key, reason))
                continue
            entries.append((key, record))
    else:
        def _on_invalid(entry_dir: Path, error: Exception) -> None:
            unreadable.append(ArchiveUnreadable(entry_dir.name, str(error)))

        entries = list(iter_project_records(root, on_invalid=_on_invalid))

    candidates: list[ArchiveRecordEntry] = []
    refused: list[ArchiveRecordEntry] = []
    for key, record in entries:
        entry = _classify_archive_entry(
            key, record, project_dir=projects_dir / key, corpora_root=corpora, explicit=explicit
        )
        is_candidate = entry.cls in _ARCHIVE_CANDIDATE_CLASSES or (
            entry.cls == ARCHIVE_CLASS_LIVE and explicit
        )
        (candidates if is_candidate else refused).append(entry)

    candidates.sort(key=lambda e: e.key)
    refused.sort(key=lambda e: e.key)
    unreadable.sort(key=lambda e: e.key)
    return ArchiveRecordsPlan(tuple(candidates), tuple(refused), tuple(unreadable))


def _archive_append_manifest_line(manifest_path: Path, payload: bytes) -> None:
    """fd-bound append+fsync of one manifest line. A short `os.write` is
    treated as a failed append (raised as OSError) so a truncated line
    never gets fsynced as if it were the real record."""
    fd = os.open(
        str(manifest_path),
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
        0o600,
    )
    try:
        written = os.write(fd, payload)
        if written != len(payload):
            raise OSError(f"short manifest write: {written}/{len(payload)} bytes")
        os.fsync(fd)
    finally:
        os.close(fd)


def _archive_append_manifest_correction(
    manifest_path: Path, key: str, half: str, exc: Exception
) -> None:
    """Best-effort correction line for a manifest intent line whose logged
    move did not happen (`os.rename` failed after the intent line was
    already fsynced). Never raises — the caller's own ArchiveApplyError is
    the authoritative signal either way."""
    record = {"ts": time.time(), "key": key, "event": "move-failed", "half": half, "error": str(exc)}
    payload = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    try:
        _archive_append_manifest_line(manifest_path, payload)
    except OSError:
        pass


def apply_archive_records(
    archive_root: Path | str, candidates: Sequence[ArchiveRecordEntry]
) -> ArchiveApplyResult:
    """Log-durable-before-move: appends+fsyncs one `manifest.jsonl` line
    before `os.rename`-ing `projects/<key>` into `<archive_root>/projects/
    <key>` — AND, for a candidate with `archive_corpus` set, `corpora/<key>`
    into `<archive_root>/corpora/<key>` too. One manifest line covers both
    intents for such a record. `archive_root` is an explicit destination
    (production passes the neutral root's `archive/` sibling of
    `corpora/`, never a path inside the active generation directory that
    rollback snapshots digest) — this function never derives it from a
    catalog root. A destination collision on EITHER half (`archive-
    collision`), or a failed manifest append (including a short write),
    refuses the whole record before anything moves. If a rename fails
    AFTER its manifest line was already fsynced, a best-effort correction
    line (`event: "move-failed"`) is appended so the manifest doesn't
    silently disagree with reality; if the record half moves but the
    corpus half then fails, the record stays archived (the manifest line
    already recorded that intent) and a distinct error is appended so the
    run's rc is still nonzero. The caller holds the exclusive state
    activity lock for the whole call, so no additional per-record locking
    is taken here."""
    root = Path(archive_root)
    archive_projects = root / "projects"
    archive_corpora = root / "corpora"
    archive_projects.mkdir(parents=True, exist_ok=True)
    archive_corpora.mkdir(parents=True, exist_ok=True)
    manifest_path = root / "manifest.jsonl"
    applied: list[ArchivedRecord] = []
    errors: list[ArchiveApplyError] = []
    for entry in candidates:
        dest = archive_projects / entry.key
        corpus_dest = archive_corpora / entry.key if entry.archive_corpus else None
        if dest.exists() or (corpus_dest is not None and corpus_dest.exists()):
            errors.append(ArchiveApplyError(entry.key, "archive-collision"))
            continue
        record = {
            "ts": time.time(),
            "key": entry.key,
            "display": entry.display,
            "class": entry.cls,
            "from": str(entry.project_dir),
            "to": str(dest),
            "attachments": list(entry.attachments),
            "corpus": (
                {"from": str(entry.corpus_dir), "to": str(corpus_dest)}
                if corpus_dest is not None
                else None
            ),
        }
        payload = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        try:
            _archive_append_manifest_line(manifest_path, payload)
        except OSError as exc:
            errors.append(ArchiveApplyError(entry.key, f"manifest append failed: {exc}"))
            continue
        try:
            os.rename(str(entry.project_dir), str(dest))
        except OSError as exc:
            _archive_append_manifest_correction(manifest_path, entry.key, "record", exc)
            errors.append(ArchiveApplyError(entry.key, f"move failed after manifest log: {exc}"))
            continue
        corpus_archived = False
        if corpus_dest is not None:
            try:
                os.rename(str(entry.corpus_dir), str(corpus_dest))
                corpus_archived = True
            except OSError as exc:
                _archive_append_manifest_correction(manifest_path, entry.key, "corpus", exc)
                errors.append(
                    ArchiveApplyError(
                        entry.key, f"corpus move failed after record archived: {exc}"
                    )
                )
        applied.append(
            ArchivedRecord(
                entry.key, entry.display, entry.cls, entry.attachments, dest,
                corpus_destination=corpus_dest, corpus_archived=corpus_archived,
            )
        )
    return ArchiveApplyResult(tuple(applied), tuple(errors))


def _derived_legacy_aliases(resolved_root: Path) -> list[str]:
    """Every legacy alias this working tree would have produced, so an
    imported record claiming any of them wins over publishing a new key."""
    aliases: list[str] = []
    with contextlib.suppress(ValueError):
        aliases.append(legacy_slug(resolved_root))
    currency = legacy_currency_slug(resolved_root)
    if currency is not None and currency not in aliases:
        aliases.append(currency)
    retro = legacy_review_retro_slug(resolved_root)
    if retro not in aliases:
        aliases.append(retro)
    return aliases


def resolve_or_derive_key(
    state_root: Path | str,
    project_root: Path | str,
    *,
    identity: ProjectIdentity | None = None,
) -> str:
    """Read-only twin of ensure_project_record: map a working tree to its
    catalog key WITHOUT publishing anything. A record already claiming the
    canonical identity or any derived legacy alias (an imported history)
    wins; otherwise the derived key is returned unpublished —
    ensure_project_record would publish a record with exactly that key.
    `identity` lets a caller reuse one git identity probe across
    derivations."""
    resolved = Path(project_root).resolve()
    if identity is None:
        identity = project_identity(resolved)
    for reference in (identity.canonical, identity.key, *_derived_legacy_aliases(resolved)):
        key = resolve_project_reference(state_root, reference)
        if key is not None:
            return key
    return identity.key


def ensure_project_record(
    state_root: Path | str,
    project_root: Path | str,
    *,
    identity: ProjectIdentity | None = None,
) -> str:
    """Resolve-or-publish the identity record for a working tree; returns
    its stable key.

    Legacy-alias mapping first: a record already claiming this root's
    canonical identity or any of its derived legacy aliases (an imported
    history) wins and keeps its key. Only when nothing matches is a fresh
    record published; publish's first-writer-wins rename arbitrates the
    concurrent case, and a losing publish whose winner names the same
    canonical returns the winner's key. `identity` lets a caller reuse one
    git identity probe (must describe `project_root`)."""
    resolved = Path(project_root).resolve()
    if identity is None:
        identity = project_identity(resolved)
    aliases = _derived_legacy_aliases(resolved)
    for reference in (identity.canonical, identity.key, *aliases):
        key = resolve_project_reference(state_root, reference)
        if key is not None:
            return key
    record = build_identity_record(
        identity, legacy_aliases=aliases, observed_roots=(str(resolved),)
    )
    return publish_identity_record(state_root, record).name


def _resolve_catalog_key_no_git(state_root: Path | str, resolved_path: Path) -> str | None:
    """Catalog-only project lookup for the diagnostics crash path (decision
    4): scans PUBLISHED identity records for a match against
    `resolved_path` using pure path/hash comparisons only — canonical (the
    path: form only; a remote:/git-common-dir: canonical cannot be derived
    without git), legacy_aliases, and observed_roots. NEVER calls
    `project_identity` or any subprocess — `resolve_or_derive_key` does not
    satisfy this contract, since absent a supplied identity it calls
    `project_identity` itself. Returns the matching key, or None when the
    root is uncataloged — the caller falls back to global.jsonl. A corrupt
    published record is skipped rather than raised (best-effort: a crash
    handler must not itself crash on unrelated catalog damage)."""
    resolved_str = str(resolved_path)
    path_canonical = f"path:{resolved_str}"
    derived_aliases = set(_derived_legacy_aliases(resolved_path))
    for _key, record in iter_project_records(state_root, on_invalid=lambda *_a: None):
        if record.get("canonical") == path_canonical:
            return record["key"]
        if resolved_str in record.get("observed_roots", ()):
            return record["key"]
        if derived_aliases & set(record.get("legacy_aliases", ())):
            return record["key"]
    return None


# --- Part 7A: worker-failure diagnostics schema (decision 3) ----------------

WORKER_FAILURE_SCHEMA_VERSION = 1
_WORKER_FAILURE_KEYS = frozenset(
    {"schema_version", "ts", "worker", "project_path", "session_id", "rc", "error"}
)


def is_valid_worker_failure_record(record: object) -> bool:
    """Decision 3's schema gate, used by the import planner's per-line
    diagnostics validator (decision 9)."""
    if not isinstance(record, dict) or set(record.keys()) != _WORKER_FAILURE_KEYS:
        return False
    if record.get("schema_version") != WORKER_FAILURE_SCHEMA_VERSION:
        return False
    ts = record.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return False
    if not isinstance(record.get("worker"), str) or not record["worker"]:
        return False
    project_path = record.get("project_path")
    if project_path is not None and not isinstance(project_path, str):
        return False
    session_id = record.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        return False
    rc = record.get("rc")
    if rc is not None and (not isinstance(rc, int) or isinstance(rc, bool)):
        return False
    return isinstance(record.get("error"), str)


# --- Part 7A: corpus baseline + drift (decisions 10-12) ---------------------
#
# `corpus_artifact_paths` is the SINGLE baseline/drift and fresh-authority
# presence selection authority (decision 10). It matches top-level entries
# only (non-recursive glob) and raises loudly on a matching entry that is not
# a regular file (an impostor `LEARNINGS-*.md` directory is an anomaly, never
# silently skipped). The tuple below is parity-pinned by the test suite against
# `hooks/commit-learnings.sh::LEARNINGS_PATHSPECS` (its LEGACY-mode tuple —
# the hook drops the portable pattern after activation, which the baseline
# deliberately does not: portable snapshots remain baseline/drift evidence
# but are excluded from the legacy cutover source map).

CORPUS_ARTIFACT_SPECS = ("LEARNINGS.md", "LEARNINGS-*.md", "*-PORTABLE-LEARNINGS.md")


def corpus_artifact_paths(root: Path | str) -> list[Path]:
    """Top-level LEARNINGS.md, sorted LEARNINGS-*.md, sorted
    *-PORTABLE-LEARNINGS.md under `root` — the same set the baseline
    fingerprints and the drift comparator re-hashes. Raises ValueError on a
    matching entry that is not a regular file."""
    root = Path(root)
    paths: list[Path] = []
    seen: set[str] = set()
    for spec in CORPUS_ARTIFACT_SPECS:
        for path in sorted(root.glob(spec)):
            if path.name in seen:
                continue  # overlapping spec matched the same name twice
            seen.add(path.name)
            if not path.is_file():
                raise ValueError(f"corpus artifact {path} is not a regular file")
            paths.append(path)
    return paths


CORPUS_BASELINE_SCHEMA_VERSION = 1
_CORPUS_BASELINE_MAX_BYTES = 65536
_CORPUS_BASELINE_KEYS = frozenset({"schema_version", "canonical", "key", "ts", "head", "files"})
_CORPUS_BASELINE_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CORPUS_LOCK_TIMEOUT_SECONDS = 10
_CORPUS_LOCK_POLL_SECONDS = 0.05


class CorpusBaselineAbsent(RuntimeError):
    """`learn corpus drift`: no baseline recorded for this project (rc 2) —
    distinct from a malformed baseline (ValueError, rc 1)."""


def is_valid_corpus_baseline_record(record: object) -> bool:
    """Decision 11's exact schema gate: sha256-hex per file entry, relative
    non-traversing file names, and key/canonical consistency (the key's
    16-hex suffix must match sha256(canonical)[:16] — the same rule
    `identity_record_is_valid` enforces)."""
    if not isinstance(record, dict) or set(record.keys()) != _CORPUS_BASELINE_KEYS:
        return False
    if record.get("schema_version") != CORPUS_BASELINE_SCHEMA_VERSION:
        return False
    canonical = record.get("canonical")
    key = record.get("key")
    if not (isinstance(canonical, str) and canonical):
        return False
    if not (isinstance(key, str) and _IDENTITY_KEY_RE.match(key)):
        return False
    if key.rsplit("-", 1)[1] != hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]:
        return False
    ts = record.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return False
    head = record.get("head")
    if head is not None and not isinstance(head, str):
        return False
    files = record.get("files")
    if not isinstance(files, dict) or not files:
        return False
    for name, digest in files.items():
        if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
            return False
        if not (isinstance(digest, str) and _CORPUS_BASELINE_SHA256_RE.match(digest)):
            return False
    return True


def _corpus_baseline_path_for(project_path: Path, key: str) -> Path:
    """Storage routing (decision 11): neutral -> projects/<key>/corpus-
    baseline.json; legacy -> corpus-baseline/<slug>.json, the same
    `legacy_slug` derivation reconcile/diagnostics use."""
    paths = state_paths()
    if paths.active:
        return paths.root / "projects" / key / "corpus-baseline.json"
    slug = legacy_slug(project_path)
    return paths.child("corpus-baseline", f"{slug}.json")


def build_corpus_baseline(root: Path, *, canonical: str, key: str, head: str | None) -> dict:
    """Pure baseline construction (decision 10). Raises ValueError('no
    corpus artifacts') on an empty selection; whole-file sha256 over raw
    bytes with plain reads — the repo working tree is trusted per the
    threat model, so an unreadable corpus file fails loud (OSError),
    unlike currency's silent-skip `corpus_sha256`."""
    paths = corpus_artifact_paths(root)
    if not paths:
        raise ValueError("no corpus artifacts")
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    record = {
        "schema_version": CORPUS_BASELINE_SCHEMA_VERSION,
        "canonical": canonical,
        "key": key,
        "ts": time.time(),
        "head": head,
        "files": files,
    }
    if not is_valid_corpus_baseline_record(record):
        raise ValueError("constructed corpus baseline fails its own schema gate")
    return record


def _acquire_structural_lock_blocking(project_root: Path | str) -> int:
    """Bounded-blocking acquire of the project structural lock shared with
    every corpus writer (decision 10) — the SAME lock inode
    `structural_lock_path` names, so no new lock constructor is introduced.
    Returns the open fd; release with `fcntl.flock(fd, LOCK_UN)` then
    `os.close(fd)`. Raises TimeoutError on a busy lock."""
    path = structural_lock_path(project_root)
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o644)
    deadline = time.monotonic() + _CORPUS_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                os.close(fd)
                raise
            if time.monotonic() >= deadline:
                os.close(fd)
                raise TimeoutError(
                    f"structural lock busy for {project_root} "
                    f"({_CORPUS_LOCK_TIMEOUT_SECONDS}s timeout)"
                ) from exc
            time.sleep(_CORPUS_LOCK_POLL_SECONDS)


def write_corpus_baseline(project_root: Path, *, canonical: str, key: str, head: str | None) -> dict:
    """Baseline writer (decisions 10-11): hashes the live corpus under the
    project structural lock, then writes atomic temp + os.replace WITH
    directory fsync (`_replace_json_fsynced` — an authority record like
    pending.json, not a cache, unlike the diagnostics log). Raises
    ValueError on an empty corpus selection or a non-regular matching
    entry; TimeoutError if the structural lock cannot be acquired."""
    root = Path(project_root).resolve()
    lock_fd = _acquire_structural_lock_blocking(root)
    try:
        record = build_corpus_baseline(root, canonical=canonical, key=key, head=head)
        path = _corpus_baseline_path_for(root, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        _replace_json_fsynced(path, record)
        return record
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def read_corpus_baseline(project_root: Path, key: str) -> dict:
    """fd-bound baseline read (decision 11): fails loud (ValueError) on
    malformed content — never treated as empty. Raises
    `CorpusBaselineAbsent` when the file is simply missing, so the CLI can
    map the two outcomes to different exit codes (rc 2 vs rc 1)."""
    path = _corpus_baseline_path_for(Path(project_root).resolve(), key)
    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError as exc:
        raise CorpusBaselineAbsent(str(path)) from exc
    try:
        st = os.fstat(fd)
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_size > _CORPUS_BASELINE_MAX_BYTES
        ):
            raise ValueError(f"{path} is not a plain regular single-link file within the size cap")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(_CORPUS_BASELINE_MAX_BYTES + 1)
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > _CORPUS_BASELINE_MAX_BYTES:
        raise ValueError(f"{path} exceeds the size cap")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from None
    if not is_valid_corpus_baseline_record(record):
        raise ValueError(f"{path} fails the corpus-baseline schema")
    return record


def compute_corpus_drift(project_root: Path, key: str, head: str | None) -> dict:
    """Read-only comparator (decision 10): live `corpus_artifact_paths`
    hashes vs. the stored baseline's `files` map, the live side hashed
    under the project structural lock. `head` is provenance only — it
    never gates the content comparison (a branch switch that changes
    corpus bytes IS drift; one that does not, is not). Raises
    `CorpusBaselineAbsent` / `ValueError` (malformed baseline, unreadable
    corpus file, non-regular matching entry) — the caller maps those to
    rc 2 / rc 1."""
    root = Path(project_root).resolve()
    # Lock FIRST, then read the baseline inside the same critical section
    # (council review): `write_corpus_baseline` replaces the baseline while
    # holding this lock, so a read taken before acquiring it can pair a
    # stale baseline with post-write live hashes — a false drift report.
    lock_fd = _acquire_structural_lock_blocking(root)
    try:
        baseline = read_corpus_baseline(root, key)
        paths = corpus_artifact_paths(root)
        live = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    baseline_files = baseline["files"]
    added = sorted(set(live) - set(baseline_files))
    removed = sorted(set(baseline_files) - set(live))
    common = set(live) & set(baseline_files)
    changed = sorted(name for name in common if live[name] != baseline_files[name])
    return {
        "head": head,
        "baseline_head": baseline.get("head"),
        "baseline_ts": baseline.get("ts"),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": len(common) - len(changed),
    }


# --- read-only import planner (parent plan Task 4) --------------------------

_PLAN_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_DISTILLED_FROM_RE = re.compile(r"<!--\s*distilled-from:\s*([0-9a-f]+)\s*-->", re.IGNORECASE)
_RECONCILE_REQUIRED_KEYS = (
    "removed",
    "superseded_by",
    "reason",
    "file",
    "project_path",
    "session_id",
)
_FOLD_LEDGER_REQUIRED_KEYS = ("folded", "survivor", "body", "provenance", "date")


@dataclass(frozen=True)
class PlanArtifact:
    """One classified legacy source artifact: relpath, allowlist kind, the
    planned action (import/report/reset/skip/block), source digest, human
    detail, and owning project canonical when known."""

    path: str
    kind: str
    action: str
    digest: str | None
    detail: str
    project: str | None


@dataclass(frozen=True)
class PlanProject:
    """One stable-identity alias group (or a synthesized legacy-orphan)."""

    canonical: str
    key: str
    display: str
    aliases: tuple[str, ...]
    selected_digest: str | None
    selected_alias: str | None
    declined_aliases: tuple[str, ...]
    record: dict


@dataclass(frozen=True)
class MergedPlanArtifact:
    """A staged destination assembled from MULTIPLE legacy sources,
    ts-order merged (decision 9) — today only colliding per-project
    diagnostics files, when two or more legacy slugs alias to the same
    catalog key. `PlanArtifact` models one source and one digest, so a
    collision needs its own plan representation: `sources` holds
    (relpath, digest) pairs in deterministic (relpath-sorted) order — each
    still digest-verified individually at staging time — and
    `merged_digest` is the sha256 of the merged payload bytes that
    actually lands at `dest`."""

    dest: str
    kind: str
    sources: tuple[tuple[str, str], ...]
    merged_digest: str
    project: str | None


@dataclass(frozen=True)
class ImportPlan:
    source_root: str
    inventory_digest: str
    generation_id: str | None
    source_changed: bool
    artifacts: tuple[PlanArtifact, ...]
    projects: tuple[PlanProject, ...]
    blockers: tuple[str, ...]
    reports: tuple[str, ...]
    resets: tuple[str, ...]
    preferences: tuple[tuple[str, str], ...]
    merges: tuple[MergedPlanArtifact, ...] = ()


def _read_file_capped(path: Path, cap: int = _PLAN_MAX_ARTIFACT_BYTES) -> bytes | None:
    """fd-bound source read (O_NOFOLLOW, S_ISREG + nlink==1 + cap on the fd)
    — the house shared-dir pattern. None for anything unreadable that way."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > cap:
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(cap + 1)
        return raw if len(raw) <= cap else None
    except OSError:
        return None
    finally:
        if fd != -1:
            os.close(fd)


def _pool_target_defect(target: Path) -> str:
    """The exact reason a pool symlink target yielded no bytes: truly missing
    keeps the dangling wording; a target that exists but fails the fd gate
    (symlink chain, non-regular, hardlinked, oversized) names that defect
    instead — the two are different operator problems."""
    try:
        st = os.lstat(str(target))
    except OSError:
        return "dangling link (target missing or unreadable); reported and omitted"
    if stat.S_ISLNK(st.st_mode):
        return "symlink-chained target (not a plain regular file); reported and omitted"
    if not stat.S_ISREG(st.st_mode):
        return "target is not a regular file; reported and omitted"
    if st.st_nlink != 1:
        return f"hardlinked target (nlink={st.st_nlink}); reported and omitted"
    if st.st_size > _PLAN_MAX_ARTIFACT_BYTES:
        return "target exceeds the size cap; reported and omitted"
    return "target unreadable; reported and omitted"


def source_inventory_digest(root: Path | str) -> str:
    """One inventory walk, no git probes, no artifact validation — the cheap
    legacy-drift probe `learn state status` uses (the full plan belongs to
    `learn state import`)."""
    return _source_inventory(Path(root))[0]


def _source_inventory(root: Path) -> tuple[str, dict[str, dict]]:
    """Deterministic content inventory of the legacy source. Symlinks record
    their target string AND the target's content digest (when readable), so
    a portable mutated mid-scan changes the digest even though the file
    itself lives outside the legacy root (decision 5)."""
    entries: dict[str, dict] = {}
    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            base = Path(dirpath)
            for name in dirnames:
                dir_path = base / name
                rel = dir_path.relative_to(root).as_posix()
                try:
                    st = dir_path.lstat()
                except OSError:
                    entries[rel] = {"type": "missing"}
                    continue
                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.readlink(str(dir_path))
                    except OSError:
                        target = ""
                    entries[rel] = {"type": "dir-symlink", "target": target}
                else:
                    entries[rel] = {"type": "dir"}
            for name in sorted(filenames):
                path = base / name
                rel = path.relative_to(root).as_posix()
                try:
                    st = path.lstat()
                except OSError:
                    entries[rel] = {"type": "missing"}
                    continue
                if stat.S_ISLNK(st.st_mode):
                    try:
                        target = os.readlink(str(path))
                    except OSError:
                        target = ""
                    raw = None
                    if target and Path(target).is_absolute():
                        raw = _read_file_capped(Path(target))
                    entries[rel] = {
                        "type": "symlink",
                        "target": target,
                        "target_digest": (
                            hashlib.sha256(raw).hexdigest() if raw is not None else None
                        ),
                    }
                elif stat.S_ISREG(st.st_mode):
                    raw = _read_file_capped(path)
                    entries[rel] = {
                        "type": "file",
                        "digest": (
                            hashlib.sha256(raw).hexdigest() if raw is not None else None
                        ),
                    }
                else:
                    entries[rel] = {"type": "special"}
    payload = json.dumps(entries, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), entries


_KNOWN_TOP_DIRS = frozenset(
    {
        "portable", "mined", "rules", "review-retro", "reconcile", "currency",
        "reduce", "locks", "diagnostics", "corpus-baseline",
    }
)
# The currency per-project run lock is `<slug>.lock` where <slug> ends in the
# 8-hex path-hash suffix (`learnings-prune.sh::currency_lock_path`).
_CURRENCY_LOCK_RE = re.compile(r"-[0-9a-f]{8}\.lock$")


def _is_known_lock(rel: str) -> bool:
    """Only the lock inodes the live system creates under the legacy root:
    locks/* (mined-pool / distill), the two durable-ledger sibling locks,
    reconcile ledger sibling locks, and the currency per-project run lock.
    Every other .lock path is foreign (structural locks live in /tmp)."""
    parts = rel.split("/")
    if len(parts) != 2:
        return False
    top, name = parts
    if top == "locks":
        return True
    if top == "rules" and name == "ledger.json.lock":
        return True
    if top == "review-retro" and name == "pending.json.lock":
        return True
    if top == "reconcile" and name.endswith(".jsonl.lock"):
        return True
    if top == "diagnostics" and name.endswith(".jsonl.lock"):
        return True
    return top == "currency" and bool(_CURRENCY_LOCK_RE.search(name))


def _classify_source_path(rel: str) -> tuple[str, str]:
    """(kind, clean-case action) for one owned-allowlist relpath; validators
    may downgrade the action. Unknown paths are foreign: report, never copy
    or delete."""
    parts = rel.split("/")
    name = parts[-1]
    if name.endswith(".lock"):
        return ("lock", "skip") if _is_known_lock(rel) else ("foreign", "report")
    if ".claimed." in name:
        return ("claimed-notification", "report")
    if len(parts) == 1:
        return {
            ".mine-input-hashes": ("cache", "import"),
            ".mine-last-run": ("cache", "import"),
            ".fold-state.json": ("cache", "import"),
            ".pool-broken-links.json": ("obsolete-cache", "report"),
            "ARTIFACTS.md": ("projection", "report"),
        }.get(name, ("foreign", "report"))
    top = parts[0]
    if len(parts) != 2 or top not in _KNOWN_TOP_DIRS:
        return ("foreign", "report")
    if top == "portable":
        return ("portable-snapshot", "import") if name.endswith(PORTABLE_SUFFIX) else ("foreign", "report")
    if top == "mined":
        if name == ".fold-ledger.jsonl":
            return ("durable-ledger", "import")
        if name.startswith(".") and name.endswith(".provenance.json"):
            return ("durable-evidence", "import")
        if name.startswith(".") and name.endswith(".prev"):
            return ("recovery", "import")
        if name.endswith(".md"):
            return ("durable-knowledge", "import")
        return ("foreign", "report")
    if top == "rules":
        return {
            "ledger.json": ("durable-ledger", "import"),
            "promote.notify": ("directive", "import"),
            "report.md": ("projection", "report"),
        }.get(name, ("foreign", "report"))
    if top == "review-retro":
        if name == "pending.json":
            return ("durable-ledger", "import")
        if name == "pending.notified":
            return ("cache", "import")
        if name.endswith(".runlog.jsonl"):
            return ("durable-ledger", "import")
        if name.endswith((".last-head", ".surfaced")):
            return ("cache", "import")
        return ("foreign", "report")
    if top == "reconcile":
        return ("durable-ledger", "import") if name.endswith(".jsonl") else ("foreign", "report")
    if top == "currency":
        if name.endswith(".notify"):
            return ("directive", "import")
        if name.endswith(".last-run"):
            return ("drift-state", "import")
        return ("foreign", "report")
    if top == "reduce":
        return ("cache", "import") if name.endswith(".cohesive.json") else ("foreign", "report")
    if top == "diagnostics":
        return ("worker-diagnostics", "import") if name.endswith(".jsonl") else ("foreign", "report")
    if top == "corpus-baseline":
        return ("corpus-baseline", "import") if name.endswith(".json") else ("foreign", "report")
    if top == "locks":
        return ("dirty-marker", "report") if name.endswith(".dirty") else ("foreign", "report")
    return ("foreign", "report")


def _jsonl_lines(raw: bytes) -> list[object]:
    """Parse JSONL; raises ValueError naming the first bad line."""
    out = []
    for index, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {index} is not valid JSON: {exc}") from None
    return out


_RULES_LEDGER_STATUSES = frozenset({"pending-file", "promoted", "demoted", "candidate"})
_PENDING_LEDGER_STATUSES = frozenset({"pending", "promoted", "declined"})
# Mirror of learnings-review-retro.sh's `_LEDGER_KNOWN_KEYS` (Decision 6
# hardening 2): the exact top-level key set `reconcile_ledger` constructs --
# an unrecognized key must reject the whole file rather than round-trip
# unvalidated forever.
_PENDING_LEDGER_KNOWN_KEYS = frozenset(
    {
        "status",
        "first_queued",
        "project_count",
        "projects",
        "total",
        "directives",
        "decided_at",
        "decided_project_count",
    }
)

# Part 4 additive schema mirror of learnings-rules.sh's own constants/helpers
# (three-touch-point rule: this validator, learnings-rules.sh::_valid_ledger_entry,
# and the import planner all enforce the identical shape).
_RULES_PROMOTION_SCOPE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_RULES_PROVENANCE_KEYS = frozenset({"nugget", "domain", "distilled_from", "seen_in"})
_RULES_EVIDENCE_KEYS = frozenset({"date", "recurrence", "source"})
_RULES_MAX_EVIDENCE_ENTRIES = 5
# Part 5 decision 1/11 additive schema mirror: the `candidate` status's
# `source` token (same three-touch-point rule).
_RULES_SOURCE_KEYS = frozenset({"kind", "ref"})
# Part 6 decision 3 mirror: the review track's discriminated provenance
# shape, selected by `source.kind == "review-misses"` (same three-touch-point
# rule as the constants above).
_RULES_REVIEW_PROVENANCE_KEYS = frozenset({"projects", "total", "directives", "first_queued"})
_RULES_REVIEW_MAX_DIRECTIVES = 6
# Part 6D decision 4 mirror: Track B's discriminated provenance shape,
# selected by `source.kind == "review-loops"` (same three-touch-point rule
# as the constants above).
_RULES_LOOP_PROVENANCE_KEYS = frozenset({"projects", "sessions", "first_queued"})


def _rules_is_valid_promotion_scope(value: object) -> bool:
    """Mirror of `learnings-rules.sh::is_valid_promotion_scope`: nominal
    syntax check only, no catalog-membership check (Part 6)."""
    if value is None:
        return True
    if not isinstance(value, str) or not value.startswith("project:"):
        return False
    project_key = value[len("project:") :]
    return bool(project_key) and bool(_RULES_PROMOTION_SCOPE_KEY_RE.match(project_key))


def _validate_rules_ledger(data: dict) -> None:
    """Mirror of `learnings-rules.sh::load_ledger`'s fail-loud shape gate:
    a global bool `armed` plus per-slug entry records."""
    if not isinstance(data.get("armed"), bool):
        raise ValueError("rules ledger: 'armed' must be a bool")
    entries = data.get("entries")
    if not isinstance(entries, dict):
        raise ValueError("rules ledger: 'entries' must be an object")
    for key, entry in entries.items():
        if not isinstance(entry, dict):
            raise ValueError(f"rules ledger entry {key!r}: not an object")
        if entry.get("status") not in _RULES_LEDGER_STATUSES:
            raise ValueError(
                f"rules ledger entry {key!r}: invalid status {entry.get('status')!r}"
            )
        is_candidate = entry["status"] == "candidate"
        promotion_scope = entry.get("promotion_scope")
        if not _rules_is_valid_promotion_scope(promotion_scope):
            raise ValueError(
                f"rules ledger entry {key!r}: invalid 'promotion_scope' {promotion_scope!r}"
            )
        is_project_scoped = promotion_scope is not None
        if is_candidate and is_project_scoped:
            raise ValueError(
                f"rules ledger entry {key!r}: candidate 'promotion_scope' must be null or absent"
            )

        # Part 6C decision 5: `source` is extracted here, ABOVE the `line`
        # checks below, mirroring the same reorder in
        # `learnings-rules.sh::_valid_ledger_entry` -- the review-track
        # `line` rules need `source_kind` to discriminate.
        source = entry.get("source")
        if is_candidate and source is None:
            raise ValueError(f"rules ledger entry {key!r}: candidate requires 'source'")
        if source is not None:
            if not isinstance(source, dict) or set(source.keys()) != _RULES_SOURCE_KEYS:
                raise ValueError(
                    f"rules ledger entry {key!r}: 'source' must be an object with "
                    f"exactly {sorted(_RULES_SOURCE_KEYS)}"
                )
            if not isinstance(source.get("kind"), str) or not source["kind"]:
                raise ValueError(f"rules ledger entry {key!r}: source 'kind' must be a non-empty str")
            if not isinstance(source.get("ref"), str) or not source["ref"]:
                raise ValueError(f"rules ledger entry {key!r}: source 'ref' must be a non-empty str")
        source_kind = source.get("kind") if isinstance(source, dict) else None

        # Part 6E decision 3 mirror: `review-misses` has NO project-scoped
        # projection channel, ever -- it projects to the single shared
        # gate data file, never a per-project rules file, so a
        # project-scoped `review-misses` entry is a hand-corruption case.
        # Runs for every status, not just `promoted`. Replaces 6D's
        # `review-loops` + scope rejection (deleted): decision 3 gives
        # `review-loops` a project-scoped channel as of this slice.
        if source_kind == "review-misses" and is_project_scoped:
            raise ValueError(
                f"rules ledger entry {key!r}: source.kind 'review-misses' has no "
                "project-scoped projection channel; 'promotion_scope' must be absent"
            )

        line = entry.get("line")
        if line is not None and not isinstance(line, str):
            raise ValueError(f"rules ledger entry {key!r}: 'line' must be str or null")
        if is_candidate:
            if line is not None:
                raise ValueError(f"rules ledger entry {key!r}: candidate 'line' must be null")
        elif entry["status"] in ("promoted", "pending-file"):
            if entry["status"] == "pending-file" and source_kind == "review-misses":
                # Part 6C decision 5: a review entry may never hold status
                # `pending-file` -- its placement always resolves
                # `local_target` to `None`, and `heal_pending` passes that
                # straight to `read_rules_file`. Forbidding the state here
                # makes that path unreachable rather than adding a `None`
                # guard there.
                #
                # Part 6D decision 9: this check stays scoped to
                # `review-misses` exactly -- `review-loops` DOES write a
                # rules-file line, so `pending-file` is its legitimate
                # crash-recovery marker, the same role `portable-mine`
                # already uses it for.
                raise ValueError(
                    f"rules ledger entry {key!r}: status 'pending-file' is not valid "
                    f"for source.kind 'review-misses'"
                )
            if is_project_scoped and entry["status"] == "promoted":
                # Part 6E decision 5 mirror: relaxed from "must be exactly
                # null" -- `line: None` (channel-off / pre-6E residue) or
                # the real projected text. The type check must come first:
                # `not line` alone lets a non-str (5, ["x"], True) slip
                # through, since `not 5` is False and the old exactly-null
                # pin would have caught it.
                if line is not None and not (isinstance(line, str) and line):
                    raise ValueError(
                        f"rules ledger entry {key!r}: project-scoped 'promoted' entry "
                        "'line' must be null or a non-empty str"
                    )
            elif is_project_scoped and entry["status"] == "pending-file":
                # Part 6E decision 5 mirror: explicit pin -- `pending-file`
                # is strictly the two-phase crash marker, so a null-line
                # variant would be unconvergeable.
                if not (isinstance(line, str) and line):
                    raise ValueError(
                        f"rules ledger entry {key!r}: project-scoped 'pending-file' "
                        "entry must have a non-empty str 'line'"
                    )
            elif source_kind == "review-misses" and entry["status"] == "promoted":
                # Part 6C decision 5: a gate projection carries no Markdown
                # line -- EXACTLY `None`, mirroring the project-scoped
                # inversion above rather than merely permitting a string.
                if line is not None:
                    raise ValueError(
                        f"rules ledger entry {key!r}: review-misses 'promoted' entry must have line=null"
                    )
            elif not (isinstance(line, str) and line):
                # Part 6D decision 10: `review-loops` falls through to this
                # generic branch DELIBERATELY -- it requires a non-empty
                # `line` for `promoted`/`pending-file`, the OPPOSITE of the
                # `review-misses` rule immediately above. This is not an
                # oversight; it is the direct consequence of the two kinds
                # projecting to different surfaces. `review-misses` projects
                # to the gate data file, never a Markdown line, so `line`
                # must be exactly `None`. `review-loops` projects to the
                # shared rules file, exactly like `portable-mine`, so `line`
                # must be the real projected text. Do not "fix" this into
                # matching `review-misses`.
                raise ValueError(
                    f"rules ledger entry {key!r}: 'line' must be a non-empty str "
                    f"for status {entry['status']!r}"
                )
        remapped_to = entry.get("remapped_to")
        if remapped_to is not None and not isinstance(remapped_to, str):
            raise ValueError(
                f"rules ledger entry {key!r}: 'remapped_to' must be str or absent"
            )
        if is_candidate and remapped_to is not None:
            raise ValueError(
                f"rules ledger entry {key!r}: candidate 'remapped_to' must be null or absent"
            )
        if not isinstance(entry.get("date"), str):
            raise ValueError(f"rules ledger entry {key!r}: 'date' must be str")
        rec = entry.get("recurrence_at_decision")
        if not isinstance(rec, int) or isinstance(rec, bool):
            raise ValueError(
                f"rules ledger entry {key!r}: 'recurrence_at_decision' must be int"
            )
        if is_candidate and rec != 0:
            # Co-review F4: consistency, not impact -- every admission path
            # already writes exactly 0 (decision 11), and a corrupt value
            # here is inert in practice (promote_slug overwrites it from the
            # pool at promotion). But the candidate shape already rejects
            # `line`, `promotion_scope`, `remapped_to`, and `superseded_by`
            # in this same block; leaving this one field unpinned is an
            # inconsistency in an otherwise fully-pinned shape, not a live
            # correctness gap.
            raise ValueError(
                f"rules ledger entry {key!r}: candidate 'recurrence_at_decision' must be 0"
            )

        provenance = entry.get("provenance")
        if is_candidate and provenance is None:
            # Co-review F3: decision 11 and the branch's provenance-complete
            # contract require it -- `source` was already mandatory for
            # candidates; `provenance` must be too.
            raise ValueError(f"rules ledger entry {key!r}: candidate requires 'provenance'")
        if provenance is not None:
            # Part 6 decision 3, Part 6D decision 4: discriminated by
            # `source.kind`, mirroring learnings-rules.sh::_valid_provenance
            # -- "review-misses" selects the review-track shape,
            # "review-loops" selects Track B's shape; everything else (absent
            # source, or a kind this module does not itself mint) keeps the
            # original portable-mine shape, unchanged in every respect.
            if source_kind == "review-misses":
                if not isinstance(provenance, dict) or set(provenance.keys()) != _RULES_REVIEW_PROVENANCE_KEYS:
                    raise ValueError(
                        f"rules ledger entry {key!r}: provenance for source.kind 'review-misses' "
                        f"must be an object with exactly {sorted(_RULES_REVIEW_PROVENANCE_KEYS)}"
                    )
                projects = provenance.get("projects")
                if not isinstance(projects, list) or not all(isinstance(p, str) for p in projects):
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'projects' must be a list of str")
                total = provenance.get("total")
                if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'total' must be a non-negative int")
                directives = provenance.get("directives")
                if (
                    not isinstance(directives, list)
                    or not all(isinstance(d, str) for d in directives)
                    or len(directives) > _RULES_REVIEW_MAX_DIRECTIVES
                ):
                    raise ValueError(
                        f"rules ledger entry {key!r}: provenance 'directives' must be a list of at "
                        f"most {_RULES_REVIEW_MAX_DIRECTIVES} str"
                    )
                first_queued = provenance.get("first_queued")
                if not isinstance(first_queued, str) or not first_queued:
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'first_queued' must be a non-empty str")
            elif source_kind == "review-loops":
                if not isinstance(provenance, dict) or set(provenance.keys()) != _RULES_LOOP_PROVENANCE_KEYS:
                    raise ValueError(
                        f"rules ledger entry {key!r}: provenance for source.kind 'review-loops' "
                        f"must be an object with exactly {sorted(_RULES_LOOP_PROVENANCE_KEYS)}"
                    )
                projects = provenance.get("projects")
                if not isinstance(projects, list) or not all(isinstance(p, str) and p for p in projects):
                    raise ValueError(
                        f"rules ledger entry {key!r}: provenance 'projects' must be a list of non-empty str"
                    )
                sessions = provenance.get("sessions")
                if not isinstance(sessions, int) or isinstance(sessions, bool) or sessions < 0:
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'sessions' must be a non-negative int")
                first_queued = provenance.get("first_queued")
                if not isinstance(first_queued, str) or not first_queued:
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'first_queued' must be a non-empty str")
            else:
                if not isinstance(provenance, dict) or set(provenance.keys()) != _RULES_PROVENANCE_KEYS:
                    raise ValueError(
                        f"rules ledger entry {key!r}: 'provenance' must be an object with "
                        f"exactly {sorted(_RULES_PROVENANCE_KEYS)}"
                    )
                if not isinstance(provenance.get("nugget"), str) or not provenance["nugget"]:
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'nugget' must be a non-empty str")
                if provenance.get("domain") is not None and not isinstance(provenance["domain"], str):
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'domain' must be str or null")
                if provenance.get("distilled_from") is not None and not isinstance(
                    provenance["distilled_from"], str
                ):
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'distilled_from' must be str or null")
                seen_in = provenance.get("seen_in")
                if not isinstance(seen_in, list) or not all(isinstance(s, str) for s in seen_in):
                    raise ValueError(f"rules ledger entry {key!r}: provenance 'seen_in' must be a list of str")

        evidence = entry.get("evidence")
        if evidence is not None:
            if not isinstance(evidence, list) or len(evidence) > _RULES_MAX_EVIDENCE_ENTRIES:
                raise ValueError(
                    f"rules ledger entry {key!r}: 'evidence' must be a list of at "
                    f"most {_RULES_MAX_EVIDENCE_ENTRIES} entries"
                )
            for ev in evidence:
                if not isinstance(ev, dict) or set(ev.keys()) != _RULES_EVIDENCE_KEYS:
                    raise ValueError(
                        f"rules ledger entry {key!r}: evidence entry must be an object "
                        f"with exactly {sorted(_RULES_EVIDENCE_KEYS)}"
                    )
                if not isinstance(ev.get("date"), str):
                    raise ValueError(f"rules ledger entry {key!r}: evidence 'date' must be str")
                ev_rec = ev.get("recurrence")
                if not isinstance(ev_rec, int) or isinstance(ev_rec, bool):
                    raise ValueError(f"rules ledger entry {key!r}: evidence 'recurrence' must be int")
                if not isinstance(ev.get("source"), str):
                    raise ValueError(f"rules ledger entry {key!r}: evidence 'source' must be str")

        superseded_by = entry.get("superseded_by")
        if superseded_by is not None and not isinstance(superseded_by, str):
            raise ValueError(f"rules ledger entry {key!r}: 'superseded_by' must be str or absent")
        if is_candidate and superseded_by is not None:
            raise ValueError(
                f"rules ledger entry {key!r}: candidate 'superseded_by' must be null or absent"
            )

        # Decision 12: `replaces_line` mirrored now (type only), valid only
        # while an overwrite's intent is staged on a `pending-file` record.
        replaces_line = entry.get("replaces_line")
        if replaces_line is not None and (not isinstance(replaces_line, str) or not replaces_line):
            # Co-review F5: an empty string passed `isinstance(..., str)`
            # while `learnings-rules.sh::_settle_replaces_line`'s own gate
            # treats it as a hand-corrupted record and silently drops the
            # intent -- a fail-loud validator must not admit a state the
            # runtime silently discards.
            raise ValueError(f"rules ledger entry {key!r}: 'replaces_line' must be a non-empty str or null")
        if replaces_line is not None and entry["status"] != "pending-file":
            raise ValueError(
                f"rules ledger entry {key!r}: 'replaces_line' is only valid on status 'pending-file'"
            )


def _validate_pending_ledger(data: dict) -> None:
    """Mirror of `learnings-review-retro.sh::_validate_ledger`'s wholesale
    shape gate: a status record per candidate slug."""
    for slug, entry in data.items():
        if not isinstance(entry, dict):
            raise ValueError(f"pending ledger entry {slug!r}: not an object")
        if set(entry.keys()) - _PENDING_LEDGER_KNOWN_KEYS:
            raise ValueError(f"pending ledger entry {slug!r}: unrecognized key(s)")
        if entry.get("status") not in _PENDING_LEDGER_STATUSES:
            raise ValueError(
                f"pending ledger entry {slug!r}: invalid status {entry.get('status')!r}"
            )
        for field_name in ("project_count", "total"):
            value = entry.get(field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(
                    f"pending ledger entry {slug!r}: {field_name!r} must be a non-negative int"
                )
        for field_name in ("projects", "directives"):
            value = entry.get(field_name)
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError(
                    f"pending ledger entry {slug!r}: {field_name!r} must be a list of strings"
                )
        if not isinstance(entry.get("first_queued"), str):
            raise ValueError(f"pending ledger entry {slug!r}: 'first_queued' must be str")
        if not isinstance(entry.get("decided_at"), (str, type(None))):
            raise ValueError(
                f"pending ledger entry {slug!r}: 'decided_at' must be str or null"
            )
        dpc = entry.get("decided_project_count")
        if dpc is not None and (not isinstance(dpc, int) or isinstance(dpc, bool) or dpc < 0):
            raise ValueError(
                f"pending ledger entry {slug!r}: 'decided_project_count' must be a "
                "non-negative int or absent"
            )


def _validate_owned_bytes(rel: str, kind: str, raw: bytes) -> str | None:
    """Shape/invariant gate for one owned artifact's bytes. Returns None when
    sound, else the exact defect (the caller maps it to block vs reset)."""
    name = rel.rsplit("/", 1)[-1]
    try:
        if kind == "durable-ledger":
            if name == ".fold-ledger.jsonl":
                for record in _jsonl_lines(raw):
                    if not isinstance(record, dict) or any(
                        key not in record for key in _FOLD_LEDGER_REQUIRED_KEYS
                    ):
                        raise ValueError("ledger record missing required keys")
            elif name.endswith(".runlog.jsonl"):
                for record in _jsonl_lines(raw):
                    if not isinstance(record, dict):
                        raise ValueError("runlog record is not an object")
            elif rel.startswith("reconcile/"):
                slug = name.removesuffix(".jsonl")
                for record in _jsonl_lines(raw):
                    if not isinstance(record, dict) or any(
                        not isinstance(record.get(key), str) or not record.get(key)
                        for key in _RECONCILE_REQUIRED_KEYS
                    ):
                        raise ValueError("reconcile record missing required keys")
                    try:
                        derived = legacy_slug(Path(record["project_path"]))
                    except ValueError:
                        derived = None
                    if derived != slug:
                        raise ValueError(
                            f"slug correspondence violated: project_path "
                            f"{record['project_path']!r} does not derive {slug!r}"
                        )
            else:  # rules/ledger.json, review-retro/pending.json
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("ledger is not a JSON object")
                if rel == "rules/ledger.json":
                    _validate_rules_ledger(data)
                else:
                    _validate_pending_ledger(data)
        elif kind == "durable-evidence":
            # Mirror of `learnings-mine.sh::load_all_provenance`: the live
            # writer produces {"groups": [[str,...],...]}; the legacy flat
            # form is {"bullets": [str,...]}. Anything else is a defect.
            data = json.loads(raw.decode("utf-8"))
            sound = False
            if isinstance(data, dict):
                if isinstance(data.get("groups"), list):
                    sound = all(
                        isinstance(g, list) and all(isinstance(b, str) for b in g)
                        for g in data["groups"]
                    )
                elif isinstance(data.get("bullets"), list):
                    sound = all(isinstance(b, str) for b in data["bullets"])
            if not sound:
                raise ValueError(
                    "provenance sidecar is not a {'groups': [[str,...],...]} "
                    "or legacy {'bullets': [str,...]} object"
                )
        elif kind == "drift-state":
            if not isinstance(json.loads(raw.decode("utf-8")), dict):
                raise ValueError("currency state is not a JSON object")
        elif kind == "worker-diagnostics":
            # Per-line JSONL validator (decision 9): a whole-file json.loads
            # would reject any multi-line diagnostics log as "Extra data".
            # global.jsonl is the designed aggregate of uncataloged roots and
            # null-project mine-chain records, so it alone is exempt from the
            # uniform-project_path rule below.
            lines = _jsonl_lines(raw)
            for record in lines:
                if not is_valid_worker_failure_record(record):
                    raise ValueError("diagnostics record fails schema validation")
            if name != "global.jsonl":
                # Exactly one uniform non-null project_path (council review,
                # fix round 2): an EMPTY or whitespace-only file used to slip
                # through the >1 check with zero paths, skip the slug check,
                # and mint a spurious legacy-orphan project in pass 2.
                project_paths = {record["project_path"] for record in lines}
                if len(project_paths) != 1 or None in project_paths:
                    raise ValueError(
                        f"diagnostics file must carry exactly one uniform "
                        f"non-null project_path; found "
                        f"{sorted(str(p) for p in project_paths)}"
                    )
                (only_path,) = project_paths
                # The writer records str(Path.resolve()) at entry, so a
                # relative or empty path is corruption — and legacy_slug
                # would resolve it against the IMPORTER's cwd, silently
                # deriving a wrong slug.
                if not Path(only_path).is_absolute():
                    raise ValueError(
                        f"diagnostics project_path {only_path!r} is not absolute"
                    )
                # Slug correspondence, same rule as reconcile/ above (council
                # review): a misnamed file would otherwise pass validation,
                # fail the pass-2 slug lookup, and silently mint a spurious
                # legacy-orphan project instead of blocking loudly.
                try:
                    derived = legacy_slug(Path(only_path))
                except ValueError:
                    derived = None
                if derived != name.removesuffix(".jsonl"):
                    raise ValueError(
                        f"slug correspondence violated: project_path "
                        f"{only_path!r} does not derive "
                        f"{name.removesuffix('.jsonl')!r}"
                    )
        elif kind == "corpus-baseline":
            data = json.loads(raw.decode("utf-8"))
            if not is_valid_corpus_baseline_record(data):
                raise ValueError("corpus baseline fails schema validation")
        elif kind == "cache":
            if name == ".mine-input-hashes":
                data = json.loads(raw.decode("utf-8"))
                if not isinstance(data, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in data.items()
                ):
                    raise ValueError("mine cache is not a {slug: digest} object")
            elif name in (".fold-state.json",) or name.endswith(".cohesive.json"):
                if not isinstance(json.loads(raw.decode("utf-8")), dict):
                    raise ValueError("cache is not a JSON object")
            elif name == "pending.notified" or name.endswith(".surfaced"):
                if not isinstance(json.loads(raw.decode("utf-8")), list):
                    raise ValueError("cache is not a JSON list")
            # .mine-last-run / *.last-head: opaque small text is sound.
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        return str(exc)
    return None


def _apply_portable_preferences(
    conflicts: dict[str, dict[str, str]], preferences
) -> tuple[dict[str, str], list[str]]:
    """Resolve repeatable --prefer-portable selections against the CURRENT
    conflict set (canonical -> {alias: digest}, divergent digests only).
    Returns (selections by canonical, errors). Zero or multiple matches,
    an alias shared by multiple candidate identities, and two different
    selections for one project all fail with the relevant candidates."""
    selections: dict[str, str] = {}
    errors: list[str] = []
    seen: list[str] = []
    for preference in preferences:
        normalized = str(preference).removesuffix(PORTABLE_SUFFIX)
        if normalized in seen:
            continue  # repeating the same preference is idempotent
        seen.append(normalized)
        matches = [
            (canonical, alias)
            for canonical, aliases in sorted(conflicts.items())
            for alias in sorted(aliases)
            if alias == normalized
        ]
        if not matches:
            candidates = sorted({a for aliases in conflicts.values() for a in aliases})
            errors.append(
                f"--prefer-portable {preference!r} matches no alias in any current "
                f"conflict (candidates: {candidates})"
            )
            continue
        if len(matches) > 1:
            owners = sorted({canonical for canonical, _ in matches})
            errors.append(
                f"--prefer-portable {preference!r} is shared by multiple candidate "
                f"identities: {owners}"
            )
            continue
        canonical, alias = matches[0]
        if canonical in selections and selections[canonical] != alias:
            errors.append(
                f"two different aliases selected for {canonical}: "
                f"{selections[canonical]!r} and {alias!r}"
            )
            continue
        selections[canonical] = alias
    return selections, errors


class _AliasGroup:
    def __init__(self, identity: ProjectIdentity):
        self.identity = identity
        self.aliases: dict[str, str] = {}  # portable alias -> content digest
        self.state_aliases: set[str] = set()
        self.roots: set[str] = set()
        # Producer-side path strings AS GIVEN (pool symlink target parents,
        # reconcile project_path values) — the review-retro producer hashes
        # its path un-resolved, so raw strings key retro state too.
        self.raw_roots: set[str] = set()


def _merge_diagnostics_records(sources: tuple[tuple[str, str], ...], root: Path) -> bytes | None:
    """ts-ordered JSONL merge of two or more validated diagnostics sources
    (decision 9). Every source is re-read and digest-verified individually
    against its recorded digest; the merged payload is the concatenation of
    every record, sorted by `ts` (source order breaks ties, so a merge is
    deterministic even across equal timestamps). Returns None on any
    mismatch or read failure — the caller treats that as "source changed;
    rerun" at plan time, or "source changed while staging; rerun apply"."""
    records: list[tuple[object, int, dict]] = []
    for order, (rel, expected_digest) in enumerate(sources):
        raw = _read_file_capped(root / rel)
        if raw is None or hashlib.sha256(raw).hexdigest() != expected_digest:
            return None
        try:
            lines = _jsonl_lines(raw)
        except ValueError:
            return None
        for record in lines:
            if not isinstance(record, dict):
                return None
            records.append((record.get("ts"), order, record))
    records.sort(key=lambda item: (item[0], item[1]))
    return "".join(
        json.dumps(record, ensure_ascii=False) + "\n" for _ts, _order, record in records
    ).encode("utf-8")


def plan_import(legacy_root: Path | str, *, prefer_portable=()) -> ImportPlan:
    """Deterministic read-only import plan over the owned legacy allowlist.

    Writes nothing anywhere, holds no lock across the scan (decisions 5/16);
    snapshot consistency comes from the inventory digest computed before and
    after the scan — a mismatch returns 'source changed; rerun'."""
    root = Path(legacy_root)
    blockers: list[str] = []
    reports: list[str] = []
    resets: list[str] = []
    artifacts: list[PlanArtifact] = []
    preferences_recorded: list[tuple[str, str]] = []

    inventory_digest, entries = _source_inventory(root)
    if not root.is_dir():
        return ImportPlan(
            str(root), inventory_digest, None, False, (), (),
            (), (f"legacy root absent: {root}",), (), (),
        )

    groups: dict[str, _AliasGroup] = {}
    orphan_aliases: set[str] = set()
    identity_cache: dict[str, ProjectIdentity] = {}

    def identity_for_root(project_root: Path) -> ProjectIdentity | None:
        key = str(project_root.resolve())
        if key not in identity_cache:
            try:
                identity_cache[key] = project_identity(project_root)
            except IdentityResolutionError as exc:
                blockers.append(f"cannot resolve project identity for {project_root}: {exc}")
                return None
        return identity_cache[key]

    def group_for_root(project_root: Path) -> _AliasGroup | None:
        identity = identity_for_root(project_root)
        if identity is None:
            return None
        group = groups.setdefault(identity.canonical, _AliasGroup(identity))
        group.roots.add(str(project_root.resolve()))
        return group

    def harvested_group_for_root(project_root: Path) -> _AliasGroup | None:
        """Like group_for_root, but an identity failure keeps the
        legacy-orphan preservation fallback instead of blocking the plan."""
        key = str(project_root.resolve())
        if key not in identity_cache:
            try:
                identity_cache[key] = project_identity(project_root)
            except IdentityResolutionError:
                return None
        identity = identity_cache[key]
        group = groups.setdefault(identity.canonical, _AliasGroup(identity))
        group.roots.add(key)
        return group

    # --- pass 1: portable pool -> alias candidates and known project roots.
    pool_items: list[tuple[str, dict]] = sorted(
        (rel, meta) for rel, meta in entries.items()
        if rel.startswith("portable/") and meta.get("type") != "dir"
    )
    for rel, meta in pool_items:
        name = rel.rsplit("/", 1)[-1]
        kind, _action = _classify_source_path(rel)
        if kind != "portable-snapshot":
            artifacts.append(PlanArtifact(rel, kind, "report", None, "unowned pool entry", None))
            reports.append(f"{rel}: unowned pool entry")
            continue
        alias = name.removesuffix(PORTABLE_SUFFIX)
        if meta["type"] != "symlink":
            detail = "regular-file pool impostor (the v1 pool is symlink-only)"
            artifacts.append(PlanArtifact(rel, kind, "block", None, detail, None))
            blockers.append(f"{rel}: {detail}")
            continue
        target_str = meta.get("target") or ""
        target = Path(target_str)
        if not target.is_absolute():
            detail = f"relative symlink target {target_str!r}"
            artifacts.append(PlanArtifact(rel, kind, "block", None, detail, None))
            blockers.append(f"{rel}: {detail}")
            continue
        if target.name != name:
            detail = f"basename-mismatched symlink target {target_str!r}"
            artifacts.append(PlanArtifact(rel, kind, "block", None, detail, None))
            blockers.append(f"{rel}: {detail}")
            continue
        raw = _read_file_capped(target)
        project_root = target.parent
        group = group_for_root(project_root) if project_root.is_dir() else None
        canonical = group.identity.canonical if group else None
        if group is not None:
            group.raw_roots.add(str(project_root))
        if raw is None:
            detail = _pool_target_defect(target)
            artifacts.append(PlanArtifact(rel, kind, "report", None, detail, canonical))
            reports.append(f"{rel}: {detail}")
            continue
        if not _DISTILLED_FROM_RE.search(raw.decode("utf-8", errors="replace")):
            detail = "unowned/hand-authored portable (no distilled-from marker); not imported"
            artifacts.append(PlanArtifact(rel, kind, "report", None, detail, canonical))
            reports.append(f"{rel}: {detail}")
            continue
        if group is None:
            detail = "portable target's project directory is unresolvable"
            artifacts.append(PlanArtifact(rel, kind, "block", None, detail, None))
            blockers.append(f"{rel}: {detail}")
            continue
        group.aliases[alias] = hashlib.sha256(raw).hexdigest()
        artifacts.append(
            PlanArtifact(rel, kind, "import", group.aliases[alias], "validated portable snapshot", canonical)
        )

    # --- state-only projects: a project can hold reconcile/currency/reduce/
    # retro state without any current pool symlink. Validated reconcile
    # records carry project_path; an extant, identity-resolvable root joins
    # the real project maps rather than falling to legacy-orphan (which
    # remains the preservation fallback for unresolvable paths).
    for rel, meta in sorted(entries.items()):
        parts = rel.split("/")
        if len(parts) != 2 or parts[0] != "reconcile" or meta.get("type") != "file":
            continue
        if _classify_source_path(rel)[0] != "durable-ledger":
            continue
        raw = _read_file_capped(root / rel)
        if raw is None or _validate_owned_bytes(rel, "durable-ledger", raw) is not None:
            continue  # pass 2 blocks the defect; nothing sound to harvest
        for record in _jsonl_lines(raw):
            project_path = record["project_path"]
            candidate = Path(project_path)
            if not candidate.is_dir():
                continue
            group = harvested_group_for_root(candidate)
            if group is not None:
                group.raw_roots.add(project_path)

    # --- state-only projects, diagnostics: a project can hold a diagnostics
    # log alone (decision 9, council round 2) — without this harvest, such a
    # project would produce an unmapped legacy-orphan instead of joining its
    # real identity. global.jsonl is excluded: it names no single project.
    for rel, meta in sorted(entries.items()):
        parts = rel.split("/")
        if len(parts) != 2 or parts[0] != "diagnostics" or meta.get("type") != "file":
            continue
        if parts[1] == "global.jsonl":
            continue
        if _classify_source_path(rel)[0] != "worker-diagnostics":
            continue
        raw = _read_file_capped(root / rel)
        if raw is None or _validate_owned_bytes(rel, "worker-diagnostics", raw) is not None:
            continue  # pass 2 blocks the defect; nothing sound to harvest
        for record in _jsonl_lines(raw):
            project_path = record.get("project_path")
            if project_path is None:
                continue
            candidate = Path(project_path)
            if not candidate.is_dir():
                continue
            group = harvested_group_for_root(candidate)
            if group is not None:
                group.raw_roots.add(project_path)

    # --- state-only projects, corpus baseline: a project can hold a corpus
    # baseline alone (decision 9). Unlike reconcile/diagnostics — which carry
    # a live project_path to re-probe via project_identity() — a baseline
    # stores its own VALIDATED canonical/key directly, so the harvest joins
    # (or creates) a group from those fields with no second git probe.
    # corpus_baseline_map keys every seen <slug>.json's basename to its
    # validated canonical, so project_for_state_file below never needs a
    # parallel path-derived table for corpus-baseline files.
    corpus_baseline_map: dict[str, str] = {}
    for rel, meta in sorted(entries.items()):
        parts = rel.split("/")
        if len(parts) != 2 or parts[0] != "corpus-baseline" or meta.get("type") != "file":
            continue
        if _classify_source_path(rel)[0] != "corpus-baseline":
            continue
        raw = _read_file_capped(root / rel)
        if raw is None or _validate_owned_bytes(rel, "corpus-baseline", raw) is not None:
            continue  # pass 2 blocks the defect; nothing sound to harvest
        record = json.loads(raw.decode("utf-8"))
        canonical = record["canonical"]
        corpus_baseline_map[parts[1].removesuffix(".json")] = canonical
        if canonical not in groups:
            identity = ProjectIdentity(canonical, record["key"].rsplit("-", 1)[0], record["key"])
            groups[canonical] = _AliasGroup(identity)

    # --- alias equivalence groups, conflicts, and preferences.
    conflicts = {
        canonical: dict(group.aliases)
        for canonical, group in groups.items()
        if len(set(group.aliases.values())) > 1
    }
    selections, preference_errors = _apply_portable_preferences(conflicts, prefer_portable)
    blockers.extend(preference_errors)
    selected: dict[str, tuple[str | None, str | None, tuple[str, ...]]] = {}
    for canonical, group in sorted(groups.items()):
        if not group.aliases:
            selected[canonical] = (None, None, ())
            continue
        digests = set(group.aliases.values())
        if len(digests) == 1:
            selected[canonical] = (next(iter(digests)), None, ())
            continue
        if canonical in selections:
            alias = selections[canonical]
            digest = group.aliases[alias]
            declined = tuple(sorted(a for a, d in group.aliases.items() if d != digest))
            selected[canonical] = (digest, alias, declined)
            preferences_recorded.append((alias, "selected"))
            preferences_recorded.extend((a, "declined") for a in declined)
        else:
            selected[canonical] = (None, None, ())
            aliases = sorted(group.aliases)
            blockers.append(
                f"project {canonical}: divergent portable aliases {aliases} — "
                f"redistill one worktree, or pass a repeatable "
                f"--prefer-portable <legacy-alias> selection"
            )
    for artifact_index, artifact in enumerate(artifacts):
        if artifact.kind != "portable-snapshot" or artifact.action != "import":
            continue
        canonical = artifact.project
        digest_alias = selected.get(canonical)
        if canonical in conflicts:
            digest, _alias, _declined = digest_alias
            if digest is None:
                artifacts[artifact_index] = PlanArtifact(
                    artifact.path, artifact.kind, "block", artifact.digest,
                    "divergent portable aliases; selection required", canonical,
                )
            elif artifact.digest != digest:
                artifacts[artifact_index] = PlanArtifact(
                    artifact.path, artifact.kind, "report", artifact.digest,
                    "declined by --prefer-portable selection; source untouched", canonical,
                )

    # --- slug indexes for state-file -> project mapping.
    reconcile_map: dict[str, str] = {}
    currency_map: dict[str, str] = {}
    retro_map: dict[str, str] = {}
    for canonical, group in groups.items():
        for observed_root in group.roots:
            observed = Path(observed_root)
            with contextlib.suppress(ValueError):
                slug = legacy_slug(observed)
                reconcile_map[slug] = canonical
                group.state_aliases.add(slug)
            currency = legacy_currency_slug(observed)
            if currency:
                currency_map[currency] = canonical
                group.state_aliases.add(currency)
            retro = legacy_review_retro_slug(observed)
            retro_map[retro] = canonical
            group.state_aliases.add(retro)
        # The retro producer hashes its path AS GIVEN (un-resolved cwd), so
        # raw producer-side path strings key retro state too.
        for raw_root in group.raw_roots:
            retro = legacy_review_retro_slug(raw_root)
            retro_map[retro] = canonical
            group.state_aliases.add(retro)

    def project_for_state_file(rel: str, name: str) -> tuple[str | None, str | None]:
        """(mapped canonical, orphan slug). Exactly one side is set for a
        per-project state file; both are None for global files. Registering
        an orphan is the CALLER's decision (durable artifacts only) — a
        rebuildable cache must never mint an orphan identity record."""
        top = rel.split("/", 1)[0]
        if top == "reconcile":
            slug = name.removesuffix(".jsonl")
            mapped = reconcile_map.get(slug)
        elif top == "currency":
            slug = name.removesuffix(".notify").removesuffix(".last-run")
            mapped = currency_map.get(slug)
        elif top == "reduce":
            slug = name.removesuffix(".cohesive.json")
            mapped = reconcile_map.get(slug)
        elif top == "review-retro" and name not in ("pending.json", "pending.notified"):
            slug = name.removesuffix(".runlog.jsonl").removesuffix(".last-head").removesuffix(".surfaced")
            mapped = retro_map.get(slug)
        elif top == "diagnostics" and name != "global.jsonl":
            # Same legacy_slug derivation as reconcile (one mapping source,
            # no parallel table) — the diagnostics writer's legacy routing
            # derives the identical slug for the identical root.
            slug = name.removesuffix(".jsonl")
            mapped = reconcile_map.get(slug)
        elif top == "corpus-baseline":
            # corpus_baseline_map was populated straight from each file's own
            # validated canonical (the harvest pass above) — no path-derived
            # table needed, since a baseline carries no project_path field.
            slug = name.removesuffix(".json")
            mapped = corpus_baseline_map.get(slug)
        else:
            return None, None
        return (mapped, None) if mapped else (None, slug)

    # --- pass 2: everything outside the portable pool.
    for rel, meta in sorted(entries.items()):
        if meta.get("type") == "dir-symlink":
            # os.walk never descends through a symlinked directory, so a
            # known top-level dir behind one would silently vanish from the
            # plan; the operator must materialize it first.
            if "/" not in rel and rel in _KNOWN_TOP_DIRS:
                detail = (
                    f"known directory is a symlink to {meta.get('target')!r}; "
                    f"the import cannot see through it — materialize it as a "
                    f"real directory and rerun"
                )
                artifacts.append(PlanArtifact(rel, "dir-symlink", "block", None, detail, None))
                blockers.append(f"{rel}: {detail}")
            else:
                artifacts.append(PlanArtifact(rel, "foreign", "report", None, "unowned symlinked directory", None))
                reports.append(f"{rel}: unowned symlinked directory")
            continue
        if rel.startswith("portable/") or rel == "portable":
            continue
        name = rel.rsplit("/", 1)[-1]
        if meta.get("type") == "dir":
            if "/" not in rel and rel in _KNOWN_TOP_DIRS:
                continue
            artifacts.append(PlanArtifact(rel, "foreign", "report", None, "unowned directory", None))
            reports.append(f"{rel}: unowned directory")
            continue
        kind, action = _classify_source_path(rel)
        if kind == "lock":
            artifacts.append(PlanArtifact(rel, kind, "skip", None, "lock inode anchor; never copied", None))
            continue
        if meta.get("type") != "file":
            artifacts.append(PlanArtifact(rel, "foreign", "report", None, f"unexpected {meta.get('type')} entry", None))
            reports.append(f"{rel}: unexpected {meta.get('type')} entry")
            continue
        mapped_project, orphan_slug = project_for_state_file(rel, name)
        if kind in ("foreign", "claimed-notification", "dirty-marker", "obsolete-cache", "projection"):
            detail = {
                "foreign": "unowned file; reported, never copied or deleted",
                "claimed-notification": "claimed notification marker (mid-claim leftover)",
                "dirty-marker": "dirty distill marker (interrupted distill evidence)",
                "obsolete-cache": "obsolete symlink-pool cache; not imported",
                "projection": "projection; regenerated rather than imported",
            }[kind]
            artifacts.append(PlanArtifact(rel, kind, "report", meta.get("digest"), detail, mapped_project))
            reports.append(f"{rel}: {detail}")
            continue
        if kind == "cache" and orphan_slug is not None:
            # Rebuildable per-project cache attached to no resolvable
            # project: reset rather than importing under a synthesized
            # orphan — the next run rebuilds it, and a cache alone never
            # mints an orphan identity record.
            detail = "rebuildable cache keyed to no resolvable project; reset"
            artifacts.append(PlanArtifact(rel, kind, "reset", None, detail, None))
            resets.append(f"{rel}: {detail}; next run rebuilds it")
            continue
        if orphan_slug is not None:
            # Durable orphan-attached history: preserved under the
            # synthesized legacy-orphan record (whose catalog key is a
            # valid identity key — see build_legacy_orphan_record).
            orphan_aliases.add(orphan_slug)
            project = f"legacy-orphan:{orphan_slug}"
        else:
            project = mapped_project
        raw = _read_file_capped(root / rel)
        if raw is None:
            defect = "not a plain regular single-link file within the size cap"
        else:
            defect = _validate_owned_bytes(rel, kind, raw)
        if defect is not None:
            if kind == "cache":
                artifacts.append(PlanArtifact(rel, kind, "reset", None, f"malformed cache: {defect}", project))
                resets.append(f"{rel}: malformed cache resets ({defect}); next run rebuilds it")
            else:
                artifacts.append(PlanArtifact(rel, kind, "block", None, defect, project))
                blockers.append(f"{rel}: {defect}")
            continue
        artifacts.append(
            PlanArtifact(rel, kind, action, hashlib.sha256(raw).hexdigest(), "validated", project)
        )

    # --- stale project-local worker copies (bounded: known roots only).
    sibling_dir = Path(__file__).resolve().parent
    for _canonical, group in sorted(groups.items()):
        for observed_root in sorted(group.roots):
            for worker in sorted(Path(observed_root).glob("bin/learnings-*.sh")):
                sibling = sibling_dir / worker.name
                if not sibling.is_file():
                    continue  # custom project helper, not a shadowed worker
                current = _read_file_capped(sibling)
                copy = _read_file_capped(worker)
                if current is None or copy is None or current != copy:
                    reports.append(
                        f"stale local worker copy: {worker} differs from the current "
                        f"installed {worker.name}"
                    )

    # --- project groups (real + synthesized legacy orphans).
    projects: list[PlanProject] = []
    for canonical, group in sorted(groups.items()):
        digest, alias, declined = selected[canonical]
        aliases = tuple(sorted(group.aliases))
        primary = alias or (aliases[0] if aliases else None)
        record = build_identity_record(
            group.identity,
            legacy_aliases=tuple(sorted(set(aliases) | group.state_aliases)),
            portable_filename=f"{primary}{PORTABLE_SUFFIX}" if primary else None,
            observed_roots=tuple(sorted(group.roots)),
        )
        projects.append(
            PlanProject(canonical, group.identity.key, group.identity.display,
                        aliases, digest, alias, declined, record)
        )
    for alias in sorted(orphan_aliases):
        record = build_legacy_orphan_record(alias)
        projects.append(
            PlanProject(record["canonical"], record["key"], record["display"],
                        (alias,), None, None, (), record)
        )
    projects.sort(key=lambda p: p.canonical)

    # --- decision 9: collapse colliding per-project diagnostics files (two
    # or more legacy slugs aliasing to the same catalog key) into one
    # ts-ordered merged artifact. A lone diagnostics file per project needs
    # no merge; _staging_copy_map routes it directly to its project.
    key_by_canonical = {p.canonical: p.key for p in projects}
    diagnostics_by_project: dict[str, list[int]] = {}
    for index, artifact in enumerate(artifacts):
        if (
            artifact.kind == "worker-diagnostics"
            and artifact.action == "import"
            and artifact.project is not None
            and artifact.path.rsplit("/", 1)[-1] != "global.jsonl"
        ):
            diagnostics_by_project.setdefault(artifact.project, []).append(index)
    merges: list[MergedPlanArtifact] = []
    for canonical, indices in sorted(diagnostics_by_project.items()):
        if len(indices) < 2:
            continue
        key = key_by_canonical.get(canonical)
        if key is None:
            blockers.append(f"diagnostics merge for {canonical}: no planned project key")
            continue
        sources = tuple(sorted((artifacts[i].path, artifacts[i].digest) for i in indices))
        merged_payload = _merge_diagnostics_records(sources, root)
        if merged_payload is None:
            blockers.append(
                f"diagnostics merge for {canonical}: a source changed during "
                f"the scan; rerun the plan"
            )
            continue
        dest = f"projects/{key}/diagnostics/workers.jsonl"
        merged_digest = hashlib.sha256(merged_payload).hexdigest()
        merges.append(MergedPlanArtifact(dest, "worker-diagnostics", sources, merged_digest, canonical))
        for i in indices:
            a = artifacts[i]
            artifacts[i] = PlanArtifact(a.path, a.kind, "merge", a.digest, f"merged into {dest}", a.project)

    # --- decision 9: colliding per-project corpus-baseline files (two or
    # more legacy slugs aliasing to the same catalog key) are compared
    # SEMANTICALLY — key/canonical/the files sha256 map — not by raw bytes,
    # since ts and head always differ between two real snapshots. Identical
    # maps adopt the newest by ts (the older sources are declined, not
    # merged — a baseline is a point-in-time fingerprint, not an append-only
    # log); differing maps BLOCK, naming both sources.
    baseline_by_project: dict[str, list[int]] = {}
    for index, artifact in enumerate(artifacts):
        if (
            artifact.kind == "corpus-baseline"
            and artifact.action == "import"
            and artifact.project is not None
        ):
            baseline_by_project.setdefault(artifact.project, []).append(index)
    for canonical, indices in sorted(baseline_by_project.items()):
        if len(indices) < 2:
            continue
        parsed: list[tuple[int, dict]] = []
        rescan_defect = False
        for i in indices:
            raw = _read_file_capped(root / artifacts[i].path)
            if raw is None or hashlib.sha256(raw).hexdigest() != artifacts[i].digest:
                rescan_defect = True
                break
            parsed.append((i, json.loads(raw.decode("utf-8"))))
        if rescan_defect:
            blockers.append(
                f"corpus-baseline collision for {canonical}: a source changed "
                f"during the scan; rerun the plan"
            )
            continue
        maps = {
            (rec["key"], rec["canonical"], tuple(sorted(rec["files"].items())))
            for _i, rec in parsed
        }
        if len(maps) == 1:
            newest_index = max(parsed, key=lambda item: item[1]["ts"])[0]
            for i, _rec in parsed:
                if i == newest_index:
                    continue
                a = artifacts[i]
                artifacts[i] = PlanArtifact(
                    a.path, a.kind, "report", a.digest,
                    f"superseded by a newer identical corpus baseline "
                    f"({artifacts[newest_index].path})",
                    a.project,
                )
        else:
            paths = sorted(artifacts[i].path for i in indices)
            detail = f"corpus-baseline collision for {canonical}: divergent baselines at {paths}"
            blockers.append(detail)
            for i in indices:
                a = artifacts[i]
                artifacts[i] = PlanArtifact(a.path, a.kind, "block", None, detail, a.project)

    # --- snapshot consistency: inventory digest before and after the scan.
    post_digest, _post_entries = _source_inventory(root)
    source_changed = post_digest != inventory_digest
    if source_changed:
        blockers.append("source changed during the scan; rerun the plan")

    blockers_tuple = tuple(sorted(set(blockers)))
    generation_id = None
    if not blockers_tuple and not source_changed:
        selected_content = sorted(
            (p.canonical, p.selected_digest) for p in projects if p.selected_digest
        )
        imported = sorted(
            (a.path, a.digest) for a in artifacts if a.action == "import"
        )
        merged_content = sorted((m.dest, m.merged_digest) for m in merges)
        generation_id = hashlib.sha256(
            json.dumps(
                {
                    "inventory": inventory_digest,
                    "selected": selected_content,
                    "imports": imported,
                    "merges": merged_content,
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

    return ImportPlan(
        str(root),
        inventory_digest,
        generation_id,
        source_changed,
        tuple(sorted(artifacts, key=lambda a: a.path)),
        tuple(projects),
        blockers_tuple,
        tuple(sorted(set(reports))),
        tuple(sorted(set(resets))),
        tuple(dict.fromkeys(preferences_recorded)),
        tuple(merges),
    )


def _fsync_dir(path: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _discard_initializer(init_dir: Path) -> None:
    """Remove only the OWNED hidden initializer (its two known files + dir)."""
    for name in (_IDENTITY_NAME, f".{_IDENTITY_NAME}.tmp"):
        with contextlib.suppress(OSError):
            (init_dir / name).unlink()
    with contextlib.suppress(OSError):
        init_dir.rmdir()


def _published_identity_record(project_dir: Path) -> dict | None:
    """The published record at `projects/<key>/identity.json`, or None when
    missing/unreadable/invalid or when the record does not name its own dir."""
    try:
        record = _read_json_record(project_dir / _IDENTITY_NAME)
    except (FileNotFoundError, OSError, ValueError):
        return None
    if not identity_record_is_valid(record) or record["key"] != project_dir.name:
        return None
    return record


def publish_identity_record(state_root: Path | str, record: dict) -> Path:
    """Atomically publish `projects/<key>/identity.json`.

    Writes into a hidden sibling initializer (temp + os.replace within the
    same directory, fsynced), then renames the initializer to the published
    key directory. The rename is the race arbiter: a losing initializer
    checks that the winner's validated record names the same canonical
    identity and discards only itself, so a
    published project directory is never observable without valid identity
    metadata. A mismatched or corrupt winner fails closed untouched."""
    if not identity_record_is_valid(record):
        raise ValueError("refusing to publish an invalid identity record")
    projects = Path(state_root) / "projects"
    projects.mkdir(parents=True, exist_ok=True)
    dest = projects / record["key"]
    init_dir = projects / f".init-{record['key']}.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    init_dir.mkdir()
    try:
        payload = (
            json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        tmp = init_dir / f".{_IDENTITY_NAME}.tmp"
        fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, init_dir / _IDENTITY_NAME)
        _fsync_dir(init_dir)
        try:
            os.rename(init_dir, dest)
        except OSError:
            winner = _published_identity_record(dest)
            _discard_initializer(init_dir)
            if winner is None or winner["canonical"] != record["canonical"]:
                raise IdentityResolutionError(
                    f"project key collision at {dest}: existing record does not "
                    f"match {record['canonical']!r}"
                ) from None
            return dest
        _fsync_dir(projects)
        return dest
    except BaseException:
        if init_dir.is_dir():
            _discard_initializer(init_dir)
        raise


def resolve_project_reference(state_root: Path | str, reference: str) -> str | None:
    """Map any known project identifier to ONE canonical key.

    Accepts stable keys, full canonical values (including `legacy-orphan:`
    ids), bare legacy slugs / imported `seen_in` values, and portable
    filenames (a bare slug and its `<slug>-PORTABLE-LEARNINGS.md` form
    address the same record). Returns None for an unknown reference; raises
    IdentityResolutionError on an ambiguous reference or a published project
    directory without valid identity metadata."""
    ref = (reference or "").strip()
    if not ref:
        return None
    projects = Path(state_root) / "projects"
    try:
        entries = sorted(projects.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return None
    stripped = ref.removesuffix(PORTABLE_SUFFIX) if ref.endswith(PORTABLE_SUFFIX) else None
    matched: list[str] = []
    for entry in entries:
        if entry.name.startswith(".") or not entry.is_dir():
            continue  # hidden initializers are never published records
        record = _published_identity_record(entry)
        if record is None:
            raise IdentityResolutionError(
                f"published project directory {entry} has no valid identity record"
            )
        aliases = set(record["legacy_aliases"])
        forms = {record["key"], record["canonical"], *aliases}
        if record.get("portable_filename"):
            forms.add(record["portable_filename"])
        forms.update(f"{alias}{PORTABLE_SUFFIX}" for alias in aliases)
        if ref in forms or (stripped is not None and stripped in forms):
            matched.append(record["key"])
    if len(matched) > 1:
        raise IdentityResolutionError(
            f"ambiguous project reference {ref!r}: matches {sorted(matched)}"
        )
    return matched[0] if matched else None


def normalize_remote(remote: str) -> str | None:
    """Canonicalize supported network Git URLs on host + path (+ non-default
    port), dropping scheme and userinfo so HTTPS/`ssh://`/SCP transports of
    one repository share one canonical; local forms stay non-remote."""
    value = remote.strip()
    if not value or value.startswith(("/", "./", "../", "file:")):
        return None
    if "://" not in value and re.match(r"^(?:[^@/]+@)?\[", value):
        # A bracketed IPv6 SCP form ([::1]:org/repo.git) does not fit the SCP
        # host pattern; canonicalizing it silently would emit garbage.
        raise IdentityResolutionError(f"unsupported bracketed IPv6 SCP remote: {value}")
    scp = _REMOTE_SCP_RE.match(value) if "://" not in value else None
    if scp:
        path = scp.group("path").lstrip("/").rstrip("/").removesuffix(".git")
        if re.match(r"^\d+:", path):
            return None
        if ":" in path.split("/", 1)[0]:
            # An unbracketed IPv6 SCP form (git@2001:db8::1:org/repo.git)
            # matched the SCP pattern with host="2001"; canonicalizing it
            # silently would emit garbage, same as the bracketed rejection.
            raise IdentityResolutionError(f"unsupported unbracketed IPv6 SCP remote: {value}")
        return f"{scp.group('host').lower()}/{path}" if path else None
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "ssh", "git"} or not parsed.hostname:
        return None
    defaults = {"http": 80, "https": 443, "ssh": 22, "git": 9418}
    try:
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname.lower()
    authority = host if port in (None, defaults[parsed.scheme]) else f"{host}:{port}"
    path = parsed.path.rstrip("/").removesuffix(".git")
    if not path or not path.startswith("/"):
        return None
    return f"{authority}{path}"


# git 2.56 reworded a gitfile that points at a non-repo: 2.55 said "not a git
# repository: (null)", 2.56 says "gitfile does not point to a valid repository".
_GIT_NOT_A_REPO_TOKENS = ("not a git repository", "gitfile does not point to a valid repository")


def _git(cwd: Path, *args: str) -> str | None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, env=env,
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise IdentityResolutionError("git identity probe failed") from None
    if result.returncode == 0:
        return result.stdout.strip() or None
    if any(token in result.stderr.lower() for token in (*_GIT_NOT_A_REPO_TOKENS, "must be run in a work tree")):
        return None
    raise IdentityResolutionError(f"git identity probe failed: {' '.join(args)}")




def _enrollment_owner_regex() -> re.Pattern[str] | None:
    settings = load_install_settings()
    return re.compile(settings.owned_remote_pattern, re.IGNORECASE) if settings.owned_remote_pattern else None


def enrollment_owner_qualified(root: Path) -> bool:
    """True when ``root`` is a repository we own: no remotes at all, or an
    ``origin`` under the owner pattern.

    "No remotes at all" is the local-only case, NOT "no remote named origin" —
    `git clone --origin upstream` leaves a foreign clone in the latter state.

    The remote list is read before the URL because `git remote get-url origin`
    exits non-zero with no origin, which `_git` treats as a fault, not an answer.
    A probe failure raises: unknown ownership is not evidence of foreignness.
    """
    remotes = _git(root, "remote")
    if remotes is None:
        # No remotes. The other None cause, "not a git repository", is excluded
        # by the caller's earlier rev-parse — not by anything here.
        return True
    if "origin" not in remotes.split():
        return False
    url = _git(root, "remote", "get-url", "origin")
    if url is None:
        return False
    pattern = _enrollment_owner_regex()
    return pattern is not None and bool(pattern.match(url))


def qualified_enrollment_root(project_root: Path | str, allowed_root: Path | str) -> Path | None:
    """Return the exact ``allowed/category/repository`` Git root or ``None``.

    Two gates, both required: the topology gate (an exact two-component root
    under the allowed root) and the ownership gate (``enrollment_owner_qualified``
    — no remotes at all, or an ``origin`` under the owner pattern).

    Non-Git directories, Git roots outside the exact two-component topology, and
    foreign clones are ordinary negative results. Filesystem and Git probe
    failures remain errors: unknown is not evidence that a directory is scratch
    or foreign. Lifecycle callers catch ``IdentityResolutionError`` only to emit
    a named fail-closed status; exceptions are never a negative qualification
    signal.
    """
    if not load_install_settings().auto_enroll:
        return None
    configured_allowed = Path(allowed_root).expanduser()
    try:
        project = Path(project_root).resolve(strict=True)
        allowed = configured_allowed.resolve(strict=True)
    except OSError as exc:
        raise IdentityResolutionError(f"enrollment path resolution failed: {exc}") from None
    configured_absolute = Path(os.path.abspath(configured_allowed))
    if configured_absolute != allowed:
        raise IdentityResolutionError("enrollment allowed root must not traverse a symlink")
    if not project.is_dir() or not allowed.is_dir():
        return None
    try:
        project.relative_to(allowed)
    except ValueError:
        return None
    top = _git(project, "rev-parse", "--show-toplevel")
    if top is None:
        return None
    try:
        root = Path(top).resolve(strict=True)
        relative = root.relative_to(allowed)
    except OSError as exc:
        raise IdentityResolutionError(f"enrollment Git root resolution failed: {exc}") from None
    except ValueError:
        return None
    if not root.is_dir() or len(relative.parts) != 2:
        return None
    if not enrollment_owner_qualified(root):
        return None
    return root


def project_identity(cwd: Path | str) -> ProjectIdentity:
    root = Path(cwd).resolve()
    top = _git(root, "rev-parse", "--show-toplevel")
    if top:
        root = Path(top).resolve()
    remotes = _git(root, "remote")
    remote_values: dict[str, str] = {}
    if remotes:
        for name in remotes.splitlines():
            # A transient get-url failure propagates: erroring beats silently
            # downgrading a remote-keyed project to a path/common-dir identity.
            value = _git(root, "remote", "get-url", name)
            normalized = normalize_remote(value) if value else None
            if normalized:
                remote_values[name] = normalized
    canonical = remote_values.get("origin")
    if canonical is None and len(set(remote_values.values())) == 1:
        canonical = next(iter(remote_values.values()))
    if canonical is None:
        common = _git(root, "rev-parse", "--git-common-dir")
        if common:
            common_path = Path(common)
            common_root = (root / common_path).resolve() if not common_path.is_absolute() else common_path.resolve()
            canonical = f"git-common-dir:{common_root}"
        else:
            canonical = f"path:{root}"
    if canonical.startswith("git-common-dir:"):
        common_root = Path(canonical.removeprefix("git-common-dir:"))
        # A normal bare/common `.git` directory names its worktree parent;
        # a separate git-dir has no reliable worktree basename, so retain the
        # resolved top-level display instead.
        display = common_root.parent.name if common_root.name == ".git" else common_root.name.removesuffix(".git")
    else:
        display = canonical.rsplit("/", 1)[-1].removesuffix(".git") or root.name
    local_scheme = ":" in canonical and canonical.split(":", 1)[0] in {"path", "git-common-dir"}
    identity = _identity(canonical if local_scheme else f"remote:{canonical}", display)
    return ProjectIdentity(identity.canonical, identity.display, identity.key, root)


def _identity(canonical: str, display: str) -> ProjectIdentity:
    safe = _DASH_RE.sub("-", _SLUG_INVALID_RE.sub("", display.lower().replace("_", "-").replace(" ", "-"))).strip("-")
    if not safe:
        # A display that sanitizes to nothing carries no usable name; fall
        # back on the display FIELD too so it matches the key prefix.
        safe = display = "project"
    return ProjectIdentity(canonical, display, f"{safe}-{hashlib.sha256(canonical.encode()).hexdigest()[:16]}")


# --- Part 7B1: latent external project-corpus records ----------------------

CORPUS_ACTIVE_SCHEMA_VERSION = 1
CORPUS_PROJECTION_SCHEMA_VERSION = 1
CORPUS_EPOCH_SCHEMA_VERSION = 1
CORPUS_CACHE_SCHEMA_VERSION = 1
_CORPUS_ACTIVE_NAME = "active.json"
_CORPUS_DEACTIVATED_NAME = "deactivated.json"
_CORPUS_ROLLBACK_TRANSACTION_NAME = "rollback-transaction.json"
_CORPUS_INIT_PENDING_NAME = "init-pending.json"
_CORPUS_EPOCH_NAME = ".epoch"
_CORPUS_RECORD_MAX_BYTES = 64 * 1024
CORPUS_ROLLBACK_TRANSACTION_SCHEMA_VERSION = 1
CORPUS_LEGACY_MIGRATION_AUDIT_SCHEMA_VERSION = 1
CORPUS_ABANDON_NOTICE_SCHEMA_VERSION = 1
CORPUS_INIT_PENDING_SCHEMA_VERSION = 1
EXTERNAL_CORPUS_FILE_MAX_BYTES = 1 << 20
EXTERNAL_CORPUS_MAX_CHILDREN = 256
EXTERNAL_CORPUS_DIRECTORY_MODE = 0o700
LEGACY_MIGRATION_ROSTER_MAX_BYTES = 256 * 1024
LEGACY_MIGRATION_ROSTER_MAX_ROWS = 64
CORPUS_MUTATION_JOURNAL_MAX_BYTES = 64 * 1024
LEGACY_TARGET_LOCK_TIMEOUT_SECONDS = 5.0
EXTERNAL_PROJECTION_ARTIFACT_SPECS = tuple(
    spec for spec in CORPUS_ARTIFACT_SPECS if spec != "*-PORTABLE-LEARNINGS.md"
)
CORPUS_SYNC_POLICY = {
    "clean": (0, 0, 0),
    "external-only": (3, 0, 2),
    "repository-only": (3, 2, 0),
    "both": (3, 2, 2),
    "unprojected": (2, 2, 2),
    "pending-stale": (2, 2, 2),
    "busy": (2, 2, 2),
    "sync-recovery-pending": (2, 2, 2),
    "malformed": (1, 1, 1),
}
_CORPUS_REVISION_RE = re.compile(r"^rev-[0-9a-f]{16,64}$")
_CORPUS_FILE_RE = re.compile(r"^LEARNINGS(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?\.md$")


def _init_pending_is_valid(record: object, project_key: str, revision: str) -> bool:
    return (
        isinstance(record, dict)
        and record == {
            "schema_version": CORPUS_INIT_PENDING_SCHEMA_VERSION,
            "project_key": project_key,
            "revision": revision,
        }
    )
_REF_COUNT_LINE_RE = re.compile(
    r"<!-- ref-count: (?P<count>\d+), last-ref: (?P<last>[^ ]+) -->"
)
_CORPUS_ACTIVE_KEYS = frozenset(
    {
        "schema_version", "project_key", "canonical_digest", "observed_roots",
        "canonical_aliases", "active_revision", "previous_revision",
        "activated_at", "reason",
    }
)
_CORPUS_PROJECTION_KEYS = frozenset(
    {"schema_version", "observed_root", "project_key", "revision", "repository_files", "corpus_files", "updated_at"}
)
_CORPUS_CACHE_KEYS = frozenset(
    {
        "schema_version", "epoch_nonce", "observed_root", "observed_root_dev",
        "observed_root_ino", "project_key", "active_revision",
    }
)
_CORPUS_DEPLOYMENT_PHASES = frozenset({"deploying", "complete"})
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


def is_valid_corpus_filename(name: object) -> bool:
    """Accept the flat corpus filename contract, including dotted topic slugs.

    A filename is never interpreted as a path.  In particular, a dotted slug
    such as ``LEARNINGS-api.v2.md`` is valid while hidden names, separators,
    and traversal-looking names are not.
    """
    if not isinstance(name, str) or name.startswith(".") or "/" in name or "\\" in name:
        return False
    if ".." in name:
        return False
    return bool(_CORPUS_FILE_RE.fullmatch(name))


def find_header_ref_count(content: str) -> re.Match[str] | None:
    """Find the marker only above the first lesson section, never in body text."""
    head_end = len(content)
    offset = 0
    for line in content.splitlines(keepends=True):
        if line.startswith("## "):
            head_end = offset
            break
        offset += len(line)
    return _REF_COUNT_LINE_RE.search(content[:head_end])


def corpora_root() -> Path | None:
    neutral = _neutral_root()
    return neutral / "corpora" if neutral is not None else None


def corpus_project_dir(project_key: str) -> Path:
    if not is_project_key(project_key):
        raise ValueError(f"invalid project key: {project_key!r}")
    root = corpora_root()
    if root is None:
        raise ValueError("neutral corpus root is unavailable")
    return root / project_key


def corpus_active_path(project_key: str) -> Path:
    return corpus_project_dir(project_key) / _CORPUS_ACTIVE_NAME


def corpus_deactivated_path(project_key: str) -> Path:
    return corpus_project_dir(project_key) / _CORPUS_DEACTIVATED_NAME


def corpus_rollback_transaction_path(project_key: str) -> Path:
    return corpus_project_dir(project_key) / _CORPUS_ROLLBACK_TRANSACTION_NAME


def corpus_revision_dir(project_key: str, revision: str) -> Path:
    if not isinstance(revision, str) or not _CORPUS_REVISION_RE.fullmatch(revision):
        raise ValueError(f"invalid corpus revision: {revision!r}")
    return corpus_project_dir(project_key) / "revisions" / revision


def _observed_root_id(root: Path) -> str:
    """Pure ID derivation for an already validated observed root."""
    return hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]


def observed_path_id(project_root: Path | str) -> str:
    return _observed_root_id(_validated_project_root(project_root))


def corpus_projection_path(project_key: str, project_root: Path | str) -> Path:
    return corpus_project_dir(project_key) / "projections" / f"{observed_path_id(project_root)}.json"


def corpus_legacy_migration_audit_path(project_key: str, project_root: Path | str) -> Path:
    """The immutable audit evidence for one roster-authorized first cutover."""
    return (
        corpus_project_dir(project_key) / "migrations"
        / f"{observed_path_id(project_root)}.json"
    )


def _migration_file_record_is_valid(value: object, *, portable: bool = False) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"name", "sha256", "size_bytes"}
        and isinstance(value.get("name"), str)
        and (
            bool(_PATH_DERIVED_PORTABLE_RE.fullmatch(value["name"]))
            if portable
            else is_valid_corpus_filename(value["name"])
        )
        and isinstance(value.get("sha256"), str)
        and bool(_SHA256_HEX_RE.fullmatch(value["sha256"]))
        and isinstance(value.get("size_bytes"), int)
        and not isinstance(value["size_bytes"], bool)
        and 0 <= value["size_bytes"] <= EXTERNAL_CORPUS_FILE_MAX_BYTES
    )


def _migration_file_records(value: object, *, portable: bool = False) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= EXTERNAL_CORPUS_MAX_CHILDREN
        and all(_migration_file_record_is_valid(item, portable=portable) for item in value)
        and len({item["name"] for item in value}) == len(value)
    )


def corpus_legacy_migration_audit_is_valid(record: object, *, project_key: str | None = None) -> bool:
    keys = {
        "schema_version", "project_key", "observed_root", "roster_sha256",
        "row_sha256", "source_files", "target_digest", "archives", "created_at",
    }
    return (
        isinstance(record, dict)
        and set(record) == keys
        and record.get("schema_version") == CORPUS_LEGACY_MIGRATION_AUDIT_SCHEMA_VERSION
        and is_project_key(record.get("project_key"))
        and (project_key is None or record["project_key"] == project_key)
        and _valid_audit_observed_root(record.get("observed_root"))
        and all(
            isinstance(record.get(name), str) and _SHA256_HEX_RE.fullmatch(record[name])
            for name in ("roster_sha256", "row_sha256", "target_digest")
        )
        and _migration_file_records(record.get("source_files"))
        and bool(record["source_files"])
        and _migration_file_records(record.get("archives"), portable=True)
        and isinstance(record.get("created_at"), (int, float))
        and not isinstance(record["created_at"], bool)
    )


def _valid_audit_observed_root(value: object) -> bool:
    """Audit roots are historical evidence and need not still exist."""
    return (
        isinstance(value, str)
        and Path(value).is_absolute()
        and ".." not in Path(value).parts
    )


def read_corpus_legacy_migration_audit(project_key: str, project_root: Path | str) -> dict | None:
    root = _validated_project_root(project_root)
    return _read_valid_corpus_record(
        corpus_legacy_migration_audit_path(project_key, root),
        lambda record: (
            corpus_legacy_migration_audit_is_valid(record, project_key=project_key)
            and record["observed_root"] == str(root)
        ),
        "legacy migration audit record",
    )


def _build_corpus_legacy_migration_audit(plan: CorpusTransitionPlan) -> dict:
    if not (plan.legacy_migration_roster_sha256 and plan.legacy_migration_row_sha256):
        raise ValueError("migration audit requires a roster-bound transition plan")
    record = {
        "schema_version": CORPUS_LEGACY_MIGRATION_AUDIT_SCHEMA_VERSION,
        "project_key": plan.project_key,
        "observed_root": plan.project_root,
        "roster_sha256": plan.legacy_migration_roster_sha256,
        "row_sha256": plan.legacy_migration_row_sha256,
        "source_files": [
            {"name": item.name, "sha256": item.sha256, "size_bytes": item.size_bytes}
            for item in plan.source_files
        ],
        "target_digest": plan.target_digest,
        "archives": [
            {"name": item.name, "sha256": item.sha256, "size_bytes": item.size_bytes}
            for item in plan.retained_archives
        ],
        "created_at": time.time(),
    }
    if not corpus_legacy_migration_audit_is_valid(record, project_key=plan.project_key):
        raise ValueError("invalid legacy migration audit record")
    return record


def _write_corpus_legacy_migration_audit(plan: CorpusTransitionPlan) -> None:
    path = corpus_legacy_migration_audit_path(plan.project_key, plan.project_root)
    record = _build_corpus_legacy_migration_audit(plan)
    existing = read_corpus_legacy_migration_audit(plan.project_key, plan.project_root)
    if existing is not None:
        immutable = (
            "project_key", "observed_root", "row_sha256",
            "source_files", "target_digest", "archives",
        )
        if any(existing[name] != record[name] for name in immutable):
            raise _ProjectCorpusTransitionBlocked("legacy migration audit conflicts with this import plan")
        return
    _ensure_transition_directory(path.parent, "migrations")
    _replace_transition_json(path, record, "migration-audit")


def _supersede_legacy_migration_audit(plan: CorpusTransitionPlan) -> tuple[str, ...]:
    """Quarantine the one preview-frozen pre-active audit before replacement."""
    expected = plan.legacy_migration_superseded_audit_sha256
    if expected is None:
        return ()
    path = corpus_legacy_migration_audit_path(plan.project_key, plan.project_root)
    raw = _raw_authority_digest(path)
    if raw is None or raw[0] != expected:
        raise _ProjectCorpusTransitionBlocked("superseded legacy migration audit changed while acquiring locks")
    quarantine = corpus_project_dir(plan.project_key) / "quarantine"
    _ensure_transition_directory(quarantine, "migration-audit-quarantine")
    destination = quarantine / f"migration-audit-{path.name}-superseded-{expected[:16]}"
    if destination.exists() or destination.is_symlink():
        raise _ProjectCorpusTransitionBlocked(
            "superseded legacy migration audit is already quarantined; rerun plan"
        )
    try:
        os.rename(path, destination)
        _fsync_dir(quarantine)
        _fsync_dir(path.parent)
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(
            f"cannot preserve superseded legacy migration audit: {exc}"
        ) from None
    return (f"retained superseded legacy migration audit at {destination}",)


def corpus_epoch_path() -> Path:
    root = corpora_root()
    if root is None:
        raise ValueError("neutral corpus root is unavailable")
    return root / _CORPUS_EPOCH_NAME


def corpus_lock_path(project_key: str) -> Path:
    """The identity-scoped external-corpus lock; the override is test-only."""
    if not is_project_key(project_key):
        raise ValueError(f"invalid project key: {project_key!r}")
    configured = os.environ.get("LEARNINGS_CORPUS_LOCK_DIR")
    if configured:
        lock_dir = _safe_absolute(configured)
        if lock_dir is None:
            raise ValueError("LEARNINGS_CORPUS_LOCK_DIR must be absolute")
    else:
        lock_dir = Path("/tmp")
    return lock_dir / f"learnings-corpus-{project_key}.lock"


def _valid_corpus_files(files: object, *, require_nonempty: bool = True) -> bool:
    return (
        isinstance(files, dict)
        and (bool(files) or not require_nonempty)
        and all(
            isinstance(name, str)
            and is_valid_corpus_filename(name)
            and isinstance(digest, str)
            and _SHA256_HEX_RE.fullmatch(digest)
            for name, digest in files.items()
        )
    )


def _valid_observed_roots(roots: object) -> bool:
    if not isinstance(roots, list) or not roots or len(roots) > 128:
        return False
    for root in roots:
        if not isinstance(root, str):
            return False
        path = Path(root)
        if not path.is_absolute() or ".." in path.parts or str(path.resolve()) != root:
            return False
    return True


def corpus_active_record_is_valid(record: object, *, project_key: str | None = None) -> bool:
    if not isinstance(record, dict) or set(record) != _CORPUS_ACTIVE_KEYS:
        return False
    key = record.get("project_key")
    if not is_project_key(key) or (project_key is not None and key != project_key):
        return False
    roots = record.get("observed_roots")
    aliases = record.get("canonical_aliases")
    if not (
        isinstance(record.get("schema_version"), int)
        and record["schema_version"] == CORPUS_ACTIVE_SCHEMA_VERSION
        and isinstance(record.get("canonical_digest"), str)
        and _SHA256_HEX_RE.fullmatch(record["canonical_digest"])
        and _valid_observed_roots(roots)
        and isinstance(aliases, list)
        and bool(aliases)
        and len(aliases) <= 128
        and all(isinstance(alias, str) and alias for alias in aliases)
        and isinstance(record.get("active_revision"), str)
        and _CORPUS_REVISION_RE.fullmatch(record["active_revision"])
        and (record.get("previous_revision") is None or (
            isinstance(record["previous_revision"], str)
            and _CORPUS_REVISION_RE.fullmatch(record["previous_revision"])
            and record["previous_revision"] != record["active_revision"]
        ))
        and isinstance(record.get("activated_at"), (int, float))
        and not isinstance(record["activated_at"], bool)
        and record.get("reason") in {"fresh", "import", "reimport", "rollback"}
    ):
        return False
    return True


def build_corpus_active_record(
    identity: ProjectIdentity,
    project_root: Path | str,
    revision: str,
    *,
    previous_revision: str | None = None,
    canonical_aliases: tuple[str, ...] | list[str] = (),
    observed_roots: tuple[str, ...] | list[str] = (),
    reason: str = "fresh",
) -> dict:
    root = _validated_project_root(project_root)
    record = {
        "schema_version": CORPUS_ACTIVE_SCHEMA_VERSION,
        "project_key": identity.key,
        "canonical_digest": hashlib.sha256(identity.canonical.encode("utf-8")).hexdigest(),
        "observed_roots": sorted({str(root), *observed_roots}),
        "canonical_aliases": sorted({identity.canonical, *canonical_aliases}),
        "active_revision": revision,
        "previous_revision": previous_revision,
        "activated_at": time.time(),
        "reason": reason,
    }
    if not corpus_active_record_is_valid(record):
        raise ValueError("invalid corpus active record")
    return record


def corpus_projection_record_is_valid(record: object, *, project_key: str | None = None) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == _CORPUS_PROJECTION_KEYS
        and record.get("schema_version") == CORPUS_PROJECTION_SCHEMA_VERSION
        and is_project_key(record.get("project_key"))
        and (project_key is None or record["project_key"] == project_key)
        and _valid_observed_roots([record.get("observed_root")])
        and isinstance(record.get("revision"), str)
        and _CORPUS_REVISION_RE.fullmatch(record["revision"])
        and _valid_corpus_files(record.get("repository_files"), require_nonempty=False)
        and _valid_corpus_files(record.get("corpus_files"), require_nonempty=False)
        and isinstance(record.get("updated_at"), (int, float))
        and not isinstance(record["updated_at"], bool)
    )


def build_corpus_projection_record(
    project_key: str,
    project_root: Path | str,
    revision: str,
    repository_files: dict[str, str],
    corpus_files: dict[str, str],
) -> dict:
    root = _validated_project_root(project_root)
    record = {
        "schema_version": CORPUS_PROJECTION_SCHEMA_VERSION,
        "observed_root": str(root),
        "project_key": project_key,
        "revision": revision,
        "repository_files": dict(sorted(repository_files.items())),
        "corpus_files": dict(sorted(corpus_files.items())),
        "updated_at": time.time(),
    }
    if not corpus_projection_record_is_valid(record, project_key=project_key):
        raise ValueError("invalid corpus projection record")
    return record


def corpus_epoch_record_is_valid(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"schema_version", "nonce"}
        and record.get("schema_version") == CORPUS_EPOCH_SCHEMA_VERSION
        and isinstance(record.get("nonce"), str)
        and bool(re.fullmatch(r"[0-9a-f]{16}", record["nonce"]))
    )


def build_corpus_epoch_record() -> dict:
    return {"schema_version": CORPUS_EPOCH_SCHEMA_VERSION, "nonce": uuid.uuid4().hex[:16]}


def corpus_deactivated_record_is_valid(record: object, *, project_key: str | None = None) -> bool:
    """7B1 preserves a deactivated authority pointer with the active schema."""
    return corpus_active_record_is_valid(record, project_key=project_key)


def corpus_deployment_state_path() -> Path:
    root = _neutral_root()
    if root is None:
        raise ValueError("neutral corpus root is unavailable")
    return root / CORPUS_DEPLOYMENT_STATE_NAME


def corpus_deployment_state_is_valid(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"schema_version", "phase", "nonce", "compatibility_revision"}
        and record.get("schema_version") == CORPUS_DEPLOYMENT_STATE_SCHEMA_VERSION
        and record.get("phase") in _CORPUS_DEPLOYMENT_PHASES
        and isinstance(record.get("nonce"), str)
        and bool(re.fullmatch(r"[0-9a-f]{16,64}", record["nonce"]))
        and isinstance(record.get("compatibility_revision"), int)
        and not isinstance(record["compatibility_revision"], bool)
        and record["compatibility_revision"] > 0
    )


def read_corpus_deployment_state() -> dict | None:
    path = corpus_deployment_state_path()
    try:
        record = _read_corpus_record(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError(f"cutover deployment state is unreadable: {exc}") from None
    if not corpus_deployment_state_is_valid(record):
        raise ValueError("cutover deployment state has an invalid schema")
    return record


def cutover_deployment_status() -> dict:
    """Return the deployment capability without changing state."""
    try:
        record = read_corpus_deployment_state()
    except ValueError as exc:
        return {"status": "malformed", "record": None, "reason": str(exc)}
    if record is None:
        return {"status": "absent", "record": None, "reason": "deployment state is absent"}
    if record["phase"] == "deploying":
        return {"status": "deploying", "record": record, "reason": "deployment is interrupted or in progress"}
    if record["compatibility_revision"] != CORPUS_CUTOVER_COMPAT_REVISION:
        return {"status": "stale", "record": record, "reason": "deployment compatibility revision is stale"}
    return {"status": "current", "record": record, "reason": "deployment is cutover-capable"}


def _read_valid_corpus_record(path: Path, validator, label: str) -> dict | None:
    try:
        record = _read_corpus_record(path)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} is not a plain regular single-link record: {exc}") from None
    if not validator(record):
        raise ValueError(f"{label} has an invalid schema")
    return record


def _write_valid_corpus_record(path: Path, record: dict, validator, label: str) -> None:
    if not validator(record):
        raise ValueError(f"refusing to write invalid {label}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _replace_json_fsynced(path, record)


def read_corpus_active_record(project_key: str) -> dict | None:
    return _read_valid_corpus_record(
        corpus_active_path(project_key),
        lambda record: corpus_active_record_is_valid(record, project_key=project_key),
        "active corpus record",
    )


def write_corpus_active_record(project_key: str, record: dict) -> None:
    _write_valid_corpus_record(
        corpus_active_path(project_key),
        record,
        lambda value: corpus_active_record_is_valid(value, project_key=project_key),
        "active corpus record",
    )


def read_corpus_deactivated_record(project_key: str) -> dict | None:
    return _read_valid_corpus_record(
        corpus_deactivated_path(project_key),
        lambda record: corpus_deactivated_record_is_valid(record, project_key=project_key),
        "deactivated corpus record",
    )


def write_corpus_deactivated_record(project_key: str, record: dict) -> None:
    _write_valid_corpus_record(
        corpus_deactivated_path(project_key),
        record,
        lambda value: corpus_deactivated_record_is_valid(value, project_key=project_key),
        "deactivated corpus record",
    )


def _rollback_transaction_is_valid(record: object, *, project_key: str | None = None) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {
            "schema_version", "project_key", "source_revision", "target_kind", "target_revision",
            "freeze_revision", "source_active_sha256", "phase",
        }
        and record.get("schema_version") == CORPUS_ROLLBACK_TRANSACTION_SCHEMA_VERSION
        and is_project_key(record.get("project_key"))
        and (project_key is None or record["project_key"] == project_key)
        and isinstance(record.get("source_revision"), str)
        and _CORPUS_REVISION_RE.fullmatch(record["source_revision"])
        and record.get("target_kind") in {"external", "legacy"}
        and (
            (record["target_kind"] == "external" and isinstance(record.get("target_revision"), str)
             and _CORPUS_REVISION_RE.fullmatch(record["target_revision"]))
            or (record["target_kind"] == "legacy" and record.get("target_revision") is None)
        )
        and (
            record.get("freeze_revision") is None
            or (isinstance(record["freeze_revision"], str) and _CORPUS_REVISION_RE.fullmatch(record["freeze_revision"]))
        )
        and isinstance(record.get("source_active_sha256"), str)
        and _SHA256_HEX_RE.fullmatch(record["source_active_sha256"])
        and record.get("phase") in {"prepared", "complete"}
    )


def _read_rollback_transaction(project_key: str) -> dict | None:
    return _read_valid_corpus_record(
        corpus_rollback_transaction_path(project_key),
        lambda record: _rollback_transaction_is_valid(record, project_key=project_key),
        "corpus rollback transaction",
    )


def _build_rollback_transaction(
    project_key: str, source_revision: str, target_kind: str, target_revision: str | None,
    freeze_revision: str | None, source_active_sha256: str,
) -> dict:
    record = {
        "schema_version": CORPUS_ROLLBACK_TRANSACTION_SCHEMA_VERSION,
        "project_key": project_key,
        "source_revision": source_revision,
        "target_kind": target_kind,
        "target_revision": target_revision,
        "freeze_revision": freeze_revision,
        "source_active_sha256": source_active_sha256,
        "phase": "prepared",
    }
    if not _rollback_transaction_is_valid(record, project_key=project_key):
        raise ValueError("invalid corpus rollback transaction")
    return record


def _complete_rollback_transaction(record: dict) -> dict:
    completed = {**record, "phase": "complete"}
    if not _rollback_transaction_is_valid(completed, project_key=record.get("project_key")):
        raise ValueError("invalid completed corpus rollback transaction")
    return completed


def read_corpus_projection_record(project_key: str, project_root: Path | str) -> dict | None:
    root = _validated_project_root(project_root)
    return _read_valid_corpus_record(
        corpus_projection_path(project_key, root),
        lambda record: (
            corpus_projection_record_is_valid(record, project_key=project_key)
            and record["observed_root"] == str(root)
        ),
        "corpus projection record",
    )


def write_corpus_projection_record(project_key: str, project_root: Path | str, record: dict) -> None:
    root = _validated_project_root(project_root)
    _write_valid_corpus_record(
        corpus_projection_path(project_key, root),
        record,
        lambda value: (
            corpus_projection_record_is_valid(value, project_key=project_key)
            and value["observed_root"] == str(root)
        ),
        "corpus projection record",
    )


def read_corpus_epoch_record() -> dict | None:
    return _read_valid_corpus_record(corpus_epoch_path(), corpus_epoch_record_is_valid, "corpus epoch record")


def write_corpus_epoch_record(record: dict) -> None:
    _write_valid_corpus_record(corpus_epoch_path(), record, corpus_epoch_record_is_valid, "corpus epoch record")


def _replace_corpus_epoch() -> None:
    root = corpora_root()
    if root is None:
        raise ValueError("neutral corpus root is unavailable")
    root.mkdir(parents=True, exist_ok=True)
    write_corpus_epoch_record(build_corpus_epoch_record())


def _validated_project_root(project_root: Path | str) -> Path:
    root = Path(project_root)
    try:
        valid = root.is_absolute() and root.is_dir()
        resolved = root.resolve() if valid else None
    except OSError:
        valid = False
        resolved = None
    if not valid or resolved is None:
        raise ProjectRootError("project_root must be an existing absolute directory")
    return resolved


def _read_corpus_record(path: Path) -> object:
    raw = _read_activation_capped(path)
    if raw is None:
        raise ValueError(f"{path.name} is not a plain regular single-link file within the cap")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{path.name} is not valid JSON: {exc}") from None


def _regular_single_link(path: Path, *, max_bytes: int | None = _CORPUS_RECORD_MAX_BYTES) -> bool:
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        return (
            stat.S_ISREG(st.st_mode)
            and st.st_nlink == 1
            and (max_bytes is None or st.st_size <= max_bytes)
        )
    finally:
        os.close(fd)


def _external_corpus_defect(path: Path, detail: str) -> CorpusResolutionError:
    return CorpusResolutionError(f"external corpus file {path.name!r} is {detail}")


def select_external_corpus_files(location: CorpusLocation) -> tuple[Path, ...]:
    """Select the corpus's direct Markdown children without reopening them.

    An external revision is a flat, owned directory: any visible non-corpus
    child is authority damage, not an empty entry a consumer may ignore.
    """
    if location.mode != "external":
        raise CorpusResolutionError("external corpus selector received a legacy location")
    try:
        entries = location.corpus_root.iterdir()
    except OSError as exc:
        raise CorpusResolutionError("external corpus revision is unreadable") from exc
    selected: list[Path] = []
    try:
        for entry in entries:
            if entry.name.startswith("."):
                continue
            if len(selected) >= EXTERNAL_CORPUS_MAX_CHILDREN:
                raise CorpusResolutionError("external corpus revision exceeds the 256-child cap")
            if not is_valid_corpus_filename(entry.name):
                raise CorpusResolutionError(
                    f"external corpus revision has foreign visible child {entry.name!r}"
                )
            selected.append(entry)
    except OSError as exc:
        raise CorpusResolutionError("external corpus revision is unreadable") from exc
    if not any(path.name == "LEARNINGS.md" for path in selected):
        raise CorpusResolutionError("external corpus revision is missing LEARNINGS.md")
    return tuple(sorted(selected, key=lambda path: path.name))


def select_external_projection_files(project_root: Path | str) -> tuple[Path, ...]:
    """Select only checkout files that can be projected from external state.

    This is deliberately distinct from the legacy baseline selector: portable
    projections and host instruction files are not repository synchronization
    targets.  Reads remain fd-bound in the shared snapshot reader below.
    """
    root = _validated_project_root(project_root)
    selected: list[Path] = []
    try:
        entries = root.iterdir()
        for entry in entries:
            if entry.name.startswith("."):
                continue
            if (
                not any(entry.match(spec) for spec in EXTERNAL_PROJECTION_ARTIFACT_SPECS)
                or entry.match("*-PORTABLE-LEARNINGS.md")
                or not is_valid_corpus_filename(entry.name)
            ):
                continue
            if len(selected) >= EXTERNAL_CORPUS_MAX_CHILDREN:
                raise CorpusResolutionError("repository corpus exceeds the 256-child cap")
            selected.append(entry)
    except OSError as exc:
        raise CorpusResolutionError("repository corpus is unreadable") from exc
    return tuple(sorted(selected, key=lambda path: (path.name != "LEARNINGS.md", path.name)))


def _read_external_corpus_snapshot(location: CorpusLocation, path: Path) -> CorpusSnapshot:
    """Read one selected corpus file; external reads are cap-bound on one fd."""
    if location.mode != "external":
        raise CorpusResolutionError("external corpus reader received a legacy location")
    if path.parent != location.corpus_root or not is_valid_corpus_filename(path.name):
        raise CorpusResolutionError("external corpus selector returned an invalid child")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError as exc:
        raise _external_corpus_defect(path, "missing") from exc
    except OSError as exc:
        raise _external_corpus_defect(path, "unreadable") from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise _external_corpus_defect(path, "unreadable") from exc
        if not stat.S_ISREG(st.st_mode):
            raise _external_corpus_defect(path, "not a regular file")
        if st.st_nlink != 1:
            raise _external_corpus_defect(path, "multiply linked")
        if st.st_size > EXTERNAL_CORPUS_FILE_MAX_BYTES:
            raise _external_corpus_defect(path, "over the 1 MiB cap")
        try:
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                raw = handle.read(EXTERNAL_CORPUS_FILE_MAX_BYTES + 1)
        except OSError as exc:
            raise _external_corpus_defect(path, "unreadable") from exc
        if len(raw) > EXTERNAL_CORPUS_FILE_MAX_BYTES:
            raise _external_corpus_defect(path, "over the 1 MiB cap")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _external_corpus_defect(path, "not valid UTF-8") from exc
        return CorpusSnapshot(path, path.name, text, len(raw), st.st_dev, st.st_ino)
    finally:
        if fd != -1:
            os.close(fd)


def read_external_corpus_snapshot(location: CorpusLocation, path: Path) -> CorpusSnapshot:
    """Public fd-bound external read used by read-only consumers."""
    return _read_external_corpus_snapshot(location, path)


def _read_legacy_corpus_snapshot(location: CorpusLocation, path: Path) -> CorpusSnapshot:
    """Legacy reads retain tolerant caller selection but are fd-bound once selected."""
    if path.parent != location.corpus_root or not is_valid_corpus_filename(path.name):
        raise CorpusMutationError("legacy corpus selector returned an invalid child")
    fd = -1
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise CorpusMutationError(f"legacy corpus file {path.name!r} is unsafe")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read()
        text = raw.decode("utf-8")
        return CorpusSnapshot(path, path.name, text, len(raw), st.st_dev, st.st_ino)
    except UnicodeDecodeError as exc:
        raise CorpusMutationError(f"legacy corpus file {path.name!r} is not valid UTF-8") from exc
    except OSError as exc:
        raise CorpusMutationError(f"legacy corpus file {path.name!r} is unreadable") from exc
    finally:
        if fd != -1:
            os.close(fd)


def _acquire_until(path: Path, *, exclusive: bool, deadline: float | None, mode: int) -> _ActivityLock:
    """Acquire a local flock with one caller-owned monotonic deadline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(str(path), flags, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise CorpusMutationError(f"lock path {path} is not a regular single-link file")
        operation = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(fd, operation)
                lock = _ActivityLock(fd)
                fd = -1
                return lock
            except BlockingIOError:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError from None
                time.sleep(0.01)
    finally:
        if fd != -1:
            os.close(fd)


def _snapshot_digest(snapshot: CorpusSnapshot) -> str:
    return hashlib.sha256(snapshot.text.encode("utf-8")).hexdigest()


def _snapshot_record(snapshot: CorpusSnapshot) -> dict[str, object]:
    return {
        "dev": snapshot.st_dev,
        "ino": snapshot.st_ino,
        "digest": _snapshot_digest(snapshot),
    }


def _snapshot_record_is_valid(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"dev", "ino", "digest"}
        and isinstance(record["dev"], int)
        and isinstance(record["ino"], int)
        and isinstance(record["digest"], str)
        and bool(_SHA256_HEX_RE.fullmatch(record["digest"]))
    )


_MUTATION_JOURNAL_KEYS = frozenset({"schema_version", "nonce", "operations", "removals"})
_MUTATION_OPERATION_KEYS = frozenset({"name", "phase", "original", "digest", "staged"})
_MUTATION_REMOVAL_KEYS = frozenset({"name", "original"})
_MUTATION_STAGE_RE = re.compile(r"\.corpus-mutation-([0-9a-f]{32})-(\d+)\.tmp")
_MUTATION_JOURNAL_RE = re.compile(r"\.corpus-mutation-([0-9a-f]{32})\.json")
_MUTATION_JOURNAL_TMP_RE = re.compile(r"\.corpus-mutation-([0-9a-f]{32})\.journal\.tmp")


def corpus_mutation_journal_is_valid(record: object) -> bool:
    """Pure exact-schema validator; recovery never guesses a journal shape."""
    if not isinstance(record, dict) or set(record) != _MUTATION_JOURNAL_KEYS:
        return False
    if record.get("schema_version") != 1 or not isinstance(record.get("nonce"), str):
        return False
    if not re.fullmatch(r"[0-9a-f]{32}", record["nonce"]):
        return False
    operations = record.get("operations")
    removals = record.get("removals")
    if not isinstance(operations, list) or not isinstance(removals, list):
        return False
    seen: set[str] = set()
    last_phase = 0
    authority_count = 0
    phase_order = {"creation": 0, "replacement": 1, "authority": 2}
    for ordinal, operation in enumerate(operations):
        if not isinstance(operation, dict) or set(operation) != _MUTATION_OPERATION_KEYS:
            return False
        name = operation.get("name")
        phase = operation.get("phase")
        if (
            not is_valid_corpus_filename(name)
            or name in seen
            or phase not in phase_order
            or phase_order[phase] < last_phase
        ):
            return False
        last_phase = phase_order[phase]
        if phase == "authority":
            authority_count += 1
            if authority_count != 1:
                return False
        seen.add(name)
        original = operation.get("original")
        if (phase == "creation") != (original is None):
            return False
        if original is not None and not _snapshot_record_is_valid(original):
            return False
        if not isinstance(operation.get("digest"), str) or not _SHA256_HEX_RE.fullmatch(operation["digest"]):
            return False
        staged = operation.get("staged")
        if staged != f".corpus-mutation-{record['nonce']}-{ordinal}.tmp":
            return False
    for removal in removals:
        if not isinstance(removal, dict) or set(removal) != _MUTATION_REMOVAL_KEYS:
            return False
        name = removal.get("name")
        if not is_valid_corpus_filename(name) or name == "LEARNINGS.md" or name in seen:
            return False
        seen.add(name)
        if not _snapshot_record_is_valid(removal.get("original")):
            return False
    membership_changes = bool(removals) or any(operation["phase"] == "creation" for operation in operations)
    authority_name = next(
        (operation["name"] for operation in operations if operation["phase"] == "authority"),
        None,
    )
    if membership_changes and authority_name is not None and authority_name != "LEARNINGS.md":
        return False
    if membership_changes and any(
        operation["phase"] == "replacement" and operation["name"] == "LEARNINGS.md"
        for operation in operations
    ):
        return False
    return True


class CorpusWriteSession:
    """The one mutation boundary for legacy and external corpus files."""

    def __init__(self, location: CorpusLocation, *, timeout_seconds: float | None):
        self.location = location
        self.timeout_seconds = timeout_seconds
        self._activity: _ActivityLock | None = None
        self._identity: _ActivityLock | None = None
        self._entered = False
        self._deadline: float | None = None
        self._legacy_target_deadline: float | None = None

    def __enter__(self) -> CorpusWriteSession:
        if self._entered:
            raise CorpusMutationError("corpus write session cannot be re-entered")
        deadline = None if self.timeout_seconds is None else time.monotonic() + max(0, self.timeout_seconds)
        self._deadline = deadline
        try:
            try:
                self._activity = _acquire_until(activity_lock_path(), exclusive=False, deadline=deadline, mode=0o600)
            except TimeoutError:
                raise CorpusLockTimeoutError("activity lock timeout") from None
            except Exception as exc:
                raise CorpusMutationError("cannot acquire activity lock") from exc
            try:
                mode = 0o600 if self.location.mode == "external" else 0o644
                self._identity = _acquire_until(self.location.lock_path, exclusive=True, deadline=deadline, mode=mode)
            except TimeoutError:
                raise CorpusLockTimeoutError("identity lock timeout") from None
            except Exception as exc:
                raise CorpusMutationError("cannot acquire identity lock") from exc
            self._entered = True
            if self.location.mode == "external":
                self._recover_external_transaction()
            return self
        except BaseException:
            with contextlib.suppress(Exception):
                self.close()
            raise

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Close in reverse order; deliberately safe after partial entry failures."""
        error: Exception | None = None
        identity, self._identity = self._identity, None
        activity, self._activity = self._activity, None
        if identity is not None:
            try:
                identity.close()
            except Exception as exc:
                error = exc
        if activity is not None:
            try:
                activity.close()
            except Exception as exc:
                if error is None:
                    error = exc
        self._entered = False
        self._deadline = None
        self._legacy_target_deadline = None
        if error is not None:
            raise error

    def _require_entered(self) -> None:
        if not self._entered or self._identity is None or self._activity is None:
            raise CorpusMutationError("corpus write session is not active")

    def select_files(self) -> tuple[Path, ...]:
        self._require_entered()
        if self.location.mode == "external":
            return select_external_corpus_files(self.location)
        try:
            entries = self.location.corpus_root.iterdir()
        except OSError as exc:
            raise CorpusMutationError("legacy corpus is unreadable") from exc
        selected = [
            path for path in entries
            if is_valid_corpus_filename(path.name) and _regular_single_link(path, max_bytes=None)
        ]
        return tuple(sorted(selected, key=lambda path: path.name))

    def read(self, path: Path) -> CorpusSnapshot:
        self._require_entered()
        if self.location.mode == "external":
            return _read_external_corpus_snapshot(self.location, path)
        return _read_legacy_corpus_snapshot(self.location, path)

    def _check_snapshot(self, snapshot: CorpusSnapshot) -> None:
        current = self.read(snapshot.path)
        if (
            current.st_dev != snapshot.st_dev
            or current.st_ino != snapshot.st_ino
            or current.text != snapshot.text
        ):
            raise CorpusMutationError(f"stale corpus snapshot for {snapshot.name}")

    def _validate_batch(
        self, batch: CorpusMutationBatch
    ) -> tuple[
        list[tuple[CorpusSnapshot, str]],
        list[tuple[str, str]],
        tuple[CorpusSnapshot, str] | None,
        list[CorpusSnapshot],
    ]:
        if not isinstance(batch, CorpusMutationBatch):
            raise CorpusMutationError("commit requires CorpusMutationBatch")
        try:
            raw_replacements = list(batch.replacements)
            creations = list(batch.creations)
            removals = list(batch.removals)
        except TypeError as exc:
            raise CorpusMutationError("invalid batch collection") from exc
        replacements: list[tuple[CorpusSnapshot, str]] = []
        for item in raw_replacements:
            if not isinstance(item, tuple) or len(item) != 2:
                raise CorpusMutationError("invalid replacement")
            snapshot, text = item
            if not isinstance(snapshot, CorpusSnapshot) or not isinstance(text, str):
                raise CorpusMutationError("invalid replacement")
            if snapshot.text != text:
                replacements.append((snapshot, text))
        authority = batch.authority_replacement
        if authority is not None:
            if not isinstance(authority, tuple) or len(authority) != 2:
                raise CorpusMutationError("invalid authority replacement")
            if not isinstance(authority[0], CorpusSnapshot) or not isinstance(authority[1], str):
                raise CorpusMutationError("invalid authority replacement")
            if authority[0].text == authority[1]:
                authority = None
        names: set[str] = set()
        for snapshot, text in replacements + ([] if authority is None else [authority]):
            if (
                not isinstance(snapshot, CorpusSnapshot)
                or not isinstance(text, str)
                or snapshot.path != self.location.corpus_root / snapshot.name
                or not is_valid_corpus_filename(snapshot.name)
            ):
                raise CorpusMutationError("invalid replacement")
            if snapshot.name in names:
                raise CorpusMutationError("overlapping batch targets")
            names.add(snapshot.name)
        for item in creations:
            if not isinstance(item, tuple) or len(item) != 2:
                raise CorpusMutationError("invalid creation")
            name, text = item
            if not is_valid_corpus_filename(name) or not isinstance(text, str) or name in names:
                raise CorpusMutationError("invalid or overlapping creation target")
            target = self.location.corpus_root / name
            try:
                os.lstat(target)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise CorpusMutationError(f"cannot inspect creation target: {name}") from exc
            else:
                raise CorpusMutationError(f"creation target already exists: {name}")
            names.add(name)
        for snapshot in removals:
            if (
                not isinstance(snapshot, CorpusSnapshot)
                or not is_valid_corpus_filename(snapshot.name)
                or snapshot.name == "LEARNINGS.md"
            ):
                raise CorpusMutationError("LEARNINGS.md cannot be removed")
            if snapshot.path != self.location.corpus_root / snapshot.name or snapshot.name in names:
                raise CorpusMutationError("overlapping batch targets")
            names.add(snapshot.name)
        membership_changes = bool(creations or removals)
        primary_replacement = any(snapshot.name == "LEARNINGS.md" for snapshot, _ in replacements)
        nonprimary_authority = authority is not None and authority[0].name != "LEARNINGS.md"
        if membership_changes and (primary_replacement or nonprimary_authority):
            raise CorpusMutationError("membership-changing LEARNINGS.md mutation must be authority")
        return replacements, creations, authority, removals

    def _visible_peak_check(self, creations: list[tuple[str, str]]) -> None:
        if self.location.mode != "external":
            return
        live = self.select_files()
        # The external adapter owns the complete live-revision byte contract,
        # including recovery (which runs before a caller can preflight). Do
        # not rely on every writer remembering to read unrelated siblings.
        try:
            for path in live:
                self.read(path)
        except CorpusResolutionError as exc:
            raise CorpusMutationError(str(exc)) from exc
        if len(live) + len(creations) > EXTERNAL_CORPUS_MAX_CHILDREN:
            raise CorpusMutationError("external corpus visible child cap would be exceeded")

    def _write_stage(self, path: Path, payload: bytes, mode: int) -> None:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fchmod(fd, mode)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _legacy_target_lock(self, path: Path):
        """Keep the historic target-inode flock inside the structural session."""
        fd = -1
        try:
            fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise CorpusMutationError("legacy target lock requires a regular single-link file")
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if (
                        self._legacy_target_deadline is not None
                        and time.monotonic() >= self._legacy_target_deadline
                    ):
                        raise CorpusLockTimeoutError("legacy target lock timeout") from None
                    time.sleep(0.01)
            yield
        except CorpusMutationError:
            raise
        except OSError as exc:
            raise CorpusMutationError("cannot acquire legacy target lock") from exc
        finally:
            if fd != -1:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def _stage_external(self, operations: list[tuple[str, str, CorpusSnapshot | None, str]]) -> tuple[dict, list[Path]]:
        nonce = uuid.uuid4().hex
        journal_operations: list[dict] = []
        staged: list[Path] = []
        try:
            for ordinal, (phase, name, original, text) in enumerate(operations):
                payload = text.encode("utf-8")
                if len(payload) > EXTERNAL_CORPUS_FILE_MAX_BYTES:
                    raise CorpusMutationError(f"replacement {name!r} exceeds the 1 MiB cap")
                stage = self.location.corpus_root / f".corpus-mutation-{nonce}-{ordinal}.tmp"
                mode = 0o644 if original is None else os.stat(original.path, follow_symlinks=False).st_mode & 0o7777
                self._write_stage(stage, payload, mode)
                staged.append(stage)
                journal_operations.append({
                    "name": name, "phase": phase, "original": None if original is None else _snapshot_record(original),
                    "digest": hashlib.sha256(payload).hexdigest(), "staged": stage.name,
                })
            journal = {"schema_version": 1, "nonce": nonce, "operations": journal_operations, "removals": []}
            return journal, staged
        except BaseException:
            for stage in staged:
                with contextlib.suppress(OSError):
                    stage.unlink()
            raise

    def _publish_journal(self, journal: dict) -> Path:
        if not corpus_mutation_journal_is_valid(journal):
            raise CorpusMutationError("invalid mutation journal")
        raw = json.dumps(journal, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > CORPUS_MUTATION_JOURNAL_MAX_BYTES:
            raise CorpusMutationError("mutation journal exceeds cap")
        final = self.location.corpus_root / f".corpus-mutation-{journal['nonce']}.json"
        temporary = self.location.corpus_root / f".corpus-mutation-{journal['nonce']}.journal.tmp"
        self._write_stage(temporary, raw, 0o600)
        os.replace(temporary, final)
        _fsync_dir(self.location.corpus_root)
        return final

    def _read_journal(self, path: Path) -> dict:
        raw = _read_file_capped(path, CORPUS_MUTATION_JOURNAL_MAX_BYTES)
        if raw is None:
            raise CorpusMutationError("published mutation journal is unsafe or too large")
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise CorpusMutationError("published mutation journal is malformed") from exc
        if not corpus_mutation_journal_is_valid(record):
            raise CorpusMutationError("published mutation journal has an invalid schema")
        return record

    def _recovery_current(self, name: str) -> CorpusSnapshot | None:
        path = self.location.corpus_root / name
        try:
            os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CorpusMutationError("cannot inspect visible recovery target") from exc
        try:
            return self.read(path)
        except CorpusResolutionError as exc:
            raise CorpusMutationError("visible recovery target is unsafe") from exc

    @staticmethod
    def _matches_record(snapshot: CorpusSnapshot | None, record: dict | None) -> bool:
        return snapshot is not None and record is not None and _snapshot_record(snapshot) == record

    def _verify_staged_payload(self, operation: dict) -> Path:
        path = self.location.corpus_root / operation["staged"]
        fd = -1
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > EXTERNAL_CORPUS_FILE_MAX_BYTES:
                raise CorpusMutationError("staged mutation payload is unsafe")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                raw = handle.read(EXTERNAL_CORPUS_FILE_MAX_BYTES + 1)
            if len(raw) > EXTERNAL_CORPUS_FILE_MAX_BYTES or hashlib.sha256(raw).hexdigest() != operation["digest"]:
                raise CorpusMutationError("staged mutation payload digest mismatch")
            return path
        except OSError as exc:
            raise CorpusMutationError("staged mutation payload is unavailable") from exc
        finally:
            if fd != -1:
                os.close(fd)

    def _recover_external_transaction(self) -> None:
        root = self.location.corpus_root
        journals = sorted(root.glob(".corpus-mutation-*.json"))
        if any(_MUTATION_JOURNAL_RE.fullmatch(path.name) is None for path in journals):
            raise CorpusMutationError("malformed published mutation journal name")
        if len(journals) > 1:
            raise CorpusMutationError("multiple published mutation journals block recovery")
        if not journals:
            # Only after confirming no published record anchors them may owned temps go.
            for path in root.iterdir():
                if not (_MUTATION_STAGE_RE.fullmatch(path.name) or _MUTATION_JOURNAL_TMP_RE.fullmatch(path.name)):
                    continue
                with contextlib.suppress(OSError):
                    path.unlink()
            return
        journal_path = journals[0]
        journal = self._read_journal(journal_path)
        operations = journal["operations"]
        removals = journal["removals"]
        unapplied: list[dict] = []
        for operation in operations:
            current = self._recovery_current(operation["name"])
            if current is not None and _snapshot_digest(current) == operation["digest"]:
                continue
            if operation["original"] is None and current is None:
                unapplied.append(operation)
                continue
            if self._matches_record(current, operation["original"]):
                unapplied.append(operation)
                continue
            raise CorpusMutationError("divergent visible replacement blocks recovery")
        pending_removals: list[dict] = []
        for removal in removals:
            current = self._recovery_current(removal["name"])
            if current is None:
                continue
            if self._matches_record(current, removal["original"]):
                pending_removals.append(removal)
                continue
            raise CorpusMutationError("divergent visible removal blocks recovery")
        self._visible_peak_check([("", "")] * sum(1 for operation in unapplied if operation["original"] is None))
        staged = {operation["name"]: self._verify_staged_payload(operation) for operation in unapplied}
        for operation in unapplied:
            os.replace(staged[operation["name"]], root / operation["name"])
            _fsync_dir(root)
        for removal in pending_removals:
            (root / removal["name"]).unlink()
            _fsync_dir(root)
        for operation in operations:
            with contextlib.suppress(OSError):
                (root / operation["staged"]).unlink()
        journal_path.unlink()
        _fsync_dir(root)

    def commit(self, batch: CorpusMutationBatch) -> CorpusMutationResult:
        self._require_entered()
        replacements, creations, authority, removals = self._validate_batch(batch)
        self._visible_peak_check(creations)
        operations: list[tuple[str, str, CorpusSnapshot | None, str]] = [
            ("creation", name, None, text) for name, text in creations
        ] + [("replacement", snapshot.name, snapshot, text) for snapshot, text in replacements]
        if authority is not None:
            operations.append(("authority", authority[0].name, authority[0], authority[1]))
        if not operations and not removals:
            return CorpusMutationResult(MappingProxyType({}))
        if self.location.mode == "external":
            for snapshot, _ in replacements:
                self._check_snapshot(snapshot)
            if authority is not None:
                self._check_snapshot(authority[0])
            for snapshot in removals:
                self._check_snapshot(snapshot)
            journal, _staged = self._stage_external(operations)
            journal["removals"] = [
                {"name": snapshot.name, "original": _snapshot_record(snapshot)}
                for snapshot in removals
            ]
            nonce = journal["nonce"]
            published = self.location.corpus_root / f".corpus-mutation-{nonce}.json"
            journal_temp = self.location.corpus_root / f".corpus-mutation-{nonce}.journal.tmp"
            try:
                journal_path = self._publish_journal(journal)
            except BaseException:
                if not published.exists():
                    for staged in _staged:
                        with contextlib.suppress(OSError):
                            staged.unlink()
                    with contextlib.suppress(OSError):
                        journal_temp.unlink()
                raise
            try:
                self._recover_external_transaction()
            except BaseException:
                # Published journal intentionally remains for the next checked session.
                raise
            assert not journal_path.exists()
        else:
            staged: list[tuple[Path, Path]] = []
            try:
                target_deadline = time.monotonic() + LEGACY_TARGET_LOCK_TIMEOUT_SECONDS
                self._legacy_target_deadline = (
                    target_deadline
                    if self._deadline is None
                    else min(self._deadline, target_deadline)
                )
                with contextlib.ExitStack() as target_locks:
                    for _phase, _name, original, _text in operations:
                        if original is not None:
                            target_locks.enter_context(self._legacy_target_lock(original.path))
                    for snapshot in removals:
                        target_locks.enter_context(self._legacy_target_lock(snapshot.path))
                    for snapshot, _ in replacements:
                        self._check_snapshot(snapshot)
                    if authority is not None:
                        self._check_snapshot(authority[0])
                    for snapshot in removals:
                        self._check_snapshot(snapshot)
                    for ordinal, (_phase, name, original, text) in enumerate(operations):
                        target = self.location.corpus_root / name
                        temporary = target.parent / f".{target.name}.mutation-{os.getpid()}-{ordinal}.tmp"
                        mode = 0o644 if original is None else os.stat(target, follow_symlinks=False).st_mode & 0o7777
                        self._write_stage(temporary, text.encode("utf-8"), mode)
                        staged.append((temporary, target))
                    for temporary, target in staged:
                        os.replace(temporary, target)
                        _fsync_dir(target.parent)
                    for snapshot in removals:
                        snapshot.path.unlink()
                        _fsync_dir(snapshot.path.parent)
            finally:
                self._legacy_target_deadline = None
                for temporary, _target in staged:
                    with contextlib.suppress(OSError):
                        temporary.unlink()
        committed: dict[Path, CorpusSnapshot] = {}
        for _phase, name, _original, _text in operations:
            path = self.location.corpus_root / name
            committed[path] = self.read(path)
        return CorpusMutationResult(MappingProxyType(committed))


def session_class() -> str:
    """LEARNINGS_SESSION_CLASS: interactive (default) | automation | harness.
    Unset or empty is interactive; an unknown value falls open to interactive
    with one stderr warning — this gate must never block a session. The
    standalone hook scripts carry their own copy (no imports between hook
    scripts); `bin/` tools that already load this module use this one."""
    value = os.environ.get("LEARNINGS_SESSION_CLASS")
    if not value or value in ("interactive", "automation", "harness"):
        return value or "interactive"
    # Warn once per process per value: bin/learn classifies at startup and
    # the seam classifies again, and a typo must not read as two faults.
    if value not in _SESSION_CLASS_WARNED:
        _SESSION_CLASS_WARNED.add(value)
        print(
            f"learnings: unknown LEARNINGS_SESSION_CLASS={value}, treating as interactive",
            file=sys.stderr,
        )
    return "interactive"


_SESSION_CLASS_WARNED: set[str] = set()


class SessionClassRefused(RuntimeError):
    """A corpus write was requested under LEARNINGS_SESSION_CLASS=harness."""


def corpus_write_session(location: CorpusLocation, *, timeout_seconds: float | None) -> CorpusWriteSession:
    # The one storage seam every corpus writer goes through — structural
    # workers, `learn` subcommands, and `learn search`'s ref-count bump all
    # commit here — so a harness session is refused at the seam regardless
    # of which entry point (or none) gated it above. Raised before any lock
    # is taken.
    if session_class() == "harness":
        raise SessionClassRefused("corpus write refused: LEARNINGS_SESSION_CLASS=harness")
    return CorpusWriteSession(location, timeout_seconds=timeout_seconds)


def _semantic_snapshot_digest(files: tuple[CorpusSnapshot, ...]) -> str:
    contents = {
        snapshot.name: hashlib.sha256(snapshot.text.encode("utf-8")).hexdigest()
        for snapshot in files
    }
    encoded = json.dumps(contents, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_semantic_corpus_snapshot(
    location: CorpusLocation, *, timeout_seconds: float | None = 10.0
) -> SemanticCorpusSnapshot:
    """Read one complete corpus view and release its recovery/session locks."""
    with corpus_write_session(location, timeout_seconds=timeout_seconds) as session:
        files = tuple(session.read(path) for path in session.select_files())
    return SemanticCorpusSnapshot(files=files, digest=_semantic_snapshot_digest(files))


def _subtopics_block_has_nested_child(content: str, names: set[str]) -> bool:
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if not _SUBTOPICS_LABEL.match(line):
            continue
        for child in lines[index + 1 :]:
            if not _BULLET_LINE.match(child):
                break
            match = _NESTED_CHILD_REF.search(child)
            if match and match.group(1) in names:
                return True
    return False


def _selected_corpus_is_index(main_text: str, names: set[str]) -> bool:
    if _THIN_INDEX_FINGERPRINT in main_text or _RICH_INDEX_ENTRY.search(main_text):
        return True
    if any(match.group(1) in names for match in _SUBFILE_LINK.finditer(main_text)):
        return True
    return _subtopics_block_has_nested_child(main_text, names)


def read_corpus_orientation_facts(
    location: CorpusLocation, *, timeout_seconds: float | None = 10.0
) -> CorpusOrientationFacts:
    """Return bounded main-file orientation facts without reading topic bodies."""
    with corpus_write_session(location, timeout_seconds=timeout_seconds) as session:
        paths = session.select_files()
        names = {path.name for path in paths}
        main = next(path for path in paths if path.name == "LEARNINGS.md")
        snapshot = session.read(main)
    topics = sum(name.startswith("LEARNINGS-") for name in names)
    if not snapshot.text:
        mode = "empty"
    elif _selected_corpus_is_index(snapshot.text, names):
        mode = "index"
    else:
        mode = "monolith"
    return CorpusOrientationFacts(len(snapshot.text.splitlines()), mode, topics)


def _valid_active_revision(project_key: str, record: dict) -> Path | None:
    try:
        root = corpus_revision_dir(project_key, record["active_revision"])
    except ValueError:
        return None
    if not root.is_dir() or root.is_symlink():
        return None
    names: set[str] = set()
    try:
        for path in root.iterdir():
            if path.name.startswith("."):
                continue
            if len(names) >= EXTERNAL_CORPUS_MAX_CHILDREN:
                return None
            names.add(path.name)
    except OSError:
        return None
    if "LEARNINGS.md" not in names or not all(is_valid_corpus_filename(name) for name in names):
        return None
    if not all(_regular_single_link(root / name, max_bytes=None) for name in names):
        return None
    return root


def _iter_active_corpus_records():
    root = corpora_root()
    if root is None:
        return
    try:
        entries = sorted(root.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return
    for entry in entries:
        if entry.name.startswith("."):
            continue
        active = entry / _CORPUS_ACTIVE_NAME
        if entry.is_symlink() or not entry.is_dir():
            yield entry.name, None, active
            continue
        try:
            active.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            yield entry.name, None, active
            continue
        try:
            record = read_corpus_active_record(entry.name)
        except ValueError:
            yield entry.name, None, active
            continue
        if record is None:
            continue
        yield entry.name, record, active


def _sync_deltas(
    live: dict[str, str], baseline: dict[str, str]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    live_names = set(live)
    baseline_names = set(baseline)
    return (
        tuple(sorted(live_names - baseline_names)),
        tuple(sorted(baseline_names - live_names)),
        tuple(sorted(name for name in live_names & baseline_names if live[name] != baseline[name])),
    )


def _sync_snapshot(
    *,
    root: Path,
    location: CorpusLocation | None,
    active: dict | None,
    projection: dict | None,
    projection_sha256: str | None,
    repository_files: dict[str, str],
    corpus_files: dict[str, str],
    state: str,
    blockers: tuple[str, ...] = (),
    notes: tuple[str, ...] = (),
) -> CorpusSynchronizationSnapshot:
    deployment = cutover_deployment_status()
    deployment_record = deployment.get("record")
    deployment_revision = (
        deployment_record.get("compatibility_revision")
        if isinstance(deployment_record, dict)
        and isinstance(deployment_record.get("compatibility_revision"), int)
        else None
    )
    projection_repository = projection["repository_files"] if projection is not None else {}
    projection_corpus = projection["corpus_files"] if projection is not None else {}
    repository_deltas = _sync_deltas(repository_files, projection_repository)
    external_deltas = _sync_deltas(corpus_files, projection_corpus)
    return CorpusSynchronizationSnapshot(
        project_root=str(root),
        projection_id=observed_path_id(root),
        project_key=location.project_key if location is not None else None,
        active_revision=active.get("active_revision") if active is not None else None,
        previous_revision=active.get("previous_revision") if active is not None else None,
        repository_files=tuple(sorted(repository_files.items())),
        corpus_files=tuple(sorted(corpus_files.items())),
        projection_repository_files=tuple(sorted(projection_repository.items())),
        projection_corpus_files=tuple(sorted(projection_corpus.items())),
        projection_revision=projection.get("revision") if projection is not None else None,
        projection_sha256=projection_sha256,
        repository_added=repository_deltas[0],
        repository_removed=repository_deltas[1],
        repository_changed=repository_deltas[2],
        external_added=external_deltas[0],
        external_removed=external_deltas[1],
        external_changed=external_deltas[2],
        deployment_status=deployment["status"],
        deployment_revision=deployment_revision,
        identity_lock_path=str(location.lock_path) if location is not None else None,
        state=state,
        blockers=blockers,
        notes=notes,
    )


def inspect_corpus_synchronization(
    project_root: Path | str, *, identity_lock_held: bool = False
) -> CorpusSynchronizationSnapshot:
    """Take one bounded identity-locked, read-only synchronization snapshot."""
    root = _validated_project_root(project_root)
    try:
        location = resolve_project_corpus_strict(root)
    except (CorpusResolutionError, IdentityResolutionError, ValueError) as exc:
        return _sync_snapshot(
            root=root, location=None, active=None, projection=None, projection_sha256=None,
            repository_files={}, corpus_files={}, state="malformed", blockers=(str(exc),),
        )
    if location is None or location.mode != "external":
        raise CorpusResolutionError("external corpus authority is absent; inspect `learn corpus status --cwd ...`")
    lock = None
    try:
        if not identity_lock_held:
            lock = _acquire_until(
                location.lock_path,
                exclusive=True,
                deadline=time.monotonic() + LEGACY_TARGET_LOCK_TIMEOUT_SECONDS,
                mode=0o600,
            )
    except TimeoutError:
        return _sync_snapshot(
            root=root, location=location, active=None, projection=None, projection_sha256=None,
            repository_files={}, corpus_files={}, state="busy",
            blockers=("external corpus identity lock is busy; retry `learn corpus drift --cwd ...`",),
        )
    try:
        try:
            active = read_corpus_active_record(location.project_key)
            if active is None or _valid_active_revision(location.project_key, active) is None:
                raise ValueError("active corpus authority is missing or malformed")
            active_location = _external_location_for_record(root, location.project_key, active)
            if active_location is None:
                raise ValueError("active external corpus revision is missing or malformed")
            repository_location = CorpusLocation(
                root, location.project_key, root, location.lock_path, "external"
            )
            repository_files = {
                snapshot.name: _snapshot_digest(snapshot)
                for snapshot in (
                    _read_external_corpus_snapshot(repository_location, path)
                    for path in select_external_projection_files(root)
                )
            }
            corpus_files = {
                snapshot.name: _snapshot_digest(snapshot)
                for snapshot in (
                    _read_external_corpus_snapshot(active_location, path)
                    for path in select_external_corpus_files(active_location)
                )
            }
            projection_path = corpus_projection_path(location.project_key, root)
            raw_projection = _raw_authority_digest(projection_path)
            projection_sha256 = raw_projection[0] if raw_projection is not None else None
            projection = read_corpus_projection_record(location.project_key, root)
            transaction = _read_valid_corpus_record(
                corpus_sync_transaction_path(location.project_key, root),
                lambda record: _sync_transaction_is_valid(
                    record, key=location.project_key
                ),
                "corpus synchronization transaction",
            )
        except (CorpusResolutionError, OSError, ValueError) as exc:
            return _sync_snapshot(
                root=root, location=location, active=None, projection=None, projection_sha256=None,
                repository_files={}, corpus_files={}, state="malformed", blockers=(str(exc),),
            )
        sync_blockers: tuple[str, ...] = ()
        if transaction is not None:
            state = "sync-recovery-pending"
            if transaction["revision"] != active["active_revision"]:
                sync_blockers = (
                    "pending synchronization transaction names a different active revision",
                )
        elif projection is None:
            state = "unprojected"
        elif projection["revision"] not in {active["active_revision"], active["previous_revision"]}:
            state = "pending-stale"
        else:
            repository_changed = repository_files != projection["repository_files"]
            external_changed = corpus_files != projection["corpus_files"]
            state = (
                "both" if repository_changed and external_changed else
                "repository-only" if repository_changed else
                "external-only" if external_changed else "clean"
            )
        return _sync_snapshot(
            root=root, location=location, active=active, projection=projection,
            projection_sha256=projection_sha256, repository_files=dict(sorted(repository_files.items())),
            corpus_files=dict(sorted(corpus_files.items())), state=state,
            blockers=sync_blockers,
        )
    finally:
        if lock is not None:
            lock.close()


_CORPUS_SYNC_TRANSACTION_KEYS = frozenset(
    {
        "schema_version", "nonce", "operation", "project_key", "revision", "projection_sha256",
        "before_repository_files", "target_repository_files", "corpus_files",
    }
)


def corpus_sync_transaction_path(project_key: str, project_root: Path | str) -> Path:
    return corpus_project_dir(project_key) / "sync-transactions" / f"{observed_path_id(project_root)}.json"


def _sync_transaction_path_for_observed_root(project_key: str, observed_root: str) -> Path:
    """Find durable evidence for an observed root even after it disappeared."""
    normalized = str(Path(observed_root).resolve(strict=False))
    path_id = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return corpus_project_dir(project_key) / "sync-transactions" / f"{path_id}.json"


def _read_sync_transaction_for_observed_root(project_key: str, observed_root: str) -> dict | None:
    return _read_valid_corpus_record(
        _sync_transaction_path_for_observed_root(project_key, observed_root),
        lambda record: _sync_transaction_is_valid(record, key=project_key),
        "corpus synchronization transaction",
    )


def _pending_sync_transactions(project_key: str) -> tuple[dict, ...]:
    directory = corpus_project_dir(project_key) / "sync-transactions"
    if not directory.exists():
        return ()
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("synchronization transaction directory is malformed")
    records = []
    for path in sorted(directory.glob("*.json"), key=lambda item: item.name):
        record = _read_valid_corpus_record(
            path, lambda value: _sync_transaction_is_valid(value, key=project_key),
            "corpus synchronization transaction",
        )
        if record is not None:
            records.append(record)
    return tuple(records)


def _sync_repository_loss_preview(
    repository_files: dict[str, str],
    projection_files: dict[str, str],
    target_files: dict[str, str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Classify every checkout-side loss before a synchronization write.

    Projection ownership is deliberately distinct from a currently matching
    digest: a user-edited projected file is still ours, but needs the explicit
    replacement flag before it can be overwritten or removed.
    """
    modified_owned: list[str] = []
    obsolete_owned: list[str] = []
    foreign_unowned: list[str] = []
    for name, live_digest in sorted(repository_files.items()):
        target_digest = target_files.get(name)
        projected_digest = projection_files.get(name)
        if projected_digest is None:
            foreign_unowned.append(name)
        elif target_digest == live_digest:
            continue
        elif live_digest != projected_digest:
            modified_owned.append(name)
        elif target_digest is None:
            obsolete_owned.append(name)
    return tuple(modified_owned), tuple(obsolete_owned), tuple(foreign_unowned)


def _stale_projection_maps_are_complete(snapshot: CorpusSynchronizationSnapshot) -> bool:
    """Stale evidence is usable only to name an explicit-loss recovery plan."""
    if (
        snapshot.state != "pending-stale"
        or snapshot.project_key is None
        or snapshot.projection_revision is None
    ):
        return False
    try:
        revision = corpus_revision_dir(snapshot.project_key, snapshot.projection_revision)
    except ValueError:
        return False
    mapped = _transition_maps_from_directory(revision)
    return mapped is not None and mapped[0] == dict(snapshot.projection_corpus_files)


def _plan_corpus_synchronization(
    project_root: Path | str,
    *,
    operation: str,
    replace_repository: bool = False,
    identity_lock_held: bool = False,
    transaction_owned_files: dict[str, str] | None = None,
) -> CorpusPublishPlan:
    if operation not in {"publish", "unpublish"}:
        raise ValueError(f"unsupported corpus synchronization operation: {operation}")
    requested = Path(project_root)
    root = _validated_project_root(requested)
    if requested.is_symlink() or requested != root:
        raise ProjectRootError(
            f"{operation} requires the normalized physical project root, not an alias"
        )
    snapshot = inspect_corpus_synchronization(root, identity_lock_held=identity_lock_held)
    repository_files = dict(snapshot.repository_files)
    corpus_files = dict(snapshot.corpus_files)
    recovery_target_files: dict[str, str] | None = None
    pending_operation: str | None = None
    pending_record: dict | None = None
    if snapshot.state == "sync-recovery-pending" and snapshot.project_key is not None:
        pending_record = _read_sync_transaction(snapshot.project_key, root)
        if pending_record is not None:
            pending_operation = pending_record["operation"]
            if pending_operation == operation and operation == "publish":
                # Preview the durable staged target, not newer mutable external bytes
                # that recovery is intentionally not authorized to publish.
                recovery_target_files = dict(pending_record["corpus_files"])
    stale_recovery = _stale_projection_maps_are_complete(snapshot)
    effective_state = snapshot.state
    if stale_recovery and replace_repository:
        repository_changed = repository_files != dict(snapshot.projection_repository_files)
        external_changed = corpus_files != dict(snapshot.projection_corpus_files)
        effective_state = (
            "both" if repository_changed and external_changed else
            "repository-only" if repository_changed else
            "external-only" if external_changed else "clean"
        )
    projection_files = dict(snapshot.projection_repository_files)
    if transaction_owned_files:
        projection_files.update(transaction_owned_files)
    target_files = (
        recovery_target_files if recovery_target_files is not None else corpus_files
    ) if operation == "publish" else {}
    modified_owned, obsolete_owned, foreign_unowned = _sync_repository_loss_preview(
        repository_files, projection_files, target_files
    )
    blockers = list(snapshot.blockers)
    if pending_operation is not None and pending_operation != operation:
        blockers.append(
            f"pending {pending_operation} transaction must recover before {operation}"
        )
    try:
        orphan_stages = sorted(
            name
            for name in os.listdir(root)
            if re.fullmatch(r"\..+\.sync-[0-9a-f]{16}\.tmp", name)
        )
    except OSError as exc:
        blockers.append(f"cannot enumerate checkout synchronization stages: {exc}")
    else:
        expected_stages = (
            {
                _publish_temp_name(name, pending_record["nonce"])
                for name in pending_record["target_repository_files"]
            }
            if pending_record is not None
            else set()
        )
        unexpected_stages = sorted(set(orphan_stages) - expected_stages)
        if unexpected_stages:
            label = (
                "unexpected synchronization stages block recovery: "
                if pending_record is not None
                else "orphan synchronization stages block a new plan: "
            )
            blockers.append(label + ", ".join(unexpected_stages))
    if snapshot.state == "sync-recovery-pending":
        # The executor can replay the durable record; a fresh plan must not
        # silently authorize a competing transaction.
        pass
    elif effective_state in {"unprojected", "pending-stale", "busy", "malformed"}:
        blockers.append(f"{operation} requires a usable checkout projection, found {effective_state}")
    elif operation == "publish" and effective_state in {"repository-only", "both"} and not replace_repository:
        blockers.append(
            f"publish refuses {snapshot.state} drift without --replace-repository"
        )
    elif operation == "unpublish" and effective_state in {"repository-only", "both"} and not replace_repository:
        blockers.append(
            "unpublish refuses repository-side drift without --replace-repository"
        )
    if effective_state != "sync-recovery-pending" and foreign_unowned:
        blockers.append(
            "foreign/unowned repository corpus paths block synchronization: "
            + ", ".join(foreign_unowned)
        )
    if effective_state != "sync-recovery-pending" and modified_owned and not replace_repository:
        blockers.append(
            "modified projection-owned repository corpus paths require --replace-repository: "
            + ", ".join(modified_owned)
        )
    return CorpusPublishPlan(
        snapshot.project_root, snapshot.project_key, snapshot.active_revision, effective_state,
        snapshot.repository_files, tuple(sorted(corpus_files.items())), snapshot.projection_sha256,
        tuple(sorted(set(blockers))), operation, replace_repository,
        modified_owned, obsolete_owned, foreign_unowned,
        tuple(sorted((recovery_target_files or {}).items())),
        pending_operation,
    )


def plan_corpus_publish(
    project_root: Path | str,
    *,
    replace_repository: bool = False,
    identity_lock_held: bool = False,
) -> CorpusPublishPlan:
    return _plan_corpus_synchronization(
        project_root,
        operation="publish",
        replace_repository=replace_repository,
        identity_lock_held=identity_lock_held,
    )


def plan_corpus_unpublish(
    project_root: Path | str,
    *,
    replace_repository: bool = False,
    identity_lock_held: bool = False,
) -> CorpusPublishPlan:
    return _plan_corpus_synchronization(
        project_root,
        operation="unpublish",
        replace_repository=replace_repository,
        identity_lock_held=identity_lock_held,
    )


class CorpusSynchronizationSession:
    """Publish lock holder: activity, deployment, identity, then checkout lock."""

    def __init__(self, plan: CorpusPublishPlan):
        self.plan = plan
        self._activity = self._deployment = self._identity = self._structural = None

    def __enter__(self):
        try:
            if self.plan.project_key is None:
                raise _ProjectCorpusTransitionBlocked(
                    "external project key is unavailable"
                )
            self._activity = try_activity_shared()
            if self._activity is None:
                raise _ProjectCorpusTransitionBlocked(
                    "state activity is busy"
                )
            self._deployment = _acquire_deployment_lock(
                exclusive=False, nonblocking=True
            )
            if self._deployment is None:
                raise _ProjectCorpusTransitionBlocked(
                    "machine deployment is busy"
                )
            self._identity = _acquire_corpus_identity_lock(
                corpus_lock_path(self.plan.project_key), nonblocking=True
            )
            if self._identity is None:
                raise _ProjectCorpusTransitionBlocked(
                    "project corpus identity is busy"
                )
            self._structural = _acquire_legacy_structural_lock(
                structural_lock_path(Path(self.plan.project_root)),
                nonblocking=True,
            )
            if self._structural is None:
                raise _ProjectCorpusTransitionBlocked(
                    "checkout structural lock is busy"
                )
        except _ProjectCorpusTransitionBlocked:
            self.close()
            raise
        except (OSError, ValueError) as exc:
            self.close()
            raise _ProjectCorpusTransitionBlocked(
                f"cannot acquire synchronization session: {exc}"
            ) from None
        return self

    def close(self):
        for lock in (self._structural, self._identity, self._deployment, self._activity):
            if lock is not None:
                lock.close()
        self._activity = self._deployment = self._identity = self._structural = None

    def __exit__(self, *_: object) -> None:
        self.close()


def _sync_transaction_is_valid(record: object, *, key: str) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == _CORPUS_SYNC_TRANSACTION_KEYS
        and record.get("schema_version") == 1
        and record.get("operation") in {"publish", "unpublish"}
        and record.get("project_key") == key
        and isinstance(record.get("nonce"), str)
        and bool(re.fullmatch(r"[0-9a-f]{16}", record["nonce"]))
        and isinstance(record.get("revision"), str)
        and bool(_CORPUS_REVISION_RE.fullmatch(record["revision"]))
        and (
            record.get("projection_sha256") is None
            or (
                isinstance(record.get("projection_sha256"), str)
                and bool(_SHA256_HEX_RE.fullmatch(record["projection_sha256"]))
            )
        )
        and all(
            _valid_corpus_files(record.get(name), require_nonempty=False)
            for name in (
                "before_repository_files",
                "target_repository_files",
                "corpus_files",
            )
        )
    )


@dataclass(frozen=True)
class _PublishEntry:
    payload: bytes
    dev: int
    ino: int
    mode: int
    nlink: int


def _open_publish_directory(root: Path) -> int:
    """Open the validated physical checkout once for basename-only mutation."""
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        expected = root.stat()
        actual = os.fstat(fd)
        if (
            not stat.S_ISDIR(actual.st_mode)
            or (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino)
        ):
            raise _ProjectCorpusTransitionBlocked(
                "project directory changed during publish"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_publish_entry(
    directory_fd: int, name: str, *, cap: int = EXTERNAL_CORPUS_FILE_MAX_BYTES
) -> _PublishEntry | None:
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise _ProjectCorpusTransitionBlocked(f"unsafe publish entry: {name}")
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(
            f"publish entry is unreadable: {name}"
        ) from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > cap
        ):
            raise _ProjectCorpusTransitionBlocked(f"unsafe publish entry: {name}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            payload = handle.read(cap + 1)
        if len(payload) > cap:
            raise _ProjectCorpusTransitionBlocked(f"oversized publish entry: {name}")
        return _PublishEntry(
            payload,
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
        )
    finally:
        if fd != -1:
            os.close(fd)


def _publish_entry_digest(entry: _PublishEntry | None) -> str | None:
    return hashlib.sha256(entry.payload).hexdigest() if entry is not None else None


def _publish_temp_name(name: str, nonce: str) -> str:
    return f".{name}.sync-{nonce}.tmp"


def _stage_publish_payload(
    directory_fd: int, name: str, payload: bytes, nonce: str
) -> str:
    if not is_valid_corpus_filename(name):
        raise _ProjectCorpusTransitionBlocked(f"unsafe publish target: {name}")
    expected = hashlib.sha256(payload).hexdigest()
    temporary = _publish_temp_name(name, nonce)
    existing = _read_publish_entry(directory_fd, temporary)
    if existing is not None:
        if (
            _publish_entry_digest(existing) != expected
            or stat.S_IMODE(existing.mode) != 0o644
        ):
            raise _ProjectCorpusTransitionBlocked(
                f"publish stage is malformed or foreign: {temporary}"
            )
        return temporary
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o644,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _ProjectCorpusTransitionBlocked(
                f"publish stage is unsafe: {temporary}"
            )
        os.fchmod(fd, 0o644)
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("zero-byte publish stage write")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    staged = _read_publish_entry(directory_fd, temporary)
    if staged is None or _publish_entry_digest(staged) != expected:
        raise _ProjectCorpusTransitionBlocked(
            f"publish stage verification failed: {temporary}"
        )
    return temporary


def _publish_entry_evidence(entry: _PublishEntry) -> tuple[int, int, int, int]:
    return entry.dev, entry.ino, entry.mode, entry.nlink


def _install_publish_payload(
    directory_fd: int,
    name: str,
    temporary: str,
    *,
    before_digest: str | None,
    target_digest: str,
) -> None:
    live = _read_publish_entry(directory_fd, name)
    live_digest = _publish_entry_digest(live)
    if live_digest == target_digest and live is not None and stat.S_IMODE(live.mode) == 0o644:
        return
    if live is None:
        if before_digest is not None:
            raise _ProjectCorpusTransitionBlocked(
                f"publish target changed after authorization: {name}"
            )
    elif live_digest != before_digest and live_digest != target_digest:
        raise _ProjectCorpusTransitionBlocked(
            f"publish target changed after authorization: {name}"
        )
    staged = _read_publish_entry(directory_fd, temporary)
    if (
        staged is None
        or _publish_entry_digest(staged) != target_digest
        or stat.S_IMODE(staged.mode) != 0o644
    ):
        raise _ProjectCorpusTransitionBlocked(
            f"publish stage is unavailable or changed: {temporary}"
        )
    if live is None:
        try:
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _ProjectCorpusTransitionBlocked(
                f"publish target appeared immediately before create: {name}"
            )
    else:
        immediate = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _publish_entry_evidence(live) != (
            immediate.st_dev,
            immediate.st_ino,
            immediate.st_mode,
            immediate.st_nlink,
        ):
            raise _ProjectCorpusTransitionBlocked(
                f"publish target changed immediately before replace: {name}"
            )
    immediate_stage = os.stat(
        temporary, dir_fd=directory_fd, follow_symlinks=False
    )
    if _publish_entry_evidence(staged) != (
        immediate_stage.st_dev,
        immediate_stage.st_ino,
        immediate_stage.st_mode,
        immediate_stage.st_nlink,
    ):
        raise _ProjectCorpusTransitionBlocked(
            f"publish stage changed immediately before replace: {temporary}"
        )
    os.replace(
        temporary,
        name,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )
    os.fsync(directory_fd)


def _remove_publish_entry(
    directory_fd: int, name: str, *, before_digest: str
) -> None:
    """Remove one pre-authorized owned file, with an inode check at unlink."""
    live = _read_publish_entry(directory_fd, name)
    if live is None:
        return
    if _publish_entry_digest(live) != before_digest:
        raise _ProjectCorpusTransitionBlocked(
            f"publish obsolete target changed after authorization: {name}"
        )
    immediate = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _publish_entry_evidence(live) != (
        immediate.st_dev,
        immediate.st_ino,
        immediate.st_mode,
        immediate.st_nlink,
    ):
        raise _ProjectCorpusTransitionBlocked(
            f"publish obsolete target changed immediately before remove: {name}"
        )
    os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _repository_map_from_publish_fd(directory_fd: int) -> dict[str, str]:
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(
            "repository corpus cannot be enumerated"
        ) from exc
    selected = [
        name
        for name in names
        if not name.startswith(".")
        and any(Path(name).match(spec) for spec in EXTERNAL_PROJECTION_ARTIFACT_SPECS)
        and not Path(name).match("*-PORTABLE-LEARNINGS.md")
        and is_valid_corpus_filename(name)
    ]
    if len(selected) > EXTERNAL_CORPUS_MAX_CHILDREN:
        raise _ProjectCorpusTransitionBlocked(
            "repository corpus exceeds the 256-child cap"
        )
    result: dict[str, str] = {}
    for name in selected:
        entry = _read_publish_entry(directory_fd, name)
        if entry is None:
            raise _ProjectCorpusTransitionBlocked(
                f"repository corpus disappeared during verification: {name}"
            )
        result[name] = hashlib.sha256(entry.payload).hexdigest()
    return dict(sorted(result.items()))


def _publish_mode_mismatches(root: Path, target_files: dict[str, str]) -> tuple[str, ...]:
    """Return target paths that need a mode-only replacement to reach 0644."""
    directory_fd = _open_publish_directory(root)
    try:
        mismatches = []
        for name in sorted(target_files):
            entry = _read_publish_entry(directory_fd, name)
            if entry is not None and stat.S_IMODE(entry.mode) != 0o644:
                mismatches.append(name)
        return tuple(mismatches)
    finally:
        os.close(directory_fd)


def _cleanup_publish_stages(
    directory_fd: int, target_files: dict[str, str], nonce: str
) -> None:
    _assert_publish_stage_family(directory_fd, target_files, nonce)
    changed = False
    for name, digest in sorted(target_files.items()):
        temporary = _publish_temp_name(name, nonce)
        staged = _read_publish_entry(directory_fd, temporary)
        if staged is None:
            continue
        if _publish_entry_digest(staged) != digest:
            raise _ProjectCorpusTransitionBlocked(
                f"refusing to remove changed publish stage: {temporary}"
            )
        os.unlink(temporary, dir_fd=directory_fd)
        changed = True
    if changed:
        os.fsync(directory_fd)


def _assert_publish_stage_family(
    directory_fd: int, target_files: dict[str, str], nonce: str
) -> None:
    """Reject every synchronization temp not owned by this transaction."""
    expected = {_publish_temp_name(name, nonce) for name in target_files}
    pattern = re.compile(r"\..+\.sync-[0-9a-f]{16}\.tmp")
    try:
        candidates = [name for name in os.listdir(directory_fd) if pattern.fullmatch(name)]
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked("cannot enumerate publish stages") from exc
    unexpected = sorted(set(candidates) - expected)
    if unexpected:
        raise _ProjectCorpusTransitionBlocked(
            "unexpected synchronization stages block synchronization: "
            + ", ".join(unexpected)
        )


def _read_sync_transaction(project_key: str, root: Path) -> dict | None:
    return _read_valid_corpus_record(
        corpus_sync_transaction_path(project_key, root),
        lambda record: _sync_transaction_is_valid(record, key=project_key),
        "corpus synchronization transaction",
    )


def _supersede_sync_transaction(
    project_key: str, root: Path, record: dict
) -> dict[str, str]:
    """Quarantine a blocked sync record after proving it owns every live path.

    This is deliberately available only to the explicit publish replacement
    route.  It never treats a foreign corpus basename as transaction debris.
    """
    transaction_path = corpus_sync_transaction_path(project_key, root)
    raw_projection = _raw_authority_digest(corpus_projection_path(project_key, root))
    if raw_projection is None or raw_projection[0] != record["projection_sha256"]:
        raise _ProjectCorpusTransitionBlocked(
            "pending synchronization transaction no longer has its prior projection evidence"
        )
    projection = read_corpus_projection_record(project_key, root)
    if projection is None:
        raise _ProjectCorpusTransitionBlocked(
            "pending synchronization transaction projection is unavailable"
        )
    directory_fd = _open_publish_directory(root)
    try:
        live = _repository_map_from_publish_fd(directory_fd)
        projection_files = projection["repository_files"]
        target_files = record["target_repository_files"]
        foreign = sorted(
            name
            for name in live
            if name not in projection_files
            and not (name in target_files and live[name] == target_files[name])
        )
        if foreign:
            raise _ProjectCorpusTransitionBlocked(
                "foreign/unowned repository corpus paths block transaction supersession: "
                + ", ".join(foreign)
            )
        _cleanup_publish_stages(directory_fd, target_files, record["nonce"])
    finally:
        os.close(directory_fd)
    quarantine = transaction_path.parent / "quarantine"
    _ensure_transition_directory(quarantine, "sync-transaction-quarantine")
    destination = quarantine / f"{transaction_path.name}-{record['nonce']}"
    os.rename(transaction_path, destination)
    _fsync_dir(quarantine)
    _fsync_dir(transaction_path.parent)
    return {
        name: digest
        for name, digest in target_files.items()
        if name not in projection_files and live.get(name) == digest
    }


def _projection_matches_publish_target(
    project_key: str,
    root: Path,
    revision: str,
    repository_files: dict[str, str],
    corpus_files: dict[str, str],
) -> bool:
    projection = read_corpus_projection_record(project_key, root)
    return (
        projection is not None
        and projection["revision"] == revision
        and projection["repository_files"] == repository_files
        and projection["corpus_files"] == corpus_files
    )


def _preserve_stale_projection_evidence(
    project_key: str, root: Path, active: dict, expected_sha256: str | None
) -> None:
    """Durably retain a stale projection before the normal atomic replacement."""
    projection_path = corpus_projection_path(project_key, root)
    projection = read_corpus_projection_record(project_key, root)
    if projection is None or projection["revision"] in {
        active["active_revision"], active["previous_revision"],
    }:
        return
    raw = _read_file_capped(projection_path, _CORPUS_RECORD_MAX_BYTES)
    if raw is None:
        raise _ProjectCorpusTransitionBlocked("stale projection evidence is unreadable")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise _ProjectCorpusTransitionBlocked("stale projection changed before quarantine")
    directory = projection_path.parent / "quarantine"
    _ensure_transition_directory(directory, "stale-projection-quarantine")
    destination = directory / f"{observed_path_id(root)}-{digest}.json"
    if destination.exists() or destination.is_symlink():
        existing = _read_file_capped(destination, _CORPUS_RECORD_MAX_BYTES)
        if existing != raw:
            raise _ProjectCorpusTransitionBlocked("stale projection quarantine evidence conflicts")
        return
    _write_new_fsynced(destination, raw)
    _fsync_dir(directory)
    _crash_point("reimport-after-stale-projection-quarantine")


def _sync_crash_point(operation: str, point: str) -> None:
    _crash_point(f"{operation}-{point}")


def apply_corpus_publish(preview: CorpusPublishPlan | Path | str) -> CorpusPublishPlan:
    """Apply one publish or unpublish plan through the shared sync engine."""
    root = _validated_project_root(
        preview.project_root if isinstance(preview, CorpusPublishPlan) else preview
    )
    reported = preview if isinstance(preview, CorpusPublishPlan) else plan_corpus_publish(root)
    if reported.blockers:
        raise _ProjectCorpusTransitionBlocked(*reported.blockers)
    with CorpusSynchronizationSession(reported):
        if reported.project_key is None:
            raise _ProjectCorpusTransitionBlocked("external project key is unavailable")
        project_key = reported.project_key
        transaction_path = corpus_sync_transaction_path(project_key, root)
        record = _read_sync_transaction(project_key, root)
        if record is not None and record["operation"] != reported.operation:
            raise _ProjectCorpusTransitionBlocked(
                f"pending {record['operation']} transaction must recover before {reported.operation}"
            )
        active = read_corpus_active_record(project_key)
        if record is not None and (active is None or active["active_revision"] != record["revision"]):
            raise _ProjectCorpusTransitionBlocked(
                "pending synchronization transaction names a different active revision"
            )
        transaction_owned_files: dict[str, str] | None = None
        superseded = False
        if (
            record is not None
            and reported.operation == "publish"
            and reported.replace_repository
        ):
            transaction_owned_files = _supersede_sync_transaction(project_key, root, record)
            record = None
            superseded = True
        if record is None:
            current = _plan_corpus_synchronization(
                root,
                operation=reported.operation,
                replace_repository=reported.replace_repository,
                identity_lock_held=True,
                transaction_owned_files=transaction_owned_files,
            )
            if not superseded and reported != current:
                raise _ProjectCorpusTransitionBlocked(
                    "synchronization plan changed while acquiring locks; rerun apply"
                )
            if current.blockers:
                raise _ProjectCorpusTransitionBlocked(*current.blockers)
            if (
                current.operation == "publish"
                and current.state == "clean"
                and current.repository_files == current.corpus_files
                and not _publish_mode_mismatches(root, dict(current.corpus_files))
            ) or (
                current.operation == "unpublish"
                and current.state == "clean"
                and not current.repository_files
            ):
                return current
            if current.state not in {"clean", "external-only", "repository-only", "both"}:
                raise _ProjectCorpusTransitionBlocked(
                    f"{current.operation} cannot apply from {current.state}"
                )
            if current.project_key is None or current.active_revision is None:
                raise _ProjectCorpusTransitionBlocked(
                    "external synchronization authority is incomplete"
                )
            project_key = current.project_key
            target_files = (
                dict(current.recovery_target_files or current.corpus_files)
                if current.operation == "publish"
                else {}
            )
            record = {
                "schema_version": 1,
                "nonce": uuid.uuid4().hex[:16],
                "operation": current.operation,
                "project_key": project_key,
                "revision": current.active_revision,
                "projection_sha256": current.projection_sha256,
                "before_repository_files": dict(current.repository_files),
                "target_repository_files": target_files,
                "corpus_files": dict(current.corpus_files),
            }
            _ensure_transition_directory(transaction_path.parent, "sync-transactions")
            _replace_transition_json(transaction_path, record, "sync-transaction")
            _sync_crash_point(record["operation"], "after-transaction")
        active = read_corpus_active_record(project_key)
        if active is None or active["active_revision"] != record["revision"]:
            raise _ProjectCorpusTransitionBlocked(
                "pending synchronization transaction names a different active revision"
            )
        target_files = dict(record["target_repository_files"])
        before_files = dict(record["before_repository_files"])
        source_files = dict(record["corpus_files"])
        if (
            record["operation"] == "publish" and target_files != source_files
        ) or (
            record["operation"] == "unpublish" and target_files
        ):
            raise _ProjectCorpusTransitionBlocked(
                "pending synchronization transaction has an invalid operation target"
            )
        revision = corpus_revision_dir(project_key, record["revision"])
        directory_fd = _open_publish_directory(root)
        try:
            _assert_publish_stage_family(directory_fd, target_files, record["nonce"])
            staged: dict[str, str] = {}
            for name, target_digest in sorted(target_files.items()):
                live = _read_publish_entry(directory_fd, name)
                live_digest = _publish_entry_digest(live)
                if (
                    live_digest == target_digest
                    and live is not None
                    and stat.S_IMODE(live.mode) == 0o644
                ):
                    continue
                before_digest = before_files.get(name)
                if live is None:
                    if before_digest is not None:
                        raise _ProjectCorpusTransitionBlocked(
                            f"publish target changed after authorization: {name}"
                        )
                elif live_digest != before_digest and live_digest != target_digest:
                    raise _ProjectCorpusTransitionBlocked(
                        f"publish target changed after authorization: {name}"
                    )
                staged_entry = _read_publish_entry(
                    directory_fd, _publish_temp_name(name, record["nonce"])
                )
                payload = (
                    live.payload
                    if live_digest == target_digest and live is not None
                    else staged_entry.payload
                    if staged_entry is not None
                    and _publish_entry_digest(staged_entry) == target_digest
                    and stat.S_IMODE(staged_entry.mode) == 0o644
                    else _read_file_capped(revision / name, EXTERNAL_CORPUS_FILE_MAX_BYTES)
                )
                if (
                    payload is None
                    or hashlib.sha256(payload).hexdigest() != target_digest
                ):
                    raise _ProjectCorpusTransitionBlocked(
                        f"authorized external publish payload is unavailable: {name}"
                    )
                staged[name] = _stage_publish_payload(
                    directory_fd, name, payload, record["nonce"]
                )
            _sync_crash_point(record["operation"], "after-stage-all")
            for name, temporary in sorted(staged.items()):
                _install_publish_payload(
                    directory_fd,
                    name,
                    temporary,
                    before_digest=before_files.get(name),
                    target_digest=target_files[name],
                )
            _sync_crash_point(record["operation"], "after-install")
            obsolete = sorted(
                set(before_files) - set(target_files),
                key=lambda name: (name == "LEARNINGS.md", name),
            )
            for name in obsolete:
                _remove_publish_entry(
                    directory_fd, name, before_digest=before_files[name]
                )
                _sync_crash_point(record["operation"], "after-obsolete-remove")
            if _repository_map_from_publish_fd(directory_fd) != target_files:
                raise _ProjectCorpusTransitionBlocked(
                    "synchronization target verification failed"
                )
        finally:
            os.close(directory_fd)
        if not _projection_matches_publish_target(
            project_key, root, record["revision"], target_files, source_files
        ):
            live_projection = _raw_authority_digest(
                corpus_projection_path(project_key, root)
            )
            live_projection_digest = (
                live_projection[0] if live_projection is not None else None
            )
            if live_projection_digest != record["projection_sha256"]:
                raise _ProjectCorpusTransitionBlocked(
                    "checkout projection changed after publish authorization"
                )
            _preserve_stale_projection_evidence(project_key, root, active, record["projection_sha256"])
            projection = build_corpus_projection_record(
                project_key,
                root,
                record["revision"],
                target_files,
                source_files,
            )
            _sync_crash_point(record["operation"], "before-projection")
            write_corpus_projection_record(project_key, root, projection)
        _sync_crash_point(record["operation"], "after-projection")
        directory_fd = _open_publish_directory(root)
        try:
            _cleanup_publish_stages(directory_fd, target_files, record["nonce"])
        finally:
            os.close(directory_fd)
        _sync_crash_point(record["operation"], "after-stage-cleanup")
        if _read_sync_transaction(project_key, root) != record:
            raise _ProjectCorpusTransitionBlocked(
                "synchronization transaction changed before cleanup"
            )
        transaction_path.unlink()
        _fsync_dir(transaction_path.parent)
        return _plan_corpus_synchronization(
            root,
            operation=reported.operation,
            replace_repository=reported.replace_repository,
            identity_lock_held=True,
        )


def apply_corpus_unpublish(preview: CorpusPublishPlan | Path | str) -> CorpusPublishPlan:
    if isinstance(preview, CorpusPublishPlan):
        if preview.operation != "unpublish":
            raise ValueError("unpublish requires an unpublish plan")
        return apply_corpus_publish(preview)
    return apply_corpus_publish(plan_corpus_unpublish(preview))


def inspect_active_corpus_authority() -> tuple[dict, ...]:
    """Enumerate every corpus authority entry, including damaged entries.

    This intentionally does not use ``_active_corpus_transition_guard``:
    machine transitions need one blocker, while status and recovery need the
    complete set of rows.
    """
    root = corpora_root()
    if root is None or not root.exists():
        return ()
    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return ({"project_key": "(corpora)", "status": "malformed", "reason": str(exc)},)
    rows: list[dict] = []
    for entry in entries:
        if entry.name.startswith("."):
            continue
        row = {"project_key": entry.name, "status": "malformed", "reason": "authority entry is not a directory"}
        if entry.is_symlink() or not entry.is_dir():
            rows.append(row)
            continue
        try:
            active = read_corpus_active_record(entry.name)
        except ValueError as exc:
            rows.append({"project_key": entry.name, "status": "malformed", "reason": str(exc)})
            continue
        if active is not None:
            if _valid_active_revision(entry.name, active) is None:
                rows.append(
                    {
                        "project_key": entry.name,
                        "status": "dangling",
                        "reason": "active revision is missing or malformed",
                    }
                )
            else:
                status = "external"
                reason = None
                live_observed: list[str] = []
                missing_observed: list[str] = []
                pending_operations: list[str] = []
                for observed in active["observed_roots"]:
                    try:
                        exists = Path(observed).is_dir()
                    except OSError as exc:
                        status, reason = "malformed", str(exc)
                        break
                    (live_observed if exists else missing_observed).append(observed)
                    try:
                        pending = _read_sync_transaction_for_observed_root(
                            entry.name, observed
                        )
                    except ValueError as exc:
                        status, reason = "malformed", str(exc)
                        break
                    if pending is not None:
                        pending_operations.append(pending["operation"])
                pending_label = ", ".join(sorted(set(pending_operations)))
                if status == "external" and missing_observed:
                    status = "defunct"
                    reason = "an observed checkout is missing"
                    if pending_operations:
                        reason += (
                            f"; pending {pending_label} "
                            "synchronization recovery evidence remains"
                        )
                elif status == "external" and pending_operations:
                    status = "sync-recovery-pending"
                    reason = (
                        f"pending {pending_label} synchronization; "
                        "recover it or use `learn corpus publish --replace-repository` "
                        "to supersede it"
                    )
                if status in {"external", "defunct"}:
                    projection_pending = False
                    for observed in live_observed:
                        checkout = Path(observed)
                        try:
                            projection = read_corpus_projection_record(entry.name, checkout)
                        except ValueError as exc:
                            status, reason = "malformed", str(exc)
                            break
                        if projection is None or projection["revision"] not in {
                            active["active_revision"],
                            active["previous_revision"],
                        }:
                            projection_pending = True
                    if status == "external" and projection_pending:
                        status, reason = (
                            "pending-stale",
                            "checkout projection is absent or stale",
                        )
                    elif status == "defunct" and projection_pending:
                        reason += "; a live checkout projection is absent or stale"
                row = {"project_key": entry.name, "status": status, "record": active}
                if reason:
                    row["reason"] = reason
                rows.append(row)
            continue
        try:
            deactivated = read_corpus_deactivated_record(entry.name)
        except ValueError as exc:
            rows.append({"project_key": entry.name, "status": "malformed", "reason": str(exc)})
            continue
        if deactivated is not None:
            if _valid_active_revision(entry.name, deactivated) is None:
                rows.append(
                    {
                        "project_key": entry.name,
                        "status": "dangling",
                        "reason": "deactivated revision is missing or malformed",
                    }
                )
            else:
                rows.append({"project_key": entry.name, "status": "deactivated", "record": deactivated})
        else:
            rows.append(
                {
                    "project_key": entry.name,
                    "status": "malformed",
                    "reason": "authority directory has no active or deactivated record",
                }
            )
    return tuple(rows)


def inspect_project_corpus_status(
    *, project_root: Path | str | None = None, project_key: str | None = None
) -> dict:
    """Inspect one checkout or key without repairing or publishing anything."""
    if (project_root is None) == (project_key is None):
        raise ValueError("exactly one of project_root or project_key is required")
    if project_key is not None:
        if not is_project_key(project_key):
            raise ValueError(f"invalid project key: {project_key!r}")
        root = corpora_root()
        if root is None:
            return {"project_key": project_key, "status": "absent", "reason": "neutral corpus root is unavailable"}
        rows = [row for row in inspect_active_corpus_authority() if row["project_key"] == project_key]
        return rows[0] if rows else {
            "project_key": project_key,
            "status": "absent",
            "reason": "no corpus authority record",
        }
    root = _validated_project_root(project_root)
    identity = None
    try:
        identity = project_identity(root)
    except IdentityResolutionError:
        pass
    for row in inspect_active_corpus_authority():
        record = row.get("record")
        root_matches = record is not None and (
            str(root) in record.get("observed_roots", ())
            or (identity is not None and identity.canonical in record.get("canonical_aliases", ()))
        )
        if root_matches:
            if row["status"] == "deactivated":
                return row
            direct = {
                "project_key": row["project_key"],
                "status": "external",
                "record": record,
            }
            try:
                pending = _read_sync_transaction(row["project_key"], root)
            except ValueError as exc:
                return {**direct, "status": "malformed", "reason": str(exc)}
            if pending is not None:
                return {
                    **direct,
                    "status": "sync-recovery-pending",
                    "reason": (
                        f"pending {pending['operation']} synchronization; recover it or use "
                        "`learn corpus publish --replace-repository` to supersede it"
                    ),
                }
            try:
                projection = read_corpus_projection_record(row["project_key"], root)
            except ValueError as exc:
                return {**direct, "status": "malformed", "reason": str(exc)}
            if projection is None:
                return {
                    **direct,
                    "status": "pending-stale",
                    "reason": "checkout has no current cutover projection",
                }
            if projection["revision"] not in {
                record["active_revision"],
                record["previous_revision"],
            }:
                return {
                    **direct,
                    "status": "pending-stale",
                    "reason": "checkout projection names a stale revision",
                }
            return direct
    if _legacy_corpus_present(root):
        return {"project_key": None, "status": "legacy", "reason": "repository corpus remains authoritative"}
    return {"project_key": None, "status": "absent", "reason": "no corpus authority or legacy corpus"}


def _external_location_for_record(project_root: Path, project_key: str, record: dict) -> CorpusLocation | None:
    revision = _valid_active_revision(project_key, record)
    if revision is None:
        return None
    return CorpusLocation(project_root, project_key, revision, corpus_lock_path(project_key), "external")


def iter_active_external_locations(
    scan_root: Path | str,
) -> tuple[tuple[CorpusLocation, ...], tuple[tuple[str, str], ...]]:
    """Enumerate valid active corpus locations below one scan root.

    A damaged catalog entry is local to its project key: callers receive one
    bounded error and can continue processing the remaining locations.
    """
    root = _validated_project_root(scan_root)
    locations: list[CorpusLocation] = []
    errors: list[tuple[str, str]] = []
    for project_key, record, _active in _iter_active_corpus_records() or ():
        if record is None:
            errors.append((project_key, "active corpus record is malformed"))
            continue
        revision = _valid_active_revision(project_key, record)
        if revision is None:
            errors.append((project_key, "active corpus revision is malformed or dangling"))
            continue
        observed: list[Path] = []
        for value in record["observed_roots"]:
            try:
                candidate = Path(value)
                if not candidate.is_dir():
                    continue
                candidate = candidate.resolve()
            except OSError:
                continue
            if candidate == root or root in candidate.parents:
                observed.append(candidate)
        if observed:
            selected = min(observed, key=str)
            locations.append(
                CorpusLocation(selected, project_key, revision, corpus_lock_path(project_key), "external")
            )
    ordered = tuple(sorted(locations, key=lambda location: (location.project_key, str(location.project_root))))
    return ordered, tuple(errors)


def _legacy_corpus_present(project_root: Path) -> bool:
    source = project_root / "LEARNINGS.md"
    return _regular_single_link(source, max_bytes=None)


_SYSTEM_OWNERSHIP_MARKER = b"<!-- Organized by topic, not chronologically."
_PRIMARY_NOT_SYSTEM_OWNED_BLOCKER = "primary LEARNINGS.md is not system-owned"
_PRIMARY_UNCOMMITTED_BLOCKER = "primary LEARNINGS.md system ownership is uncommitted or ambiguous"


def _system_owned_legacy_corpus(project_root: Path) -> bool:
    """Recognize the canonical HTML marker in fd-bound whole-primary bytes."""
    source = project_root / "LEARNINGS.md"
    raw = _read_file_capped(source, EXTERNAL_CORPUS_FILE_MAX_BYTES)
    if raw is None or _SYSTEM_OWNERSHIP_MARKER not in raw:
        return False
    try:
        tracked = _git(project_root, "ls-files", "--error-unmatch", "--", "LEARNINGS.md")
    except IdentityResolutionError:
        return False
    return tracked == "LEARNINGS.md"


def _legacy_primary_is_committed(project_root: Path) -> bool:
    """Ownership is ambiguous until the tracked primary has a committed tip."""
    if not _system_owned_legacy_corpus(project_root):
        return False
    try:
        return _git(project_root, "log", "-1", "--format=%H", "--", "LEARNINGS.md") is not None
    except IdentityResolutionError:
        return False


def _legacy_roster_missing_marker_eligible(project_root: Path) -> tuple[bool, str | None]:
    """Prove the narrow historic-marker exception without classifying ownership."""
    primary = project_root / "LEARNINGS.md"
    raw = _read_file_capped(primary, EXTERNAL_CORPUS_FILE_MAX_BYTES)
    if raw is None:
        return False, "primary LEARNINGS.md is not a readable regular single-link file"
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, "primary LEARNINGS.md is not valid UTF-8"
    if _SYSTEM_OWNERSHIP_MARKER in raw:
        return False, "primary LEARNINGS.md contains the current ownership marker"
    try:
        tracked = _git(project_root, "ls-files", "--error-unmatch", "--", "LEARNINGS.md")
        committed = _git(project_root, "log", "-1", "--format=%H", "--", "LEARNINGS.md")
    except IdentityResolutionError as exc:
        return False, f"primary LEARNINGS.md Git provenance is unavailable: {exc}"
    if tracked != "LEARNINGS.md":
        return False, "primary LEARNINGS.md is not tracked"
    if committed is None:
        return False, "primary LEARNINGS.md has no committed provenance"
    return True, None


_LEGACY_MIGRATION_ROSTER_KEYS = frozenset({"schema_version", "rows"})
_LEGACY_MIGRATION_ROW_KEYS = frozenset({
    "root", "canonical_identity", "identity_key", "project_key", "primary_commit",
    "sources", "target_digest", "archives",
})


def _canonical_record_digest(record: dict) -> str:
    return hashlib.sha256(_canonical_json_bytes(record)).hexdigest()


def _legacy_migration_row_is_valid(row: object) -> bool:
    if not isinstance(row, dict) or set(row) != _LEGACY_MIGRATION_ROW_KEYS:
        return False
    root = row.get("root")
    if not isinstance(root, str) or len(root.encode("utf-8")) > 4096:
        return False
    path = Path(root)
    if not path.is_absolute() or ".." in path.parts:
        return False
    identity = row.get("canonical_identity")
    key = row.get("identity_key")
    project_key = row.get("project_key")
    if not (
        isinstance(identity, str) and 0 < len(identity.encode("utf-8")) <= 4096
        and isinstance(key, str) and is_project_key(key)
        and isinstance(project_key, str) and is_project_key(project_key)
        and isinstance(row.get("primary_commit"), str) and bool(re.fullmatch(r"[0-9a-f]{40,64}", row["primary_commit"]))
        and isinstance(row.get("target_digest"), str) and bool(_SHA256_HEX_RE.fullmatch(row["target_digest"]))
        and _migration_file_records(row.get("sources")) and bool(row["sources"])
        and _migration_file_records(row.get("archives"), portable=True)
    ):
        return False
    return "LEARNINGS.md" in {item["name"] for item in row["sources"]}


def _read_legacy_migration_roster(path: Path | str) -> tuple[Path, str, tuple[dict, ...]]:
    """Read the explicit one-shot roster through the normal fd-bound reader."""
    raw_path = Path(path)
    if not raw_path.is_absolute():
        raise ValueError("legacy migration roster path must be absolute")
    raw = _read_file_capped(raw_path, LEGACY_MIGRATION_ROSTER_MAX_BYTES)
    if raw is None:
        raise ValueError("legacy migration roster is not a plain regular single-link file within the cap")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"legacy migration roster is not valid UTF-8 JSON: {exc}") from None
    if not (
        isinstance(record, dict)
        and set(record) == _LEGACY_MIGRATION_ROSTER_KEYS
        and record.get("schema_version") == 1
        and isinstance(record.get("rows"), list)
        and 0 < len(record["rows"]) <= LEGACY_MIGRATION_ROSTER_MAX_ROWS
        and all(_legacy_migration_row_is_valid(row) for row in record["rows"])
    ):
        raise ValueError("legacy migration roster has an invalid schema")
    if raw != _canonical_json_bytes(record):
        raise ValueError("legacy migration roster must use canonical JSON")
    roots = [row["root"] for row in record["rows"]]
    keys = [row["project_key"] for row in record["rows"]]
    if len(set(roots)) != len(roots) or len(set(keys)) != len(keys):
        raise ValueError("legacy migration roster has duplicate roots or project keys")
    return raw_path.resolve(), hashlib.sha256(raw).hexdigest(), tuple(record["rows"])


def _legacy_migration_row_for_project(
    roster_path: Path | str | None, root: Path, identity: ProjectIdentity, project_key: str
) -> tuple[Path, str, dict, str] | None:
    if roster_path is None:
        return None
    resolved, roster_digest, rows = _read_legacy_migration_roster(roster_path)
    row = next((candidate for candidate in rows if candidate["root"] == str(root)), None)
    if row is None:
        raise ValueError("legacy migration roster has no row for this checkout")
    if (
        row["canonical_identity"] != identity.canonical
        or row["identity_key"] != identity.key
        or row["project_key"] != project_key
    ):
        raise ValueError("legacy migration roster identity does not match this checkout")
    try:
        primary_commit = _git(root, "log", "-1", "--format=%H", "--", "LEARNINGS.md")
        tracked = _git(root, "ls-files", "--error-unmatch", "--", "LEARNINGS.md")
    except IdentityResolutionError as exc:
        raise ValueError(f"legacy migration roster Git provenance is unavailable: {exc}") from None
    if tracked != "LEARNINGS.md" or primary_commit != row["primary_commit"]:
        raise ValueError("legacy migration roster primary Git provenance changed")
    return resolved, roster_digest, row, _canonical_record_digest(row)


def _recognized_legacy_portable_names(
    neutral_root: Path, project_key: str, project_root: Path
) -> tuple[tuple[str, ...], str | None, str | None, tuple[str, ...]]:
    """Exact rollback-export names bound to this checkout or catalog history."""
    names: set[str] = set()
    ignored: set[str] = set()

    def consider(candidate: str) -> None:
        if _PATH_DERIVED_PORTABLE_RE.fullmatch(candidate):
            names.add(candidate)
        else:
            ignored.add(candidate)

    derivation_error = None
    inspection_error = None
    try:
        consider(portable_filename(project_root))
    except ValueError as exc:
        derivation_error = f"cannot derive this checkout's portable filename: {exc}"
    except OSError as exc:
        inspection_error = f"cannot inspect this checkout's path for a portable filename: {exc}"
    record = _published_identity_record(neutral_root / "projects" / project_key)
    if record is None:
        return (
            tuple(sorted(names)),
            derivation_error,
            inspection_error,
            tuple(sorted(ignored)),
        )
    if record.get("portable_filename"):
        consider(record["portable_filename"])
    for alias in record["legacy_aliases"]:
        consider(f"{alias}{PORTABLE_SUFFIX}")
    for observed_root in record["observed_roots"]:
        with contextlib.suppress(OSError, ValueError):
            consider(portable_filename(observed_root))
    return (
        tuple(sorted(names)),
        derivation_error,
        inspection_error,
        tuple(sorted(ignored)),
    )


def _legacy_import_candidates(
    project_root: Path,
    recognized_portable_names: tuple[str, ...],
    *,
    accepted_archives: tuple[CorpusTransitionFile, ...],
    archive_requires_exact_bytes: bool,
    derivation_error: str | None,
    inspection_error: str | None,
    ignored_catalog_names: tuple[str, ...],
    bare_remedy: str,
    portable_remedy: str,
) -> tuple[tuple[Path, ...], tuple[str, ...], tuple[str, ...]]:
    """Select only primary/topic Markdown and report every excluded corpus artifact.

    A legacy repository can contain ordinary non-corpus files, so this never
    applies the external revision directory's "only corpus children" rule to
    the checkout.  Portable snapshots are explicitly excluded: their bytes do
    not represent the project corpus being cut over.
    """
    selected: list[Path] = []
    blockers: list[str] = []
    notes: list[str] = []
    try:
        entries = sorted(project_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return (), (f"cannot enumerate repository corpus artifacts: {exc}",), ()
    recognized_portables = set(recognized_portable_names)
    accepted_archive_map = {item.name: item for item in accepted_archives}
    seen_accepted_archives: set[str] = set()
    for path in entries:
        name = path.name
        if name == "PORTABLE-LEARNINGS.md" or name.endswith(PORTABLE_SUFFIX):
            accepted = accepted_archive_map.get(name)
            if accepted is not None:
                seen_accepted_archives.add(name)
                if archive_requires_exact_bytes:
                    payload = _read_file_capped(path, EXTERNAL_CORPUS_FILE_MAX_BYTES)
                    if payload is None:
                        blockers.append(f"retained migration archive is unsafe: {name}")
                    elif (
                        len(payload) != accepted.size_bytes
                        or hashlib.sha256(payload).hexdigest() != accepted.sha256
                    ):
                        blockers.append(f"retained migration archive changed: {name}")
                    else:
                        notes.append(
                            f"retained migration archive is unmanaged and not imported: {name}"
                        )
                    continue
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    blockers.append(f"retained migration archive is unsafe: {name} ({exc})")
                    continue
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                ):
                    blockers.append(f"retained migration archive is unsafe: {name}")
                elif metadata.st_size > EXTERNAL_CORPUS_FILE_MAX_BYTES:
                    notes.append(
                        f"retained migration archive exceeds the adoption cap and remains unmanaged: {name}"
                    )
                else:
                    payload = _read_file_capped(path, EXTERNAL_CORPUS_FILE_MAX_BYTES)
                    if payload is None:
                        blockers.append(f"retained migration archive is unsafe: {name}")
                    elif (
                        len(payload) != accepted.size_bytes
                        or hashlib.sha256(payload).hexdigest() != accepted.sha256
                    ):
                        notes.append(
                            f"retained migration archive differs from adoption bytes and remains unmanaged: {name}"
                        )
                    else:
                        notes.append(f"retained migration archive is unmanaged and not imported: {name}")
                continue
            if name not in recognized_portables:
                recognized_summary = ", ".join(recognized_portable_names) or "none"
                if name == "PORTABLE-LEARNINGS.md":
                    remedy = bare_remedy
                    if name in ignored_catalog_names:
                        remedy += "; the identity catalog also records this non-path-derived bare name"
                elif name in ignored_catalog_names:
                    remedy = (
                        "the identity catalog records this name, but it is not a "
                        "path-derived <slug>-<8hex>-PORTABLE-LEARNINGS.md export; "
                        "archive it outside the checkout before retrying"
                    )
                elif inspection_error is not None:
                    remedy = f"{inspection_error}; retry after path inspection succeeds"
                elif derivation_error is not None:
                    remedy = (
                        f"{derivation_error}; archive this export outside the checkout "
                        "before retrying; to regenerate it later, first rename the checkout "
                        "directory to contain at least one ASCII letter or digit"
                    )
                else:
                    remedy = portable_remedy
                blockers.append(
                    f"portable-shaped artifact is not recognized rollback evidence: {name}; "
                    f"recognized rollback evidence names: {recognized_summary}; "
                    f"{remedy}"
                )
                continue
            try:
                metadata = path.lstat()
            except OSError as exc:
                blockers.append(
                    f"portable rollback evidence is unsafe: {name} ({exc}); "
                    "restore it to a plain regular single-link file"
                )
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                blockers.append(
                    f"portable rollback evidence is unsafe: {name}; "
                    "restore it to a plain regular single-link file"
                )
                continue
            notes.append(f"retained portable rollback evidence is not imported: {name}")
            continue
        if name == "LEARNINGS.md":
            selected.append(path)
            continue
        if name.startswith("LEARNINGS-") and name.endswith(".md"):
            if not is_valid_corpus_filename(name):
                blockers.append(f"invalid corpus topic filename: {name}")
            else:
                selected.append(path)
    if archive_requires_exact_bytes:
        for name in sorted(set(accepted_archive_map) - seen_accepted_archives):
            blockers.append(f"retained migration archive is missing: {name}")
    return tuple(selected), tuple(blockers), tuple(notes)


def _transition_lesson_lines(text: str) -> tuple[str, ...]:
    """The existing auto-split no-lesson-lost line parser, kept byte-for-byte.

    It deliberately ignores headings and HTML metadata while preserving a
    sorted multiset of all lesson-content lines, including duplicates.
    """
    no_comments = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    return tuple(sorted(
        line.strip()
        for line in no_comments.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ))


_NO_AUTHORITY_BLOCKER = "existing corpus authority is malformed: no active or deactivated record"


def _interrupted_init_pending(project_key: str) -> bool:
    """True when this key's directory holds only a fresh init's pending marker."""
    pending = corpus_project_dir(project_key) / _CORPUS_INIT_PENDING_NAME
    try:
        record = _read_corpus_record(pending)
    except (OSError, ValueError):
        return False
    return (
        isinstance(record, dict)
        and set(record) == {"schema_version", "project_key", "revision"}
        and record["schema_version"] == CORPUS_INIT_PENDING_SCHEMA_VERSION
        and record["project_key"] == project_key
        and isinstance(record["revision"], str)
    )


def _transition_authority_blockers(project_key: str, project_root: Path) -> tuple[str, ...]:
    """Report damaged or existing authority for this exact planned key only."""
    root = corpora_root()
    if root is None:
        return ("neutral corpus root is unavailable",)
    project_dir = root / project_key
    try:
        exists = project_dir.exists() or project_dir.is_symlink()
    except OSError as exc:
        return (f"cannot inspect existing corpus authority: {exc}",)
    if not exists:
        return ()
    blockers: list[str] = []
    try:
        st = project_dir.lstat()
    except OSError as exc:
        return (f"existing corpus authority is unreadable: {exc}",)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return ("existing corpus authority is malformed: project directory is unsafe",)
    active_present = False
    deactivated_present = False
    migrations = project_dir / "migrations"
    try:
        migration_metadata = migrations.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        blockers.append(f"existing corpus migrations are unreadable: {exc}")
    else:
        if stat.S_ISLNK(migration_metadata.st_mode) or not stat.S_ISDIR(migration_metadata.st_mode):
            blockers.append("existing corpus migrations are unsafe")
    try:
        active = read_corpus_active_record(project_key)
    except ValueError as exc:
        blockers.append(f"existing corpus authority is malformed: {exc}")
    else:
        if active is not None:
            active_present = True
            revision = _valid_active_revision(project_key, active)
            if revision is None:
                blockers.append("existing corpus authority is dangling: active revision is missing or malformed")
            blockers.append(
                "project already has active external authority; inspect it with "
                f"learn corpus status --cwd {project_root}"
            )
    try:
        deactivated = read_corpus_deactivated_record(project_key)
    except ValueError as exc:
        blockers.append(f"existing corpus deactivation record is malformed: {exc}")
    else:
        if deactivated is not None:
            deactivated_present = True
            if _valid_active_revision(project_key, deactivated) is None:
                blockers.append("existing corpus deactivation record is dangling")
            else:
                blockers.append("project has deactivated external authority; inspect it before a fresh import")
    if not active_present and not deactivated_present and not blockers:
        blockers.append(_NO_AUTHORITY_BLOCKER)
    try:
        for entry in project_dir.iterdir():
            if entry.name == "staging" or entry.name.startswith(".staging"):
                blockers.append(
                    "existing corpus staging is present; import cannot adopt or overwrite it in preview"
                )
                break
    except OSError as exc:
        blockers.append(f"cannot inspect existing corpus staging: {exc}")
    projections = project_dir / "projections"
    try:
        projection_entries = sorted(projections.iterdir(), key=lambda path: path.name)
    except FileNotFoundError:
        projection_entries = []
    except OSError as exc:
        blockers.append(f"existing corpus projections are unreadable: {exc}")
        projection_entries = []
    for projection in projection_entries:
        if _owned_transition_temp_name(projection.name):
            continue
        if not re.fullmatch(r"[0-9a-f]{16}\.json", projection.name):
            blockers.append(f"foreign corpus projection artifact: {projection.name}")
            continue
        try:
            _read_valid_corpus_record(
                projection,
                lambda record: corpus_projection_record_is_valid(record, project_key=project_key),
                "corpus projection record",
            )
        except ValueError as exc:
            blockers.append(f"existing corpus projection is malformed: {exc}")
    try:
        migration_entries = sorted(migrations.iterdir(), key=lambda path: path.name)
    except FileNotFoundError:
        migration_entries = []
    except OSError as exc:
        blockers.append(f"existing corpus migrations are unreadable: {exc}")
        migration_entries = []
    for migration in migration_entries:
        if _owned_transition_temp_name(migration.name):
            continue
        if not re.fullmatch(r"[0-9a-f]{16}\.json", migration.name):
            blockers.append(f"foreign corpus migration audit artifact: {migration.name}")
            continue
        try:
            record = _read_valid_corpus_record(
                migration,
                lambda value: corpus_legacy_migration_audit_is_valid(value, project_key=project_key),
                "legacy migration audit record",
            )
            if record is None:
                continue
            expected_id = _observed_root_id(Path(record["observed_root"]))
            if expected_id != migration.stem:
                blockers.append(f"existing corpus migration audit is malformed: {migration.name}")
        except ValueError as exc:
            blockers.append(f"existing corpus migration audit is malformed: {exc}")
    return tuple(blockers)


def _known_independent_clone_roots(
    neutral_root: Path, project_key: str, importing_root: Path, worktrees: tuple[Path, ...]
) -> tuple[str, ...]:
    """Published observed roots outside this checkout's strict worktree set.

    These are identity evidence only.  Import never locks, projects, or claims
    synchronization for an independent clone.
    """
    linked = set(worktrees)
    try:
        records = iter_project_records(neutral_root)
        record = next((record for key, record in records if key == project_key), None)
    except IdentityResolutionError:
        return ()
    if record is None:
        return ()
    roots: list[str] = []
    for value in record["observed_roots"]:
        try:
            candidate = Path(value).resolve()
        except OSError:
            continue
        if candidate != importing_root and candidate not in linked:
            roots.append(str(candidate))
    return tuple(sorted(set(roots)))


def _plan_legacy_project_corpus_import(
    project_root: Path | str, *, legacy_migration_roster: Path | str | None
) -> CorpusTransitionPlan:
    """Build a no-write import plan for one existing repository corpus.

    This intentionally does not acquire locks, publish identity, or create
    parent directories.  The future transition applies the same selection
    under its exclusive maintenance session and rejects every drift.
    """
    root = _validated_project_root(project_root)
    identity = project_identity(root)
    blockers: list[str] = []
    notes: list[str] = []
    neutral = _neutral_root()
    if neutral is None:
        raise ValueError("neutral corpus root is unavailable")
    try:
        project_key = resolve_or_derive_key(neutral, root, identity=identity)
    except IdentityResolutionError as exc:
        project_key = identity.key
        blockers.append(f"project identity is ambiguous: {exc}")
    if project_key != identity.key:
        notes.append(f"identity key elevated from {identity.key} to existing key {project_key}")
    if identity.canonical.startswith(("path:", "git-common-dir:")):
        notes.append("project has no network remote; identity is local to its checkout/common Git directory")
    roster_path: str | None = None
    roster_sha256: str | None = None
    row_sha256: str | None = None
    roster_row: dict | None = None
    retained_archives: tuple[CorpusTransitionFile, ...] = ()
    superseded_audit_sha256: str | None = None
    archives_require_exact = True
    if legacy_migration_roster is not None:
        try:
            roster, roster_sha256, roster_row, row_sha256 = _legacy_migration_row_for_project(
                legacy_migration_roster, root, identity, project_key
            )
            roster_path = str(roster)
            retained_archives = tuple(
                CorpusTransitionFile(item["name"], item["sha256"], item["size_bytes"])
                for item in roster_row["archives"]
            )
        except ValueError as exc:
            blockers.append(str(exc))
    try:
        existing_audit = read_corpus_legacy_migration_audit(project_key, root)
    except ValueError as exc:
        blockers.append(f"legacy migration audit is malformed: {exc}")
        existing_audit = None
    if existing_audit is not None:
        if roster_row is None:
            blockers.append(
                "legacy migration audit exists without a matching roster import; "
                "restore the reviewed roster or inspect/quarantine the orphan audit"
            )
        elif existing_audit["row_sha256"] == row_sha256:
            try:
                archives_require_exact = (
                    read_corpus_active_record(project_key) is None
                    and read_corpus_deactivated_record(project_key) is None
                )
            except ValueError:
                archives_require_exact = True
        else:
            authority_absent = False
            try:
                active = read_corpus_active_record(project_key)
                deactivated = read_corpus_deactivated_record(project_key)
            except ValueError:
                blockers.append("legacy migration audit conflicts with this roster row")
                active = deactivated = None
            else:
                authority_absent = active is None and deactivated is None
            raw = _raw_authority_digest(corpus_legacy_migration_audit_path(project_key, root))
            if (
                authority_absent
                and raw is not None
                and _legacy_migration_audit_supersession_is_safe(project_key, root)
            ):
                superseded_audit_sha256 = raw[0]
                notes.append("legacy migration audit will be superseded after lock-time digest verification")
            else:
                if "legacy migration audit conflicts with this roster row" not in blockers:
                    blockers.append("legacy migration audit conflicts with this roster row")

    (
        recognized_portables,
        derivation_error,
        inspection_error,
        ignored_catalog_names,
    ) = _recognized_legacy_portable_names(neutral, project_key, root)
    if inspection_error is not None:
        blockers.append(inspection_error)
    if derivation_error is not None:
        notes.append(
            "this checkout directory yields no portable slug; new rollback evidence "
            "cannot be named at this path"
        )
    candidates, candidate_blockers, candidate_notes = _legacy_import_candidates(
        root,
        recognized_portables,
        accepted_archives=retained_archives,
        archive_requires_exact_bytes=archives_require_exact,
        derivation_error=derivation_error,
        inspection_error=inspection_error,
        ignored_catalog_names=ignored_catalog_names,
        bare_remedy=(
            "the bare legacy name is ambiguous and is never rollback evidence; "
            "archive it outside the checkout before import"
        ),
        portable_remedy=(
            "for a moved system export, run machine state import or archive the old "
            "file outside the checkout"
        ),
    )
    blockers.extend(candidate_blockers)
    notes.extend(candidate_notes)
    primary = root / "LEARNINGS.md"
    topics = tuple(path for path in candidates if path.name != "LEARNINGS.md")
    primary_status = "absent"
    if not primary.exists() and topics:
        blockers.append("orphan topic-only corpus has no primary LEARNINGS.md")
    elif not primary.exists():
        blockers.append("valid system-owned primary LEARNINGS.md is absent")
    elif not _system_owned_legacy_corpus(root):
        primary_status = "foreign-or-unsafe"
        blockers.append(_PRIMARY_NOT_SYSTEM_OWNED_BLOCKER)
    elif not _legacy_primary_is_committed(root):
        primary_status = "uncommitted"
        blockers.append(_PRIMARY_UNCOMMITTED_BLOCKER)
    else:
        primary_status = "committed-system-owned"

    # A reviewed roster can waive only a missing historic marker. The ordinary
    # primary_status remains immutable drift evidence; all other gates stand.
    if roster_row is not None:
        marker_eligible, marker_reason = _legacy_roster_missing_marker_eligible(root)
        if marker_eligible:
            blockers = [
                blocker for blocker in blockers if blocker != _PRIMARY_NOT_SYSTEM_OWNED_BLOCKER
            ]
        elif _PRIMARY_NOT_SYSTEM_OWNED_BLOCKER in blockers:
            blockers.append(
                f"legacy migration roster cannot waive primary ownership: {marker_reason}"
            )

    if len(candidates) > EXTERNAL_CORPUS_MAX_CHILDREN:
        blockers.append(f"repository corpus exceeds the {EXTERNAL_CORPUS_MAX_CHILDREN}-child cap")

    source_files: list[CorpusTransitionFile] = []
    snapshots: list[CorpusSnapshot] = []
    location = CorpusLocation(root, project_key, root, corpus_lock_path(project_key), "external")
    for candidate in candidates[:EXTERNAL_CORPUS_MAX_CHILDREN]:
        try:
            snapshot = _read_external_corpus_snapshot(location, candidate)
        except CorpusResolutionError as exc:
            blockers.append(f"legacy corpus input {candidate.name} is unsafe: {exc}")
            continue
        source_files.append(
            CorpusTransitionFile(snapshot.name, _snapshot_digest(snapshot), snapshot.size_bytes)
        )
        snapshots.append(snapshot)
    source_files.sort(key=lambda source: (source.name != "LEARNINGS.md", source.name))
    snapshots.sort(key=lambda snapshot: (snapshot.name != "LEARNINGS.md", snapshot.name))
    lessons = tuple(
        lesson
        for snapshot in snapshots
        for lesson in _transition_lesson_lines(snapshot.text)
    )
    lesson_multiset = tuple(sorted(lessons))
    lesson_multiset_digest = hashlib.sha256(
        json.dumps(lesson_multiset, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    target_digest = _semantic_snapshot_digest(tuple(snapshots))
    if roster_row is not None:
        row_sources = {
            item["name"]: (item["sha256"], item["size_bytes"])
            for item in roster_row["sources"]
        }
        observed_sources = {
            item.name: (item.sha256, item.size_bytes) for item in source_files
        }
        if row_sources != observed_sources:
            blockers.append("legacy migration roster source files changed")
        if roster_row["target_digest"] != target_digest:
            blockers.append("legacy migration roster target digest changed")
    # A digest names content/staging, while a revision is a unique authority
    # target.  Under-lock recomputation carries this selected id rather than
    # deriving a revision from mutable source bytes.
    target_revision = f"rev-{uuid.uuid4().hex}"

    try:
        worktrees = tuple(sorted({path.resolve() for path in _worktree_roots(root, strict=True)}, key=str))
    except IdentityResolutionError as exc:
        worktrees = ()
        blockers.append(f"strict linked-worktree enumeration failed: {exc}")
    # Preserve root -> legacy-lock pairing for the report. Acquisition order
    # is independently sorted from this report tuple.
    structural_locks = tuple(str(structural_lock_path(worktree)) for worktree in worktrees)
    independent_clones = _known_independent_clone_roots(neutral, project_key, root, worktrees)

    deployment = cutover_deployment_status()
    deployment_revision = None
    record = deployment.get("record")
    if isinstance(record, dict) and isinstance(record.get("compatibility_revision"), int):
        deployment_revision = record["compatibility_revision"]
    if deployment["status"] != "current":
        blockers.append(
            f"cutover deployment is {deployment['status']}: {deployment['reason']}"
        )
    blockers.extend(_transition_authority_blockers(project_key, root))
    authority_recovery = _legacy_migration_authority_recovery_evidence(
        project_key, root, tuple(source_files), target_digest
    ) or superseded_audit_sha256 is not None
    certification_blockers = (
        "legacy migration roster", "legacy migration audit", "retained migration archive",
    )
    roster_accepted = (
        roster_row is not None
        and not any(blocker.startswith(certification_blockers) for blocker in blockers)
    )
    projection_id = observed_path_id(root)
    return CorpusTransitionPlan(
        project_root=str(root),
        canonical_identity=identity.canonical,
        identity_key=identity.key,
        project_key=project_key,
        primary_status=primary_status,
        source_files=tuple(source_files),
        target_digest=target_digest,
        target_revision=target_revision,
        lesson_multiset_digest=lesson_multiset_digest,
        lesson_count=len(lesson_multiset),
        worktree_roots=tuple(str(worktree) for worktree in worktrees),
        structural_lock_paths=structural_locks,
        independent_clone_roots=independent_clones,
        identity_lock_path=str(corpus_lock_path(project_key)),
        projection_path=str(corpus_projection_path(project_key, root)),
        projection_id=projection_id,
        deployment_status=deployment["status"],
        deployment_revision=deployment_revision,
        blockers=tuple(sorted(set(blockers))),
        notes=tuple(sorted(set(notes))),
        legacy_migration_roster_path=roster_path,
        legacy_migration_roster_sha256=roster_sha256,
        legacy_migration_row_sha256=row_sha256,
        retained_archives=retained_archives,
        legacy_migration_superseded_audit_sha256=superseded_audit_sha256,
        legacy_migration_archives_require_exact=archives_require_exact,
        legacy_migration_authority_recovery=authority_recovery,
        legacy_migration_roster_accepted=roster_accepted,
    )


def _reimport_source_snapshots(
    root: Path, project_key: str
) -> tuple[tuple[CorpusSnapshot, ...], tuple[str, ...]]:
    """Read exactly the external projection allowlist from one checkout."""
    location = CorpusLocation(root, project_key, root, corpus_lock_path(project_key), "external")
    try:
        snapshots = tuple(
            _read_external_corpus_snapshot(location, path)
            for path in select_external_projection_files(root)
        )
    except (CorpusResolutionError, OSError) as exc:
        return (), (f"repository corpus source is unsafe: {exc}",)
    if not any(snapshot.name == "LEARNINGS.md" for snapshot in snapshots):
        return (), ("repository corpus source is missing LEARNINGS.md",)
    return tuple(sorted(snapshots, key=lambda item: (item.name != "LEARNINGS.md", item.name))), ()


def _deterministic_reimport_revision(
    *, project_key: str, active_revision: str, source_files: dict[str, str],
    departing_files: dict[str, str], role: str,
) -> str:
    """Name one re-import artifact from the exact authorization evidence.

    A retry derives the same names without scanning historical revisions.  An
    extant directory is adopted later only when this exact name and map match.
    """
    payload = {
        "role": role, "project_key": project_key, "active_revision": active_revision,
        "source_files": sorted(source_files.items()), "departing_files": sorted(departing_files.items()),
    }
    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"rev-{digest[:32]}"


def plan_project_corpus_reimport(
    project_root: Path | str,
    *,
    replace_external: bool = False,
    identity_lock_held: bool = False,
    identity_override: ProjectIdentity | None = None,
) -> CorpusReimportPlan:
    """Plan a post-cutover checkout-to-new-revision import without writing."""
    root = _validated_project_root(project_root)
    identity = identity_override or project_identity(root)
    snapshot = inspect_corpus_synchronization(root, identity_lock_held=identity_lock_held)
    if snapshot.project_key is None or snapshot.active_revision is None:
        raise CorpusResolutionError("external corpus authority is absent")
    project_key = snapshot.project_key
    blockers = list(snapshot.blockers)
    notes = list(snapshot.notes)
    source_snapshots, source_blockers = _reimport_source_snapshots(root, project_key)
    blockers.extend(source_blockers)
    source_files = tuple(
        CorpusTransitionFile(item.name, _snapshot_digest(item), item.size_bytes)
        for item in source_snapshots
    )
    repository_files = dict(snapshot.repository_files)
    corpus_files = dict(snapshot.corpus_files)
    external_loss = tuple(sorted(
        set(snapshot.external_added) | set(snapshot.external_removed) | set(snapshot.external_changed)
    ))
    if source_snapshots:
        target_digest = _semantic_snapshot_digest(source_snapshots)
        lessons = tuple(sorted(
            lesson for item in source_snapshots for lesson in _transition_lesson_lines(item.text)
        ))
        lesson_multiset_digest = hashlib.sha256(
            json.dumps(lessons, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
    else:
        target_digest = ""
        lessons = ()
        lesson_multiset_digest = hashlib.sha256(b"[]").hexdigest()
    target_revision = _deterministic_reimport_revision(
        project_key=project_key, active_revision=snapshot.active_revision,
        source_files=repository_files, departing_files=corpus_files,
        role="target",
    )
    frozen_revision = _deterministic_reimport_revision(
        project_key=project_key, active_revision=snapshot.active_revision,
        source_files=repository_files, departing_files=corpus_files,
        role="frozen",
    )
    try:
        worktrees = tuple(sorted({path.resolve() for path in _worktree_roots(root, strict=True)}, key=str))
    except IdentityResolutionError as exc:
        worktrees = ()
        blockers.append(f"strict linked-worktree enumeration failed: {exc}")
    deployment = cutover_deployment_status()
    deployment_record = deployment.get("record")
    deployment_revision = (
        deployment_record.get("compatibility_revision")
        if isinstance(deployment_record, dict)
        and isinstance(deployment_record.get("compatibility_revision"), int)
        else None
    )
    if deployment["status"] != "current":
        blockers.append(f"cutover deployment is {deployment['status']}: {deployment['reason']}")
    safe_pending_repair = (
        snapshot.state == "pending-stale"
        and repository_files == dict(snapshot.projection_repository_files)
        and corpus_files == dict(snapshot.projection_corpus_files)
    )
    recoverable_pending = (
        snapshot.state == "pending-stale"
        and snapshot.projection_revision == target_revision
        and _transition_maps_from_directory(corpus_revision_dir(project_key, target_revision))
        == (repository_files, target_digest)
        and _transition_maps_from_directory(corpus_revision_dir(project_key, frozen_revision))
        is not None
        and _transition_maps_from_directory(corpus_revision_dir(project_key, frozen_revision))[0]
        == corpus_files
    )
    stale_recovery = _stale_projection_maps_are_complete(snapshot)
    if safe_pending_repair:
        state = "pending-repair"
    elif stale_recovery and replace_external:
        repository_changed = repository_files != dict(snapshot.projection_repository_files)
        external_changed = corpus_files != dict(snapshot.projection_corpus_files)
        state = (
            "both" if repository_changed and external_changed else
            "repository-only" if repository_changed else
            "external-only" if external_changed else "clean"
        )
        notes.append("stale projection requires the explicit external replacement requested")
    else:
        state = "pending-reimport" if recoverable_pending else snapshot.state
    if state in {"unprojected", "pending-stale", "busy", "sync-recovery-pending", "malformed"}:
        if state == "sync-recovery-pending":
            transaction = _read_sync_transaction(project_key, root)
            if transaction is not None:
                blockers.append(
                    f"pending {transaction['operation']} synchronization must recover or be superseded first"
                )
            else:
                blockers.append("pending synchronization must recover before import")
        else:
            blockers.append(f"import requires a usable checkout projection, found {state}")
    elif state in {"external-only", "both"} and not replace_external:
        blockers.append(f"import refuses {state} drift without --replace-external")
    elif replace_external and state not in {"external-only", "both"}:
        blockers.append("--replace-external is only valid for external-only or both drift")
    return CorpusReimportPlan(
        project_root=str(root), canonical_identity=identity.canonical, identity_key=identity.key,
        project_key=project_key, active_revision=snapshot.active_revision,
        previous_revision=snapshot.previous_revision,
        frozen_revision=frozen_revision,
        state=state, source_files=source_files,
        repository_files=tuple(sorted(repository_files.items())),
        corpus_files=tuple(sorted(corpus_files.items())),
        projection_repository_files=snapshot.projection_repository_files,
        projection_corpus_files=snapshot.projection_corpus_files,
        projection_revision=snapshot.projection_revision, projection_sha256=snapshot.projection_sha256,
        target_digest=target_digest, target_revision=target_revision,
        lesson_multiset_digest=lesson_multiset_digest, lesson_count=len(lessons),
        worktree_roots=tuple(str(item) for item in worktrees),
        structural_lock_paths=tuple(str(structural_lock_path(item)) for item in worktrees),
        independent_clone_roots=_known_independent_clone_roots(
            _neutral_root() or Path("/dev/null"), project_key, root, worktrees
        ),
        identity_lock_path=str(corpus_lock_path(project_key)),
        projection_path=str(corpus_projection_path(project_key, root)), projection_id=observed_path_id(root),
        deployment_status=deployment["status"], deployment_revision=deployment_revision,
        replace_external=replace_external, external_loss=external_loss,
        pending_projection_repair=safe_pending_repair,
        blockers=tuple(sorted(set(blockers))),
        notes=tuple(sorted(set(notes))),
    )


def plan_project_corpus_import(
    project_root: Path | str, *, replace_external: bool = False,
    legacy_migration_roster: Path | str | None = None,
) -> CorpusTransitionPlan | CorpusReimportPlan:
    """Plan legacy cutover or the explicit post-cutover re-import route."""
    root = _validated_project_root(project_root)
    try:
        location = resolve_project_corpus_strict(root)
    except CorpusResolutionError as exc:
        if "active external corpus is malformed or dangling" not in str(exc):
            raise
        # A damaged active record is still a legacy import-plan blocker, not a
        # reason to bypass the historic report-only inspection surface.
        return _plan_legacy_project_corpus_import(root, legacy_migration_roster=legacy_migration_roster)
    if location is not None and location.mode == "external":
        if legacy_migration_roster is not None:
            try:
                audit = read_corpus_legacy_migration_audit(location.project_key, root)
            except ValueError:
                audit = None
            if audit is not None:
                # The roster cannot authorize a re-import. It can only resume
                # a first cutover already evidenced by this checkout's audit.
                return _plan_legacy_project_corpus_import(
                    root, legacy_migration_roster=legacy_migration_roster
                )
        reimport = plan_project_corpus_reimport(root, replace_external=replace_external)
        if legacy_migration_roster is not None:
            return replace(
                reimport,
                blockers=tuple(sorted(set(reimport.blockers + (
                    "--legacy-migration-roster is only valid for a legacy import",
                )))),
            )
        return reimport
    if replace_external:
        legacy = _plan_legacy_project_corpus_import(root, legacy_migration_roster=legacy_migration_roster)
        return replace(
            legacy,
            blockers=tuple(sorted(set(legacy.blockers + (
                "--replace-external requires existing external authority",
            )))),
        )
    return _plan_legacy_project_corpus_import(root, legacy_migration_roster=legacy_migration_roster)


def _rollback_repository_map(
    root: Path, neutral: Path, project_key: str, *, retained_archives: tuple[CorpusTransitionFile, ...]
) -> tuple[dict[str, str] | None, tuple[str, ...], tuple[str, ...]]:
    """Read the checkout's current corpus map without claiming ownership."""
    (
        recognized_portable_names,
        derivation_error,
        inspection_error,
        ignored_catalog_names,
    ) = _recognized_legacy_portable_names(neutral, project_key, root)
    candidates, blockers, candidate_notes = _legacy_import_candidates(
        root,
        recognized_portable_names,
        accepted_archives=retained_archives,
        archive_requires_exact_bytes=False,
        derivation_error=derivation_error,
        inspection_error=inspection_error,
        ignored_catalog_names=ignored_catalog_names,
        bare_remedy=(
            "the bare legacy name is ambiguous and is never rollback evidence; "
            "archive it outside the checkout before rollback; rollback never imports "
            "or removes portable files"
        ),
        portable_remedy=(
            "archive the unrecognized file outside the checkout before rollback; "
            "rollback never imports or removes portable files"
        ),
    )
    if inspection_error is not None:
        blockers = (inspection_error, *blockers)
    notes = tuple(candidate_notes)
    if derivation_error is not None:
        notes += (
            "this checkout directory yields no portable slug; new rollback evidence "
            "cannot be named at this path",
        )
    if blockers:
        return None, blockers, notes
    location = CorpusLocation(root, "", root, Path("/dev/null"), "external")
    try:
        snapshots = tuple(_read_external_corpus_snapshot(location, path) for path in candidates)
    except CorpusResolutionError as exc:
        return None, (f"repository corpus input is unsafe: {exc}",), notes
    return (
        dict(sorted((snapshot.name, _snapshot_digest(snapshot)) for snapshot in snapshots)),
        (),
        notes,
    )


def _raw_authority_digest(path: Path) -> tuple[str, int] | None:
    raw = _read_file_capped(path, _CORPUS_RECORD_MAX_BYTES)
    if raw is None:
        return None
    return hashlib.sha256(raw).hexdigest(), len(raw)


def plan_project_corpus_rollback(project_root: Path | str) -> CorpusRollbackPlan:
    """Build a no-write rollback plan from current checkout and authority truth."""
    root = _validated_project_root(project_root)
    identity = project_identity(root)
    neutral = _neutral_root()
    if neutral is None:
        raise ValueError("neutral corpus root is unavailable")
    blockers: list[str] = []
    # An active record that claims this checkout wins over the catalog, as in
    # retirement: after `learn corpus relink` the catalog names the old identity.
    authority_key = inspect_project_corpus_status(project_root=root).get("project_key")
    try:
        key = authority_key or resolve_or_derive_key(neutral, root, identity=identity)
    except IdentityResolutionError as exc:
        key = identity.key
        blockers.append(f"project identity is ambiguous: {exc}")
    deployment = cutover_deployment_status()
    if deployment["status"] != "current":
        blockers.append(
            f"cutover deployment is {deployment['status']}: {deployment['reason']}"
        )
    try:
        worktrees = tuple(sorted({path.resolve() for path in _worktree_roots(root, strict=True)}, key=str))
    except IdentityResolutionError as exc:
        worktrees = ()
        blockers.append(f"strict linked-worktree enumeration failed: {exc}")
    structural = tuple(str(structural_lock_path(path)) for path in worktrees)
    active = None
    try:
        active = read_corpus_active_record(key)
    except ValueError as exc:
        blockers.append(f"active authority is malformed: {exc}")
    notes: list[str] = []
    if active is None and not blockers:
        try:
            deactivated = read_corpus_deactivated_record(key)
        except ValueError as exc:
            blockers.append(f"deactivated authority is malformed: {exc}")
        else:
            if deactivated is not None and _valid_active_revision(key, deactivated) is not None:
                notes.append("project authority is already deactivated; legacy remains authoritative")
            else:
                blockers.append("active authority is absent; project is already legacy or requires status inspection")
    active_revision = active.get("active_revision") if active else None
    previous = active.get("previous_revision") if active else None
    target_kind = "external" if previous is not None else ("legacy" if active is not None else None)
    source_authority_sha256 = None
    if active is not None:
        raw = _raw_authority_digest(corpus_active_path(key))
        if raw is None:
            blockers.append("active authority bytes are unreadable")
        else:
            source_authority_sha256 = raw[0]
    external_files: dict[str, str] = {}
    external_target_digest: str | None = None
    external_readable = False
    if active is not None:
        revision = _valid_active_revision(key, active)
        if revision is None:
            blockers.append("active authority is dangling: active revision is missing or malformed")
        else:
            mapped = _transition_maps_from_directory(revision)
            if mapped is None:
                blockers.append("active authority is dangling: active revision is malformed")
            else:
                external_files, external_target_digest = mapped
                external_readable = True
        if previous is not None:
            previous_path = corpus_revision_dir(key, previous)
            if _transition_maps_from_directory(previous_path) is None:
                blockers.append("previous rollback revision is missing or malformed")
    repository_files: dict[str, str] = {}
    projection = None
    retained_archives: tuple[CorpusTransitionFile, ...] = ()
    if active is not None and previous is None:
        try:
            audit = read_corpus_legacy_migration_audit(key, root)
        except ValueError as exc:
            blockers.append(f"legacy migration audit is malformed: {exc}")
            audit = None
        try:
            projection = read_corpus_projection_record(key, root)
        except ValueError as exc:
            blockers.append(f"cutover projection is malformed: {exc}")
        if audit is not None:
            audit_sources = {item["name"]: item["sha256"] for item in audit["source_files"]}
            audit_matches_live_cutover = (
                projection is not None
                and projection.get("revision") == active_revision
                and projection.get("repository_files") == audit_sources
                and projection.get("corpus_files") == audit_sources
            )
            if audit_matches_live_cutover:
                retained_archives = tuple(
                    CorpusTransitionFile(item["name"], item["sha256"], item["size_bytes"])
                    for item in audit["archives"]
                )
            elif audit["archives"]:
                blockers.append("legacy migration audit does not match the live active projection")
            else:
                notes.append(
                    "legacy migration audit does not match the live active projection; no archive exemption is needed"
                )
        repository_map, repository_blockers, repository_notes = _rollback_repository_map(
            root, neutral, key, retained_archives=retained_archives
        )
        notes.extend(repository_notes)
        if repository_map is None:
            blockers.extend(
                repository_blockers
                or ("repository corpus map is missing without a reported reason",)
            )
        else:
            repository_files = repository_map
        if projection is None:
            blockers.append("cutover projection is missing; inspect `learn corpus status --cwd`")
        else:
            if projection["revision"] != active_revision:
                blockers.append("cutover projection is stale; inspect `learn corpus status --cwd`")
            if repository_map is None and external_readable:
                external_changed = external_files != projection["corpus_files"]
                if external_changed:
                    blockers.append(
                        "external corpus drift: external corpus differs from the cutover "
                        "projection while repository input is unavailable; publish or restore "
                        "the external corpus before rollback"
                    )
            elif repository_map is not None:
                repository_changed = repository_files != projection["repository_files"]
                if not external_readable:
                    if repository_changed:
                        blockers.append(
                            "repository corpus drift: checkout differs from the cutover "
                            "projection while external authority is unreadable; resolve the "
                            "dangling authority before attributing sides"
                        )
                else:
                    external_changed = external_files != projection["corpus_files"]
                    if repository_changed and external_changed:
                        blockers.append(
                            "both-side drift: repository and external corpus differ from the cutover projection"
                        )
                    elif repository_changed:
                        blockers.append(
                            "repository-only drift: restore the checkout to its cutover projection before rollback"
                        )
                    elif external_changed:
                        blockers.append(
                            "external-only drift: unpublished external lessons require explicit publish "
                            "in Part 7C before rollback"
                        )
    freeze_revision = f"rev-{uuid.uuid4().hex}" if active is not None and previous is not None else None
    transaction_path = corpus_rollback_transaction_path(key)
    try:
        transaction = _read_rollback_transaction(key)
    except ValueError as exc:
        blockers.append(f"corpus rollback transaction is malformed: {exc}")
        transaction = None
    if transaction is not None:
        completed_external = (
            active is not None
            and transaction["target_kind"] == "external"
            and active_revision == transaction["target_revision"]
            and previous == transaction["freeze_revision"]
        )
        matches = (
            transaction["source_revision"] == active_revision
            and transaction["target_kind"] == target_kind
            and transaction["target_revision"] == previous
            and transaction["source_active_sha256"] == source_authority_sha256
        )
        if completed_external and transaction["phase"] == "complete":
            notes.append("external rollback transaction is already complete")
        elif completed_external:
            notes.append("recovering completed external rollback transaction")
        elif active is not None and transaction["phase"] == "complete":
            blockers.append(
                "complete rollback transaction conflicts with current authority; later-slice recovery is required"
            )
        elif active is not None and not matches:
            blockers.append(
                "corpus rollback transaction conflicts with current authority; inspect and recover it first"
            )
        elif active is not None:
            freeze_revision = transaction["freeze_revision"]
            notes.append("resuming prepared corpus rollback transaction")
        elif transaction["target_kind"] == "legacy":
            raw = _raw_authority_digest(corpus_deactivated_path(key))
            if raw is None or raw[0] != transaction["source_active_sha256"]:
                blockers.append("rollback transaction deactivation evidence is missing or changed")
            elif transaction["phase"] == "complete":
                notes.append("legacy rollback transaction is already complete")
            else:
                notes.append("recovering completed legacy deactivation transaction")
        else:
            blockers.append("rollback transaction target is absent or conflicts with current authority")
    return CorpusRollbackPlan(
        project_root=str(root), canonical_identity=identity.canonical, identity_key=identity.key,
        project_key=key, active_revision=active_revision, previous_revision=previous,
        freeze_revision=freeze_revision,
        repository_files=tuple(sorted(repository_files.items())), corpus_files=tuple(sorted(external_files.items())),
        projection_path=str(corpus_projection_path(key, root)),
        projection_revision=projection.get("revision") if projection else None,
        projection_repository_files=tuple(sorted(projection.get("repository_files", {}).items())) if projection else (),
        projection_corpus_files=tuple(sorted(projection.get("corpus_files", {}).items())) if projection else (),
        worktree_roots=tuple(str(path) for path in worktrees), structural_lock_paths=structural,
        identity_lock_path=str(corpus_lock_path(key)), blockers=tuple(sorted(set(blockers))),
        notes=tuple(sorted(set(notes))), transaction_path=str(transaction_path), target_kind=target_kind,
        source_authority_sha256=source_authority_sha256,
        retained_archives=retained_archives,
    )


_ROLLBACK_IMMUTABLE_PLAN_FIELDS = (
    "project_root", "canonical_identity", "identity_key", "project_key", "active_revision",
    "previous_revision", "repository_files", "corpus_files", "projection_path", "projection_revision",
    "projection_repository_files", "projection_corpus_files", "worktree_roots", "structural_lock_paths",
    "identity_lock_path", "transaction_path", "target_kind", "source_authority_sha256",
    "retained_archives",
)


def _rollback_plan_drift(preview: CorpusRollbackPlan, current: CorpusRollbackPlan) -> tuple[str, ...]:
    return tuple(name for name in _ROLLBACK_IMMUTABLE_PLAN_FIELDS if getattr(preview, name) != getattr(current, name))


# Offline transitions own authority swaps and complete revision publication;
# CorpusWriteSession remains exclusively responsible for steady-state in-place
# mutation of the current active revision.
class _ProjectCorpusTransitionBlocked(RuntimeError):
    def __init__(self, *blockers: str):
        super().__init__(blockers[0] if blockers else "project corpus transition blocked")
        self.blockers = tuple(blockers)


class ProjectCorpusTransitionSession:
    """One nonblocking offline maintenance window for an import/rollback.

    Lock order is fixed: activity, deploy, live-worker census, project
    identity, then every linked-worktree legacy structural lock in lexical
    path order.  The reverse release is intentional and this context never
    enters CorpusWriteSession.
    """

    def __init__(self, plan: CorpusTransitionPlan | CorpusReimportPlan | CorpusRollbackPlan):
        self.plan = plan
        self._activity: _ActivityLock | None = None
        self._deployment: _ActivityLock | None = None
        self._identity: _ActivityLock | None = None
        self._legacy: list[_ActivityLock] = []

    def __enter__(self) -> ProjectCorpusTransitionSession:
        self._activity = try_activity_exclusive()
        if self._activity is None:
            raise _ProjectCorpusTransitionBlocked(
                "offline maintenance window is busy; stop learnings workers and retry"
            )
        self._deployment = _acquire_deployment_lock(exclusive=False, nonblocking=True)
        if self._deployment is None:
            self.close()
            raise _ProjectCorpusTransitionBlocked(
                "machine deployment is busy or unavailable; retry after deploy completes"
            )
        try:
            workers = scan_legacy_workers()
        except RuntimeError as exc:
            self.close()
            raise _ProjectCorpusTransitionBlocked(f"worker census unavailable: {exc}") from None
        if workers:
            self.close()
            details = ", ".join(f"pid {worker.pid} ({worker.fingerprint})" for worker in workers)
            raise _ProjectCorpusTransitionBlocked(f"live legacy worker: {details}")
        try:
            self._identity = _acquire_corpus_identity_lock(
                Path(self.plan.identity_lock_path), nonblocking=True
            )
        except OSError as exc:
            self.close()
            raise _ProjectCorpusTransitionBlocked(f"cannot acquire corpus identity lock: {exc}") from None
        if self._identity is None:
            self.close()
            raise _ProjectCorpusTransitionBlocked(
                "project corpus identity is busy; retry in the maintenance window"
            )
        try:
            pending = _pending_sync_transactions(self.plan.project_key)
        except ValueError as exc:
            self.close()
            raise _ProjectCorpusTransitionBlocked(
                f"synchronization recovery evidence is malformed: {exc}"
            ) from None
        if pending:
            self.close()
            raise _ProjectCorpusTransitionBlocked(
                f"pending {pending[0]['operation']} synchronization must recover or be superseded first"
            )
        for path in sorted({Path(value) for value in self.plan.structural_lock_paths}, key=str):
            try:
                lock = _acquire_legacy_structural_lock(path, nonblocking=True)
            except OSError as exc:
                self.close()
                raise _ProjectCorpusTransitionBlocked(f"cannot acquire legacy structural lock {path}: {exc}") from None
            if lock is None:
                self.close()
                raise _ProjectCorpusTransitionBlocked(
                    f"legacy structural lock is busy: {path}; stop workers and retry"
                )
            self._legacy.append(lock)
        return self

    def close(self) -> None:
        for lock in reversed(self._legacy):
            lock.close()
        self._legacy.clear()
        if self._identity is not None:
            self._identity.close()
            self._identity = None
        if self._deployment is not None:
            self._deployment.close()
            self._deployment = None
        if self._activity is not None:
            self._activity.close()
            self._activity = None

    def __exit__(self, *_: object) -> None:
        self.close()


def _acquire_legacy_structural_lock(path: Path, *, nonblocking: bool) -> _ActivityLock | None:
    """Acquire the historic structural lock without changing its 0644 mode."""
    fd = -1
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(errno.EINVAL, "legacy structural lock must be regular")
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
    except BlockingIOError:
        if fd != -1:
            os.close(fd)
        return None
    except OSError:
        if fd != -1:
            os.close(fd)
        raise
    return _ActivityLock(fd)


_TRANSITION_IMMUTABLE_PLAN_FIELDS = (
    "project_root", "canonical_identity", "identity_key", "project_key", "primary_status",
    "source_files", "target_digest", "lesson_multiset_digest", "lesson_count",
    "worktree_roots", "structural_lock_paths", "projection_path", "projection_id",
    "deployment_status", "deployment_revision", "identity_lock_path",
    "legacy_migration_roster_path", "legacy_migration_row_sha256", "retained_archives",
    "legacy_migration_superseded_audit_sha256", "legacy_migration_archives_require_exact",
    "legacy_migration_authority_recovery", "legacy_migration_roster_accepted",
)


def _transition_plan_drift(preview: CorpusTransitionPlan, current: CorpusTransitionPlan) -> tuple[str, ...]:
    return tuple(
        field_name
        for field_name in _TRANSITION_IMMUTABLE_PLAN_FIELDS
        if getattr(preview, field_name) != getattr(current, field_name)
    )


def _validate_legacy_migration_plan_roster(plan: CorpusTransitionPlan, root: Path) -> None:
    """Reprove the exception row after locks, before any authority mutation."""
    if plan.legacy_migration_roster_path is None:
        return
    identity = project_identity(root)
    try:
        _path, _roster_digest, row, row_digest = _legacy_migration_row_for_project(
            plan.legacy_migration_roster_path, root, identity, plan.project_key
        )
    except ValueError as exc:
        raise _ProjectCorpusTransitionBlocked(str(exc)) from None
    if (
        row_digest != plan.legacy_migration_row_sha256
        or row["target_digest"] != plan.target_digest
        or tuple(
            CorpusTransitionFile(item["name"], item["sha256"], item["size_bytes"])
            for item in row["archives"]
        ) != plan.retained_archives
    ):
        raise _ProjectCorpusTransitionBlocked("legacy migration roster changed while acquiring locks; rerun apply")


_REIMPORT_IMMUTABLE_PLAN_FIELDS = (
    "project_root", "canonical_identity", "identity_key", "project_key", "active_revision",
    "previous_revision", "state", "source_files", "repository_files", "corpus_files",
    "projection_repository_files", "projection_corpus_files", "projection_revision",
    "projection_sha256", "target_digest", "lesson_multiset_digest", "lesson_count",
    "target_revision", "frozen_revision",
    "worktree_roots", "structural_lock_paths", "identity_lock_path", "projection_path",
    "projection_id", "deployment_status", "deployment_revision", "replace_external",
    "external_loss", "independent_clone_roots",
    "pending_projection_repair",
)


def _reimport_plan_drift(
    preview: CorpusReimportPlan, current: CorpusReimportPlan
) -> tuple[str, ...]:
    return tuple(
        field_name
        for field_name in _REIMPORT_IMMUTABLE_PLAN_FIELDS
        if getattr(preview, field_name) != getattr(current, field_name)
    )


def _ensure_transition_directory(path: Path, label: str) -> None:
    """Create one private directory and durably link it into a safe parent."""
    try:
        parent_metadata = path.parent.lstat()
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(
            f"transition directory parent is unavailable: {path.parent}"
        ) from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise _ProjectCorpusTransitionBlocked(
            f"transition directory parent is unsafe: {path.parent}"
        )
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        _crash_point(f"cutover-before-{label}-dir-create")
        path.mkdir(mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
        _crash_point(f"cutover-after-{label}-dir-create")
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(
            f"transition directory is unreadable: {path}"
        ) from exc
    else:
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise _ProjectCorpusTransitionBlocked(f"transition directory is unsafe: {path}")
    _crash_point(f"cutover-before-{label}-dir-self-fsync")
    _fsync_dir(path)
    _crash_point(f"cutover-after-{label}-dir-self-fsync")
    _crash_point(f"cutover-before-{label}-dir-parent-fsync")
    _fsync_dir(path.parent)
    _crash_point(f"cutover-after-{label}-dir-parent-fsync")


def _replace_transition_json(path: Path, record: dict, label: str) -> None:
    """Project-scoped authority replace with separately observable durability."""
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    _crash_point(f"cutover-before-{label}-write")
    _write_new_fsynced(temporary, _canonical_json_bytes(record))
    _crash_point(f"cutover-after-{label}-write")
    _crash_point(f"cutover-before-{label}-replace")
    os.replace(temporary, path)
    _crash_point(f"cutover-after-{label}-replace")
    _crash_point(f"cutover-before-{label}-parent-fsync")
    _fsync_dir(path.parent)
    _crash_point(f"cutover-after-{label}-parent-fsync")


def _transition_maps_from_directory(root: Path) -> tuple[dict[str, str], str] | None:
    """Return one complete, single-link corpus map or None for any defect."""
    if root.is_symlink() or not root.is_dir():
        return None
    try:
        entries = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError:
        return None
    if not entries or any(not is_valid_corpus_filename(path.name) for path in entries):
        return None
    location = CorpusLocation(root, "", root, Path("/dev/null"), "external")
    try:
        snapshots = tuple(_read_external_corpus_snapshot(location, path) for path in entries)
    except CorpusResolutionError:
        return None
    files = {snapshot.name: _snapshot_digest(snapshot) for snapshot in snapshots}
    return dict(sorted(files.items())), _semantic_snapshot_digest(snapshots)


def _legacy_migration_authority_recovery_evidence(
    project_key: str, root: Path, source_files: tuple[CorpusTransitionFile, ...], target_digest: str
) -> bool:
    """Positive current-checkout evidence permitting only interrupted cutover recovery."""
    source_map = {item.name: item.sha256 for item in source_files}
    if not source_map:
        return False
    revisions = corpus_project_dir(project_key) / "revisions"
    try:
        revision_metadata = revisions.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if stat.S_ISLNK(revision_metadata.st_mode) or not stat.S_ISDIR(revision_metadata.st_mode):
        return False
    try:
        if not any(revisions.iterdir()):
            return True
    except OSError:
        return False
    try:
        audit = read_corpus_legacy_migration_audit(project_key, root)
    except ValueError:
        return False
    audit_matches = False
    if audit is not None:
        audit_map = {item["name"]: item["sha256"] for item in audit["source_files"]}
        audit_matches = audit_map == source_map and audit["target_digest"] == target_digest
    staging = corpus_project_dir(project_key) / "staging" / target_digest
    if _transition_maps_from_directory(staging) == (source_map, target_digest):
        return True
    try:
        projection = read_corpus_projection_record(project_key, root)
    except ValueError:
        return False
    if projection is None:
        return audit_matches
    if projection["repository_files"] != source_map or projection["corpus_files"] != source_map:
        return False
    revision = corpus_revision_dir(project_key, projection["revision"])
    return _transition_maps_from_directory(revision) == (source_map, target_digest)


def _legacy_migration_audit_supersession_is_safe(project_key: str, root: Path) -> bool:
    """Refuse to supersede evidence for authority with external drift."""
    try:
        projection = read_corpus_projection_record(project_key, root)
    except ValueError:
        return False
    if projection is None:
        return True
    revision = corpus_revision_dir(project_key, projection["revision"])
    mapped = _transition_maps_from_directory(revision)
    return mapped is not None and mapped[0] == projection["corpus_files"]


def _transition_source_map(
    plan: CorpusTransitionPlan, root: Path, neutral: Path
) -> tuple[dict[str, str], str] | None:
    """Re-read the plan's exact legacy source bytes through fd validators."""
    expected = {item.name: item.sha256 for item in plan.source_files}
    (
        recognized_portables,
        derivation_error,
        inspection_error,
        ignored_catalog_names,
    ) = _recognized_legacy_portable_names(neutral, plan.project_key, root)
    candidates, blockers, _notes = _legacy_import_candidates(
        root,
        recognized_portables,
        accepted_archives=plan.retained_archives,
        archive_requires_exact_bytes=plan.legacy_migration_archives_require_exact,
        derivation_error=derivation_error,
        inspection_error=inspection_error,
        ignored_catalog_names=ignored_catalog_names,
        bare_remedy=(
            "the bare legacy name is ambiguous and is never rollback evidence; "
            "archive it outside the checkout before import"
        ),
        portable_remedy=(
            "for a moved system export, run machine state import or archive the old "
            "file outside the checkout"
        ),
    )
    if blockers or {path.name for path in candidates} != set(expected):
        return None
    location = CorpusLocation(root, plan.project_key, root, corpus_lock_path(plan.project_key), "external")
    try:
        snapshots = tuple(_read_external_corpus_snapshot(location, path) for path in candidates)
    except CorpusResolutionError:
        return None
    files = {snapshot.name: _snapshot_digest(snapshot) for snapshot in snapshots}
    if files != expected:
        return None
    return dict(sorted(files.items())), _semantic_snapshot_digest(snapshots)


def _reimport_source_map(
    plan: CorpusReimportPlan, root: Path
) -> tuple[dict[str, str], str] | None:
    """Re-read the planned projection files through the external allowlist."""
    snapshots, blockers = _reimport_source_snapshots(root, plan.project_key)
    if blockers:
        return None
    files = {item.name: _snapshot_digest(item) for item in snapshots}
    expected = {item.name: item.sha256 for item in plan.source_files}
    if files != expected:
        return None
    return dict(sorted(files.items())), _semantic_snapshot_digest(snapshots)


def _transition_recovery_blocker(plan: CorpusTransitionPlan, blocker: str) -> bool:
    """Authority/staging is rechecked under locks, never trusted from preview."""
    if blocker == _NO_AUTHORITY_BLOCKER:
        return plan.legacy_migration_authority_recovery
    return (
        blocker.startswith("existing corpus authority")
        or blocker.startswith("project already has active external authority")
        or blocker.startswith("existing corpus staging")
    )


def _owned_transition_temp_name(name: str) -> bool:
    return bool(
        re.fullmatch(
            r"(?:\.active\.json|\.rollback-transaction\.json|\.\.?epoch|\.[0-9a-f]{16}\.json)"
            r"\.tmp-\d+-[0-9a-f]{8}",
            name,
        )
    )


def _recover_transition_json_temps(project_dir: Path) -> tuple[str, ...]:
    """Quarantine only our exact interrupted record temp names under locks."""
    candidates: list[Path] = []
    if project_dir.exists() or project_dir.is_symlink():
        if project_dir.is_symlink() or not project_dir.is_dir():
            raise _ProjectCorpusTransitionBlocked(
                f"project corpus authority directory is unsafe: {project_dir}"
            )
        candidates.extend(project_dir.iterdir())
    projections = project_dir / "projections"
    if projections.is_dir() and not projections.is_symlink():
        candidates.extend(projections.iterdir())
    migrations = project_dir / "migrations"
    if migrations.is_dir() and not migrations.is_symlink():
        candidates.extend(migrations.iterdir())
    corpus_root = corpora_root()
    if corpus_root is not None and corpus_root.is_dir() and not corpus_root.is_symlink():
        candidates.extend(corpus_root.iterdir())
    notes: list[str] = []
    for path in candidates:
        if not _owned_transition_temp_name(path.name):
            continue
        if not _regular_single_link(path):
            raise _ProjectCorpusTransitionBlocked(f"owned transition temp is unsafe: {path}")
        if corpus_root is not None and path.parent == corpus_root:
            destination = _quarantine_corpus_root_transition_temp(corpus_root, path)
        else:
            destination = _quarantine_transition_staging(project_dir, path)
        notes.append(f"quarantined interrupted transition record at {destination}")
    return tuple(notes)


def _quarantine_transition_staging(project_dir: Path, path: Path) -> str:
    quarantine = project_dir / "quarantine"
    _ensure_transition_directory(quarantine, "quarantine")
    destination = quarantine / f"{path.name}-{uuid.uuid4().hex[:8]}"
    os.rename(path, destination)
    _fsync_dir(quarantine)
    _fsync_dir(path.parent)
    if path.parent != project_dir:
        _fsync_dir(project_dir)
    return str(destination)


def _quarantine_corpus_root_transition_temp(corpus_root: Path, path: Path) -> str:
    """Quarantine a corpus-root temp without fabricating a project directory."""
    quarantine = corpus_root / ".quarantine"
    _ensure_transition_directory(quarantine, "corpora-quarantine")
    destination = quarantine / f"{path.name}-{uuid.uuid4().hex[:8]}"
    os.rename(path, destination)
    _fsync_dir(quarantine)
    _fsync_dir(corpus_root)
    return str(destination)


def _stage_transition_corpus(
    plan: CorpusTransitionPlan, root: Path, source_map: dict[str, str]
) -> tuple[Path | None, tuple[str, ...], tuple[str, ...]]:
    """Create or exactly adopt digest staging; malformed peers are quarantined.

    The staged tree contains only corpus files, so it can be fd-validated with
    the same reader used by normal external authority.  It is never a hardlink
    to checkout bytes.
    """
    project_dir = corpus_project_dir(plan.project_key)
    staging_root = project_dir / "staging"
    corpus_root = corpora_root()
    if corpus_root is None:
        return None, ("neutral corpus root is unavailable",), ()
    _ensure_transition_directory(corpus_root, "corpora")
    _ensure_transition_directory(project_dir, "project")
    _ensure_transition_directory(staging_root, "staging")
    destination = staging_root / plan.target_digest
    notes: list[str] = []
    for candidate in sorted(project_dir.glob(".staging.tmp-*"), key=lambda path: path.name):
        try:
            moved = _quarantine_transition_staging(project_dir, candidate)
        except OSError as exc:
            return None, (f"cannot quarantine stale transition staging {candidate}: {exc}",), tuple(notes)
        notes.append(f"quarantined stale transition staging at {moved}")
    try:
        stage_entries = sorted(staging_root.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return None, (f"cannot inspect transition staging: {exc}",), tuple(notes)
    for candidate in stage_entries:
        if candidate == destination:
            continue
        try:
            moved = _quarantine_transition_staging(project_dir, candidate)
        except OSError as exc:
            return None, (f"cannot quarantine foreign transition staging {candidate}: {exc}",), tuple(notes)
        if plan.legacy_migration_superseded_audit_sha256 is not None:
            notes.append(f"quarantined superseded transition staging at {moved}")
            continue
        return None, (f"foreign transition staging was quarantined at {moved}; inspect it and retry",), tuple(notes)
    if destination.exists() or destination.is_symlink():
        validated = _transition_maps_from_directory(destination)
        if validated == (source_map, plan.target_digest):
            return destination, (), tuple(notes + [f"adopted exact digest staging {destination.name}"])
        try:
            moved = _quarantine_transition_staging(project_dir, destination)
        except OSError as exc:
            return None, (f"cannot quarantine malformed transition staging {destination}: {exc}",), tuple(notes)
        return None, (f"malformed transition staging was quarantined at {moved}; retry import",), tuple(notes)
    temporary = project_dir / f".staging.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        _crash_point("cutover-before-stage-create")
        temporary.mkdir(mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
        _crash_point("cutover-after-stage-create")
        for name in sorted(source_map):
            payload = _read_file_capped(root / name, EXTERNAL_CORPUS_FILE_MAX_BYTES)
            if payload is None or hashlib.sha256(payload).hexdigest() != source_map[name]:
                raise _ProjectCorpusTransitionBlocked("source changed while staging; rerun apply")
            _crash_point("cutover-before-stage-file")
            _write_new_fsynced(temporary / name, payload)
            _crash_point("cutover-after-stage-file")
        _crash_point("cutover-before-stage-fsync")
        _fsync_dir(temporary)
        _crash_point("cutover-after-stage-fsync")
        if _transition_maps_from_directory(temporary) != (source_map, plan.target_digest):
            raise _ProjectCorpusTransitionBlocked("staged corpus failed digest validation")
        _crash_point("cutover-before-stage-rename")
        os.rename(temporary, destination)
        _crash_point("cutover-after-stage-rename")
        _crash_point("cutover-before-stage-parent-fsync")
        _fsync_dir(staging_root)
        _crash_point("cutover-after-stage-parent-fsync")
    except _ProjectCorpusTransitionBlocked:
        raise
    except OSError as exc:
        return None, (f"cannot stage project corpus: {exc}",), tuple(notes)
    return destination, (), tuple(notes)


def _copy_transition_revision(
    plan: CorpusTransitionPlan, staging: Path, source_map: dict[str, str]
) -> tuple[str | None, tuple[str, ...], tuple[str, ...]]:
    """Copy verified staging into one unique revision, adopting an exact retry."""
    revisions = corpus_project_dir(plan.project_key) / "revisions"
    _ensure_transition_directory(revisions, "revisions")
    notes: list[str] = []
    exact: list[Path] = []
    try:
        candidates = sorted(revisions.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return None, (f"cannot inspect corpus revisions: {exc}",), ()
    for candidate in candidates:
        if re.fullmatch(r"\.rev-[0-9a-f]{16,64}\.tmp-\d+-[0-9a-f]{8}", candidate.name):
            try:
                moved = _quarantine_transition_staging(corpus_project_dir(plan.project_key), candidate)
            except OSError as exc:
                return None, (f"cannot quarantine incomplete revision copy {candidate}: {exc}",), tuple(notes)
            notes.append(f"quarantined incomplete revision copy at {moved}")
            continue
        if not _CORPUS_REVISION_RE.fullmatch(candidate.name):
            continue
        mapped = _transition_maps_from_directory(candidate)
        if isinstance(plan, CorpusReimportPlan) and candidate.name == plan.target_revision:
            if mapped == (source_map, plan.target_digest):
                return candidate.name, (), tuple(notes + [f"adopted exact staged revision {candidate.name}"])
            return None, ("deterministic target revision already exists with different bytes",), tuple(notes)
        if not isinstance(plan, CorpusReimportPlan) and mapped == (source_map, plan.target_digest):
            exact.append(candidate)
    if not isinstance(plan, CorpusReimportPlan):
        if len(exact) == 1:
            return exact[0].name, (), tuple(notes + [f"adopted exact staged revision {exact[0].name}"])
        if len(exact) > 1:
            return None, ("multiple exact staged revisions require operator inspection",), tuple(notes)
    destination = corpus_revision_dir(plan.project_key, plan.target_revision)
    if destination.exists() or destination.is_symlink():
        return None, (f"unique target revision already exists: {destination.name}",), tuple(notes)
    temporary = revisions / f".{plan.target_revision}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        _crash_point("cutover-before-revision-create")
        temporary.mkdir(mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
        _crash_point("cutover-after-revision-create")
        for name in sorted(source_map):
            payload = _read_file_capped(staging / name, EXTERNAL_CORPUS_FILE_MAX_BYTES)
            if payload is None or hashlib.sha256(payload).hexdigest() != source_map[name]:
                raise _ProjectCorpusTransitionBlocked("digest staging changed before revision copy")
            _crash_point("cutover-before-revision-file")
            _write_new_fsynced(temporary / name, payload)
            _crash_point("cutover-after-revision-file")
        _crash_point("cutover-before-revision-fsync")
        _fsync_dir(temporary)
        _crash_point("cutover-after-revision-fsync")
        if _transition_maps_from_directory(temporary) != (source_map, plan.target_digest):
            raise _ProjectCorpusTransitionBlocked("revision copy failed digest validation")
        _crash_point("cutover-before-revision-rename")
        os.rename(temporary, destination)
        _crash_point("cutover-after-revision-rename")
        _crash_point("cutover-before-revision-parent-fsync")
        _fsync_dir(revisions)
        _crash_point("cutover-after-revision-parent-fsync")
    except _ProjectCorpusTransitionBlocked:
        raise
    except OSError as exc:
        return None, (f"cannot create corpus revision: {exc}",), tuple(notes)
    return plan.target_revision, (), tuple(notes)


def _transition_staging_cleanup_tomb(staging: Path) -> Path:
    return staging.parent.parent / f".staging-cleanup-{staging.name}"


def _remove_exact_transition_staging(staging: Path) -> str | None:
    """Durably tombstone then remove only validated digest staging.

    The rename makes post-active cleanup retryable: a crash can leave an
    owned tomb, never an ambiguous live staging directory.
    """
    tomb = _transition_staging_cleanup_tomb(staging)
    try:
        _crash_point("cutover-before-staging-cleanup")
        if staging.exists() or staging.is_symlink():
            if tomb.exists() or tomb.is_symlink():
                return f"exact transition staging cleanup tomb already exists: {tomb}"
            os.rename(staging, tomb)
            _crash_point("cutover-after-staging-cleanup-rename")
            _fsync_dir(staging.parent)
            _fsync_dir(tomb.parent)
        shutil.rmtree(tomb)
        _crash_point("cutover-after-staging-cleanup")
        _crash_point("cutover-before-staging-cleanup-parent-fsync")
        _fsync_dir(tomb.parent)
        _crash_point("cutover-after-staging-cleanup-parent-fsync")
    except OSError as exc:
        return f"exact transition staging cleanup remains pending: {exc}"
    return None


def _recover_transition_staging_cleanup_tombs(
    project_dir: Path, target_digest: str
) -> tuple[str, ...]:
    """Finish this import's owned post-active cleanup tomb.

    A matching active revision has already proved the staged bytes.  A crash
    during recursive deletion may leave a partial tomb, which is still owned
    by its exact name and must not block retry forever.
    """
    expected = f".staging-cleanup-{target_digest}"
    candidates = tuple(sorted(project_dir.glob(".staging-cleanup-*"), key=lambda path: path.name))
    notes: list[str] = []
    for tomb in candidates:
        if tomb.name != expected:
            raise _ProjectCorpusTransitionBlocked(
                f"unrecognized transition cleanup tomb {tomb}; inspect it before retry"
            )
        if tomb.is_symlink() or not tomb.is_dir():
            raise _ProjectCorpusTransitionBlocked(
                f"transition cleanup tomb is malformed or foreign: {tomb}"
            )
        try:
            shutil.rmtree(tomb)
            _fsync_dir(project_dir)
        except OSError as exc:
            raise _ProjectCorpusTransitionBlocked(
                f"exact transition staging cleanup remains pending: {exc}"
            ) from exc
        notes.append(f"recovered exact transition staging cleanup tomb {tomb.name}")
    return tuple(notes)


def _active_import_outcome(
    plan: CorpusTransitionPlan, root: Path, source_map: dict[str, str]
) -> CorpusTransitionOutcome | None:
    """Repair only this checkout's matching pending projection after active."""
    try:
        active = read_corpus_active_record(plan.project_key)
    except ValueError as exc:
        return CorpusTransitionOutcome("blocked", None, (f"active authority is malformed: {exc}",), (), plan)
    if active is None:
        return None
    revision = _valid_active_revision(plan.project_key, active)
    if revision is None or _transition_maps_from_directory(revision) != (source_map, plan.target_digest):
        return CorpusTransitionOutcome(
            "blocked", None, ("project already has different or dangling external authority",), (), plan
        )
    if plan.legacy_migration_roster_path is not None:
        try:
            _write_corpus_legacy_migration_audit(plan)
        except _ProjectCorpusTransitionBlocked as exc:
            return CorpusTransitionOutcome("blocked", active["active_revision"], exc.blockers, (), plan)
    try:
        projection = read_corpus_projection_record(plan.project_key, root)
    except ValueError as exc:
        return CorpusTransitionOutcome(
            "blocked",
            active["active_revision"],
            (f"pending projection is malformed: {exc}",),
            (),
            plan,
        )
    expected = build_corpus_projection_record(
        plan.project_key, root, active["active_revision"], source_map, source_map
    )
    cleanup_notes = _recover_transition_staging_cleanup_tombs(
        corpus_project_dir(plan.project_key), plan.target_digest
    )
    staging = corpus_project_dir(plan.project_key) / "staging" / plan.target_digest
    staging_present = staging.exists() or staging.is_symlink()
    if staging_present and _transition_maps_from_directory(staging) != (
        source_map,
        plan.target_digest,
    ):
        return CorpusTransitionOutcome(
            "blocked",
            active["active_revision"],
            ("post-commit transition staging is malformed or foreign; inspect it before retry",),
            (),
            plan,
        )
    if projection is None or (
        projection["revision"] != active["active_revision"]
        or projection["repository_files"] != source_map
        or projection["corpus_files"] != source_map
    ):
        _ensure_transition_directory(corpus_projection_path(plan.project_key, root).parent, "projections")
        _replace_transition_json(corpus_projection_path(plan.project_key, root), expected, "pending-repair")
        _crash_point("cutover-after-pending-repair")
        _replace_transition_json(
            corpus_epoch_path(), build_corpus_epoch_record(), "epoch-repair"
        )
        notes = list(cleanup_notes) + ["repaired importing checkout pending projection"]
        if staging_present:
            cleanup_warning = _remove_exact_transition_staging(staging)
            if cleanup_warning:
                notes.append(cleanup_warning)
        return CorpusTransitionOutcome(
            "repaired", active["active_revision"], (), tuple(notes), plan
        )
    if staging_present:
        _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch-recovery")
        cleanup_warning = _remove_exact_transition_staging(staging)
        notes = list(cleanup_notes) + ["recovered post-active epoch and removed exact transition staging"]
        if cleanup_warning:
            notes.append(cleanup_warning)
        return CorpusTransitionOutcome(
            "recovered", active["active_revision"], (),
            tuple(notes), plan,
        )
    return CorpusTransitionOutcome("already-imported", active["active_revision"], (), cleanup_notes, plan)


def _active_reimport_outcome(
    plan: CorpusReimportPlan, root: Path, source_map: dict[str, str]
) -> CorpusTransitionOutcome | None:
    """Finish only a digest-identical re-import that already swapped authority."""
    try:
        active = read_corpus_active_record(plan.project_key)
    except ValueError as exc:
        return CorpusTransitionOutcome("blocked", None, (f"active authority is malformed: {exc}",), (), plan)
    if active is None or active.get("active_revision") != plan.target_revision:
        return None
    if active.get("previous_revision") != plan.frozen_revision:
        return CorpusTransitionOutcome(
            "blocked", active["active_revision"],
            ("active authority conflicts with interrupted re-import",), (), plan,
        )
    revision = _valid_active_revision(plan.project_key, active)
    frozen = corpus_revision_dir(plan.project_key, plan.frozen_revision)
    if (
        revision is None
        or _transition_maps_from_directory(revision) != (source_map, plan.target_digest)
        or (
            (frozen_map := _transition_maps_from_directory(frozen)) is None
            or frozen_map[0] != dict(plan.corpus_files)
        )
    ):
        return CorpusTransitionOutcome(
            "blocked", active["active_revision"],
            ("interrupted re-import authority bytes are missing or changed",), (), plan,
        )
    expected = build_corpus_projection_record(
        plan.project_key, root, plan.target_revision, source_map, source_map
    )
    projection = read_corpus_projection_record(plan.project_key, root)
    cleanup_notes = _recover_transition_staging_cleanup_tombs(
        corpus_project_dir(plan.project_key), plan.target_digest
    )
    staging = corpus_project_dir(plan.project_key) / "staging" / plan.target_digest
    if staging.exists() or staging.is_symlink():
        if _transition_maps_from_directory(staging) != (source_map, plan.target_digest):
            return CorpusTransitionOutcome(
                "blocked", active["active_revision"],
                ("post-commit re-import staging is malformed or foreign; inspect it before retry",), (), plan,
            )
    notes = list(cleanup_notes)
    if projection is None or projection != expected:
        _ensure_transition_directory(corpus_projection_path(plan.project_key, root).parent, "projections")
        _replace_transition_json(corpus_projection_path(plan.project_key, root), expected, "pending-repair")
        _crash_point("cutover-after-pending-repair")
        notes.append("repaired importing checkout pending projection")
    _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch-repair")
    if staging.exists() or staging.is_symlink():
        cleanup_warning = _remove_exact_transition_staging(staging)
        if cleanup_warning:
            notes.append(cleanup_warning)
    return CorpusTransitionOutcome("recovered", plan.target_revision, (), tuple(notes), plan)


def _reimport_observed_roots(
    active: dict, current: CorpusReimportPlan, root: Path
) -> tuple[str, ...] | None:
    """Preserve all known checkouts when re-import replaces authority."""
    candidates = (*active["observed_roots"], *current.worktree_roots, *current.independent_clone_roots, str(root))
    normalized: set[str] = set()
    for value in candidates:
        try:
            path = Path(value)
            if not path.is_absolute() or ".." in path.parts:
                return None
            normalized.add(str(path.resolve()))
        except OSError:
            return None
    if not normalized or len(normalized) > 128:
        return None
    return tuple(sorted(normalized))


def _apply_project_corpus_reimport(plan: CorpusReimportPlan) -> CorpusTransitionOutcome:
    root = _validated_project_root(plan.project_root)
    if plan.blockers:
        return CorpusTransitionOutcome("blocked", None, plan.blockers, (), plan)
    if plan.pending_projection_repair:
        try:
            with ProjectCorpusTransitionSession(plan):
                source = _reimport_source_map(plan, root)
                active = read_corpus_active_record(plan.project_key)
                if (
                    source is None
                    or active is None
                    or active["active_revision"] != plan.active_revision
                    or source[0] != dict(plan.repository_files)
                    or dict(plan.corpus_files) != source[0]
                ):
                    return CorpusTransitionOutcome(
                        "blocked", None, ("pending projection repair evidence changed; rerun import",), (), plan
                    )
                _ensure_transition_directory(corpus_projection_path(plan.project_key, root).parent, "projections")
                _preserve_stale_projection_evidence(
                    plan.project_key,
                    root,
                    active,
                    plan.projection_sha256,
                )
                _replace_transition_json(
                    corpus_projection_path(plan.project_key, root),
                    build_corpus_projection_record(
                        plan.project_key, root, plan.active_revision, source[0], source[0]
                    ),
                    "pending-repair",
                )
                _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch-repair")
        except _ProjectCorpusTransitionBlocked as exc:
            return CorpusTransitionOutcome("blocked", None, exc.blockers, (), plan)
        return CorpusTransitionOutcome("repaired", plan.active_revision, (), (), plan)
    if plan.state == "clean":
        staging = corpus_project_dir(plan.project_key) / "staging" / plan.target_digest
        tomb = _transition_staging_cleanup_tomb(staging)
        try:
            with ProjectCorpusTransitionSession(plan):
                temp_notes = _recover_transition_json_temps(corpus_project_dir(plan.project_key))
                if not (staging.exists() or staging.is_symlink() or tomb.exists() or tomb.is_symlink()):
                    status = "recovered" if temp_notes else "already-imported"
                    return CorpusTransitionOutcome(status, plan.active_revision, (), temp_notes, plan)
                source = _reimport_source_map(plan, root)
                if source is None or (staging.exists() and _transition_maps_from_directory(staging) != source):
                    return CorpusTransitionOutcome(
                        "blocked", plan.active_revision,
                        ("clean re-import recovery staging is malformed or changed",), (), plan,
                    )
                notes = list(_recover_transition_staging_cleanup_tombs(
                    corpus_project_dir(plan.project_key), plan.target_digest
                ))
                _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch-repair")
                if staging.exists() or staging.is_symlink():
                    cleanup_warning = _remove_exact_transition_staging(staging)
                    if cleanup_warning:
                        notes.append(cleanup_warning)
        except _ProjectCorpusTransitionBlocked as exc:
            return CorpusTransitionOutcome("blocked", plan.active_revision, exc.blockers, (), plan)
        return CorpusTransitionOutcome("recovered", plan.active_revision, (), tuple(notes), plan)
    try:
        with ProjectCorpusTransitionSession(plan):
            source = _reimport_source_map(plan, root)
            if source is None or source[1] != plan.target_digest:
                return CorpusTransitionOutcome(
                    "blocked", None, ("source changed while acquiring locks; rerun apply",), (), plan
                )
            source_map, _digest = source
            temp_notes = _recover_transition_json_temps(corpus_project_dir(plan.project_key))
            recovered = _active_reimport_outcome(plan, root, source_map)
            if recovered is not None:
                return replace(recovered, notes=temp_notes + recovered.notes)
            current = plan_project_corpus_reimport(
                root,
                replace_external=plan.replace_external,
                identity_lock_held=True,
                identity_override=ProjectIdentity(
                    plan.canonical_identity, plan.canonical_identity, plan.identity_key, root
                ),
            )
            drift = _reimport_plan_drift(plan, current)
            if drift:
                return CorpusTransitionOutcome(
                    "blocked", None,
                    (f"import plan changed while acquiring locks ({', '.join(drift)}); rerun apply",), (), current,
                )
            if current.blockers:
                return CorpusTransitionOutcome("blocked", None, current.blockers, (), current)
            source = _reimport_source_map(current, root)
            if source is None or source[1] != current.target_digest:
                return CorpusTransitionOutcome(
                    "blocked", None, ("source changed while acquiring locks; rerun apply",), (), current
                )
            source_map, _digest = source
            active = read_corpus_active_record(current.project_key)
            if active is None or active.get("active_revision") != current.active_revision:
                return CorpusTransitionOutcome(
                    "blocked", None, ("active authority changed while acquiring locks; rerun apply",), (), current
                )
            departing = _valid_active_revision(current.project_key, active)
            departing_map = _transition_maps_from_directory(departing) if departing is not None else None
            if departing_map is None or departing_map[0] != dict(current.corpus_files):
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    ("departing active revision changed while acquiring locks; rerun apply",),
                    (),
                    current,
                )
            observed_roots = _reimport_observed_roots(active, current, root)
            if observed_roots is None:
                return CorpusTransitionOutcome(
                    "blocked", None, ("re-import observed-root union is invalid or exceeds 128 roots",), (), current
                )
            canonical_aliases = tuple(
                sorted(
                    {
                        *active["canonical_aliases"],
                        current.canonical_identity,
                    }
                )
            )
            if len(canonical_aliases) > 128:
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    ("re-import canonical alias union exceeds 128 aliases",),
                    (),
                    current,
                )
            staging, blockers, stage_notes = _stage_transition_corpus(current, root, source_map)
            if staging is None:
                return CorpusTransitionOutcome("blocked", None, blockers, stage_notes, current)
            revision, blockers, revision_notes = _copy_transition_revision(current, staging, source_map)
            if revision is None:
                return CorpusTransitionOutcome("blocked", None, blockers, stage_notes + revision_notes, current)
            frozen = _freeze_corpus_revision(current.project_key, departing, current.frozen_revision)
            projection_path = corpus_projection_path(current.project_key, root)
            _ensure_transition_directory(projection_path.parent, "projections")
            _preserve_stale_projection_evidence(
                current.project_key, root, active, current.projection_sha256
            )
            _replace_transition_json(
                projection_path,
                build_corpus_projection_record(current.project_key, root, revision, source_map, source_map),
                "pending-projection",
            )
            _crash_point("cutover-after-pending-projection")
            neutral = _neutral_root()
            catalog = _published_identity_record(neutral / "projects" / current.project_key) if neutral else None
            if catalog is None:
                return CorpusTransitionOutcome("blocked", None, ("published catalog identity is invalid",), (), current)
            authority_identity = ProjectIdentity(catalog["canonical"], catalog["display"], current.project_key, root)
            replacement = build_corpus_active_record(
                authority_identity, root, revision, previous_revision=frozen,
                canonical_aliases=canonical_aliases,
                observed_roots=observed_roots, reason="reimport",
            )
            _replace_transition_json(corpus_active_path(current.project_key), replacement, "active")
            _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch")
            cleanup_warning = _remove_exact_transition_staging(staging)
            notes = temp_notes + stage_notes + revision_notes + (f"froze departing revision {frozen}",)
            if cleanup_warning:
                notes += (cleanup_warning,)
            return CorpusTransitionOutcome("imported", revision, (), notes, current)
    except _ProjectCorpusTransitionBlocked as exc:
        return CorpusTransitionOutcome("blocked", None, exc.blockers, (), plan)


def _apply_legacy_project_corpus_import(plan_or_root: CorpusTransitionPlan | Path | str) -> CorpusTransitionOutcome:
    """Perform one guarded import using the exact immutable preview when given."""
    preview = (
        plan_or_root
        if isinstance(plan_or_root, CorpusTransitionPlan)
        else plan_project_corpus_import(_validated_project_root(plan_or_root))
    )
    root = _validated_project_root(preview.project_root)
    preflight = tuple(
        blocker for blocker in preview.blockers if not _transition_recovery_blocker(preview, blocker)
    )
    if preflight:
        return CorpusTransitionOutcome("blocked", None, preflight, (), preview)
    try:
        with ProjectCorpusTransitionSession(preview):
            current = plan_project_corpus_import(
                root, legacy_migration_roster=preview.legacy_migration_roster_path
            )
            drift = _transition_plan_drift(preview, current)
            if drift:
                return CorpusTransitionOutcome(
                    "blocked", None,
                    (f"import plan changed while acquiring locks ({', '.join(drift)}); rerun apply",), (), current,
                )
            current = replace(
                current,
                target_revision=preview.target_revision,
                legacy_migration_roster_sha256=preview.legacy_migration_roster_sha256,
            )
            under_lock = tuple(
                blocker for blocker in current.blockers if not _transition_recovery_blocker(current, blocker)
            )
            if under_lock:
                return CorpusTransitionOutcome("blocked", None, under_lock, (), current)
            neutral = _neutral_root()
            if neutral is None:
                return CorpusTransitionOutcome(
                    "blocked", None, ("neutral corpus root is unavailable",), (), current
                )
            source = _transition_source_map(current, root, neutral)
            if source is None or source[1] != current.target_digest:
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    ("source changed while acquiring locks; rerun apply",),
                    (),
                    current,
                )
            _validate_legacy_migration_plan_roster(current, root)
            source_map, _digest = source
            project_dir = corpus_project_dir(current.project_key)
            temp_notes = _recover_transition_json_temps(project_dir)
            active_outcome = _active_import_outcome(current, root, source_map)
            if active_outcome is not None:
                return replace(active_outcome, notes=temp_notes + active_outcome.notes)
            identity = project_identity(root)
            if identity.key != current.identity_key:
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    ("project identity changed while acquiring locks; rerun apply",),
                    (),
                    current,
                )
            _crash_point("cutover-before-identity-publication")
            published_key = ensure_project_record(neutral, root, identity=identity)
            _crash_point("cutover-after-identity-publication")
            if published_key != current.project_key:
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    ("project identity key changed during import; rerun apply",),
                    (),
                    current,
                )
            supersession_notes = _supersede_legacy_migration_audit(current)
            staging, blockers, stage_notes = _stage_transition_corpus(current, root, source_map)
            if staging is None:
                return CorpusTransitionOutcome("blocked", None, blockers, stage_notes, current)
            revision, blockers, revision_notes = _copy_transition_revision(current, staging, source_map)
            if revision is None:
                return CorpusTransitionOutcome("blocked", None, blockers, stage_notes + revision_notes, current)
            if current.legacy_migration_roster_path is not None:
                _write_corpus_legacy_migration_audit(current)
            projection = build_corpus_projection_record(current.project_key, root, revision, source_map, source_map)
            _crash_point("cutover-before-pending-projection")
            projection_path = corpus_projection_path(current.project_key, root)
            _ensure_transition_directory(projection_path.parent, "projections")
            _replace_transition_json(projection_path, projection, "pending-projection")
            _crash_point("cutover-after-pending-projection")
            catalog = _published_identity_record(neutral / "projects" / current.project_key)
            if catalog is None:
                return CorpusTransitionOutcome("blocked", None, ("published catalog identity is invalid",), (), current)
            authority_identity = ProjectIdentity(
                catalog["canonical"], catalog["display"], current.project_key, identity.project_root
            )
            active = build_corpus_active_record(
                authority_identity, root, revision, canonical_aliases=(identity.canonical,), reason="import"
            )
            _replace_transition_json(corpus_active_path(current.project_key), active, "active")
            _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "epoch")
            cleanup_warning = _remove_exact_transition_staging(staging)
            notes = stage_notes + revision_notes + supersession_notes
            if cleanup_warning:
                notes += (cleanup_warning,)
            return CorpusTransitionOutcome("imported", revision, (), notes, current)
    except _ProjectCorpusTransitionBlocked as exc:
        return CorpusTransitionOutcome("blocked", None, exc.blockers, (), preview)


def apply_project_corpus_import(
    plan_or_root: CorpusTransitionPlan | CorpusReimportPlan | Path | str,
) -> CorpusTransitionOutcome:
    """Apply the one public import verb through its explicit plan variant."""
    preview = (
        plan_or_root
        if isinstance(plan_or_root, (CorpusTransitionPlan, CorpusReimportPlan))
        else plan_project_corpus_import(_validated_project_root(plan_or_root))
    )
    if isinstance(preview, CorpusReimportPlan):
        return _apply_project_corpus_reimport(preview)
    return _apply_legacy_project_corpus_import(preview)


def _freeze_corpus_revision(project_key: str, source: Path, revision: str) -> str:
    """Copy the lock-held departing revision into a new immutable revision."""
    mapped = _transition_maps_from_directory(source)
    if mapped is None:
        raise _ProjectCorpusTransitionBlocked("departing external revision is malformed")
    files, _digest = mapped
    revisions = corpus_project_dir(project_key) / "revisions"
    _ensure_transition_directory(revisions, "rollback-revisions")
    temp_pattern = re.compile(
        rf"\.{re.escape(revision)}\.tmp-\d+-[0-9a-f]{{8}}"
    )
    for candidate in sorted(revisions.iterdir(), key=lambda path: path.name):
        if temp_pattern.fullmatch(candidate.name):
            _quarantine_transition_staging(corpus_project_dir(project_key), candidate)
    destination = corpus_revision_dir(project_key, revision)
    if destination.exists() or destination.is_symlink():
        if _transition_maps_from_directory(destination) == mapped:
            return revision
        raise _ProjectCorpusTransitionBlocked("rollback frozen revision already exists with different bytes")
    temporary = revisions / f".{revision}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        _crash_point("cutover-before-rollback-freeze-create")
        temporary.mkdir(mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
        _crash_point("cutover-after-rollback-freeze-create")
        for name in sorted(files):
            payload = _read_file_capped(source / name, EXTERNAL_CORPUS_FILE_MAX_BYTES)
            if payload is None or hashlib.sha256(payload).hexdigest() != files[name]:
                raise _ProjectCorpusTransitionBlocked("departing external revision changed while rollback was locked")
            _crash_point("cutover-before-rollback-freeze-file")
            _write_new_fsynced(temporary / name, payload)
            _crash_point("cutover-after-rollback-freeze-file")
        _crash_point("cutover-before-rollback-freeze-fsync")
        _fsync_dir(temporary)
        _crash_point("cutover-after-rollback-freeze-fsync")
        if _transition_maps_from_directory(temporary) != mapped:
            raise _ProjectCorpusTransitionBlocked("frozen rollback revision failed validation")
        _crash_point("cutover-before-rollback-freeze-rename")
        os.rename(temporary, destination)
        _crash_point("cutover-after-rollback-freeze-rename")
        _crash_point("cutover-before-rollback-freeze-parent-fsync")
        _fsync_dir(revisions)
        _crash_point("cutover-after-rollback-freeze-parent-fsync")
    except OSError as exc:
        raise _ProjectCorpusTransitionBlocked(f"cannot freeze departing external revision: {exc}") from None
    return revision


def _write_complete_rollback_transaction(project_key: str, transaction: dict) -> None:
    _replace_transition_json(
        corpus_rollback_transaction_path(project_key),
        _complete_rollback_transaction(transaction),
        "rollback-transaction-complete",
    )


def apply_project_corpus_rollback(plan_or_root: CorpusRollbackPlan | Path | str) -> CorpusTransitionOutcome:
    """Apply a guarded project rollback; no steady-state write session is entered."""
    preview = (
        plan_or_root
        if isinstance(plan_or_root, CorpusRollbackPlan)
        else plan_project_corpus_rollback(plan_or_root)
    )
    if preview.blockers:
        return CorpusTransitionOutcome("blocked", preview.active_revision, preview.blockers, (), None)
    if preview.active_revision is None:
        try:
            transaction = _read_rollback_transaction(preview.project_key)
        except ValueError as exc:
            return CorpusTransitionOutcome("blocked", None, (str(exc),), (), None)
        if transaction is None:
            return CorpusTransitionOutcome("already-rolled-back", None, (), preview.notes, None)
        try:
            with ProjectCorpusTransitionSession(preview):
                raw = _raw_authority_digest(corpus_deactivated_path(preview.project_key))
                if (
                    transaction["target_kind"] != "legacy"
                    or raw is None
                    or raw[0] != transaction["source_active_sha256"]
                ):
                    return CorpusTransitionOutcome(
                        "blocked", None, ("rollback transaction deactivation evidence is missing or changed",), (), None
                    )
                if transaction["phase"] == "complete":
                    return CorpusTransitionOutcome("already-rolled-back", None, (), preview.notes, None)
                _recover_transition_json_temps(corpus_project_dir(preview.project_key))
                _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "rollback-epoch-recovery")
                _write_complete_rollback_transaction(preview.project_key, transaction)
                return CorpusTransitionOutcome("already-rolled-back", None, (), preview.notes, None)
        except _ProjectCorpusTransitionBlocked as exc:
            return CorpusTransitionOutcome("blocked", None, exc.blockers, (), None)
    root = _validated_project_root(preview.project_root)
    try:
        with ProjectCorpusTransitionSession(preview):
            _recover_transition_json_temps(corpus_project_dir(preview.project_key))
            current = plan_project_corpus_rollback(root)
            if current.blockers:
                return CorpusTransitionOutcome("blocked", current.active_revision, current.blockers, (), None)
            drift = _rollback_plan_drift(preview, current)
            if drift:
                return CorpusTransitionOutcome(
                    "blocked",
                    None,
                    (f"rollback plan changed while acquiring locks ({', '.join(drift)}); rerun apply",),
                    (),
                    None,
                )
            active = read_corpus_active_record(current.project_key)
            if active is None:
                return CorpusTransitionOutcome(
                    "blocked", None, ("active authority disappeared while acquiring locks; rerun status",), (), None
                )
            transaction = _read_rollback_transaction(current.project_key)
            if transaction is not None and (
                transaction["target_kind"] == "external"
                and active["active_revision"] == transaction["target_revision"]
                and active["previous_revision"] == transaction["freeze_revision"]
            ):
                if transaction["phase"] == "complete":
                    return CorpusTransitionOutcome("rolled-back", active["active_revision"], (), current.notes, None)
                _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "rollback-epoch-recovery")
                _write_complete_rollback_transaction(current.project_key, transaction)
                return CorpusTransitionOutcome("rolled-back", active["active_revision"], (), current.notes, None)
            if transaction is None:
                if current.source_authority_sha256 is None or current.target_kind is None:
                    return CorpusTransitionOutcome(
                        "blocked", None, ("rollback authority evidence is unavailable",), (), None
                    )
                transaction = _build_rollback_transaction(
                    current.project_key, active["active_revision"], current.target_kind,
                    current.previous_revision, current.freeze_revision, current.source_authority_sha256,
                )
                _replace_transition_json(
                    corpus_rollback_transaction_path(current.project_key), transaction, "rollback-transaction"
                )
            elif (
                transaction["source_revision"] != active["active_revision"]
                or transaction["source_active_sha256"]
                != _raw_authority_digest(corpus_active_path(current.project_key))[0]
            ):
                return CorpusTransitionOutcome(
                    "blocked", None, ("rollback transaction conflicts with active authority",), (), None
                )
            if current.previous_revision is not None:
                source = _valid_active_revision(current.project_key, active)
                if source is None or preview.freeze_revision is None:
                    return CorpusTransitionOutcome(
                        "blocked", None, ("departing active revision is unavailable for freezing",), (), None
                    )
                frozen = _freeze_corpus_revision(current.project_key, source, transaction["freeze_revision"])
                neutral = _neutral_root()
                catalog = (
                    _published_identity_record(neutral / "projects" / current.project_key)
                    if neutral is not None else None
                )
                if catalog is None:
                    return CorpusTransitionOutcome(
                        "blocked", None, ("published catalog identity is invalid",), (), None
                    )
                live_identity = project_identity(root)
                identity = ProjectIdentity(catalog["canonical"], catalog["display"], current.project_key, root)
                replacement = build_corpus_active_record(
                    identity, root, current.previous_revision, previous_revision=frozen,
                    canonical_aliases=tuple(active["canonical_aliases"]) + (live_identity.canonical,),
                    reason="rollback",
                )
                _replace_transition_json(corpus_active_path(current.project_key), replacement, "rollback-active")
                _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "rollback-epoch")
                _write_complete_rollback_transaction(current.project_key, transaction)
                return CorpusTransitionOutcome(
                    "rolled-back", current.previous_revision, (), (f"frozen departing revision {frozen}",), None
                )
            active_path = corpus_active_path(current.project_key)
            deactivated = corpus_deactivated_path(current.project_key)
            if deactivated.exists() or deactivated.is_symlink():
                history = deactivated.with_name(f"deactivated-history-{uuid.uuid4().hex[:16]}.json")
                _crash_point("cutover-before-rollback-deactivation-history-rename")
                os.replace(deactivated, history)
                _crash_point("cutover-after-rollback-deactivation-history-rename")
                _crash_point("cutover-before-rollback-deactivation-history-parent-fsync")
                _fsync_dir(deactivated.parent)
                _crash_point("cutover-after-rollback-deactivation-history-parent-fsync")
            _crash_point("cutover-before-rollback-deactivation-rename")
            os.replace(active_path, deactivated)
            _crash_point("cutover-after-rollback-deactivation-rename")
            _crash_point("cutover-before-rollback-deactivation-parent-fsync")
            _fsync_dir(deactivated.parent)
            _crash_point("cutover-after-rollback-deactivation-parent-fsync")
            _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "rollback-epoch")
            _write_complete_rollback_transaction(current.project_key, transaction)
            return CorpusTransitionOutcome("legacy-rolled-back", current.active_revision, (), (), None)
    except _ProjectCorpusTransitionBlocked as exc:
        return CorpusTransitionOutcome("blocked", preview.active_revision, exc.blockers, (), None)


def _corpus_resolution_blocked(reason: str) -> None:
    print(f"learnings-state: corpus resolution blocked: {reason}", file=sys.stderr)


def _corpus_write_state() -> StatePaths:
    """Return the single activation snapshot that authorizes corpus writes."""
    paths, status = _evaluate_activation()
    if status.state != ACTIVATION_VALID:
        raise IdentityResolutionError("external corpus initialization requires valid neutral activation")
    return paths


def _active_record_for_canonical(canonical: str) -> tuple[str, dict] | None:
    for key, record, _active in _iter_active_corpus_records() or ():
        if record is not None and canonical in record["canonical_aliases"]:
            return key, record
    return None


def _malformed_active_record_has_authority(
    project_root: Path,
    identity: ProjectIdentity,
    paths: StatePaths,
    activation: ActivationStatus,
    *,
    active_records=None,
) -> bool:
    """Whether malformed active records conservatively claim this project.

    A damaged activation record makes every malformed authority record block.
    With a valid activation, only an exact candidate key or a candidate key's
    canonical suffix blocks; the candidates cover both the live identity and
    any already-published catalog identity for this checkout.
    """
    if active_records is None:
        active_records = tuple(_iter_active_corpus_records() or ())
    invalid_keys = {key for key, record, _active in active_records if record is None}
    if not invalid_keys:
        return False
    if activation.state != ACTIVATION_VALID:
        return True
    candidate_keys = {identity.key}
    try:
        candidate_keys.add(resolve_or_derive_key(paths.root, project_root, identity=identity))
    except IdentityResolutionError:
        return True
    candidate_suffixes = {
        key.rsplit("-", 1)[-1]
        for key in candidate_keys
        if re.fullmatch(r"[0-9a-f]{16}", key.rsplit("-", 1)[-1])
    }
    return bool(
        invalid_keys & candidate_keys
        or candidate_suffixes
        & {
            key.rsplit("-", 1)[-1]
            for key in invalid_keys
            if re.fullmatch(r"[0-9a-f]{16}", key.rsplit("-", 1)[-1])
        }
    )


def _add_observed_root(
    project_root: Path, identity: ProjectIdentity, project_key: str, record: dict
) -> tuple[dict, CorpusLocation]:
    """Under ``project_key``'s lock, persist a discovered checkout alias."""
    root_is_known = str(project_root) in record["observed_roots"]
    identity_is_known = identity.canonical in record["canonical_aliases"]
    if not root_is_known and not identity_is_known:
        raise IdentityResolutionError("active corpus record no longer matches project identity")
    if not root_is_known or not identity_is_known:
        record = dict(record)
        record["canonical_aliases"] = sorted({*record["canonical_aliases"], identity.canonical})
        record["observed_roots"] = sorted({*record["observed_roots"], str(project_root)})
        write_corpus_active_record(project_key, record)
        _replace_corpus_epoch()
    location = _external_location_for_record(project_root, project_key, record)
    if location is None:
        raise IdentityResolutionError("active corpus record is malformed or dangling")
    return record, location


def _resolve_project_corpus(project_root: Path | str, *, strict: bool) -> CorpusLocation | None:
    """Read-only corpus selection, optionally surfacing authoritative damage."""
    root = _validated_project_root(project_root)

    def blocked(reason: str) -> None:
        if strict:
            raise CorpusResolutionError(reason)
        _corpus_resolution_blocked(reason)

    try:
        active_records = tuple(_iter_active_corpus_records() or ())
    except OSError as exc:
        if strict:
            raise CorpusResolutionError("corpus authority scan failed") from exc
        _corpus_resolution_blocked("corpus authority scan failed")
        return None
    for key, record, _active in active_records:
        if record is None or str(root) not in record["observed_roots"]:
            continue
        location = _external_location_for_record(root, key, record)
        if location is None:
            blocked("active external corpus is malformed or dangling (regular single-link validation failed)")
        return location
    try:
        identity = project_identity(root)
    except IdentityResolutionError:
        blocked("identity probe failed")
        return None
    paths, activation = _evaluate_activation()
    if _malformed_active_record_has_authority(
        root, identity, paths, activation, active_records=active_records
    ):
        blocked("an active external corpus record is malformed")
        return None
    for key, record, _active in active_records:
        if record is not None and identity.canonical in record["canonical_aliases"]:
            if identity.project_root is not None:
                alias_root = identity.project_root
            else:
                try:
                    git_top = _git(root, "rev-parse", "--show-toplevel")
                except IdentityResolutionError:
                    blocked("identity probe failed")
                    return None
                alias_root = Path(git_top).resolve() if git_top else root
            location = _external_location_for_record(alias_root, key, record)
            if location is None:
                blocked("active external corpus is malformed or dangling (regular single-link validation failed)")
            return location
    legacy_root = identity.project_root or root
    legacy_authority = (
        activation.state != ACTIVATION_VALID and _legacy_corpus_present(legacy_root)
    ) or (
        activation.state == ACTIVATION_VALID and _system_owned_legacy_corpus(legacy_root)
    )
    if legacy_authority:
        try:
            lock_path = structural_lock_path(legacy_root)
        except OSError as exc:
            if strict:
                raise CorpusResolutionError("legacy corpus lock resolution failed") from exc
            _corpus_resolution_blocked("legacy corpus lock resolution failed")
            return None
        return CorpusLocation(legacy_root, identity.key, legacy_root, lock_path, "legacy-repository")
    return None


def resolve_project_corpus(project_root: Path | str) -> CorpusLocation | None:
    """Compatible read-only selection; corruption stays diagnostic + absent."""
    return _resolve_project_corpus(project_root, strict=False)


def resolve_project_corpus_strict(project_root: Path | str) -> CorpusLocation | None:
    """Read-only selection for consumers that must fail closed on authority."""
    return _resolve_project_corpus(project_root, strict=True)


def _cache_record_is_valid(record: object) -> bool:
    if not isinstance(record, dict) or set(record) != _CORPUS_CACHE_KEYS:
        return False
    observed = record.get("observed_root")
    try:
        observed_is_canonical = (
            isinstance(observed, str)
            and Path(observed).is_absolute()
            and str(Path(observed).resolve()) == observed
        )
    except OSError:
        observed_is_canonical = False
    return (
        record.get("schema_version") == CORPUS_CACHE_SCHEMA_VERSION
        and isinstance(record.get("epoch_nonce"), str)
        and bool(re.fullmatch(r"[0-9a-f]{16}", record["epoch_nonce"]))
        and observed_is_canonical
        and isinstance(record.get("observed_root_dev"), int)
        and not isinstance(record["observed_root_dev"], bool)
        and isinstance(record.get("observed_root_ino"), int)
        and not isinstance(record["observed_root_ino"], bool)
        and is_project_key(record.get("project_key"))
        and isinstance(record.get("active_revision"), str)
        and bool(_CORPUS_REVISION_RE.fullmatch(record["active_revision"]))
    )


def _cache_contains_project_root(project_root: Path, observed_root: Path) -> bool:
    if project_root != observed_root and observed_root not in project_root.parents:
        return False
    candidate = project_root
    while candidate != observed_root:
        if os.path.lexists(candidate / ".git"):
            return False
        candidate = candidate.parent
    return True


def _external_cache_record(location: CorpusLocation, epoch_nonce: str) -> dict:
    stat_result = location.project_root.stat()
    return {
        "schema_version": CORPUS_CACHE_SCHEMA_VERSION,
        "epoch_nonce": epoch_nonce,
        "observed_root": str(location.project_root),
        "observed_root_dev": stat_result.st_dev,
        "observed_root_ino": stat_result.st_ino,
        "project_key": location.project_key,
        "active_revision": location.corpus_root.name,
    }


def _cached_external_location(
    project_root: Path, cache_record: object, epoch: dict | None
) -> tuple[CorpusLocation, dict] | None:
    if not _cache_record_is_valid(cache_record):
        return None
    if epoch is None or epoch["nonce"] != cache_record["epoch_nonce"]:
        return None
    try:
        observed_root = Path(cache_record["observed_root"]).resolve()
        observed_stat = observed_root.stat()
    except OSError:
        return None
    if (
        str(observed_root) != cache_record["observed_root"]
        or observed_stat.st_dev != cache_record["observed_root_dev"]
        or observed_stat.st_ino != cache_record["observed_root_ino"]
        or not _cache_contains_project_root(project_root, observed_root)
    ):
        return None
    try:
        record = read_corpus_active_record(cache_record["project_key"])
    except ValueError:
        return None
    if record is None or record["active_revision"] != cache_record["active_revision"]:
        return None
    location = _external_location_for_record(observed_root, cache_record["project_key"], record)
    if location is None:
        return None
    return location, dict(cache_record)


def resolve_project_corpus_cached(
    project_root: Path | str, cache_record: object = None
) -> tuple[CorpusLocation | None, dict | None]:
    """Resolve once, reusing only a verified positive external identity cache."""
    root = _validated_project_root(project_root)
    try:
        epoch = read_corpus_epoch_record()
    except ValueError:
        epoch = None
    cached = _cached_external_location(root, cache_record, epoch)
    if cached is not None:
        return cached
    location = resolve_project_corpus_strict(root)
    if location is None or location.mode != "external":
        return location, None
    if epoch is None:
        return location, None
    try:
        replacement = _external_cache_record(location, epoch["nonce"])
    except OSError:
        replacement = None
    return location, replacement


def resolve_corpus_for_write(
    project_root: Path | str, *, requested_root: Path | str | None = None
) -> CorpusLocation:
    """Resolve a mutation root without ever creating an external revision.

    Strict authority damage is deliberately distinct from clean absence.  The
    latter keeps the historic first-write behavior: callers may create a
    repository ``LEARNINGS.md`` (or their explicit test override) later.
    """
    root = _validated_project_root(project_root)
    requested = Path(requested_root).resolve() if requested_root is not None else None
    location = resolve_project_corpus_strict(root)
    if location is not None and location.mode == "external":
        if requested is not None and requested != location.corpus_root:
            raise CorpusResolutionError("requested corpus root conflicts with active external corpus")
        # Selection is the external adapter's authority/child safety preflight.
        select_external_corpus_files(location)
        return location
    if requested is not None and (not requested.is_absolute() or not requested.is_dir()):
        raise CorpusResolutionError("requested corpus root must be an existing directory")
    corpus_root = requested if requested is not None else root
    try:
        identity = project_identity(root)
        key = identity.key
    except IdentityResolutionError as exc:
        raise CorpusResolutionError("identity probe failed") from exc
    return CorpusLocation(root, key, corpus_root, structural_lock_path(root), "legacy-repository")


@contextlib.contextmanager
def _corpus_lock(project_key: str):
    try:
        lock = _acquire_corpus_identity_lock(corpus_lock_path(project_key), nonblocking=False)
    except OSError as exc:
        raise IdentityResolutionError(f"cannot acquire corpus identity lock: {exc}") from exc
    if lock is None:
        raise IdentityResolutionError("cannot acquire corpus identity lock")
    try:
        yield
    finally:
        lock.close()


def _acquire_corpus_identity_lock(path: Path, *, nonblocking: bool) -> _ActivityLock | None:
    fd = -1
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            str(path),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(errno.EINVAL, "corpus identity lock must be a regular single-link file")
        if metadata.st_mode & 0o777 != 0o600:
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
    except BlockingIOError:
        if fd != -1:
            os.close(fd)
        return None
    except OSError:
        if fd != -1:
            os.close(fd)
        raise
    return _ActivityLock(fd)


def try_corpus_identity_lock(location: CorpusLocation) -> _ActivityLock | None:
    if location.mode != "external":
        return None
    return _acquire_corpus_identity_lock(location.lock_path, nonblocking=True)


def _template_bytes() -> bytes:
    here = Path(__file__).resolve()
    candidates = (
        here.parent.parent / "templates" / "LEARNINGS.md",  # source + neutral core
        here.parent.parent.parent / "templates" / "LEARNINGS.md",  # legacy ~/.claude/bin/learnings
    )
    for template in candidates:
        raw = _read_file_capped(template, _CORPUS_RECORD_MAX_BYTES)
        if raw is not None:
            return raw
    raise RuntimeError("cannot read canonical LEARNINGS template")


def _create_initial_revision(project_key: str, revision: str | None = None) -> tuple[str, Path]:
    revision = revision or f"rev-{uuid.uuid4().hex}"
    corpus_root = corpora_root()
    if corpus_root is None:
        raise ValueError("neutral corpus root is unavailable")
    corpus_root.mkdir(parents=True, exist_ok=True, mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
    project_dir = corpus_project_dir(project_key)
    project_dir.mkdir(exist_ok=True, mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
    revisions = project_dir / "revisions"
    revisions.mkdir(exist_ok=True, mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
    destination = corpus_revision_dir(project_key, revision)
    temporary = destination.parent / f".{revision}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    temporary.mkdir(mode=EXTERNAL_CORPUS_DIRECTORY_MODE)
    try:
        raw = _template_bytes()
        _write_new_fsynced(temporary / "LEARNINGS.md", raw)
        _fsync_dir(temporary)
        os.rename(temporary, destination)
        _fsync_dir(destination.parent)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        raise
    return revision, destination


def ensure_project_corpus(
    project_root: Path | str, *, target_revision: str | None = None
) -> CorpusLocation:
    """Explicitly publish one template-backed external corpus, never implicitly."""
    root = _validated_project_root(project_root)
    git_top = _git(root, "rev-parse", "--show-toplevel")
    if git_top:
        root = Path(git_top).resolve()
    try:
        existing = resolve_project_corpus_strict(root)
    except CorpusResolutionError as exc:
        raise IdentityResolutionError(str(exc)) from exc
    if existing is not None and existing.mode == "legacy-repository":
        return existing
    if existing is not None and existing.mode == "external":
        if activation_status().state != ACTIVATION_VALID:
            raise IdentityResolutionError("external corpus is read-only until neutral activation is valid")
        identity = project_identity(root)
        with activity_lock():
            write_state = _corpus_write_state()
            if _malformed_active_record_has_authority(
                root, identity, write_state, activation_status()
            ):
                raise IdentityResolutionError("an active external corpus record is malformed")
            with _corpus_lock(existing.project_key):
                record = read_corpus_active_record(existing.project_key)
                if record is None:
                    raise IdentityResolutionError("active corpus record became invalid")
                _record, location = _add_observed_root(root, identity, existing.project_key, record)
                pending = corpus_project_dir(existing.project_key) / _CORPUS_INIT_PENDING_NAME
                if pending.exists():
                    pending_record = _read_corpus_record(pending)
                    if not _init_pending_is_valid(pending_record, existing.project_key, record["active_revision"]):
                        raise IdentityResolutionError("external corpus init recovery evidence is malformed")
                    _replace_corpus_epoch()
                    pending.unlink()
                    _fsync_dir(pending.parent)
        return location
    if activation_status().state != ACTIVATION_VALID:
        raise IdentityResolutionError("external corpus initialization requires valid neutral activation")
    if _legacy_corpus_present(root):
        raise IdentityResolutionError("foreign repository corpus requires explicit conflict handling")
    identity = project_identity(root)
    with activity_lock():
        write_state = _corpus_write_state()
        if _malformed_active_record_has_authority(
            root, identity, write_state, activation_status()
        ):
            raise IdentityResolutionError("an active external corpus record is malformed")
        catalog_key = resolve_or_derive_key(write_state.root, root, identity=identity)
        if catalog_key != identity.key:
            identity = ProjectIdentity(identity.canonical, identity.display, catalog_key)
        while True:
            existing_record = _active_record_for_canonical(identity.canonical)
            target_key = existing_record[0] if existing_record is not None else identity.key
            with _corpus_lock(target_key):
                existing_record = _active_record_for_canonical(identity.canonical)
                if existing_record is not None:
                    key, _record = existing_record
                    if key != target_key:
                        continue
                    record = read_corpus_active_record(key)
                    if record is None:
                        raise IdentityResolutionError("active corpus record became invalid")
                    _record, location = _add_observed_root(root, identity, key, record)
                    return location
                if target_key != identity.key:
                    continue
                if _legacy_corpus_present(root):
                    raise IdentityResolutionError("foreign repository corpus requires explicit conflict handling")
                catalog_key = ensure_project_record(write_state.root, root, identity=identity)
                if catalog_key != identity.key:
                    raise IdentityResolutionError("project identity changed during external corpus initialization")
                if _legacy_corpus_present(root):
                    raise IdentityResolutionError("foreign repository corpus requires explicit conflict handling")
                if target_revision is None:
                    revision, destination = _create_initial_revision(identity.key)
                else:
                    revision, destination = _create_initial_revision(
                        identity.key, target_revision
                    )
                record = build_corpus_active_record(identity, root, revision)
                pending = corpus_project_dir(identity.key) / _CORPUS_INIT_PENDING_NAME
                _replace_transition_json(
                    pending,
                    {
                        "schema_version": CORPUS_INIT_PENDING_SCHEMA_VERSION,
                        "project_key": identity.key,
                        "revision": revision,
                    },
                    "init-pending",
                )
                # A fresh checkout otherwise has no cutover projection, so
                # `learn corpus publish|unpublish|import` refuse it as
                # "unprojected" forever. Record the empty-repository baseline
                # projection now, before the active record, so a crash before
                # this point retries with no projection yet (harmless) rather
                # than an active record with none.
                maps = _transition_maps_from_directory(destination)
                if maps is None:
                    raise ValueError("initial corpus revision is not a readable corpus directory")
                projection_path = corpus_projection_path(identity.key, root)
                _ensure_transition_directory(projection_path.parent, "projections")
                write_corpus_projection_record(
                    identity.key,
                    root,
                    build_corpus_projection_record(identity.key, root, revision, {}, maps[0]),
                )
                _crash_point("init-after-projection-before-active")
                write_corpus_active_record(identity.key, record)
                _crash_point("init-after-active-before-epoch")
                _replace_corpus_epoch()
                pending.unlink()
                _fsync_dir(pending.parent)
                return CorpusLocation(root, identity.key, destination, corpus_lock_path(identity.key), "external")


def _repository_corpus_artifact_blockers(root: Path) -> tuple[str, ...]:
    """Reject every checkout corpus-shaped artifact before fresh authority.

    `ensure_project_corpus` predates topic and portable files.  Init and
    registration are the only fresh-authority callers, so keep the broader
    transition guard here rather than widening normal corpus resolution.
    """
    try:
        artifacts = corpus_artifact_paths(root)
    except ValueError as exc:
        return (f"repository corpus artifact is unsafe: {exc}",)
    if not artifacts:
        return ()
    names = ", ".join(path.name for path in artifacts)
    primary = root / "LEARNINGS.md"
    if primary in artifacts and _system_owned_legacy_corpus(root):
        return (
            "repository has a committed system-owned legacy corpus; run "
            f"learn corpus import --cwd {root}",
        )
    return (f"repository corpus artifacts block fresh initialization: {names}",)


def _deployment_owned_legacy_artifacts_only(legacy: Path) -> bool:
    """A lone shipped artifact is executable metadata, never corpus authority."""
    try:
        entries = tuple(legacy.iterdir())
    except OSError:
        return False
    if len(entries) != 1 or entries[0].name != "ARTIFACTS.md":
        return False
    artifact = entries[0]
    raw = _read_file_capped(artifact, _CORPUS_RECORD_MAX_BYTES)
    if raw is None:
        return False
    configured = os.environ.get("LEARNINGS_CORE_HOME")
    if configured:
        core_root = _safe_absolute(configured)
    else:
        core_root = _home() / ".local" / "share" / "learnings-md-system"
    here = Path(__file__).resolve()
    candidates = [
        here.parent.parent / "ARTIFACTS.md",
        here.parent.parent / "docs" / "ARTIFACTS.md",
    ]
    if core_root is not None:
        candidates.insert(0, core_root / "ARTIFACTS.md")
    for candidate in candidates:
        # A configured core must not turn the legacy input into its own proof.
        try:
            same_file = os.path.samefile(candidate, artifact)
        except OSError:
            same_file = False
        if same_file:
            continue
        canonical = _read_file_capped(candidate, _CORPUS_RECORD_MAX_BYTES)
        if canonical is not None and canonical == raw:
            return True
    return False


def _fresh_neutral_state_check() -> FreshNeutralStateCheck:
    """Prove that bootstrap cannot overwrite or reinterpret machine state."""
    neutral = _neutral_root()
    if neutral is None:
        return FreshNeutralStateCheck(
            "error", ("neutral state root is unresolvable (unsafe XDG_STATE_HOME/HOME)",)
        )
    blockers: list[str] = []
    try:
        neutral_present = neutral.exists() or neutral.is_symlink()
    except OSError as exc:
        return FreshNeutralStateCheck("error", (f"cannot inspect neutral state: {exc}",))
    if neutral_present:
        # An empty directory can have been provisioned by an installer.  It is
        # harmless; every durable authority artifact is not.
        for name in (_ACTIVATION_NAME, _DEACTIVATED_NAME, "generations", "corpora"):
            if (neutral / name).exists() or (neutral / name).is_symlink():
                blockers.append(f"neutral state already contains {name}")
    legacy = default_legacy_root()
    try:
        if legacy.exists() and any(legacy.iterdir()) and not _deployment_owned_legacy_artifacts_only(legacy):
            blockers.append("importable legacy state is present")
    except OSError as exc:
        return FreshNeutralStateCheck("error", (f"cannot inspect legacy state: {exc}",))
    return FreshNeutralStateCheck("blocked" if blockers else "fresh", tuple(blockers))


def _fresh_neutral_state_blockers() -> tuple[str, ...]:
    """Compatibility accessor for read-only planners."""
    return _fresh_neutral_state_check().blockers


def bootstrap_empty_neutral_state() -> BootstrapOutcome:
    """Create the canonical empty generation only on a proven empty machine."""
    neutral = _neutral_root()
    if neutral is None:
        return BootstrapOutcome("blocked", None, ("neutral state root is unresolvable",), ())
    # A deploy may die after publishing its verified empty generation but
    # before activation.  That exact tree is ours, not foreign state: adopt it
    # only when it is the sole bootstrap candidate and validates byte-for-byte.
    generations = neutral / "generations"
    if activation_status().state == ACTIVATION_ABSENT and generations.is_dir():
        for partial in generations.glob(".bootstrap-*.tmp-*"):
            if partial.is_dir() and not partial.is_symlink():
                shutil.rmtree(partial, ignore_errors=True)
        entries = tuple(sorted(generations.iterdir(), key=lambda path: path.name))
        candidates = tuple(
            path
            for path in entries
            if re.fullmatch(r"bootstrap-[0-9a-f]{32}", path.name)
            and path.is_dir()
            and not path.is_symlink()
        )
        competing_state = any(
            (neutral / name).exists() or (neutral / name).is_symlink()
            for name in (_DEACTIVATED_NAME, "corpora")
        )
        if not competing_state and len(entries) == len(candidates) == 1:
            generation = candidates[0].name
            manifest_raw = _read_file_capped(candidates[0] / _MANIFEST_NAME)
            manifest = None
            if manifest_raw is not None:
                with contextlib.suppress(ValueError, UnicodeDecodeError):
                    manifest = json.loads(manifest_raw.decode("utf-8"))
            expected_manifest = {
                "schema_version": IMPORT_MANIFEST_SCHEMA_VERSION,
                "import_id": generation,
                "source_root": str(default_legacy_root()),
                "source_inventory_digest": source_inventory_digest(default_legacy_root()),
                "entries": {}, "sources": [], "merges": [], "reports": [], "resets": [],
                "preferences": [], "notes": ["canonical empty bootstrap"],
            }
            if manifest == expected_manifest and verify_generation(candidates[0], generation) is None:
                _replace_json_fsynced(neutral / _ACTIVATION_NAME, build_activation_record(generation))
                return BootstrapOutcome("activated", generation, (), ("adopted verified interrupted empty bootstrap",))
        if not entries:
            with contextlib.suppress(OSError):
                generations.rmdir()
    freshness = _fresh_neutral_state_check()
    if freshness.status == "error":
        return BootstrapOutcome("error", None, freshness.blockers, ())
    if freshness.blockers:
        return BootstrapOutcome("blocked", None, freshness.blockers, ())
    generation = f"bootstrap-{uuid.uuid4().hex}"
    staging = neutral / "generations" / f".{generation}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    destination = neutral / "generations" / generation
    try:
        staging.mkdir(parents=True)
        # Empty state still uses the normal generation and manifest formats;
        # no hand-maintained digest or parallel schema is introduced.
        inventory_digest = source_inventory_digest(default_legacy_root())
        manifest = {
            "schema_version": IMPORT_MANIFEST_SCHEMA_VERSION,
            "import_id": generation,
            "source_root": str(default_legacy_root()),
            "source_inventory_digest": inventory_digest,
            "entries": {},
            "sources": [], "merges": [], "reports": [], "resets": [],
            "preferences": [], "notes": ["canonical empty bootstrap"],
        }
        manifest_bytes = _canonical_json_bytes(manifest)
        _write_new_fsynced(staging / _MANIFEST_NAME, manifest_bytes)
        _write_new_fsynced(
            staging / _GENERATION_NAME,
            _canonical_json_bytes(build_generation_record(
                generation,
                source_inventory_digest=inventory_digest,
                staged_manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
            )),
        )
        _fsync_dir(staging)
        _crash_point("bootstrap-after-staging")
        problem = verify_generation(staging, generation)
        if problem:
            return BootstrapOutcome("error", None, (f"empty generation verification failed: {problem}",), ())
        os.rename(staging, destination)
        _fsync_dir(destination.parent)
        _crash_point("bootstrap-after-generation-rename")
        _replace_json_fsynced(neutral / _ACTIVATION_NAME, build_activation_record(generation))
    except OSError as exc:
        return BootstrapOutcome("error", None, (f"empty bootstrap failed: {exc}",), ())
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    check = activation_status()
    if check.state != ACTIVATION_VALID or check.generation != generation:
        return BootstrapOutcome("error", None, ("empty bootstrap activation did not verify",), ())
    return BootstrapOutcome("activated", generation, (), ("created canonical empty neutral generation",))


def plan_project_corpus_init(project_root: Path | str) -> CorpusTransitionPlan:
    """Describe fresh template-backed initialization without writing state."""
    root = _validated_project_root(project_root)
    identity = project_identity(root)
    neutral = _neutral_root()
    if neutral is None:
        raise ValueError("neutral corpus root is unavailable")
    blockers = list(_repository_corpus_artifact_blockers(root))
    status = activation_status()
    bootstrap_needed = status.state != ACTIVATION_VALID
    if bootstrap_needed:
        blockers.extend(_fresh_neutral_state_blockers())
    try:
        key = resolve_or_derive_key(neutral, root, identity=identity)
    except IdentityResolutionError as exc:
        key = identity.key
        blockers.append(f"project identity is ambiguous: {exc}")
    try:
        active = read_corpus_active_record(key)
    except ValueError as exc:
        active = None
        blockers.append(f"existing corpus authority is malformed: {exc}")
    active_revision = _valid_active_revision(key, active) if active is not None else None
    resumes_interrupted_init = False
    if active_revision is None:
        authority_blockers = list(_transition_authority_blockers(key, root))
        # A fresh init that crashed after its marker but before the active
        # record leaves a project directory with no authority at all. That is
        # this verb's own interrupted work, not damage: retry replaces it.
        if authority_blockers == [_NO_AUTHORITY_BLOCKER] and _interrupted_init_pending(key):
            resumes_interrupted_init = True
        else:
            blockers.extend(authority_blockers)
    deployment = cutover_deployment_status()
    if active_revision is None and deployment["status"] != "current":
        blockers.append(f"cutover deployment is {deployment['status']}: {deployment['reason']}")
    template = _template_bytes()
    digest = hashlib.sha256(template).hexdigest()
    revision = f"rev-{uuid.uuid4().hex}"
    notes = ["repository mutation: none", f"bootstrap needed: {'yes' if bootstrap_needed else 'no'}"]
    if resumes_interrupted_init:
        notes.append("an interrupted fresh init left its pending marker; retry replaces it")
    if active_revision is not None:
        blockers = [item for item in blockers if "project already has active external authority" not in item]
        notes.append("already-valid external authority is an idempotent no-op")
    record = deployment.get("record")
    deployment_revision = record.get("compatibility_revision") if isinstance(record, dict) else None
    return CorpusTransitionPlan(
        project_root=str(root), canonical_identity=identity.canonical, identity_key=identity.key,
        project_key=key, primary_status="fresh", source_files=(), target_digest=digest,
        target_revision=active_revision or revision, lesson_multiset_digest=hashlib.sha256(b"[]").hexdigest(),
        lesson_count=0, worktree_roots=(), structural_lock_paths=(), independent_clone_roots=(),
        identity_lock_path=str(corpus_lock_path(key)), projection_path=str(corpus_projection_path(key, root)),
        projection_id=observed_path_id(root), deployment_status=deployment["status"],
        deployment_revision=deployment_revision if isinstance(deployment_revision, int) else None,
        blockers=tuple(sorted(set(blockers))), notes=tuple(notes),
    )


def apply_project_corpus_init(
    plan_or_root: CorpusTransitionPlan | Path | str,
) -> CorpusTransitionOutcome:
    """Initialize through shared activity, deployment, and identity guards."""
    preview = (
        plan_or_root
        if isinstance(plan_or_root, CorpusTransitionPlan)
        else plan_project_corpus_init(_validated_project_root(plan_or_root))
    )
    root = _validated_project_root(preview.project_root)
    if preview.blockers:
        return CorpusTransitionOutcome("blocked", None, preview.blockers, (), preview)
    with activity_lock():
        deployment = _acquire_deployment_lock(exclusive=False, nonblocking=True)
        if deployment is None:
            return CorpusTransitionOutcome(
                "blocked",
                None,
                ("machine deployment is busy or unavailable; retry after deploy completes",),
                (),
                preview,
            )
        with deployment:
            # Re-plan only after the deployment gate is shared-held.  The
            # caller's preview owns the revision token; all other authority
            # facts must remain identical.
            current = plan_project_corpus_init(root)
            drift = _transition_plan_drift(preview, current)
            if drift:
                return CorpusTransitionOutcome(
                    "blocked", None,
                    (f"init plan changed while acquiring locks ({', '.join(drift)}); rerun apply",),
                    (), current,
                )
            plan = replace(current, target_revision=preview.target_revision)
            if plan.blockers:
                return CorpusTransitionOutcome("blocked", None, plan.blockers, (), plan)
            if activation_status().state != ACTIVATION_VALID:
                outcome = bootstrap_empty_neutral_state()
                if outcome.blockers:
                    return CorpusTransitionOutcome("blocked", None, outcome.blockers, outcome.notes, plan)
            if _repository_corpus_artifact_blockers(root):
                return CorpusTransitionOutcome("blocked", None, _repository_corpus_artifact_blockers(root), (), plan)
            try:
                location = ensure_project_corpus(root, target_revision=plan.target_revision)
            except IdentityResolutionError as exc:
                return CorpusTransitionOutcome("blocked", None, (str(exc),), (), plan)
    return CorpusTransitionOutcome("initialized", location.corpus_root.name, (), ("repository mutation: none",), plan)


def plan_corpus_relink(project_root: Path | str, project_key: str) -> CorpusRelinkPlan:
    """Report-only preview of re-linking an orphaned checkout to
    ``project_key``'s external corpus record.

    A checkout stops matching its record when BOTH its folder moves and its
    Git remote changes: neither ``observed_roots`` nor ``canonical_aliases``
    matches any more, so ordinary resolution and ``_add_observed_root``'s
    normal top-up both refuse. Relink is the explicit, guarded repair: every
    blocker here is re-checked again by ``apply_corpus_relink`` under both
    locks, so a record that changes between plan and apply blocks instead of
    silently overwriting a live project's corpus.
    """
    root = _validated_project_root(project_root)
    blockers: list[str] = []
    notes: list[str] = []

    if activation_status().state != ACTIVATION_VALID:
        blockers.append("neutral activation is not valid")

    record: dict | None = None
    active_revision: str | None = None
    if not is_project_key(project_key):
        blockers.append(f"invalid project key: {project_key!r}")
    else:
        malformed = False
        try:
            record = read_corpus_active_record(project_key)
        except ValueError as exc:
            blockers.append(f"active corpus record for {project_key!r} is malformed: {exc}")
            malformed = True
        if record is None and not malformed:
            try:
                deactivated = read_corpus_deactivated_record(project_key)
            except ValueError as exc:
                blockers.append(f"corpus record for {project_key!r} is malformed: {exc}")
                deactivated = None
            if deactivated is not None:
                blockers.append(
                    f"corpus authority for {project_key!r} is deactivated, not active; "
                    "relink requires an active record"
                )
            else:
                blockers.append(f"no active corpus record for project key {project_key!r}")

    if record is not None:
        active_revision = record["active_revision"]
        live_roots: list[str] = []
        for observed in record["observed_roots"]:
            try:
                still_present = Path(observed).exists()
            except OSError:
                still_present = True  # fail closed: an unreadable root is not proven absent
            if still_present:
                live_roots.append(observed)
        if live_roots:
            blockers.append(
                "recorded checkout root(s) still exist on disk, so this corpus is not "
                f"orphaned: {', '.join(sorted(live_roots))}"
            )
        notes.append(
            "confirm this is the same project: the record's canonical aliases are "
            f"{', '.join(record['canonical_aliases'])}; its recorded roots are "
            f"{', '.join(record['observed_roots'])}"
        )
        try:
            notes.append(_relink_projection_note(project_key, record, root))
        except ValueError as exc:
            blockers.append(f"checkout projection is malformed: {exc}")

    try:
        current_location = resolve_project_corpus_strict(root)
    except CorpusResolutionError as exc:
        blockers.append(f"cannot determine current corpus authority: {exc}")
        current_location = None
    if current_location is not None and current_location.mode == "external":
        blockers.append(
            "checkout already resolves to an active external corpus (project key "
            f"{current_location.project_key!r}); relink is unnecessary"
        )

    if _system_owned_legacy_corpus(root):
        blockers.append(
            "checkout carries a system-owned legacy corpus; run `learn corpus import`, not relink"
        )

    identity: ProjectIdentity | None = None
    try:
        identity = project_identity(root)
    except IdentityResolutionError as exc:
        blockers.append(f"identity probe failed: {exc}")

    if identity is not None:
        try:
            active_records = tuple(_iter_active_corpus_records() or ())
        except OSError as exc:
            blockers.append(f"corpus authority scan failed: {exc}")
            active_records = ()
        for other_key, other_record, _active in active_records:
            if other_key == project_key or other_record is None:
                continue
            if identity.canonical in other_record["canonical_aliases"]:
                blockers.append(
                    "checkout identity is already claimed by a different active corpus "
                    f"record (project key {other_key!r})"
                )
                break

    try:
        artifacts = corpus_artifact_paths(root)
    except ValueError as exc:
        notes.append(f"cannot enumerate repository corpus artifacts: {exc}")
        artifacts = []
    if artifacts:
        names = ", ".join(path.name for path in artifacts)
        notes.append(
            f"repository corpus-shaped file(s) present and left untouched: {names}; "
            "retire them separately with `learn corpus retire`"
        )

    return CorpusRelinkPlan(
        project_root=str(root),
        canonical_identity=identity.canonical if identity is not None else None,
        project_key=project_key,
        active_revision=active_revision,
        blockers=tuple(sorted(set(blockers))),
        notes=tuple(notes),
    )


def apply_corpus_relink(plan: CorpusRelinkPlan) -> CorpusTransitionOutcome:
    """Apply a previously reported ``plan_corpus_relink`` plan.

    Modeled on ``ensure_project_corpus``'s existing-external-record branch:
    the same activity lock, write-state authorization, malformed-record
    authority check, and per-key identity lock. Every blocker is recomputed
    under both locks by re-running ``plan_corpus_relink``; a record that
    changed since ``plan`` was built blocks the apply and writes nothing.
    """
    root = _validated_project_root(plan.project_root)
    if plan.blockers:
        return CorpusTransitionOutcome("blocked", None, plan.blockers, (), plan)
    try:
        with activity_lock():
            write_state = _corpus_write_state()
            identity = project_identity(root)
            if _malformed_active_record_has_authority(root, identity, write_state, activation_status()):
                return CorpusTransitionOutcome(
                    "blocked", None, ("an active external corpus record is malformed",), (), plan
                )
            with _corpus_lock(plan.project_key):
                current = plan_corpus_relink(root, plan.project_key)
                if current.blockers:
                    return CorpusTransitionOutcome("blocked", None, current.blockers, (), current)
                record = read_corpus_active_record(plan.project_key)
                if record is None:
                    return CorpusTransitionOutcome(
                        "blocked", None, ("active corpus record became invalid",), (), current
                    )
                updated = dict(record)
                updated["observed_roots"] = [str(root)]
                updated["canonical_aliases"] = sorted({*record["canonical_aliases"], identity.canonical})
                # The projection lands first: if its write fails, the active
                # record still names the old root and relink can be rerun.
                carried = _carry_projection_to_relinked_root(plan.project_key, record, root)
                write_corpus_active_record(plan.project_key, updated)
                _replace_corpus_epoch()
    except IdentityResolutionError as exc:
        return CorpusTransitionOutcome("blocked", None, (str(exc),), (), plan)
    notes = (f"relinked checkout at {root}",)
    if carried is not None:
        notes += (f"carried the checkout projection from {carried}",)
    return CorpusTransitionOutcome("relinked", record["active_revision"], (), notes, current)


def _relink_projection_candidates(project_key: str, record: dict) -> list[tuple[str, Path, dict]]:
    """Current projections recorded for the record's departing roots.

    A projection is current when it names the active or previous revision.
    The departing roots are absent from disk, so their projection paths are
    derived directly instead of through ``corpus_projection_path``.
    """
    projections = corpus_project_dir(project_key) / "projections"
    candidates: list[tuple[str, Path, dict]] = []
    for departing in record["observed_roots"]:
        path = projections / f"{_observed_root_id(Path(departing))}.json"
        try:
            projection = _read_corpus_record(path)
        except (OSError, ValueError):
            continue
        if (
            not corpus_projection_record_is_valid(projection, project_key=project_key)
            or projection["observed_root"] != departing
            or projection["revision"] not in {record["active_revision"], record["previous_revision"]}
        ):
            continue
        candidates.append((departing, path, projection))
    return candidates


def _relink_projection_note(project_key: str, record: dict, root: Path) -> str:
    if read_corpus_projection_record(project_key, root) is not None:
        return "the checkout already has a projection; none is carried"
    candidates = _relink_projection_candidates(project_key, record)
    if len(candidates) == 1:
        return f"the checkout projection will be carried from {candidates[0][0]}"
    if candidates:
        roots = ", ".join(sorted(item[0] for item in candidates))
        return (
            f"{len(candidates)} departing roots carry current projections ({roots}); none is "
            "carried, and the checkout stays unprojected until the next publish"
        )
    return "no departing root carries a current projection; the checkout stays unprojected"


def _carry_projection_to_relinked_root(project_key: str, record: dict, root: Path) -> str | None:
    """Move a departing root's current projection to the relinked root.

    Publish and unpublish refuse a checkout with no projection, so a relink
    that left the record behind under the old path would strand the checkout
    in ``pending-stale``. Projection state is per checkout, so only a sole
    candidate is carried; the old file is removed after the new one is
    durable. Returns the departing root the projection came from, or None.
    """
    if read_corpus_projection_record(project_key, root) is not None:
        return None
    candidates = _relink_projection_candidates(project_key, record)
    if len(candidates) != 1:
        return None
    departing, path, projection = candidates[0]
    write_corpus_projection_record(
        project_key,
        root,
        build_corpus_projection_record(
            project_key,
            root,
            projection["revision"],
            projection["repository_files"],
            projection["corpus_files"],
        ),
    )
    path.unlink(missing_ok=True)
    _fsync_dir(path.parent)
    return departing


def register_project_corpus(project_root: Path | str) -> RegistrationOutcome:
    """Shared fresh-registration core; callers perform host qualification first."""
    root = _validated_project_root(project_root)
    if activation_status().state != ACTIVATION_VALID:
        return RegistrationOutcome("blocked", str(root), None, ("valid neutral activation is required",), ())
    blockers = _repository_corpus_artifact_blockers(root)
    if blockers:
        return RegistrationOutcome("blocked", str(root), None, blockers, ())
    try:
        outcome = apply_project_corpus_init(root)
    except (OSError, ValueError, IdentityResolutionError) as exc:
        return RegistrationOutcome("blocked", str(root), None, (str(exc),), ())
    if outcome.blockers:
        return RegistrationOutcome("blocked", str(root), None, outcome.blockers, outcome.notes)
    project_key = outcome.plan.project_key if outcome.plan else None
    return RegistrationOutcome("registered", str(root), project_key, (), outcome.notes)


def _active_corpus_transition_guard() -> str | None:
    """Machine transitions cannot hide any present external authority record."""
    root = corpora_root()
    if root is None or not root.exists():
        return None
    blockers: list[str] = []
    try:
        pending = plan_abandon_external_corpora()
    except ValueError as exc:
        return f"external abandonment evidence is malformed: {exc}"
    for key, _path, _digest, _size, _roots, _revisions, phase in pending.records:
        if phase == "pending":
            blockers.append(f"{key} (pending abandonment must be completed first)")
    for row in inspect_active_corpus_authority():
        key = row["project_key"]
        status = row["status"]
        if status in {"external", "pending-stale"}:
            blockers.append(f"{key} ({status}: {row.get('reason') or 'active authority'})")
            continue
        if status not in {"malformed", "dangling"} or not isinstance(key, str):
            continue
        active = root / key / _CORPUS_ACTIVE_NAME
        if active.exists() or active.is_symlink():
            blockers.append(f"{key} ({status}: {row.get('reason') or 'active authority'})")
    if not blockers:
        return None
    return "active external corpus records block machine transition: " + "; ".join(sorted(blockers))


def plan_abandon_external_corpora() -> AbandonExternalPlan:
    """List every raw active project authority without changing disk state."""
    root = corpora_root()
    if root is None or not root.is_dir() or root.is_symlink():
        return AbandonExternalPlan(())
    neutral = _neutral_root()
    if neutral is None:
        return AbandonExternalPlan(())
    pending: dict[str, dict] = {}
    complete: set[str] = set()
    notices = neutral / "operator-notices"
    try:
        notice_paths = sorted(notices.glob("abandoned-*.json"))
    except OSError:
        notice_paths = []
    for path in notice_paths:
        try:
            notice = _read_corpus_record(path)
        except (OSError, ValueError) as exc:
            raise ValueError(f"abandonment notice is malformed: {path}: {exc}") from None
        if not _abandon_notice_is_valid(notice):
            raise ValueError(f"abandonment notice is malformed: {path}")
        key = notice["project_key"]
        expected_path = root / key / _CORPUS_ACTIVE_NAME
        if path.name != f"abandoned-{key}.json" or notice["active_path"] != str(
            expected_path
        ):
            raise ValueError(f"abandonment notice identity is inconsistent: {path}")
        if notice["phase"] == "pending":
            pending[key] = notice
        else:
            complete.add(key)
    records: list[tuple[str, str, str | None, int | None, tuple[str, ...], tuple[str, ...], str | None]] = []
    for key, record, active in _iter_active_corpus_records() or ():
        if key in complete:
            raise ValueError(f"complete abandonment evidence conflicts with newly present active authority: {key}")
        roots: tuple[str, ...] = ()
        if record is not None:
            roots = tuple(record.get("observed_roots", ()))
        revisions_dir = root / key / "revisions"
        try:
            revisions = tuple(sorted(
                entry.name for entry in revisions_dir.iterdir()
                if _CORPUS_REVISION_RE.fullmatch(entry.name)
            ))
        except OSError:
            revisions = ()
        raw = _raw_authority_digest(active)
        if raw is None:
            raise ValueError(f"active authority bytes are unreadable: {active}")
        phase = "pending" if key in pending else None
        records.append((key, str(active), raw[0], raw[1], roots, revisions, phase))
        pending.pop(key, None)
    for key, notice in pending.items():
        project_dir = root / key
        revisions_dir = project_dir / "revisions"
        try:
            revisions = tuple(sorted(
                entry.name for entry in revisions_dir.iterdir() if _CORPUS_REVISION_RE.fullmatch(entry.name)
            ))
        except OSError:
            revisions = ()
        records.append((
            key, notice["active_path"], notice["raw_sha256"], notice["raw_size"], (), revisions, "pending"
        ))
    return AbandonExternalPlan(tuple(sorted(records, key=lambda item: item[0])))


def _safe_authority_child_key(value: object) -> bool:
    """One direct corpus child name; deliberately broader than a valid identity key."""
    return (
        isinstance(value, str)
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value))
        and value not in {".", ".."}
    )


def _abandon_notice_is_valid(record: object) -> bool:
    return (
        isinstance(record, dict)
        and set(record) == {"schema_version", "project_key", "active_path", "raw_sha256", "raw_size", "phase"}
        and record.get("schema_version") == CORPUS_ABANDON_NOTICE_SCHEMA_VERSION
        and _safe_authority_child_key(record.get("project_key"))
        and isinstance(record.get("active_path"), str) and Path(record["active_path"]).is_absolute()
        and isinstance(record.get("raw_sha256"), str) and _SHA256_HEX_RE.fullmatch(record["raw_sha256"])
        and isinstance(record.get("raw_size"), int)
        and not isinstance(record["raw_size"], bool)
        and record["raw_size"] >= 0
        and record.get("phase") in {"pending", "complete"}
    )


def _write_abandon_notice(neutral: Path, key: str, active: Path, raw: tuple[str, int], phase: str) -> None:
    notices = neutral / "operator-notices"
    _ensure_transition_directory(notices, "abandon-notices")
    record = {
        "schema_version": CORPUS_ABANDON_NOTICE_SCHEMA_VERSION,
        "project_key": key,
        "active_path": str(active),
        "raw_sha256": raw[0],
        "raw_size": raw[1],
        "phase": phase,
    }
    if not _abandon_notice_is_valid(record):
        raise _ProjectCorpusTransitionBlocked("abandonment notice is invalid")
    _replace_transition_json(
        notices / f"abandoned-{key}.json",
        record, f"abandon-{phase}",
    )


def _recover_abandon_notice_temps(neutral: Path) -> None:
    """Quarantine only exact owned notice temps before replanning."""
    notices = neutral / "operator-notices"
    if not notices.exists():
        return
    if notices.is_symlink() or not notices.is_dir():
        raise _ProjectCorpusTransitionBlocked("operator notice directory is unsafe")
    pattern = re.compile(
        r"\.abandoned-[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json"
        r"\.tmp-\d+-[0-9a-f]{8}"
    )
    candidates = [path for path in notices.iterdir() if pattern.fullmatch(path.name)]
    if not candidates:
        return
    quarantine = notices / "quarantine"
    _ensure_transition_directory(quarantine, "abandon-notice-quarantine")
    for path in sorted(candidates, key=lambda item: item.name):
        if not _regular_single_link(path):
            raise _ProjectCorpusTransitionBlocked(
                f"owned abandonment notice temp is unsafe: {path}"
            )
        os.rename(path, quarantine / f"{path.name}-{uuid.uuid4().hex[:8]}")
        _fsync_dir(quarantine)
        _fsync_dir(notices)


def abandon_external_corpora(plan: AbandonExternalPlan | None = None) -> tuple[str, ...]:
    """Break-glass abandon raw authorities one key at a time, retrying disk truth."""
    preview = plan or plan_abandon_external_corpora()
    if not preview.records:
        return ()
    activity = try_activity_exclusive()
    if activity is None:
        raise _ProjectCorpusTransitionBlocked("offline maintenance window is busy; nothing was abandoned")
    locks: list[_ActivityLock] = []
    try:
        try:
            workers = scan_legacy_workers()
        except RuntimeError as exc:
            raise _ProjectCorpusTransitionBlocked(f"worker census unavailable: {exc}") from None
        if workers:
            details = ", ".join(f"pid {worker.pid} ({worker.fingerprint})" for worker in workers)
            raise _ProjectCorpusTransitionBlocked(f"live legacy worker: {details}")
        neutral = _neutral_root()
        if neutral is None:
            raise _ProjectCorpusTransitionBlocked("neutral corpus root is unavailable")
        _recover_abandon_notice_temps(neutral)
        current = plan_abandon_external_corpora()
        reported = {record[0]: record for record in preview.records}
        observed = {record[0]: record for record in current.records}
        for key, record in observed.items():
            prior = reported.get(key)
            if prior is None:
                raise _ProjectCorpusTransitionBlocked(f"unreported active external authority appeared: {key}")
            if (
                prior[2:6] != record[2:6]
                and not (prior[6] == record[6] == "pending")
            ):
                raise _ProjectCorpusTransitionBlocked(f"reported external authority changed: {key}")
        for key, record in reported.items():
            if key not in observed and record[6] != "pending":
                raise _ProjectCorpusTransitionBlocked(f"reported external authority disappeared: {key}")
        for key, _path, _digest, _size, _roots, _revisions, _pending in current.records:
            if not is_project_key(key):
                continue
            lock = _acquire_corpus_identity_lock(corpus_lock_path(key), nonblocking=True)
            if lock is None:
                raise _ProjectCorpusTransitionBlocked(f"project corpus identity is busy: {key}")
            locks.append(lock)
        moved: list[str] = []
        for key, raw_path, digest, size, _roots, _revisions, _pending_state in current.records:
            active = Path(raw_path)
            project_dir = active.parent
            deactivated = project_dir / _CORPUS_DEACTIVATED_NAME
            _recover_transition_json_temps(project_dir)
            notice_path = neutral / "operator-notices" / f"abandoned-{key}.json"
            notice = _read_corpus_record(notice_path) if notice_path.exists() else None
            if notice is None:
                if digest is None or size is None:
                    raise _ProjectCorpusTransitionBlocked(f"raw authority evidence is unavailable: {key}")
                _write_abandon_notice(neutral, key, active, (digest, size), "pending")
                notice = _read_corpus_record(notice_path)
            if not _abandon_notice_is_valid(notice) or notice["phase"] not in {"pending", "complete"}:
                raise _ProjectCorpusTransitionBlocked(f"abandonment notice is malformed: {key}")
            if notice["phase"] == "complete":
                continue
            raw = _raw_authority_digest(active)
            if raw is None:
                raw = _raw_authority_digest(deactivated)
                if raw is None or raw != (notice["raw_sha256"], notice["raw_size"]):
                    raise _ProjectCorpusTransitionBlocked(f"pending abandonment evidence is missing or changed: {key}")
            elif raw != (notice["raw_sha256"], notice["raw_size"]):
                raise _ProjectCorpusTransitionBlocked(f"pending active authority changed: {key}")
            active_present = active.exists() or active.is_symlink()
            if active_present and (deactivated.exists() or deactivated.is_symlink()):
                history = project_dir / f"deactivated-history-{uuid.uuid4().hex[:16]}.json"
                _crash_point("cutover-before-abandon-history-rename")
                os.replace(deactivated, history)
                _crash_point("cutover-after-abandon-history-rename")
                _crash_point("cutover-before-abandon-history-parent-fsync")
                _fsync_dir(project_dir)
                _crash_point("cutover-after-abandon-history-parent-fsync")
            if active_present:
                _crash_point("cutover-before-abandon-rename")
                os.replace(active, deactivated)
                _crash_point("cutover-after-abandon-rename")
                _crash_point("cutover-before-abandon-parent-fsync")
                _fsync_dir(project_dir)
                _crash_point("cutover-after-abandon-parent-fsync")
            _replace_transition_json(corpus_epoch_path(), build_corpus_epoch_record(), "abandon-epoch")
            _crash_point("cutover-after-abandon-record")
            _write_abandon_notice(neutral, key, active, (notice["raw_sha256"], notice["raw_size"]), "complete")
            moved.append(key)
        return tuple(moved)
    finally:
        for lock in reversed(locks):
            lock.close()
        activity.close()


# --- Part 3C: legacy-worker census (co-validation decision 8) ---------------

# Every learnings-*.sh entrypoint that writes corpus, pool, or movable state.
# A superset of the plan's "11 writers" phrasing: blocking on a read-mostly
# worker only delays apply, while missing a writer risks a torn import, so
# the census fingerprints every worker script that mutates anything.
CENSUS_WORKER_SCRIPTS = frozenset(
    {
        "learnings-write.sh",
        "learnings-index.sh",
        "learnings-retire.sh",
        "learnings-register.sh",
        # Deleted 2026-09-07 (worker trim, then the `learn sync` retirement
        # once its last in-repo corpus moved to the store), kept as legacy
        # fingerprints: a
        # process started before the deploy removed the script can still be
        # mutating the state formats `apply_import` migrates (mined/, the
        # rules and pending ledgers), and the lock probes only catch it
        # while it holds a lock. Drop these once those formats stop being
        # imported.
        "learnings-mine.sh",
        "learnings-fold.sh",
        "learnings-rules.sh",
        "learnings-review-retro.sh",
        "learnings-sync.sh",
    }
)

# Hook runners that spawn workers (decision 8 names the first four; the
# remaining lifecycle hooks spawn the same workers, so they fingerprint too).
CENSUS_HOOK_RUNNERS = frozenset(
    {
        "learning-on-start.py",
        "learning-on-failure.py",
        "codex-learnings-hook.py",
        "commit-learnings.sh",
        "scaffold-learnings.sh",
    }
)

# Mirror of bin/learn's mutating_commands (parity-pinned by
# tests/test_neutral_state.py); `state` is deliberately absent from both.
LEARN_MUTATING_SUBCOMMANDS = frozenset(
    {
        "add",
        "index",
        "migrate-ids",
        "cleanup",
    }
)

# This is intentionally a census-only contract until 7B3 exposes the verbs.
# Keep it separate from the top-level CLI set: `learn corpus status|baseline|drift`
# are read operations and must not make an importer wait for a reader.
LEARN_CORPUS_MUTATING_ACTIONS = frozenset(
    {"init", "import", "publish", "unpublish", "retire", "rollback", "relink"}
)
_LEARN_CORPUS_OPTION_ARITY = {"--cwd": 1, "--project-key": 1}

# argv[0] basenames that READ text as data: a fingerprint appearing among
# their operands (`grep learnings-mine.sh`, `git diff bin/learnings-mine.sh`,
# `vim learnings-rules.sh`) is content, not a running worker.
_CENSUS_ARGV0_DENYLIST = frozenset(
    {
        "grep", "egrep", "fgrep", "ggrep", "rg", "ack", "ag",
        "git", "diff", "less", "more", "tail", "head", "cat", "bat",
        "vi", "vim", "nvim", "emacs", "nano", "code", "open",
        "sed", "awk", "wc", "sort", "man",
    }
)


@dataclass(frozen=True)
class WorkerProcess:
    """One live legacy worker the census matched."""

    pid: int
    command: str
    fingerprint: str


def _census_rows() -> list[list]:
    """macOS `ps -ww` snapshot as [pid, ppid, stat, command] rows. Lines
    that do not open with valid pid/ppid/stat columns are continuations of
    the previous command (a literal newline in `python -c`/`sh -c` argv), so
    they are reassembled into that row's command — a worker operand cannot
    hide behind a newline. Fails loud when ps yields nothing: the census
    cannot prove absence from an empty snapshot."""
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        result = subprocess.run(
            ["ps", "-ww", "-axo", "pid=,ppid=,stat=,command="],
            capture_output=True, text=True, env=env, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"legacy-worker census failed: {exc}") from None
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(
            f"legacy-worker census failed: ps rc={result.returncode}"
        )
    rows: list[list] = []
    pattern = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$")
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if match:
            rows.append([int(match.group(1)), int(match.group(2)), match.group(3), match.group(4)])
        elif rows:
            rows[-1][3] += "\n" + line
    return rows


def _match_worker_fingerprint(command: str) -> str | None:
    """Tokenized, locale-stable argv matching. Exact basename match against
    the worker/hook fingerprints anywhere in the argv (wrapper chains such
    as `uv run --script /path/learnings-mine.sh` included); `learn` matches
    only when its first non-flag operand is a mutating subcommand, and a
    worker name among learn's LATER operands is data (`learn search
    learnings-mine.sh`), not a running worker. Reader processes (argv[0] in
    the denylist) never match. Tokens split on whitespace AND on ps's
    `\\NNN` control-char escapes (macOS renders a literal newline in argv as
    `\\012` inside one row), so a newline cannot glue a worker operand onto
    a non-matching token. Runs of shell-operator characters (`;`, `&`,
    `|`) are further split into their own tokens, so a compact
    `learn search x;learnings-mine.sh` cannot glue an operator to an
    operand and hide the worker. A non-mutating `learn` claims its
    operands as data only up to the next shell-separator token (any token
    made solely of `;&|` characters — `&&`, `||`, `;`, `|`, `&`, `;;`) —
    scanning resumes after it, so a compound command cannot hide a
    trailing worker behind a leading `learn search`. This deliberately
    errs toward matching: argv is reconstructed from ps WITHOUT quoting,
    so a quoted data argument containing an operator
    (`learn search "a;learnings-mine.sh"`) scans past the operator and
    can raise a spurious blocker — that false block costs one glance
    during a manual maintenance window, while a missed live worker risks
    state corruption."""
    tokens = [token for token in re.split(r"\s+|\\\d{3}", command) if token]
    tokens = [
        piece
        for token in tokens
        for piece in re.split(r"([;&|]+)", token)
        if piece
    ]
    if not tokens:
        return None
    if tokens[0].rsplit("/", 1)[-1] in _CENSUS_ARGV0_DENYLIST:
        return None
    index = 0
    while index < len(tokens):
        base = tokens[index].rsplit("/", 1)[-1]
        if base == "learnings-index.sh":
            cursor = index + 1
            preview = False
            while cursor < len(tokens) and not re.fullmatch(r"[;&|]+", tokens[cursor]):
                if tokens[cursor] == "--cwd":
                    cursor += 2
                    continue
                preview = preview or tokens[cursor] == "--dry-run"
                cursor += 1
            if not preview:
                return base
            index = cursor
            continue
        if base in CENSUS_WORKER_SCRIPTS or base in CENSUS_HOOK_RUNNERS:
            return base
        if base == "learn":
            if index + 1 < len(tokens) and tokens[index + 1] == "index":
                cursor = index + 2
                while cursor < len(tokens) and not re.fullmatch(r"[;&|]+", tokens[cursor]):
                    if tokens[cursor] == "--cwd":
                        cursor += 2
                        continue
                    if tokens[cursor] == "--apply":
                        return "learn index"
                    cursor += 1
                if cursor < len(tokens):
                    index = cursor
                    continue
                return None
            if index + 1 < len(tokens) and tokens[index + 1] == "corpus":
                cursor = index + 2
                while cursor < len(tokens) and not re.fullmatch(r"[;&|]+", tokens[cursor]):
                    token = tokens[cursor]
                    if token in _LEARN_CORPUS_OPTION_ARITY:
                        value_index = cursor + 1
                        if value_index >= len(tokens) or re.fullmatch(r"[;&|]+", tokens[value_index]):
                            break
                        cursor += _LEARN_CORPUS_OPTION_ARITY[token] + 1
                        continue
                    if token.startswith("-"):
                        cursor += 1
                        continue
                    if token in LEARN_CORPUS_MUTATING_ACTIONS:
                        return f"learn corpus {token}"
                    break
                while cursor < len(tokens) and not re.fullmatch(r"[;&|]+", tokens[cursor]):
                    cursor += 1
                if cursor < len(tokens):
                    index = cursor
                    continue
                return None
            for later in tokens[index + 1:]:
                if later.startswith("-"):
                    continue
                if later in LEARN_MUTATING_SUBCOMMANDS:
                    return f"learn {later}"
                break
            # learn's later operands are data up to the next shell
            # separator; without one, nothing after can be a worker.
            for separator_index in range(index + 1, len(tokens)):
                if re.fullmatch(r"[;&|]+", tokens[separator_index]):
                    index = separator_index
                    break
            else:
                return None
        index += 1
    return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def scan_legacy_workers() -> tuple[WorkerProcess, ...]:
    """The live-legacy-worker census (decision 8): every matched process
    blocks apply/activation. Excluded: this process, its ancestor chain,
    zombies, and this process's own descendant snapshot (the importer's ps,
    git, and helper subprocesses must not self-block). Candidate liveness is
    rechecked so an exited row cannot block. LEARNINGS_STATE_CENSUS_FILTER
    (test isolation only) NARROWS matching to commands containing the given
    marker; it can hide, never invent — production never sets it, and the
    decision-10 documented residual already covers uncoordinated spawns. The
    filter is honored only when LEARNINGS_STATE_CENSUS_FILTER_ACK=1
    accompanies it, so a filter export leaked into a real shell alone stays
    inert."""
    rows = _census_rows()
    ppid_of = {pid: ppid for pid, ppid, _stat, _command in rows}
    children: dict[int, list[int]] = {}
    for pid, ppid, _stat, _command in rows:
        children.setdefault(ppid, []).append(pid)
    self_pid = os.getpid()
    excluded = {self_pid}
    cursor = ppid_of.get(self_pid, os.getppid())
    seen: set[int] = set()
    while cursor and cursor > 0 and cursor not in seen:
        seen.add(cursor)
        excluded.add(cursor)
        cursor = ppid_of.get(cursor, 0)
    stack = [self_pid]
    while stack:
        for child in children.get(stack.pop(), ()):  # descendant snapshot
            if child not in excluded:
                excluded.add(child)
                stack.append(child)
    required = os.environ.get("LEARNINGS_STATE_CENSUS_FILTER")
    if required and os.environ.get("LEARNINGS_STATE_CENSUS_FILTER_ACK") != "1":
        # A leaked filter export alone must never narrow the census; the
        # filter is honored only when the test harness pairs it with the ack.
        required = None
    matches = []
    for pid, _ppid, stat_column, command in rows:
        if pid in excluded or stat_column.startswith("Z"):
            continue
        if required and required not in command:
            continue
        fingerprint = _match_worker_fingerprint(command)
        if fingerprint is None or not _pid_alive(pid):
            continue
        matches.append(WorkerProcess(pid, command, fingerprint))
    return tuple(sorted(matches, key=lambda worker: worker.pid))


# --- Part 3C decision 9: centralized activation lock-probe inventory --------

# Every lock family that blocks activation. A held member means a live
# worker; tests/test_neutral_state.py asserts this inventory against the
# actual lock-path constructors so a new family cannot be silently missed.
LOCK_PROBE_FAMILIES = (
    "structural",       # /tmp/learnings-structure-<sha1/16>.lock per worktree
    "pool",             # <state root>/locks/*.lock (mined-pool + distill)
    "reconcile",        # <state root>/reconcile/*.jsonl.lock
    "rules-ledger",     # <state root>/rules/ledger.json.lock
    "pending-ledger",   # <state root>/review-retro/pending.json.lock
    "currency",         # <state root>/currency/<slug>-<8hex>.lock
    "codex-adapter",    # host-owned journal/runtime locks (journal survives)
    "corpus-identity",  # one external lock per published active corpus key
)


def codex_adapter_state_dir() -> Path:
    """The Codex adapter's host-owned session state dir (mirror of the
    adapter's `_state_dir`, without creating it). A held runtime lock there
    means a live Codex-side worker; the journal itself is host-owned and is
    never imported or touched."""
    configured = os.environ.get("LEARNINGS_ADAPTER_STATE_DIR")
    if configured:
        path = Path(configured).expanduser()
        if path.is_absolute():
            return path
    return _home() / ".codex" / "learnings-adapter" / "sessions"


def _worktree_roots(checkout: Path, strict: bool = False) -> list[Path]:
    """Active worktree paths of one checkout (`git worktree list --porcelain
    -z`), resolved; falls back to the resolved checkout root alone when
    enumeration fails or reports nothing — the parent-plan conservative
    fallback for a non-bare checkout."""
    resolved = Path(checkout).resolve()
    # Same stripping as `_git`: an inherited GIT_DIR/GIT_WORK_TREE overrides
    # `git -C` and would enumerate the caller's repository instead.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"LC_ALL": "C", "LANG": "C", "GIT_TERMINAL_PROMPT": "0"})
    if strict:
        # Non-git roots legitimately have one structural lock. A git checkout
        # whose enumeration fails is different: a cutover could miss a linked
        # worktree, so callers must receive a blocker rather than the fallback.
        try:
            probe = subprocess.run(
                ["git", "-C", str(resolved), "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env=env,
            )
        except (OSError, subprocess.SubprocessError):
            raise IdentityResolutionError("git worktree probe failed") from None
        if probe.returncode != 0:
            if any(token in probe.stderr.lower() for token in _GIT_NOT_A_REPO_TOKENS):
                return [resolved]
            raise IdentityResolutionError("git worktree probe failed")
        if probe.stdout.strip() != "true":
            raise IdentityResolutionError("git worktree probe failed")
    try:
        result = subprocess.run(
            ["git", "-C", str(resolved), "worktree", "list", "--porcelain", "-z"],
            capture_output=True, text=True, timeout=10, check=False, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        if strict:
            raise IdentityResolutionError("git worktree enumeration failed") from None
        return [resolved]
    if result.returncode != 0:
        if strict:
            raise IdentityResolutionError("git worktree enumeration failed")
        return [resolved]
    roots = [
        Path(record[len("worktree "):]).resolve()
        for record in result.stdout.split("\0")
        if record.startswith("worktree ")
    ]
    return roots or [resolved]


def _ledger_lock_probes(root: Path) -> list[tuple[str, Path]]:
    probes: list[tuple[str, Path]] = []
    probes.extend(("pool", path) for path in sorted((root / "locks").glob("*.lock")))
    probes.extend(
        ("reconcile", path) for path in sorted((root / "reconcile").glob("*.jsonl.lock"))
    )
    probes.append(("rules-ledger", root / "rules" / "ledger.json.lock"))
    probes.append(("pending-ledger", root / "review-retro" / "pending.json.lock"))
    probes.extend(
        ("currency", path)
        for path in sorted((root / "currency").glob("*.lock"))
        if _CURRENCY_LOCK_RE.search(path.name)
    )
    return probes


def activation_lock_probes(
    legacy_root: Path | str,
    *,
    project_roots=(),
    extra_state_roots=(),
) -> tuple[tuple[str, Path], ...]:
    """Enumerate every (family, lock path) that must be free before an
    activation transition: structural locks for each planned project's
    active worktrees (bounded — known roots only, no filesystem crawl), the
    ledger-lock families under the legacy root (plus any extra state root,
    e.g. the target generation at reactivate), and the Codex adapter's
    host runtime locks."""
    probes: list[tuple[str, Path]] = []
    seen_worktrees: set[Path] = set()
    for checkout in project_roots:
        for worktree in _worktree_roots(Path(checkout)):
            if worktree not in seen_worktrees:
                seen_worktrees.add(worktree)
                probes.append(("structural", structural_lock_path(worktree)))
    for key, record, _active in _iter_active_corpus_records() or ():
        if record is not None:
            probes.append(("corpus-identity", corpus_lock_path(key)))
    for root in (Path(legacy_root), *(Path(extra) for extra in extra_state_roots)):
        probes.extend(_ledger_lock_probes(root))
    codex_dir = codex_adapter_state_dir()
    for pattern in ("*.lock", "*.review-lock", "*/.notifications.lock"):
        probes.extend(("codex-adapter", path) for path in sorted(codex_dir.glob(pattern)))
    unique: list[tuple[str, Path]] = []
    seen_paths: set[Path] = set()
    for family, path in probes:
        if path not in seen_paths:
            seen_paths.add(path)
            unique.append((family, path))
    return tuple(unique)


def _flock_is_held(path: Path) -> bool:
    """Non-blocking LOCK_EX probe; the fd is closed in try/finally
    immediately after the check (decision 9). A missing lock file is not
    held — the inode only exists once a writer has created it. Every
    other open failure (EACCES, ELOOP, EISDIR, I/O errors) propagates,
    and a non-regular file at a lock path (a FIFO would otherwise block
    the open forever) raises OSError — both become the caller's
    "lock probe failed" blocker in _mutable_gate, never a silent
    "not held" that clears a required activation gate."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"non-regular file at lock path {path}")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def held_activation_locks(
    legacy_root: Path | str,
    *,
    project_roots=(),
    extra_state_roots=(),
) -> tuple[str, ...]:
    """`"<family>: <path>"` for every enumerated lock currently held."""
    return tuple(
        f"{family}: {path}"
        for family, path in activation_lock_probes(
            legacy_root,
            project_roots=project_roots,
            extra_state_roots=extra_state_roots,
        )
        if _flock_is_held(path)
    )


# ---------------------------------------------------------------------------
# Part 3C Task A: apply — staged generation, atomic publication, activation.
# ---------------------------------------------------------------------------

STAGING_SCHEMA_VERSION = 1
IMPORT_MANIFEST_SCHEMA_VERSION = 1
_STAGING_NAME = "staging.json"
_MANIFEST_NAME = "import-manifest.json"
_DEACTIVATED_NAME = "deactivated.json"
_STAGING_UUID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# staging.json is provenance, generation.json + import-manifest.json are the
# verification anchors: all three are excluded from the content audit.
_GENERATION_META_NAMES = frozenset({_STAGING_NAME, _GENERATION_NAME, _MANIFEST_NAME})


@dataclass(frozen=True)
class ApplyOutcome:
    """The apply verdict: `activated`, `staged-not-activated` (a published
    generation exists but a re-gate blocker stopped activation), or
    `blocked` (nothing published)."""

    status: str
    generation: str | None
    blockers: tuple[str, ...]
    notes: tuple[str, ...]
    plan: ImportPlan | None


class _StagingDefect(RuntimeError):
    """A defect found while staging our OWN in-progress generation; the
    staging directory is removed and the message becomes a blocker."""


def _crash_point(name: str) -> None:
    """Test-only crash injection (LEARNINGS_APPLY_CRASH_POINT): the process
    REALLY dies (os._exit, no cleanup), so crash-recovery assertions always
    run against on-disk truth in a fresh process."""
    if os.environ.get("LEARNINGS_APPLY_CRASH_POINT") == name:
        os._exit(70)


def _canonical_json_bytes(record: dict) -> bytes:
    return (json.dumps(record, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _write_new_fsynced(path: Path, payload: bytes) -> None:
    """Exclusive-create write + fsync — staged files must never overwrite."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_json_fsynced(path: Path, record: dict) -> None:
    """Atomic same-directory temp + os.replace + directory fsync. The swap
    name carries a random suffix: a crash between write and replace
    strands the temp file, and a pid-only name would then O_EXCL-crash
    any later process that recycles the PID."""
    tmp = path.parent / f".{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    _write_new_fsynced(tmp, _canonical_json_bytes(record))
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def default_legacy_root() -> Path:
    """The legacy source root apply/rollback/reactivate operate on."""
    return _home() / ".claude" / "learnings"


def _staging_stamp_defect(stamp: object) -> str | None:
    """Shape-validate one staging.json stamp; None when sound."""
    if not isinstance(stamp, dict):
        return "stamp is not a JSON object"
    if stamp.get("schema_version") != STAGING_SCHEMA_VERSION:
        return "unknown stamp schema version"
    if not isinstance(stamp.get("staging_uuid"), str) or not _STAGING_UUID_RE.match(
        stamp["staging_uuid"]
    ):
        return "malformed staging uuid"
    if not _valid_generation_id(stamp.get("import_id")):
        return "malformed import id"
    if not isinstance(stamp.get("importer_pid"), int) or stamp["importer_pid"] <= 0:
        return "malformed importer pid"
    if not isinstance(stamp.get("created_at"), str):
        return "missing creation timestamp"
    if stamp.get("status") not in ("IN_PROGRESS", "COMPLETE"):
        return "unknown stamp status"
    if stamp["status"] == "COMPLETE":
        digest = stamp.get("source_inventory_digest")
        if not isinstance(digest, str) or not _SHA256_RE.match(digest):
            return "COMPLETE stamp lacks its source inventory digest"
    return None


def _read_staging_stamp(path: Path) -> tuple[dict | None, str | None]:
    """(stamp, defect) — exactly one side is None."""
    raw = _read_file_capped(path, _ACTIVATION_MAX_BYTES)
    if raw is None:
        return None, "stamp unreadable (missing, symlink, or oversized)"
    try:
        stamp = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, "stamp is not valid JSON"
    defect = _staging_stamp_defect(stamp)
    if defect:
        return None, defect
    return stamp, None


def verify_generation(gen_dir: Path | str, generation: str) -> str | None:
    """Full digest re-verification of one generation tree (decision 4):
    generation.json schema + digests, manifest bytes against the recorded
    manifest digest, every content file against the manifest entries
    (set-exact, symlink-free), identity records re-validated. Runs only at
    transitions (apply audit, adoption, reactivate) — never on hot paths.
    None when sound; the first defect otherwise."""
    gen_dir = Path(gen_dir)
    raw = _read_file_capped(gen_dir / _GENERATION_NAME, _ACTIVATION_MAX_BYTES)
    record: object = None
    if raw is not None:
        try:
            record = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            record = None
    if not _generation_is_valid(record, generation):
        return f"{_GENERATION_NAME} is missing or invalid for generation {generation}"
    manifest_raw = _read_file_capped(gen_dir / _MANIFEST_NAME)
    if manifest_raw is None:
        return f"{_MANIFEST_NAME} is missing or unreadable"
    if hashlib.sha256(manifest_raw).hexdigest() != record["staged_manifest_digest"]:
        return "import manifest bytes do not match the recorded manifest digest"
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return "import manifest is not valid JSON"
    if not isinstance(manifest, dict) or manifest.get("import_id") != generation:
        return "import manifest does not name this generation"
    if manifest.get("source_inventory_digest") != record["source_inventory_digest"]:
        return "manifest and generation record disagree on the source inventory digest"
    entries = manifest.get("entries")
    if not isinstance(entries, dict) or not all(
        isinstance(rel, str) and isinstance(digest, str) and _SHA256_RE.match(digest)
        for rel, digest in entries.items()
    ):
        return "import manifest entries are malformed"
    actual: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(gen_dir, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = str(path.relative_to(gen_dir))
            if rel in _GENERATION_META_NAMES:
                continue
            if path.is_symlink():
                return f"unexpected symlink in the generation tree: {rel}"
            payload = _read_file_capped(path)
            if payload is None:
                return f"unreadable generation file: {rel}"
            actual[rel] = hashlib.sha256(payload).hexdigest()
    if actual != entries:
        missing = sorted(set(entries) - set(actual))[:3]
        extra = sorted(set(actual) - set(entries))[:3]
        changed = sorted(rel for rel in set(actual) & set(entries) if actual[rel] != entries[rel])[:3]
        return (
            "generation content does not match its manifest "
            f"(missing={missing} extra={extra} changed={changed})"
        )
    projects_dir = gen_dir / "projects"
    if projects_dir.is_dir():
        for project_dir in sorted(p for p in projects_dir.iterdir() if p.is_dir()):
            if _published_identity_record(project_dir) is None:
                return f"invalid identity record under projects/{project_dir.name}"
    return None


def _translate_mine_cache(plan: ImportPlan, legacy_root: Path) -> tuple[dict[str, str] | None, str | None]:
    """Exact-match-or-reset (override ruling): the legacy `.mine-input-hashes`
    translates to stable project keys ONLY when its entries are precisely
    {non-declined selected alias: selected digest} for every imported
    portable — keys AND values. Anything else resets wholesale (the next
    mine performs a normal full pass); unmatched bytes are never marked
    already-mined, and `-<digest16>` override namespaces are never seeded."""
    artifact = next((a for a in plan.artifacts if a.path == ".mine-input-hashes"), None)
    if artifact is None or artifact.action != "import":
        return None, None  # absent or already planned as a reset
    reset_note = (
        ".mine-input-hashes: legacy mine cache reset (not an exact match for "
        "the selected portables); the next mine performs a normal full pass"
    )
    raw = _read_file_capped(legacy_root / ".mine-input-hashes")
    if raw is None:
        return None, reset_note
    try:
        cache = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, reset_note
    if not isinstance(cache, dict):
        return None, reset_note
    expected: dict[str, str] = {}
    translated: dict[str, str] = {}
    for project in plan.projects:
        if not project.selected_digest:
            continue
        for alias in project.aliases:
            if alias not in project.declined_aliases:
                expected[alias] = project.selected_digest
        translated[project.key] = project.selected_digest
    if not expected or cache != expected:
        return None, reset_note
    return translated, (
        f".mine-input-hashes: translated to {len(translated)} stable project "
        f"key(s) as cache/mine-input-hashes"
    )


def _read_import_source(path: Path) -> bytes | None:
    """Read one planned source file. Pool portables are single-hop symlinks
    the plan already validated (absolute target, matching basename); they
    are read through that one recorded hop. Everything else goes through
    the fd-bound capped read directly."""
    try:
        if os.path.islink(str(path)):
            target = Path(os.readlink(str(path)))
            return _read_file_capped(target) if target.is_absolute() else None
    except OSError:
        return None
    return _read_file_capped(path)


def _staging_copy_map(plan: ImportPlan, legacy_root: Path) -> dict[str, tuple[Path, str]]:
    """dest relpath -> (source path, expected sha256) for every planned
    import. Portables collapse to `projects/<key>/portable.md` (byte-identical
    alias twins dedupe); the mine cache is translated, never copied raw;
    everything else keeps its legacy relpath under the generation root."""
    key_by_canonical = {p.canonical: p.key for p in plan.projects}
    copies: dict[str, tuple[Path, str]] = {}
    for artifact in plan.artifacts:
        if artifact.action != "import" or artifact.digest is None:
            continue
        if artifact.kind == "portable-snapshot":
            key = key_by_canonical.get(artifact.project)
            if key is None:
                raise _StagingDefect(f"{artifact.path}: portable has no planned project")
            copies.setdefault(f"projects/{key}/portable.md", (legacy_root / artifact.path, artifact.digest))
        elif artifact.path == ".mine-input-hashes":
            continue
        elif artifact.kind == "worker-diagnostics" and artifact.path.rsplit("/", 1)[-1] != "global.jsonl":
            # A lone (non-colliding) per-project diagnostics file: routed to
            # its neutral home directly. A collision (2+ sources) never
            # reaches this branch — plan_import already reassigned those
            # artifacts' action to "merge" and carries them in plan.merges
            # instead (decision 9).
            key = key_by_canonical.get(artifact.project)
            if key is None:
                raise _StagingDefect(f"{artifact.path}: diagnostics file has no planned project")
            dest = f"projects/{key}/diagnostics/workers.jsonl"
            copies.setdefault(dest, (legacy_root / artifact.path, artifact.digest))
        elif artifact.kind == "corpus-baseline":
            # A collision (2+ sources for one project) never reaches this
            # branch with more than one "import" artifact: plan_import
            # already downgraded every non-newest source to "report"
            # (identical maps) or "block" (divergent maps) — decision 9.
            key = key_by_canonical.get(artifact.project)
            if key is None:
                raise _StagingDefect(f"{artifact.path}: corpus baseline has no planned project")
            dest = f"projects/{key}/corpus-baseline.json"
            copies.setdefault(dest, (legacy_root / artifact.path, artifact.digest))
        else:
            copies[artifact.path] = (legacy_root / artifact.path, artifact.digest)
    return copies


def _stage_content(
    staging_dir: Path, plan: ImportPlan, legacy_root: Path
) -> tuple[dict[str, str], list[str]]:
    """Stage every owned file into the staging tree. Returns
    ({dest relpath: sha256}, notes); raises _StagingDefect on any defect."""
    entries: dict[str, str] = {}
    notes: list[str] = []

    def _stage_bytes(dest_rel: str, payload: bytes) -> None:
        dest = staging_dir / dest_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        _write_new_fsynced(dest, payload)
        entries[dest_rel] = hashlib.sha256(payload).hexdigest()

    staged_any = False
    for dest_rel, (source, expected_digest) in sorted(_staging_copy_map(plan, legacy_root).items()):
        payload = _read_import_source(source)
        if payload is None or hashlib.sha256(payload).hexdigest() != expected_digest:
            raise _StagingDefect(f"{source}: source changed while staging; rerun apply")
        _stage_bytes(dest_rel, payload)
        if not staged_any:
            staged_any = True
            _crash_point("during-staging")
    for merge in plan.merges:
        payload = _merge_diagnostics_records(merge.sources, legacy_root)
        if payload is None or hashlib.sha256(payload).hexdigest() != merge.merged_digest:
            raise _StagingDefect(f"{merge.dest}: source changed while staging; rerun apply")
        _stage_bytes(merge.dest, payload)
    for project in plan.projects:
        if not identity_record_is_valid(project.record):
            raise _StagingDefect(f"planned identity record for {project.canonical} is invalid")
        _stage_bytes(f"projects/{project.key}/{_IDENTITY_NAME}", _canonical_json_bytes(project.record))
    translated, cache_note = _translate_mine_cache(plan, legacy_root)
    if cache_note:
        notes.append(cache_note)
    if translated:
        _stage_bytes("cache/mine-input-hashes", _canonical_json_bytes(translated))
    return entries, notes


def _stage_generation(
    neutral: Path, plan: ImportPlan, legacy_root: Path
) -> tuple[Path | None, list[str], list[str]]:
    """Run the staging protocol (plan Task A steps 1-5) for one generation.
    Returns (published generation dir, blockers, notes); a defect removes
    our OWN staging directory (we created it, we are alive, the exclusive
    lock excludes every cooperating writer) and returns the blocker."""
    import_id = plan.generation_id
    generations = neutral / "generations"
    gen_dest = generations / import_id
    staging_parent = neutral / "staging"
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging_uuid = uuid.uuid4().hex
    staging_dir = staging_parent / staging_uuid
    try:
        staging_dir.mkdir()  # exclusive create on the generations filesystem
    except OSError as exc:
        return None, [f"cannot create staging directory {staging_dir}: {exc}"], []
    try:
        _crash_point("before-stamp")
        stamp = {
            "schema_version": STAGING_SCHEMA_VERSION,
            "staging_uuid": staging_uuid,
            "import_id": import_id,
            "importer_pid": os.getpid(),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "IN_PROGRESS",
        }
        _write_new_fsynced(staging_dir / _STAGING_NAME, _canonical_json_bytes(stamp))
        _fsync_dir(staging_dir)
        entries, notes = _stage_content(staging_dir, plan, legacy_root)
        manifest = {
            "schema_version": IMPORT_MANIFEST_SCHEMA_VERSION,
            "import_id": import_id,
            "source_root": plan.source_root,
            "source_inventory_digest": plan.inventory_digest,
            "entries": entries,
            "sources": [
                {
                    "path": a.path,
                    "kind": a.kind,
                    "action": a.action,
                    "digest": a.digest,
                    "detail": a.detail,
                    "project": a.project,
                }
                for a in plan.artifacts
            ],
            "merges": [
                {
                    "dest": m.dest,
                    "kind": m.kind,
                    "sources": [list(s) for s in m.sources],
                    "digest": m.merged_digest,
                    "project": m.project,
                }
                for m in plan.merges
            ],
            "reports": list(plan.reports),
            "resets": list(plan.resets),
            "preferences": [list(item) for item in plan.preferences],
            "notes": notes,
        }
        manifest_bytes = _canonical_json_bytes(manifest)
        _write_new_fsynced(staging_dir / _MANIFEST_NAME, manifest_bytes)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        _write_new_fsynced(
            staging_dir / _GENERATION_NAME,
            _canonical_json_bytes(
                build_generation_record(
                    import_id,
                    source_inventory_digest=plan.inventory_digest,
                    staged_manifest_digest=manifest_digest,
                )
            ),
        )
        for dirpath, _dirnames, _filenames in os.walk(staging_dir):
            _fsync_dir(Path(dirpath))
        # Step 4: reread and digest-audit the staged tree from disk.
        problem = verify_generation(staging_dir, import_id)
        if problem:
            raise _StagingDefect(f"staged-tree audit failed: {problem}")
        _crash_point("before-complete")
        _replace_json_fsynced(
            staging_dir / _STAGING_NAME,
            dict(
                stamp,
                status="COMPLETE",
                source_inventory_digest=plan.inventory_digest,
                staged_manifest_digest=manifest_digest,
            ),
        )
        _crash_point("after-complete")
        generations.mkdir(parents=True, exist_ok=True)
        os.rename(staging_dir, gen_dest)
    except _StagingDefect as exc:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return None, [str(exc)], []
    except OSError as exc:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return None, [f"staging failed: {exc}"], []
    _fsync_dir(generations)
    _crash_point("after-rename")
    return gen_dest, [], notes


def _cleanup_staging(staging_parent: Path, active_generation: str | None) -> tuple[str | None, list[str]]:
    """Retry hygiene under the exclusive lock. Removable: a shape-valid
    stamped staging path whose recorded importer is DEAD and whose import id
    is not active (rmtree) — a COMPLETE stamp additionally requires the
    child's import manifest to match the shape _stage_generation actually
    emits: schema version, import id and source inventory digest matching
    the stamp, and at least one well-formed entry (the plan's manifest
    condition; an IN_PROGRESS child legitimately lacks one) — or an
    exact-UUID-named, non-symlink, EMPTY unstamped child (rmdir only —
    never recursive; non-empty by execution time blocks as unrecognized,
    the decision-3 race rule). Everything else blocks untouched."""
    notes: list[str] = []
    if not staging_parent.is_dir():
        return None, notes
    for child in sorted(staging_parent.iterdir()):
        if child.is_symlink() or not _STAGING_UUID_RE.match(child.name) or not child.is_dir():
            return f"unrecognized staging path {child}; not touched — resolve it by hand", notes
        stamp_path = child / _STAGING_NAME
        if not stamp_path.is_symlink() and not stamp_path.exists():
            try:
                child.rmdir()
            except OSError:
                return (
                    f"unrecognized staging path {child}: unstamped and non-empty; "
                    f"left untouched (never recursed) — resolve it by hand"
                ), notes
            notes.append(f"removed empty unstamped staging directory {child.name}")
            continue
        stamp, defect = _read_staging_stamp(stamp_path)
        if defect:
            return f"staging path {child} has a malformed stamp ({defect}); not touched", notes
        pid = stamp["importer_pid"]
        if _pid_alive(pid):
            return (
                f"another import appears to be in progress "
                f"(staging {child.name}, importer pid {pid}); not touched"
            ), notes
        if active_generation is not None and stamp["import_id"] == active_generation:
            return f"staging path {child} names the active generation; not touched", notes
        if stamp["status"] == "COMPLETE":
            manifest_raw = _read_file_capped(child / _MANIFEST_NAME)
            manifest = None
            if manifest_raw is not None:
                with contextlib.suppress(ValueError, UnicodeDecodeError):
                    manifest = json.loads(manifest_raw.decode("utf-8"))
            entries = manifest.get("entries") if isinstance(manifest, dict) else None
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema_version") != IMPORT_MANIFEST_SCHEMA_VERSION
                or manifest.get("import_id") != stamp["import_id"]
                or manifest.get("source_inventory_digest") != stamp.get("source_inventory_digest")
                or not isinstance(entries, dict)
                or len(entries) == 0
                or not all(
                    isinstance(rel, str) and isinstance(digest, str) and _SHA256_RE.match(digest)
                    for rel, digest in entries.items()
                )
            ):
                return (
                    f"unrecognized staging path {child}: COMPLETE stamp without a "
                    f"valid import manifest; not touched — resolve it by hand"
                ), notes
        shutil.rmtree(child)
        notes.append(f"removed staging directory {child.name} left by dead importer pid {pid}")
    return None, notes


def _adoption_defect(gen_dest: Path, import_id: str, plan: ImportPlan) -> str | None:
    """The decision-8 override composite, ALL required: shape-valid COMPLETE
    provenance stamp, matching import id and source inventory, DEAD creator,
    and full digest verification. (The caller already established no active
    generation pointer.) None when adoptable."""
    stamp, defect = _read_staging_stamp(gen_dest / _STAGING_NAME)
    if defect:
        return f"provenance stamp: {defect}"
    if stamp["import_id"] != import_id:
        return "provenance stamp names a different import id"
    if stamp["status"] != "COMPLETE":
        return "provenance stamp is not COMPLETE"
    if _pid_alive(stamp["importer_pid"]):
        return f"creator pid {stamp['importer_pid']} is still alive"
    if stamp.get("source_inventory_digest") != plan.inventory_digest:
        return "provenance stamp records a different source inventory"
    return verify_generation(gen_dest, import_id)


def _mutable_gate(root: Path, plan: ImportPlan, *, recheck_inventory: bool = False) -> tuple[str, ...]:
    """The complete pre-activation mutable gate: live legacy workers
    (decision 8), every held granular lock across the planned projects'
    worktrees + ledgers + the Codex adapter (decision 9), and — on the
    post-publication re-gate — the source inventory digest."""
    blockers: list[str] = []
    if recheck_inventory and source_inventory_digest(root) != plan.inventory_digest:
        blockers.append("legacy source inventory changed since the plan; rerun apply")
    try:
        workers = scan_legacy_workers()
    except RuntimeError as exc:
        blockers.append(f"worker census unavailable: {exc}")
        workers = ()
    for worker in workers:
        blockers.append(f"live legacy worker: pid {worker.pid} ({worker.fingerprint})")
    project_roots = sorted({r for p in plan.projects for r in p.record.get("observed_roots", ())})
    try:
        held = held_activation_locks(root, project_roots=project_roots)
    except OSError as exc:
        blockers.append(f"lock probe failed: {exc}")
        held = ()
    for item in held:
        blockers.append(f"held lock — {item}")
    return tuple(blockers)


def apply_import(legacy_root: Path | str, *, prefer_portable=()) -> ApplyOutcome:
    """Stage, publish, and activate one neutral generation (plan Task A).

    The CALLER (cmd_state) holds the exclusive activity lock for the whole
    call and has already refused apply-on-VALID with drift reporting; both
    are re-checked here cheaply as a second net. Gate order: recompute the
    complete plan -> census -> lock probes -> adoption/staging -> publish ->
    full mutable re-gate -> activation.json (atomic, LAST) -> decision-11
    self-check."""
    root = Path(legacy_root)
    notes: list[str] = []
    external_blocker = _active_corpus_transition_guard()
    if external_blocker:
        return ApplyOutcome("blocked", None, (external_blocker,), (), None)
    status = activation_status()
    if status.state == ACTIVATION_VALID:
        return ApplyOutcome(
            "blocked",
            status.generation,
            (f"a neutral generation is already active ({status.generation}); apply is refused",),
            (),
            None,
        )
    neutral = _neutral_root()
    if neutral is None:
        return ApplyOutcome(
            "blocked", None,
            ("neutral state root is unresolvable (unsafe XDG_STATE_HOME/HOME)",),
            (), None,
        )
    plan = plan_import(root, prefer_portable=prefer_portable)
    if plan.blockers:
        return ApplyOutcome("blocked", None, plan.blockers, (), plan)
    if plan.generation_id is None:
        return ApplyOutcome("blocked", None, ("no deterministic import id",), (), plan)
    import_id = plan.generation_id

    gate = _mutable_gate(root, plan)
    if gate:
        return ApplyOutcome("blocked", None, gate, (), plan)

    gen_dest = neutral / "generations" / import_id
    if gen_dest.is_symlink() or gen_dest.exists():
        defect = _adoption_defect(gen_dest, import_id, plan)
        if defect:
            return ApplyOutcome(
                "blocked", import_id,
                (
                    f"existing generation {import_id} cannot be adopted ({defect}); "
                    f"no existing generation is ever replaced",
                ),
                tuple(notes), plan,
            )
        notes.append(
            f"adopted the existing unactivated generation {import_id} "
            f"from an interrupted identical apply"
        )
    else:
        blocker, cleanup_notes = _cleanup_staging(neutral / "staging", status.generation)
        notes.extend(cleanup_notes)
        if blocker:
            return ApplyOutcome("blocked", None, (blocker,), tuple(notes), plan)
        staged, stage_blockers, stage_notes = _stage_generation(neutral, plan, root)
        notes.extend(stage_notes)
        if staged is None:
            return ApplyOutcome("blocked", None, tuple(stage_blockers), tuple(notes), plan)

    # Step 6: the complete mutable re-gate after publication. A new blocker
    # leaves the generation staged but NOT activated — legacy stays live.
    regate = list(_mutable_gate(root, plan, recheck_inventory=True))
    if not regate:
        problem = verify_generation(gen_dest, import_id)
        if problem:
            regate.append(f"published generation failed verification: {problem}")
    if regate:
        regate.append(
            f"generation {import_id} is staged but NOT activated; "
            f"resolve the blocker and rerun the identical apply"
        )
        return ApplyOutcome("staged-not-activated", import_id, tuple(regate), tuple(notes), plan)

    _crash_point("before-activation")
    _replace_json_fsynced(neutral / _ACTIVATION_NAME, build_activation_record(import_id))
    # Decision 11: the just-written record must round-trip through the
    # ordinary read path as VALID naming this generation.
    check = activation_status()
    if check.state != ACTIVATION_VALID or check.generation != import_id:
        raise RuntimeError(
            f"post-activation self-check failed: {check.state} ({check.reason})"
        )
    return ApplyOutcome("activated", import_id, (), tuple(notes), plan)


# ---------------------------------------------------------------------------
# Part 3C Task B: rollback + reactivate — one atomic replace each way.
# ---------------------------------------------------------------------------


_DEACTIVATED_SNAPSHOT_NAME = "deactivated-verification.json"
ROLLBACK_SNAPSHOT_SCHEMA_VERSION = 1


def _tree_digest_entries(gen_dir: Path) -> dict[str, str] | None:
    """{relpath: sha256} over EVERY regular file in the tree (symlink-free);
    None when any file is unreadable or a symlink appears."""
    entries: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(gen_dir, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                return None
            payload = _read_file_capped(path)
            if payload is None:
                return None
            entries[str(path.relative_to(gen_dir))] = hashlib.sha256(payload).hexdigest()
    return entries


def _rollback_snapshot(neutral: Path, generation: str) -> str | None:
    """Tree snapshot of the generation being deactivated, written BEFORE
    the atomic replace. Reactivate re-verifies against this rollback-time
    state (a live generation legitimately drifts from its import manifest,
    so 'restore exactly what was deactivated' is the verification
    decision 6 can actually keep); a missing/mismatched snapshot falls
    back to the strict import-manifest verification.

    Deterministic contract: returns None when the snapshot was written,
    else a reason string. Rollback ALWAYS proceeds either way — it is the
    emergency circuit breaker — but a no-write path is never silent: the
    caller surfaces the reason so the operator knows reactivate will
    refuse a lived-in (drifted) generation. Any EXISTING snapshot (a prior
    rollback's, same generation id) is unlinked first, so a failed capture
    can never leave a stale anchor: after a no-write path, reactivate is
    guaranteed to fall back to the strict import-manifest verification —
    exactly what the CLI warning states — never to compare against a
    stale snapshot and block with a misleading 'changed since rollback'."""
    try:
        (neutral / _DEACTIVATED_SNAPSHOT_NAME).unlink(missing_ok=True)
    except OSError as exc:
        return f"stale snapshot removal failed: {exc}"
    gen_dir = neutral / "generations" / generation
    if not gen_dir.is_dir():
        return "generation tree missing"
    entries = _tree_digest_entries(gen_dir)
    if entries is None:
        return "generation tree unreadable or contains symlinks/oversized files"
    try:
        _replace_json_fsynced(
            neutral / _DEACTIVATED_SNAPSHOT_NAME,
            {
                "schema_version": ROLLBACK_SNAPSHOT_SCHEMA_VERSION,
                "generation": generation,
                "entries": entries,
            },
        )
    except OSError as exc:
        return f"snapshot write failed: {exc}"
    return None


def _snapshot_verification_defect(neutral: Path, generation: str) -> str | None:
    """Verify the generation tree for reactivation. Against the rollback
    snapshot when one matches this generation (accepting pre-rollback live
    drift, catching post-rollback tampering); otherwise the strict
    import-manifest verification (pristine generations)."""
    snapshot = None
    with contextlib.suppress(OSError, ValueError):
        raw = _read_file_capped(neutral / _DEACTIVATED_SNAPSHOT_NAME)
        if raw is not None:
            snapshot = json.loads(raw.decode("utf-8"))
    gen_dir = neutral / "generations" / generation
    if (
        isinstance(snapshot, dict)
        and snapshot.get("schema_version") == ROLLBACK_SNAPSHOT_SCHEMA_VERSION
        and snapshot.get("generation") == generation
        and isinstance(snapshot.get("entries"), dict)
        and all(
            isinstance(rel, str) and isinstance(digest, str) and _SHA256_RE.match(digest)
            for rel, digest in snapshot["entries"].items()
        )
    ):
        actual = _tree_digest_entries(gen_dir)
        if actual is None:
            return "generation tree is unreadable or contains symlinks"
        if actual != snapshot["entries"]:
            missing = sorted(set(snapshot["entries"]) - set(actual))[:3]
            extra = sorted(set(actual) - set(snapshot["entries"]))[:3]
            changed = sorted(
                rel
                for rel in set(actual) & set(snapshot["entries"])
                if actual[rel] != snapshot["entries"][rel]
            )[:3]
            return (
                "generation content changed since rollback "
                f"(missing={missing} extra={extra} changed={changed})"
            )
        # The anchors must still be sound even when the tree matches.
        raw_gen = _read_file_capped(gen_dir / _GENERATION_NAME, _ACTIVATION_MAX_BYTES)
        record = None
        if raw_gen is not None:
            with contextlib.suppress(ValueError, UnicodeDecodeError):
                record = json.loads(raw_gen.decode("utf-8"))
        if not _generation_is_valid(record, generation):
            return f"{_GENERATION_NAME} is missing or invalid for generation {generation}"
        return None
    return verify_generation(gen_dir, generation)


def rollback_activation() -> tuple[str, str | None, str | None]:
    """Deactivate the neutral state with EXACTLY one atomic
    os.replace(activation.json -> deactivated.json) plus a directory fsync.

    Never deletes the generation tree or the legacy tree; the record moves
    aside verbatim (even an INVALID one — resolution falls back to legacy
    the moment the pointer is gone). Idempotent: with no activation record
    the call is a reported no-op that leaves any existing deactivated.json
    untouched. Returns (verdict, generation, snapshot_warning):
    ("deactivated", <generation or None for an invalid record>, <None on a
    successfully written rollback-time snapshot, else _rollback_snapshot's
    reason string — rollback proceeds regardless, but the caller must
    surface the reason>), ("absent", None, None), or ("blocked", None,
    <active external corpus reason>)."""
    external_blocker = _active_corpus_transition_guard()
    if external_blocker:
        return "blocked", None, external_blocker
    neutral = _neutral_root()
    if neutral is None:
        return "absent", None, None
    activation = neutral / _ACTIVATION_NAME
    try:
        present = activation.lstat() is not None
    except OSError:
        present = False
    if not present:
        return "absent", None, None
    generation = None
    with contextlib.suppress(OSError, ValueError):
        record = _read_json_record(activation)
        if _activation_is_valid(record):
            generation = record["generation"]
    snapshot_warning = None
    if generation is not None:
        snapshot_warning = _rollback_snapshot(neutral, generation)
    _crash_point("rollback-before-replace")
    os.replace(activation, neutral / _DEACTIVATED_NAME)
    _crash_point("rollback-after-replace")
    _fsync_dir(neutral)
    return "deactivated", generation, snapshot_warning


def reactivate_deactivated() -> tuple[str, str | None, tuple[str, ...]]:
    """Restore the preserved activation record — validated target ONLY.

    The deactivated record must be a schema-valid activation naming a
    generation whose tree passes the FULL digest re-verification
    (decision 4); there is no arbitrary generation selection. Legacy-only
    drift accumulated since rollback is listed and explicitly NOT merged.
    Returns (verdict, generation, notes) where verdict is one of
    "reactivated", "already-active", "nothing-to-reactivate", "blocked"."""
    external_blocker = _active_corpus_transition_guard()
    if external_blocker:
        return "blocked", None, (external_blocker,)
    status = activation_status()
    if status.state == ACTIVATION_VALID:
        return "already-active", status.generation, ()
    neutral = _neutral_root()
    if neutral is None:
        return "blocked", None, ("neutral state root is unresolvable (unsafe XDG_STATE_HOME/HOME)",)
    deactivated = neutral / _DEACTIVATED_NAME
    try:
        raw = _read_activation_capped(deactivated)
    except FileNotFoundError:
        return "nothing-to-reactivate", None, ()
    except OSError:
        raw = None
    if raw is None:
        if deactivated.is_symlink() or deactivated.exists():
            return "blocked", None, (f"{deactivated} exists but is not a readable regular file",)
        return "nothing-to-reactivate", None, ()
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        record = None
    if not _activation_is_valid(record):
        return "blocked", None, (
            f"{deactivated} is not a valid activation record; nothing was changed",
        )
    generation = record["generation"]
    gen_dir = neutral / "generations" / generation
    problem = _snapshot_verification_defect(neutral, generation)
    if problem:
        return "blocked", generation, (
            f"generation {generation} failed verification: {problem}; nothing was changed",
        )
    notes: list[str] = []
    gen_record = _read_json_record(gen_dir / _GENERATION_NAME)
    recorded_digest = gen_record["source_inventory_digest"]
    legacy = default_legacy_root()
    if legacy.is_dir() and source_inventory_digest(legacy) != recorded_digest:
        notes.append(
            "legacy drift: the legacy tree changed since this generation was "
            "imported; reactivation does NOT merge it — the neutral "
            "generation resumes exactly as preserved"
        )
    _crash_point("reactivate-before-replace")
    os.replace(deactivated, neutral / _ACTIVATION_NAME)
    _crash_point("reactivate-after-replace")
    _fsync_dir(neutral)
    check = activation_status()
    if check.state != ACTIVATION_VALID or check.generation != generation:
        raise RuntimeError(
            f"post-reactivation self-check failed: {check.state} ({check.reason})"
        )
    return "reactivated", generation, tuple(notes)


def deactivated_generation() -> str | None:
    """The generation named by a schema-valid deactivated.json, else None —
    the reseed messaging's source for 'the preserved prior generation'."""
    neutral = _neutral_root()
    if neutral is None:
        return None
    try:
        raw = _read_activation_capped(neutral / _DEACTIVATED_NAME)
    except OSError:
        return None
    if raw is None:
        return None
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return record["generation"] if _activation_is_valid(record) else None
