#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
# STDOUT CONTRACT: this hook's stdout is the SessionStart `additionalContext`
# channel. main() prints EITHER exactly one JSON object (a diverged-trunk,
# failed-push, or stranded-branch warning) OR nothing at all — never a stray
# print, never more than one object.
"""Hook: SessionStart — snapshot-commit the LEARNINGS corpus.

The corpus is written only by `learn add` (quiet corpus, 2026-09-06): the
review, distill, and organize jobs that once regenerated LEARNINGS files
between sessions are deleted. SessionStart is still the snapshot moment for a
repo that keeps a committed corpus in its tree. Every enrolled project now
holds its corpus in the central store, where this hook logs
`skip:external-corpus` and commits nothing; the legacy in-tree path below is
kept for a checkout that still carries LEARNINGS files in HEAD.

Policy (see docs/AUDIT-integration-coherence.md "Deferred follow-on work"):
  - EXPLICIT INSTALLATION POLICY. No settings file means no automatic
    registration, snapshot commit or push. An explicitly enabled snapshot
    profile can manage a corpus already committed in HEAD. Optional first
    enrollment also requires the state seam to prove the physical Git root is exactly
    `$HOME/Code/<category>/<repository>` (or the test override),
    and the locked Git selection contains only regular, single-link top-level
    LEARNINGS files. Non-Git scratch, wrong-depth roots, absent/ignored/unsafe
    files, and unavailable qualification skip without `.gitattributes` or Git
    mutation. Registration owns template scaffolding; this hook remains the one
    commit writer.
  - Once opted in, snapshot ALL dirty LEARNINGS artifacts — tracked-with-changes
    AND new untracked siblings the split/distill paths generate. (Excluding the
    latter would orphan split children / portable files: a `git clean` or fresh
    checkout would lose them.) Committed via an explicit file list — NEVER
    `git add -A`, so a code edit in flight is left alone.
  - THROWAWAY INDEX. Staging + commit go through a temp index seeded from HEAD
    (`GIT_INDEX_FILE`), so the user's REAL index is never mutated: a failed/
    rejected/timed-out commit leaves any pre-staged work (edits OR deletions)
    exactly as it was, and a successful one only syncs our own paths. No
    restore logic, no edge cases.
  - RE-ENTRANCY GUARD. A background `claude -p` (review/distill/validate/prune)
    sets LEARNINGS_REVIEW_NESTED=1 and fires lifecycle hooks too; the snapshot
    skips so it can't commit a half-settled mid-pipeline corpus.
  - SERIALIZE with the system's own LEARNINGS writers. A still-running prior
    SessionEnd review/reduce/auto-split mutates these files under the project
    structural lock; the snapshot takes the SAME lock (non-blocking — skip if
    held) so the scan can't see a half-written / mixed-stage file. (Distill uses
    a separate lock domain; its `*-PORTABLE-LEARNINGS.md` writes are atomic
    temp-then-rename, so a snapshot mid-distill is at worst one stale publish the
    next session re-commits — accepted, see audit Finding 5.)
  - SKIP when: nested, not a git work tree, not opted in, nothing dirty, lock
    held, mid-merge/rebase/cherry-pick/revert/bisect, detached HEAD, or unborn.
  - NON-BLOCKING. Every failure logs to /tmp and never interrupts startup.
  - --no-verify on the snapshot commit (scoped exception to the never-skip-hooks
    rule, approved by S). This is automated `.md` housekeeping, not user code;
    running the repo's pre-commit hook here is precisely what could `git add -A`
    in-flight code into the snapshot. Skipping it keeps the commit constrained
    to exactly our LEARNINGS files.
  - CURRENT BRANCH for the commit (labeled `chore(learnings): session-start
    snapshot`), so `git status` stays clean on whatever branch you're on. The
    automatic commit uses an explicitly configured snapshot email; it never
    inherits the ordinary Git email. `LEARNINGS_SNAPSHOT_EMAIL` may override
    identity only after settings enable commits. Ordinary commits are untouched.
  - ORIGIN SYNC (Option Y), only when the session starts ON THE TRUNK and the
    settings enable pushes and the remote matches the configured owner pattern.
    LEARNINGS are a shared append-trunk, so on the trunk the snapshot is
    reconciled with origin: fetch (explicit refspec so origin/<trunk> is never
    read stale), then FAST-FORWARD ONLY — push when ahead AND the ahead range is
    snapshot-only (every commit was authored by this hook — subject matches the
    snapshot message; a commit a user authored on main, even a hand-edited
    .gitattributes, is HELD, never force-bypassed past the PR-only guard),
    FF-absorb origin's moves when behind.
    NEVER force-pushes, NEVER auto-rebases
    (a stuck rebase would be a worse surprise than a delayed push), so it cannot
    lose work on either side. The owned-remote gate stops the hook pushing the
    user's local snapshots into a cloned THIRD-PARTY repo that uses this same
    system. SSH connect + net timeouts are bounded so an offline SessionStart
    fails fast instead of hanging startup.
  - OFF THE TRUNK the snapshot is also pushed, but only to a branch ALREADY
    published to origin and only when the ahead range is snapshot-only. The old
    "it rides the eventual PR" assumption held only if the branch got pushed
    again before the merge: GitHub squash-merges the REMOTE branch, so a
    snapshot committed after the last push never lands, and the post-merge
    branch delete then drops the only ref holding it. Push-only — a feature
    branch is never fast-forwarded onto origin's moves (see
    _sync_branch_to_origin).
  - DIVERGED TRUNK (ahead AND behind — a PR merged on origin without a local
    pull) can't be fast-forwarded, so the snapshot can't reach origin. Rather
    than let it lurk unpushed and silent (the exact bug this change fixes),
    main() prints a SessionStart `additionalContext` warning directly (no
    relay hook involved); reconciling stays a deliberate, context-aware step
    (`git pull --rebase` / fast-forward). Same direct-print treatment for a
    snapshot stranded on a published feature branch whose push failed. A Git
    synchronization failure is classified, logged with a credential-redacted
    bounded diagnostic, and surfaced with its exact recovery class rather than
    collapsed to a bare `push-failed` status.

Reads {cwd} from the SessionStart hook stdin JSON. Emits nothing on stdout,
UNLESS the trunk diverged, a push fails, or a branch snapshot is stranded, in
which case it prints exactly one JSON object with the warning as SessionStart
`additionalContext` (see the STDOUT CONTRACT note at the top of this file).
Set LEARNINGS_AUTO_COMMIT=0 to disable everything, or LEARNINGS_AUTO_PUSH=0 to
keep snapshots local (no sync).
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

LOG_PATH = "/tmp/learnings-autocommit.log"
COMMIT_MESSAGE = "chore(learnings): session-start snapshot"
# git pathspecs (matched from cwd). Portable files don't start with
# `LEARNINGS-`, so they need their own pattern. In neutral mode the portable
# pattern is dropped — see _learnings_pathspecs.
LEARNINGS_PATHSPECS = ("LEARNINGS.md", "LEARNINGS-*.md", "*-PORTABLE-LEARNINGS.md")
NEUTRAL_LEARNINGS_PATHSPECS = ("LEARNINGS.md", "LEARNINGS-*.md")
GIT_TIMEOUT_SECONDS = 30
# Network git ops (fetch/push) get a longer but still bounded timeout. Paired
# with an SSH connect timeout (see _net_env), an offline SessionStart fails
# fast instead of hanging startup.
GIT_NET_TIMEOUT_SECONDS = 20

# Auto-push owned-remote allowlist. The snapshot stays on the current branch
# (so `git status` is unaffected on feature branches); ONLY when a session
# starts on the trunk does the hook reconcile + push to origin (Option Y).
# The push is gated to remotes the user OWNS: the opt-in gate already scopes
# the hook to repos that track the corpus, but those can include a third-party
# repo the user cloned that uses this same system — this stops the hook from
# pushing the user's local snapshots into someone else's project. Anchored with
# `.match` so a look-alike host (`evilgithub.com`, `github.com.evil`) can't pass.

# `.gitattributes` lines that mark the corpus generated (GitHub collapses the
# diffs in PR review + drops the files from language stats) and union-merge
# (concurrent/rebase edits auto-resolve instead of stopping on conflict markers).
# Ensured idempotently in every opted-in repo so the de-noising rolls out
# everywhere: existing repos backfill on their next session, new ones once
# opted in, and a deleted line self-heals. One writer (this hook), keyed on the
# same opt-in gate as the snapshot so un-opted-in repos are never touched.
GITATTRIBUTES_LINES = (
    "LEARNINGS*.md linguist-generated merge=union",
    "*-PORTABLE-LEARNINGS.md linguist-generated merge=union",
)
GITATTRIBUTES_HEADER = (
    "# LEARNINGS corpus = companion journal maintained by background hooks, not\n"
    "# the running codebase. Marked generated (collapses PR diffs, drops from\n"
    "# language stats) + union-merge (concurrent/rebase edits auto-resolve).\n"
    "# Managed by the learnings auto-commit hook; safe to edit or extend.\n"
)


def _log(msg: str) -> None:
    fd: int | None = None
    try:
        fd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            fd = None
            f.write(f"{int(time.time())} {msg}\n")
    except OSError:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True)
class PushOutcome:
    ok: bool
    category: str = ""
    diagnostic: str = ""


def _sanitize_push_diagnostic(stderr: str) -> str:
    """Return bounded Git diagnostic text with credentials removed."""
    line = " | ".join(part.strip() for part in stderr.splitlines() if part.strip())
    line = re.sub(r"[\x00-\x1f\x7f]+", " ", line)
    line = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", line, flags=re.IGNORECASE)
    line = re.sub(
        r"\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]{8,})\b",
        "[redacted]",
        line,
        flags=re.IGNORECASE,
    )
    return line[:200]


def _classify_git_failure(stderr: str) -> str:
    """Classify GitHub/Git fetch or push stderr from specific to generic."""
    lower = stderr.lower()
    if "gh007" in lower or "private email address" in lower or "email privacy" in lower:
        return "remote:email-privacy"
    if "non-fast-forward" in lower or "fetch first" in lower:
        return "remote:non-fast-forward"
    if "gh006" in lower or "gh013" in lower or "protected branch" in lower or "repository rule" in lower:
        return "remote:branch-policy"
    if "permission denied (publickey)" in lower:
        return "transport:ssh-auth"
    if "authentication failed for 'http" in lower:
        return "transport:https-auth"
    if (
        "could not resolve host" in lower
        or "could not resolve hostname" in lower
        or "connection timed out" in lower
        or "connection refused" in lower
        or "failed to connect" in lower
        or "could not connect" in lower
        or "network is unreachable" in lower
        or "operation timed out" in lower
    ):
        return "transport:unavailable"
    return "remote:rejected"


def _git(
    cwd: Path,
    *args: str,
    env: dict[str, str] | None = None,
    timeout: int = GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def _is_git_worktree(cwd: Path) -> bool:
    try:
        r = _git(cwd, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


def _is_tracked_and_clean(cwd: Path, relpath: str) -> bool:
    """True iff `relpath` is TRACKED AND has no staged/unstaged changes vs HEAD
    (its working-tree content equals the committed version). Untracked or dirty →
    False; git error → False (can't prove clean, so the caller treats it as
    unsafe).

    Tracking is checked EXPLICITLY first: `git status --porcelain` emits nothing
    for an IGNORED untracked path too (git hides ignored files), so status alone
    would mis-read an ignored `.gitattributes` as clean — and the backfill would
    then rewrite the user's ignored file and fail to stage it (`git add` refuses
    an ignored path). `git ls-files` lists only tracked paths, so empty output
    means not tracked. (codex PR #35 round 7.)"""
    try:
        ls = _git(cwd, "ls-files", "--", relpath)
        if ls.returncode != 0 or ls.stdout.strip() == "":
            return False
        r = _git(cwd, "status", "--porcelain", "--", relpath)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and r.stdout.strip() == ""


def _git_dir(cwd: Path) -> Path | None:
    try:
        r = _git(cwd, "rev-parse", "--git-dir")
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    gd = Path(r.stdout.strip())
    return gd if gd.is_absolute() else (cwd / gd)


def _operation_in_progress(cwd: Path) -> bool:
    """True if mid-merge/rebase/cherry-pick/revert/bisect — committing now
    could entangle the snapshot with an in-flight operation. Conservative:
    if the git dir can't be located, treat as in-progress (skip)."""
    gd = _git_dir(cwd)
    if gd is None:
        return True
    markers = (
        "MERGE_HEAD",
        "rebase-merge",
        "rebase-apply",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
    )
    return any((gd / m).exists() for m in markers)


def _head_skip_reason(cwd: Path) -> str | None:
    """None if HEAD is an attached branch with at least one commit, else the
    skip reason."""
    if _git(cwd, "symbolic-ref", "-q", "HEAD").returncode != 0:
        return "skip:detached-head"
    if _git(cwd, "rev-parse", "--verify", "-q", "HEAD").returncode != 0:
        return "skip:unborn"
    return None


_OPTIONAL_STATE_MODULE_UNSET = object()
_optional_state_module = _OPTIONAL_STATE_MODULE_UNSET


def _load_optional_state_module():
    """Fail-open state seam (duplicated per the standalone-file hook
    convention — no imports between hook scripts): resolves the sibling
    learnings-state.sh across the source, neutral-core, and rollback
    layouts. None (legacy behavior) when no copy loads."""
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
        name = "learnings_state_snapshot"
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


def _learnings_pathspecs() -> tuple[str, ...]:
    """Snapshot pathspecs for the current runtime mode. After activation the
    identity catalog owns portable snapshots, so `*-PORTABLE-LEARNINGS.md`
    leaves the pathspec: a tracked root export is no longer committed (and a
    stale one is never resurrected into the git record) — it is left
    untouched in the working tree. Fail-open: no loadable state seam, or
    legacy mode, keeps the full legacy tuple byte-identically.

    A skipped tracked dirty portable is harmless here — the snapshot just
    leaves it dirty (no abort, no loss), so this needs no tracked-portable
    carve-out like a branch-switching git operation would. Mode probe uses
    activation_status(),
    which never prints, so an invalid activation record can't leak a
    stderr line into every SessionStart."""
    module = _load_optional_state_module()
    if module is not None:
        try:
            if module.activation_status().state == module.ACTIVATION_VALID:
                return NEUTRAL_LEARNINGS_PATHSPECS
        except Exception:
            pass
    return LEARNINGS_PATHSPECS


def _external_corpus_gate(cwd: Path) -> str | None:
    """Return a startup no-op status for external authority or its damage.

    This deliberately precedes every legacy git probe in ``commit_snapshot``.
    A missing state seam remains legacy-compatible, while an authoritative
    record that cannot be resolved is fail-closed rather than snapshotting a
    checkout that no longer owns the corpus.
    """
    module = _load_optional_state_module()
    if module is None:
        return None
    try:
        location, _ = module.resolve_project_corpus_cached(cwd)
    except Exception as exc:
        if isinstance(exc, module.CorpusResolutionError):
            return "skip:external-corpus-unresolvable"
        return None
    if location is not None and location.mode == "external":
        return "skip:external-corpus"
    return None


def _is_learnings_name(name: str) -> bool:
    """A bare filename (no directory) that is a LEARNINGS artifact."""
    return (
        name == "LEARNINGS.md"
        or (name.startswith("LEARNINGS-") and name.endswith(".md"))
        or name.endswith("-PORTABLE-LEARNINGS.md")
    )


def _corpus_committed(cwd: Path) -> bool | None:
    """True if HEAD has a committed top-level LEARNINGS artifact.

    Keyed on HEAD, not the index: a scaffolded or staged LEARNINGS.md is a
    first-enrollment candidate, not an existing committed corpus. Exact-depth
    automatic enrollment is qualified and validated separately.

    Top-level ONLY: an unrelated nested file (e.g. `templates/LEARNINGS.md`,
    which *this* repo has, or `docs/LEARNINGS.md`) is NOT the system's corpus.
    The learnings system always keeps LEARNINGS files at the repo root, so a
    nested match must not opt the repo in. (`git ls-tree` pathspecs don't glob
    like `git diff`'s, so the HEAD tree is filtered in Python.)"""
    r = _git(cwd, "ls-tree", "-r", "--name-only", "-z", "HEAD")
    if r.returncode != 0:
        return None
    return any("/" not in name and _is_learnings_name(name) for name in r.stdout.split("\0") if name)


def _has_top_level_corpus_entry(cwd: Path) -> bool | None:
    """Cheap pre-lock fingerprint for a first-enrollment candidate."""
    try:
        with os.scandir(cwd) as entries:
            return any(_is_learnings_name(entry.name) for entry in entries)
    except OSError as exc:
        _log(f"{cwd}: auto-enroll candidate scan error: {type(exc).__name__}: {exc}")
        return None


def _first_enrollment_files_safe(cwd: Path, files: list[str]) -> bool:
    """Every selected first-corpus path is top-level regular/single-link."""
    if not files:
        return False
    for relpath in files:
        if "/" in relpath or (relpath != ".gitattributes" and not _is_learnings_name(relpath)):
            return False
        try:
            st = os.lstat(cwd / relpath)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return False
    return True


def _temporary_index_enrollment_safe(cwd: Path, files: tuple[str, ...], env: dict[str, str]) -> bool:
    """Revalidate first-corpus files and their staged Git modes after add."""
    if not _first_enrollment_files_safe(cwd, list(files)):
        return False
    staged = _git(cwd, "ls-files", "--stage", "-z", "--", *files, env=env)
    if staged.returncode != 0:
        return False
    expected = set(files)
    seen: set[str] = set()
    for record in staged.stdout.split("\0"):
        if not record:
            continue
        try:
            metadata, path = record.split("\t", 1)
            mode, _object_id, stage = metadata.split()
        except ValueError:
            return False
        if path not in expected or path in seen or mode not in {"100644", "100755"} or stage != "0":
            return False
        seen.add(path)
    return seen == expected


def _project_lock_path(cwd: Path) -> Path:
    """The project structural lock — SAME path the LEARNINGS writers use
    (bin/learnings-write.sh / learnings-auto-split.sh::_project_lock_path).
    The sha1 is over the resolved cwd: matching it is the whole point, so the
    snapshot serializes against those writers."""
    digest = hashlib.sha1(str(cwd.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path("/tmp") / f"learnings-structure-{digest}.lock"


def _try_project_lock(cwd: Path) -> int | None:
    """Non-blocking acquire of the project structural lock. Returns the fd on
    success; None if a writer holds it (skip — defer to next SessionStart) or
    on any error."""
    try:
        fd = os.open(str(_project_lock_path(cwd)), os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:  # BlockingIOError (held) or any flock failure
        os.close(fd)
        return None
    return fd


def _release_project_lock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def _dirty_learnings(cwd: Path) -> list[str] | None:
    """LEARNINGS artifacts to snapshot once the corpus is opted in: tracked
    files with staged OR unstaged changes, PLUS new untracked siblings the
    split/distill paths generate. Returns None on git error (caller skips —
    never a partial commit).

    Untracked discovery uses `--exclude-standard`, so files matched by an
    explicit `.gitignore` are NOT force-committed — respecting a deliberate
    ignore over forcing durability (this hook runs in every repo globally;
    overriding `.gitignore` is the more surprising behavior). A repo that
    tracks LEARNINGS.md yet ignores its `LEARNINGS-*.md` siblings is
    self-contradictory and out of scope; un-ignore them to opt the siblings in.
    (Codex flagged this 2026-06-03; documented-and-declined.)

    Deletions are picked up too (a tracked file removed from the worktree shows
    in `git diff`/`git diff --cached`), so a deleted LEARNINGS file is committed
    as a deletion. Intended — the reduce/split paths legitimately delete stale
    subfiles and the snapshot must capture that, else a `git clean` would
    resurrect them. A user's manual/in-progress deletion is captured the same
    way; accepted (review 2026-06-04, document-and-declined): the blast radius is
    exactly the one deleted path (same-topic siblings and the portable-pool copy
    under ~/.claude/learnings/ are untouched), and every prior version stays
    recoverable from history (`git checkout <pre-deletion-sha> -- <file>`). The
    opt-in gate keys on HEAD, so any file this can delete-commit necessarily has
    committed history to recover from."""
    pathspecs = _learnings_pathspecs()
    files: set[str] = set()
    for diff_args in (
        ("diff", "--name-only", "-z"),
        ("diff", "--cached", "--name-only", "-z"),
    ):
        r = _git(cwd, *diff_args, "--", *pathspecs)
        if r.returncode != 0:
            return None
        files.update(p for p in r.stdout.split("\0") if p)
    others = _git(
        cwd,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        *pathspecs,
    )
    if others.returncode != 0:
        return None
    files.update(p for p in others.stdout.split("\0") if p)
    # Top-level only — consistent with the opt-in gate. The system keeps
    # LEARNINGS files at the repo root; a nested match (e.g. via the leading-`*`
    # portable pattern) is not the corpus and must not be swept in.
    return sorted(p for p in files if "/" not in p)


def _ensure_gitattributes(cwd: Path) -> bool:
    """Idempotently ensure the corpus `.gitattributes` lines exist at the repo
    root. Returns True iff the file was created or appended to.

    Called only for opted-in repos (gated by the same HEAD check as the
    snapshot), so this never drops a `.gitattributes` into a repo that hasn't
    adopted the corpus.

    Idempotency keys on the glob PATTERN (first whitespace-delimited token), not
    the whole line: a pattern already present is left untouched (so a user's
    customized `LEARNINGS*.md` rule is respected and we never duplicate it),
    while a pattern that's been deleted is re-appended (self-heal). Never raises
    — a hook must not break SessionStart; on any OSError it reports no change."""
    ga = cwd / ".gitattributes"
    required = {line.split()[0]: line for line in GITATTRIBUTES_LINES}
    try:
        existing = ga.read_text(encoding="utf-8") if ga.exists() else None
    except OSError:
        return False
    governed: set[str] = set()
    if existing:
        for raw in existing.splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                governed.add(line.split()[0])
    missing = [line for pat, line in required.items() if pat not in governed]
    if not missing:
        return False
    if existing is None:
        new_content = GITATTRIBUTES_HEADER + "\n".join(missing) + "\n"
    else:
        sep = "" if existing.endswith("\n") or existing == "" else "\n"
        new_content = existing + sep + "\n".join(missing) + "\n"
    try:
        tmp = ga.with_name(f".gitattributes.tmp.{os.getpid()}")
        tmp.write_text(new_content, encoding="utf-8")
        os.replace(tmp, ga)
    except OSError:
        return False
    return True


def _commit_via_temp_index(
    cwd: Path,
    files: list[str],
    *,
    snapshot_email: str,
    first_enrollment_files: tuple[str, ...] = (),
) -> str:
    """Stage + commit through a THROWAWAY index seeded from HEAD, so the user's
    real index is never mutated.

    On failure the real index is untouched — any pre-staged LEARNINGS edits OR
    deletions survive exactly, with no restore logic. On success the commit
    advanced HEAD via the temp index; the real index is then synced for our
    paths so `git status` shows them clean. Hooks run normally (the temp index's
    staged diff is just our `.md` files)."""
    git_dir = _git_dir(cwd)
    if git_dir is None:
        return "error:gitdir"
    # Sweep any stale temp indexes left by a process killed (SIGKILL) between
    # read-tree and the finally-unlink below. We hold the project lock here, and
    # the temp index is per-repo, so no live sibling can own one — they're all
    # dead leftovers, safe to remove. Keeps them from accumulating over time.
    for stale in git_dir.glob(".learnings-autocommit-index.*"):
        try:
            stale.unlink()
        except OSError:
            pass
    tmp_index = git_dir / f".learnings-autocommit-index.{os.getpid()}"
    env = os.environ.copy()
    env["GIT_INDEX_FILE"] = str(tmp_index)
    env["GIT_AUTHOR_EMAIL"] = snapshot_email
    env["GIT_COMMITTER_EMAIL"] = snapshot_email
    try:
        rt = _git(cwd, "read-tree", "HEAD", env=env)
        if rt.returncode != 0:
            return f"error:read-tree:{rt.stderr.strip()[:200]}"
        add = _git(cwd, "add", "--", *files, env=env)
        if add.returncode != 0:
            return f"error:add:{add.stderr.strip()[:200]}"
        if first_enrollment_files and not _temporary_index_enrollment_safe(cwd, first_enrollment_files, env):
            return "error:first-enrollment-validation"
        # --no-verify: skip the repo's pre-commit/commit-msg hooks for this
        # automated `.md` housekeeping commit (scoped exception to the never-skip
        # rule, approved by S). It's not user code, and running an arbitrary
        # pre-commit hook here is exactly what could `git add -A` in-flight code
        # into the snapshot. With hooks off, the temp index — HEAD plus only our
        # files — commits exactly those, nothing else.
        commit = _git(cwd, "commit", "--no-verify", "-m", COMMIT_MESSAGE, env=env)
        if commit.returncode != 0:
            return f"error:commit:{commit.stderr.strip()[:200]}"
    finally:
        try:
            tmp_index.unlink()
        except OSError:
            pass
    # HEAD advanced; bring the real index up to date for our paths (best-effort)
    # so they don't show as staged-modified against the new HEAD. The commit is
    # already durable — if this sync doesn't complete (raise or non-zero rc),
    # record it as "index-sync-deferred" rather than a clean success so the log
    # is accurate. The only effect is our just-committed paths transiently show
    # staged-modified against the new HEAD; the next snapshot's reset (or any
    # `git add`/`git reset`/`git status`) clears it.
    #
    # Decline note (review 2026-06-04): if the user had STAGED a distinct blob of
    # a LEARNINGS path (`git add` v2) and regen then churned the worktree to v3,
    # the snapshot commits v3 and this reset replaces the staged v2 in the real
    # index with v3 — the staged v2 is dropped. Accepted: only uncommitted index
    # state is at risk, every committed version stays in history, and the
    # worktree copy is intact. Re-staging a curated LEARNINGS edit after regen is
    # a rare workflow and the loss is an index entry, not history.
    synced = False
    try:
        reset = _git(cwd, "reset", "-q", "--", *files)
        synced = reset.returncode == 0
    except (OSError, subprocess.SubprocessError):
        synced = False
    if synced:
        return f"committed:{len(files)}"
    return f"committed:{len(files)}:index-sync-deferred"


def _trunk_branch(cwd: Path) -> str | None:
    """The repo's trunk branch name. Prefers what origin considers default
    (`refs/remotes/origin/HEAD`), falling back to a local `main`/`master`. None
    if neither is resolvable — caller then declines to sync (current behaviour)."""
    r = _git(cwd, "symbolic-ref", "-q", "refs/remotes/origin/HEAD")
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip().rsplit("/", 1)[-1]
    for cand in ("main", "master"):
        if _git(cwd, "rev-parse", "--verify", "-q", f"refs/heads/{cand}").returncode == 0:
            return cand
    return None


def _current_branch(cwd: Path) -> str | None:
    """The checked-out branch name, or None if detached (already filtered
    upstream by _head_skip_reason, but kept total)."""
    r = _git(cwd, "symbolic-ref", "--short", "-q", "HEAD")
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return None


def _remote_url(cwd: Path, remote: str = "origin", *, push: bool = False) -> str | None:
    """The remote's URL. With push=True, the EFFECTIVE push URL (honoring
    remote.<r>.pushurl / pushInsteadOf) — i.e. the url `git push` actually
    targets. The owned-remote gate must validate THAT url, since it guards a
    push: a repo with an owned fetch url but an unowned pushurl would otherwise
    slip past the gate and get snapshots --no-verify-pushed to the wrong remote.
    `--push` is a no-op (returns the fetch url) when no pushurl is configured.

    Scope: a remote with MULTIPLE push urls (git pushes to ALL of them) is a
    deliberate multi-mirror setup that can't arise in this single-user threat
    model, so only the first effective push url is validated — `--push` without
    `--all`. (Codex PR #35 round 4; document-and-declined, not in scope.)"""
    args = ["remote", "get-url"]
    if push:
        args.append("--push")
    args.append(remote)
    r = _git(cwd, *args)
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def _is_owned_remote(url: str | None) -> bool:
    """Use the same configured owner pattern as automatic enrollment."""
    module = _load_optional_state_module()
    if module is None:
        return False
    try:
        pattern = module._enrollment_owner_regex()
        return bool(url) and pattern is not None and pattern.match(url) is not None
    except Exception:
        return False


def _ahead_behind(cwd: Path, local_ref: str, remote_ref: str) -> tuple[int, int] | None:
    """(ahead, behind) commit counts of `local_ref` relative to `remote_ref`,
    or None on git error / unexpected output."""
    r = _git(cwd, "rev-list", "--left-right", "--count", f"{remote_ref}...{local_ref}")
    if r.returncode != 0:
        return None
    parts = r.stdout.split()
    if len(parts) != 2:
        return None
    try:
        behind, ahead = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    return ahead, behind


def _ahead_is_snapshot_only(cwd: Path, branch: str) -> bool | None:
    """True iff EVERY commit in origin/<branch>..<branch> is a hook-authored
    snapshot (subject == COMMIT_MESSAGE). The auto-push bypasses the repo's
    pre-push hooks with --no-verify, so it must carry ONLY this hook's own
    snapshots — never a commit a user authored themselves (code straight on local
    main, or unpushed work-in-progress on a feature branch).

    Authorship (the fixed snapshot subject), NOT a path check, is the right
    signal: the snapshot legitimately commits LEARNINGS files AND the corpus
    `.gitattributes`, so a user's HAND-EDITED `.gitattributes` (or LEARNINGS)
    commit would look path-corpus-only and slip through. Subject-matching catches
    it. (Spoofing the subject to smuggle code is a LOCAL actor — out of scope.)

    None on git error (caller declines to push). An empty range counts as NOT
    snapshot-only: nothing sanctioned to ship, so the bypass isn't warranted.
    Empty-subject commits stay in the list (they fail the == check → rejected)."""
    r = _git(
        cwd,
        "log",
        "--format=%s",
        f"refs/remotes/origin/{branch}..refs/heads/{branch}",
    )
    if r.returncode != 0:
        return None
    subjects = r.stdout.splitlines()
    if not subjects:
        return False
    return all(s == COMMIT_MESSAGE for s in subjects)


def _ahead_has_snapshot(cwd: Path, branch: str) -> bool | None:
    """True iff ANY commit in origin/<branch>..<branch> is a hook-authored
    snapshot (subject == COMMIT_MESSAGE). Used wherever the sync could not ship
    the ahead range, to tell a stranded-LEARNINGS case (a snapshot is present →
    notify the user) from ordinary code-only divergence (no snapshot → no
    LEARNINGS notice, which would mislead). None on git error. (codex PR #35
    round 7; extended to feature branches in PR #42.)"""
    r = _git(
        cwd,
        "log",
        "--format=%s",
        f"refs/remotes/origin/{branch}..refs/heads/{branch}",
    )
    if r.returncode != 0:
        return None
    return any(s == COMMIT_MESSAGE for s in r.stdout.splitlines())


def _net_env() -> dict[str, str]:
    """Env for network git ops: bound the SSH connect so an offline SessionStart
    fails fast (never hangs startup) and never blocks on an interactive prompt.

    LC_ALL=C pins git's messages to English so `_fetch_branch` can tell a
    deleted remote branch (`couldn't find remote ref`) from an unreachable
    network — a distinction that decides whether the user gets a rescue warning
    or is left alone to retry next session."""
    env = os.environ.copy()
    base = env.get("GIT_SSH_COMMAND", "ssh")
    env["GIT_SSH_COMMAND"] = f"{base} -o ConnectTimeout=10 -o BatchMode=yes"
    env["LC_ALL"] = "C"
    return env


def _fetch_branch(cwd: Path, branch: str, net: dict[str, str]) -> str:
    """Refresh `refs/remotes/origin/<branch>` from origin. Returns "ok",
    "missing" (the branch no longer exists on origin) or "offline" (unreachable
    / timed out / any other failure).

    The two failure modes must stay distinguishable: "missing" means the branch
    was merged-and-deleted and a snapshot sitting on it is genuinely stranded
    (warn the user), while "offline" is transient and self-heals on the next
    connected session — warning there would cry wolf. git names the first case
    `couldn't find remote ref`, and _net_env pins LC_ALL=C so that string is not
    localized out from under this check.

    Fetches straight into the remote-tracking ref via an explicit (force)
    refspec, so every ahead/behind and snapshot-only check downstream compares
    against a GUARANTEED-fresh origin/<branch> — never a tracking ref left
    stale. A source-only `git fetch origin <branch>` writes only FETCH_HEAD plus
    an *opportunistic* tracking update that a non-standard remote.origin.fetch
    can suppress; `+` updates it unconditionally (and absorbs the rare upstream
    rewind). FF safety is enforced separately by --ff-only and the snapshot-only
    push gate."""
    r = _git(
        cwd,
        "fetch",
        "-q",
        "origin",
        f"+refs/heads/{branch}:refs/remotes/origin/{branch}",
        env=net,
        timeout=GIT_NET_TIMEOUT_SECONDS,
    )
    if r.returncode == 0:
        return "ok"
    if "couldn't find remote ref" in r.stderr:
        return "missing"
    category = _classify_git_failure(r.stderr)
    diagnostic = _sanitize_push_diagnostic(r.stderr)
    detail = f": {diagnostic}" if diagnostic else ""
    if category in ("transport:ssh-auth", "transport:https-auth"):
        _log(f"{cwd}: fetch failure [{category}]{detail}")
        return category
    if category == "transport:unavailable":
        _log(f"{cwd}: fetch failure [{category}]{detail}")
    return "offline"


def _push_snapshot(cwd: Path, branch: str, net: dict[str, str]) -> PushOutcome:
    """Fast-forward-push `branch` to origin, skipping the repo's pre-push hooks.

    --no-verify is the same scoped carve-out the snapshot COMMIT already takes:
    this is automated `.md` housekeeping, not user code. Callers must first prove
    the ahead range is snapshot-only, so the bypass can only ever ship this
    hook's own commits. Without it the push would run the machine's PR-only guard
    (which blocks main outright) and whatever `ty check` / pre-commit stage the
    repo installs — meaning a repo whose CODE doesn't typecheck could never get
    its corpus to origin, which is precisely the stranding this path prevents."""
    try:
        r = _git(
            cwd,
            "push",
            "--no-verify",
            "-q",
            "origin",
            f"{branch}:{branch}",
            env=net,
            timeout=GIT_NET_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        diagnostic = f"{type(exc).__name__} during bounded push"
        outcome = PushOutcome(False, "transport:unavailable", diagnostic)
    else:
        if r.returncode == 0:
            return PushOutcome(True)
        outcome = PushOutcome(
            False,
            _classify_git_failure(r.stderr),
            _sanitize_push_diagnostic(r.stderr),
        )
    detail = f": {outcome.diagnostic}" if outcome.diagnostic else ""
    _log(f"{cwd}: push failure [{outcome.category}]{detail}")
    return outcome


def _has_tracking_ref(cwd: Path, branch: str) -> bool:
    """True iff `refs/remotes/origin/<branch>` exists locally — i.e. the branch
    has been PUBLISHED to origin at some point. Checked before any network op so
    a purely local scratch branch costs nothing at SessionStart."""
    return _git(cwd, "rev-parse", "--verify", "-q", f"refs/remotes/origin/{branch}").returncode == 0


def _sync_branch_to_origin(cwd: Path, branch: str) -> str:
    """Keep an ALREADY-PUBLISHED feature branch's snapshots on origin.

    Why this exists: the snapshot commits to whatever branch the session starts
    on, and off-trunk it was assumed to "ride the eventual PR". It only does if
    the branch is pushed again before the merge — GitHub squash-merges the REMOTE
    branch, so anything committed locally after the last push never lands, and
    the post-merge branch cleanup then deletes the only ref holding it. That tail
    window (last push → merge) is one SessionStart wide and silent.

    Push-only, and deliberately narrower than the trunk path:
      - Requires the branch to ALREADY exist on origin. Publishing a branch is
        the user's call; a local scratch branch is left alone.
      - Requires the ahead range to be snapshot-only, so unpushed user code is
        never shipped to an open PR behind their back. Nothing is stranded by
        holding: the user's own next push carries both.
      - Never fast-forwards the local branch onto origin's moves and never
        force-pushes — moving a checked-out feature branch under the user is a
        worse surprise than a delayed push.

    Accepted cost: pushing on session start adds a commit to an open PR, which
    re-triggers CI and (on a repo configured to dismiss stale approvals) would
    re-request review. The corpus is `linguist-generated`, so the diff itself
    stays collapsed in review. Set LEARNINGS_AUTO_PUSH=0 to opt out."""
    if not _has_tracking_ref(cwd, branch):
        return ""  # never published — not ours to publish
    # Cheap LOCAL pre-check before touching the network. This path is push-only,
    # and a fetch can only move origin/<branch> FORWARD — which can shrink the
    # ahead count but never grow it. So `ahead == 0` against the (possibly stale)
    # tracking ref proves there is nothing to push, and fetching anyway would be
    # pure SessionStart latency spent holding the project structural lock that
    # the corpus writers need. The trunk path can't do this (it fetches in order
    # to discover origin's moves and FF-absorb them); this one has no such duty.
    # Only origin REWINDING (a force-push backward) could hide a pushable commit
    # here — excluded by the single-user threat model, and picked up next session.
    ab = _ahead_behind(cwd, f"refs/heads/{branch}", f"refs/remotes/origin/{branch}")
    if ab is None:
        return "branch:no-upstream"
    if not ab[0]:
        return "branch:behind" if ab[1] else "branch:in-sync"
    net = _net_env()
    fetched = _fetch_branch(cwd, branch, net)
    if fetched == "missing":
        # Merged-and-deleted on origin (a stale tracking ref outlives it). Never
        # re-create it — and a snapshot left behind here IS stranded.
        return _stranded_or(cwd, branch, "branch:gone-on-origin")
    if fetched in ("transport:ssh-auth", "transport:https-auth"):
        return _stranded_or(cwd, branch, f"branch:fetch-failed:{fetched}")
    if fetched != "ok":
        # Transient: unreachable / timed out. The snapshot is safe locally and
        # the next connected session pushes it, so do NOT raise a rescue notice.
        return "branch:offline"
    ab = _ahead_behind(cwd, f"refs/heads/{branch}", f"refs/remotes/origin/{branch}")
    if ab is None:
        return "branch:no-upstream"
    ahead, behind = ab
    if not ahead:
        return "branch:behind" if behind else "branch:in-sync"
    if behind:
        # Remote branch moved elsewhere — never force.
        return _stranded_or(cwd, branch, "branch:diverged")
    snapshot_only = _ahead_is_snapshot_only(cwd, branch)
    if snapshot_only is None:
        return "branch:diff-error"
    if not snapshot_only:
        # Unpushed user code under the snapshot. NOT stranded: the user's own
        # next push to their open PR carries the snapshot along with it.
        return "branch:non-corpus-ahead"
    push = _push_snapshot(cwd, branch, net)
    if push.ok:
        return "branch:pushed"
    # The push lost a race (origin moved between fetch and push) or was rejected.
    # This is the case where a stranded snapshot is CERTAIN — the ahead range was
    # just proven snapshot-only — so it must warn, not merely log.
    return f"branch:stranded-push-failed:{push.category}"


def _stranded_or(cwd: Path, branch: str, status: str) -> str:
    """Mark `status` as `branch:stranded-*` when a hook snapshot is actually
    sitting unpushed in the ahead range, else return it unchanged.

    The residual loss window this whole path exists to close: the push failed,
    so the snapshot is reachable ONLY from the local branch — and the very next
    thing that happens to a merged branch is `git branch -D`. `main()` turns the
    stranded flavor into an in-session warning; the plain flavor is log-only.
    Same positive-fingerprint discipline as the trunk's `diverged` vs
    `non-corpus-diverged`: never raise a LEARNINGS notice for an ahead range
    that carries no LEARNINGS."""
    has_snapshot = _ahead_has_snapshot(cwd, branch)
    if has_snapshot is None:
        return "branch:diff-error"
    return status.replace("branch:", "branch:stranded-", 1) if has_snapshot else status


def _sync_trunk_to_origin(cwd: Path, trunk: str) -> str:
    """Best-effort reconcile of local `trunk` with origin + push of the snapshot.
    ONLY ever fast-forwards — never force-pushes, never auto-rebases — so it
    cannot lose work on either side. Runs under the project lock the caller
    holds. Returns a short status suffix for the log."""
    net = _net_env()
    fetched = _fetch_branch(cwd, trunk, net)
    if fetched in ("transport:ssh-auth", "transport:https-auth"):
        snapshot_only = _ahead_is_snapshot_only(cwd, trunk)
        if snapshot_only:
            return f"fetch-failed:{fetched}"
        if snapshot_only is False:
            return "sync:non-corpus-ahead" if _ahead_has_snapshot(cwd, trunk) else "sync:offline"
        return "sync:diff-error"
    if fetched != "ok":
        return "sync:offline"  # offline / unreachable — snapshot is safe locally
    ab = _ahead_behind(cwd, f"refs/heads/{trunk}", f"refs/remotes/origin/{trunk}")
    if ab is None:
        return "sync:no-upstream"
    ahead, behind = ab
    if ahead and not behind:
        # The push below uses --no-verify, which bypasses the machine's global
        # pre-push hook (it BLOCKS direct pushes to main — the PR-only rule). That
        # bypass is sanctioned ONLY for this hook's own snapshot commits, so gate
        # on it: require EVERY commit in the ahead range to be a hook snapshot
        # (subject == COMMIT_MESSAGE). A commit a user authored on local main —
        # code, OR a hand-edited .gitattributes / LEARNINGS file a path check
        # would wave through — is HELD instead (snapshot stays safe locally; the
        # held status is logged, not silent).
        snapshot_only = _ahead_is_snapshot_only(cwd, trunk)
        if snapshot_only is None:
            return "sync:diff-error"
        if not snapshot_only:
            return "sync:non-corpus-ahead"
        # Snapshot-only + FF-only (origin is strictly behind) → the push can't
        # clobber anything.
        push = _push_snapshot(cwd, trunk, net)
        return "pushed" if push.ok else f"push-failed:{push.category}"
    if behind and not ahead:
        # Purely behind (origin advanced via a PR merge; nothing local to push).
        # Fast-forward local trunk up to origin — FF can't lose work, and we
        # hold the project lock so no concurrent writer races the worktree.
        ff = _git(cwd, "merge", "--ff-only", f"refs/remotes/origin/{trunk}")
        return "absorbed" if ff.returncode == 0 else "absorb-failed"
    if ahead and behind:
        # Diverged: a PR merged on origin without a local pull. Don't force,
        # don't auto-rebase (a stuck rebase would be a worse surprise). Leave it
        # — the snapshot is safe locally and a later clean reconcile drains it.
        # Logged (not silent) so the divergence is visible. BUT only call it
        # "diverged" (which main() turns into a stranded-LEARNINGS notice) when a
        # hook snapshot is actually in the ahead range; ordinary code-only
        # divergence (user left a commit on main + origin moved) carries no
        # stranded snapshot, so it gets a distinct status that does NOT raise the
        # misleading LEARNINGS drift marker.
        has_snapshot = _ahead_has_snapshot(cwd, trunk)
        if has_snapshot is None:
            return "sync:diff-error"
        return "diverged" if has_snapshot else "non-corpus-diverged"
    return "in-sync"


def _maybe_sync(cwd: Path) -> str:
    """Gate + run the origin sync (Option Y). Returns a status suffix to append
    to the snapshot status, or "" when no sync is attempted: push disabled, no
    owned remote, or an unpublished branch.

    On the trunk this reconciles both ways (push when ahead, FF-absorb when
    behind). On any other branch it is push-only and only for a branch already
    published to origin — see _sync_branch_to_origin for why the snapshot must
    not be left local there either.

    Never raises: the snapshot is already durable by the time this runs, so a
    network timeout / git error here must NOT mask the committed status — it
    degrades to a `sync:error` suffix instead."""
    if os.environ.get("LEARNINGS_AUTO_PUSH") == "0":
        return ""
    module = _load_optional_state_module()
    try:
        if module is None or not module.load_install_settings().auto_push:
            return ""
    except Exception:
        return ""
    try:
        trunk = _trunk_branch(cwd)
        branch = _current_branch(cwd)
        if trunk is None or branch is None:
            return ""
        if not _is_owned_remote(_remote_url(cwd, push=True)):
            return ""
        if branch == trunk:
            return _sync_trunk_to_origin(cwd, trunk)
        return _sync_branch_to_origin(cwd, branch)
    except (OSError, subprocess.SubprocessError):
        return "sync:error"


def commit_snapshot(cwd: Path) -> str:
    """Snapshot-commit dirty LEARNINGS files for a managed/eligible repo. Returns a
    short status string (for the log + tests). Never raises — any git error,
    including a subprocess timeout, is caught and reported as an error status;
    the commit goes through a throwaway index, so a failure never touches the
    user's real index."""
    if os.environ.get("LEARNINGS_AUTO_COMMIT") == "0":
        return "skip:disabled"
    # Re-entrancy guard, same as every other trigger in the system: a background
    # `claude -p` (review / distill / validate / prune) sets LEARNINGS_REVIEW_
    # NESTED=1 and fires lifecycle hooks too. Snapshotting mid-pipeline would
    # commit a half-settled corpus and immediately leave fresh dirty output.
    if os.environ.get("LEARNINGS_REVIEW_NESTED") == "1":
        return "skip:nested"
    module = _load_optional_state_module()
    if module is None or not hasattr(module, "load_install_settings"):
        return "skip:settings-unavailable"
    try:
        settings = module.load_install_settings()
    except Exception as exc:
        reason = str(exc) if isinstance(exc, getattr(module, "InstallSettingsError", ())) else "settings:unavailable"
        print(f"learnings: {reason}; automatic snapshot skipped", file=sys.stderr)
        return "skip:settings-invalid"
    if not settings.auto_commit:
        return "skip:disabled"
    if settings.snapshot_email is None:
        print("learnings: settings:snapshot-identity-required; automatic snapshot skipped", file=sys.stderr)
        return "skip:snapshot-identity-required"
    gate = _external_corpus_gate(cwd)
    if gate is not None:
        return gate
    if not _is_git_worktree(cwd):
        return "skip:not-a-repo"
    # Normalize to the repo ROOT. The corpus lives at the repo root, and the
    # LEARNINGS writers lock on the project-root cwd — so when a session is
    # launched from a SUBDIR, operating on `cwd` would scan the wrong dir
    # (missing the root churn) and lock on a path the writers don't use. Anchor
    # everything below to the toplevel so launch dir doesn't matter.
    try:
        top = _git(cwd, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.SubprocessError):
        return "skip:not-a-repo"
    if top.returncode != 0 or not top.stdout.strip():
        return "skip:not-a-repo"
    cwd = Path(top.stdout.strip())
    if _operation_in_progress(cwd):
        return "skip:operation-in-progress"
    try:
        head_skip = _head_skip_reason(cwd)
        if head_skip is not None:
            return head_skip
        # Explicitly enabled profiles retain legacy committed-corpus behavior.
        # Optional enrollment is narrower: exact-depth Git roots under the scaffold
        # root, resolved by the shared state seam. A cheap on-disk fingerprint
        # avoids taking the structural lock before registration has scaffolded
        # the first corpus file.
        committed = _corpus_committed(cwd)
        if committed is None:
            return "error:corpus-head"
        auto_enroll = False
        if not committed:
            module = _load_optional_state_module()
            if module is None:
                return "skip:auto-enroll-unavailable"
            allowed = Path(os.environ.get("LEARNINGS_SCAFFOLD_ROOT") or Path.home() / "Code")
            try:
                qualified = module.qualified_enrollment_root(cwd, allowed)
            except Exception as exc:
                _log(f"{cwd}: auto-enroll qualification error: {type(exc).__name__}: {exc}")
                return "skip:auto-enroll-unavailable"
            if qualified != cwd.resolve():
                return "skip:not-opted-in"
            candidate_present = _has_top_level_corpus_entry(cwd)
            if candidate_present is None:
                return "skip:auto-enroll-unavailable"
            if not candidate_present:
                return "skip:awaiting-scaffold"
            auto_enroll = True

        lock_fd = _try_project_lock(cwd)
        if lock_fd is None:
            return "skip:locked"
        try:
            files = _dirty_learnings(cwd)
            if files is None:
                return "error:diff"
            if auto_enroll and not files:
                return "skip:auto-enroll-blocked"
            if auto_enroll and not _first_enrollment_files_safe(cwd, files):
                return "skip:auto-enroll-unsafe"
            # Backfill the corpus `.gitattributes` (Dial A de-noising). If the
            # ensure changed the file, it rides into THIS snapshot commit — so an
            # opted-in repo with an otherwise-clean corpus still gets it without
            # waiting for the next churn. BUT the snapshot stages the WHOLE
            # working-tree `.gitattributes` and the Option-Y auto-push ships it
            # past the PR-only guard with --no-verify; so only backfill when the
            # file carries no uncommitted USER content to sweep — it either
            # doesn't exist yet (created fresh = purely hook lines) or is tracked
            # and clean vs HEAD (we append only the managed hunk). A dirty or
            # untracked-with-content `.gitattributes` holds user edits: skip the
            # (non-urgent) backfill this session — it self-heals once the file is
            # clean — rather than --no-verify-push user content. (codex #35 rd 6.)
            ga = cwd / ".gitattributes"
            if (not ga.exists() or _is_tracked_and_clean(cwd, ".gitattributes")) and _ensure_gitattributes(cwd):
                files = files + [".gitattributes"]
            first_enrollment_files = tuple(files) if auto_enroll else ()
            snap_status = (
                _commit_via_temp_index(
                    cwd,
                    files,
                    snapshot_email=settings.snapshot_email,
                    first_enrollment_files=first_enrollment_files,
                )
                if files
                else "skip:clean"
            )
            # Option Y: get the snapshot to origin. Runs even on skip:clean so a
            # prior stuck snapshot drains and origin moves are absorbed, but only
            # when on the trunk with an owned remote (see _maybe_sync). Skipped
            # if the snapshot itself errored — don't push a half-made state.
            if snap_status.startswith("error"):
                return snap_status
            sync_status = _maybe_sync(cwd)
            return f"{snap_status}|{sync_status}" if sync_status else snap_status
        finally:
            _release_project_lock(lock_fd)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error:git:{type(exc).__name__}"


def _diverged_warning(cwd: Path) -> str:
    """User-facing text for a diverged trunk: local `main` has unpushed
    snapshot commit(s) AND origin moved (a PR likely merged without a local
    pull). FF-only sync can't self-heal that, so the snapshot sits unpushed;
    rather than let it lurk silently, main() surfaces this directly as
    SessionStart `additionalContext`.

    Guidance carried over from the deleted PostToolUse relay
    (learning-hook.py::_check_diverged_notify, removed by Task 3 of the
    deterministic-SessionStart-delivery plan), with two deliberate deltas:
    the repo path is now folded directly into the sentence (the marker body
    used to carry it separately) and the old "one-shot" framing is dropped —
    this version re-prints every SessionStart while the trunk stays
    diverged, since there's no marker deletion to make it actually one-shot."""
    return (
        f"Your LEARNINGS history on `main` has drifted apart from GitHub in "
        f"{cwd} — there are local snapshot commits AND new commits on GitHub "
        "(a PR likely merged without a local pull). Your learnings are safe "
        "locally but aren't reaching GitHub until this is reconciled. Say "
        "'reconcile learnings with GitHub' and I'll fast-forward/rebase "
        "`main` onto origin safely (never a force-push)."
    )


def _branch_stranded_warning(cwd: Path) -> str:
    """User-facing text for a snapshot stranded on a published feature branch:
    the commit landed but couldn't be pushed (the remote branch moved, or was
    merged and deleted). It now exists on exactly one local ref, and the next
    thing that happens to a merged branch is `git branch -D`.

    Guidance carried over from the deleted PostToolUse relay
    (learning-hook.py::_check_branch_stranded_notify, removed by Task 3),
    with the same two deltas as `_diverged_warning`: the repo path is now
    folded directly into the sentence, and the old "one-shot" framing is
    dropped since this re-prints every SessionStart while the branch stays
    stranded."""
    return (
        f"A LEARNINGS snapshot was committed on a branch in {cwd} but "
        "couldn't be pushed to GitHub (the branch moved on, or was already "
        "merged and deleted there). It now exists only in this local branch "
        "— once that branch is deleted the commit is unreachable by name and "
        "only a reflog dig gets it back. Before merging or deleting this "
        "branch, say 'rescue the stranded learnings' — I'll list what the "
        "trunk is missing and cherry-pick it across."
    )


def _failure_route(category: str) -> str:
    routes = {
        "remote:email-privacy": (
            "Create a recovery ref, replay only the verified snapshot commits "
            "with the GitHub noreply identity, then use the sanctioned "
            "snapshot-only fast-forward push."
        ),
        "remote:non-fast-forward": (
            "Run the corpus-aware landing reconciliation; never force-push or retry before refreshing origin."
        ),
        "remote:branch-policy": (
            "Preserve the local snapshot and inspect the repository rule before choosing a permitted landing route."
        ),
        "transport:ssh-auth": (
            "Normalize the GitHub remote to HTTPS, use the existing "
            "GH_TOKEN-backed gh credential helper, then retry only the "
            "verified snapshot-only fast-forward range."
        ),
        "transport:https-auth": (
            "Verify or renew the GitHub credential used by the authenticated "
            "HTTPS transport before retrying the verified snapshot-only range."
        ),
        "transport:unavailable": (
            "Preserve the local snapshot and retry the bounded sync after network access is available."
        ),
        "remote:rejected": (
            "Preserve the local snapshot and inspect the redacted hook log; do not retry the push blindly."
        ),
    }
    return routes.get(category, routes["remote:rejected"])


def _sync_failure_warning(cwd: Path, category: str) -> str:
    return (
        f"A LEARNINGS snapshot on the current branch in {cwd} is safe locally but its "
        f"GitHub synchronization failed. Failure class: `{category}`. "
        f"{_failure_route(category)}"
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
        data = json.loads(sys.stdin.read() or "{}")
        cwd = Path(data.get("cwd") or os.getcwd())
    except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
        return
    try:
        status = commit_snapshot(cwd)
    except Exception as exc:  # noqa: BLE001 — must never break SessionStart
        _log(f"{cwd}: unexpected error: {exc!r}")
        return
    parts = status.split("|")
    warnings: list[str] = []
    if status in {"skip:settings-invalid", "skip:settings-unavailable", "skip:snapshot-identity-required"}:
        warnings.append(
            f"Automatic LEARNINGS snapshot skipped ({status.removeprefix('skip:')}). "
            "Configure a valid machine-local settings.json and an explicit snapshot email; "
            "no project changes or network operations were performed."
        )
    if "diverged" in parts:
        warnings.append(_diverged_warning(cwd))
    elif branch_failure := next((p for p in parts if p.startswith("branch:stranded-")), None):
        # Push to a published feature branch failed with a hook snapshot in the
        # ahead range. Same hazard as a diverged trunk, but more urgent: the
        # branch's next stop is usually `git branch -D`.
        if branch_failure.startswith(("branch:stranded-fetch-failed:", "branch:stranded-push-failed:")):
            category = branch_failure.split("-failed:", 1)[1]
            warnings.append(_sync_failure_warning(cwd, category))
        else:
            warnings.append(_branch_stranded_warning(cwd))
    elif sync_failure := next((p for p in parts if p.startswith(("push-failed:", "fetch-failed:"))), None):
        category = sync_failure.split("-failed:", 1)[1]
        warnings.append(_sync_failure_warning(cwd, category))
    # Quiet on the common no-ops; record anything that acted or errored.
    if status not in ("skip:clean", "skip:not-opted-in"):
        _log(f"{cwd}: {status}")
    if warnings:
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "SessionStart",
                        "additionalContext": "\n\n---\n\n".join(warnings),
                    }
                }
            )
        )


if __name__ == "__main__":
    main()
