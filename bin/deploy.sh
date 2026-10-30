#!/usr/bin/env bash
# Deploy this project's provider-neutral shared core.
#
# Source of truth: this repo (./hooks/, ./templates/).
# Neutral core: ~/.local/share/learnings-md-system/ (override with
# LEARNINGS_CORE_HOME). The installed core is the ONLY deployed executable
# copy (trim PR, 2026-09-06): the former ~/.claude mirror leg — hooks,
# templates, bin helpers, and the `learn` CLI copied into ~/.claude — is
# retired. ~/.claude/skills is the one Claude-specific destination this
# script still writes, because Claude reads skills from there.
#
# Idempotent. Backs up any existing deployed file that differs from this repo's
# version with a timestamped backup directory before overwriting. A clean
# (no-op) run produces no backup directory.
#
# Hook REGISTRATIONS in ~/.claude/settings.json are NOT auto-managed — see
# settings.snippet.json in this repo for the current registration block.
#
# Backups: stored under $CORE_ROOT/backups/<timestamp>/. Last
# BACKUP_RETENTION timestamped subdirs are kept; older ones are pruned.

set -euo pipefail

case "$#" in
  0) ;;
  1)
    case "$1" in
      --core-only)
        echo "ℹ deploy.sh: --core-only is now the only mode; the flag is accepted as a no-op (it will be removed)." >&2
        ;;
      *)
        echo "✗ unknown deploy argument: $1" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "✗ deploy accepts at most one argument (--core-only, kept as a no-op)" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_SRC="$REPO_ROOT/hooks"
TEMPLATES_SRC="$REPO_ROOT/templates"
BIN_SRC="$REPO_ROOT/bin"
SKILLS_SRC="$REPO_ROOT/skills"
CORE_ROOT="${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}"
CORE_HOOKS_DST="$CORE_ROOT/hooks"
CORE_TEMPLATES_DST="$CORE_ROOT/templates"
CORE_BIN_DST="$CORE_ROOT/bin"
CORE_CLI_DST="$CORE_BIN_DST/learn"
ADAPTER_SRC="$REPO_ROOT/plugins/learnings-md-system-codex/scripts/codex-learnings-hook.py"
ADAPTER_DST="$CORE_ROOT/adapters/codex/codex-learnings-hook.py"
SKILLS_DST="$HOME/.claude/skills"
ARTIFACTS_SRC="$REPO_ROOT/docs/ARTIFACTS.md"
BACKUP_PARENT="$CORE_ROOT/backups"
BACKUP_DIR="$BACKUP_PARENT/$(date +%Y%m%d-%H%M%S)"
BACKUP_RETENTION="${LEARNINGSMD_BACKUP_RETENTION:-10}"
# Scripts removed from the repo whose DEPLOYED copies must also be removed —
# otherwise a zombie copy lingers at $CORE_BIN_DST forever (the copy loop
# only ships what exists in the repo) and stale resolvers keep finding it.
RETIRED_SCRIPTS=(
  learnings-validate.sh learnings-consolidate.sh
  learnings-distill.sh learnings-prune.sh learnings-tiers.sh
  learnings-maintain.sh learnings-maintain-all.sh learnings-reduce.sh
  learnings-review.sh learnings-auto-split.sh learnings-summarize.sh
  learnings-split.sh learnings-consolidate-sections.sh
  learnings-reconcile-log.sh learnings-doctor.sh learnings-corpus-mode.sh
  learnings-mine.sh learnings-fold.sh learnings-rules.sh
  learnings-review-retro.sh learnings-model-runner.sh
  learnings-sync.sh
)
# Hooks removed from the repo whose DEPLOYED copies must also be removed —
# sibling of RETIRED_SCRIPTS, scoped to $CORE_HOOKS_DST.
RETIRED_HOOKS=(
  learning-hook.py learning-on-end.py learning-on-compact.py
  learning-mine-trigger.py
)

# One-time legacy cleanup (trim PR, 2026-09-06): a deploy from before this
# change may have left executable copies under ~/.claude — the mirror leg
# this script no longer writes. Remove exactly these paths if present, never
# anything else under ~/.claude/hooks (the user's own hooks live there too).
LEGACY_CLAUDE_HOOKS_DIR="$HOME/.claude/hooks"
LEGACY_CLAUDE_HOOK_FILES=(
  learning-hook.py learning-on-start.py learning-on-failure.py
  learning-on-end.py learning-on-compact.py learning-mine-trigger.py
  preflight-gate.py commit-learnings.sh scaffold-learnings.sh
)
LEGACY_CLAUDE_TEMPLATES_LEARNINGS="$HOME/.claude/templates/LEARNINGS.md"
LEGACY_CLAUDE_BIN_LEARNINGS_DIR="$HOME/.claude/bin/learnings"
LEGACY_CLAUDE_CLI="$HOME/.claude/bin/learn"

while [[ "$CORE_ROOT" != "/" && "$CORE_ROOT" == */ ]]; do
  CORE_ROOT="${CORE_ROOT%/}"
done
CORE_HOOKS_DST="$CORE_ROOT/hooks"
CORE_TEMPLATES_DST="$CORE_ROOT/templates"
CORE_BIN_DST="$CORE_ROOT/bin"
CORE_CLI_DST="$CORE_BIN_DST/learn"
ADAPTER_DST="$CORE_ROOT/adapters/codex/codex-learnings-hook.py"
CORE_ARTIFACTS_DST="$CORE_ROOT/ARTIFACTS.md"
BACKUP_PARENT="$CORE_ROOT/backups"
BACKUP_DIR="$BACKUP_PARENT/$(date +%Y%m%d-%H%M%S)"
if [[ "$CORE_ROOT" != /* ]]; then
  echo "✗ LEARNINGS_CORE_HOME must be an absolute path: $CORE_ROOT" >&2
  exit 1
fi
case "$CORE_ROOT/" in
  *"//"*|*"/./"*|*"/../"*)
    echo "✗ LEARNINGS_CORE_HOME must not contain empty, '.' or '..' path components: $CORE_ROOT" >&2
    exit 1
    ;;
esac
case "$CORE_ROOT" in
  "/"|"$HOME"|"$HOME/.claude"|"$HOME/.claude/"*|"$REPO_ROOT"|"$REPO_ROOT/"*)
    echo "✗ Refusing unsafe LEARNINGS_CORE_HOME: $CORE_ROOT" >&2
    exit 1
    ;;
esac

file_mode() {
  local mode
  local path="$1"
  if mode="$(stat -f '%Lp' "$path" 2>/dev/null)" && [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  if mode="$(stat -c '%a' "$path" 2>/dev/null)" && [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  return 1
}

# --- Clean-tree gate (opt-in; Finding 3) -------------------------------
# The project-local SessionEnd hook auto-runs this on every session-end. If
# a session ends mid-edit on a deployed source (hooks/ templates/ bin/ skills/
# or the Codex adapter), the uncommitted — possibly broken — file would ship
# to the installed core and become the global copy every other project
# falls back to. So the SessionEnd hook sets DEPLOY_REQUIRE_CLEAN=1: when the
# deployed-source paths are dirty, skip-and-log instead of copying. Scope is
# DEPLOYED SOURCES ONLY — the routinely-dirty regen artifacts (LEARNINGS*.md,
# *-PORTABLE-LEARNINGS.md) are deliberately excluded or the gate would block
# every auto-deploy. The manual/canonical `learn deploy` path leaves the var
# unset and so is never gated — an explicit human deploy of a dirty tree is
# fine.
if [[ "${DEPLOY_REQUIRE_CLEAN:-}" == "1" ]]; then
  # `git status --porcelain` catches STAGED, unstaged, AND untracked changes
  # (plain `git diff --quiet` misses staged) across every deployed-source path
  # INCLUDING skills/ and the exact Codex adapter source. Codex review 2026-06-03.
  #
  # Capture into a var with explicit rc handling rather than testing the command
  # substitution inline. `set -e` is SUPPRESSED inside `[[ $(...) ]]`, and git's
  # error goes to stderr (uncaptured) — so a failing `git status` (e.g. a held
  # index.lock racing this session-end auto-deploy) would substitute an empty
  # string, read as "clean", and ship a possibly-broken tree. Fail CLOSED: any
  # non-zero git rc → skip the deploy. (Review 2026-06-04.)
  if _clean_status="$(git -C "$REPO_ROOT" status --porcelain -- hooks templates bin skills docs/ARTIFACTS.md plugins/learnings-md-system-codex/scripts/codex-learnings-hook.py 2>/dev/null)"; then
    if [[ -n "$_clean_status" ]]; then
      echo "→ Skipping auto-deploy: deployed-source paths (hooks/ templates/ bin/ skills/ docs/ARTIFACTS.md and the Codex adapter) are dirty (staged, unstaged, or untracked)."
      echo "  Commit or stash those changes, then run 'learn deploy' to ship them."
      exit 0
    fi
  else
    echo "→ Skipping auto-deploy: 'git status' failed; cannot confirm deployed-source paths are clean."
    exit 0
  fi
fi

# --- Preflight checks (Codex iteration-3 finding) ----------------------
# All preflight must run BEFORE any file is copied — otherwise a failure
# here leaves the user in a partially-upgraded state (new hooks expect a
# CLI/skill the deploy never installed).
if [[ ! -f "$ADAPTER_SRC" || ! -x "$ADAPTER_SRC" ]]; then
  echo "✗ missing canonical Codex adapter: $ADAPTER_SRC" >&2
  exit 1
fi
if ! ADAPTER_SOURCE_MODE="$(file_mode "$ADAPTER_SRC")"; then
  echo "✗ cannot read canonical Codex adapter mode: $ADAPTER_SRC" >&2
  exit 1
fi

# No-clobber check: `learn` is a generic command name.
check_owned_cli_target() {
  local target="$1"
  if [[ -f "$target" ]] && ! grep -q "learnings-system CLI" "$target"; then
    echo "✗ Refusing to overwrite $target — file lacks the learnings-system" >&2
    echo "  ownership marker. Looks like a foreign 'learn' binary." >&2
    echo "  Move it aside (e.g. mv $target $target.bak) and re-run." >&2
    exit 1
  fi
}
check_owned_cli_target "$CORE_CLI_DST"

# This read-only guard precedes even creation of the deployment lock. Existing
# installations must declare their automation policy before defaults change.
if [[ -f "$BIN_SRC/learnings-state.sh" ]]; then
STATE_SOURCE="$BIN_SRC/learnings-state.sh" SETTINGS_CORE="$CORE_ROOT" uv run --no-project python -c '
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("deploy_install_settings", os.environ["STATE_SOURCE"])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
previous = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    loader.exec_module(module)
    module.check_install_settings_upgrade(os.environ["SETTINGS_CORE"])
except module.InstallSettingsError as exc:
    try: path = module.install_settings_path()
    except module.InstallSettingsError: path = "LEARNINGS_SETTINGS_FILE (absolute path required)"
    print(f"deploy: {exc}; explicit valid settings required at {path}", file=sys.stderr)
    raise SystemExit(1)
finally:
    sys.dont_write_bytecode = previous
'
fi

# Cutover authority must never observe a mixed deployment.  This stamp is
# deliberately outside a generation: it describes executable compatibility,
# not corpus content.  `deploying` is durable before the first copy and
# `complete` is replaced only after every shipped seam has been verified.
STATE_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/learnings-md-system"
DEPLOYMENT_STATE="$STATE_ROOT/cutover-deployment.json"
# One lock inode serializes every whole-machine deployment.  Re-execing this
# script from Python keeps the macOS fcntl flock open across the Bash body;
# the inode is deliberately never unlinked.
DEPLOY_LOCK="$STATE_ROOT/deploy.lock"
if [[ "${LEARNINGS_DEPLOY_LOCK_HELD:-}" != "1" ]]; then
  DEPLOY_SCRIPT="$REPO_ROOT/bin/deploy.sh" DEPLOY_LOCK="$DEPLOY_LOCK" \
    exec uv run --no-project python -c '
import fcntl, os, stat, sys
from pathlib import Path
path = Path(os.environ["DEPLOY_LOCK"])
path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
metadata = os.fstat(fd)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
    os.close(fd)
    raise OSError("deployment lock must be a regular single-link file")
if metadata.st_mode & 0o777 != 0o600:
    os.fchmod(fd, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
os.set_inheritable(fd, True)
env = os.environ.copy()
env["LEARNINGS_DEPLOY_LOCK_HELD"] = "1"
env["LEARNINGS_DEPLOY_LOCK_FD"] = str(fd)
os.execve("/bin/bash", ["/bin/bash", os.environ["DEPLOY_SCRIPT"], *sys.argv[1:]], env)
' "$@"
fi
if [[ -f "$BIN_SRC/learnings-state.sh" ]]; then
CUTOVER_REVISION="$(STATE_SOURCE="$BIN_SRC/learnings-state.sh" uv run --no-project python -c '
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("deploy_state_revision", os.environ["STATE_SOURCE"])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
loader.exec_module(module)
print(module.CORPUS_CUTOVER_COMPAT_REVISION)
' 2>/dev/null || true)"
else
  # Minimal deploy-layout fixtures predate the state seam.  Real deployment
  # sources always carry it; retaining this fallback keeps the old clean-tree
  # gate test fixture focused on its own contract.
  CUTOVER_REVISION=1
fi
if [[ ! "$CUTOVER_REVISION" =~ ^[1-9][0-9]*$ ]]; then
  echo "✗ cannot read cutover compatibility revision" >&2
  exit 1
fi
DEPLOY_NONCE="$(uuidgen | tr -d '-' | tr '[:upper:]' '[:lower:]')"
if [[ ! "$DEPLOY_NONCE" =~ ^[0-9a-f]{16,64}$ ]]; then
  echo "✗ cannot create deployment nonce" >&2
  exit 1
fi
write_deployment_phase() {
  local phase="$1"
  mkdir -p "$STATE_ROOT"
  DEPLOY_PHASE="$phase" DEPLOY_PATH="$DEPLOYMENT_STATE" DEPLOY_NONCE="$DEPLOY_NONCE" DEPLOY_REVISION="$CUTOVER_REVISION" \
    uv run --no-project python -c '
import json, os, tempfile
from pathlib import Path
path = Path(os.environ["DEPLOY_PATH"])
record = {"schema_version": 1, "phase": os.environ["DEPLOY_PHASE"], "nonce": os.environ["DEPLOY_NONCE"], "compatibility_revision": int(os.environ["DEPLOY_REVISION"])}
phase = os.environ["DEPLOY_PHASE"]
def crash(boundary):
    if os.environ.get("LEARNINGS_DEPLOY_CRASH_POINT") == boundary:
        os._exit(70)
crash(f"before-{phase}-write")
fd, temporary = tempfile.mkstemp(prefix=".cutover-deployment.json.tmp-", dir=path.parent)
try:
    with os.fdopen(fd, "wb") as handle:
        handle.write((json.dumps(record, sort_keys=True, indent=2) + "\n").encode())
        handle.flush()
        crash(f"after-{phase}-write")
        crash(f"before-{phase}-fsync")
        os.fsync(handle.fileno())
        crash(f"after-{phase}-fsync")
    crash(f"before-{phase}-replace")
    os.replace(temporary, path)
    crash(f"after-{phase}-replace")
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
except BaseException:
    try: os.unlink(temporary)
    except FileNotFoundError: pass
    raise
'
}
if [[ -f "$BIN_SRC/learnings-state.sh" ]]; then
STATE_SOURCE="$BIN_SRC/learnings-state.sh" SETTINGS_CORE="$CORE_ROOT" uv run --no-project python -c '
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("deploy_install_provenance", os.environ["STATE_SOURCE"])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
previous = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    loader.exec_module(module)
    module.write_install_settings_compatibility(os.environ["SETTINGS_CORE"])
finally:
    sys.dont_write_bytecode = previous
'
fi
write_deployment_phase deploying

# --- Stage actual deployment -------------------------------------------

mkdir -p "$CORE_HOOKS_DST" "$CORE_TEMPLATES_DST" "$CORE_BIN_DST" "$SKILLS_DST"

backup_needed=0
backup_one() {
  local src="$1" dst="$2" subdir="$3"
  if [[ -f "$dst" ]] && ! cmp -s "$src" "$dst"; then
    backup_needed=1
    mkdir -p "$BACKUP_DIR/$subdir"
    cp -p "$dst" "$BACKUP_DIR/$subdir/$(basename "$dst")"
  fi
}

for src in "$HOOKS_SRC"/*; do
  [[ -f "$src" ]] || continue
  backup_one "$src" "$CORE_HOOKS_DST/$(basename "$src")" "installed-core/hooks"
done
for src in "$TEMPLATES_SRC"/*; do
  [[ -f "$src" ]] || continue
  backup_one "$src" "$CORE_TEMPLATES_DST/$(basename "$src")" "installed-core/templates"
done
for src in "$BIN_SRC"/learnings-*.sh; do
  [[ -f "$src" ]] || continue
  backup_one "$src" "$CORE_BIN_DST/$(basename "$src")" "installed-core/bin"
done
# The pre-flight gate class data file deploys NEXT TO the retro script — both
# the deployed retro copy and the gate hook resolve it there.
backup_one "$BIN_SRC/preflight-gate-classes.json" "$CORE_BIN_DST/preflight-gate-classes.json" "installed-core/bin"
# Retired deployed copies are backed up before the later removal step, so the
# removal is as reversible as an overwrite. Guarded on absence from the
# CURRENT source tree, not just membership in the static name list — a name
# once retired must not be treated as a zombie forever if it is legitimately
# a live source file again (and a test fixture that reuses a retired name as
# a stand-in "kept" script must not have it deleted out from under it).
for name in "${RETIRED_SCRIPTS[@]}"; do
  if [[ ! -f "$BIN_SRC/$name" && -f "$CORE_BIN_DST/$name" ]]; then
    backup_needed=1
    mkdir -p "$BACKUP_DIR/installed-core/bin"
    cp -p "$CORE_BIN_DST/$name" "$BACKUP_DIR/installed-core/bin/$name"
  fi
done
for name in "${RETIRED_HOOKS[@]}"; do
  if [[ ! -f "$HOOKS_SRC/$name" && -f "$CORE_HOOKS_DST/$name" ]]; then
    backup_needed=1
    mkdir -p "$BACKUP_DIR/installed-core/hooks"
    cp -p "$CORE_HOOKS_DST/$name" "$BACKUP_DIR/installed-core/hooks/$name"
  fi
done
backup_one "$BIN_SRC/learn" "$CORE_CLI_DST" "installed-core/bin"
backup_one "$ADAPTER_SRC" "$ADAPTER_DST" "installed-core/adapters/codex"
if [[ -f "$ARTIFACTS_SRC" ]]; then backup_one "$ARTIFACTS_SRC" "$CORE_ARTIFACTS_DST" "installed-core"; fi
if [[ -d "$SKILLS_SRC" ]]; then
  for skill_dir in "$SKILLS_SRC"/*/; do
    [[ -d "$skill_dir" ]] || continue
    skill_name=$(basename "$skill_dir")
    for src in "$skill_dir"*; do
      [[ -f "$src" ]] || continue
      backup_one "$src" "$SKILLS_DST/$skill_name/$(basename "$src")" "skills/$skill_name"
    done
  done
fi

# One-time legacy cleanup (trim PR, 2026-09-06): back up, then remove exactly
# the fixed set of paths a pre-trim deploy could have left under ~/.claude.
# Never touches any other file in ~/.claude/hooks — S's own hooks live there.
legacy_removed=()
for name in "${LEGACY_CLAUDE_HOOK_FILES[@]}"; do
  target="$LEGACY_CLAUDE_HOOKS_DIR/$name"
  if [[ -f "$target" ]]; then
    backup_needed=1
    mkdir -p "$BACKUP_DIR/legacy-cleanup/hooks"
    cp -p "$target" "$BACKUP_DIR/legacy-cleanup/hooks/$name"
    rm -f "$target"
    legacy_removed+=("$target")
  fi
done
if [[ -f "$LEGACY_CLAUDE_TEMPLATES_LEARNINGS" ]]; then
  backup_needed=1
  mkdir -p "$BACKUP_DIR/legacy-cleanup/templates"
  cp -p "$LEGACY_CLAUDE_TEMPLATES_LEARNINGS" "$BACKUP_DIR/legacy-cleanup/templates/LEARNINGS.md"
  rm -f "$LEGACY_CLAUDE_TEMPLATES_LEARNINGS"
  legacy_removed+=("$LEGACY_CLAUDE_TEMPLATES_LEARNINGS")
fi
if [[ -d "$LEGACY_CLAUDE_BIN_LEARNINGS_DIR" && ! -L "$LEGACY_CLAUDE_BIN_LEARNINGS_DIR" ]]; then
  backup_needed=1
  mkdir -p "$BACKUP_DIR/legacy-cleanup/bin"
  cp -pr "$LEGACY_CLAUDE_BIN_LEARNINGS_DIR" "$BACKUP_DIR/legacy-cleanup/bin/learnings"
  rm -rf "$LEGACY_CLAUDE_BIN_LEARNINGS_DIR"
  legacy_removed+=("$LEGACY_CLAUDE_BIN_LEARNINGS_DIR")
fi
# `learn` is a generic command name: remove the legacy copy only when it
# carries this project's ownership marker (same check the core target gets).
if [[ -f "$LEGACY_CLAUDE_CLI" ]]; then
  if grep -q "learnings-system CLI" "$LEGACY_CLAUDE_CLI"; then
    backup_needed=1
    mkdir -p "$BACKUP_DIR/legacy-cleanup/bin"
    cp -p "$LEGACY_CLAUDE_CLI" "$BACKUP_DIR/legacy-cleanup/bin/learn"
    rm -f "$LEGACY_CLAUDE_CLI"
    legacy_removed+=("$LEGACY_CLAUDE_CLI")
  else
    echo "ℹ NOTICE: $LEGACY_CLAUDE_CLI is not this project's learn CLI; left in place."
  fi
fi
if [[ $backup_needed -eq 1 ]]; then
  echo "→ Backed up changed deployed files to: $BACKUP_DIR"
  # Rotate: keep the BACKUP_RETENTION newest timestamped subdirs under
  # BACKUP_PARENT, prune older. Names are sortable timestamps so a
  # plain `sort | head -n <prune_count>` works portably on BSD head
  # (macOS) without relying on GNU head's `head -n -N` form.
  if [[ -d "$BACKUP_PARENT" ]]; then
    # shellcheck disable=SC2012
    _backup_list=$(ls -1 "$BACKUP_PARENT" 2>/dev/null | sort)
    if [[ -n "$_backup_list" ]]; then
      _backup_total=$(printf '%s\n' "$_backup_list" | wc -l | tr -d ' ')
      _prune_count=$(( _backup_total - BACKUP_RETENTION ))
      if (( _prune_count > 0 )); then
        printf '%s\n' "$_backup_list" | head -n "$_prune_count" | while IFS= read -r old; do
          # Defensive: only rm under BACKUP_PARENT, only timestamped names
          if [[ "$old" =~ ^[0-9]{8}-[0-9]{6}$ ]]; then
            rm -rf "$BACKUP_PARENT/$old"
          fi
        done
      fi
    fi
  fi
fi

for target in "${legacy_removed[@]:-}"; do
  [[ -n "$target" ]] || continue
  echo "→ Removed legacy ~/.claude copy: $target (backup in $BACKUP_DIR/legacy-cleanup)"
done

# Skip directories (e.g. __pycache__ created by `uv run` against scripts in
# the source dir). cp -p (no -r) would otherwise fail on them.
copy_files() {
  local src_dir="$1" dst_dir="$2"
  for f in "$src_dir"/*; do
    [[ -f "$f" ]] || continue
    cp -p "$f" "$dst_dir/"
  done
}

# Bin helpers land BEFORE the hooks copy: hooks import learnings-state.sh at
# load, so a SessionStart firing mid-deploy must find the state helper
# already in place. The mode adapter imports that state helper too; copy the
# state module first so a partial deployment cannot expose the adapter
# before its compatible state seam.
copy_bin_helper() {
  local src="$1"
  cp -p "$src" "$CORE_BIN_DST/"
  if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "after-copy-$(basename "$src")" ]]; then kill -KILL "$$"; fi
}
if [[ -f "$BIN_SRC/learnings-state.sh" ]]; then
  copy_bin_helper "$BIN_SRC/learnings-state.sh"
fi
for src in "$BIN_SRC"/learnings-*.sh; do
  [[ -f "$src" ]] || continue
  [[ "$(basename "$src")" == "learnings-state.sh" ]] && continue
  copy_bin_helper "$src"
done
[[ -f "$BIN_SRC/preflight-gate-classes.json" ]] && cp -p "$BIN_SRC/preflight-gate-classes.json" "$CORE_BIN_DST/"
for name in "${RETIRED_SCRIPTS[@]}"; do
  if [[ ! -f "$BIN_SRC/$name" && -f "$CORE_BIN_DST/$name" ]]; then
    rm -f "$CORE_BIN_DST/$name"
    echo "→ Removed retired script: $CORE_BIN_DST/$name (backup in $BACKUP_DIR/installed-core/bin)"
  fi
done
chmod +x "$CORE_BIN_DST"/*.sh 2>/dev/null || true

# The Codex adapter is an independently executable seam.  Stage beside the
# destination and rename only after its complete executable bytes exist, so
# a hook running during deployment sees either version, never a partial file.
install_codex_adapter() {
  local adapter_dir destination_mode source_mode stale temporary
  adapter_dir="$(dirname "$ADAPTER_DST")"
  for stale in "$adapter_dir"/.codex-learnings-hook.py.tmp.*; do
    [[ -f "$stale" && ! -L "$stale" ]] || continue
    rm -f "$stale"
  done
  source_mode="$ADAPTER_SOURCE_MODE"
  destination_mode=""
  if [[ -f "$ADAPTER_DST" && ! -L "$ADAPTER_DST" ]]; then
    if ! destination_mode="$(file_mode "$ADAPTER_DST")"; then
      destination_mode=""
    fi
  fi
  if [[ -f "$ADAPTER_DST" && ! -L "$ADAPTER_DST" ]] && cmp -s "$ADAPTER_SRC" "$ADAPTER_DST" && [[ "$source_mode" == "$destination_mode" ]]; then
    return 0
  fi
  temporary="$(mktemp "$adapter_dir/.codex-learnings-hook.py.tmp.XXXXXX")"
  if ! cp -p "$ADAPTER_SRC" "$temporary" || ! chmod "$source_mode" "$temporary"; then
    rm -f "$temporary"
    return 1
  fi
  if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "before-adapter-replace" ]]; then kill -KILL "$$"; fi
  if ! mv -f "$temporary" "$ADAPTER_DST"; then
    rm -f "$temporary"
    return 1
  fi
}

copy_files "$HOOKS_SRC" "$CORE_HOOKS_DST"
chmod +x "$CORE_HOOKS_DST"/*.sh "$CORE_HOOKS_DST"/*.py 2>/dev/null || true
for name in "${RETIRED_HOOKS[@]}"; do
  if [[ ! -f "$HOOKS_SRC/$name" && -f "$CORE_HOOKS_DST/$name" ]]; then
    rm -f "$CORE_HOOKS_DST/$name"
    echo "→ Removed retired hook: $CORE_HOOKS_DST/$name (backup in $BACKUP_DIR/installed-core/hooks)"
  fi
done

# Cold-machine interpreter-floor probe (never blocks deploy — warn only).
# The Claude hook registrations run under --offline, so uv cannot warm a
# managed interpreter at hook-fire time — this probe IS the detector: it
# runs the exact registration prefix (settings.snippet.json) once and warns
# when no interpreter satisfying the hooks' own PEP 723 floor
# (hooks/commit-learnings.sh:3, bin/learnings-state.sh:3) is available
# offline. LEARNINGS_HOOK_PYTHON_FLOOR overrides the floor for testing.
check_hook_python_floor() {
  local floor="${LEARNINGS_HOOK_PYTHON_FLOOR:->=3.11}"
  local cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/learnings-md-system/uv-cache"
  if ! UV_CACHE_DIR="$cache_dir" uv run --no-project --offline --python "$floor" python -c pass >/dev/null 2>&1; then
    echo "⚠ WARNING: no Python $floor interpreter is available offline."
    echo "  The Claude hook registrations (settings.snippet.json) run under"
    echo "  uv run --no-project --offline --python '$floor'; every hook fire"
    echo "  will fail silently until one is installed."
    echo "  Fix: uv python install 3.13 (or any interpreter satisfying $floor)."
  fi
}
check_hook_python_floor

# Registration check (never edits settings.json — warn only). The
# learning-on-start.py SessionStart injector ships with the hooks copy
# above but is NOT auto-registered in ~/.claude/settings.json; a deploy
# with the hook file present but no registration silently no-ops.
has_neutral_start_registration() {
  local settings_json="$1"
  local installed_hook="$CORE_HOOKS_DST/learning-on-start.py"
  local portable_hook='${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/hooks/learning-on-start.py'
  uv run --no-project python -c '
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        root = json.load(handle)
except (OSError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)

hooks = root.get("hooks") if isinstance(root, dict) else None
groups = hooks.get("SessionStart") if isinstance(hooks, dict) else None
if not isinstance(groups, list):
    raise SystemExit(1)
for group in groups:
    entries = group.get("hooks") if isinstance(group, dict) else None
    if not isinstance(entries, list):
        continue
    for entry in entries:
        command = entry.get("command") if isinstance(entry, dict) else None
        if isinstance(command, str) and any(path in command for path in sys.argv[2:]):
            raise SystemExit(0)
raise SystemExit(1)
' "$settings_json" "$portable_hook" "$installed_hook" 2>/dev/null
}

# Legacy-form convergence notice (never edits settings.json — notice only).
# deploy.sh never edits settings.json, so a machine that merged the
# pre-#149 snippet (bare `uv run python`, no --no-project) keeps syncing
# whatever project it's cwd'd into on every hook fire with no signal. This
# is deliberately separate from has_neutral_start_registration above: that
# check only confirms a hook PATH is registered and stays warning-free
# once it is (the registration works); this one additionally inspects the
# invocation form of EVERY registered hook command and never turns a
# working (if stale) registration into a WARNING.
has_legacy_uv_hook_invocation() {
  local settings_json="$1"
  local installed_hooks_dir="$CORE_HOOKS_DST/"
  local portable_hooks_dir='${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/hooks/'
  # Only THIS system's uv-run hooks are in scope — the ones settings.snippet.json
  # registers through `uv run`. The legacy Claude tree's hooks dir is shared
  # with unrelated user hooks (format-on-save, ...), and our own bash hook
  # (scaffold-learnings.sh) never carries the wrapper; neither may trip this.
  local snippet_json="$REPO_ROOT/settings.snippet.json"
  # settings.json stores each registration verbatim, so a hand-written legacy
  # registration may spell the tree as $HOME/~ rather than the expanded path.
  local legacy_hooks_dirs=(
    "$LEGACY_CLAUDE_HOOKS_DIR/" '$HOME/.claude/hooks/' '${HOME}/.claude/hooks/' '~/.claude/hooks/'
  )
  if [[ ! -f "$snippet_json" ]]; then
    echo "⚠ WARNING: $snippet_json is missing; skipping the legacy-registration check." >&2
    return 1
  fi
  local rc=0
  uv run --no-project python -c '
import json
import re
import sys


def load_hooks(path, *, unusable_rc):
    try:
        with open(path, encoding="utf-8") as handle:
            root = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit(unusable_rc)
    hooks = root.get("hooks") if isinstance(root, dict) else None
    if not isinstance(hooks, dict):
        raise SystemExit(unusable_rc)
    return hooks


def commands(hooks):
    for groups in hooks.values():
        if not isinstance(groups, list):
            continue
        for group in groups:
            entries = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(entries, list):
                continue
            for entry in entries:
                command = entry.get("command") if isinstance(entry, dict) else None
                if isinstance(command, str):
                    yield command


# rc 2 = the snippet is unreadable or names no uv-run hook: the check cannot
# run, which the caller reports instead of silently retiring the detector.
names = set()
for command in commands(load_hooks(sys.argv[2], unusable_rc=2)):
    # Basename after /hooks/, whatever the quoting around it.
    match = re.search(r"/hooks/([\w.-]+)", command)
    if match and "uv run" in command:
        names.add(match.group(1))
if not names:
    raise SystemExit(2)
dirs = sys.argv[3:]
markers = [d + n for d in dirs for n in sorted(names)]
hooks = load_hooks(sys.argv[1], unusable_rc=1)
for groups in hooks.values():
    if not isinstance(groups, list):
        continue
    for group in groups:
        entries = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(entries, list):
            continue
        for entry in entries:
            command = entry.get("command") if isinstance(entry, dict) else None
            if not isinstance(command, str):
                continue
            # The snippet form exactly: isolated cache, no project sync, offline,
            # and the >=3.11 floor selector (a bare --python <other> is not current).
            current = (
                "UV_CACHE_DIR=" in command
                and "--no-project" in command
                and "--offline" in command
                and re.search(r"--python\s+[\x27\"]?>=3\.11", command) is not None
            )
            if "uv run" in command and any(marker in command for marker in markers) and not current:
                raise SystemExit(0)
raise SystemExit(1)
' "$settings_json" "$snippet_json" "$portable_hooks_dir" "$installed_hooks_dir" "${legacy_hooks_dirs[@]}" 2>/dev/null || rc=$?
  if [[ $rc -eq 2 ]]; then
    echo "⚠ WARNING: $snippet_json names no uv-run hook (unreadable or drifted); skipping the legacy-registration check." >&2
    return 1
  fi
  return "$rc"
}

SETTINGS_JSON="$HOME/.claude/settings.json"
if [[ -f "$SETTINGS_JSON" ]] && ! has_neutral_start_registration "$SETTINGS_JSON"; then
  echo "⚠ WARNING: $SETTINGS_JSON does not register the neutral-core learning-on-start.py."
  echo "  Merge the SessionStart entry from $REPO_ROOT/settings.snippet.json"
  echo "  by hand — deploy.sh never edits settings.json."
fi
if [[ -f "$SETTINGS_JSON" ]] && has_legacy_uv_hook_invocation "$SETTINGS_JSON"; then
  echo "ℹ NOTICE: $SETTINGS_JSON registers a hook without the full --no-project --offline --python wrapper (pre-#149 form)."
  echo "  Re-merge the SessionStart/PreToolUse/etc. entries from"
  echo "  $REPO_ROOT/settings.snippet.json by hand to stop hooks from syncing"
  echo "  whatever project you're in on every fire — deploy.sh never edits settings.json."
fi

copy_files "$TEMPLATES_SRC" "$CORE_TEMPLATES_DST"

if [[ -f "$BIN_SRC/learn" ]]; then
  # No-clobber preflight already ran above — safe to copy.
  cp -p "$BIN_SRC/learn" "$CORE_CLI_DST"
  chmod +x "$CORE_CLI_DST"
fi

# Runtime-artifact key: ships with the neutral core so the manifest travels
# with the executables it inventories.
if [[ -f "$ARTIFACTS_SRC" ]]; then cp -p "$ARTIFACTS_SRC" "$CORE_ARTIFACTS_DST"; fi

if [[ -d "$SKILLS_SRC" ]]; then
  for skill_dir in "$SKILLS_SRC"/*/; do
    [[ -d "$skill_dir" ]] || continue
    skill_name=$(basename "$skill_dir")
    mkdir -p "$SKILLS_DST/$skill_name"
    for src in "$skill_dir"*; do
      [[ -f "$src" ]] || continue
      cp -p "$src" "$SKILLS_DST/$skill_name/"
    done
  done
fi

# Bootstrap only a machine whose durable state is demonstrably empty.  A
# populated neutral state is a non-fresh redeploy: do not reinterpret it
# merely because new executable bytes arrived.
if [[ -f "$CORE_BIN_DST/learnings-state.sh" ]]; then
if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "before-bootstrap" ]]; then kill -KILL "$$"; fi
BOOTSTRAP_STATUS="$(STATE_SOURCE="$CORE_BIN_DST/learnings-state.sh" uv run --no-project python -c '
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("deploy_state_bootstrap", os.environ["STATE_SOURCE"])
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
loader.exec_module(module)
outcome = module.bootstrap_empty_neutral_state()
print(outcome.status)
' || true)"
case "$BOOTSTRAP_STATUS" in
  activated) echo "→ Fresh neutral bootstrap activated" ;;
  blocked) echo "→ Non-fresh bootstrap skip" ;;
  error) echo "✗ bootstrap failed while inspecting or verifying machine state" >&2; exit 1 ;;
  *) echo "✗ bootstrap probe failed: $BOOTSTRAP_STATUS" >&2; exit 1 ;;
esac
if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "after-bootstrap" ]]; then kill -KILL "$$"; fi
else
  echo "→ Non-fresh bootstrap skip: state helper is absent from this reduced deployment fixture"
fi

mkdir -p "$(dirname "$ADAPTER_DST")"
install_codex_adapter
if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "before-verify" ]]; then kill -KILL "$$"; fi

# Compare every independently loadable state seam before publishing current.
if [[ -f "$BIN_SRC/learnings-state.sh" ]]; then
  cmp -s "$BIN_SRC/learnings-state.sh" "$CORE_BIN_DST/learnings-state.sh"
fi
if [[ -f "$BIN_SRC/learnings-register.sh" ]]; then
  cmp -s "$BIN_SRC/learnings-register.sh" "$CORE_BIN_DST/learnings-register.sh"
fi
cmp -s "$ADAPTER_SRC" "$ADAPTER_DST"
if [[ "${LEARNINGS_DEPLOY_CRASH_POINT:-}" == "after-verify" ]]; then kill -KILL "$$"; fi
write_deployment_phase complete

echo "→ Deployed:"
for f in "$HOOKS_SRC"/*; do
  [[ -f "$f" ]] || continue
  echo "    $CORE_HOOKS_DST/$(basename "$f")"
done
for f in "$TEMPLATES_SRC"/*; do
  [[ -f "$f" ]] || continue
  echo "    $CORE_TEMPLATES_DST/$(basename "$f")"
done
for f in "$BIN_SRC"/learnings-*.sh; do
  [[ -f "$f" ]] || continue
  echo "    $CORE_BIN_DST/$(basename "$f")"
done
[[ -f "$CORE_BIN_DST/preflight-gate-classes.json" ]] && echo "    $CORE_BIN_DST/preflight-gate-classes.json"
[[ -f "$CORE_CLI_DST" ]] && echo "    $CORE_CLI_DST"
[[ -f "$CORE_ARTIFACTS_DST" ]] && echo "    $CORE_ARTIFACTS_DST"
echo "    $ADAPTER_DST"
if [[ -d "$SKILLS_SRC" ]]; then
  for skill_dir in "$SKILLS_SRC"/*/; do
    [[ -d "$skill_dir" ]] || continue
    skill_name=$(basename "$skill_dir")
    for f in "$skill_dir"*; do
      [[ -f "$f" ]] || continue
      echo "    $SKILLS_DST/$skill_name/$(basename "$f")"
    done
  done
fi
echo
echo "Reminder: hook REGISTRATIONS in ~/.claude/settings.json are not auto-managed."
echo "          See ./settings.snippet.json for this project's current block."
echo "          The 'learn' CLI is at $CORE_CLI_DST."
