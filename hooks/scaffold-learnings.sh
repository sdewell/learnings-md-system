#!/usr/bin/env bash
# Hook: SessionStart
# If the current project is under the allowed root (default
# ~/Code/{category}/{proj}/) and is missing LEARNINGS.md, copy it from the
# template directory.
#
# Env overrides (mostly for tests):
#   LEARNINGS_TEMPLATE_DIR  template source dir (default: this install's
#                           sibling templates directory)
#   LEARNINGS_SCAFFOLD_ROOT path prefix that gates scaffolding
#                           (default $HOME/Code)

set -euo pipefail

# LEARNINGS_SESSION_CLASS=harness: a test/CI harness session must never touch
# the corpus or spawn a worker (see CLAUDE.md). An unrecognized value falls
# open to interactive with one stderr warning, matching the Python hooks'
# duplicated _session_class() helper.
case "${LEARNINGS_SESSION_CLASS:-interactive}" in
  interactive|automation|harness) ;;
  *)
    echo "learnings: unknown LEARNINGS_SESSION_CLASS=${LEARNINGS_SESSION_CLASS}, treating as interactive" >&2
    ;;
esac
if [[ "${LEARNINGS_SESSION_CLASS:-interactive}" == "harness" ]]; then
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for worker in \
  "$SCRIPT_DIR/../bin/learnings-register.sh" \
  "${LEARNINGS_CORE_HOME:-$HOME/.local/share/learnings-md-system}/bin/learnings-register.sh" \
  "$SCRIPT_DIR/../bin/learnings/learnings-register.sh" \
  "$HOME/.claude/bin/learnings/learnings-register.sh"; do
  if [[ -x "$worker" ]]; then
    exec "$worker"
  fi
done
echo 'learnings: corpus mode unavailable; skipping scaffold' >&2
echo '{"decision":"approve"}'
