#!/usr/bin/env bash
# InstallGuard pre-commit shim — for users who don't use the
# `pre-commit` framework. Symlink or copy to `.git/hooks/pre-commit`:
#
#   ln -s ../../examples/hooks/pre-commit.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Behaviour:
#   * Runs only when a lockfile is in the staged diff.
#   * Calls `installguard scan` at the repo root.
#   * Exits non-zero on any block decision (which aborts the commit).
#   * Set `INSTALLGUARD_SKIP=1` in the environment to bypass for one commit.

set -euo pipefail

if [[ "${INSTALLGUARD_SKIP:-}" == "1" ]]; then
  echo "installguard: skipped via INSTALLGUARD_SKIP=1" >&2
  exit 0
fi

# Only run when lockfiles are actually being committed.
changed=$(git diff --cached --name-only --diff-filter=ACMR \
  | grep -E '(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$' || true)
if [[ -z "$changed" ]]; then
  exit 0
fi

if ! command -v installguard >/dev/null 2>&1; then
  echo "installguard: binary not on PATH; install with \`cargo install --locked installguard\`" >&2
  echo "installguard: skipping (set INSTALLGUARD_SKIP=1 to silence)" >&2
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel)
exec installguard scan --path "$repo_root" --format human
