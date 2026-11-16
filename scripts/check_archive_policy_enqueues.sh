#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Test fixtures deliberately seed malformed queue rows; production enqueues all pass through
# client/archive_policy.rs so new sender, witness, push, or rescue paths cannot bypass the veto.
found=0
while IFS= read -r source; do
  case "$source" in
    src/client/archive_policy.rs|src/client/*_unit_tests.rs) continue ;;
    src/client/live_sync.rs|src/client/live_plane.rs)
      if sed '/^#\[cfg(test)\]/,$d' "$source" | rg -n 'enqueue_labyrinth_item\('; then
        printf 'Direct archive enqueue in production section of %s\n' "$source" >&2
        found=1
      fi
      ;;
    *)
      if rg -n 'enqueue_labyrinth_item\(' "$source"; then
        printf 'Direct archive enqueue in %s\n' "$source" >&2
        found=1
      fi
      ;;
  esac
done < <(rg --files src/client src/push src/labyrinth -g '*.rs')

exit "$found"
