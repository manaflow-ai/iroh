#!/usr/bin/env bash
set -euo pipefail
found=0
while IFS= read -r -d '' file; do
  if grep -nE 'macos-14(-large|-xlarge)?([[:space:]"\047]|$)' "$file"; then found=1; fi
done < <(find .github/workflows .github/actions -type f -print0 2>/dev/null || true)
if [ "$found" -ne 0 ]; then echo 'Deprecated macOS 14 runner label found.' >&2; exit 1; fi
