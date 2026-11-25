#!/usr/bin/env bash
# Print semantic version for Omega Pulse from git tags.
set -euo pipefail

# In case git is not installed or we are not in a git tree:
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    printf '%s\n' "${PULSE_VERSION:-0.1.0-dev}"
    exit 0
fi

# Try git describe matching tags like v0.1.0, v1.2.0
if desc=$(git describe --tags --match 'v*' --long 2>/dev/null); then
    # Format from describe: v<MAJOR>.<MINOR>.<PATCH>-<COMMITS>-g<SHA>
    tag_and_commits="${desc%-g*}"
    sha="${desc##*-g}"
    commits="${tag_and_commits##*-}"
    tag="${tag_and_commits%-*}"
    ver="${tag#v}"

    if [[ "$commits" -eq 0 ]]; then
        printf '%s\n' "$ver"
    else
        IFS='.' read -r major minor patch <<< "$ver"
        next_patch=$((patch + 1))
        printf '%s.%s.%s-dev.%s+%s\n' "$major" "$minor" "$next_patch" "$commits" "$sha"
    fi
else
    # No v* tag exists yet; start from 0.1.0
    commits=$(git rev-list --count HEAD 2>/dev/null || echo 0)
    sha=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    if [[ "$commits" -eq 0 ]]; then
        printf '0.1.0-dev\n'
    else
        printf '0.1.0-dev.%s+%s\n' "$commits" "$sha"
    fi
fi
