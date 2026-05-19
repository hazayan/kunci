#!/bin/sh
set -eu

file=.beads/issues.jsonl
ref=${BEADS_REF:-HEAD}

if [ ! -f "$file" ]; then
	printf '%s\n' "beads git-crypt check: $file is missing" >&2
	exit 1
fi

if [ -s "$file" ] && [ "$(head -c 1 "$file")" != "{" ]; then
	printf '%s\n' "beads git-crypt check: $file is not plaintext in the working tree" >&2
	exit 1
fi

if ! git check-attr filter -- "$file" | grep -q 'filter: git-crypt'; then
	printf '%s\n' "beads git-crypt check: $file is not marked with filter=git-crypt" >&2
	exit 1
fi

if ! git diff --quiet "$ref" -- "$file"; then
	printf '%s\n' "beads git-crypt check: $file has unstaged changes after the Beads export" >&2
	exit 1
fi

if [ "$ref" = "HEAD" ]; then
	if ! git diff --cached --quiet -- "$file"; then
		printf '%s\n' "beads git-crypt check: $file has staged changes after the Beads export" >&2
		exit 1
	fi
fi

header_hex=$(git cat-file -p "$ref:$file" 2>/dev/null | od -An -tx1 -N 10 | tr -d ' \n' || true)
if [ "$header_hex" != "00474954435259505400" ]; then
	printf '%s\n' "beads git-crypt check: committed $file is not encrypted at $ref" >&2
	printf '%s\n' "Run: scripts/commit-encrypted-beads.sh --bookmark main --push zung" >&2
	exit 1
fi
