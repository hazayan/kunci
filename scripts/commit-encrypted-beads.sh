#!/bin/sh
set -eu

bookmark=main
remote=

usage() {
	cat <<'EOF'
usage: scripts/commit-encrypted-beads.sh [--bookmark NAME] [--push REMOTE]

Rewrite the commit pointed to by a jj bookmark so Beads metadata is written
through git-crypt, then import the rewritten commit back into jj without
materializing encrypted Beads into the working tree.

Options:
  --bookmark NAME  Bookmark to rewrite. Defaults to main.
  --push REMOTE    Push the rewritten bookmark to REMOTE after import.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--bookmark)
			[ "$#" -ge 2 ] || {
				usage >&2
				exit 2
			}
			bookmark=$2
			shift 2
			;;
		--push)
			[ "$#" -ge 2 ] || {
				usage >&2
				exit 2
			}
			remote=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage >&2
			exit 2
			;;
	esac
done

files=
for file in .beads/issues.jsonl .beads/interactions.jsonl; do
	[ -f "$file" ] || continue

	if ! git check-attr filter -- "$file" | grep -q 'filter: git-crypt'; then
		printf '%s\n' "commit-encrypted-beads: $file is not marked filter=git-crypt" >&2
		exit 1
	fi

	if [ -s "$file" ] && [ "$(head -c 1 "$file")" != "{" ]; then
		printf '%s\n' "commit-encrypted-beads: $file is not plaintext in the working tree" >&2
		exit 1
	fi

	files="$files $file"
done

if [ -z "$files" ]; then
	printf '%s\n' "commit-encrypted-beads: no Beads metadata files found" >&2
	exit 0
fi

target_commit=$(jj log -r "$bookmark" --no-graph -T 'commit_id' 2>/dev/null)
if [ -z "$target_commit" ]; then
	printf '%s\n' "commit-encrypted-beads: jj bookmark $bookmark does not resolve to a commit" >&2
	exit 1
fi

tmp_index=$(mktemp "${TMPDIR:-/tmp}/beads-index.XXXXXX")
msg_file=$(mktemp "${TMPDIR:-/tmp}/beads-message.XXXXXX")
trap 'rm -f "$tmp_index" "$msg_file"' EXIT INT TERM

GIT_INDEX_FILE=$tmp_index git read-tree "$target_commit"

# shellcheck disable=SC2086
GIT_INDEX_FILE=$tmp_index git add -f -- $files

for file in $files; do
	header_hex=$(GIT_INDEX_FILE=$tmp_index git cat-file -p ":$file" 2>/dev/null | od -An -tx1 -N 10 | tr -d ' \n' || true)
	if [ "$header_hex" != "00474954435259505400" ]; then
		printf '%s\n' "commit-encrypted-beads: staged $file is not encrypted" >&2
		exit 1
	fi
done

tree=$(GIT_INDEX_FILE=$tmp_index git write-tree)
git show -s --format=%B "$target_commit" >"$msg_file"

parent_args=
for parent in $(git show -s --format=%P "$target_commit"); do
	parent_args="$parent_args -p $parent"
done

author_name=$(git show -s --format=%an "$target_commit")
author_email=$(git show -s --format=%ae "$target_commit")
author_date=$(git show -s --format=%aI "$target_commit")

# shellcheck disable=SC2086
rewritten_commit=$(
	env \
		GIT_AUTHOR_NAME="$author_name" \
		GIT_AUTHOR_EMAIL="$author_email" \
		GIT_AUTHOR_DATE="$author_date" \
		git commit-tree "$tree" $parent_args -F "$msg_file"
)

git update-ref "refs/heads/$bookmark" "$rewritten_commit"

jj --ignore-working-copy git import

BEADS_REF=$bookmark scripts/check-beads-git-crypt.sh

if [ -n "$remote" ]; then
	jj --ignore-working-copy git push --remote "$remote" --bookmark "$bookmark"
fi
