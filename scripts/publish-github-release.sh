#!/usr/bin/env bash
# Creates or finishes the GitHub release for a version, run by the Release workflow after the tag is pushed:
#   publish-github-release.sh <version>
# A public release that carries its committed note (if any) is left alone. A draft, or a release missing its note,
# gets the note on top of its body and is published, so a retry never reports success for a release users can't see
# or one without its warning. `--verify-tag` refuses to create a missing tag from the default branch, so the release
# always points at the published commit.
set -euo pipefail

version=$1
notes=".github/release-notes/$version.md"
here=$(dirname "$0")

# 0 when the body carries the note, 1 when it doesn't. A checker that can't run fails the release instead of being
# read as a missing note, which would prepend the note again on every retry.
carries_note() {
  local code=0
  bun "$here/carries-release-notes.ts" "$notes" <<<"$1" || code=$?
  case $code in
    0) return 0 ;;
    10) return 1 ;;
    *)
      echo "::error::could not check release $version for its note (exit $code)" >&2
      exit 1
      ;;
  esac
}

if existing=$(gh release view "$version" --json isDraft,body 2>/dev/null); then
  body=$(jq -r .body <<<"$existing")
  if [ -f "$notes" ] && ! carries_note "$body"; then
    combined=$(mktemp)
    printf '%s\n\n%s\n' "$(cat "$notes")" "$body" >"$combined"
    gh release edit "$version" --notes-file "$combined" --draft=false
    echo "Release $version: added its committed note and published it"
  elif [ "$(jq -r .isDraft <<<"$existing")" = true ]; then
    gh release edit "$version" --draft=false
    echo "Release $version: published the draft"
  else
    echo "Release $version already exists, skipping"
  fi
elif [ -f "$notes" ]; then
  gh release create "$version" --verify-tag --generate-notes --notes-file "$notes"
else
  gh release create "$version" --verify-tag --generate-notes
fi
