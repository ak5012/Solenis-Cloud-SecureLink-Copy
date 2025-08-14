#!/bin/bash
set -e

# Only .py/.json that were Added/Copied/Modified/Renamed in the latest commit
CHANGED_FILES=$(
  git diff-tree --no-commit-id --name-only --diff-filter=ACMR -r HEAD \
  | grep -E '\.(py|json)$' || true
)

BRANCH=$(git rev-parse --abbrev-ref HEAD)
ANY_NEW=false

for FILE in $CHANGED_FILES; do
  # Skip if not a regular file (e.g., deleted)
  [[ -f "$FILE" ]] || continue

  BASENAME=$(basename "$FILE")
  DIRNAME=$(dirname "$FILE")
  EXTENSION="${BASENAME##*.}"
  NAME_NOEXT="${BASENAME%.*}"

  # Skip files that are already versioned like name-12.py
  if [[ "$NAME_NOEXT" =~ -[0-9]+$ ]]; then
    continue
  fi

  # Find highest existing version
  PATTERN="$DIRNAME/$NAME_NOEXT-[0-9]*.$EXTENSION"
  HIGHEST=0
  for EXISTING in $PATTERN; do
    [[ ! -e "$EXISTING" ]] && continue
    VERSION=$(echo "$EXISTING" | sed -E "s#^.*/${NAME_NOEXT}-([0-9]+)\.${EXTENSION}\$#\1#")
    [[ "$VERSION" =~ ^[0-9]+$ ]] || continue
    (( VERSION > HIGHEST )) && HIGHEST=$VERSION
  done

  NEXT=$((HIGHEST + 1))
  VERSIONED_FILE="$DIRNAME/$NAME_NOEXT-$NEXT.$EXTENSION"

  cp "$FILE" "$VERSIONED_FILE"
  git add "$VERSIONED_FILE"
  ANY_NEW=true
done

if [ "$ANY_NEW" = true ]; then
  git commit -m "Version .py/.json on branch $BRANCH"
else
  echo "No new .py/.json files to version."
fi


