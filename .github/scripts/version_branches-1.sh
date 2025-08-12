#!/bin/bash
set -e

# Get changed files in the latest commit
CHANGED_FILES=$(git diff-tree --no-commit-id --name-only -r HEAD)

BRANCH=$(git rev-parse --abbrev-ref HEAD)
ANY_NEW=false

for FILE in $CHANGED_FILES; do
  # Only handle regular files (skip deleted and non-file changes)
  if [ ! -f "$FILE" ]; then
    continue
  fi

  BASENAME=$(basename "$FILE")
  DIRNAME=$(dirname "$FILE")
  EXTENSION="${BASENAME##*.}"
  FILENAME="${BASENAME%.*}"

  # Find highest version already existing
  PATTERN="$DIRNAME/$FILENAME-[0-9]*.$EXTENSION"
  HIGHEST=0
  for EXISTING in $PATTERN; do
    [[ ! -e $EXISTING ]] && continue
    VERSION=$(echo "$EXISTING" | sed -E "s/.*$FILENAME-([0-9]+)\.$EXTENSION$/\1/")
    [[ "$VERSION" =~ ^[0-9]+$ ]] || continue
    if (( VERSION > HIGHEST )); then
      HIGHEST=$VERSION
    fi
  done

  NEXT=$((HIGHEST + 1))
  VERSIONED_FILE="$DIRNAME/$FILENAME-$NEXT.$EXTENSION"

  # Copy the changed file to new versioned file
  cp "$FILE" "$VERSIONED_FILE"
  git add "$VERSIONED_FILE"
  ANY_NEW=true
done

if [ "$ANY_NEW" = true ]; then
  git commit -m "Create new versioned file(s) on branch $BRANCH"
else
  echo "No new files to version."
fi
