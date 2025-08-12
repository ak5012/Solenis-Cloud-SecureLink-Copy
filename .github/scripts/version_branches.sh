#!/bin/bash

set -e

# List of branches to version
branches=("BOSS" "Cloud Sync" "GPAM")

for branch in "${branches[@]}"; do
  # Find latest versioned branch for this branch
  latest_ver=$(git branch -r | grep "origin/${branch}-" | awk -F"${branch}-" '{print $2}' | sort -V | tail -n1)

  if [[ -z "$latest_ver" ]]; then
    new_ver="1.0"
  else
    # Increment minor version (you can change this logic)
    major=$(echo $latest_ver | cut -d. -f1)
    minor=$(echo $latest_ver | cut -d. -f2)
    new_minor=$((minor+1))
    new_ver="${major}.${new_minor}"
  fi

  new_branch="${branch}-${new_ver}"

  # Create new branch from main
  git checkout main
  git pull
  git checkout -b "$new_branch"
  git push origin "$new_branch"
done
