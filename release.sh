#!/usr/bin/env bash
set -e

# Usage: ./release.sh 0.2.0

version=$1
if [ -z "$version" ]; then
  echo "Usage: $0 <new-version>"
  exit 1
fi

# Bump version
cargo set-version $version

# Commit and tag
git add Cargo.toml Cargo.lock
git commit -m "Bump version to $version"
git tag -a "v$version" -m "Release v$version"

# Push everything
git push
git push --tags
