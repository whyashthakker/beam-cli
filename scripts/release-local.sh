#!/usr/bin/env bash
# Release from this machine (no GitHub Actions): version bump, checks, binaries, stress report,
# GitHub Release, npm publish.
# Usage: npm run release -- patch|minor|major|X.Y.Z   bump, commit, push, then release
#        npm run release                              release the version already in package.json
# Every step is skipped if it's already done, so a failed run can simply be re-run.
set -euo pipefail
cd "$(dirname "$0")/.."

bump=${1:-}

# Fail before changing anything if we can't finish.
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || { echo "Release from main." >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "Commit your changes first." >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Not logged in to GitHub; run: gh auth login" >&2; exit 1; }
npm whoami >/dev/null 2>&1 || { echo "Not logged in to npm; run: npm login" >&2; exit 1; }
git pull --ff-only origin main

if [ -n "$bump" ]; then
  npm version "$bump" --no-git-tag-version >/dev/null
  version=$(node -p "require('./package.json').version")
  git add package.json package-lock.json
  # [skip ci] keeps the release workflow from racing this script for the same tag.
  git commit -m "Release $version [skip ci]"
fi

version=$(node -p "require('./package.json').version")
tag="v$version"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Unexpected version: $version" >&2; exit 1; }
git push origin HEAD

npm ci
npm run validate:skills
npm run typecheck
npm test

rm -rf release-binaries
npm run build:binaries
# darwin binaries need an ad-hoc signature to run on Apple silicon
for f in release-binaries/beam-darwin-*; do codesign --force --sign - "$f"; done

node --expose-gc scripts/stress-report.mjs --out stress-report.json
cp stress-report.json release-binaries/

if gh release view "$tag" >/dev/null 2>&1; then
  echo "$tag exists; uploading binaries to it."
  gh release upload "$tag" release-binaries/* --clobber
else
  gh release create "$tag" release-binaries/* --target "$(git rev-parse HEAD)" --title "$tag" --generate-notes
fi
git fetch --tags --quiet

# Checks, build and stress report already ran above, so skip prepublishOnly.
if npm view "@agent-beam/beam@$version" version >/dev/null 2>&1; then
  echo "@agent-beam/beam@$version is already on npm."
else
  npm publish --ignore-scripts
fi
echo "Released $tag to GitHub and npm."
