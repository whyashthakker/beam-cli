#!/usr/bin/env bash
# Release from this machine (no GitHub Actions): checks, binaries, stress report, GitHub Release.
# Usage: npm run release:local        (then: npm publish)
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(node -p "require('./package.json').version")
tag="v$version"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Unexpected version: $version" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "Commit your changes first." >&2; exit 1; }
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
echo "Released $tag. Now run: npm publish"
