#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync, renameSync, existsSync } from "node:fs";
import { join } from "node:path";

const OUT_DIR = "release-binaries";

// pkg target -> final artifact name
const TARGETS = [
  ["node22-linux-x64", "beam-linux-x64"],
  ["node22-linux-arm64", "beam-linux-arm64"],
  ["node22-macos-arm64", "beam-darwin-arm64"],
  ["node22-macos-x64", "beam-darwin-x64"],
  ["node22-win-x64", "beam-win-x64.exe"],
];

mkdirSync(OUT_DIR, { recursive: true });

for (const [target, outName] of TARGETS) {
  const outPath = join(OUT_DIR, outName);
  console.log(`Building ${outName} (${target})...`);
  execFileSync(
    "npx",
    ["pkg", ".", "--targets", target, "--output", outPath],
    { stdio: "inherit" }
  );
  if (!existsSync(outPath)) {
    throw new Error(`Expected output not found: ${outPath}`);
  }
}

console.log(`\nDone. Binaries in ${OUT_DIR}/`);
