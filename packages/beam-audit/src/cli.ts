#!/usr/bin/env node
// Standalone, zero-beam-cli-install entry point for the scanner. The main `beam` CLI runs the
// same logic via `beam audit`, importing runAudit() from run.js directly instead of forking this
// process -- see src/cli.ts's "audit" branch in the beam-cli package.
import { runAudit } from "./run.js";

runAudit(process.argv.slice(2)).catch(err => {
  console.error("[beam-audit] fatal error:", err);
  process.exitCode = 2;
});
