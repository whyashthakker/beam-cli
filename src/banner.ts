const BANNER = String.raw` __    ___  ____  __ _  ____  ____  ____   __   _  _
 / _\  / __)(  __)(  ( \(_  _)(  _ \(  __) / _\ ( \/ )
/    \( (_ \ ) _) /    /  )(   ) _ ( ) _) /    \/ \/ \
\_/\_/ \___/(____)\_)__) (__) (____/(____)\_/\_/\_)(_/`;

import { indigo } from "./color.js";

// Printed to stderr (never stdout) so it never corrupts JSON/plain output that other tools or
// scripts pipe from commands like 'beam scan' or 'beam agent extract'. Scripts that shell out to
// several 'beam' subcommands in a row (e.g. scripts/setup-global.sh) set BEAM_NO_BANNER=1 so the
// art prints once instead of once per invocation.
export function printBanner(): void {
  if (process.env.BEAM_NO_BANNER) return;
  console.error(indigo(BANNER));
}
