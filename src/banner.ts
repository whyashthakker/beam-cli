const BANNER = String.raw` __    ___  ____  __ _  ____  ____  ____   __   _  _
 / _\  / __)(  __)(  ( \(_  _)(  _ \(  __) / _\ ( \/ )
/    \( (_ \ ) _) /    /  )(   ) _ ( ) _) /    \/ \/ \
\_/\_/ \___/(____)\_)__) (__) (____/(____)\_/\_/\_)(_/`;

// Printed to stderr (never stdout) so it never corrupts JSON/plain output that other tools or
// scripts pipe from commands like 'beam scan' or 'beam agent extract'.
export function printBanner(): void {
  console.error(BANNER);
}
