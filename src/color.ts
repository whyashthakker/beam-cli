// Minimal ANSI color helpers -- no dependency pulled in just for this. Each helper is bound to
// the stream it's meant to wrap (banner/errors go to stderr, everything else to stdout) so color
// is only ever applied when *that* stream is a TTY, and never when NO_COLOR is set or output is
// piped/redirected (scripts, `| cat`, CI logs).
function wrap(code: string, stream: NodeJS.WriteStream) {
  return (text: string): string => (!process.env.NO_COLOR && stream.isTTY ? `\x1b[${code}m${text}\x1b[0m` : text);
}

export const indigo = wrap("38;5;99", process.stderr);
export const green = wrap("32", process.stdout);
export const red = wrap("31", process.stdout);
export const dim = wrap("2", process.stdout);

// A lighter blue than indigo, for tips/suggestions ("run 'beam connect'") that should stand out
// from plain text without competing with the green/red step results around them.
export const cyan = wrap("38;5;74", process.stdout);
