import { emitKeypressEvents } from "node:readline";
import { cyan, dim, green, red } from "./color.js";

// Strips ANSI escape codes so column widths are computed from what actually prints, not the
// escape bytes -- lets renderTable/renderColumns take colored cell values without misaligning.
const ANSI_RE = /\x1b\[[0-9;]*m/g;
function visibleLength(s: string): number {
  return s.replace(ANSI_RE, "").length;
}
function padVisible(s: string, width: number): string {
  return s + " ".repeat(Math.max(0, width - visibleLength(s)));
}

export interface CheckboxItem { label: string; checked?: boolean }

// Arrow-key checkbox list, ending in a "Submit" row — ↑/↓ to move, space/enter to toggle the
// highlighted box, enter on Submit to finish. Falls back to "everything pre-checked" when stdin
// or stdout isn't a TTY (piped/non-interactive shells), since there's no way to drive arrow keys.
export async function checkbox(title: string, items: CheckboxItem[]): Promise<number[]> {
  if (!items.length) return [];
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return items.map((_, i) => i).filter(i => items[i].checked !== false);
  }

  const state = items.map(i => i.checked !== false);
  let cursor = 0;
  const rows = items.length + 1; // + the Submit row

  function render(first: boolean): void {
    if (!first) process.stdout.write(`\x1b[${rows + 1}A\x1b[0J`);
    const lines = items.map((item, i) => {
      const onCursor = cursor === i;
      const box = state[i] ? green("●") : dim("○");
      const label = onCursor ? cyan(item.label) : item.label;
      return `  ${onCursor ? cyan("❯") : " "} ${box} ${label}`;
    });
    const onSubmit = cursor === items.length;
    lines.push(`  ${onSubmit ? cyan("❯") : " "} ${onSubmit ? cyan("Submit") : dim("Submit")}`);
    process.stdout.write(`${lines.join("\n")}\n\n`);
  }

  console.log(title);
  console.log(dim("  ↑/↓ move · space toggle · enter on Submit to finish\n"));
  render(true);

  return new Promise((resolve) => {
    emitKeypressEvents(process.stdin);
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();

    function cleanup(): void {
      process.stdin.setRawMode(!!wasRaw);
      process.stdin.pause();
      process.stdin.removeListener("keypress", onKeypress);
    }

    function onKeypress(_str: string, key: { name?: string; ctrl?: boolean }): void {
      if (key.ctrl && key.name === "c") { cleanup(); process.exit(130); }
      else if (key.name === "up") { cursor = (cursor - 1 + rows) % rows; render(false); }
      else if (key.name === "down") { cursor = (cursor + 1) % rows; render(false); }
      else if (key.name === "space") {
        if (cursor < items.length) { state[cursor] = !state[cursor]; render(false); }
      } else if (key.name === "return") {
        if (cursor === items.length) {
          cleanup();
          resolve(state.map((checked, i) => (checked ? i : -1)).filter(i => i >= 0));
        } else {
          state[cursor] = !state[cursor];
          render(false);
        }
      }
    }
    process.stdin.on("keypress", onKeypress);
  });
}

// Arrow-key Yes/No choice, replacing the old type-"y"-or-"n" text prompt: a vertical two-row list
// (matching checkbox()'s layout) that ↑/↓/tab moves through, enter confirms, and y/n still work
// directly as shortcuts. Falls back to the classic "[Y/n]" text prompt when stdin/stdout isn't a
// TTY, same as checkbox().
export async function confirm(question: string, defaultYes = true): Promise<boolean> {
  const prompt = question.trim();
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(`${prompt} ${defaultYes ? "[Y/n]" : "[y/N]"} (non-interactive shell, defaulting to ${defaultYes ? "yes" : "no"})`);
    return defaultYes;
  }

  let choice = defaultYes;
  const rows = 2;

  function render(first: boolean): void {
    if (!first) process.stdout.write(`\x1b[${rows}A\x1b[0J`);
    const yes = choice ? `${cyan("❯")} ${cyan("Yes")}` : `  ${dim("Yes")}`;
    const no = !choice ? `${cyan("❯")} ${cyan("No")}` : `  ${dim("No")}`;
    process.stdout.write(`  ${yes}\n  ${no}\n`);
  }

  console.log(prompt);
  console.log(dim("  ↑/↓ choose · enter to confirm"));
  render(true);

  return new Promise((resolve) => {
    emitKeypressEvents(process.stdin);
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();

    function cleanup(): void {
      process.stdin.setRawMode(!!wasRaw);
      process.stdin.pause();
      process.stdin.removeListener("keypress", onKeypress);
    }

    function finish(value: boolean): void {
      process.stdout.write(`\x1b[${rows}A\x1b[0J  ${value ? green("✔ Yes") : red("✖ No")}\n`);
      cleanup();
      resolve(value);
    }

    function onKeypress(_str: string, key: { name?: string; ctrl?: boolean }): void {
      if (key.ctrl && key.name === "c") { cleanup(); process.exit(130); }
      else if (key.name === "up" || key.name === "down" || key.name === "tab" || key.name === "left" || key.name === "right") {
        choice = !choice;
        render(false);
      } else if (key.name === "y") finish(true);
      else if (key.name === "n") finish(false);
      else if (key.name === "return") finish(choice);
    }
    process.stdin.on("keypress", onKeypress);
  });
}

// Beam's own spinner: a watchful eye that opens and closes — the owl keeping
// an eye on your agents. Doubled ends hold the shut/wide-open frames a beat
// longer, so it reads as a blink-and-pulse rather than a flat cycle.
const FRAMES = ["·", "·", "∘", "○", "◎", "◉", "◉", "◎", "○", "∘"];

// Runs `fn` while animating a spinner in place on the current line, then replaces it with a
// ✔/✖ result line. Falls back to plain "label..." on a non-TTY stdout (nothing to animate).
export async function withSpinner<T>(label: string, fn: () => Promise<T>): Promise<T> {
  if (!process.stdout.isTTY) {
    console.log(`${label}...`);
    try {
      const result = await fn();
      console.log(`✔ ${label}`);
      return result;
    } catch (e) {
      console.log(`✖ ${label}`);
      throw e;
    }
  }

  let frame = 0;
  process.stdout.write(`\x1b[?25l${cyan(FRAMES[0])} ${label}`);
  const timer = setInterval(() => {
    frame = (frame + 1) % FRAMES.length;
    process.stdout.write(`\r\x1b[K${cyan(FRAMES[frame])} ${label}`);
  }, 110);

  try {
    const result = await fn();
    clearInterval(timer);
    process.stdout.write(`\r\x1b[K${green("✔")} ${label}\x1b[?25h\n`);
    return result;
  } catch (e) {
    clearInterval(timer);
    process.stdout.write(`\r\x1b[K${red("✖")} ${label}\x1b[?25h\n`);
    throw e;
  }
}

export interface TableRow { label: string; value: string }

// A minimal two-column box-drawn summary table — no dependency pulled in for this. Cell values
// may contain ANSI color codes (e.g. to flag a status green/red); widths and padding are computed
// from visible length, so colored cells still line up. Borders are dimmed rather than the caller
// wrapping the whole table in one color, which would otherwise clobber any per-cell color the
// moment an inner reset code fires.
export function renderTable(rows: TableRow[]): string {
  const labelWidth = Math.max(...rows.map(r => visibleLength(r.label)));
  const valueWidth = Math.max(...rows.map(r => visibleLength(r.value)));
  const border = (l: string, m: string, r: string) =>
    dim(`${l}${"─".repeat(labelWidth + 2)}${m}${"─".repeat(valueWidth + 2)}${r}`);
  const out = [border("┌", "┬", "┐")];
  for (const row of rows) {
    out.push(`${dim("│")} ${padVisible(row.label, labelWidth)} ${dim("│")} ${padVisible(row.value, valueWidth)} ${dim("│")}`);
  }
  out.push(border("└", "┴", "┘"));
  return out.join("\n");
}

// Same box-drawing style as renderTable, but for arbitrary-width listings (e.g. 'beam agent
// list') instead of a fixed label/value pair. Also ANSI-safe, for the same reason.
export function renderColumns(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => visibleLength(r[i] ?? ""))));
  const border = (l: string, m: string, r: string) => dim(`${l}${widths.map(w => "─".repeat(w + 2)).join(m)}${r}`);
  const fmt = (cells: string[]) => `${dim("│")} ${cells.map((c, i) => padVisible(c ?? "", widths[i])).join(` ${dim("│")} `)} ${dim("│")}`;
  const out = [border("┌", "┬", "┐"), fmt(headers), border("├", "┼", "┤")];
  for (const row of rows) out.push(fmt(row));
  out.push(border("└", "┴", "┘"));
  return out.join("\n");
}
