import { emitKeypressEvents } from "node:readline";

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
    const lines = items.map((item, i) => `  ${cursor === i ? "❯" : " "} [${state[i] ? "x" : " "}] ${item.label}`);
    lines.push(`  ${cursor === items.length ? "❯" : " "} Submit`);
    process.stdout.write(`${lines.join("\n")}\n\n`);
  }

  console.log(title);
  console.log("  (↑/↓ move · space/enter toggle · enter on Submit to finish)\n");
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
  process.stdout.write(`${FRAMES[0]} ${label}`);
  const timer = setInterval(() => {
    frame = (frame + 1) % FRAMES.length;
    process.stdout.write(`\r${FRAMES[frame]} ${label}`);
  }, 110);

  try {
    const result = await fn();
    clearInterval(timer);
    process.stdout.write(`\r✔ ${label}\n`);
    return result;
  } catch (e) {
    clearInterval(timer);
    process.stdout.write(`\r✖ ${label}\n`);
    throw e;
  }
}

export interface TableRow { label: string; value: string }

// A minimal two-column box-drawn summary table — no dependency pulled in for this.
export function renderTable(rows: TableRow[]): string {
  const labelWidth = Math.max(...rows.map(r => r.label.length));
  const valueWidth = Math.max(...rows.map(r => r.value.length));
  const line = (l: string, m: string, r: string) => `${l}${"─".repeat(labelWidth + 2)}${m}${"─".repeat(valueWidth + 2)}${r}`;
  const out = [line("┌", "┬", "┐")];
  for (const row of rows) {
    out.push(`│ ${row.label.padEnd(labelWidth)} │ ${row.value.padEnd(valueWidth)} │`);
  }
  out.push(line("└", "┴", "┘"));
  return out.join("\n");
}
