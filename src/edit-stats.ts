// How many lines an edit added and removed, worked out on the device from the tool's own input so
// only the two counts -- never the file contents -- leave the machine.

export type LineChanges = { added: number; removed: number };

const MAX_LINES = 20_000;

function lines(text: string): string[] {
  if (!text) return [];
  const parts = text.split(/\r?\n/);
  if (parts[parts.length - 1] === "") parts.pop();
  return parts.slice(0, MAX_LINES);
}

// Lines present only in `after` count as added, lines present only in `before` as removed, so an
// edit that changes one line inside a five-line block reports +1 -1, not +5 -5.
function diffCounts(before: string, after: string): LineChanges {
  const remaining = new Map<string, number>();
  for (const line of lines(before)) remaining.set(line, (remaining.get(line) ?? 0) + 1);
  let added = 0;
  for (const line of lines(after)) {
    const left = remaining.get(line) ?? 0;
    if (left > 0) remaining.set(line, left - 1);
    else added++;
  }
  let removed = 0;
  for (const count of remaining.values()) removed += count;
  return { added, removed };
}

function patchCounts(patch: string): LineChanges {
  let added = 0;
  let removed = 0;
  for (const line of lines(patch)) {
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("***")) continue;
    if (line.startsWith("+")) added++;
    else if (line.startsWith("-")) removed++;
  }
  return { added, removed };
}

const str = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined);
const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

/** Line counts for a write/edit tool call, or undefined when the input doesn't say (so the UI can show "—", not "+0 −0"). */
export function changedLines(toolInput: unknown): LineChanges | undefined {
  const text = str(toolInput);
  if (text !== undefined) return /^(\*\*\* Begin Patch|diff --git|--- |@@ )/m.test(text) ? patchCounts(text) : undefined;
  const input = record(toolInput);

  if (Array.isArray(input.edits)) {
    const total = { added: 0, removed: 0 };
    for (const edit of input.edits) {
      const e = record(edit);
      const counts = diffCounts(str(e.old_string) ?? "", str(e.new_string) ?? "");
      total.added += counts.added;
      total.removed += counts.removed;
    }
    return total;
  }
  const before = str(input.old_string) ?? str(input.old_str);
  const after = str(input.new_string) ?? str(input.new_str);
  if (before !== undefined || after !== undefined) return diffCounts(before ?? "", after ?? "");

  const patch = str(input.patch) ?? str(input.diff) ?? str(input.command);
  if (patch && /^(\*\*\* Begin Patch|diff --git|--- |@@ )/m.test(patch)) return patchCounts(patch);

  const content = str(input.content) ?? str(input.contents) ?? str(input.file_text);
  if (content !== undefined) return { added: lines(content).length, removed: 0 };
  return undefined;
}
