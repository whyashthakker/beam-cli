/** A bounded suggestion for commands with a concrete, stable target. */
export function commandBehaviorRegex(command: string): string | null {
  if (!command || command.length > 4000 || /\[(?:REDACTED|TRUNCATED)[^\]]*\]|…|[$`\\\n\r]/i.test(command)) return null;
  const source = command.trim();
  if (/^(?:(?:sudo|command)\s+)?(?:env|printenv)(?:\s+-0)?$/i.test(source))
    return String.raw`(?:^|[;&|]\s*)(?:(?:sudo|command)\s+)?(?:env|printenv)(?:\s+-0)?(?=\s*(?:[;&|]|$))`;

  const ping = /^(?:(?:sudo|command)\s+)?(?:\/[A-Za-z0-9_.\/-]+\/)?ping(?:\s+(?:--|-[A-Za-z][A-Za-z0-9-]*(?:=\d{1,6})?|\d{1,6}))*\s+(['"]?)([A-Za-z0-9.-]+)\1$/i.exec(source);
  const host = ping?.[2]?.replace(/\.$/, "");
  if (!host || host.length > 200 || !/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(host)) return null;
  const pattern = String.raw`(?:^|[;&|]\s*)(?:(?:sudo|command)\s+)?(?:\/?[A-Za-z0-9_.-]+\/)*ping(?:\s+(?:--|-[A-Za-z][A-Za-z0-9-]*(?:=\d{1,6})?|\d{1,6}))*\s+['"]?${host.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\.?['"]?(?=$|[\s;&|])`;
  return pattern.length <= 300 ? pattern : null;
}
