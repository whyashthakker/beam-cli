// Network topology detection. A single public IP address is ordinary (DNS servers, API hosts, curl
// output) and is only REPORTED, never redacted. What reveals how your network is laid out is protected:
//   INTERNAL_IP    private/internal addresses: RFC1918 (10/8, 172.16/12, 192.168/16), carrier-grade NAT
//                  (100.64/10), link-local (169.254/16, fe80::/10), IPv6 unique-local (fc00::/7)
//   NETWORK_RANGE  any CIDR block (10.0.0.0/8, 203.0.113.0/24, fd00::/8) and address ranges (10.0.0.1-50)
//   INTERNAL_HOST  internal DNS names: *.internal, *.corp, *.lan, *.intranet, *.private, *.home.arpa, *.localdomain,
//                  *.cluster.local (not bare *.local: config.local / settings.local are ordinary filenames)
// Not reported at all: loopback, 0.0.0.0, multicast/broadcast, and documentation ranges
// (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32), which are examples, not topology.
// Pure and stateless, like data-detectors.ts.

export type TopologyKind = "INTERNAL_IP" | "INTERNAL_HOST" | "NETWORK_RANGE";
export type NetworkKind = TopologyKind | "PUBLIC_IP";
export const TOPOLOGY_KINDS: ReadonlySet<string> = new Set<TopologyKind>(["INTERNAL_IP", "INTERNAL_HOST", "NETWORK_RANGE"]);

export interface NetworkHit { kind: NetworkKind; start: number; end: number }
export interface NetworkDetector { kind: TopologyKind; pattern: RegExp; replacement: string; validate?: (match: string) => boolean }

// ---- IPv4 -------------------------------------------------------------------------------------
function octets(raw: string): number[] | null {
  const parts = raw.split(".");
  if (parts.length !== 4 || parts.some(p => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return parts.map(Number);
}
type Class = "internal" | "public" | "ignore";
function classifyV4(raw: string): Class | null {
  const o = octets(raw); if (!o) return null;
  const [a, b, c] = o as [number, number, number, number];
  if (a === 0 || a === 127 || a >= 224) return "ignore"; // unspecified, loopback, multicast/reserved/broadcast
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return "ignore"; // documentation
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254)) return "internal";
  return "public";
}

// ---- IPv6 -------------------------------------------------------------------------------------
function parseV6(raw: string): number[] | null {
  let text = raw.replace(/%[\w.-]+$/, "");
  if (!text.includes(":") || /:::/.test(text) || !/\d/.test(text)) return null;
  // Embedded IPv4 tail (::ffff:10.0.0.1).
  const tail = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text);
  if (tail) {
    const o = octets(tail[1]!); if (!o) return null;
    text = `${text.slice(0, -tail[1]!.length)}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (s: string) => (s === "" ? [] : s.split(":"));
  const head = groups(halves[0]!), rest = halves.length === 2 ? groups(halves[1]!) : [];
  if ([...head, ...rest].some(g => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  if (halves.length === 1) return head.length === 8 ? head.map(g => parseInt(g, 16)) : null;
  if (head.length + rest.length > 7) return null;
  return [...head.map(g => parseInt(g, 16)), ...Array(8 - head.length - rest.length).fill(0), ...rest.map(g => parseInt(g, 16))];
}
function classifyV6(raw: string): Class | null {
  const g = parseV6(raw); if (!g) return null;
  if (g.slice(0, 7).every(x => x === 0) && (g[7] === 0 || g[7] === 1)) return "ignore"; // :: and ::1
  if (g[0] === 0x2001 && g[1] === 0x0db8) return "ignore"; // documentation
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) { // IPv4-mapped: classify the embedded address
    return classifyV4(`${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`);
  }
  if ((g[0]! & 0xfe00) === 0xfc00 || (g[0]! & 0xffc0) === 0xfe80) return "internal"; // unique-local, link-local
  if ((g[0]! & 0xff00) === 0xff00) return "ignore"; // multicast
  return "public";
}

// ---- patterns ---------------------------------------------------------------------------------
const V4 = String.raw`(?:\d{1,3}\.){3}\d{1,3}`;
const V4_RE = new RegExp(String.raw`(?<![\w.-])${V4}(?![\w-]|\.\d)`, "g");
const CIDR4_RE = new RegExp(String.raw`(?<![\w.-])${V4}\/(?:3[0-2]|[12]?\d)(?![\w.]|\/)`, "g");
const RANGE4_RE = new RegExp(String.raw`(?<![\w.-])${V4}\s?-\s?(?:(?:\d{1,3}\.){3})?\d{1,3}(?![\w.-]|\.\d)`, "g");
// IPv6 candidates are hex/colon runs, then verified by the parser (so 12:34:56 times and MAC addresses fail).
const V6_RE = /(?<![\w:.-])[0-9a-fA-F:]{2,45}(?:%[\w.-]+)?(?:\.\d{1,3}){0,3}(?![\w:.-]|\/\d)/g;
const CIDR6_RE = /(?<![\w:.-])[0-9a-fA-F:]{2,45}(?:\.\d{1,3}){0,3}\/(?:12[0-8]|1[01]\d|[1-9]?\d)(?![\w.\/])/g;
const HOST_RE = /(?<![\w./@-])[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:internal|corp|lan|intranet|private|home\.arpa|localdomain|cluster\.local)(?![\w-]|\.\w)/gi;

const validRange4 = (m: string) => {
  const [first, second] = m.split(/\s?-\s?/);
  if (!octets(first!)) return false;
  const last = second!.includes(".") ? octets(second!) !== null : Number(second) <= 255;
  return last && classifyV4(first!) !== "ignore";
};
const validCidr4 = (m: string) => { const a = m.split("/")[0]!; return octets(a) !== null && classifyV4(a) !== "ignore"; };
const validCidr6 = (m: string) => { const a = m.split("/")[0]!; return classifyV6(a) !== null && classifyV6(a) !== "ignore"; };

/** Topology detectors, for data-detectors.ts. Order matters there: ranges are listed before single addresses. */
export const NETWORK_DETECTORS: NetworkDetector[] = [
  { kind: "NETWORK_RANGE", pattern: CIDR4_RE, replacement: "[NETWORK_RANGE_REDACTED]", validate: validCidr4 },
  { kind: "NETWORK_RANGE", pattern: CIDR6_RE, replacement: "[NETWORK_RANGE_REDACTED]", validate: validCidr6 },
  { kind: "NETWORK_RANGE", pattern: RANGE4_RE, replacement: "[NETWORK_RANGE_REDACTED]", validate: validRange4 },
  { kind: "INTERNAL_IP", pattern: V4_RE, replacement: "[INTERNAL_IP_REDACTED]", validate: m => classifyV4(m) === "internal" },
  { kind: "INTERNAL_IP", pattern: V6_RE, replacement: "[INTERNAL_IP_REDACTED]", validate: m => classifyV6(m) === "internal" },
  { kind: "INTERNAL_HOST", pattern: HOST_RE, replacement: "[INTERNAL_HOST_REDACTED]" },
];

/** Every address and range worth reporting, including public IPs (report-only). Non-overlapping. */
export function scanNetwork(text: string): NetworkHit[] {
  const hits: NetworkHit[] = [];
  const add = (re: RegExp, kind: NetworkKind | ((m: string) => NetworkKind | null), ok?: (m: string) => boolean) => {
    for (const m of text.matchAll(new RegExp(re.source, re.flags))) {
      if (ok && !ok(m[0])) continue;
      const k = typeof kind === "function" ? kind(m[0]) : kind;
      if (k) hits.push({ kind: k, start: m.index!, end: m.index! + m[0].length });
    }
  };
  add(CIDR4_RE, "NETWORK_RANGE", validCidr4); add(CIDR6_RE, "NETWORK_RANGE", validCidr6); add(RANGE4_RE, "NETWORK_RANGE", validRange4);
  add(V4_RE, m => { const c = classifyV4(m); return c === "internal" ? "INTERNAL_IP" : c === "public" ? "PUBLIC_IP" : null; });
  add(V6_RE, m => { const c = classifyV6(m); return c === "internal" ? "INTERNAL_IP" : c === "public" ? "PUBLIC_IP" : null; });
  add(HOST_RE, "INTERNAL_HOST");
  const out: NetworkHit[] = []; let lastEnd = -1;
  for (const hit of hits.sort((a, b) => a.start - b.start || b.end - a.end)) { if (hit.start < lastEnd) continue; out.push(hit); lastEnd = hit.end; }
  return out;
}

/** Counts by kind, e.g. { INTERNAL_IP: 2, PUBLIC_IP: 1 }. Never contains an address. */
export function countNetwork(text: string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const hit of scanNetwork(text)) counts[hit.kind] = (counts[hit.kind] ?? 0) + 1;
  return counts;
}

export type NetworkMode = "report" | "redact" | "block" | "off";
/** `report` (default): note it, change nothing the model sees. `redact`: replace topology in prompts/output.
 * `block`: also block prompts that contain it. `off`: don't look. Beam's own logs always omit topology unless `off`. */
export function networkMode(policyValue?: string, envValue?: string): NetworkMode {
  return ([policyValue, envValue].find(v => v === "report" || v === "redact" || v === "block" || v === "off") as NetworkMode | undefined) ?? "report";
}
