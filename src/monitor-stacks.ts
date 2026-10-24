// Stack-aware App monitoring: which software an app runs, attacks aimed at particular stacks, and
// exposures of their debug and admin endpoints. Declare the stack (the SDK's `stack`, or
// `beam monitor --stack`; `--app` detects it) and an attack on software the app doesn't run is
// rolled up as not applicable instead of raised, while the attacks that matter for its own stack
// are. Pure TypeScript with no Node.js built-ins (the SDK runs in edge runtimes).
import type { MonitorRule } from "./monitor-rules.js";

/** What an app can declare. Each runs a set of families; paths and attacks belong to families. */
export const STACK_FAMILIES = {
  nextjs: ["js", "nextjs", "react"],
  node: ["js"],
  express: ["js"],
  nestjs: ["js"],
  vite: ["js", "vite"],
  django: ["python", "django"],
  flask: ["python", "flask"],
  fastapi: ["python", "fastapi"],
  rails: ["ruby", "rails"],
  laravel: ["php", "laravel"],
  php: ["php"],
  wordpress: ["php", "wordpress"],
  spring: ["java", "spring"],
  java: ["java"],
  go: ["go"],
  dotnet: ["dotnet"],
  static: [],
} as const satisfies Record<string, readonly string[]>;
export type Stack = keyof typeof STACK_FAMILIES;
export const STACKS = Object.keys(STACK_FAMILIES) as Stack[];
export const isStack = (v: unknown): v is Stack => typeof v === "string" && v in STACK_FAMILIES;

// Paths only one family serves. A request for one, from an app that doesn't run that family and
// with no response status to go on, can't have worked.
const FAMILY_PATHS: [family: string, path: RegExp][] = [
  ["php", /\.(?:php\d?|phtml)(?=[/?#;]|$)|\/phpmyadmin(?=[/?#]|$)/i],
  ["wordpress", /\/(?:wordpress|wp-(?:admin|content|includes|json|login\.php))(?=[/?#]|$)|\/xmlrpc\.php/i],
  ["dotnet", /\.(?:aspx?|ashx|asmx|axd)(?=[/?#;]|$)|\/web\.config(?=[?#]|$)/i],
  ["java", /\.(?:jsp|jspx|do|action)(?=[/?#;]|$)|\/(?:actuator|jolokia|manager\/html|jmx-console|web-console)(?=[/?#]|$)/i],
  ["cgi", /\.(?:cgi|pl)(?=[/?#;]|$)|\/cgi-bin(?=[/?#]|$)/i],
  ["vite", /\/@(?:fs|vite|id)\//i],
  ["rails", /\/rails\/info(?=[/?#]|$)/i],
  ["laravel", /\/(?:_ignition|telescope|horizon|_debugbar)(?=[/?#]|$)|\/storage\/logs\/laravel\.log/i],
  ["django", /\/__debug__(?=[/?#]|$)/i],
  ["go", /\/debug\/(?:pprof|vars)(?=[/?#]|$)/i],
];

/** The families a path belongs to (empty for an ordinary path any app might serve). */
export function pathFamilies(path: string): string[] {
  const route = path.split(/[?#]/)[0]!;
  const families = FAMILY_PATHS.filter(([, re]) => re.test(route)).map(([family]) => family);
  // wp-login.php is WordPress, not any PHP app: a Laravel app can't serve it either.
  return families.includes("wordpress") ? ["wordpress"] : families;
}

/** True when the stack runs none of the families the path or rule belongs to. */
export function foreignTo(stack: Stack, families: readonly string[]): boolean {
  const runs = STACK_FAMILIES[stack] as readonly string[];
  return families.length > 0 && !families.some(f => runs.includes(f));
}

// The response status in an access-log line was 2xx (same reading as monitor-rules.ts).
const ACCESS_STATUS = /"[A-Z]+ \S+ HTTP\/[\d.]+" (\d{3})\b|"(?:status|httpStatus|status_code|statusCode|response_status)"\s*:\s*"?(\d{3})\b/;
const served = (raw: string) => ((raw.match(ACCESS_STATUS)?.[1] ?? raw.match(ACCESS_STATUS)?.[2]) ?? "").startsWith("2");

/**
 * Every pattern here must stay linear in its input (this runs inside customer apps, on attacker-
 * written text): match fixed markers with separate tests, never `marker[^x]*other` across a line.
 *
 * Attacks on particular frameworks, and their debug or admin endpoints answering the public.
 * `families` says which software each targets: against an app that declares a stack without it,
 * the request is rolled up as not applicable. Exposures need a 2xx, so they need the status.
 */
export const stackRules: (MonitorRule & { families: string[] })[] = [
  // Next.js and React
  { id: "stack.nextjs.middleware_bypass", title: "Next.js middleware bypass attempt (x-middleware-subrequest)", severity: "critical", category: "exploit", families: ["nextjs"], sources: ["http"],
    match: s => /"x-middleware-subrequest"\s*:/i.test(s) },
  { id: "stack.nextjs.sourcemap_exposed", title: "Next.js source maps served publicly", severity: "medium", category: "recon", families: ["nextjs"], sources: ["http"],
    match: (s, raw) => /\.js\.map(?=[\s?"#]|$)/i.test(s) && /\/_next\/static\//i.test(s) && served(raw) },
  // Vite dev servers (CVE-2025-30208 and kin): arbitrary file read through /@fs and ?raw??.
  { id: "stack.vite.fs_read", title: "Vite dev server file read attempt", severity: "high", category: "exploit", families: ["vite"], sources: ["http"],
    match: s => /\/@fs\/|[?&](?:raw|import&raw|inline)\?\?|\?import&raw\?\?/i.test(s) },
  // Node.js
  { id: "stack.node.package_files_exposed", title: "Node.js package files served publicly", severity: "high", category: "secrets", families: ["js"], sources: ["http"],
    match: (s, raw) => /\/(?:\.npmrc|package-lock\.json|node_modules\/[^\s"?]+)(?=[\s?"#]|$)/i.test(s) && served(raw) },
  // Python
  { id: "stack.flask.debugger_console", title: "Werkzeug debugger console attempt", severity: "critical", category: "exploit", families: ["flask", "python"], sources: ["http"],
    match: s => /[?&]__debugger__=yes&(?:cmd|frm)=/i.test(s) },
  { id: "stack.flask.console_exposed", title: "Werkzeug debugger console served publicly", severity: "critical", category: "secrets", families: ["flask", "python"], sources: ["http"],
    match: (s, raw) => /"[A-Z]+ \/console(?:[?\s])|"path"\s*:\s*"\/console(?:[?"])/i.test(s) && served(raw) },
  { id: "stack.django.debug_toolbar_exposed", title: "Django debug toolbar served publicly", severity: "high", category: "secrets", families: ["django"], sources: ["http"],
    match: (s, raw) => /\/__debug__\//i.test(s) && served(raw) },
  // Ruby on Rails
  { id: "stack.rails.info_exposed", title: "Rails info pages served publicly", severity: "high", category: "secrets", families: ["rails"], sources: ["http"],
    match: (s, raw) => /\/rails\/info\/(?:properties|routes)/i.test(s) && served(raw) },
  // PHP and Laravel
  { id: "stack.laravel.ignition_rce", title: "Laravel Ignition remote code execution attempt (CVE-2021-3129)", severity: "critical", category: "exploit", families: ["laravel"], sources: ["http"],
    match: s => /\/_ignition\/execute-solution/i.test(s) },
  { id: "stack.laravel.debug_tools_exposed", title: "Laravel debug tools or logs served publicly", severity: "high", category: "secrets", families: ["laravel"], sources: ["http"],
    match: (s, raw) => /\/(?:telescope|horizon|_debugbar)(?:\/|[\s?"]|$)|\/storage\/logs\/laravel\.log/i.test(s) && served(raw) },
  { id: "stack.php.phpunit_rce", title: "PHPUnit eval-stdin remote code execution attempt (CVE-2017-9841)", severity: "critical", category: "exploit", families: ["php"], sources: ["http"],
    match: s => /eval-stdin\.php/i.test(s) && /\/phpunit\//i.test(s) },
  { id: "stack.php.cgi_argument_injection", title: "PHP-CGI argument injection attempt (CVE-2024-4577)", severity: "critical", category: "exploit", families: ["php"], sources: ["http"],
    match: s => /\?(?:­|-)d[\s+]*(?:allow_url_include|auto_prepend_file|cgi\.force_redirect)/i.test(s) },
  { id: "stack.php.stream_wrapper", title: "PHP stream wrapper injection attempt", severity: "high", category: "exploit", families: ["php"], sources: ["http"],
    match: s => /\b(?:php:\/\/(?:input|filter|stdin)|phar:\/\/|expect:\/\/|data:\/\/text\/plain;base64)/i.test(s) },
  // WordPress
  { id: "stack.wordpress.recon_user_enum", title: "WordPress user enumeration", severity: "medium", category: "recon", families: ["wordpress"], sources: ["http"],
    match: s => /\/wp-json\/wp\/v2\/users|[?&]author=\d+(?:[&\s"]|$)/i.test(s) },
  { id: "stack.wordpress.plugin_file_read", title: "WordPress plugin file read attempt", severity: "high", category: "exploit", families: ["wordpress"], sources: ["http"],
    match: s => /admin-ajax\.php\?/i.test(s) && /[?&]action=(?:revslider_show_image|duplicator_download|kc_get_thumbn)/i.test(s) },
  // Java and Spring
  { id: "stack.spring.spring4shell", title: "Spring4Shell attempt (CVE-2022-22965)", severity: "critical", category: "exploit", families: ["spring", "java"], sources: ["http"],
    match: s => /class\.module\.classLoader/i.test(s) },
  { id: "stack.java.expression_injection", title: "Java expression injection attempt (SpEL or OGNL)", severity: "critical", category: "exploit", families: ["java"], sources: ["http", "log"],
    match: s => /T\(java\.lang\.(?:Runtime|ProcessBuilder|System)\)|%\{\(#|\$\{#_memberAccess|@ognl\.OgnlContext|#context\[/i.test(s) },
  { id: "stack.spring.actuator_exposed", title: "Spring Boot actuator served publicly", severity: "critical", category: "secrets", families: ["spring"], sources: ["http"],
    match: (s, raw) => /\/actuator\/(?:env|heapdump|threaddump|configprops|gateway\/routes|jolokia|loggers|mappings)(?=[\s?"#/]|$)/i.test(s) && served(raw) },
  { id: "stack.java.admin_console_exposed", title: "Java admin console served publicly", severity: "high", category: "secrets", families: ["java"], sources: ["http"],
    match: (s, raw) => /\/(?:manager\/html|jolokia|jmx-console|web-console)(?=[\s?"#/]|$)/i.test(s) && served(raw) },
  // Go
  { id: "stack.go.pprof_exposed", title: "Go pprof or expvar served publicly", severity: "high", category: "secrets", families: ["go"], sources: ["http"],
    match: (s, raw) => /\/debug\/(?:pprof|vars)(?=[\s?"#/]|$)/i.test(s) && served(raw) },
  // .NET
  { id: "stack.dotnet.diagnostics_exposed", title: "ASP.NET diagnostics served publicly (elmah or trace)", severity: "high", category: "secrets", families: ["dotnet"], sources: ["http"],
    match: (s, raw) => /\/(?:elmah|trace)\.axd/i.test(s) && served(raw) },
  { id: "stack.dotnet.telerik_rau", title: "Telerik UI upload exploit attempt (CVE-2019-18935)", severity: "critical", category: "exploit", families: ["dotnet"], sources: ["http"],
    match: s => /Telerik\.Web\.UI\.WebResource\.axd\?/i.test(s) && /[?&]type=rau\b/i.test(s) },
  { id: "stack.dotnet.web_config_exposed", title: "web.config served publicly", severity: "critical", category: "secrets", families: ["dotnet"], sources: ["http"],
    match: (s, raw) => /\/web\.config(?=[\s?"#]|$)/i.test(s) && served(raw) },
  // GraphQL, any stack
  { id: "stack.graphql.recon_introspection", title: "GraphQL introspection query", severity: "medium", category: "recon", families: [], sources: ["http"],
    // Each query parameter once, then its value: one regex across the line backtracked quadratically.
    match: s => { for (const [, value] of s.matchAll(/[?&]query=([^\s"&]*)/gi)) if (/__(?:schema|type)\b/i.test(value!)) return true; return false; } },
];

const byId = new Map(stackRules.map(r => [r.id, r]));
/** The families a rule targets (stack rules only; built-in rules target every stack). */
export function ruleFamilies(ruleId: string): string[] {
  return byId.get(ruleId)?.families ?? [];
}
