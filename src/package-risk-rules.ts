import { redact, type Finding, type Severity } from "./core.js";
import { riskRules } from "./skill-risk-rules.js";

// Malicious-package checks for npm and PyPI code. Skills are prose an agent obeys; packages are
// code that runs, so these look for the shapes real supply-chain malware takes (event-stream,
// ua-parser-js, the PyPI "exec(base64...)" droppers, dependency-confusion beacons) rather than for
// instructions. Ordinary package code uses eval, child_process, fetch and process.env all the
// time, so none of those count on their own: a finding needs a malware shape, and blocking takes a
// critical one, which mostly comes from combinations (see COMBOS).
type CodeRule = {
  id: string; title: string; severity: Severity; explanation: string;
  /** Cheap substring prefilter: the regex only runs when one of these occurs in the file. */
  hints: string[];
  find: (content: string) => number;
  /** A signal only feeds combinations and is never reported on its own. */
  signal?: boolean;
};

const regex = (re: RegExp) => (content: string) => re.exec(content)?.index ?? -1;
// At least `min` hits of a pattern in one file (javascript-obfuscator output is full of _0x names).
const many = (re: RegExp, min: number) => (content: string) => {
  let count = 0, first = -1;
  for (const m of content.matchAll(re)) { if (first < 0) first = m.index ?? 0; if (++count >= min) return first; }
  return -1;
};

export const codeRules: CodeRule[] = [
  { id: "pkg.decode_exec", title: "Decodes a payload and executes it", severity: "critical", explanation: "Code is base64/hex/zlib-decoded and passed straight to eval or exec, so what runs is never visible in the source. This is the signature of most malicious PyPI and npm droppers.",
    hints: ["atob", "Buffer.from", "b64decode", "decompress", "marshal", "fromhex", "codecs"],
    find: regex(/\b(?:eval|Function|runInThisContext|runInNewContext|runInContext)\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\()|\bnew\s+Function\s*\(\s*(?:atob\s*\(|Buffer\.from\s*\()|\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|codecs\.decode|__import__\(\s*["'](?:base64|zlib|marshal|codecs)["']\s*\))/) },
  { id: "pkg.exfil_endpoint", title: "Hardcoded data-collection endpoint", severity: "high", explanation: "The code contains a Discord or Telegram bot webhook with its token, or a public request-capture service. Malicious packages use these to receive stolen data without running their own server.",
    hints: ["discord", "telegram", "webhook.site", "pipedream", "interact.sh", "oast.", "burpcollaborator", "requestbin", "requestcatcher", "canarytokens", "ngrok", "transfer.sh", "pastebin"],
    find: regex(/discord(?:app)?\.com\/api\/webhooks\/\d{15,20}\/[\w-]{30,}|api\.telegram\.org\/bot\d{6,12}:[\w-]{30,}|\bwebhook\.site\/[\w-]{8,}|\.m\.pipedream\.net\b|\b(?:interact\.sh|oast\.(?:fun|live|me|online|pro|site)|burpcollaborator\.net|requestbin\.(?:net|com)|requestcatcher\.com|canarytokens\.com)\b|\b[\w-]+\.ngrok(?:-free)?\.(?:io|app)\b|\btransfer\.sh\b|\bpastebin\.com\/raw\b/) },
  { id: "pkg.env_harvest", title: "Serializes the whole environment", severity: "high", explanation: "Every environment variable, which on a developer machine or CI runner includes API keys and tokens, is turned into one string. Ordinary code reads the variables it needs by name.",
    hints: ["process.env", "os.environ"],
    find: regex(/JSON\.stringify\(\s*process\.env\b|json\.dumps\(\s*(?:dict\(\s*)?os\.environ\b|\bstr\(\s*os\.environ\s*\)/) },
  { id: "pkg.obfuscated", title: "Obfuscated code", severity: "high", explanation: "The file looks like javascript-obfuscator output or a long run of hex escapes. Published libraries are minified, not obfuscated; obfuscation exists to stop a reviewer from reading the code.",
    hints: ["_0x", "\\x"],
    find: content => Math.max(many(/\b_0x[0-9a-f]{4,6}\b/g, 40)(content), regex(/(?:\\x[2-7][0-9a-fA-F]){40,}/)(content)) },
  { id: "pkg.sensitive_files", title: "Reads credential or wallet files", severity: "high", explanation: "The code references SSH keys, cloud or registry credentials, shell history, browser password stores or crypto wallets. Confirm the package has a reason to touch them.",
    hints: [".ssh", "id_rsa", "id_ed25519", "id_ecdsa", ".aws", ".git-credentials", ".docker", ".kube", "gcloud", "/etc/", "Login Data", "Local State", "cookies.sqlite", "key4.db", "wallet.dat", "Exodus", "solana", ".electrum", "Keychains", "_history"],
    find: regex(/\.ssh[\\/](?:id_\w+|authorized_keys|config)\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws[\\/]credentials\b|\.git-credentials\b|\.docker[\\/]config\.json\b|\.kube[\\/]config\b|\.config[\\/]gcloud\b|\/etc\/shadow\b|[\\/]Login Data\b|[\\/]Local State\b|\bcookies\.sqlite\b|\bkey4\.db\b|\bwallet\.dat\b|\bExodus[\\/]|\.config[\\/]solana[\\/]id\.json\b|\.electrum\b|Library[\\/]Keychains\b|\.(?:bash|zsh)_history\b/) },
  // CLIs read .npmrc for registry settings all the time; stealing the publish token in it is how
  // npm worms spread (Shai-Hulud, 2025). So it only counts at install time or next to a webhook.
  { id: "pkg.registry_tokens", title: "Reads package-registry credentials", severity: "info", explanation: "The code reads .npmrc or .pypirc, where registry publish tokens live.", signal: true,
    hints: [".npmrc", ".pypirc"],
    find: regex(/\.npmrc\b|\.pypirc\b/) },
  { id: "pkg.recon", title: "Collects host details", severity: "info", explanation: "Hostname, username or network interfaces are read together.", signal: true,
    hints: ["hostname", "userInfo", "networkInterfaces", "getuser", "getlogin", "platform.node"],
    find: content => {
      const hits = [/\bos\.hostname\(\)/, /\bos\.userInfo\(/, /\bos\.networkInterfaces\(/, /\bsocket\.gethostname\(\)/, /\bgetpass\.getuser\(\)/, /\bos\.getlogin\(\)/, /\bplatform\.node\(\)/]
        .map(re => re.exec(content)?.index ?? -1).filter(i => i >= 0);
      return hits.length >= 2 ? Math.min(...hits) : -1;
    } },
  { id: "pkg.network", title: "Makes network calls", severity: "info", explanation: "The file sends requests or opens sockets.", signal: true,
    hints: ["http", "fetch", "axios", "XMLHttpRequest", "net", "dns", "WebSocket", "requests.", "urlopen", "socket.", "curl", "wget"],
    find: regex(/\brequire\(\s*["'](?:node:)?(?:https?|net|dns|tls|dgram)["']\s*\)\.\w+\s*\(|\bhttps?\.(?:request|get)\s*\(|\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\bXMLHttpRequest\b|\bnet\.(?:connect|createConnection)\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\(|\bnew\s+WebSocket\s*\(|\brequests\.(?:get|post|put)\s*\(|\burlopen\s*\(|\burllib\.request\.Request\b|\bhttp\.client\.HTTPS?Connection\b|\bsocket\.(?:socket|create_connection)\s*\(|\bhttpx\.(?:get|post|Client)\b|\b(?:curl|wget)\s[^\n]{0,80}https?:\/\//) },
];

// Shell-shaped rules borrowed from the skill scanner. They only run on code that executes at
// install time and on bundled shell scripts: `launchctl load` in pm2's runtime code is its job; in
// a postinstall it's a package making itself permanent.
const SHELL_RULE_IDS = new Set(["risk.persistence", "risk.destructive_broad", "risk.download_exec", "risk.decode_exec"]);
const shellRules = riskRules.filter(r => SHELL_RULE_IDS.has(r.id));

const lineOf = (content: string, index: number) => content.slice(0, index).split("\n").length;
// Minified files are one enormous line, so evidence is cut around the match rather than taken whole.
const around = (content: string, index: number) => redact(content.slice(Math.max(0, index - 40), index + 160).replace(/\s+/g, " ").trim()).slice(0, 200);

export function scanCode(content: string, options: { shell?: boolean } = {}): Finding[] {
  const findings: Finding[] = [];
  for (const rule of codeRules) {
    if (!rule.hints.some(h => content.includes(h))) continue;
    const at = rule.find(content);
    if (at >= 0) findings.push({ id: rule.id, title: rule.title, severity: rule.severity, explanation: rule.explanation, evidence: around(content, at), line: lineOf(content, at) });
  }
  if (options.shell) {
    const lines = content.split(/\r?\n/);
    for (const rule of shellRules) {
      const i = lines.findIndex(l => l.length <= 2000 && rule.re.test(l));
      if (i >= 0) findings.push({ id: rule.id, title: rule.title, severity: rule.severity, explanation: rule.explanation, evidence: redact(lines[i].trim()).slice(0, 200), line: i + 1 });
    }
  }
  return findings;
}

export const isSignal = (id: string) => codeRules.some(r => r.id === id && r.signal);

// "install" is a marker for files that run when the package is installed (npm lifecycle scripts
// and what they call, a sdist's setup.py). "package" combos look across the whole package.
const COMBOS: Array<{ scope: "file" | "package"; all: string[]; id: string; title: string; severity: Severity; explanation: string }> = [
  { scope: "file", all: ["pkg.env_harvest", "pkg.network"], id: "pkg.combo.env_exfil", title: "Sends the environment over the network", severity: "critical", explanation: "The same file serializes every environment variable and makes network calls: the shape of token theft." },
  { scope: "file", all: ["install", "pkg.env_harvest"], id: "pkg.combo.install_env", title: "Collects the environment during install", severity: "critical", explanation: "Code that runs on install serializes every environment variable. Nothing about installing a library needs that." },
  { scope: "file", all: ["install", "pkg.recon", "pkg.network"], id: "pkg.combo.install_beacon", title: "Fingerprints the machine and phones home during install", severity: "critical", explanation: "Install-time code reads the hostname or username and sends network traffic, the pattern of dependency-confusion and recon payloads." },
  { scope: "file", all: ["install", "pkg.exfil_endpoint"], id: "pkg.combo.install_exfil", title: "Install-time code talks to a data-collection endpoint", severity: "critical", explanation: "A webhook or request-capture service is contacted from code that runs on install." },
  { scope: "file", all: ["install", "pkg.obfuscated"], id: "pkg.combo.install_obfuscated", title: "Obfuscated code runs during install", severity: "critical", explanation: "What the install script does is deliberately hidden." },
  { scope: "file", all: ["pkg.sensitive_files", "pkg.exfil_endpoint"], id: "pkg.combo.credential_exfil", title: "Credential files and a data-collection endpoint together", severity: "critical", explanation: "Reading key, token or wallet files next to a webhook is the shape of credential theft." },
  { scope: "file", all: ["install", "pkg.registry_tokens"], id: "pkg.combo.install_registry_tokens", title: "Reads registry tokens during install", severity: "high", explanation: "Install-time code reads .npmrc or .pypirc. Publish tokens stolen this way let a worm republish every package the victim maintains." },
  { scope: "file", all: ["pkg.registry_tokens", "pkg.exfil_endpoint"], id: "pkg.combo.registry_token_exfil", title: "Registry tokens and a data-collection endpoint together", severity: "critical", explanation: "Reading .npmrc or .pypirc next to a webhook is the shape of publish-token theft." },
  { scope: "file", all: ["pkg.sensitive_files", "pkg.network"], id: "pkg.combo.credential_network", title: "Reads credential files and makes network calls", severity: "medium", explanation: "Legitimate for SDKs that load their own credentials; otherwise a reason to read the file." },
  { scope: "package", all: ["pkg.typosquat", "pkg.new_package"], id: "pkg.combo.fresh_typosquat", title: "Brand-new package named like a popular one", severity: "critical", explanation: "A package published in the last month whose name is one typo from a popular package is the classic typosquat (and the shape of names AI agents hallucinate)." },
];

export function packageComboFindings(perFile: Array<{ file: string; ids: Set<string> }>, packageIds: Set<string>): Array<Finding & { file: string }> {
  const all = new Set([...packageIds, ...perFile.flatMap(f => [...f.ids])]);
  const out: Array<Finding & { file: string }> = [];
  for (const c of COMBOS) {
    const files = c.scope === "package" ? (c.all.every(id => all.has(id)) ? ["(whole package)"] : []) : perFile.filter(f => c.all.every(id => f.ids.has(id))).map(f => f.file);
    for (const file of files) out.push({ id: c.id, title: c.title, severity: c.severity, explanation: c.explanation, evidence: `Together: ${c.all.join(" + ")}`, file });
  }
  return out;
}

// Typosquat check against the most-installed names. Only the names a person or agent typed are
// checked (the requested package, a project's direct dependencies), never transitive ones.
const POPULAR: Record<"npm" | "pip", string[]> = {
  npm: ["react", "react-dom", "preact", "angular", "svelte", "next", "nuxt", "express", "fastify", "lodash", "underscore", "ramda", "axios", "request", "node-fetch", "superagent", "chalk", "commander", "yargs", "minimist", "inquirer", "debug", "dotenv", "cross-env", "rimraf", "mkdirp", "minimatch", "semver", "moment", "dayjs", "date-fns", "luxon", "typescript", "webpack", "rollup", "esbuild", "parcel", "@babel/core", "eslint", "prettier", "mocha", "vitest", "mongoose", "mongodb", "sequelize", "prisma", "@prisma/client", "mysql", "mysql2", "redis", "ioredis", "sqlite3", "socket.io", "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "morgan", "body-parser", "cookie-parser", "multer", "nodemon", "colors", "color", "classnames", "rxjs", "tslib", "core-js", "bluebird", "async", "fs-extra", "chokidar", "cheerio", "puppeteer", "playwright", "jquery", "bootstrap", "tailwindcss", "postcss", "autoprefixer", "styled-components", "redux", "react-redux", "zustand", "react-router", "react-router-dom", "graphql", "openai", "@anthropic-ai/sdk", "langchain", "discord.js", "electron", "three", "chart.js", "marked", "highlight.js", "sharp", "nodemailer", "stripe", "twilio", "firebase", "aws-sdk", "@types/node", "@types/react", "ethers", "web3", "event-stream", "ua-parser-js", "node-ipc", "coffee-script"],
  pip: ["requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn", "tensorflow", "torch", "torchvision", "keras", "transformers", "openai", "anthropic", "langchain", "flask", "django", "fastapi", "uvicorn", "gunicorn", "pydantic", "sqlalchemy", "psycopg2", "psycopg2-binary", "pymysql", "redis", "celery", "boto3", "botocore", "awscli", "pytest", "setuptools", "wheel", "python-dateutil", "pyyaml", "jinja2", "markupsafe", "click", "rich", "typer", "tqdm", "pillow", "opencv-python", "beautifulsoup4", "lxml", "selenium", "scrapy", "httpx", "aiohttp", "cryptography", "pycryptodome", "paramiko", "colorama", "termcolor", "attrs", "certifi", "charset-normalizer", "packaging", "virtualenv", "poetry", "black", "flake8", "mypy", "pylint", "isort", "jupyter", "notebook", "ipython", "plotly", "networkx", "sympy", "nltk", "spacy", "xgboost", "lightgbm", "discord-py", "python-telegram-bot", "pygame", "tweepy", "docker", "kubernetes", "protobuf", "grpcio", "websockets", "pyjwt", "bcrypt", "python-dotenv", "loguru", "huggingface-hub", "datasets", "tokenizers", "accelerate", "diffusers", "streamlit", "gradio"],
};

// PEP 503: pip treats "Foo_Bar", "foo.bar" and "foo-bar" as the same package.
export const normalizePipName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

// Edit distance with adjacent transpositions ("reqeusts"), stopping early once it passes 1.
function withinOneEdit(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) return false;
  let prev2: number[] = [], prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const row = [i];
    for (let j = 1; j <= b.length; j++) {
      row[j] = Math.min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) row[j] = Math.min(row[j], prev2[j - 2] + 1);
    }
    if (Math.min(...row) > 1) return false;
    prev2 = prev; prev = row;
  }
  return prev[b.length] <= 1;
}

/** The popular package `name` looks like a typo of, if any. */
export function typosquatOf(name: string, ecosystem: "npm" | "pip"): string | undefined {
  const norm = (n: string) => (ecosystem === "pip" ? normalizePipName(n) : n.toLowerCase());
  const candidate = norm(name);
  const popular = POPULAR[ecosystem].map(norm);
  if (candidate.length < 5 || popular.includes(candidate)) return undefined;
  // npm names differ by separators alone (crossenv vs cross-env, the 2017 typosquat); pip normalizes those away.
  const bare = (n: string) => n.replace(/[-_.]/g, "");
  return popular.find(p => withinOneEdit(candidate, p) || (ecosystem === "npm" && bare(candidate) === bare(p)));
}
