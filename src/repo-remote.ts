import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * Where a repository lives, for the dashboard's repository tag: GitHub, GitLab, Bitbucket, Azure
 * DevOps, AWS CodeCommit, Hugging Face, self-hosted servers, and so on -- plus the container
 * registries (AWS ECR, GHCR, Docker Hub, ...) a command pushes to or pulls from.
 *
 * Read from `.git/config` and the command text. No `git` process is spawned and nothing touches the
 * network. Credentials in a URL (https://user:token@host/...) are always dropped, and only
 * host + path (the same "owner/repo" you would read off the page) are reported.
 */
export type RepoRemote = {
  /** github | gitlab | bitbucket | azure-devops | aws-codecommit | codeberg | sourcehut | gitea | huggingface | other */
  provider: string;
  /** Host name only, no port or credentials. */
  host: string;
  /** owner/repo, group/subgroup/repo, org/project/repo (Azure DevOps) or the repository name (CodeCommit). */
  path: string;
  protocol: "https" | "http" | "ssh" | "git" | "codecommit";
  /** A web link to the repository, only for hosts whose layout is known. Always https. */
  url?: string;
  /** AWS region, for CodeCommit. */
  region?: string;
};

export type RegistryRef = {
  /** aws-ecr | aws-ecr-public | ghcr | docker-hub | gcr | gcp-artifact-registry | azure-acr | quay | gitlab-registry */
  provider: string;
  host: string;
  /** Repository path inside the registry (no tag, no digest). */
  path: string;
  tag?: string;
  /** AWS account id (ECR) -- an identifier, not a secret. */
  account?: string;
  region?: string;
};

const SAFE_SEGMENT = /^[A-Za-z0-9._~@+-]+$/;
const cleanPath = (p: string) => p.replace(/^\/+/, "").replace(/\/+$/, "").replace(/\.git$/i, "");
const okPath = (p: string) => p.length > 0 && p.length <= 200 && p.split("/").every(s => SAFE_SEGMENT.test(s) && s !== "." && s !== "..");

function providerOf(host: string): string {
  const h = host.toLowerCase();
  if (/(^|\.)github\./.test(h) || h === "github.com" || h.endsWith(".github.com")) return "github";
  if (/(^|\.)gitlab\./.test(h) || h.includes("gitlab")) return "gitlab";
  if (/(^|\.)bitbucket\./.test(h) || h.includes("bitbucket")) return "bitbucket";
  if (h === "dev.azure.com" || h === "ssh.dev.azure.com" || h.endsWith(".visualstudio.com")) return "azure-devops";
  if (/^git-codecommit(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/.test(h)) return "aws-codecommit";
  if (h === "codeberg.org") return "codeberg";
  if (h === "git.sr.ht" || h === "sr.ht") return "sourcehut";
  if (h === "huggingface.co" || h.endsWith(".hf.co")) return "huggingface";
  if (h.includes("gitea") || h.includes("forgejo")) return "gitea";
  return "other";
}

function browse(provider: string, host: string, path: string, region?: string): string | undefined {
  switch (provider) {
    case "azure-devops": {
      const [org, project, repo] = path.split("/");
      return org && project && repo ? `https://dev.azure.com/${org}/${project}/_git/${repo}` : undefined;
    }
    case "aws-codecommit":
      return region ? `https://${region}.console.aws.amazon.com/codesuite/codecommit/repositories/${path}/browse?region=${region}` : undefined;
    case "sourcehut":
      return `https://git.sr.ht/${path}`;
    default:
      return `https://${host}/${path}`;
  }
}

/** Parses any git remote URL form. Returns undefined for local paths and anything unrecognisable. */
export function parseRemoteUrl(input: string): RepoRemote | undefined {
  const raw = input.trim();
  if (!raw || raw.length > 500) return undefined;

  // codecommit::us-east-1://my-repo  or  codecommit://profile@my-repo
  const cc = /^codecommit(?:::([a-z0-9-]+))?:\/\/(?:[^@/]+@)?([A-Za-z0-9._-]+)\/?$/.exec(raw);
  if (cc) {
    const region = cc[1];
    return { provider: "aws-codecommit", host: region ? `git-codecommit.${region}.amazonaws.com` : "git-codecommit.amazonaws.com", path: cc[2], protocol: "codecommit", ...(region ? { region } : {}), ...(region ? { url: browse("aws-codecommit", "", cc[2], region) } : {}) };
  }

  let host = "", path = "", protocol: RepoRemote["protocol"] = "https";
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(raw);
  if (scheme) {
    let u: URL;
    try { u = new URL(raw); } catch { return undefined; }
    const proto = u.protocol.replace(":", "").toLowerCase();
    if (proto === "file") return undefined;
    protocol = proto === "http" ? "http" : proto === "https" ? "https" : proto === "git" ? "git" : "ssh";
    host = u.hostname.toLowerCase(); // port, user and password are dropped here
    path = decodeURIComponent(u.pathname);
  } else {
    // scp-like: git@github.com:owner/repo.git   (but not C:\path or ./relative)
    const scp = /^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):(?!\/\/)(.+)$/.exec(raw);
    if (!scp || /^[A-Za-z]$/.test(scp[1])) return undefined;
    host = scp[1].toLowerCase(); path = scp[2]; protocol = "ssh";
  }
  if (!host || !/^[a-z0-9.-]+$/.test(host)) return undefined;

  let provider = providerOf(host);
  let region: string | undefined;
  path = cleanPath(path);
  if (provider === "azure-devops") {
    // https://dev.azure.com/org/project/_git/repo   |   git@ssh.dev.azure.com:v3/org/project/repo
    path = path.replace(/^v3\//, "").replace(/\/_git\//, "/");
    const vs = /^([a-z0-9-]+)\.visualstudio\.com$/.exec(host);
    if (vs) path = `${vs[1]}/${path}`;
  } else if (provider === "aws-codecommit") {
    region = /^git-codecommit(?:-fips)?\.([a-z0-9-]+)\./.exec(host)?.[1];
    path = path.replace(/^v1\/repos\//, "");
  } else if (provider === "sourcehut") {
    path = path.replace(/^~/, "~");
  }
  if (!okPath(path)) return undefined;
  if (protocol === "http") provider = providerOf(host);
  return {
    provider, host, path, protocol,
    ...(region ? { region } : {}),
    ...(protocol !== "http" ? { url: browse(provider, host, path, region) } : {}),
  };
}

function readSmall(file: string, max = 65536): string | undefined {
  try {
    if (!existsSync(file) || statSync(file).size > max) return undefined;
    const fd = openSync(file, "r");
    try { const buf = Buffer.alloc(max); const n = readSync(fd, buf, 0, max, 0); return buf.subarray(0, n).toString("utf8"); } finally { closeSync(fd); }
  } catch { return undefined; }
}

/** The origin remote (or the first remote) from a git directory's config. */
export function readOriginRemote(gitDir: string): RepoRemote | undefined {
  const config = readSmall(join(gitDir, "config"));
  if (!config) return undefined;
  const remotes: { name: string; url?: string }[] = [];
  let current: { name: string; url?: string } | undefined;
  for (const line of config.split(/\r?\n/)) {
    const section = /^\s*\[\s*remote\s+"([^"]+)"\s*\]\s*$/.exec(line);
    if (section) { current = { name: section[1] }; remotes.push(current); continue; }
    if (/^\s*\[/.test(line)) { current = undefined; continue; }
    const url = current && !current.url ? /^\s*url\s*=\s*(.+?)\s*$/.exec(line) : null;
    if (current && url) current.url = url[1];
  }
  const pick = remotes.find(r => r.name === "origin" && r.url) ?? remotes.find(r => r.url);
  return pick?.url ? parseRemoteUrl(pick.url) : undefined;
}

// ---- container registries ---------------------------------------------------------------------

const TAG = "(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?";
const REGISTRIES: { provider: string; re: RegExp; build: (m: RegExpExecArray) => RegistryRef }[] = [
  { provider: "aws-ecr", re: new RegExp(`\\b(\\d{12})\\.dkr\\.ecr(?:-fips)?\\.([a-z0-9-]+)\\.amazonaws\\.com(?:\\.cn)?/([a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "aws-ecr", host: `${m[1]}.dkr.ecr.${m[2]}.amazonaws.com`, path: m[3], account: m[1], region: m[2], ...(m[4] ? { tag: m[4] } : {}) }) },
  { provider: "aws-ecr-public", re: new RegExp(`\\bpublic\\.ecr\\.aws/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "aws-ecr-public", host: "public.ecr.aws", path: m[1], ...(m[2] ? { tag: m[2] } : {}) }) },
  { provider: "ghcr", re: new RegExp(`\\bghcr\\.io/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "ghcr", host: "ghcr.io", path: m[1], ...(m[2] ? { tag: m[2] } : {}) }) },
  { provider: "gcp-artifact-registry", re: new RegExp(`\\b([a-z0-9-]+)-docker\\.pkg\\.dev/([a-z0-9][a-z0-9.:-]*/[a-z0-9._-]+/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "gcp-artifact-registry", host: `${m[1]}-docker.pkg.dev`, path: m[2], region: m[1], ...(m[3] ? { tag: m[3] } : {}) }) },
  { provider: "gcr", re: new RegExp(`\\b((?:[a-z]+\\.)?gcr\\.io)/([a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "gcr", host: m[1].toLowerCase(), path: m[2], ...(m[3] ? { tag: m[3] } : {}) }) },
  { provider: "azure-acr", re: new RegExp(`\\b([a-z0-9]{5,50})\\.azurecr\\.io/([a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "azure-acr", host: `${m[1]}.azurecr.io`, path: m[2], ...(m[3] ? { tag: m[3] } : {}) }) },
  { provider: "quay", re: new RegExp(`\\bquay\\.io/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "quay", host: "quay.io", path: m[1], ...(m[2] ? { tag: m[2] } : {}) }) },
  { provider: "gitlab-registry", re: new RegExp(`\\bregistry\\.gitlab\\.com/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "gitlab-registry", host: "registry.gitlab.com", path: m[1], ...(m[2] ? { tag: m[2] } : {}) }) },
  { provider: "docker-hub", re: new RegExp(`\\b(?:docker\\.io|index\\.docker\\.io|registry-1\\.docker\\.io)/([a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*)${TAG}`, "i"),
    build: m => ({ provider: "docker-hub", host: "docker.io", path: m[1], ...(m[2] ? { tag: m[2] } : {}) }) },
];

/** Container registries named in a command (docker push/pull/build, aws ecr, ...). At most 4, no duplicates. */
export function registriesIn(text: string): RegistryRef[] {
  const out: RegistryRef[] = []; const seen = new Set<string>();
  for (const { re, build } of REGISTRIES) {
    for (const m of text.matchAll(new RegExp(re.source, "gi"))) {
      const ref = build(m as RegExpExecArray);
      const key = `${ref.provider}|${ref.host}|${ref.path}`;
      if (seen.has(key) || !okPath(ref.path.replace(/:/g, ""))) continue;
      seen.add(key); out.push(ref);
      if (out.length >= 4) return out;
    }
  }
  return out;
}
