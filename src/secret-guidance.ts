// What to do when a credential has leaked. Provider is guessed from the value's public prefix only; the
// value itself is never returned or printed.
export interface Provider { name: string; rotate: string }

const PROVIDERS: Array<{ re: RegExp; p: Provider }> = [
  { re: /^sk-ant-/, p: { name: "Anthropic", rotate: "Console > Settings > API keys: create a new key, then delete the exposed one." } },
  { re: /^sk-/, p: { name: "OpenAI", rotate: "platform.openai.com > API keys: revoke the exposed key and create a new one." } },
  { re: /^(?:gh[pousr]_|github_pat_)/, p: { name: "GitHub", rotate: "GitHub > Settings > Developer settings > Tokens: delete the token and issue a new one." } },
  { re: /^AKIA/, p: { name: "AWS", rotate: "IAM > Users > Security credentials: make the access key inactive, create a new one, then delete the old; review CloudTrail for use." } },
  { re: /^xox[baprs]-/, p: { name: "Slack", rotate: "api.slack.com/apps: revoke the token or reinstall the app to issue a new one." } },
  { re: /^beam_app_/, p: { name: "Beam", rotate: "Revoke the app key in your Beam workspace and generate a new one." } },
];

export function providerOf(value: string): Provider | null {
  return PROVIDERS.find(x => x.re.test(value))?.p ?? null;
}

export const PRIVATE_KEY_GUIDANCE: Provider = { name: "Private key", rotate: "Generate a new key pair, replace the public key wherever it is authorised (servers, GitHub, cloud), and discard the old one." };

export const GENERIC_ROTATION = "Treat it as compromised: rotate it with the provider first (policy 6.1), then remove it from history with git filter-repo or BFG and force-push.";

/** One line per leaked provider, e.g. "AWS: IAM > ...". */
export function rotationAdvice(providers: Iterable<Provider | null>): string {
  const seen = new Map<string, string>();
  let unknown = false;
  for (const p of providers) { if (p) seen.set(p.name, p.rotate); else unknown = true; }
  const lines = [...seen].map(([name, how]) => `${name}: ${how}`);
  if (unknown) lines.push("Other key: rotate it in the issuing service.");
  return lines.length ? `${lines.join(" ")} Then clean history (git filter-repo or BFG).` : GENERIC_ROTATION;
}
