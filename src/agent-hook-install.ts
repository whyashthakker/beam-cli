import { readFile, mkdir, writeFile, rename, rm, copyFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { parse as parseJSONC, type ParseError } from 'jsonc-parser';
import { parseDocument, isMap, isSeq } from 'yaml';
import { parse as parseTOML } from 'smol-toml';
import { HOOK_CATALOG, type HookSpec } from './hook-catalog.js';
import { mergeHookSpec, unmergeHookSpec, ownsHook, hookCommands, object, eventCommand } from './hook-config.js';
import { pluginSource, PLUGIN_MARKER } from './agent-plugins.js';
import type { HookTarget, CustomInstaller } from './agent-installers.js';
import type { Obj } from './agents.js';

const ENV_ROOTS: Record<string, [string, string]> = {
  'claude-code': ['CLAUDE_CONFIG_DIR', '.claude'], codex: ['CODEX_HOME', '.codex'], gemini: ['GEMINI_CLI_HOME', ''],
  'copilot-cli': ['COPILOT_HOME', '.copilot'], vscode: ['COPILOT_HOME', '.copilot'],
  kimi: ['KIMI_CODE_HOME', '.kimi-code'], qwen: ['QWEN_HOME', '.qwen'], cline: ['CLINE_DIR', '.cline'],
  kiro: ['KIRO_HOME', '.kiro'], grok: ['GROK_HOME', '.grok'], hermes: ['HERMES_HOME', '.hermes'], pi: ['PI_CODING_AGENT_DIR', '.pi/agent'],
  opencode: ['OPENCODE_CONFIG_DIR', '.config/opencode'], crush: ['CRUSH_GLOBAL_CONFIG', '.config/crush'],
};
export function agentHookPath(spec: HookSpec, home: string, settings?: string): string {
  if (settings) return resolve(settings);
  if (spec.format === 'project') throw new Error(`${spec.name} hooks are project-scoped. Use beam agent install ${spec.id} --settings /repo/.openhands/hooks.json`);
  if (spec.id === 'cline' && process.env.CLINE_HOOKS_DIR) return resolve(process.env.CLINE_HOOKS_DIR);
  const override = ENV_ROOTS[spec.id];
  if (override && process.env[override[0]]) return join(process.env[override[0]]!, spec.path.slice(override[1].length).replace(/^\//, ''));
  if (spec.path.startsWith('.config/') && process.env.XDG_CONFIG_HOME) return join(process.env.XDG_CONFIG_HOME, spec.path.slice(8));
  if (spec.id === 'devin' && process.platform === 'win32') return join(process.env.APPDATA || join(home, 'AppData/Roaming'), 'devin/config.json');
  return join(home, spec.path);
}
export function agentDetectionPaths(spec: HookSpec, home: string): string[] {
  const override = ENV_ROOTS[spec.id];
  const paths = [join(home, spec.id === 'copilot-cli' ? '.copilot/config.json' : spec.detect)];
  if (override && process.env[override[0]]) paths.push(join(process.env[override[0]]!, spec.id === 'copilot-cli' ? 'config.json' : spec.id === 'gemini' ? '.gemini' : ''));
  if (spec.detect.startsWith('.config/') && process.env.XDG_CONFIG_HOME) paths.push(join(process.env.XDG_CONFIG_HOME, spec.detect.slice(8)));
  return paths;
}
export async function optionalText(path: string): Promise<string> {
  try { return await readFile(path, 'utf8'); } catch (e) { if ((e as NodeJS.ErrnoException).code === 'ENOENT') return ''; throw e; }
}
export async function writeHookFile(path: string, content: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  try { await copyFile(path, `${path}.beam-backup`, constants.COPYFILE_EXCL); } catch (e) { if (!['ENOENT','EEXIST'].includes((e as NodeJS.ErrnoException).code || '')) throw e; }
  const temp = `${path}.${randomUUID()}.tmp`;
  try { await writeFile(temp, content, { mode, flag: 'wx' }); await rename(temp, path); } finally { await rm(temp, { force: true }); }
}
function jsonConfig(raw: string): Obj {
  const errors: ParseError[] = [];
  const value = parseJSONC(raw || '{}', errors, { allowTrailingComma: true });
  if (errors.length) throw new Error('Hook configuration contains invalid JSON; fix it before installing.');
  return object(value);
}
function command(t: HookTarget): string {
  if (process.platform === 'win32') return `"${t.nodePath}" "${t.cliPath}" hook ${t.agentId}`;
  return [t.nodePath, t.cliPath].map(s => `"${s.replace(/(["\\$`])/g, '\\$1')}"`).join(' ') + ` hook ${t.agentId}`;
}
function stripToml(raw: string): string {
  const begin = '# beam:begin Kimi hooks'; const end = '# beam:end Kimi hooks';
  if (!raw.includes(begin) && !raw.includes(end)) return raw;
  const start = raw.indexOf(begin), stop = raw.indexOf(end);
  if (start < 0 || stop < start || raw.indexOf(begin, start + 1) >= 0) throw new Error('Malformed Beam hook block; configuration was not changed.');
  return raw.slice(0, start) + raw.slice(stop + end.length).replace(/^\n/, '');
}
function yamlUpdate(raw: string, spec: HookSpec, cmd?: string): string {
  const doc = parseDocument(raw.replace(/^\s*# beam:(?:begin.*|end)\n/gm, '') || '{}');
  if (doc.errors.length || !isMap(doc.contents)) throw new Error('Invalid YAML hook configuration.');
  const hooks = doc.get('hooks', true);
  if (hooks !== undefined && !isMap(hooks)) throw new Error('Expected a YAML hooks mapping.');
  if (!hooks && cmd) doc.set('hooks', doc.createNode({}));
  for (const event of spec.events) {
    const node = doc.getIn(['hooks', event], true);
    if (node !== undefined && !isSeq(node)) throw new Error(`Expected a YAML hooks.${event} list.`);
    if (isSeq(node)) {
      node.items = node.items.filter(item => !ownsHook(String(isMap(item) ? item.get('command') ?? '' : ''), spec.id));
      if (!node.items.length && !cmd) doc.deleteIn(['hooks', event]);
    }
    if (cmd) {
      if (!doc.hasIn(['hooks', event])) doc.setIn(['hooks', event], doc.createNode([]));
      doc.addIn(['hooks', event], { command: eventCommand(cmd, event), timeout: 30 });
    }
  }
  if (!cmd && isMap(doc.get("hooks", true)) && (doc.get("hooks", true) as import("yaml").YAMLMap).items.length === 0) doc.delete("hooks");
  return String(doc);
}
function scriptSource(t: HookTarget, event: string): string {
  const cmd = eventCommand(command(t), event);
  return process.platform === 'win32' ? `# beam-managed hook\n$payload = [Console]::In.ReadToEnd()\n$payload | & ${cmd}\nexit $LASTEXITCODE\n` : `#!/bin/sh\n# beam-managed hook\nexec ${cmd}\n`;
}

export function catalogInstaller(spec: HookSpec, settings?: string): CustomInstaller {
  const pathFor = (home: string) => agentHookPath(spec, home, settings);
  return {
    async install(home, target) {
      const path = pathFor(home); const cmd = command(target);
      if (spec.format === 'plugin') {
        const raw = await optionalText(path);
        const legacy = spec.id === 'opencode' && raw.includes('export const BeamPlugin') && raw.includes('Beam denied this tool execution.');
        if (raw && !raw.startsWith(PLUGIN_MARKER) && !legacy) throw new Error(`Refusing to overwrite unowned plugin ${path}`);
        const next = pluginSource(target);
        if (next !== raw) await writeHookFile(path, next);
        if (spec.id === 'opencode' && !settings) {
          const legacyPath = join(home, '.opencode/plugins/beam.ts');
          const legacy = await optionalText(legacyPath);
          if (legacy.includes('export const BeamPlugin') && legacy.includes('Beam denied this tool execution.')) { await copyFile(legacyPath, legacyPath + '.beam-backup', constants.COPYFILE_EXCL).catch(e => { if (e.code !== 'EEXIST') throw e; }); await rm(legacyPath); }
        }
        return { path, alreadyInstalled: next === raw, note: 'Restart the agent to load the generated integration.' };
      }
      if (spec.format === 'scripts') {
        const files = spec.events.map(e => join(path, e + (process.platform === 'win32' ? '.ps1' : '')));
        const contents = await Promise.all(files.map(optionalText));
        for (let i=0; i<files.length; i++) if (contents[i] && !contents[i].includes('# beam-managed hook')) throw new Error(`Existing ${files[i]} is not managed by Beam; chain it manually.`);
        let same = true;
        for (let i=0; i<files.length; i++) { const next = scriptSource(target, spec.events[i]); if (next !== contents[i]) { same = false; await writeHookFile(files[i], next, 0o700); } }
        return { path, alreadyInstalled: same };
      }
      const raw = await optionalText(path);
      let next: string;
      if (spec.format === 'toml') {
        parseTOML(raw); const base = stripToml(raw).trimEnd();
        next = (base ? base + '\n\n' : '') + '# beam:begin Kimi hooks\n' + spec.events.map(e => `[[hooks]]\nevent = ${JSON.stringify(e)}\ncommand = ${JSON.stringify(eventCommand(cmd, e))}\ntimeout = 30\n`).join('\n') + '# beam:end Kimi hooks\n';
        parseTOML(next);
      } else if (spec.format === 'yaml') next = yamlUpdate(raw, spec, cmd);
      else {
        const existing = jsonConfig(raw);
        const own = (c: string) => ownsHook(c, spec.id) || (spec.format === 'auggie' && spec.events.some(e => c === join(dirname(path), 'hooks', `beam-${e}${process.platform === 'win32' ? '.ps1' : '.sh'}`)));
        let merged = mergeHookSpec(spec, unmergeHookSpec(spec, existing, own), cmd);
        if (spec.format === 'auggie') {
          for (const event of spec.events) {
            const script = join(dirname(path), 'hooks', `beam-${event}${process.platform === 'win32' ? '.ps1' : '.sh'}`);
            const old = await optionalText(script);
            if (old && !old.includes('# beam-managed hook')) throw new Error(`Refusing to overwrite ${script}`);
            await writeHookFile(script, scriptSource(target, event), 0o700);
            const groups = object(merged.hooks)[event] as Obj[];
            for (const group of groups) for (const ref of (group.hooks ?? []) as Obj[]) if (ownsHook(String(ref.command), spec.id)) { ref.command = script; ref.timeout = 30000; }
          }
        }
        next = JSON.stringify(merged, null, 2) + '\n';
      }
      if (next !== raw) await writeHookFile(path, next);
      if (spec.format === 'goose') {
        const manifest = join(dirname(dirname(path)), 'plugin.json');
        const old = await optionalText(manifest);
        if (old && jsonConfig(old).name !== 'beam') throw new Error(`Refusing to overwrite ${manifest}`);
        await writeHookFile(manifest, JSON.stringify({ name: 'beam', version: '1.0.0', description: 'Beam agent activity capture' }, null, 2) + '\n');
      }
      return { path, alreadyInstalled: next === raw, note: spec.id === 'hermes' ? 'Review and approve the updated shell hooks in Hermes, then restart the active profile.' : 'Restart the agent and review its hook trust settings.' };
    },
    async uninstall(home) {
      const path = pathFor(home);
      if (spec.format === 'scripts') {
        let removed = false;
        for (const e of spec.events) { const file = join(path, e + (process.platform === 'win32' ? '.ps1' : '')); if ((await optionalText(file)).includes('# beam-managed hook')) { await rm(file); removed = true; } }
        return { path, removed };
      }
      const raw = await optionalText(path); if (!raw) return { path, removed: false };
      if (spec.format === 'plugin') {
        if (!raw.startsWith(PLUGIN_MARKER)) return { path, removed: false };
        await rm(path); return { path, removed: true };
      }
      let next: string;
      if (spec.format === 'toml') { parseTOML(raw); next = stripToml(raw); }
      else if (spec.format === 'yaml') next = yamlUpdate(raw, spec);
      else {
        const existing = jsonConfig(raw);
        const own = (c: string) => ownsHook(c, spec.id) || (spec.format === 'auggie' && spec.events.some(e => c === join(dirname(path), 'hooks', `beam-${e}${process.platform === 'win32' ? '.ps1' : '.sh'}`)));
        const changed = unmergeHookSpec(spec, existing, own);
        if (JSON.stringify(changed) === JSON.stringify(existing)) return { path, removed: false };
        next = JSON.stringify(changed, null, 2) + '\n';
        if (spec.format === 'auggie') for (const e of spec.events) { const script = join(dirname(path), 'hooks', `beam-${e}${process.platform === 'win32' ? '.ps1' : '.sh'}`); if ((await optionalText(script)).includes('# beam-managed hook')) await rm(script); }
      }
      if (next !== raw) await writeHookFile(path, next);
      return { path, removed: next !== raw };
    },
    async isInstalled(home) {
      const path = pathFor(home);
      if (spec.format === 'scripts') return (await Promise.all(spec.events.map(async e => (await optionalText(join(path, e + (process.platform === 'win32' ? '.ps1' : '')))).includes('# beam-managed hook')))).every(Boolean);
      const raw = await optionalText(path); if (!raw) return false;
      if (spec.format === 'plugin') return raw === pluginSource({ nodePath: process.execPath, cliPath: new URL('./cli.js', import.meta.url).pathname, agentId: spec.id }) || raw.startsWith(PLUGIN_MARKER);
      if (spec.format === 'toml') return raw.includes('# beam:begin Kimi hooks') && spec.events.every(e => raw.includes(`event = ${JSON.stringify(e)}`));
      if (spec.format === 'yaml') { const doc = parseDocument(raw); return !doc.errors.length && spec.events.every(e => { const node = doc.getIn(['hooks', e], true); return isSeq(node) && node.items.some(i => isMap(i) && ownsHook(String(i.get('command')), spec.id)); }); }
      const parsed = jsonConfig(raw);
      const commands = hookCommands(spec, parsed);
      return spec.events.every(e => commands.some(c => (ownsHook(c, spec.id) && c.endsWith(`--event ${JSON.stringify(e)}`)) || (spec.format === 'auggie' && c.includes(`beam-${e}.`))));
    },
  };
}
export const CATALOG_INSTALLERS: Record<string, CustomInstaller> = Object.fromEntries(HOOK_CATALOG.filter(s => s.id !== 'openclaw').map(spec => [spec.id, catalogInstaller(spec)]));
