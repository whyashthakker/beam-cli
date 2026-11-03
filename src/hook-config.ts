import { hookSpec, type HookSpec } from './hook-catalog.js';
import type { Obj } from './agents.js';

export function object(value: unknown): Obj {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected a configuration object.');
  return value as Obj;
}
function list(value: unknown): Obj[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error('Expected a hook array; existing configuration was not changed.');
  return value.map(object);
}
export function eventCommand(command: string, event: string): string { return `${command} --event ${JSON.stringify(event)}`; }
export function ownsHook(command: string, agent: string): boolean {
  const ids = agent === 'vscode' || agent === 'copilot-cli' ? '(?:vscode|copilot-cli)' : agent;
  return (command.startsWith('beam ') || command.includes('cli.js')) && new RegExp(` hook ${ids}(?: --event ["']?[\\w.:-]+["']?)?$`).test(command);
}

export function mergeHookSpec(spec: HookSpec, existing: Obj, command: string): Obj {
  const base = unmergeHookSpec(spec, existing, c => ownsHook(c, spec.id));
  if (spec.format === 'kiro') {
    return { ...base, version: base.version ?? 'v1', hooks: [...list(base.hooks), ...spec.events.map(event => ({ name: `beam-${event}`, description: 'Beam activity capture', trigger: event, ...(event.includes('Tool') ? { matcher: '.*' } : {}), action: { type: 'command', command: eventCommand(command, event) }, timeout: 30, enabled: true }))] };
  }
  const top = spec.format === 'top';
  const anti = spec.format === 'antigravity';
  const hooks = top ? { ...base } : { ...object(anti ? base.beam : base.hooks) };
  // VS Code and Copilot share a native lower-camel file; one registration handles both hosts.
  const events = spec.events;
  for (const event of events) {
    const cmd = eventCommand(command, event);
    const ref = { type: 'command', command: cmd, timeout: 30 };
    if (spec.format === 'copilot' || spec.format === 'vscode') hooks[event] = [...list(hooks[event]), { type: 'command', bash: cmd, powershell: `& ${cmd}`, timeoutSec: 30 }];
    else if (spec.format === 'cursor') hooks[event] = [...list(hooks[event]), { command: cmd, ...(event === 'preToolUse' || event.startsWith('postTool') ? { matcher: '^(?!(?:Read|ReadFile)$).*' } : {}) }];
    else if (spec.format === 'windsurf') hooks[event] = [...list(hooks[event]), { command: cmd, show_output: false, working_directory: '.' }];
    else if (spec.format === 'flat') hooks[event] = [...list(hooks[event]), { name: 'Beam', command: cmd, timeout: 30 }];
    else if (anti && event === 'Stop') hooks[event] = [...list(hooks[event]), ref];
    else {
      const matcher = spec.id === 'muse' || spec.id === 'openhands' || anti ? '*' : ['codex','qwen','goose','auggie'].includes(spec.id) ? '.*' : '';
      const useMatcher = /Tool|Permission/.test(event) || spec.id === 'muse';
      hooks[event] = [...list(hooks[event]), { ...(useMatcher ? { matcher } : {}), hooks: [['qwen','gemini'].includes(spec.id) ? { type: 'command', command: cmd, timeout: 30000 } : ref] }];
    }
  }
  if (top) return hooks;
  return { ...(spec.format === 'copilot' || spec.format === 'vscode' || spec.format === 'cursor' ? { version: 1 } : {}), ...base, ...(spec.id === 'muse' ? { schema_version: base.schema_version ?? 1 } : {}), [anti ? 'beam' : 'hooks']: hooks };
}

export function unmergeHookSpec(spec: HookSpec, existing: Obj, own: (command: string) => boolean): Obj {
  if (spec.format === 'kiro') return { ...existing, hooks: list(existing.hooks).filter(h => !own(String(object(h.action).command ?? ''))) };
  const top = spec.format === 'top'; const anti = spec.format === 'antigravity';
  if (!top && existing[anti ? 'beam' : 'hooks'] === undefined) return existing;
  const hooks = top ? { ...existing } : { ...object(existing[anti ? 'beam' : 'hooks']) };
  for (const [event, value] of Object.entries(hooks)) {
    if (!Array.isArray(value)) continue; // reserved metadata such as Muse hooks.state
    hooks[event] = list(value).flatMap(entry => {
      if (Array.isArray(entry.hooks)) {
        const kept = list(entry.hooks).filter(h => !own(String(h.command ?? '')));
        return kept.length ? [{ ...entry, hooks: kept }] : [];
      }
      return own(String(entry.command ?? entry.bash ?? '')) ? [] : [entry];
    });
  }
  return top ? hooks : { ...existing, [anti ? 'beam' : 'hooks']: hooks };
}
export function hookCommands(spec: HookSpec, existing: Obj): string[] {
  if (spec.format === 'kiro') return list(existing.hooks).map(h => String(object(h.action).command ?? ''));
  const hooks = spec.format === 'top' ? existing : object(existing[spec.format === 'antigravity' ? 'beam' : 'hooks']);
  return Object.values(hooks).flatMap(v => Array.isArray(v) ? list(v).flatMap(h => Array.isArray(h.hooks) ? list(h.hooks).map(r => String(r.command ?? '')) : [String(h.command ?? h.bash ?? '')]) : []);
}
