import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtemp, readFile, writeFile, mkdir, rm, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { HOOK_CATALOG } from '../src/hook-catalog.js';
import { installHook, uninstallHook, isHookInstalled } from '../src/install.js';
import { adaptHookPayload } from '../src/hook-adapters.js';
import { normalize } from '../src/core.js';
import { captureHook } from '../src/client.js';
import { pluginSource } from '../src/agent-plugins.js';
import { drainHookSpool, spoolHookEvent } from '../src/hook-spool.js';
import { createCollector } from '../src/server.js';

const savedEnv = { ...process.env };
const savedFetch = global.fetch;
const savedStdin = process.stdin;
let home: string;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'beam-coverage-'));
  for (const key of ['CLAUDE_CONFIG_DIR','CODEX_HOME','GEMINI_CLI_HOME','COPILOT_HOME','KIMI_CODE_HOME','QWEN_HOME','CLINE_DIR','CLINE_HOOKS_DIR','KIRO_HOME','GROK_HOME','HERMES_HOME','PI_CODING_AGENT_DIR','OPENCODE_CONFIG_DIR','CRUSH_GLOBAL_CONFIG','XDG_CONFIG_HOME']) delete process.env[key];
  process.env.BEAM_HOME = home; process.env.BEAM_DATA_DIR = home; process.env.BEAM_TOKEN = 'test-token';
  process.env.BEAM_OPENCLAW_BIN = '/missing/openclaw';
  process.exitCode = 0;
});
afterEach(async () => {
  process.env = { ...savedEnv }; global.fetch = savedFetch;
  Object.defineProperty(process, 'stdin', { value: savedStdin, configurable: true });
  process.exitCode = 0; jest.restoreAllMocks(); await rm(home, { recursive: true, force: true });
});

describe('agent installation lifecycle', () => {
  it.each(HOOK_CATALOG.filter(s => s.id !== 'openclaw').map(s => [s.id]))('%s installs, upgrades idempotently, and removes its integration', async id => {
    const explicit = id === 'openhands' ? join(home, 'repo/.openhands/hooks.json') : undefined;
    const first = await installHook(id, home, explicit);
    expect(first.alreadyInstalled).toBe(false);
    expect(await isHookInstalled(id, home, explicit)).toBe(true);
    const second = await installHook(id, home, explicit);
    expect(second.alreadyInstalled).toBe(true);
    expect((await uninstallHook(id, home, explicit)).removed).toBe(true);
    expect(await isHookInstalled(id, home, explicit)).toBe(false);
    expect((await uninstallHook(id, home, explicit)).removed).toBe(false);
  });

  it('preserves JSONC settings, foreign hook entries and reserved metadata', async () => {
    const path = join(home, '.config/muse/settings.json'); await mkdir(join(home, '.config/muse'), { recursive: true });
    const original = '{ // user comment\n "schema_version":1, "theme":"dark", "hooks":{"state":{"foreign":false}, "PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"echo keep","extra":true}]}]}, }';
    await writeFile(path, original);
    await installHook('muse', home); await installHook('muse', home); await uninstallHook('muse', home);
    const config = JSON.parse(await readFile(path, 'utf8'));
    expect(config.hooks.state).toEqual({ foreign: false });
    expect(config.hooks.PreToolUse).toEqual([{ matcher: 'Read', hooks: [{ type:'command', command:'echo keep', extra:true }] }]);
    expect(config.theme).toBe('dark');
    expect(await readFile(path + '.beam-backup', 'utf8')).toBe(original);
  });

  it('merges existing Hermes hooks without deleting user hooks or comments', async () => {
    const path = join(home, '.hermes/config.yaml'); await mkdir(join(home, '.hermes'));
    await writeFile(path, 'model: x # keep\nhooks:\n  pre_tool_call:\n    - command: custom.sh\n');
    await installHook('hermes', home); await installHook('hermes', home); await uninstallHook('hermes', home);
    const yaml = await readFile(path,'utf8'); expect(yaml).toContain('# keep'); expect(yaml).toContain('custom.sh'); expect(yaml).not.toContain('cli.js');
  });

  it('does not overwrite malformed configuration or a foreign native script', async () => {
    const path = join(home, '.qwen/settings.json'); await mkdir(join(home, '.qwen')); await writeFile(path,'{"hooks":');
    await expect(installHook('qwen',home)).rejects.toThrow('invalid JSON'); expect(await readFile(path,'utf8')).toBe('{"hooks":');
    await mkdir(join(home,'.cline/hooks'),{ recursive:true }); await writeFile(join(home,'.cline/hooks/PreToolUse'),'#!/bin/sh\necho foreign\n');
    await expect(installHook('cline',home)).rejects.toThrow('not managed');
  });

  it('keeps OpenHands repository scoped and honors config-root overrides', async () => {
    await expect(installHook('openhands',home)).rejects.toThrow('project-scoped');
    process.env.CODEX_HOME = join(home,'relocated');
    expect((await installHook('codex',home)).path).toBe(join(home,'relocated/hooks.json'));
  });
});

describe('native payloads and action details', () => {
  it.each([
    ['windsurf','pre_read_code',{ trajectory_id:'s', tool_info:{ file_path:'/repo/a.ts' } },'file.read','proposed'],
    ['windsurf','post_run_command',{ trajectory_id:'s', tool_info:{ command:'pwd' } },'command.exec','completed hook'],
    ['antigravity','PreToolUse',{ toolCall:{ name:'read_file', args:{ path:'/repo/a.ts' } } },'file.read','proposed'],
    ['cline','PostToolUse',{ taskId:'s', postToolUse:{ tool:'write_to_file', parameters:{ path:'/repo/a.ts', content:'hello' } } },'file.write','completed hook'],
    ['copilot-cli','postToolUseFailure',{ sessionId:'s', toolName:'bash', toolArgs:'{"command":"false"}', error:'exit 1' },'command.exec','failed hook'],
    ['gemini','AfterTool',{ tool_name:'run_shell_command', tool_input:{ command:'pwd' } },'command.exec','completed hook'],
    ['hermes','post_tool_call',{ tool_name:'terminal', tool_input:{ command:'pwd' } },'command.exec','completed hook'],
    ['kiro','PreToolUse',{ tool_name:'list_directory', tool_input:{ path:'/repo/src' } },'directory.read','proposed'],
  ] as const)('%s %s preserves the action and its actual lifecycle', (agent,event,raw,type,phase) => {
    const normalized = normalize(adaptHookPayload(agent,raw,event));
    expect(normalized.type).toBe(type); expect(normalized.phase).toBe(phase); expect(normalized.activity?.hookEvent).toBe(event);
  });

  it('records search terms, visited URL requests, and the exact supplied edit changes', () => {
    const search = normalize(adaptHookPayload('codex',{ tool_name:'web.run', tool_input:{ search_query:[{ q:'typescript file hooks' }], open:[{ ref_id:'https://example.com/docs' }] } },'PreToolUse'));
    expect(search.activity?.searchTerms).toContain('typescript file hooks'); expect(search.activity?.urls).toContain('https://example.com/docs');
    const edit = normalize(adaptHookPayload('muse',{ tool_name:'edit_file', tool_input:{ path:'/repo/a.ts', old_string:'before', new_string:'after' } },'PostToolUse'));
    expect(edit.activity?.paths).toEqual(['/repo/a.ts']); expect(edit.activity?.edits).toEqual({ old:'before', new:'after' }); expect(edit.lines).toEqual({ added:1, removed:1 });
  });

  it('preserves Pi replacement text and OpenCode patch targets', () => {
    const pi = normalize(adaptHookPayload('pi', { tool_name:'edit', tool_input:{ path:'/repo/a', oldText:'before', newText:'' } }, 'tool_call'));
    expect(pi.activity?.edits).toMatchObject({ old:'before', new:'' }); expect(pi.lines).toEqual({ added:0, removed:1 });
    const patch = normalize(adaptHookPayload('opencode',{ tool_name:'apply_patch', tool_input:{ patchText:'*** Begin Patch\n*** Update File: /repo/a\n@@\n-before\n+after\n*** End Patch' } },'tool.execute.before'));
    expect(patch.activity?.paths).toContain('/repo/a'); expect(patch.lines).toEqual({ added:1,removed:1 });
  });

  it('masks credentials in structured fields and marks large payloads as truncated', () => {
    const event = normalize(adaptHookPayload('qwen',{ tool_name:'mcp__browser__navigate', tool_input:{ url:'https://example.com', password:'plainsecret', headers:{ authorization:'plaintextsecret' }, content:'x'.repeat(20000) } },'PreToolUse'));
    expect(JSON.stringify(event.activity)).not.toContain('plainsecret'); expect(JSON.stringify(event.activity)).not.toContain('plaintextsecret');
    expect(event.activity?.truncated).toBe(true); expect(event.mcp).toMatchObject({ server:'browser', tool:'navigate' });
  });

  it('does not collapse different agents or sessions that reuse the same tool ID', () => {
    const raw = { hook_event_name:'PreToolUse', tool_name:'Read', tool_use_id:'call-1', tool_input:{ path:'/repo/a' } };
    const one = normalize({ ...raw,source_agent:'kiro',session_id:'one' });
    const two = normalize({ ...raw,source_agent:'kiro',session_id:'two' });
    expect(one.id).not.toBe(two.id);
  });
});

describe('generated plugin callbacks', () => {
  it.each(['opencode','kilo','pi','amp'])('%s passes native callbacks into Beam with their event and input', async agent => {
    const sent: Array<{ args:string[]; payload:any }> = [];
    const childProcess = {
      spawn: (_node:string,args:string[]) => ({ on:()=>{}, unref:()=>{}, stdin:{ on:()=>{}, end:(body:string)=>sent.push({ args,payload:JSON.parse(body) }) } }),
      spawnSync: (_node:string,args:string[],opts:any) => { sent.push({ args,payload:JSON.parse(opts.input) }); return { status:0, stdout:'{}' }; },
    };
    const code = ts.transpileModule(pluginSource({ agentId:agent,nodePath:'/node',cliPath:'/beam/cli.js' }), { compilerOptions:{ module:ts.ModuleKind.CommonJS, target:ts.ScriptTarget.ES2022 } }).outputText;
    const exports:any = {};
    runInNewContext(code,{ exports,require:(id:string) => { expect(id).toBe('node:child_process'); return childProcess; } });
    if (agent === 'opencode' || agent === 'kilo') {
      const handlers = await (agent === 'kilo' ? exports.default.server : exports.BeamPlugin)({ directory:'/repo' });
      await handlers['tool.execute.before']({ tool:'read',callID:'1',sessionID:'s' },{ args:{ path:'/repo/a' } });
      await handlers['tool.execute.after']({ tool:'read',callID:'1',sessionID:'s',args:{ path:'/repo/a' } },{ output:'contents' });
    } else {
      const handlers = new Map<string,Function>(); const api = { on:(name:string,fn:Function)=>handlers.set(name,fn), system:{},helpers:{} };
      exports.default(api);
      if (agent === 'pi') {
        const ctx = { cwd:'/repo',sessionManager:{ getSessionId:()=> 's' } };
        await handlers.get('tool_call')!({ toolName:'read',input:{ path:'/repo/a' },toolCallId:'1' },ctx);
        await handlers.get('tool_result')!({ toolName:'read',input:{ path:'/repo/a' },toolCallId:'1',content:'contents' },ctx);
      } else {
        const event = { thread:{ id:'s' },tool:'read',input:{ path:'/repo/a' },toolUseID:'1',output:'contents' };
        await handlers.get('tool.call')!(event); await handlers.get('tool.result')!(event);
      }
    }
    expect(sent).toHaveLength(2);
    expect(sent[0].payload.tool_input.path).toBe('/repo/a'); expect(sent[1].payload.tool_response).toBeDefined();
    expect(sent[0].args).toContain('--event'); expect(sent[1].payload.hook_event_name).not.toBe(sent[0].payload.hook_event_name);
  });
});

describe('capture transport', () => {
  const stdin = (raw:unknown) => Object.defineProperty(process,'stdin',{ value:Readable.from([JSON.stringify(raw)]),configurable:true });
  it('ingests allowed prompts, edits and failures, and applies no pre-action gate to passive callbacks', async () => {
    const collector = await createCollector({ directory:join(home,'collector'),token:'test-token' });
    global.fetch = (async (url: any, init:any) => collector.fetch(new Request(String(url),init))) as typeof fetch;
    await writeFile(join(home,'policy.json'),JSON.stringify({ version:1,rules:{ mode:'enforce',blockedTools:['Edit'],disabledAgents:[] } }));
    const stdout = jest.spyOn(process.stdout,'write').mockImplementation(()=>true);
    stdin({ prompt:'Please edit a file; password=supersecret',session_id:'s' }); await captureHook('pi',home,'before_agent_start');
    stdin({ tool_name:'Edit',session_id:'s',tool_input:{ file_path:'/repo/a',old_string:'a',new_string:'b' } }); await captureHook('claude-code',home,'PostToolUse');
    stdin({ tool_name:'Bash',session_id:'s',tool_input:{ command:'false' },error:'exit 1' }); await captureHook('copilot-cli',home,'postToolUseFailure');
    expect(process.exitCode).toBe(0); expect(stdout).not.toHaveBeenCalled();
    expect(collector.store.events).toHaveLength(3);
    expect(JSON.stringify(collector.store.events)).not.toContain('supersecret');
    expect(collector.store.events.find(e=>e.type==='prompt.submit')?.session).toBe('s');
    expect(collector.store.events.some(e=>e.phase==='failed hook')).toBe(true);
  });

  it('queues offline redacted captures and replays them without deleting failed deliveries', async () => {
    global.fetch = (async()=> { throw new Error('offline'); }) as typeof fetch;
    stdin({ tool_name:'Read', tool_input:{ path:'/repo/a' },session_id:'s' }); await captureHook('kiro',home,'PreToolUse');
    expect((await readdir(join(home,'hook-spool'))).filter(n=>n.endsWith('.json'))).toHaveLength(1);
    await drainHookSpool(home,async()=>{ throw new Error('storage unavailable'); });
    const records:any[] = [];
    expect(await drainHookSpool(home,async events=>{ records.push(...events); })).toBe(1);
    expect(records[0].tool_input.path).toBe('/repo/a'); expect(await drainHookSpool(home,async()=>{})).toBe(0);
  });
});
