import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { evaluatePolicy, loadPolicy } from '../src/policy.js';
import { agentPostureChecks } from '../src/checks/agent-posture.js';
import { repositoryEnforcementChecks } from '../src/checks/repository-enforcement.js';
const fixture = () => mkdtempSync(join(tmpdir(), 'beam-audit-test-'));
test('required controls fail closed for missing and skipped evidence', () => {
 const result = evaluatePolicy([{ id: 'x', title: 'x', policySection: 'test', status: 'skip', detail: '' }], { version: 1, requiredChecks: ['x', 'missing'] });
 assert.ok(result.every(c => c.status === 'fail'));
});
test('policy validation rejects malformed evidence and supports agent restrictions', () => {
 const dir = fixture(); try {
 const file = join(dir, 'policy.json'); writeFileSync(file, JSON.stringify({version: 1, requiredChecks: [], evidence: {x: {expires: 'invalid'}}})); assert.throws(() => loadPolicy(file));
 const result = evaluatePolicy([{ id: 'inventory-Codex', title: '', policySection: '', status: 'warn', detail: '' }], {version: 1, requiredChecks: [], allowedAgents: []}); assert.equal(result[0]?.status, 'fail');
 } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('agent inspection flags bypasses without disclosing configuration secrets', () => {
 const dir = fixture(); try { mkdirSync(join(dir, '.codex')); writeFileSync(join(dir, '.codex/config.toml'), 'sandbox_mode = "danger-full-access"\napi_key = "private-test-value"');
 const result = agentPostureChecks({home: dir, repos: [], roots: [dir], platform: process.platform, log: () => {}});
 assert.ok(result.some(c => c.id.startsWith('permissions-') && c.status === 'warn')); assert.ok(!JSON.stringify(result).includes('private-test-value'));
 } finally { rmSync(dir, {recursive: true, force: true}); }
});
test('effective hooks and committed credential patterns are inspected', () => {
 const dir = fixture(); const git = (...args: string[]) => { const r = spawnSync('git', ['-C', dir, ...args], {encoding: 'utf8'}); assert.equal(r.status, 0, r.stderr); };
 try { git('init'); git('config', 'user.name', 'Audit Test'); git('config', 'user.email', 'audit@example.test');
 writeFileSync(join(dir, 'leak.txt'), 'token=ghp_' + 'A'.repeat(36)); git('add', '.'); git('-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'fixture');
 const hook = join(dir, '.git/hooks/pre-commit'); writeFileSync(hook, '#!/bin/sh\ngitleaks protect\n'); chmodSync(hook, 0o755);
 const result = repositoryEnforcementChecks({home: dir, repos: [dir], roots: [dir], platform: process.platform, log: () => {}});
 assert.equal(result.find(c => c.id.startsWith('effective-hook-'))?.status, 'warn'); assert.equal(result.find(c => c.id.startsWith('history-'))?.status, 'fail'); assert.ok(!JSON.stringify(result).includes('A'.repeat(36)));
 } finally { rmSync(dir, {recursive: true, force: true}); }
});

import { discoverReposDetailed } from '../src/discover-repos.js';
import { mcpChecks } from '../src/checks/mcp.js';
import { loggingChecks } from '../src/checks/logging.js';
import { vulnerabilityChecks } from '../src/checks/vulnerabilities.js';
import { platformSecurityChecks } from '../src/checks/platform-security.js';
import { categorySummary, CATEGORIES } from '../src/categories.js';
import { renderHtmlReport } from '../src/report-html.js';
const context=(home:string)=>({home,repos:[] as string[],roots:[home],platform:process.platform,log:()=>{}});
test('discovery includes hidden repositories and reports depth/cap/inaccessible roots',()=>{
 const dir=fixture();try{mkdirSync(join(dir,'.hidden/repo/.git'),{recursive:true});mkdirSync(join(dir,'nested/.git'),{recursive:true});
 const full=discoverReposDetailed([dir]);assert.equal(full.repos.length,2);
 assert.ok(discoverReposDetailed([dir],{maxDepth:1}).depthLimited>0);
 assert.ok(discoverReposDetailed([dir],{maxRepos:1}).capped);
 assert.equal(discoverReposDetailed([join(dir,'missing')]).inaccessible.length,1);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('Codex TOML and JSONC MCP declarations are inspected without leaking credentials',()=>{
 const dir=fixture();try{mkdirSync(join(dir,'.codex'));writeFileSync(join(dir,'.codex/config.toml'),'[mcp_servers.demo]\nurl = "http://localhost:1234"\n[mcp_servers.demo.http_headers]\nAuthorization = "private-test-secret"');
 mkdirSync(join(dir,'.cursor'));writeFileSync(join(dir,'.cursor/mcp.json'),'{ // comment\n "mcpServers": {"local": {"command":"npx",},},}');
 const checks=mcpChecks(context(dir));assert.ok(checks.some(c=>c.title==='MCP server: demo'&&c.status==='fail'));assert.ok(checks.some(c=>c.title==='MCP server: local'));assert.ok(!JSON.stringify(checks).includes('private-test-secret'));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('log samples identify fields while omitting event contents',()=>{
 const dir=fixture();try{mkdirSync(join(dir,'.codex/sessions'),{recursive:true});writeFileSync(join(dir,'.codex/sessions/session.jsonl'),JSON.stringify({timestamp:'2026-01-01',session_id:'x',type:'tool_call',payload:'private-log-content'})+'\n');const checks=loggingChecks(context(dir));assert.ok(checks.some(c=>c.detail.includes('timestamp, session, tool event')));assert.ok(!JSON.stringify(checks).includes('private-log-content'));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('OSV matching, failure, and offline behavior remain distinct',async()=>{
 const dir=fixture();try{writeFileSync(join(dir,'package-lock.json'),JSON.stringify({packages:{'node_modules/example':{version:'1.2.3'}}}));const ctx={...context(dir),repos:[dir],online:true};
 const found=await vulnerabilityChecks(ctx,async()=>new Response(JSON.stringify({results:[{vulns:[{id:'TEST-1'}]}]})));
 assert.equal(found[0]?.status,'fail');assert.ok(found[0]?.evidence?.[0]?.includes('TEST-1'));
 const failure=await vulnerabilityChecks(ctx,async()=>{throw new Error('offline');});assert.equal(failure[0]?.status,'warn');
 let calls=0;const offline=await vulnerabilityChecks({...ctx,online:false},async()=>{calls++;return new Response();});assert.equal(calls,0);assert.equal(offline[0]?.status,'skip');
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('Windows checks handle missing commands and enabled firewall without running host commands',()=>{
 const ctx={...context('/fixture'),platform:'win32' as const};
 assert.ok(platformSecurityChecks(ctx,()=>({status:null,stdout:''})).every(c=>c.status==='skip'));
 const checks=platformSecurityChecks(ctx,(_cmd,args)=>({status:0,stdout:args.join(' ').includes('Get-NetFirewallProfile')?'[true,true,true]':'Manual'}));
 assert.equal(checks.find(c=>c.id==='windows-firewall')?.status,'pass');
});
test('HTML overview has all eleven categories, escapes content, and labels missing evidence',()=>{
 const checks=[{id:'x',category:'Logging and incident traceability' as const,policySection:'8.2',title:'<script>bad</script>',status:'skip' as const,detail:'Missing evidence'}];
 assert.equal(categorySummary(checks).length,11);const html=renderHtmlReport(checks,[],{roots:['/fixture'],repoCount:0,generatedAt:'test',liveTestsRun:false});
 for(const name of CATEGORIES)assert.ok(html.includes(name));assert.ok(!html.includes('<script>bad</script>'));assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes('Live agent tests were skipped'));
});
import {remoteEnforcementChecks} from '../src/checks/remote-enforcement.js';
import {releaseChecks} from '../src/checks/vulnerabilities.js';
test('GitHub protection needs reviews, status checks and admin enforcement',()=>{
 const ctx={...context('/fixture'),repos:['/fixture'],online:true};
 const checks=remoteEnforcementChecks(ctx,(command,args)=>({status:0,stdout:command==='git'?'git@github.com:example/project.git':JSON.stringify(args[1]?.endsWith('/protection')?{required_status_checks:{contexts:['security']},required_pull_request_reviews:{required_approving_review_count:1},enforce_admins:{enabled:false}}:{default_branch:'main'})}));
 assert.equal(checks[0]?.status,'fail');
 const missing=remoteEnforcementChecks(ctx,()=>({status:1,stdout:''}));assert.equal(missing[0]?.status,'skip');
 let calls=0;remoteEnforcementChecks({...ctx,online:false},()=>{calls++;return {status:0,stdout:''};});assert.equal(calls,0);
});
test('release comparison warns about drift and handles unavailable registry evidence',async()=>{
 const dir=fixture();try{const path=join(dir,'AppData/Roaming/npm/node_modules/@openai/codex');mkdirSync(path,{recursive:true});writeFileSync(join(path,'package.json'),JSON.stringify({name:'@openai/codex',version:'1.0.0'}));const ctx={...context(dir),online:true};
 assert.equal((await releaseChecks(ctx,async()=>new Response(JSON.stringify({version:'1.0.1'}))))[0]?.status,'warn');
 assert.equal((await releaseChecks(ctx,async()=>{throw new Error('offline');}))[0]?.status,'skip');
 }finally{rmSync(dir,{recursive:true,force:true});}
});
import {looseFileChecks} from '../src/checks/loose-files.js';
test('non-repository scan deduplicates overlapping roots and emits completion progress',async()=>{
 const dir=fixture();try{mkdirSync(join(dir,'child'));writeFileSync(join(dir,'child','config.json'),'{"test":true}');const messages:string[]=[];
 const checks=await looseFileChecks({...context(dir),roots:[dir,join(dir,'child')],log:m=>messages.push(m)});
 assert.ok(checks[0]?.detail.startsWith('1 supported text files inspected'));
 assert.ok(messages.some(m=>m.startsWith('non-repository scan finished:')));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('non-repository entry and time budgets stop traversal with partial coverage',async()=>{
 const dir=fixture();try{for(let i=0;i<20;i++)writeFileSync(join(dir,`${i}.bin`),'x');
 const capped=await looseFileChecks(context(dir),{maxEntries:5});assert.equal(capped[1]?.status,'warn');assert.ok(capped[0]?.detail.includes('entry limit'));
 const expired=await looseFileChecks(context(dir),{maxMilliseconds:0});assert.equal(expired[1]?.status,'warn');assert.ok(expired[0]?.detail.includes('time budget'));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
