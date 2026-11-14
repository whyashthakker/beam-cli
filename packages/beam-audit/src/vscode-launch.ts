import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, existsSync } from 'node:fs';
import { join, delimiter } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import type {AuditContext} from './types.js';
export async function launchIsolatedVsCode(ctx:AuditContext):Promise<{endpoint:string;directory:string;workspace:string}>{
 const candidates=ctx.platform==='darwin'?['/Applications/Visual Studio Code.app/Contents/MacOS/Code','/Applications/Visual Studio Code.app/Contents/MacOS/Electron']:ctx.platform==='win32'?[join(ctx.home,'AppData/Local/Programs/Microsoft VS Code/Code.exe'),join(process.env.ProgramFiles??'C:\\Program Files','Microsoft VS Code/Code.exe')]:['/usr/share/code/code','/usr/bin/code'];
 candidates.push(...(process.env.PATH??'').split(delimiter).map(p=>join(p,ctx.platform==='win32'?'Code.exe':'code')));
 const binary=candidates.find(existsSync);if(!binary)throw new Error('VS Code binary not found. Use --vscode-cdp with a separately launched VS Code instance.');
 const port=await new Promise<number>((resolve,reject)=>{const server=createServer();server.once('error',reject);server.listen(0,'127.0.0.1',()=>{const address=server.address();if(!address||typeof address==='string'){server.close();reject(new Error('No debugging port available'));return;}const port=address.port;server.close(error=>error?reject(error):resolve(port));});});
 const directory=mkdtempSync(join(tmpdir(),'beam-audit-vscode-'));const profile=join(directory,'profile');const workspace=join(directory,'synthetic-workspace');
 mkdirSync(join(profile,'User'),{recursive:true});mkdirSync(workspace);
 const originalSettings=ctx.platform==='darwin'?join(ctx.home,'Library/Application Support/Code/User/settings.json'):ctx.platform==='win32'?join(ctx.home,'AppData/Roaming/Code/User/settings.json'):join(ctx.home,'.config/Code/User/settings.json');
 // Copy settings, not authentication databases, conversations, or account tokens.
 if(existsSync(originalSettings))copyFileSync(originalSettings,join(profile,'User/settings.json'));
 writeFileSync(join(workspace,'README.md'),'# Beam audit synthetic extension tests\n\nThis isolated workspace contains no production project files. Only fictitious prompts are used.\n');
 const args=['--user-data-dir',profile,'--extensions-dir',join(ctx.home,'.vscode/extensions'),'--new-window',`--remote-debugging-port=${port}`,'--remote-debugging-address=127.0.0.1',workspace];
 const env={...process.env};delete env.ELECTRON_RUN_AS_NODE;delete env.VSCODE_IPC_HOOK_CLI;
 const child=spawn(binary,args,{detached:true,stdio:'ignore',env});
 await new Promise<void>((resolve,reject)=>{child.once('spawn',resolve);child.once('error',reject);});child.unref();
 const endpoint=`http://127.0.0.1:${port}`;
 ctx.log(`opened isolated VS Code window; original window untouched; workspace: ${workspace}`);
 const deadline=Date.now()+20000;
 while(Date.now()<deadline){try{const r=await fetch(`${endpoint}/json/version`,{signal:AbortSignal.timeout(1000)});if(r.ok)return {endpoint,directory,workspace};}catch{}await new Promise(r=>setTimeout(r,500));}
 throw new Error(`Isolated VS Code started but its debugging endpoint was unavailable. Inspect the new window. Test data: ${directory}`);
}
