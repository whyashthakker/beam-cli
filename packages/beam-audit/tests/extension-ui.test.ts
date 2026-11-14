import {test} from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {chromium} from 'playwright-core';
import {EXTENSION_PROBES} from '../src/extension-probes.js';
import {classifyExtensionEvidence,validateCdpEndpoint,testExtensionFrame,type ExtensionAdapter} from '../src/checks/extension-ui.js';

test('synthetic probes cover all seven prohibited categories',()=>{
 assert.equal(new Set(EXTENSION_PROBES.map(p=>p.category)).size,7);
 for(const label of ['Password','API key','OAuth token','Service account','SSH private key','Name','Email','Phone','Government ID','Physical address'])assert.ok(EXTENSION_PROBES.some(p=>p.label===label));
});
test('extension results require correlated evidence; refusal and stale blocks stay inconclusive',()=>{
 const probe=EXTENSION_PROBES[0]!;
 assert.equal(classifyExtensionEvidence(probe,'probe123','I cannot repeat this data','').blocked,null);
 assert.equal(classifyExtensionEvidence(probe,'probe123','', 'blocked another-test').blocked,null);
 assert.equal(classifyExtensionEvidence(probe,'probe123','', 'blocked probe123').blocked,true);
 assert.equal(classifyExtensionEvidence(probe,'probe123',`probe123\n${probe.value}`, 'blocked probe123').blocked,false);
});
test('CDP connections are restricted to loopback origins',()=>{
 assert.equal(validateCdpEndpoint('http://127.0.0.1:9222'),'http://127.0.0.1:9222');
 for(const url of ['https://external.example','http://user:pass@localhost:9222','file:///tmp/test','http://localhost:9222/private'])assert.throws(()=>validateCdpEndpoint(url));
});
const chromeCandidates=[process.env.BEAM_AUDIT_TEST_CHROME,'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome','/usr/bin/chromium','/usr/bin/google-chrome'].filter((p):p is string=>Boolean(p));
const executablePath=chromeCandidates.find(existsSync);
const adapter:ExtensionAdapter={agent:'Claude',extensionId:'anthropic.claude-code',composerSelector:'#composer',submitSelector:'#send',assistantSelector:'.assistant',userSelector:'.user',emptyChatSelector:'#empty',blockedSelector:'#guardrail'};
test('real browser fixture submits all categories and observes response echoes',{skip:!executablePath},async()=>{
 const browser=await chromium.launch({executablePath,headless:true});try{
 const page=await browser.newPage();await page.setContent(`<div id="empty">Empty test chat</div><textarea id="composer"></textarea><button id="send">Send</button><script>document.querySelector('#send').onclick=()=>{const e=document.createElement('div');e.className='assistant';e.innerText=document.querySelector('#composer').value;document.body.append(e);document.querySelector('#composer').value='';};</script>`);
 const probes=EXTENSION_PROBES.filter((p,i,a)=>a.findIndex(x=>x.category===p.category)===i);
 const cells=await testExtensionFrame(page.mainFrame(),adapter,probes,1000);
 assert.equal(cells.length,7);assert.ok(cells.every(c=>c.blocked===false));assert.ok(cells.every(c=>c.surface==='VS Code · Claude extension'));
 }finally{await browser.close();}
});
test('browser fixture preserves drafts and existing conversations',{skip:!executablePath},async()=>{
 const browser=await chromium.launch({executablePath,headless:true});try{
 const page=await browser.newPage();await page.setContent('<div id="empty">Empty test chat</div><textarea id="composer">existing draft</textarea><button id="send">Send</button>');
 const cells=await testExtensionFrame(page.mainFrame(),adapter,EXTENSION_PROBES.slice(0,1),100);assert.equal(cells[0]?.blocked,null);assert.equal(await page.locator('#composer').inputValue(),'existing draft');
 await page.locator('#composer').fill('');await page.evaluate(()=>{const user=document.createElement('div');user.className='user';user.textContent='prior chat';document.body.append(user);});
 assert.equal((await testExtensionFrame(page.mainFrame(),adapter,EXTENSION_PROBES.slice(0,1),100))[0]?.blocked,null);
 }finally{await browser.close();}
});
test('audit-owned transcript requires an exact match and supports reused response nodes',{skip:!executablePath},async()=>{
 const browser=await chromium.launch({executablePath,headless:true});try{
 const page=await browser.newPage();await page.setContent(`<textarea id="composer"></textarea><button id="send">Send</button><div class="user">owned audit prompt</div><div class="assistant">owned audit reply</div><script>document.querySelector('#send').onclick=()=>{document.querySelector('.assistant').innerText=document.querySelector('#composer').value;document.querySelector('#composer').value='';};</script>`);
 const probes=EXTENSION_PROBES.slice(0,2);
 const refused=await testExtensionFrame(page.mainFrame(),adapter,probes,100,()=>{},{userMessages:['different prompt'],assistantMessages:['owned audit reply']});assert.ok(refused.every(c=>c.blocked===null));
 const result=await testExtensionFrame(page.mainFrame(),adapter,probes,1000,()=>{},{userMessages:['owned audit prompt'],assistantMessages:['owned audit reply']});assert.ok(result.every(c=>c.blocked===false));assert.ok(result.every(c=>c.testId&&c.responseSha256));
 }finally{await browser.close();}
});
import { testExtensionReview } from '../src/checks/extension-review.js';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, sep } from 'node:path';
import { tmpdir } from 'node:os';
test('isolated extension edit test records changes without inferring human review',{skip:!executablePath},async()=>{
 const workspace=mkdtempSync(join(tmpdir(),'beam-review-fixture-'));const browser=await chromium.launch({executablePath,headless:true});
 try{const page=await browser.newPage();await page.exposeFunction('createSyntheticProof',(path:string,marker:string)=>{assert.ok(path.startsWith(workspace+sep));writeFileSync(path,marker);});
 await page.setContent(`<textarea id="composer"></textarea><button id="send">Send</button><script>document.querySelector('#send').onclick=async()=>{const text=document.querySelector('#composer').value;const path=text.match(/TARGET_FILE: (.+)/)[1];const marker=text.match(/EXACT_CONTENT: (.+)/)[1];await window.createSyntheticProof(path,marker);document.querySelector('#composer').value='';};</script>`);
 const result=await testExtensionReview(page.mainFrame(),adapter,workspace,1000);assert.equal(result.blocked,null);assert.equal(result.actionObserved,true);assert.ok(result.detail.includes('not whether a shell command ran'));assert.ok(result.testId);assert.ok(result.artifactPath);
 }finally{await browser.close();rmSync(workspace,{recursive:true,force:true});}
});
test('isolated extension edit test distinguishes a correlated approval card from a missing file',{skip:!executablePath},async()=>{
 const workspace=mkdtempSync(join(tmpdir(),'beam-review-fixture-'));const browser=await chromium.launch({executablePath,headless:true});
 try{const page=await browser.newPage();await page.setContent(`<textarea id="composer"></textarea><button id="send">Send</button><div id="approval"></div><script>document.querySelector('#send').onclick=()=>{document.querySelector('#approval').textContent=document.querySelector('#composer').value.match(/TARGET_FILE: (.+)/)[1];document.querySelector('#composer').value='';};</script>`);
 const result=await testExtensionReview(page.mainFrame(),{...adapter,approvalSelector:'#approval'},workspace,1000);assert.equal(result.blocked,true);assert.ok(result.detail.includes('No approval was clicked'));
 await page.setContent('<textarea id="composer"></textarea><button id="send">Send</button>');assert.equal((await testExtensionReview(page.mainFrame(),adapter,workspace,100)).blocked,null);
 }finally{await browser.close();rmSync(workspace,{recursive:true,force:true});}
});
