import { expect, it, afterEach } from '@jest/globals';
import { normalize } from '../src/core.js';
import { classifyActionContext } from '../src/action-context.js';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
const classify=(command:string)=>classifyActionContext('Bash',{},'/work/beam',command,s=>s);
const dirs:string[]=[];afterEach(()=>dirs.splice(0).forEach(d=>rmSync(d,{recursive:true,force:true})));
it('distinguishes file reads, key-filtered file output, named environment and whole environment',()=>{
 expect(classify('cat .env.local').actions[0]).toMatchObject({operation:'file-read',target:'.env.local',resolvedPath:'/work/beam/.env.local',scope:'file-content'});
 expect(classify('grep "^AWS_REGION=" .env.local').actions[0]).toMatchObject({operation:'file-search',variableNames:['AWS_REGION'],scope:'matching-output'});
 expect(classify('printenv AWS_SECRET_ACCESS_KEY').actions[0]).toMatchObject({operation:'environment-lookup',variableNames:['AWS_SECRET_ACCESS_KEY']});
 expect(classify('env').actions[0]).toMatchObject({operation:'environment-dump',scope:'all-exported'});
});
it('never describes source-code searches or test strings as process environment reads',()=>{
 expect(classify('grep "process.env" src/config.ts').actions[0]).toMatchObject({operation:'source-search',target:'src/config.ts'});
 expect(classify('echo "printenv AWS_SECRET_ACCESS_KEY"').actions).toEqual([]);
 expect(classify("cat > test.ts <<'EOF'\nprintenv AWS_SECRET_ACCESS_KEY\nEOF").actions.every(a=>a.operation!=='environment-lookup')).toBe(true);
});
it('records file search scope without claiming a prefix is a single key',()=>{
 expect(classify('grep "^AWS" .env.local').actions[0].variableNames).toBeUndefined();
 expect(classify('printenv --help').actions[0].operation).toBe('command');
});
it('resolves literal cd paths but never invents expanded variable paths',()=>{
 expect(classify('cd packages/api; cat .env').actions[0].resolvedPath).toBe('/work/beam/packages/api/.env');
 expect(classify('cd "$PROJECT"; cat .env').actions[0].resolvedPath).toBeUndefined();
});
it('captures repository identity from small local Git metadata without executing git',()=>{
 const root=mkdtempSync(join(tmpdir(),'beam-action-context-'));dirs.push(root);
 mkdirSync(join(root,'.git','refs','heads'),{recursive:true});mkdirSync(join(root,'src'));
 writeFileSync(join(root,'.git','HEAD'),'ref: refs/heads/main\n');writeFileSync(join(root,'.git','refs','heads','main'),'a'.repeat(40));
 expect(classifyActionContext('Read',{file_path:'.env.local'},join(root,'src'),'',s=>s).repository).toMatchObject({root,name:root.split('/').pop(),branch:'main',commit:'a'.repeat(40)});
});
it('captures requested line scope from native tool arguments',()=>{
 const context=classifyActionContext('Read',{file_path:'settings.ts',offset:10,limit:5},'/work/beam','',s=>s);
 expect(context.actions[0]).toMatchObject({evidence:'tool-arguments',scope:'requested-lines',lineStart:10,lineEnd:14});
});
it('normalization emits sanitized context without secret values',()=>{
 const event=normalize({tool_name:'Bash',cwd:'/work/beam',tool_input:{command:'API_KEY=real-private-value printenv AWS_REGION'},hook_event_name:'PreToolUse'});
 expect(JSON.stringify(event.actionContext)).not.toContain('real-private-value');
 expect(event.actionContext?.actions[0]).toMatchObject({operation:'environment-lookup',variableNames:['AWS_REGION']});
});
it('bounded operations explicitly mark omitted context',()=>{
 const context=classify(Array.from({length:20},(_,i)=>`cat file${i}`).join(';'));
 expect(context.actions).toHaveLength(12);expect(context.truncated).toBe(true);
});
it('recognizes explicit interpreter lookups without treating quoted test fixtures as reads',()=>{
 expect(classify("node -p 'process.env.AWS_SECRET_ACCESS_KEY'").actions[0]).toMatchObject({operation:'environment-lookup',variableNames:['AWS_SECRET_ACCESS_KEY']});
 expect(classify('node -e \'console.log(process.env.AWS_REGION)\'').actions[0]).toMatchObject({operation:'environment-lookup',variableNames:['AWS_REGION']});
 expect(classify('python3 -c \'import os; print(os.getenv("API_TOKEN"))\'').actions[0]).toMatchObject({operation:'environment-lookup',variableNames:['API_TOKEN']});
 expect(classify('node -e \'console.log("process.env.API_TOKEN")\'').actions[0].operation).toBe('command');
});
