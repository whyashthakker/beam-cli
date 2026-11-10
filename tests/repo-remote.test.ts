import {expect,it} from '@jest/globals';
import {mkdtempSync,mkdirSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseRemoteUrl,registriesIn,readOriginRemote} from '../src/repo-remote.js';
import {classifyActionContext} from '../src/action-context.js';
import {redact} from '../src/core.js';

it.each([
  ['GitHub ssh','git@github.com:acme/web.git','github','github.com','acme/web','ssh','https://github.com/acme/web'],
  ['GitHub https','https://github.com/acme/web.git','github','github.com','acme/web','https','https://github.com/acme/web'],
  ['GitHub https, trailing slash','https://github.com/acme/web/','github','github.com','acme/web','https','https://github.com/acme/web'],
  ['GitHub Enterprise','git@github.acme-corp.com:platform/api.git','github','github.acme-corp.com','platform/api','ssh','https://github.acme-corp.com/platform/api'],
  ['GitLab nested groups','git@gitlab.com:acme/platform/tools/cli.git','gitlab','gitlab.com','acme/platform/tools/cli','ssh','https://gitlab.com/acme/platform/tools/cli'],
  ['self-managed GitLab on a custom port','ssh://git@gitlab.internal.acme.io:2222/team/app.git','gitlab','gitlab.internal.acme.io','team/app','ssh','https://gitlab.internal.acme.io/team/app'],
  ['Bitbucket','git@bitbucket.org:acme/web.git','bitbucket','bitbucket.org','acme/web','ssh','https://bitbucket.org/acme/web'],
  ['Azure DevOps https','https://acme@dev.azure.com/acme/Platform/_git/web','azure-devops','dev.azure.com','acme/Platform/web','https','https://dev.azure.com/acme/Platform/_git/web'],
  ['Azure DevOps ssh','git@ssh.dev.azure.com:v3/acme/Platform/web','azure-devops','ssh.dev.azure.com','acme/Platform/web','ssh','https://dev.azure.com/acme/Platform/_git/web'],
  ['Azure DevOps legacy visualstudio.com','https://acme.visualstudio.com/Platform/_git/web','azure-devops','acme.visualstudio.com','acme/Platform/web','https','https://dev.azure.com/acme/Platform/_git/web'],
  ['AWS CodeCommit https','https://git-codecommit.us-east-1.amazonaws.com/v1/repos/payments','aws-codecommit','git-codecommit.us-east-1.amazonaws.com','payments','https','https://us-east-1.console.aws.amazon.com/codesuite/codecommit/repositories/payments/browse?region=us-east-1'],
  ['AWS CodeCommit remote helper','codecommit::eu-west-1://payments','aws-codecommit','git-codecommit.eu-west-1.amazonaws.com','payments','codecommit','https://eu-west-1.console.aws.amazon.com/codesuite/codecommit/repositories/payments/browse?region=eu-west-1'],
  ['Codeberg','https://codeberg.org/acme/web.git','codeberg','codeberg.org','acme/web','https','https://codeberg.org/acme/web'],
  ['Hugging Face','https://huggingface.co/acme/model','huggingface','huggingface.co','acme/model','https','https://huggingface.co/acme/model'],
  ['unknown self-hosted git server','git@git.acme.dev:infra/deploy.git','other','git.acme.dev','infra/deploy','ssh','https://git.acme.dev/infra/deploy'],
])('parses %s',(_n,input,provider,host,path,protocol,url)=>{
  expect(parseRemoteUrl(input)).toMatchObject({provider,host,path,protocol,url});
});

it('never keeps credentials from a URL',()=>{
  const r=parseRemoteUrl('https://deploy-bot:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/web.git')!;
  expect(JSON.stringify(r)).not.toMatch(/ghp_|deploy-bot|:.*@/);
  expect(r).toMatchObject({provider:'github',path:'acme/web'});
  const q=parseRemoteUrl('https://oauth2:glpat-xxxxxxxxxxxxxxxxxxxx@gitlab.com/acme/app.git?token=abc')!;
  expect(JSON.stringify(q)).not.toMatch(/glpat|oauth2|token=/);
});
it('plain http gets no link, and local or malformed remotes are ignored',()=>{
  const r=parseRemoteUrl('http://git.acme.dev/infra/deploy.git')!;
  expect(r.protocol).toBe('http'); expect(r.url).toBeUndefined();
  for(const bad of ['','/Users/me/repo','../sibling','file:///srv/git/repo.git','C:\\work\\repo','not a url','https://github.com/..%2F..%2Fetc','ssh://host/','git@host:']) expect(parseRemoteUrl(bad)).toBeUndefined();
});

it('reads the origin remote from .git/config, preferring origin, and from a worktree common dir',()=>{
  const dir=mkdtempSync(join(tmpdir(),'beam-repo-')); mkdirSync(join(dir,'.git'));
  writeFileSync(join(dir,'.git','config'),`[core]\n\trepositoryformatversion = 0\n[remote "upstream"]\n\turl = git@github.com:other/fork.git\n[remote "origin"]\n\turl = https://tok:secret@gitlab.com/acme/app.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n`);
  const r=readOriginRemote(join(dir,'.git'))!;
  expect(r).toMatchObject({provider:'gitlab',path:'acme/app'}); expect(JSON.stringify(r)).not.toMatch(/secret|tok:/);
  expect(readOriginRemote(join(dir,'nope'))).toBeUndefined();
});

it('finds container registries in docker and aws commands',()=>{
  const ecr=registriesIn('aws ecr get-login-password | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com && docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/web:v1.4.2');
  expect(ecr).toEqual([{provider:'aws-ecr',host:'123456789012.dkr.ecr.us-east-1.amazonaws.com',path:'acme/web',account:'123456789012',region:'us-east-1',tag:'v1.4.2'}]);
  expect(registriesIn('docker pull ghcr.io/acme/tool:latest')[0]).toMatchObject({provider:'ghcr',path:'acme/tool',tag:'latest'});
  expect(registriesIn('docker push us-central1-docker.pkg.dev/my-proj/apps/web:1')[0]).toMatchObject({provider:'gcp-artifact-registry',region:'us-central1',path:'my-proj/apps/web'});
  expect(registriesIn('docker push gcr.io/my-proj/web')[0]).toMatchObject({provider:'gcr'});
  expect(registriesIn('docker push acmecorp.azurecr.io/web:2')[0]).toMatchObject({provider:'azure-acr',path:'web'});
  expect(registriesIn('docker pull quay.io/acme/img')[0]).toMatchObject({provider:'quay'});
  expect(registriesIn('docker pull public.ecr.aws/acme/img:3')[0]).toMatchObject({provider:'aws-ecr-public'});
  expect(registriesIn('docker pull registry.gitlab.com/acme/app/img')[0]).toMatchObject({provider:'gitlab-registry'});
  expect(registriesIn('docker pull docker.io/acme/img:5')[0]).toMatchObject({provider:'docker-hub'});
  expect(registriesIn('ls -la && git status')).toEqual([]);
  const many=registriesIn(Array.from({length:9},(_,i)=>`docker pull ghcr.io/acme/img${i}`).join('; '));
  expect(many.length).toBe(4);
});

it('the action context carries the remote and registries, so the dashboard can tag the repo',()=>{
  const dir=mkdtempSync(join(tmpdir(),'beam-ctx-')); mkdirSync(join(dir,'.git'));
  writeFileSync(join(dir,'.git','HEAD'),'ref: refs/heads/main\n');
  writeFileSync(join(dir,'.git','config'),'[remote "origin"]\n\turl = git@github.com:acme/web.git\n');
  const ctx=classifyActionContext('Bash',{},dir,'docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/acme/web:v1',redact);
  expect(ctx.repository).toMatchObject({branch:'main',remote:{provider:'github',host:'github.com',path:'acme/web',url:'https://github.com/acme/web'}});
  expect(ctx.registries?.[0]).toMatchObject({provider:'aws-ecr',region:'us-east-1'});
  expect(classifyActionContext('Bash',{},dir,'ls',redact).registries).toBeUndefined();
});
