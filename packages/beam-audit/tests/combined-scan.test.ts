import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseArgs } from '../src/args.js';
import { runExtensionStage } from '../src/extension-stage.js';
import { DEFAULT_EXTENSION_ADAPTERS } from '../src/checks/extension-ui.js';

test('launching VS Code adds to the normal scan; extension-only remains explicit', () => {
  const normal = parseArgs(['--launch-vscode']);
  assert.equal(normal.launchVscode, true);
  assert.equal(normal.extensionsOnly, false);
  assert.equal(parseArgs(['--launch-vscode', '--extensions-only']).extensionsOnly, true);
});

test('full scan selects workstation scope, external queries, CLI tests and extension launch', () => {
  const options = parseArgs(['--full']);
  assert.equal(options.wholePc, true);
  assert.equal(options.online, true);
  assert.equal(options.skipLive, false);
  assert.equal(options.launchVscode, true);
  assert.equal(options.extensionsOnly, false);
  assert.ok(options.html?.endsWith('beam-audit-report.html'));
  assert.ok(options.json?.endsWith('beam-audit-report.json'));
  assert.equal(parseArgs(['--skip-live', '--full']).skipLive, true);
  assert.equal(parseArgs(['--full', '--vscode-cdp', 'http://127.0.0.1:9222']).launchVscode, false);
  assert.throws(() => parseArgs(['--full', '--extensions-only']));
});

test('extension launch failure produces untested rows instead of losing workstation results', async () => {
  let calls = 0;
  const result = await runExtensionStage({ home: '/fixture', roots: [], repos: [], platform: process.platform, log: () => {} }, { launch: true, adapters: DEFAULT_EXTENSION_ADAPTERS }, {
    launch: async () => { throw new Error('VS Code absent'); },
    run: async () => { calls++; return []; },
  });
  assert.equal(calls, 0);
  assert.equal(result.matrices[0]?.cells.length, 30);
  assert.ok(result.matrices[0]?.cells.every(c => c.blocked === null));
  assert.ok(result.checks.some(c => c.id === 'extension-stage-unavailable'));
});

test('CLI emits workstation findings and both extension surfaces in one HTML/JSON report', () => {
  const dir = mkdtempSync(join(tmpdir(), 'beam-combined-test-'));
  try {
    const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
    const result = spawnSync(process.execPath, [cli, '--root', dir, '--vscode-cdp', 'http://127.0.0.1:1', '--max-files', '10', '--html', join(dir, 'report.html'), '--json', join(dir, 'report.json')], { encoding: 'utf8', timeout: 30000, env: { ...process.env, HOME: dir, USERPROFILE: dir, PATH: dir } });
    assert.ok(result.status === 0 || result.status === 1, result.stderr);
    const report = JSON.parse(readFileSync(join(dir, 'report.json'), 'utf8'));
    assert.ok(report.checks.some((c: any) => c.id === 'credential-files-present'));
    assert.ok(report.checks.some((c: any) => c.id === '6.3-disk-encryption'));
    assert.equal(report.categories.length, 11);
    const cells = report.matrices.flatMap((m: any) => m.cells);
    assert.equal(cells.length, 32);
    assert.equal(new Set(cells.map((c: any) => c.surface)).size, 2);
    const html = readFileSync(join(dir, 'report.html'), 'utf8');
    assert.ok(html.includes('Category overview'));
    assert.ok(html.includes('VS Code · Claude extension'));
    assert.ok(html.includes('VS Code · Codex extension'));
    assert.ok(html.includes('Credential files present'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
