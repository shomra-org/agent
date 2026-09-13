import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverAgentArtifacts } from '../src/inventory/agent-artifacts.mjs';
import { classify } from '../src/inventory/artifacts/classify.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-extensions-test-'));
process.on('exit', () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {  } });
const write = (rel, body) => {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  return full;
};

const manifest = (name, entry) => ({
  manifest_version: '0.3', name, version: '1.0.0',
  server: { type: 'node', entry_point: entry, mcp_config: { command: 'node', args: [`\${__dirname}/${entry}`] } },
});

write('Claude/Claude Extensions/ant.dir.notes/manifest.json', manifest('notes', 'server/index.js'));
write('Claude/Claude Extensions/ant.dir.notes/server/index.js', 'import "./lib/util.js";\n');
write('Claude/Claude Extensions/ant.dir.notes/server/lib/util.js', 'export const x = 1;\n');
write('Claude/Claude Extensions/ant.dir.notes/node_modules/dep/index.js', 'module.exports = 1;\n');
write('Claude/Claude Extensions/ant.dir.notes/README.md', '# notes\n');
write('Claude/Claude Extensions/ant.dir.off/manifest.json', manifest('off', 'index.js'));
write('Claude/Claude Extensions/ant.dir.off/index.js', 'console.log(1);\n');
write('Claude/Claude Extensions Settings/ant.dir.off.json', { isEnabled: false, userConfig: { api_key: 'sk-live-should-never-travel' } });

const roots = [{ vendor: 'claude-desktop', scope: 'user', dir: path.join(tmp, 'Claude', 'Claude Extensions') }];
const result = discoverAgentArtifacts(tmp, roots);
const extensions = result.artifacts.filter((a) => a.kind === 'extension');
const byName = (n) => extensions.find((a) => a.name === n);

test('only the per-install manifest classifies as an extension', () => {
  assert.equal(classify('Claude Extensions/x/manifest.json', 'claude-desktop'), 'extension');
  assert.equal(classify('Claude Extensions/x/server/manifest.json', 'claude-desktop'), null);
  assert.equal(classify('Claude Extensions/x/README.md', 'claude-desktop'), null, 'a bundle README is not a rules file');
  assert.equal(classify('Claude Extensions/x/manifest.json', 'claude-code'), null);
});

test('an installed extension is reported with its server source, entry point first', () => {
  const notes = byName('notes');
  assert.ok(notes, 'extension reported');
  assert.equal(notes.path, 'Claude Extensions/ant.dir.notes/manifest.json');
  assert.equal(notes.files[0]?.path, 'Claude Extensions/ant.dir.notes/server/index.js');
  assert.ok(notes.files.some((f) => f.path.endsWith('server/lib/util.js')));
  assert.ok(!notes.files.some((f) => f.path.includes('node_modules')), 'vendored dependencies are not bundled');
  assert.equal(extensions.length, 2, 'no other file under the extensions tree becomes an artifact');
});

test('a disabled extension is marked disabled and its settings never travel', () => {
  const off = byName('off');
  assert.equal(off.metadata.activation, 'disabled');
  assert.ok(!JSON.stringify(result).includes('sk-live-should-never-travel'));
});

test('a symlinked source file pointing outside the bundle is not uploaded', { skip: process.platform === 'win32' }, () => {
  const secret = write('outside/secret.js', 'const token = "outside";\n');
  fs.symlinkSync(secret, path.join(tmp, 'Claude', 'Claude Extensions', 'ant.dir.notes', 'server', 'leak.js'));
  const again = discoverAgentArtifacts(tmp, roots).artifacts.find((a) => a.name === 'notes');
  assert.ok(!again.files.some((f) => f.path.endsWith('leak.js')));
});
