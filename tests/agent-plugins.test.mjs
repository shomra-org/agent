import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverAgentArtifacts } from '../src/inventory/agent-artifacts.mjs';
import { installedPluginManifests, pluginRootOf } from '../src/inventory/artifacts/plugins.mjs';
import { classify } from '../src/inventory/artifacts/classify.mjs';

const tmp = fs.mkdtempSync(path.join(os.homedir(), '.shomra-plugins-test-'));
process.on('exit', () => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {  } });
const write = (rel, body) => {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  return full;
};

const claude = path.join(tmp, '.claude');
const installDir = path.join(claude, 'plugins', 'cache', 'acme', 'deployer', '1.2.0');

write('.claude/plugins/marketplaces/acme/.claude-plugin/marketplace.json', {
  name: 'acme', owner: { name: 'Acme' },
  plugins: [{ name: 'deployer', source: './plugins/deployer' }, { name: 'other', source: { source: 'github', repo: 'x/other' } }],
});
write('.claude/plugins/marketplaces/acme/plugins/deployer/.claude-plugin/plugin.json', { name: 'deployer' });
write('.claude/plugins/marketplaces/acme/plugins/other/.claude-plugin/plugin.json', { name: 'other' });

write('.claude/plugins/cache/acme/deployer/1.2.0/.claude-plugin/plugin.json', { name: 'deployer', version: '1.2.0', lspServers: './.lsp.json' });
write('.claude/plugins/cache/acme/deployer/1.2.0/hooks/hooks.json', {
  description: 'd', hooks: { SessionStart: [{ hooks: [{ type: 'command', command: '${CLAUDE_PLUGIN_ROOT}/bin/git status' }] }] },
});
write('.claude/plugins/cache/acme/deployer/1.2.0/.lsp.json', { dl: { command: 'npx', args: ['-y', 'deploy-ls'] } });
write('.claude/plugins/cache/acme/deployer/1.2.0/bin/git', '#!/bin/sh\necho hi\n');
write('.claude/plugins/installed_plugins.json', {
  version: 2, plugins: { 'deployer@acme': [{ scope: 'user', installPath: installDir, version: '1.2.0' }] },
});
write('.gemini/extensions/notes/gemini-extension.json', { name: 'notes', version: '1.0.0', contextFileName: 'NOTES.md' });

const roots = [
  { vendor: 'claude-code', scope: 'user', dir: claude },
  { vendor: 'gemini', scope: 'user', dir: path.join(tmp, '.gemini') },
];
const result = discoverAgentArtifacts(tmp, roots);
const plugins = result.artifacts.filter((a) => a.kind === 'plugin');
const byPath = (suffix) => plugins.find((p) => p.path.endsWith(suffix));

test('every vendor manifest location classifies as a plugin', () => {
  for (const p of [
    '.claude-plugin/plugin.json', '.claude-plugin/marketplace.json', '.codex-plugin/plugin.json',
    '.cursor-plugin/plugin.json', '.github/plugin/marketplace.json', '.plugin/plugin.json',
    '.agents/plugins/marketplace.json', 'extensions/x/gemini-extension.json', 'x/openclaw.plugin.json',
  ]) assert.equal(classify(p, 'claude-code'), 'plugin', p);
  assert.equal(classify('src/plugin.json', 'claude-code'), null, 'a bare plugin.json outside a plugin dir is not claimed');
});

test('a registered marketplace root is reported; the plugins it merely OFFERS are counted, not registered', () => {
  assert.ok(byPath('marketplaces/acme/.claude-plugin/marketplace.json'), 'the catalogue the user added is an artifact');
  assert.ok(!byPath('marketplaces/acme/plugins/other/.claude-plugin/plugin.json'), 'an offered plugin is not');
  assert.ok(!byPath('marketplaces/acme/plugins/deployer/.claude-plugin/plugin.json'), 'nor the catalogue copy of an installed one');
  assert.ok(result.available.some((a) => a.marketplace === 'acme' && a.count >= 2), 'offers are still COUNTED');
});

test('an installed plugin is reported from its INSTALL path, with its components', () => {
  const p = byPath('cache/acme/deployer/1.2.0/.claude-plugin/plugin.json');
  assert.ok(p, 'the installed copy under plugins/cache is found although the walk skips cache/');
  assert.equal(p.name, 'deployer');
  assert.equal(p.metadata.activation, 'active');
  assert.equal(p.metadata.marketplace, 'acme');
  const files = p.files.map((f) => f.path);
  assert.ok(files.some((f) => f.endsWith('1.2.0/hooks/hooks.json')), 'the conventional hooks file travels');
  assert.ok(files.some((f) => f.endsWith('1.2.0/.lsp.json')), 'the declared language-server map travels');
  const bin = p.files.find((f) => f.path.endsWith('1.2.0/bin/git'));
  assert.ok(bin, 'bin/ travels by NAME');
  assert.equal(bin.content, null, 'and never by content');
  const hooks = p.files.find((f) => f.path.endsWith('hooks/hooks.json'));
  assert.deepEqual(Object.keys(JSON.parse(hooks.content)), ['hooks'], 'the hooks file is canonicalised - only the hooks block leaves the machine');
});

test('paths are machine-relative, never absolute', () => {
  for (const p of plugins) {
    assert.ok(!p.path.includes(tmp), p.path);
    for (const f of p.files) assert.ok(!f.path.includes(tmp), f.path);
  }
});

test('a Gemini extension manifest is a plugin artifact', () => {
  const g = byPath('extensions/notes/gemini-extension.json');
  assert.ok(g);
  assert.equal(g.name, 'notes');
});

test('install records outside HOME are not followed', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-outside-'));
  fs.mkdirSync(path.join(dir, '.claude', 'plugins'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.claude', 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'x@y': [{ installPath: path.parse(dir).root }] } }));
  assert.deepEqual(installedPluginManifests(path.join(dir, '.claude')), []);
});

test('an oversize manifest is reported as capped, never as an empty plugin', () => {
  const big = { name: 'huge', owner: { name: 'x' }, plugins: Array.from({ length: 3000 }, (_, i) => ({ name: `p${i}`, source: `./plugins/p${i}`, description: 'x'.repeat(60) })) };
  write('.claude/plugins/marketplaces/huge/.claude-plugin/marketplace.json', big);
  const again = discoverAgentArtifacts(tmp, roots);
  assert.ok(!again.artifacts.some((a) => a.path.includes('marketplaces/huge/')));
  assert.ok(again.capped.some((c) => c.reason === 'manifest-too-large' && c.path.includes('marketplaces/huge/')));
});

test('pluginRootOf climbs out of the vendor manifest directory', () => {
  assert.equal(pluginRootOf(path.join('a', 'b', '.claude-plugin', 'plugin.json')), path.join('a', 'b'));
  assert.equal(pluginRootOf(path.join('a', '.github', 'plugin', 'marketplace.json')), 'a');
  assert.equal(pluginRootOf(path.join('ext', 'gemini-extension.json')), 'ext');
});

test('a component file symlinked OUT of the plugin is never read', (t) => {
  const dir = fs.mkdtempSync(path.join(os.homedir(), '.shomra-plugin-link-'));
  process.on('exit', () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {  } });
  const secret = path.join(dir, 'secret.txt');
  fs.writeFileSync(secret, 'aws_secret_access_key = SHOULD-NEVER-LEAVE');
  const root = path.join(dir, '.claude', 'plugins', 'cache', 'm', 'p', '1.0.0');
  fs.mkdirSync(path.join(root, '.claude-plugin'), { recursive: true });
  fs.writeFileSync(path.join(root, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'p' }));
  try { fs.symlinkSync(secret, path.join(root, '.lsp.json')); } catch { t.skip('this OS/user cannot create symlinks'); return; }
  fs.mkdirSync(path.join(dir, '.claude', 'plugins'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.claude', 'plugins', 'installed_plugins.json'), JSON.stringify({ version: 2, plugins: { 'p@m': [{ installPath: root }] } }));
  const found = discoverAgentArtifacts(dir, [{ vendor: 'claude-code', scope: 'user', dir: path.join(dir, '.claude') }]);
  const p = found.artifacts.find((a) => a.kind === 'plugin');
  assert.ok(p, 'the plugin itself is still reported');
  assert.ok(!JSON.stringify(p).includes('SHOULD-NEVER-LEAVE'), 'the symlinked secret did not travel');
});
