









import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { discoverAgentArtifacts, canonicalHooks, installedMarketplaces } from '../src/inventory/agent-artifacts.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-artifacts-'));
const write = (rel, body) => {
  const full = path.join(tmp, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, body);
  return full;
};


write('.claude/skills/deploy/SKILL.md', '---\nname: deploy\ndescription: Ship it\n---\n\nRun `bash scripts/setup.sh`.\n');
write('.claude/skills/deploy/scripts/setup.sh', '#!/bin/sh\necho hi\n');
write('.claude/skills/deploy/payload.bin', Buffer.from([0, 1, 2, 3, 0, 255]));
write('.claude/commands/ship.md', '---\nname: ship\n---\nDo the thing.\n');
write('.claude/agents/reviewer.md', '---\nname: reviewer\ndescription: reviews\ntools: Read\n---\nReview it.\n');
write('.claude/settings.json', JSON.stringify({
  env: { ANTHROPIC_API_KEY: 'sk-ant-api03-SECRET' },
  theme: 'dark',
  hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo guarded' }] }] },
}));

write('.claude/plugins/installed_plugins.json', JSON.stringify({ version: 2, plugins: {} }));
write('.claude/plugins/marketplaces/acme/skills/spy/SKILL.md', '---\nname: spy\n---\nExfiltrate.\n');
write('.claude/plugins/marketplaces/acme/commands/go.md', '---\nname: go\n---\nGo.\n');

write('.codex/.tmp/marketplaces/bundled/skills/staged/SKILL.md', '---\nname: staged\n---\nStaged.\n');

const roots = [
  { vendor: 'claude-code', scope: 'user', dir: path.join(tmp, '.claude') },
  { vendor: 'codex', scope: 'user', dir: path.join(tmp, '.codex') },
];
const result = discoverAgentArtifacts(tmp, roots);
const byKind = (k) => result.artifacts.filter((a) => a.kind === k);
const named = (n) => result.artifacts.find((a) => a.name === n);

test('finds each artifact kind at its scope-relative path', () => {
  assert.equal(byKind('skill').length, 1, 'one skill - the marketplace one is a catalogue');
  assert.equal(byKind('command').length, 1);
  assert.equal(byKind('subagent').length, 1);
  assert.equal(byKind('hook').length, 1);

  assert.equal(named('deploy').path, '.claude/skills/deploy/SKILL.md');
  assert.equal(named('deploy').scope, 'user');
  assert.equal(named('deploy').vendor, 'claude-code');
  
  assert.ok(!named('deploy').path.includes(tmp));
});

test('a skill ships its bundled script, and reports its binary by path only', () => {
  const files = named('deploy').files;
  const script = files.find((f) => f.path.endsWith('scripts/setup.sh'));
  const bin = files.find((f) => f.path.endsWith('payload.bin'));

  assert.ok(script, 'the script the SKILL.md runs is the program, and travels');
  assert.match(script.content, /echo hi/);

  
  
  assert.ok(bin, 'the binary is REPORTED');
  assert.equal(bin.content, null, 'and its content is null, not an empty string');
  assert.equal(bin.binary, true);
});

test('a hook travels WITHOUT the settings file it lives in', () => {
  const hook = byKind('hook')[0];
  assert.ok(!hook.content.includes('sk-ant-api03'), 'the API key beside the hooks does not travel');
  assert.ok(!hook.content.includes('dark'), 'the developer preferences do not travel');
  assert.match(hook.content, /PreToolUse/);
  assert.deepEqual(Object.keys(JSON.parse(hook.content)), ['hooks'], 'exactly one key');
});

test('available is not installed - a catalogue is counted, never registered', () => {
  assert.ok(!named('spy'), 'a marketplace skill with no plugin installed is NOT an artifact');
  assert.ok(!named('staged'), 'a skill staged under .tmp/ is NOT an artifact');

  const total = result.available.reduce((n, a) => n + a.count, 0);
  assert.equal(total, 3, 'all three catalogued files are still COUNTED, not silently dropped');
  assert.ok(result.available.some((a) => a.marketplace === 'acme'));
  assert.ok(result.available.some((a) => a.marketplace.includes('.tmp')));
});

test('an installed plugin makes its marketplace artifacts real', () => {
  fs.writeFileSync(
    path.join(tmp, '.claude', 'plugins', 'installed_plugins.json'),
    JSON.stringify({ version: 2, plugins: { 'pack@acme': {} } }),
  );
  const after = discoverAgentArtifacts(tmp, roots);
  const spy = after.artifacts.find((a) => a.name === 'spy');
  assert.ok(spy, 'once the plugin is installed the skill IS reported');
  assert.equal(spy.metadata.activation, 'active');
  assert.equal(spy.metadata.marketplace, 'acme');
});

test('an unreadable manifest reports everything rather than hiding it', () => {
  
  
  
  fs.writeFileSync(path.join(tmp, '.claude', 'plugins', 'installed_plugins.json'), '{ broken');
  assert.equal(installedMarketplaces(path.join(tmp, '.claude')), null);

  const after = discoverAgentArtifacts(tmp, roots);
  const spy = after.artifacts.find((a) => a.name === 'spy');
  assert.ok(spy, 'the marketplace artifact is reported when activation cannot be read');
  assert.equal(spy.metadata.activation, 'unknown', 'and it says so, rather than claiming active');
});

test('canonicalHooks refuses anything that is not a hooks block', () => {
  assert.equal(canonicalHooks(JSON.stringify({ theme: 'dark' })), null, 'a preferences file is not an artifact');
  assert.equal(canonicalHooks(JSON.stringify({ hooks: {} })), null, 'an empty hooks block is not an artifact');
  assert.equal(canonicalHooks('{ not json'), null, 'unparseable yields null and does not throw');
});

test('the sweep is bounded and says so', () => {
  assert.ok(Array.isArray(result.capped), 'caps are always reported, even when empty');
  assert.equal(result.capped.length, 0, 'a small fixture hits no cap');
});
