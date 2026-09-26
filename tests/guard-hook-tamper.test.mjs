import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { guardHookTamper, hookTamperReason } from '../src/guard/self-protect.mjs';

const HOOK = 'npx -y @shomra/agent tool-guard --agent claude';
const settings = (extra = {}) => JSON.stringify({
  permissions: { allow: ['Read'] },
  hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: HOOK }] }] },
  ...extra,
}, null, 2);

function sandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-hook-'));
  const home = path.join(root, 'home');
  const cwd = path.join(root, 'project');
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.mkdirSync(path.join(cwd, '.claude'), { recursive: true });
  const file = path.join(cwd, '.claude', 'settings.json');
  fs.writeFileSync(file, settings());
  return { root, home, cwd, file };
}

test('a write that drops the Shomra hook from settings is caught before it runs', () => {
  const s = sandbox();
  const without = JSON.stringify({ permissions: { allow: ['Read'] }, hooks: {} });
  const hit = guardHookTamper('Write', { file_path: s.file, content: without }, { cwd: s.cwd, home: s.home });
  assert.equal(hit?.why, 'removes-hook');
  assert.match(hookTamperReason(hit), /removes the Shomra guard hook/);
});

test('an edit that deletes the hook line is caught', () => {
  const s = sandbox();
  const hit = guardHookTamper('Edit', { file_path: s.file, old_string: `"command": "${HOOK}"`, new_string: '"command": "true"' }, { cwd: s.cwd, home: s.home });
  assert.equal(hit?.why, 'removes-hook');
});

test('turning every hook off, or pointing the guard elsewhere, is caught', () => {
  const s = sandbox();
  const off = guardHookTamper('Write', { file_path: s.file, content: settings({ disableAllHooks: true }) }, { cwd: s.cwd, home: s.home });
  assert.equal(off?.why, 'disables-hooks');
  const env = guardHookTamper('Write', { file_path: s.file, content: settings({ env: { SHOMRA_GUARD_LOCAL: '0' } }) }, { cwd: s.cwd, home: s.home });
  assert.equal(env?.why, 'guard-env');
});

test('a shell edit of a settings file that holds the hook asks first', () => {
  const s = sandbox();
  const hit = guardHookTamper('Bash', { command: `sed -i 's/tool-guard/true/' ${s.file}` }, { cwd: s.cwd, home: s.home });
  assert.equal(hit?.why, 'rewrites');
});

test('the guard ignore list is protected', () => {
  const s = sandbox();
  assert.equal(guardHookTamper('Write', { file_path: path.join(s.cwd, '.shomraignore'), content: '*\n' }, { cwd: s.cwd, home: s.home })?.why, 'ignore-list');
  assert.equal(guardHookTamper('Bash', { command: 'echo "*" >> .shomraignore' }, { cwd: s.cwd, home: s.home })?.why, 'ignore-list');
});

test('ordinary settings work stays quiet', () => {
  const s = sandbox();
  const keeps = settings({ permissions: { allow: ['Read', 'Bash(npm test:*)'] } });
  assert.equal(guardHookTamper('Write', { file_path: s.file, content: keeps }, { cwd: s.cwd, home: s.home }), null);
  assert.equal(guardHookTamper('Edit', { file_path: s.file, old_string: '"Read"', new_string: '"Read", "Grep"' }, { cwd: s.cwd, home: s.home }), null);
  assert.equal(guardHookTamper('Bash', { command: `cat ${s.file}` }, { cwd: s.cwd, home: s.home }), null);
  const other = path.join(s.cwd, 'app.json');
  fs.writeFileSync(other, '{}');
  assert.equal(guardHookTamper('Write', { file_path: other, content: '{"a":1}' }, { cwd: s.cwd, home: s.home }), null);
});

test('a settings file without the Shomra hook is none of its business', () => {
  const s = sandbox();
  fs.writeFileSync(s.file, JSON.stringify({ permissions: { allow: ['Read'] } }));
  assert.equal(guardHookTamper('Write', { file_path: s.file, content: JSON.stringify({ disableAllHooks: true }) }, { cwd: s.cwd, home: s.home }), null);
});
