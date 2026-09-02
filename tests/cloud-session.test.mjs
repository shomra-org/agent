import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { detectEnv, remoteRunner } from '../src/gate/environment.mjs';
import { PACKAGE_SPEC, SHOMRA_ANY_HOOK_RE, hookCommand, shomraHookRe } from '../src/agents/hook-command.mjs';
import { AGENT_INSTALLERS } from '../src/agents/installers.mjs';
import { sessionPosture } from '../src/guard/session-guard.mjs';

test('a cloud container is REMOTE, not a developer machine', () => {
  const e = { CLAUDE_CODE_CONTAINER_ID: 'abc123' };
  assert.equal(remoteRunner(e), 'claude-code-cloud');
  assert.equal(detectEnv(e).environment, 'REMOTE');
  assert.equal(detectEnv(e).runner, 'claude-code-cloud');
});

test('the runner version and a remote entrypoint each identify it too', () => {
  assert.equal(remoteRunner({ CLAUDE_CODE_ENVIRONMENT_RUNNER_VERSION: '1.2.3' }), 'claude-code-cloud');
  assert.equal(remoteRunner({ CLAUDE_CODE_ENTRYPOINT: 'remote_mobile' }), 'claude-code-cloud');
  assert.equal(remoteRunner({ CLAUDE_CODE_ENTRYPOINT: 'cli' }), null);
});

test('⚠ CI still wins - it carries repo, ref and commit, which is the stronger attribution', () => {
  const e = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'o/r', CLAUDE_CODE_CONTAINER_ID: 'abc' };
  assert.equal(detectEnv(e).environment, 'CI');
});

test('an ordinary laptop is still LOCAL', () => {
  assert.equal(detectEnv({ HOME: '/home/dev' }).environment, 'LOCAL');
  assert.equal(remoteRunner({}), null);
});

test('⚠⚠ a project hook resolves through npm, not an absolute path', () => {
  const portable = hookCommand('tool-guard --agent claude', { portable: true });
  assert.match(portable, /^npx -y @shomra\/agent@/);
  assert.ok(!portable.includes(process.execPath));
});

test('⚠ the committed hook pins a version and never says latest', () => {
  assert.match(PACKAGE_SPEC, /^@shomra\/agent@\d+\.\d+\.\d+/);
  assert.ok(!hookCommand('tool-guard', { portable: true }).includes('@latest'));
});

test('a global hook keeps the fast absolute path', () => {
  const local = hookCommand('tool-guard --agent claude');
  assert.ok(local.includes(process.execPath));
  assert.ok(!local.includes('npx'));
});

test('⚠ the hook detector recognises BOTH forms, or protect duplicates every hook', () => {
  assert.match(hookCommand('tool-guard --agent claude', { portable: true }), SHOMRA_ANY_HOOK_RE);
  assert.match(hookCommand('tool-guard --agent claude'), SHOMRA_ANY_HOOK_RE);
  assert.match(hookCommand('session-guard --agent claude', { portable: true }), shomraHookRe('session-guard'));
});

function installInTemp(global) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-scope-'));
  const cwd = process.cwd();
  process.chdir(dir);
  try {
    const { file } = AGENT_INSTALLERS.claude(global);
    return { settings: JSON.parse(fs.readFileSync(file, 'utf8')), dir };
  } finally {
    process.chdir(cwd);
  }
}

test('a project install writes portable commands into the committed file', () => {
  const { settings } = installInTemp(false);
  const commands = JSON.stringify(settings.hooks);
  assert.match(commands, /npx -y @shomra\/agent@/);
  assert.ok(!commands.includes(process.execPath));
});

test('a SessionStart hook is installed, so a fresh container says what is enforcing', () => {
  const { settings } = installInTemp(false);
  assert.ok(Array.isArray(settings.hooks.SessionStart));
  assert.match(JSON.stringify(settings.hooks.SessionStart), /session-guard/);
});

test('installing twice does not duplicate the hooks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-twice-'));
  const cwd = process.cwd();
  process.chdir(dir);
  try {
    AGENT_INSTALLERS.claude(false);
    const second = AGENT_INSTALLERS.claude(false);
    assert.equal(second.changed, false);
    const settings = JSON.parse(fs.readFileSync(second.file, 'utf8'));
    assert.equal(settings.hooks.SessionStart.length, 1);
    assert.equal(settings.hooks.PreToolUse.filter((h) => JSON.stringify(h).includes('tool-guard')).length, 1);
  } finally {
    process.chdir(cwd);
  }
});

test('⚠ an unconfigured CLOUD session says so in different words than a laptop', () => {
  const cloud = sessionPosture({ environment: 'REMOTE' }, {}, null);
  const laptop = sessionPosture({ environment: 'LOCAL' }, {}, null);
  assert.equal(cloud.enforcing, 'local-only');
  assert.equal(cloud.remote, true);
  assert.match(cloud.message, /EPHEMERAL CLOUD SESSION/);
  assert.notEqual(cloud.message, laptop.message);
  assert.equal(laptop.remote, false);
});

test('⚠⚠ a blocked cloud session says its gap ledger dies with the container', () => {
  const p = sessionPosture({ environment: 'REMOTE' }, { apiKey: 'k', url: 'https://x' }, false);
  assert.equal(p.enforcing, 'degraded');
  assert.match(p.message, /EPHEMERAL/);
  assert.match(p.message, /never be reported as unscreened/);
});

test('a healthy session stays silent', () => {
  const p = sessionPosture({ environment: 'REMOTE' }, { apiKey: 'k', url: 'https://x' }, true);
  assert.equal(p.enforcing, 'full');
  assert.equal(p.message, null);
});
