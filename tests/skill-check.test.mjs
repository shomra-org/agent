import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TOOL_GUARD_MATCHERS, widenToolGuardMatcher } from '../src/agents/installers.mjs';
import { cachedSkillVerdict, rememberSkillVerdict, requestedSkill, resolveSkill, skillCacheKey } from '../src/guard/skill-check.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');
const KEY = 'shm_test_key_0000000000000000';

function tmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeSkill(dir, name, body = 'Summarise the document the user names.\n', frontName = name) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'SKILL.md'), `---\nname: ${frontName}\ndescription: ${name} helper\n---\n${body}`);
  return path.join(dir, 'SKILL.md');
}

function guard(payload, { home, cwd, env = {} }) {
  const base = { ...process.env, USERPROFILE: home, HOME: home, NO_COLOR: '1' };
  for (const k of Object.keys(base)) if (k.startsWith('SHOMRA_') || k === 'CLAUDE_PROJECT_DIR') delete base[k];
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, 'tool-guard', '--agent', 'claude'], { env: { ...base, ...env }, cwd: cwd ?? home });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => {
      let body = null;
      try {
        body = JSON.parse(stdout || '{}');
      } catch {
        body = null;
      }
      done({ code, stdout, stderr, decision: body?.hookSpecificOutput?.permissionDecision ?? null, reason: body?.hookSpecificOutput?.permissionDecisionReason ?? '' });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

async function serve(answer) {
  const seen = { checks: [], calls: [] };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      let parsed = {};
      try {
        parsed = JSON.parse(body || '{}');
      } catch {
        parsed = {};
      }
      if (req.url === '/gate/check') seen.checks.push(parsed);
      else seen.calls.push({ url: req.url, body: parsed });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(req.url === '/gate/check' ? answer(parsed) : { decision: 'ALLOW' }));
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  return { url: `http://127.0.0.1:${server.address().port}`, seen, close: () => new Promise((d) => server.close(d)) };
}

const ALLOW = () => ({ decision: 'ALLOW', findings: [] });
const BANNED = () => ({
  decision: 'BLOCK',
  decidedBy: { layer: 'built-in', name: 'Registry - banned artifact' },
  findings: [{ severity: 'CRITICAL', title: 'Skill "pdf" is DENIED in your organization' }],
});

test('the Claude Code matcher names the Skill tool, and an older install is widened to it', () => {
  assert.match(TOOL_GUARD_MATCHERS.claude, /(^|\|)Skill(\||$)/);
  const pre = [{ matcher: 'Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|mcp__.*', hooks: [{ type: 'command', command: 'npx -y @shomra/agent tool-guard --agent claude' }] }];
  assert.equal(widenToolGuardMatcher(pre, TOOL_GUARD_MATCHERS.claude), true);
  assert.match(pre[0].matcher, /(^|\|)Skill(\||$)/);
  assert.equal(widenToolGuardMatcher(pre, TOOL_GUARD_MATCHERS.claude), false);
});

test('the invoked skill is read from either input shape, with a plugin or directory scope split off', () => {
  assert.deepEqual(requestedSkill({ skill: 'pdf' }), { raw: 'pdf', scope: null, name: 'pdf' });
  assert.deepEqual(requestedSkill({ skill: 'pdf', args: 'report.pdf' }), { raw: 'pdf', scope: null, name: 'pdf' });
  assert.deepEqual(requestedSkill({ command: '/review-pr 123' }), { raw: 'review-pr', scope: null, name: 'review-pr' });
  assert.deepEqual(requestedSkill({ skill: 'anthropic-skills:docx' }), { raw: 'anthropic-skills:docx', scope: 'anthropic-skills', name: 'docx' });
  assert.deepEqual(requestedSkill({ skill: 'apps/web:deploy' }), { raw: 'apps/web:deploy', scope: 'apps/web', name: 'deploy' });
  assert.equal(requestedSkill({}), null);
  assert.equal(requestedSkill({ skill: '   ' }), null);
});

test('a skill resolves in the project, in ~/.claude/skills, by its declared name, under a nested scope and in a plugin', () => {
  const home = tmp('shomra-skill-home-');
  const project = tmp('shomra-skill-proj-');
  writeSkill(path.join(project, '.claude', 'skills', 'deploy'), 'deploy');
  writeSkill(path.join(home, '.claude', 'skills', 'pdf'), 'pdf');
  writeSkill(path.join(home, '.claude', 'skills', 'notes-v2'), 'notes');
  writeSkill(path.join(project, 'apps', 'web', '.claude', 'skills', 'deploy'), 'deploy');
  const pluginRoot = path.join(home, '.claude', 'plugins', 'cache', 'acme', 'toolkit', '1.0.0');
  fs.mkdirSync(path.join(pluginRoot, '.claude-plugin'), { recursive: true });
  fs.writeFileSync(path.join(pluginRoot, '.claude-plugin', 'plugin.json'), JSON.stringify({ name: 'toolkit' }));
  writeSkill(path.join(pluginRoot, 'skills', 'lint'), 'lint');
  fs.writeFileSync(path.join(home, '.claude', 'plugins', 'installed_plugins.json'), JSON.stringify({ plugins: { 'toolkit@acme': [{ installPath: pluginRoot }] } }));

  const at = (raw) => resolveSkill(requestedSkill({ skill: raw }), { projectDir: project, cwd: project, home }).map((f) => [f.scope, f.path]);
  assert.deepEqual(at('deploy'), [['project', '.claude/skills/deploy/SKILL.md']]);
  assert.deepEqual(at('pdf'), [['user', '.claude/skills/pdf/SKILL.md']]);
  assert.deepEqual(at('notes'), [['user', '.claude/skills/notes-v2/SKILL.md']]);
  assert.deepEqual(at('apps/web:deploy'), [['project', 'apps/web/.claude/skills/deploy/SKILL.md']]);
  assert.deepEqual(at('toolkit:lint'), [['user', '.claude/plugins/cache/acme/toolkit/1.0.0/skills/lint/SKILL.md']]);
  assert.deepEqual(at('missing'), []);
  assert.deepEqual(at('../../etc:passwd'), []);
  assert.deepEqual(at('..'), []);
});

test('a skill present in both the project and ~/.claude/skills is checked in both places', () => {
  const home = tmp('shomra-skill-home-');
  const project = tmp('shomra-skill-proj-');
  writeSkill(path.join(project, '.claude', 'skills', 'deploy'), 'deploy');
  writeSkill(path.join(home, '.claude', 'skills', 'deploy'), 'deploy');
  const found = resolveSkill({ raw: 'deploy', scope: null, name: 'deploy' }, { projectDir: project, cwd: project, home });
  assert.deepEqual(found.map((f) => f.scope), ['project', 'user']);
});

test('a cached verdict is served inside its TTL and only for the same content', () => {
  const file = path.join(tmp('shomra-skill-cache-'), 'skill-verdicts.json');
  const key = skillCacheKey({ url: 'http://x', apiKey: 'k', path: '.claude/skills/a/SKILL.md', content: 'one', siblings: [] });
  const changed = skillCacheKey({ url: 'http://x', apiKey: 'k', path: '.claude/skills/a/SKILL.md', content: 'two', siblings: [] });
  const moved = skillCacheKey({ url: 'http://x', apiKey: 'k', path: '.claude/skills/a/SKILL.md', content: 'one', siblings: ['.claude/skills/a/run.sh'] });
  assert.notEqual(key, changed);
  assert.notEqual(key, moved);
  rememberSkillVerdict(key, { decision: 'BLOCK', reason: 'banned' }, { file, now: 1_000, ttl: 60_000 });
  assert.deepEqual(cachedSkillVerdict(key, { file, now: 30_000, ttl: 60_000 }), { decision: 'BLOCK', reason: 'banned' });
  assert.equal(cachedSkillVerdict(key, { file, now: 61_000, ttl: 60_000 }), null);
  assert.equal(cachedSkillVerdict(changed, { file, now: 30_000, ttl: 60_000 }), null);
  fs.writeFileSync(file, 'not json');
  assert.equal(cachedSkillVerdict(key, { file, now: 30_000, ttl: 60_000 }), null);
});

test('a skill the gate refuses is denied before it loads, and the repeat is answered from the cache', async () => {
  const home = tmp('shomra-skill-e2e-');
  writeSkill(path.join(home, '.claude', 'skills', 'pdf'), 'pdf');
  fs.writeFileSync(path.join(home, '.claude', 'skills', 'pdf', 'extract.py'), 'print(1)\n');
  const s = await serve(BANNED);
  try {
    const env = { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_BREAKER_MS: '0' };
    const payload = { tool_name: 'Skill', tool_input: { skill: 'pdf' }, cwd: home, session_id: 'sess-skill-1' };
    const first = await guard(payload, { home, env });
    assert.equal(first.decision, 'deny', first.stdout);
    assert.match(first.reason, /skill "pdf"/);
    assert.match(first.reason, /DENIED in your organization/);
    assert.equal(s.seen.checks.length, 1);
    const sent = s.seen.checks[0];
    assert.equal(sent.kind, 'skill');
    assert.equal(sent.path, '.claude/skills/pdf/SKILL.md');
    assert.match(sent.content, /name: pdf/);
    assert.deepEqual(sent.siblings, ['.claude/skills/pdf/extract.py']);
    assert.equal(sent.sessionId, 'sess-skill-1');
    assert.ok(s.seen.calls.some((c) => c.body.tool_name === 'Skill' && c.body.client_decision === 'BLOCK'), 'the refusal is recorded on the session');

    const again = await guard(payload, { home, env });
    assert.equal(again.decision, 'deny');
    assert.equal(s.seen.checks.length, 1, 'an unchanged skill is not re-checked');
  } finally {
    await s.close();
  }
});

test('an allowed skill passes, is not re-checked while unchanged, and is re-checked once it changes', async () => {
  const home = tmp('shomra-skill-e2e-');
  const project = tmp('shomra-skill-proj-');
  const file = writeSkill(path.join(project, '.claude', 'skills', 'deploy'), 'deploy');
  const s = await serve(ALLOW);
  try {
    const env = { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_BREAKER_MS: '0', CLAUDE_PROJECT_DIR: project };
    const payload = { tool_name: 'Skill', tool_input: { skill: 'deploy' }, cwd: project, session_id: 'sess-skill-2' };
    assert.equal((await guard(payload, { home, cwd: project, env })).decision, null);
    assert.equal((await guard(payload, { home, cwd: project, env })).decision, null);
    assert.equal(s.seen.checks.length, 1);
    assert.equal(s.seen.checks[0].path, '.claude/skills/deploy/SKILL.md');
    fs.appendFileSync(file, 'Then push to production.\n');
    assert.equal((await guard(payload, { home, cwd: project, env })).decision, null);
    assert.equal(s.seen.checks.length, 2, 'a changed skill is a new artifact');
  } finally {
    await s.close();
  }
});

test('a skill that cannot be found is not blocked and nothing is checked', async () => {
  const home = tmp('shomra-skill-e2e-');
  const s = await serve(BANNED);
  try {
    const out = await guard({ tool_name: 'Skill', tool_input: { skill: 'built-in-thing' }, cwd: home, session_id: 's' }, { home, env: { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_BREAKER_MS: '0' } });
    assert.equal(out.decision, null, out.stdout);
    assert.equal(out.code, 0);
    assert.match(out.stderr, /skill not checked: no SKILL\.md found for "built-in-thing"/);
    assert.equal(s.seen.checks.length, 0);
  } finally {
    await s.close();
  }
});

test('an unreachable gate lets the skill run unless the machine fails closed', async () => {
  const home = tmp('shomra-skill-e2e-');
  writeSkill(path.join(home, '.claude', 'skills', 'pdf'), 'pdf');
  const payload = { tool_name: 'Skill', tool_input: { skill: 'pdf' }, cwd: home, session_id: 's' };
  const env = { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300', SHOMRA_GUARD_BREAKER_MS: '0' };
  const open = await guard(payload, { home, env });
  assert.equal(open.decision, null, open.stdout);
  const strict = await guard(payload, { home, env: { ...env, SHOMRA_GUARD_STRICT: '1' } });
  assert.equal(strict.decision, 'deny');
  assert.match(strict.reason, /could not check the skill "pdf"/);
});

test('an agent credential alone does not ask the gate, which only accepts an org key', async () => {
  const home = tmp('shomra-skill-e2e-');
  writeSkill(path.join(home, '.claude', 'skills', 'pdf'), 'pdf');
  const s = await serve(BANNED);
  try {
    const out = await guard({ tool_name: 'Skill', tool_input: { skill: 'pdf' }, cwd: home, session_id: 's' }, { home, env: { SHOMRA_AGENT: `shm_agt_${crypto.randomBytes(8).toString('hex')}`, SHOMRA_URL: s.url, SHOMRA_GUARD_BREAKER_MS: '0' } });
    assert.equal(s.seen.checks.length, 0);
    assert.equal(out.code, 0);
  } finally {
    await s.close();
  }
});
