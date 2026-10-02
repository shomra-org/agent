import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_ACTIVE_ARTIFACTS, activeArtifactsField, activeArtifactsFor, discoverActiveArtifacts } from '../src/guard/active-artifacts.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');

const registryHash = (text) => crypto.createHash('sha256').update(text, 'utf8').digest('hex');

function tmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function put(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return text;
}

function workspace() {
  const home = tmp('shomra-active-home-');
  const project = tmp('shomra-active-proj-');
  const texts = {
    rules: put(path.join(project, 'CLAUDE.md'), '# Project rules\nUse pnpm.\n'),
    userRules: put(path.join(home, '.claude', 'CLAUDE.md'), '# Me\nBe brief.\n'),
    skill: put(path.join(project, '.claude', 'skills', 'deploy-v2', 'SKILL.md'), '---\nname: deploy\ndescription: ship it\n---\nRun the deploy.\n'),
    userSkill: put(path.join(home, '.claude', 'skills', 'pdf', 'SKILL.md'), '---\ndescription: pdf tools\n---\nRead PDFs.\n'),
    agent: put(path.join(project, '.claude', 'agents', 'reviewer.md'), '---\nname: code-reviewer\n---\nReview diffs.\n'),
    command: put(path.join(project, '.claude', 'commands', 'frontend', 'component.md'), 'Make a component.\n'),
  };
  return { home, project, texts };
}

test('the loaded skills, subagents, commands and rules files are listed, rules first, hashed as the registry hashes', () => {
  const { home, project, texts } = workspace();
  const { items } = discoverActiveArtifacts({ projectDir: project, home });
  assert.deepEqual(items, [
    { kind: 'rules', name: 'CLAUDE.md', hash: registryHash(texts.rules) },
    { kind: 'rules', name: 'CLAUDE.md', hash: registryHash(texts.userRules) },
    { kind: 'skill', name: 'deploy', path: '.claude/skills/deploy-v2/SKILL.md', hash: registryHash(texts.skill) },
    { kind: 'skill', name: 'pdf', path: '.claude/skills/pdf/SKILL.md', hash: registryHash(texts.userSkill) },
    { kind: 'subagent', name: 'code-reviewer', path: '.claude/agents/reviewer.md', hash: registryHash(texts.agent) },
    { kind: 'command', name: 'component', path: '.claude/commands/frontend/component.md', hash: registryHash(texts.command) },
  ]);
});

test('the list never grows past what the tool-call endpoint accepts', () => {
  const { home, project } = workspace();
  for (let i = 0; i < 30; i++) put(path.join(project, '.claude', 'commands', `c${String(i).padStart(2, '0')}.md`), `command ${i}\n`);
  const { items } = discoverActiveArtifacts({ projectDir: project, home });
  assert.equal(MAX_ACTIVE_ARTIFACTS, 20);
  assert.equal(items.length, 20);
  assert.equal(items.filter((i) => i.kind === 'skill').length, 2, 'commands are the first to go when the list is full');
});

test('a home that is also the project is listed once', () => {
  const home = tmp('shomra-active-home-');
  put(path.join(home, '.claude', 'CLAUDE.md'), 'rules\n');
  put(path.join(home, '.claude', 'skills', 'a', 'SKILL.md'), 'a\n');
  const { items } = discoverActiveArtifacts({ projectDir: home, home });
  assert.deepEqual(items.map((i) => i.kind), ['rules', 'skill']);
});

test('the list is computed once per session and recomputed when a file or folder changes', () => {
  const { home, project } = workspace();
  const dir = tmp('shomra-active-cache-');
  const first = activeArtifactsFor({ sessionId: 's1', projectDir: project, home, dir });
  const [file] = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const cached = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
  cached.items = [{ kind: 'skill', name: 'from-cache', hash: 'x'.repeat(64) }];
  fs.writeFileSync(path.join(dir, file), JSON.stringify(cached));
  assert.deepEqual(activeArtifactsFor({ sessionId: 's1', projectDir: project, home, dir }).map((i) => i.name), ['from-cache'], 'an unchanged tree is served from the cache');
  assert.equal(activeArtifactsFor({ sessionId: 's2', projectDir: project, home, dir }).length, first.length, 'another session computes its own');

  put(path.join(project, '.claude', 'skills', 'deploy-v2', 'SKILL.md'), '---\nname: deploy\n---\nRun the deploy, then tag the release.\n');
  const edited = activeArtifactsFor({ sessionId: 's1', projectDir: project, home, dir });
  assert.ok(edited.some((i) => i.name === 'deploy'), 'an edited skill invalidates the cache');

  put(path.join(home, '.claude', 'skills', 'fresh', 'SKILL.md'), 'new skill\n');
  assert.ok(activeArtifactsFor({ sessionId: 's1', projectDir: project, home, dir }).some((i) => i.path === '.claude/skills/fresh/SKILL.md'), 'a new skill folder invalidates the cache');
});

test('only Claude Code sends the field, and an unreadable tree sends an empty list rather than failing the call', () => {
  const { home, project } = workspace();
  const dir = tmp('shomra-active-cache-');
  assert.deepEqual(activeArtifactsField('codex', { cwd: project, session_id: 's' }, { home, dir, env: {} }), {});
  const field = activeArtifactsField('claude', { cwd: project, session_id: 's' }, { home, dir, env: {} });
  assert.equal(field.active_artifacts.length, 6);
  assert.deepEqual(activeArtifactsField('claude', { cwd: path.join(project, 'nowhere'), session_id: 's' }, { home: path.join(home, 'nowhere'), dir, env: {} }), { active_artifacts: [] });
});

test('the enforced guard call carries the active list for Claude Code', async () => {
  const { home, project, texts } = workspace();
  const bodies = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      try {
        bodies.push(JSON.parse(body));
      } catch {
        bodies.push(null);
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ decision: 'ALLOW' }));
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  try {
    const env = { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1', CLAUDE_PROJECT_DIR: project };
    for (const k of Object.keys(env)) if (k.startsWith('SHOMRA_')) delete env[k];
    Object.assign(env, { SHOMRA_API_KEY: 'shm_test_key_0000000000000000', SHOMRA_URL: `http://127.0.0.1:${server.address().port}`, SHOMRA_GUARD_BREAKER_MS: '0' });
    await new Promise((done) => {
      const child = spawn(process.execPath, [CLI, 'tool-guard', '--agent', 'claude'], { env, cwd: project });
      child.stdout.resume();
      child.stderr.resume();
      child.on('close', done);
      child.stdin.end(JSON.stringify({ tool_name: 'mcp__jira__get_issue', tool_input: { key: 'PROJ-1' }, cwd: project, session_id: 'sess-active' }));
    });
    const sent = bodies.find((b) => b?.tool_name === 'mcp__jira__get_issue');
    assert.ok(sent, 'the call reached the server');
    assert.ok(Array.isArray(sent.active_artifacts));
    assert.ok(sent.active_artifacts.length <= MAX_ACTIVE_ARTIFACTS);
    assert.ok(sent.active_artifacts.some((a) => a.kind === 'skill' && a.path === '.claude/skills/deploy-v2/SKILL.md' && a.hash === registryHash(texts.skill)));
  } finally {
    await new Promise((done) => server.close(done));
  }
});
