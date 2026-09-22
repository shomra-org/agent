import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { keyedFetch, redirectAllowed } from '../src/core/keyed-fetch.mjs';
import { breakerWindowOpen } from '../src/core/circuit-breaker.mjs';
import { guardStateTamper, insideGuardState, refuseOrAsk } from '../src/guard/self-protect.mjs';
import { forwardHeaders, localClientOnly } from '../src/commands/llm-proxy.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');

async function serve(handler) {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => handler(req, res, body));
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  return { port: server.address().port, close: () => new Promise((d) => server.close(d)) };
}

test('the org key never follows a redirect to another origin', async () => {
  const stolen = [];
  const evil = await serve((req, res) => { stolen.push(req.headers['x-shomra-key'] ?? null); res.end('{}'); });
  const good = await serve((req, res) => {
    res.writeHead(307, { location: `http://localhost:${evil.port}/steal` });
    res.end();
  });
  try {
    await assert.rejects(
      keyedFetch(`http://127.0.0.1:${good.port}/gate/tool-call`, { method: 'POST', headers: { 'X-Shomra-Key': 'shm_secret' }, body: '{}' }),
      /refused a redirect/,
    );
    assert.deepEqual(stolen, []);
  } finally {
    await evil.close();
    await good.close();
  }
});

test('a same-origin redirect is still followed with the key', async () => {
  const seen = [];
  const s = await serve((req, res) => {
    seen.push([req.url, req.headers['x-shomra-key'] ?? null]);
    if (req.url === '/old') {
      res.writeHead(308, { location: '/new' });
      return res.end();
    }
    res.end('{"ok":true}');
  });
  try {
    const res = await keyedFetch(`http://127.0.0.1:${s.port}/old`, { method: 'POST', headers: { 'X-Shomra-Key': 'k' }, body: '{}' });
    assert.equal(res.status, 200);
    assert.deepEqual(seen, [['/old', 'k'], ['/new', 'k']]);
  } finally {
    await s.close();
  }
});

test('only an upgrade to https on the same host is allowed across schemes', () => {
  assert.equal(redirectAllowed(new URL('http://api.example.com/x'), new URL('https://api.example.com/x')), true);
  assert.equal(redirectAllowed(new URL('https://api.example.com/x'), new URL('http://api.example.com/x')), false);
  assert.equal(redirectAllowed(new URL('https://api.example.com/x'), new URL('https://evil.example.com/x')), false);
  assert.equal(redirectAllowed(new URL('http://api.example.com:8080/x'), new URL('https://api.example.com/x')), false);
});

test('a breaker stamped in the future does not hold the server tier off', () => {
  const now = 1_000_000;
  assert.equal(breakerWindowOpen(now - 1000, now, 30_000), true);
  assert.equal(breakerWindowOpen(now + 60_000, now, 30_000), false);
  assert.equal(breakerWindowOpen(9e15, now, 30_000), false);
  assert.equal(breakerWindowOpen(now - 31_000, now, 30_000), false);
  assert.equal(breakerWindowOpen('1', now, 30_000), false);
  assert.equal(breakerWindowOpen(now, now, 0), false);
});

test('writes into the guard state directory are tamper, reads and ordinary work are not', () => {
  const home = '/home/dev';
  const opts = { cwd: '/home/dev/project', home, stateDir: '/home/dev/.shomra' };
  const hit = (tool, input) => !!guardStateTamper(tool, input, opts);

  assert.equal(hit('Write', { file_path: '/home/dev/.shomra/config.json', content: '{}' }), true);
  assert.equal(hit('Edit', { file_path: '~/.shomra/guard-breaker.json', old_string: 'a', new_string: 'b' }), true);
  assert.equal(hit('Write', { file_path: '../.shomra/guard-subject-types.json', content: '{}' }), true);
  assert.equal(hit('Bash', { command: 'echo \'{"at":99999999999999}\' > ~/.shomra/guard-breaker.json' }), true);
  assert.equal(hit('Bash', { command: 'rm -rf ~/.shomra' }), true);
  assert.equal(hit('Bash', { command: 'rm $HOME/.shomra/guard-ledger.json' }), true);
  assert.equal(hit('Bash', { command: 'cp /tmp/x.json /home/dev/.shomra/config.json' }), true);
  assert.equal(hit('apply_patch', { input: '*** Begin Patch\n*** Update File: /home/dev/.shomra/config.json\n@@\n-a\n+b\n*** End Patch' }), true);

  assert.equal(hit('mcp__filesystem__write_file', { path: '/home/dev/.shomra/config.json', content: '{}' }), true);
  assert.equal(hit('mcp__filesystem__move_file', { source: '/tmp/x', destination: '/home/dev/.shomra/config.json' }), true);
  assert.equal(hit('delete_file', { target_file: '/home/dev/.shomra/guard-ledger.json' }), true);

  assert.equal(hit('Read', { file_path: '/home/dev/.shomra/config.json' }), false);
  assert.equal(hit('mcp__filesystem__read_file', { path: '/home/dev/.shomra/config.json' }), false);
  assert.equal(hit('Bash', { command: 'ls -la ~/.shomra' }), false);
  assert.equal(hit('Bash', { command: 'shomra init --url https://api.shomra.ai' }), false);
  assert.equal(hit('Bash', { command: 'rm -rf node_modules && npm ci' }), false);
  assert.equal(hit('Write', { file_path: '/home/dev/project/.shomra/policy.yml', content: 'x' }), false);
  assert.equal(hit('Write', { file_path: '/home/dev/project/src/app.ts', content: 'x' }), false);
  assert.equal(insideGuardState('/home/dev/.shomra-backup/config.json', opts), false);
});

test('an agent that cannot ask a person is refused rather than waved through', () => {
  assert.equal(refuseOrAsk('claude', false), 'ask');
  assert.equal(refuseOrAsk('windsurf', false), 'deny');
  assert.equal(refuseOrAsk('claude', true), 'deny');
});

function runGuard(home, payload, env = {}) {
  const base = { ...process.env, USERPROFILE: home, HOME: home, NO_COLOR: '1' };
  for (const k of Object.keys(base)) if (k.startsWith('SHOMRA_')) delete base[k];
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, 'tool-guard', '--agent', 'claude'], { env: { ...base, ...env }, cwd: home });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.resume();
    child.on('close', () => {
      let body = null;
      try {
        body = JSON.parse(stdout || '{}');
      } catch {
        body = null;
      }
      done({ decision: body?.hookSpecificOutput?.permissionDecision ?? null, reason: body?.hookSpecificOutput?.permissionDecisionReason ?? '' });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

test('the hook asks a person before the agent rewrites the guard breaker', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-tamper-'));
  const out = await runGuard(home, {
    tool_name: 'Bash',
    tool_input: { command: `echo '{"at":99999999999999}' > ${path.join(home, '.shomra', 'guard-breaker.json')}` },
    cwd: home,
  }, { SHOMRA_API_KEY: 'shm_test_key_0000000000000000', SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  assert.equal(out.decision, 'ask');
  assert.match(out.reason, /guard state/);
});

test('a forged future breaker no longer skips the server', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-breaker-'));
  fs.mkdirSync(path.join(home, '.shomra'), { recursive: true });
  fs.writeFileSync(path.join(home, '.shomra', 'guard-breaker.json'), JSON.stringify({ at: Date.now() + 86_400_000 }));
  let hits = 0;
  const s = await serve((req, res) => {
    hits += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'BLOCK', reason: 'org policy' }));
  });
  try {
    const out = await runGuard(home, { tool_name: 'mcp__jira__get_issue', tool_input: { key: 'PROJ-1' }, cwd: home }, {
      SHOMRA_API_KEY: 'shm_test_key_0000000000000000',
      SHOMRA_URL: `http://127.0.0.1:${s.port}`,
      SHOMRA_GUARD_TIMEOUT_MS: '3000',
    });
    assert.ok(hits >= 1, 'the server tier was skipped');
    assert.equal(out.decision, 'deny');
  } finally {
    await s.close();
  }
});

test('the LLM proxy serves loopback clients only', () => {
  assert.equal(localClientOnly({ host: '127.0.0.1:4141' }), true);
  assert.equal(localClientOnly({ host: 'localhost:4141' }), true);
  assert.equal(localClientOnly({ host: '[::1]:4141' }), true);
  assert.equal(localClientOnly({ host: '127.0.0.1:4141', origin: 'http://localhost:5173' }), true);
  assert.equal(localClientOnly({ host: 'rebind.attacker.example:4141' }), false);
  assert.equal(localClientOnly({ host: '127.0.0.1:4141', origin: 'https://attacker.example' }), false);
  assert.equal(localClientOnly({ host: '127.0.0.1:4141', origin: 'null' }), false);
  assert.equal(localClientOnly({}), false);
});

test('the configured agent credential wins over one a local client sends', () => {
  const ctx = { apiKey: 'org', actor: 'host/user', sessionId: 's', agentId: 'shm_agt_configured' };
  assert.equal(forwardHeaders({ 'x-shomra-agent': 'impostor' }, ctx)['x-shomra-agent'], 'shm_agt_configured');
  assert.equal(forwardHeaders({ 'x-shomra-agent': 'shm_agt_app' }, { ...ctx, agentId: null })['x-shomra-agent'], 'shm_agt_app');
  assert.equal(forwardHeaders({ 'x-shomra-key': 'caller' }, ctx)['x-shomra-key'], 'org');
});
