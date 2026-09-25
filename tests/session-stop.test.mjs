import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { stoppedNote } from '../src/guard/emit.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-stop-'));
const KEY = 'shm_test_key_0000000000000000';
const STOPPED = { id: 's1', kind: 'SESSION', by: 'ana@example.com', at: '2026-09-25T10:00:00.000Z', reason: null, sentence: 'This session was stopped by ana@example.com. Every call in it is refused until the stop is lifted, and an approval cannot release it.' };

function run(command, payload, env) {
  const base = { ...process.env, USERPROFILE: home, HOME: home, NO_COLOR: '1' };
  for (const k of Object.keys(base)) if (k.startsWith('SHOMRA_')) delete base[k];
  fs.rmSync(path.join(home, '.shomra', 'guard-breaker.json'), { force: true });
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, command, '--agent', 'claude'], { env: { ...base, ...env }, cwd: home });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.resume();
    child.on('close', () => {
      let body = null;
      try { body = JSON.parse(stdout || '{}'); } catch { body = null; }
      done(body);
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

async function serve(answer) {
  const server = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(answer));
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((d) => server.close(d)) };
}

const CALL = { tool_name: 'mcp__jira__get_issue', tool_input: { key: 'PROJ-1' }, cwd: home, session_id: 'sess-1' };
const PROMPT = { prompt: 'keep going', cwd: home, session_id: 'sess-1' };

test('a refusal in a stopped session ends the agent’s turn, not just the one call', async () => {
  const s = await serve({ decision: 'BLOCK', reason: STOPPED.sentence, stopped: STOPPED });
  try {
    const out = await run('tool-guard', CALL, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(out?.hookSpecificOutput?.permissionDecision, 'deny');
    assert.equal(out?.continue, false, `expected the turn to end; got ${JSON.stringify(out)}`);
    assert.match(out?.stopReason ?? '', /stopped this session/);
  } finally {
    await s.close();
  }
});

test('an ordinary refusal still leaves the agent free to try something else', async () => {
  const s = await serve({ decision: 'BLOCK', reason: 'Blocked by org policy.' });
  try {
    const out = await run('tool-guard', CALL, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(out?.hookSpecificOutput?.permissionDecision, 'deny');
    assert.equal(out?.continue, undefined);
  } finally {
    await s.close();
  }
});

test('a prompt in a stopped session ends the turn before the model sees it', async () => {
  const s = await serve({ decision: 'BLOCK', reason: STOPPED.sentence, stopped: STOPPED });
  try {
    const out = await run('prompt-guard', PROMPT, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(out?.continue, false, `expected the turn to end; got ${JSON.stringify(out)}`);
    assert.equal(out?.decision, 'block');
  } finally {
    await s.close();
  }
});

test('the stop sentence is shown as text, never as terminal control characters', () => {
  const note = stoppedNote({ sentence: 'stopped\u001b[2J by ‮ana' });
  assert.ok(note && !/[\u001b‮]/.test(note));
  assert.equal(stoppedNote({}), undefined);
  assert.equal(stoppedNote(null), undefined);
});
