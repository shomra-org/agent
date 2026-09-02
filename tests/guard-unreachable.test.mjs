import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * ⚠ THE ONE THING THAT MAKES A REFUSAL MEAN ANYTHING, tested end to end through
 * the real hook rather than through the functions it calls.
 *
 * The guard fails open on purpose. That is correct for a routine call and it is
 * an ENFORCEMENT BYPASS for a destructive one: pad a command until the screen
 * times out, or burst past the rate limit, and the call runs unscreened. Every
 * assertion here is about what happens when NO SERVER VERDICT ARRIVES, which is
 * the state a unit test of the detectors can never reach.
 *
 * These would all pass with the rung check deleted if they only asserted the
 * grading, so each one drives the CLI and reads what the AGENT would receive.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'shomra.mjs');
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-unreachable-'));

const SEVERE = { tool_name: 'Bash', tool_input: { command: 'rm -rf /var/lib/postgres/data' }, cwd: home };
const ROUTINE = { tool_name: 'Read', tool_input: { file_path: '/repo/README.md' }, cwd: home };
const FORCE_PUSH = { tool_name: 'Bash', tool_input: { command: 'git push --force origin main' }, cwd: home };
/* Routine, but it reaches the server: an MCP call always escalates, so this
 * carries the ledger without itself being a severe call under test. */
const ROUTINE_ESCALATED = { tool_name: 'mcp__jira__get_issue', tool_input: { key: 'PROJ-1' }, cwd: home };

/* ⚠ ASYNC ON PURPOSE. `spawnSync` blocks the event loop, so the stub server
 * created in this same process never accepts the connection and every
 * server-backed case reads as an outage - the exact state these tests exist to
 * tell apart from a real one. */
function guard(payload, env = {}) {
  const base = { ...process.env, USERPROFILE: home, HOME: home, NO_COLOR: '1' };
  for (const k of Object.keys(base)) if (k.startsWith('SHOMRA_')) delete base[k];
  for (const dir of [home, os.homedir()]) {
    fs.rmSync(path.join(dir, '.shomra', 'guard-breaker.json'), { force: true });
  }
  return new Promise((done) => {
    const child = spawn(process.execPath, [CLI, 'tool-guard', '--agent', 'claude'], {
      env: { ...base, ...env },
      cwd: home,
    });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.resume();
    child.on('close', (code) => {
      let body = null;
      try {
        body = JSON.parse(stdout || '{}');
      } catch {
        body = null;
      }
      done({
        code,
        stdout,
        decision: body?.hookSpecificOutput?.permissionDecision ?? null,
        reason: body?.hookSpecificOutput?.permissionDecisionReason ?? '',
      });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

/** A server that answers however the case needs, on a real port. */
async function serve(handler) {
  /* ⚠ Drain the request first. The hook posts a body and sends
   * `Connection: close`; a handler that answers without consuming it leaves the
   * socket open until the client's own timeout fires, which reads exactly like
   * an outage and makes every server-backed case here a false negative. */
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => handler(req, res, body));
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((d) => server.close(d)) };
}

const KEY = 'shm_test_key_0000000000000000';

test('a SEVERE call the guard could not screen ASKS a person, it does not silently allow', async () => {
  /* Nothing is listening on this port, so the fetch fails the way an outage does. */
  const out = await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  assert.equal(out.decision, 'ask', `expected ask, got ${out.decision} (${out.stdout})`);
  assert.match(out.reason, /could not screen/i);
});

test('…and the sentence says the call was NOT judged, rather than calling it dangerous', async () => {
  const out = await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  assert.match(out.reason, /Nothing has judged it/i);
  assert.doesNotMatch(out.reason, /\bmalicious\b|\battack\b/i);
});

test('a force push over a shared branch counts as severe — it was MATERIAL until the ladder was fixed', async () => {
  const out = await guard(FORCE_PUSH, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  assert.equal(out.decision, 'ask', `expected ask, got ${out.decision}`);
});

test('a ROUTINE call still flows when the guard is unreachable — this is what keeps the hook installed', async () => {
  const out = await guard(ROUTINE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  assert.equal(out.decision, null, `a routine call must not prompt; got ${out.stdout}`);
  assert.equal(out.code, 0);
});

test('SHOMRA_GUARD_FAILOPEN_SEVERE restores the old behaviour for an org that wants it', async () => {
  const out = await guard(SEVERE, {
    SHOMRA_API_KEY: KEY,
    SHOMRA_URL: 'http://127.0.0.1:9',
    SHOMRA_GUARD_TIMEOUT_MS: '300',
    SHOMRA_GUARD_FAILOPEN_SEVERE: '1',
  });
  assert.equal(out.decision, null, `expected the escape hatch to allow; got ${out.stdout}`);
});

test('a 429 is retried against Retry-After, and a served verdict is honoured', async () => {
  let hits = 0;
  const s = await serve((req, res) => {
    hits += 1;
    if (hits === 1) {
      res.writeHead(429, { 'retry-after': '0', 'content-type': 'application/json' });
      return res.end('{}');
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'BLOCK', reason: 'Blocked by org policy.' }));
  });
  try {
    const out = await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(hits, 2, 'the 429 must be retried once, not counted as an outage');
    assert.equal(out.decision, 'deny', `expected the retry's BLOCK to be honoured; got ${out.stdout}`);
  } finally {
    await s.close();
  }
});

test('a 429 that keeps coming does not trip the breaker — one burst must not switch the server off', async () => {
  const s = await serve((req, res) => {
    res.writeHead(429, { 'retry-after': '0', 'content-type': 'application/json' });
    res.end('{}');
  });
  try {
    const out = await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(out.decision, 'ask', 'an unscreened severe call still asks');
    assert.equal(
      fs.existsSync(path.join(os.homedir(), '.shomra', 'guard-breaker.json'))
        || fs.existsSync(path.join(home, '.shomra', 'guard-breaker.json')),
      false,
      'a rate limit is not an outage: tripping the breaker skips the server for the whole cooldown',
    );
  } finally {
    await s.close();
  }
});

test('a reachable server that ALLOWS is still an allow — the rung check only covers the unscreened case', async () => {
  const s = await serve((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'ALLOW' }));
  });
  try {
    const out = await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000' });
    assert.equal(out.decision, null, `a screened allow must not prompt; got ${out.stdout}`);
  } finally {
    await s.close();
  }
});

/**
 * ⚠⚠ THE LEDGER HAD NO PRODUCER. `guard/ledger.mjs` builds the fail-open window
 * the backend's EnforcementGap reads, and until now NOTHING in this repo called
 * countCall - so every client reported zero gaps forever. The backend then asks
 * whether a capable reporter exists, gets silence, and the estate reads "no
 * outages": a smoke detector reporting no fire with a dead battery.
 *
 * Every row here therefore asserts the SEAM, not the module. The module's own
 * unit tests were green the whole time it was inert.
 */
test('an unreachable screen opens a gap window on disk — an outage nothing recorded reads like a quiet one', async () => {
  await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
  const file = path.join(home, '.shomra', 'guard-ledger.json');
  assert.ok(fs.existsSync(file), 'no ledger file: the window was never opened');
  const state = JSON.parse(fs.readFileSync(file, 'utf8'));
  const counted = (state.open?.unscreened ?? 0) + (state.open?.local ?? 0);
  assert.ok(counted > 0 || (state.pending ?? []).length > 0, `nothing counted: ${JSON.stringify(state)}`);
});

test('the gap rides out on the next call that gets through, and the server sees it', async () => {
  let seen = null;
  const s = await serve((req, res, body) => {
    try {
      seen = JSON.parse(body).guard_ledger ?? seen;
    } catch {
      /* Not every request on this port is the guard call. */
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'ALLOW' }));
  });
  try {
    /* One outage to open a window, then one reachable call to carry it. The
     * breaker cooldown is switched off so the second call actually goes out. */
    await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
    await guard(ROUTINE_ESCALATED, {
      SHOMRA_API_KEY: KEY,
      SHOMRA_URL: s.url,
      SHOMRA_GUARD_TIMEOUT_MS: '4000',
      SHOMRA_GUARD_BREAKER_MS: '0',
    });
    assert.ok(seen, 'the request carried no guard_ledger at all');
    assert.ok(Array.isArray(seen.gaps), `guard_ledger has no gaps array: ${JSON.stringify(seen)}`);
    assert.ok(seen.gaps.length > 0, 'the window was opened but never handed over');
    const gap = seen.gaps[0];
    assert.ok(gap.opened_at, 'a gap with no opened_at cannot bound anything');
    assert.ok(
      (gap.unscreened_calls ?? 0) + (gap.locally_decided_calls ?? 0) > 0,
      `a gap that counted nothing says an outage happened and cost nothing: ${JSON.stringify(gap)}`,
    );
    assert.equal(typeof seen.client_version, 'string', 'the backend needs to know which client reported');
  } finally {
    await s.close();
  }
});

test('and it is acknowledged, so one outage is not re-reported forever', async () => {
  const s = await serve((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ decision: 'ALLOW' }));
  });
  try {
    await guard(SEVERE, { SHOMRA_API_KEY: KEY, SHOMRA_URL: 'http://127.0.0.1:9', SHOMRA_GUARD_TIMEOUT_MS: '300' });
    const env = { SHOMRA_API_KEY: KEY, SHOMRA_URL: s.url, SHOMRA_GUARD_TIMEOUT_MS: '4000', SHOMRA_GUARD_BREAKER_MS: '0' };
    await guard(ROUTINE_ESCALATED, env);
    await guard(ROUTINE_ESCALATED, env);
    const state = JSON.parse(fs.readFileSync(path.join(home, '.shomra', 'guard-ledger.json'), 'utf8'));
    assert.equal((state.pending ?? []).length, 0, `an acknowledged gap must not stay pending: ${JSON.stringify(state)}`);
  } finally {
    await s.close();
  }
});
