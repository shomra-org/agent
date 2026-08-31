









import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  MAX_GAPS,
  STALE_WINDOW_MS,
  ack,
  closeWindow,
  compact,
  countCall,
  emptyLedger,
  envelope,
  makeLedgerStore,
  openWindow,
} from '../src/guard/ledger.mjs';

const T0 = 1_700_000_000_000;



test('rule 1 - an empty ledger still produces an envelope', () => {
  const env = envelope(emptyLedger(), { version: '0.3.9' });
  assert.ok(env, 'the envelope object must exist even with nothing to report');
  assert.ok(Array.isArray(env.gaps), 'gaps must be an array, not undefined');
  assert.equal(env.gaps.length, 0);
  
  
  assert.equal(env.client_version, '0.3.9');
});

test('rule 1 - a null state still produces an envelope', () => {
  const env = envelope(null);
  assert.ok(env && Array.isArray(env.gaps));
});



test('openWindow is idempotent - the FIRST failure owns the window', () => {
  let s = openWindow(emptyLedger(), { at: T0, reason: 'network' });
  const firstOpenedAt = s.open.openedAt;
  s = openWindow(s, { at: T0 + 5_000, reason: 'timeout' });
  assert.equal(s.open.openedAt, firstOpenedAt, 'a later failure must not restart the window');
  assert.equal(s.open.reason, 'network', 'nor overwrite why it started');
  
  
});

test('countCall opens a window when none is open', () => {
  
  
  const s = countCall(emptyLedger(), { at: T0, kind: 'local' });
  assert.ok(s.open, 'counting must be able to start a window');
  assert.equal(s.open.local, 1);
});



test('Tier-0-screened and wholly-unscreened calls are counted apart', () => {
  let s = countCall(emptyLedger(), { at: T0, kind: 'local' });
  s = countCall(s, { at: T0 + 1, kind: 'local' });
  s = countCall(s, { at: T0 + 2, kind: 'unscreened' });
  assert.equal(s.open.local, 2);
  assert.equal(s.open.unscreened, 1);
  
  
});



test('a window with zero calls is discarded, not reported', () => {
  const s = closeWindow(openWindow(emptyLedger(), { at: T0, reason: 'timeout' }), { at: T0 + 100 });
  assert.equal(s.open, null);
  assert.equal(s.pending.length, 0, 'a breaker that healed before the next call cost no coverage');
});

test('a window with calls is reported, with both counts and a real duration', () => {
  let s = countCall(emptyLedger(), { at: T0, kind: 'local', reason: 'timeout' });
  s = countCall(s, { at: T0 + 10, kind: 'unscreened' });
  s = closeWindow(s, { at: T0 + 30_000 });
  assert.equal(s.pending.length, 1);
  const g = s.pending[0];
  assert.equal(g.locally_decided_calls, 1);
  assert.equal(g.unscreened_calls, 1);
  assert.equal(g.opened_at, new Date(T0).toISOString());
  assert.equal(g.closed_at, new Date(T0 + 30_000).toISOString());
  assert.equal(g.reason, 'timeout');
});



test('rule 4 - a stale window closes as UNKNOWN, never as now()', () => {
  let s = countCall(emptyLedger(), { at: T0, kind: 'unscreened', reason: 'network' });
  
  s = closeWindow(s, { at: T0 + STALE_WINDOW_MS + 1 });
  const g = s.pending[0];
  assert.equal(g.closed_at, undefined, 'no end may be invented for a window we did not observe end');
  assert.match(g.reason, /end not observed/, 'and the row says so');
  
  
});

test('a window inside the staleness horizon still reports a real end', () => {
  let s = countCall(emptyLedger(), { at: T0, kind: 'unscreened' });
  s = closeWindow(s, { at: T0 + STALE_WINDOW_MS - 1 });
  assert.ok(s.pending[0].closed_at, 'a window we watched end keeps its measured duration');
});



test('rule 5 - overflow MERGES, it never truncates', () => {
  const gaps = Array.from({ length: MAX_GAPS + 10 }, (_, i) => ({
    opened_at: new Date(T0 + i * 1000).toISOString(),
    closed_at: new Date(T0 + i * 1000 + 500).toISOString(),
    unscreened_calls: 1,
    locally_decided_calls: 2,
    reason: 'timeout',
  }));
  const out = compact(gaps);
  assert.ok(out.length <= MAX_GAPS, 'the list is bounded');
  const sumU = out.reduce((n, g) => n + g.unscreened_calls, 0);
  const sumL = out.reduce((n, g) => n + g.locally_decided_calls, 0);
  
  
  assert.equal(sumU, gaps.length * 1, 'no unscreened call is lost to compaction');
  assert.equal(sumL, gaps.length * 2, 'no locally-decided call is lost either');
  assert.match(out[0].reason, /merged/, 'the merged row says what it is');
});

test('rule 5 - a merge that absorbs an unattestable window stays unattestable', () => {
  const gaps = [
    { opened_at: new Date(T0).toISOString(), unscreened_calls: 1, locally_decided_calls: 0, reason: 'end not observed' },
    ...Array.from({ length: MAX_GAPS }, (_, i) => ({
      opened_at: new Date(T0 + (i + 1) * 1000).toISOString(),
      closed_at: new Date(T0 + (i + 1) * 1000 + 10).toISOString(),
      unscreened_calls: 1,
      locally_decided_calls: 0,
      reason: 'timeout',
    })),
  ];
  const out = compact(gaps);
  assert.equal(out[0].closed_at, undefined, 'inventing a boundary would launder an unmeasurable outage into a measured one');
});

test('compact leaves a list under the cap completely alone', () => {
  const gaps = [{ opened_at: new Date(T0).toISOString(), unscreened_calls: 1, locally_decided_calls: 0, reason: 'x' }];
  assert.deepEqual(compact(gaps), gaps);
});



test('ack drops what was sent and KEEPS what arrived meanwhile', () => {
  const sentGap = { opened_at: new Date(T0).toISOString(), unscreened_calls: 1, locally_decided_calls: 0, reason: 'a' };
  const raced = { opened_at: new Date(T0 + 1).toISOString(), unscreened_calls: 5, locally_decided_calls: 0, reason: 'b' };
  
  
  const s = ack({ open: null, pending: [sentGap, raced] }, [sentGap]);
  assert.equal(s.pending.length, 1);
  assert.equal(s.pending[0].opened_at, raced.opened_at);
});

test('ack tolerates an undefined payload', () => {
  const s = ack({ open: null, pending: [] }, undefined);
  assert.deepEqual(s.pending, []);
});



test('the store survives a corrupt file rather than throwing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-ledger-'));
  const store = makeLedgerStore(dir);
  fs.writeFileSync(store.file, '{not json');
  
  
  assert.deepEqual(store.read(), emptyLedger());
  assert.ok(store.envelope().gaps, 'and it still produces an envelope');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the store round-trips a window across processes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-ledger-'));
  
  const a = makeLedgerStore(dir, { version: '9.9.9' });
  a.count('local', 'timeout');
  a.count('local', 'timeout');
  
  const b = makeLedgerStore(dir, { version: '9.9.9' });
  b.count('unscreened', 'timeout');
  assert.equal(b.read().open.local, 2, 'the window persisted across processes');
  assert.equal(b.read().open.unscreened, 1);
  
  const c = makeLedgerStore(dir, { version: '9.9.9' });
  c.close();
  const env = c.envelope();
  assert.equal(env.gaps.length, 1);
  assert.equal(env.gaps[0].locally_decided_calls, 2);
  assert.equal(env.gaps[0].unscreened_calls, 1);
  assert.equal(env.client_version, '9.9.9');
  
  c.ack(env.gaps);
  assert.equal(c.envelope().gaps.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the store writes atomically - no torn file is left behind', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-ledger-'));
  const store = makeLedgerStore(dir);
  store.count('local', 'timeout');
  const strays = fs.readdirSync(dir).filter((f) => f.endsWith('.tmp'));
  assert.equal(strays.length, 0, 'the temp file is renamed, never left');
  assert.ok(JSON.parse(fs.readFileSync(store.file, 'utf8')).open, 'and the real file parses');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a reason is bounded - an error string never lands in the ledger unclipped', () => {
  const s = openWindow(emptyLedger(), { at: T0, reason: 'x'.repeat(5000) });
  assert.ok(s.open.reason.length <= 200);
});

/*
 * The screen tier the CLI asks the backend for.
 *
 * ⚠ FULL IS THE DEFAULT AND HAS TO BE. `fast` buys latency by SPENDING
 * COVERAGE - the backend times out every provider-backed screen inside a 100ms
 * budget and reports a `minimal` basis - so a caller must ASK for the cheaper
 * screen. A typo that silently sent `fast` would degrade every screen in the
 * estate while the verdicts kept arriving and looking the same.
 */
test('screen_tier is omitted unless the operator asks for the fast screen', async () => {
  const { buildGuardBody, screenTier } = await import('../src/guard/report.mjs');
  const norm = { tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: '/x', session_id: 's1' };

  delete process.env.SHOMRA_GUARD_TIER;
  assert.equal(screenTier(), undefined, 'unset means full');
  assert.ok(!('screen_tier' in buildGuardBody(norm, 'claude')), 'and the field is omitted, not sent as null');

  for (const bad of ['', 'full', 'FULL', 'quick', '1', 'true']) {
    process.env.SHOMRA_GUARD_TIER = bad;
    assert.equal(screenTier(), undefined, `"${bad}" is not the fast tier`);
  }

  for (const good of ['fast', 'FAST', ' Fast ']) {
    process.env.SHOMRA_GUARD_TIER = good;
    assert.equal(screenTier(), 'fast', `"${good}" asks for the fast screen`);
    assert.equal(buildGuardBody(norm, 'claude').screen_tier, 'fast', 'and it reaches the body');
  }
  delete process.env.SHOMRA_GUARD_TIER;
});
