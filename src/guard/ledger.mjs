
import fs from 'node:fs';
import path from 'node:path';

export const MAX_GAPS = 50;

export const STALE_WINDOW_MS = 6 * 60 * 60 * 1000;

export const emptyLedger = () => ({ open: null, pending: [] });

export function openWindow(state, { at, reason }) {
  const s = state ?? emptyLedger();
  if (s.open) return s;
  return { ...s, open: { openedAt: at, reason: String(reason || 'unknown').slice(0, 200), unscreened: 0, local: 0 } };
}

export function countCall(state, { at, kind, reason }) {
  const s = openWindow(state, { at, reason: reason || 'breaker-open' });
  const open = { ...s.open };
  if (kind === 'unscreened') open.unscreened += 1;
  else open.local += 1;
  return { ...s, open };
}

export function closeWindow(state, { at, staleMs = STALE_WINDOW_MS } = {}) {
  const s = state ?? emptyLedger();
  if (!s.open) return s;
  const { openedAt, reason, unscreened, local } = s.open;
  if (!unscreened && !local) return { ...s, open: null };

  const stale = at - openedAt > staleMs;
  const gap = {
    opened_at: new Date(openedAt).toISOString(),
    ...(stale ? {} : { closed_at: new Date(at).toISOString() }),
    unscreened_calls: unscreened,
    locally_decided_calls: local,
    reason: stale ? `${reason} (end not observed)` : reason,
  };
  return { open: null, pending: compact([...s.pending, gap]) };
}

export function compact(gaps, max = MAX_GAPS) {
  if (gaps.length <= max) return gaps;
  const overflow = gaps.slice(0, gaps.length - max + 1);
  const kept = gaps.slice(gaps.length - max + 1);
  const anyOpen = overflow.some((g) => !g.closed_at);
  const lastClose = overflow.reduce((acc, g) => (g.closed_at && (!acc || g.closed_at > acc) ? g.closed_at : acc), null);
  const merged = {
    opened_at: overflow[0].opened_at,
    ...(anyOpen || !lastClose ? {} : { closed_at: lastClose }),
    unscreened_calls: overflow.reduce((n, g) => n + (g.unscreened_calls || 0), 0),
    locally_decided_calls: overflow.reduce((n, g) => n + (g.locally_decided_calls || 0), 0),
    reason: `${overflow.length} earlier windows, merged`,
  };
  return [merged, ...kept];
}

export function envelope(state, { version } = {}) {
  const s = state ?? emptyLedger();
  return { gaps: s.pending.slice(0, MAX_GAPS), ...(version ? { client_version: String(version).slice(0, 40) } : {}) };
}

export function ack(state, sent) {
  const s = state ?? emptyLedger();
  const done = new Set((sent ?? []).map((g) => g.opened_at));
  return { ...s, pending: s.pending.filter((g) => !done.has(g.opened_at)) };
}

export function makeLedgerStore(configDir, { version } = {}) {
  const file = path.join(configDir, 'guard-ledger.json');

  const read = () => {
    try {
      const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
      return { open: raw.open ?? null, pending: Array.isArray(raw.pending) ? raw.pending : [] };
    } catch {
      return emptyLedger();
    }
  };

  const write = (state) => {
    try {
      fs.mkdirSync(configDir, { recursive: true });

      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(state));
      fs.renameSync(tmp, file);
    } catch {

    }
  };

  const update = (fn) => {
    const next = fn(read());
    write(next);
    return next;
  };

  return {
    file,
    read,
    write,

    count: (kind, reason) => update((s) => countCall(s, { at: Date.now(), kind, reason })),

    close: () => update((s) => closeWindow(s, { at: Date.now() })),

    envelope: () => envelope(read(), { version }),

    ack: (sent) => update((s) => ack(s, sent)),
  };
}
