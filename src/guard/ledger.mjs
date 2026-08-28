/**
 * ─── THE FAIL-OPEN LEDGER (client half) ─────────────────────────────────────
 *
 * ── Why this exists ─────────────────────────────────────────────────────────
 *
 * The pre-tool-call guard FAILS OPEN, and it has to: an agent that hard-stops
 * because a SaaS backend is unreachable is an agent nobody keeps installed. The
 * breaker in `shomra.mjs` makes that cheap — once the backend times out, the
 * next calls skip the round-trip entirely for a cooldown window.
 *
 * ⚠ THE CONSEQUENCE IS THAT AN OUTAGE IS INVISIBLE ON THE SERVER. Every runtime
 * claim Shomra makes counts rows the backend WROTE, so a breaker-open window
 * produces no rows at all — byte-for-byte what a quiet, clean window produces.
 * "The guard was down for six hours" and "the guard saw nothing dangerous" are
 * the same evidence, and a reader takes the reassuring one.
 *
 * This module is the other end of `src/gate/enforcement-availability.ts` in the
 * backend. It remembers what this machine did while it was blind, and hands it
 * over on the next call that gets through — turning an absence of evidence into
 * evidence of an absence.
 *
 * ── ⚠ THE RULES ─────────────────────────────────────────────────────────────
 *
 * 1. **The envelope is sent ALWAYS, even empty.** Its PRESENCE is what tells the
 *    backend this client is CAPABLE of reporting an outage. An old client sends
 *    nothing, and nothing is also what a healthy client would send if this were
 *    "optimised" to omit the empty case — at which point every healthy estate
 *    becomes indistinguishable from an unobservable one. That change would look
 *    like a bandwidth win in review. It is the whole feature.
 *
 * 2. **Only calls that WOULD have been screened are counted.** A call the guard
 *    deliberately never escalates (benign, locally cleared, not policy-relevant
 *    — the bulk of them) is a stated design boundary, not a gap. Counting those
 *    would report every healthy machine as ~90% blind and the number would be
 *    ignored within a week.
 *
 * 3. **Counts are LOWER BOUNDS and are allowed to be.** Hooks run as concurrent
 *    short-lived processes, so two of them can read-modify-write this file at
 *    once and lose an increment. The backend already treats every count here as
 *    a floor for exactly this reason. ⚠ Do not "fix" that by making the writes
 *    heavier — a lock on the firewall's hot path costs more than the precision
 *    is worth, and the number is a floor either way.
 *
 * 4. **A window we cannot attest the END of closes as `null`, never as now().**
 *    If this machine slept, crashed, or was rebooted mid-outage, the window on
 *    disk is stale and we genuinely do not know when it ended. `closedAt: null`
 *    is the backend's "we were never told it ended" — which it grades as
 *    unmeasurable rather than as a zero-length blip.
 *
 * 5. **Nothing is ever DROPPED to stay under the cap.** Over the limit, the
 *    oldest windows MERGE into one aggregate that keeps their summed counts and
 *    spans their range. Truncating the list instead would silently delete
 *    evidence of blindness, which is the one direction this file must never
 *    fail in.
 *
 * PURE state machine + thin file I/O, split so the state rules are testable
 * without a filesystem (`tests/guard-ledger.test.mjs`).
 */
import fs from 'node:fs';
import path from 'node:path';

/** Max gaps in one envelope. Matches `@ArrayMaxSize(50)` on the backend DTO. */
export const MAX_GAPS = 50;

/**
 * How long an open window may sit on disk before we stop claiming to know when
 * it ended. Six hours: comfortably longer than any real outage a 30s breaker
 * cooldown produces, and short enough that a laptop closed overnight does not
 * come back claiming a 14-hour measured blackout.
 */
export const STALE_WINDOW_MS = 6 * 60 * 60 * 1000;

/** The empty ledger. */
export const emptyLedger = () => ({ open: null, pending: [] });

/* ── The state machine (pure) ───────────────────────────────────────────── */

/**
 * Begin a window, or leave an already-open one alone.
 *
 * ⚠ IDEMPOTENT ON PURPOSE. The breaker trips on every failed call, not just the
 * first, so a naive implementation would start a fresh window per call and
 * report a 200-call outage as 200 one-call outages — each with a tiny count,
 * none of them showing the real shape. The FIRST failure owns the window.
 */
export function openWindow(state, { at, reason }) {
  const s = state ?? emptyLedger();
  if (s.open) return s;
  return { ...s, open: { openedAt: at, reason: String(reason || 'unknown').slice(0, 200), unscreened: 0, local: 0 } };
}

/**
 * Record one call that ran without a server verdict.
 *
 * `kind` is `'local'` when the on-machine Tier-0 engine screened it (a weaker
 * screen — no org policy, no identity, no flow, no supply chain, no intent) and
 * `'unscreened'` when nothing did.
 *
 * ⚠ IT OPENS A WINDOW IF NONE IS OPEN. A count with nowhere to live would be
 * dropped, and the paths that skip the round-trip (`breakerOpen()`) do not
 * themselves fail, so they never call `openWindow` on their own.
 */
export function countCall(state, { at, kind, reason }) {
  const s = openWindow(state, { at, reason: reason || 'breaker-open' });
  const open = { ...s.open };
  if (kind === 'unscreened') open.unscreened += 1;
  else open.local += 1;
  return { ...s, open };
}

/**
 * End the open window and move it to the outbox.
 *
 * ⚠ A window that recorded NOTHING is discarded rather than reported. A breaker
 * that tripped on a call and healed before the next one cost no coverage, and a
 * zero-call gap row would be noise that makes the real ones harder to see.
 */
export function closeWindow(state, { at, staleMs = STALE_WINDOW_MS } = {}) {
  const s = state ?? emptyLedger();
  if (!s.open) return s;
  const { openedAt, reason, unscreened, local } = s.open;
  if (!unscreened && !local) return { ...s, open: null };
  // Rule 4: too old to attest an end for.
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

/**
 * Rule 5 — keep the list bounded WITHOUT losing counts.
 *
 * ⚠ The merged row deliberately carries `closed_at` only when every window it
 * absorbed had one. An aggregate spanning a window we could not attest the end
 * of is itself unattestable, and inventing a boundary for it would launder an
 * unmeasurable outage into a measured one.
 */
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

/**
 * The envelope to attach to a request.
 *
 * ⚠ ALWAYS AN OBJECT, and `gaps` is always an array — see rule 1. Returning
 * `undefined` when there is nothing to report is the single change that would
 * silently break the whole design.
 */
export function envelope(state, { version } = {}) {
  const s = state ?? emptyLedger();
  return { gaps: s.pending.slice(0, MAX_GAPS), ...(version ? { client_version: String(version).slice(0, 40) } : {}) };
}

/**
 * Drop the gaps a request confirmed delivery of.
 *
 * ⚠ Matched by `opened_at`, not by index or by count. A concurrent hook process
 * can append a new gap between building the envelope and acking it, and an
 * index-based drop would silently discard that one unreported. Re-sending a gap
 * the backend already has is free — it dedupes on (org, machine, openedAt).
 */
export function ack(state, sent) {
  const s = state ?? emptyLedger();
  const done = new Set((sent ?? []).map((g) => g.opened_at));
  return { ...s, pending: s.pending.filter((g) => !done.has(g.opened_at)) };
}

/* ── File I/O (thin) ────────────────────────────────────────────────────── */

/**
 * ⚠ EVERY OPERATION BELOW IS BEST-EFFORT AND SWALLOWS. This runs inside the
 * PreToolUse hook: a ledger that threw would break a tool call the guard had
 * already correctly allowed, which is a worse outcome than losing a count. The
 * counts are lower bounds by rule 3 regardless.
 */
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
      // ⚠ Atomic rename, not a bare write. Two hook processes writing this file
      // concurrently can lose an increment (rule 3, accepted) — but a torn file
      // would lose the WHOLE ledger, including windows already closed and
      // waiting to be reported. `.tmp` is per-process so the two cannot collide.
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(state));
      fs.renameSync(tmp, file);
    } catch {
      /* best-effort */
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
    /** A call ran with no server verdict. */
    count: (kind, reason) => update((s) => countCall(s, { at: Date.now(), kind, reason })),
    /** The backend answered — close any window and hand back what to send. */
    close: () => update((s) => closeWindow(s, { at: Date.now() })),
    /** The envelope for this request. Always present (rule 1). */
    envelope: () => envelope(read(), { version }),
    /** Confirm delivery. */
    ack: (sent) => update((s) => ack(s, sent)),
  };
}
