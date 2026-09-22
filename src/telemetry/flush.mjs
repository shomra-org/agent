import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
import { CLI_ENTRY_PATH } from '../core/package-root.mjs';
import { VERSION } from '../core/version.mjs';
import { remoteRunner } from '../gate/environment.mjs';
import { isCi } from './consent.mjs';
import { SCHEMA, aggregateTicks } from './events.mjs';

export const DEFAULT_TELEMETRY_URL = 'https://shomra-backend-emgjg9b0fcdmc8hu.westeurope-01.azurewebsites.net/public/telemetry/cli';

export const FLUSH_INTERVAL_MS = 15 * 60_000;

export const FLUSH_BYTES = 128_000;

export const BATCH_MAX = 200;

export function telemetryUrl(env = process.env) {
  const v = String(env.SHOMRA_TELEMETRY_URL ?? '').trim().replace(/\/+$/, '');
  return /^https?:\/\//i.test(v) ? v : DEFAULT_TELEMETRY_URL;
}

export function ensureIdentity(t = {}) {
  return {
    installId: typeof t?.installId === 'string' && /^[0-9a-f-]{36}$/i.test(t.installId) ? t.installId : randomUUID(),
    salt: typeof t?.salt === 'string' && t.salt.length >= 16 ? t.salt : randomBytes(16).toString('hex'),
  };
}

export function whereRunning(env = process.env) {
  if (remoteRunner(env)) return 'remote';
  return isCi(env) ? 'ci' : 'local';
}

export function envelopeFor(events, { installId, level, env = process.env }) {
  return {
    schema: SCHEMA,
    install: installId,
    cli: VERSION,
    level,
    os: process.platform,
    arch: process.arch,
    node: process.versions.node,
    where: whereRunning(env),
    events,
  };
}

async function post(url, body, fetchImpl, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': `shomra-agent/${VERSION}`, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (res.ok) return 'sent';
    return res.status === 408 || res.status === 429 || res.status >= 500 ? 'retry' : 'refused';
  } catch {
    return 'retry';
  } finally {
    clearTimeout(timer);
  }
}

export async function flushTelemetry({ store, state, identity, url = telemetryUrl(), fetchImpl = globalThis.fetch, now = Date.now(), timeoutMs = 10_000, env = process.env }) {
  if (!state?.enabled) {
    store.discard();
    return { sent: 0, refused: 0, kept: 0, expired: 0, reason: state?.reason ?? 'off' };
  }
  if (!store.lock(now)) return { sent: 0, refused: 0, kept: 0, expired: 0, reason: 'another flush is running' };
  try {
    const expired = store.prune(now);
    let sent = 0;
    let refused = 0;
    let kept = 0;
    for (const file of store.claim(now)) {
      const events = aggregateTicks(store.read(file), path.basename(file));
      let outcome = 'sent';
      for (let i = 0; i < events.length && outcome !== 'retry'; i += BATCH_MAX) {
        const batch = envelopeFor(events.slice(i, i + BATCH_MAX), { installId: identity.installId, level: state.level, env });
        outcome = await post(url, batch, fetchImpl, timeoutMs);
        if (outcome === 'sent') {
          sent += batch.events.length;
          store.writeLastBatch(batch);
        } else if (outcome === 'refused') {
          refused += batch.events.length;
        }
      }
      if (outcome === 'retry') {
        kept += 1;
        break;
      }
      store.done(file);
    }
    return { sent, refused, kept, expired };
  } finally {
    store.unlock();
  }
}

export function maybeFlushInBackground({ store, now = Date.now(), env = process.env, spawnImpl = spawn } = {}) {
  if (!store || env.SHOMRA_TELEMETRY_CHILD === '1') return false;
  const bytes = store.queueBytes();
  if (!bytes) return false;
  if (now - store.lastFlushAttempt() < FLUSH_INTERVAL_MS && bytes < FLUSH_BYTES) return false;
  if (!store.markFlushAttempt(now)) return false;
  try {
    const child = spawnImpl(process.execPath, [CLI_ENTRY_PATH, 'telemetry', 'flush', '--quiet'], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
      env: { ...env, SHOMRA_TELEMETRY_CHILD: '1' },
    });
    child?.on?.('error', () => {});
    child?.unref?.();
    return true;
  } catch {
    return false;
  }
}
