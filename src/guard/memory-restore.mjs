import fs from 'node:fs';
import path from 'node:path';
import { isMemoryPath } from '../commands/memory-scan.mjs';
import { readLedger, recordLedger, sha256 } from './memory-write.mjs';
import { gateMachine } from '../core/api-client.mjs';
import { keyedFetch } from '../core/keyed-fetch.mjs';
import { guardTimeoutMs } from '../core/circuit-breaker.mjs';

export const MAX_RESTORE_BYTES = 256 * 1024;
export const MAX_RESTORES = 20;

const readOrNull = (p) => {
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
};

export function restoreVerdict(item, { read = readOrNull, ledger = readLedger } = {}) {
  const raw = typeof item?.path === 'string' ? item.path : '';
  const p = raw ? path.resolve(raw) : '';
  if (!raw || !path.isAbsolute(raw)) return { ok: false, reason: 'the path it named is not an absolute path on this machine' };
  if (!isMemoryPath(p)) return { ok: false, reason: 'the path it named is not an agent memory or rules file, so the hook will not write it' };
  if (!ledger(p)) return { ok: false, reason: 'the hook has never seen this file on this machine' };
  if (typeof item.content !== 'string' || Buffer.byteLength(item.content, 'utf8') > MAX_RESTORE_BYTES) return { ok: false, reason: 'the version it sent is missing or too large to write back' };
  if (sha256(item.content) !== item.hash) return { ok: false, reason: 'the version it sent does not match its own hash' };
  const current = read(p);
  if (current == null) return { ok: false, reason: 'the file is no longer on disk' };
  if (sha256(current) !== item.replaces) return { ok: false, reason: 'the file changed since the rollback was asked for, so writing it back could lose someone’s edits' };
  return { ok: true, path: p };
}

export function writeRestored(p, content) {
  let mode;
  try {
    mode = fs.statSync(p).mode & 0o777;
  } catch {
    mode = 0o600;
  }
  const tmp = `${p}.${process.pid}.shomra-restore`;
  fs.writeFileSync(tmp, content, { mode });
  fs.renameSync(tmp, p);
  return sha256(fs.readFileSync(p, 'utf8'));
}

async function call(url, apiKey, route, init = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
  try {
    const res = await keyedFetch(`${url}${route}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close', ...(init.headers ?? {}) },
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    return await res.json().catch(() => ({}));
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function applyPendingRestores({ url, apiKey, read = readOrNull, write = writeRestored, ledger = readLedger, record = recordLedger } = {}) {
  const out = { applied: [], refused: [], unread: false };
  if (!url || !apiKey) return out;
  const machine = gateMachine();
  if (!machine.machineId) return out;
  const query = new URLSearchParams({ machineId: machine.machineId, hostname: machine.hostname ?? '' });
  const listed = await call(url, apiKey, `/memory/restores/pending?${query}`);
  if (!listed || !Array.isArray(listed.restores)) {
    out.unread = true;
    return out;
  }
  for (const item of listed.restores.slice(0, MAX_RESTORES)) {
    const verdict = restoreVerdict(item, { read, ledger });
    let ack;
    if (verdict.ok) {
      try {
        const written = write(verdict.path, item.content);
        record(verdict.path, [written]);
        ack = { applied: true, contentHash: written };
        out.applied.push(verdict.path);
      } catch (e) {
        ack = { applied: false, reason: `the file could not be written (${String(e?.code ?? e?.message ?? 'error').slice(0, 60)})` };
        out.refused.push({ path: item.path, reason: ack.reason });
      }
    } else {
      ack = { applied: false, reason: verdict.reason };
      out.refused.push({ path: item.path, reason: verdict.reason });
    }
    await call(url, apiKey, `/memory/restores/${encodeURIComponent(String(item.storeId ?? ''))}/ack`, {
      method: 'POST',
      body: JSON.stringify({ ...ack, machineId: machine.machineId, hostname: machine.hostname }),
    });
  }
  return out;
}

export function restoreSummary(result) {
  const lines = [];
  if (result.applied.length) lines.push(`Restored ${result.applied.length} rolled-back memory file${result.applied.length === 1 ? '' : 's'}: ${result.applied.join(', ')}`);
  for (const r of result.refused) lines.push(`Did not restore ${r.path}: ${r.reason}.`);
  if (result.unread) lines.push('Could not read which memory files were rolled back, so none were restored.');
  return lines;
}

export async function cmdMemoryRestore() {
  const { loadConfig, resolveSettings } = await import('../core/config.mjs');
  const settings = resolveSettings(loadConfig());
  if (!settings.apiKey) {
    console.error('Shomra is not configured on this machine. Run: shomra init --key shm_…');
    process.exit(1);
  }
  const result = await applyPendingRestores({ url: settings.url, apiKey: settings.apiKey });
  const lines = restoreSummary(result);
  console.log(lines.length ? lines.join('\n') : 'No rolled-back memory files are waiting for this machine.');
  process.exit(result.unread || result.refused.length ? 1 : 0);
}
