import os from 'node:os';
import { getMachineId, loadConfig } from './config.mjs';
import { clampInt } from './numbers.mjs';
import { VERSION } from './version.mjs';

export function gateMachine() {
  let machineId;
  try {
    machineId = loadConfig().machineId;
  } catch {

  }
  return { ...(machineId ? { machineId } : {}), hostname: os.hostname(), username: os.userInfo().username };
}

export function machineInfo(cfg) {
  return {
    machineId: getMachineId(cfg),
    hostname: os.hostname(),
    platform: process.platform,
    osRelease: os.release(),
    username: os.userInfo().username,
    agentVersion: VERSION,
  };
}

export async function api(url, key, route, body, opts = {}) {

  if (!url) throw new Error('no backend configured - set SHOMRA_URL or run `shomra init --url <your backend>`');

  const timeoutMs = opts.timeoutMs ?? clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 30000, 1000, 600000);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    const method = opts.method ?? 'POST';
    res = await fetch(`${url}${route}`, {
      method,

      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': key, Connection: 'close' },
      ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
      signal: ctrl.signal,
    });
  } catch (e) {
    if (e?.name === 'AbortError') throw new Error(`request timed out after ${timeoutMs}ms (raise SHOMRA_API_TIMEOUT_MS or check the backend)`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  if (!res.ok) {
    const msg = json?.message || json?.raw || res.statusText;
    const err = new Error(`${res.status} ${Array.isArray(msg) ? msg.join(', ') : msg}`);

    err.status = res.status;
    err.rejected = res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429;
    throw err;
  }
  return json;
}
