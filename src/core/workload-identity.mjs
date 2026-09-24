import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from './config.mjs';
import { keyedFetch } from './keyed-fetch.mjs';

export const EXCHANGE_PATH = '/public/agents/federated-credential';
export const WORKLOAD_SOURCES = ['github', 'gitlab', 'kubernetes'];
const RENEW_BEFORE_MS = 5 * 60_000;
const TIMEOUT_MS = 3_000;
const DEFAULT_K8S_TOKEN = '/var/run/secrets/shomra/token';

export function workloadSource(env = process.env) {
  const v = String(env.SHOMRA_WORKLOAD ?? '').trim().toLowerCase();
  return WORKLOAD_SOURCES.includes(v) ? v : null;
}

export function workloadCachePath(dir = CONFIG_DIR) {
  return path.join(dir, 'workload-credential.json');
}

export function readCachedCredential(file, { url, source, audience, now = Date.now() }) {
  try {
    const c = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (c?.url !== url || c?.source !== source || c?.audience !== audience) return null;
    if (typeof c.credential !== 'string' || !c.credential.startsWith('shm_agt_')) return null;
    return Date.parse(c.expiresAt) - now > RENEW_BEFORE_MS ? c.credential : null;
  } catch {
    return null;
  }
}

export function writeCachedCredential(file, entry) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(entry), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

async function timed(url, init) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    return await keyedFetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function platformToken(source, audience, env = process.env) {
  if (source === 'github') {
    const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!url || !bearer) throw new Error('no GitHub Actions identity token is available - give the job `permissions: id-token: write`');
    const res = await timed(`${url}&audience=${encodeURIComponent(audience)}`, { headers: { Authorization: `bearer ${bearer}` } });
    const body = res.ok ? await res.json().catch(() => null) : null;
    if (typeof body?.value !== 'string') throw new Error(`GitHub did not issue an identity token (HTTP ${res.status})`);
    return body.value;
  }
  if (source === 'gitlab') {
    const token = String(env.SHOMRA_ID_TOKEN ?? '').trim();
    if (!token) throw new Error('no GitLab identity token - add `id_tokens: SHOMRA_ID_TOKEN` with this org’s audience to the job');
    return token;
  }
  return fs.readFileSync(String(env.SHOMRA_TOKEN_FILE ?? '').trim() || DEFAULT_K8S_TOKEN, 'utf8').trim();
}

export async function exchangeWorkloadToken(url, token) {
  const res = await timed(`${url}${EXCHANGE_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Connection: 'close' },
    body: JSON.stringify({ token }),
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || typeof body?.credential !== 'string' || !body.credential.startsWith('shm_agt_')) {
    throw new Error(body?.message ?? `the exchange answered HTTP ${res.status}`);
  }
  return body;
}

export async function workloadCredential({ url, env = process.env, file = workloadCachePath(), now = Date.now(), onError } = {}) {
  const source = workloadSource(env);
  const audience = String(env.SHOMRA_AUDIENCE ?? '').trim();
  if (!source || !audience || !url) return null;
  const cached = readCachedCredential(file, { url, source, audience, now });
  if (cached) return cached;
  try {
    const minted = await exchangeWorkloadToken(url, await platformToken(source, audience, env));
    writeCachedCredential(file, { url, source, audience, credential: minted.credential, expiresAt: minted.expiresAt });
    return minted.credential;
  } catch (e) {
    onError?.(e);
    return null;
  }
}
