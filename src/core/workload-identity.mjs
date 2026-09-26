import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from './config.mjs';
import { keyedFetch } from './keyed-fetch.mjs';

export const EXCHANGE_PATH = '/public/agents/federated-credential';
export const WORKLOAD_SOURCES = ['github', 'gitlab', 'kubernetes', 'entra', 'okta'];
const RENEW_BEFORE_MS = 5 * 60_000;
const TIMEOUT_MS = 3_000;
const DEFAULT_K8S_TOKEN = '/var/run/secrets/shomra/token';
const IMDS = 'http://169.254.169.254/metadata/identity/oauth2/token';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

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

function httpsBase(raw, fallback) {
  try {
    const u = new URL(String(raw ?? '').trim() || fallback);
    if (u.protocol !== 'https:' || u.username || u.password) return null;
    return u.href.endsWith('/') ? u.href : `${u.href}/`;
  } catch {
    return null;
  }
}

async function accessToken(res, who) {
  const body = res.ok ? await res.json().catch(() => null) : null;
  if (typeof body?.access_token !== 'string') throw new Error(`${who} did not issue a token (HTTP ${res.status})`);
  return body.access_token;
}

export async function entraToken(audience, env = process.env) {
  const tenant = String(env.AZURE_TENANT_ID ?? '').trim();
  const client = String(env.AZURE_CLIENT_ID ?? '').trim();
  const federated = String(env.AZURE_FEDERATED_TOKEN_FILE ?? '').trim();
  if (federated && tenant && client) {
    const authority = httpsBase(env.AZURE_AUTHORITY_HOST, 'https://login.microsoftonline.com/');
    if (!authority) throw new Error('AZURE_AUTHORITY_HOST must be an https URL, or the workload token would be sent in the clear');
    const form = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: client,
      scope: `${audience}/.default`,
      client_assertion_type: JWT_BEARER,
      client_assertion: fs.readFileSync(federated, 'utf8').trim(),
    });
    const res = await timed(`${authority}${encodeURIComponent(tenant)}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    return accessToken(res, 'Microsoft Entra');
  }
  const query = new URLSearchParams({ resource: audience });
  if (client) query.set('client_id', client);
  const endpoint = String(env.IDENTITY_ENDPOINT ?? '').trim();
  const secret = String(env.IDENTITY_HEADER ?? '').trim();
  if (endpoint && secret) {
    query.set('api-version', '2019-08-01');
    return accessToken(await timed(`${endpoint}?${query}`, { headers: { 'X-IDENTITY-HEADER': secret } }), 'The managed identity endpoint');
  }
  query.set('api-version', '2018-02-01');
  return accessToken(await timed(`${IMDS}?${query}`, { headers: { Metadata: 'true' } }), 'The Azure instance metadata service');
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
  if (source === 'entra' || source === 'okta') {
    const given = String(env.SHOMRA_ID_TOKEN ?? '').trim();
    if (given) return given;
    const file = String(env.SHOMRA_TOKEN_FILE ?? '').trim();
    if (file) return fs.readFileSync(file, 'utf8').trim();
    if (source === 'okta') throw new Error('no Okta token - point SHOMRA_TOKEN_FILE at the file the agent keeps its Okta token in, or set SHOMRA_ID_TOKEN');
    return entraToken(audience, env);
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
