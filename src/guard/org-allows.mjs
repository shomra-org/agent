import { api } from '../core/api-client.mjs';
import { breakerOpen } from '../core/circuit-breaker.mjs';
import { ORG_ALLOWS_FILE, orgAllowsFetchedAt, writeOrgAllows } from './allows.mjs';

export const ORG_ALLOWS_TTL_MS = 10 * 60 * 1000;
export const ORG_ALLOWS_TIMEOUT_MS = 800;

export async function refreshOrgAllows({ url, apiKey, now = Date.now(), force = false, timeoutMs = ORG_ALLOWS_TIMEOUT_MS, file = ORG_ALLOWS_FILE } = {}) {
  if (!url || !apiKey) return false;
  if (!force && now - orgAllowsFetchedAt(file) < ORG_ALLOWS_TTL_MS) return false;
  if (!force && breakerOpen()) return false;
  try {
    const res = await api(url, apiKey, '/gate/allows', null, { method: 'GET', timeoutMs });
    writeOrgAllows(res?.allows ?? [], { url, now }, file);
    return true;
  } catch (e) {
    if (e?.status === 402 || e?.status === 403 || e?.status === 404) writeOrgAllows([], { url, now }, file);
    return false;
  }
}
