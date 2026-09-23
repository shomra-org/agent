const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,127}$/;
const DIGEST_RE = /^(?:sha256:)?([a-f0-9]{64})$/;

export function bareDigest(digest) {
  return DIGEST_RE.exec(String(digest ?? '').trim().toLowerCase())?.[1] ?? null;
}

export function digestMatches(installed, pinned) {
  const a = bareDigest(installed);
  const b = bareDigest(pinned);
  return !!a && !!b && a === b;
}

function pin(raw) {
  const model = typeof raw?.model === 'string' ? raw.model.trim() : '';
  if (!MODEL_RE.test(model)) return null;
  return { model, digest: bareDigest(raw.digest) };
}

export function readOrgPolicy(body) {
  if (!body || body.enabled !== true || !body.policy || typeof body.policy !== 'object') return null;
  const embed = pin(body.policy.embed);
  const chat = pin(body.policy.chat);
  if (!embed && !chat) return null;
  return { embed, chat, required: body.policy.required === true };
}

export async function fetchOrgPolicy({ url, apiKey, timeoutMs = 3_000, fetchImpl = fetch } = {}) {
  if (!url || !apiKey) return { state: 'not-enrolled', policy: null };
  try {
    const res = await fetchImpl(`${url}/gate/local-model`, { headers: { 'X-Shomra-Key': apiKey, Connection: 'close' }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return { state: 'unreadable', policy: null, status: res.status };
    const body = await res.json();
    if (body?.enabled !== true) return { state: 'not-on-plan', policy: null };
    const policy = readOrgPolicy(body);
    return { state: policy ? 'pinned' : 'none', policy };
  } catch {
    return { state: 'unreadable', policy: null };
  }
}

export function samePin(a, b) {
  const one = (x) => (x ? `${x.model}@${x.digest ?? ''}` : '');
  return !!a === !!b && (!a || (one(a.embed) === one(b.embed) && one(a.chat) === one(b.chat) && !!a.required === !!b.required));
}
