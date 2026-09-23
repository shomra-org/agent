export const DEFAULT_URLS = ['http://127.0.0.1:11434', 'http://127.0.0.1:1234', 'http://127.0.0.1:8080'];

const MAX_BODY_BYTES = 32 * 1024 * 1024;
const str = (v) => (typeof v === 'string' && v ? v : null);

export function normalizeUrl(url) {
  return String(url ?? '').trim().replace(/\/+$/, '').replace(/\/v1$/i, '');
}

export function urlLocality(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return 'invalid';
  }
  if (!/^https?:$/.test(u.protocol) || u.username || u.password) return 'invalid';
  const h = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h === '::1' || /^127\./.test(h) || h === 'host.docker.internal') return 'loopback';
  if (/^10\./.test(h) || /^192\.168\./.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || /^f[cd][0-9a-f]{2}:/.test(h) || /\.(local|lan|internal)$/.test(h)) return 'private';
  return 'remote';
}

async function readCapped(res, max) {
  if (!res.body) return '';
  const chunks = [];
  let total = 0;
  for await (const chunk of res.body) {
    total += chunk.length;
    if (total > max) throw new Error('the runtime answered with more data than a model reply can hold');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

export async function request(url, { method = 'GET', body, timeoutMs = 3_000, signal, maxBytes = MAX_BODY_BYTES } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(new Error('timeout')), timeoutMs);
  const onAbort = () => ctrl.abort(signal.reason);
  if (signal) {
    if (signal.aborted) ctrl.abort(signal.reason);
    else signal.addEventListener('abort', onAbort, { once: true });
  }
  try {
    const res = await fetch(url, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await readCapped(res, maxBytes);
    if (!res.ok) throw new Error(`HTTP ${res.status}${text ? `: ${text.replace(/\s+/g, ' ').slice(0, 160)}` : ''}`);
    return text ? JSON.parse(text) : {};
  } catch (error) {
    if (ctrl.signal.aborted) throw new Error(ctrl.signal.reason?.message === 'timeout' ? 'timeout' : 'aborted');
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener?.('abort', onAbort);
  }
}

export async function detectRuntime(url, { timeoutMs = 1_500 } = {}) {
  const base = normalizeUrl(url);
  try {
    const tags = await request(`${base}/api/tags`, { timeoutMs });
    if (Array.isArray(tags?.models)) {
      return {
        kind: 'ollama',
        url: base,
        models: tags.models.map((m) => ({ name: String(m.name ?? m.model ?? ''), digest: str(m.digest), family: str(m.details?.family), families: Array.isArray(m.details?.families) ? m.details.families.map(String) : [], size: Number(m.size) || null })).filter((m) => m.name),
      };
    }
  } catch {
  }
  try {
    const list = await request(`${base}/v1/models`, { timeoutMs });
    if (Array.isArray(list?.data)) return { kind: 'openai', url: base, models: list.data.map((m) => ({ name: String(m.id ?? ''), digest: null, family: null, families: [], size: null })).filter((m) => m.name) };
  } catch {
  }
  return null;
}

export async function findRuntime(urls = DEFAULT_URLS, opts) {
  for (const url of urls) {
    const rt = await detectRuntime(url, opts);
    if (rt) return rt;
  }
  return null;
}

function validVectors(rows, n) {
  if (!Array.isArray(rows) || rows.length !== n) throw new Error('the runtime returned the wrong number of embeddings');
  const dims = Array.isArray(rows[0]) ? rows[0].length : 0;
  if (!dims || rows.some((r) => !Array.isArray(r) || r.length !== dims || r.some((x) => typeof x !== 'number' || !Number.isFinite(x)))) {
    throw new Error('the runtime returned malformed embeddings - is this an embedding model?');
  }
  return rows;
}

export async function embed(rt, model, texts, { timeoutMs = 30_000, signal } = {}) {
  if (rt.kind === 'ollama') {
    const out = await request(`${rt.url}/api/embed`, { method: 'POST', body: { model, input: texts, truncate: true, keep_alive: '30m' }, timeoutMs, signal });
    return validVectors(out?.embeddings, texts.length);
  }
  const out = await request(`${rt.url}/v1/embeddings`, { method: 'POST', body: { model, input: texts }, timeoutMs, signal });
  const rows = Array.isArray(out?.data) ? [...out.data].sort((a, b) => (a?.index ?? 0) - (b?.index ?? 0)).map((d) => d?.embedding) : null;
  return validVectors(rows, texts.length);
}

export async function chat(rt, model, messages, { timeoutMs = 180_000, json = false, maxTokens = 4_096 } = {}) {
  if (rt.kind === 'ollama') {
    const out = await request(`${rt.url}/api/chat`, {
      method: 'POST',
      body: { model, messages, stream: false, keep_alive: '30m', options: { temperature: 0, num_predict: maxTokens, num_ctx: 16_384 }, ...(json ? { format: 'json' } : {}) },
      timeoutMs,
    });
    return String(out?.message?.content ?? '');
  }
  const out = await request(`${rt.url}/v1/chat/completions`, { method: 'POST', body: { model, messages, temperature: 0, max_tokens: maxTokens, stream: false }, timeoutMs });
  return String(out?.choices?.[0]?.message?.content ?? '');
}

export async function modelSurface(rt, model, { timeoutMs = 5_000 } = {}) {
  if (rt.kind === 'ollama') {
    const s = await request(`${rt.url}/api/show`, { method: 'POST', body: { model }, timeoutMs });
    const info = s?.model_info && typeof s.model_info === 'object' ? s.model_info : {};
    return { read: true, modelfile: str(s?.modelfile), template: str(s?.template), chatTemplate: str(info['tokenizer.chat_template']), capabilities: Array.isArray(s?.capabilities) ? s.capabilities.map(String) : null };
  }
  try {
    const p = await request(`${rt.url}/props`, { timeoutMs });
    const t = str(p?.chat_template);
    return { read: !!t, modelfile: null, template: null, chatTemplate: t, capabilities: null };
  } catch {
    return { read: false, modelfile: null, template: null, chatTemplate: null, capabilities: null };
  }
}

export async function currentDigest(rt, model, opts) {
  if (rt.kind !== 'ollama') return null;
  const fresh = await detectRuntime(rt.url, opts);
  return fresh?.models.find((m) => m.name === model)?.digest ?? null;
}
