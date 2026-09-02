import fs from 'node:fs';
import path from 'node:path';
import { breakerOpen, breakerReset, breakerTrip } from '../core/circuit-breaker.mjs';
import { CONFIG_DIR } from '../core/config.mjs';
import { clampInt } from '../core/numbers.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';

const MODEL_CACHE_FILE = path.join(CONFIG_DIR, 'model-cache.json');

function modelCacheOff() { return process.env.SHOMRA_MODEL_CACHE === '0' || String(process.env.SHOMRA_MODEL_CACHE).toLowerCase() === 'false'; }

function loadModelCache() { try { return JSON.parse(fs.readFileSync(MODEL_CACHE_FILE, 'utf8')) || {}; } catch { return {}; } }

function saveModelCache(c) { try { fs.mkdirSync(CONFIG_DIR, { recursive: true }); fs.writeFileSync(MODEL_CACHE_FILE, JSON.stringify(c)); } catch {  } }

export const MODEL_CACHE_MAX_ENTRIES = 500;

export const MODEL_CACHE_RETAIN_MS = 90 * 24 * 3600 * 1000;

export function pruneModelCache(cache, { now = Date.now(), ttl = 0, max = MODEL_CACHE_MAX_ENTRIES } = {}) {
  const horizon = Math.max(MODEL_CACHE_RETAIN_MS, ttl);
  const live = Object.entries(cache ?? {}).filter(([, v]) => v && typeof v.cachedAt === 'number' && now - v.cachedAt < horizon);
  live.sort((a, b) => b[1].cachedAt - a[1].cachedAt);
  return Object.fromEntries(live.slice(0, max));
}

export async function modelLookup(url, id, sha, timeoutMs) {
  const key = `${id}@${sha || 'latest'}`;
  const ttl = clampInt(process.env.SHOMRA_MODEL_CACHE_TTL_MS, 7 * 24 * 3600 * 1000, 0, 365 * 24 * 3600 * 1000);
  const cache = modelCacheOff() ? {} : loadModelCache();
  const hit = cache[key];

  if (hit && hit.cachedAt && Date.now() - hit.cachedAt < ttl) return { ...hit.data, cached: true };

  if (!url) {
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true };
    throw new Error('model index not configured (set SHOMRA_URL to enrich)');
  }

  if (breakerOpen()) {
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true };
    throw new Error('backend unavailable (circuit open)');
  }

  const q = `id=${encodeURIComponent(id)}${sha ? `&sha=${encodeURIComponent(sha)}` : ''}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs ?? clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 15000, 1000, 60000));
  try {
    const res = await fetch(`${url}/models/lookup?${q}`, { signal: ctrl.signal, headers: { Accept: 'application/json', 'User-Agent': 'shomra-agent' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    breakerReset();
    if (!modelCacheOff() && data && data.found) { cache[key] = { cachedAt: Date.now(), data }; saveModelCache(pruneModelCache(cache, { ttl })); }
    return data;
  } catch (e) {
    breakerTrip();
    if (hit && hit.data) return { ...hit.data, cached: true, stale: true };
    throw e;
  } finally { clearTimeout(timer); }
}

export const MODEL_SEV_RANK = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

export function printAlternatives(alts, kind, indent = '      ') {
  if (!Array.isArray(alts) || !alts.length) return;
  console.log(`${indent}${green('↳ safer alternatives')} ${dim('(same category, lower risk):')}`);
  for (const a of alts.slice(0, 5)) {
    const id = kind === 'model' ? a.modelId : (a.packageName || a.name);
    const url = kind === 'model' ? a.url : (a.repoUrl || a.homepage || '');
    const vc = a.verdict === 'FAIL' ? red : a.verdict === 'REVIEW' ? yellow : green;
    const label = id && id !== a.name ? `${bold(a.name)} ${dim('(' + id + ')')}` : bold(a.name);
    console.log(`${indent}  ${green('•')} ${label}  ${vc(String(a.verdict || '-'))} ${dim('risk ' + (a.riskScore ?? '?') + '/100')}${url ? dim(' · ' + url) : ''}`);
  }
}

export function modelFixPlan(findings, sha) {
  const text = (findings || []).map((f) => `${f.title || ''} ${f.description || ''} ${f.class || ''} ${f.surface || ''} ${f.remediation || ''}`).join(' ').toLowerCase();
  const kwargs = [];
  if (/pickle|\.bin\b|hdf5|\.h5\b|keras|serial|safetensors/.test(text)) {
    kwargs.push({ name: 'use_safetensors', value: 'True', reason: 'Load safetensors instead of pickle/HDF5 weights, which can execute code the moment they load.' });
  }

  if (/trust_remote_code|auto_map|remote code|custom (python )?code|modeling_[\w.]+\.py/.test(text)) {
    kwargs.push({ name: 'trust_remote_code', value: 'False', reason: "Never run the model repo's own Python during load." });
  }
  if (sha) {
    kwargs.push({ name: 'revision', value: JSON.stringify(String(sha).slice(0, 40)), reason: 'Pin to the exact revision Shomra reviewed instead of a mutable branch (supply-chain).' });
  }
  return kwargs.length ? { kwargs } : null;
}
