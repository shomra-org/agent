import fs from 'node:fs';
import path from 'node:path';
import { userDirs } from './discovery/platform.mjs';

const PLAT = process.platform;
const MAX_BYTES = 256 * 1024;
const MAX_ITEMS = 10;

const ENDPOINT_KEY =
  /^(?:ANTHROPIC_(?:BASE_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL|FOUNDRY_BASE_URL)|OPENAI_(?:BASE_URL|API_BASE(?:_URL)?)|AZURE_OPENAI_ENDPOINT|GOOGLE_GEMINI_BASE_URL|GEMINI_(?:API_)?BASE_URL|CODEX_BASE_URL|LITELLM_(?:BASE_URL|PROXY_URL))$/i;
const PROXY_KEY = /^(?:HTTPS?_PROXY|ALL_PROXY)$/i;
const TLS_OFF = [
  [/^NODE_TLS_REJECT_UNAUTHORIZED$/i, (v) => v.trim() === '0'],
  [/^PYTHONHTTPSVERIFY$/i, (v) => v.trim() === '0'],
  [/^GIT_SSL_NO_VERIFY$/i, (v) => /^(?:1|true|yes)$/i.test(v.trim())],
];

const PROCESS_KEYS = {
  'claude-code': /^ANTHROPIC_/i,
  codex: /^(?:OPENAI_|CODEX_)/i,
  gemini: /^(?:GEMINI_|GOOGLE_GEMINI_)/i,
  qwen: /^(?:OPENAI_|QWEN_)/i,
  'qwen-code': /^(?:OPENAI_|QWEN_)/i,
};

function managedSettingsPath() {
  if (PLAT === 'win32') return path.join(process.env.ProgramData || 'C:\\ProgramData', 'ClaudeCode', 'managed-settings.json');
  if (PLAT === 'darwin') return '/Library/Application Support/ClaudeCode/managed-settings.json';
  return '/etc/claude-code/managed-settings.json';
}

function sourcesFor(vendor, cwd, home) {
  const { HOME } = userDirs(home);
  switch (vendor) {
    case 'claude-code':
      return [
        { file: path.join(HOME, '.claude', 'settings.json'), scope: 'user', shape: 'env-json' },
        { file: path.join(HOME, '.claude', 'settings.local.json'), scope: 'user', shape: 'env-json' },
        { file: path.join(cwd, '.claude', 'settings.json'), scope: 'project', shape: 'env-json' },
        { file: path.join(cwd, '.claude', 'settings.local.json'), scope: 'project', shape: 'env-json' },
        { file: managedSettingsPath(), scope: 'managed', shape: 'env-json' },
      ];
    case 'gemini':
    case 'qwen':
    case 'qwen-code': {
      const dir = vendor === 'gemini' ? '.gemini' : '.qwen';
      return [
        { file: path.join(HOME, dir, '.env'), scope: 'user', shape: 'dotenv' },
        { file: path.join(cwd, dir, '.env'), scope: 'project', shape: 'dotenv' },
        { file: path.join(HOME, dir, 'settings.json'), scope: 'user', shape: 'gemini-settings' },
        { file: path.join(cwd, dir, 'settings.json'), scope: 'project', shape: 'gemini-settings' },
      ];
    }
    case 'codex':
      return [
        { file: path.join(HOME, '.codex', 'config.toml'), scope: 'user', shape: 'codex-toml' },
        { file: path.join(cwd, '.codex', 'config.toml'), scope: 'project', shape: 'codex-toml' },
      ];
    default:
      return [];
  }
}

function readSmall(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function parseJsonc(raw) {
  try {
    return JSON.parse(raw.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"\\])\/\/.*$/gm, '$1'));
  } catch {
    return null;
  }
}

function pairsOf(shape, raw) {
  const pairs = [];
  if (shape === 'dotenv') {
    for (const line of raw.split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (m) pairs.push([m[1], m[2].replace(/^(['"])(.*)\1$/, '$2')]);
    }
    return pairs;
  }
  if (shape === 'codex-toml') {
    let section = '';
    for (const line of raw.split(/\r?\n/)) {
      const s = /^\s*\[([^\]]+)\]\s*$/.exec(line);
      if (s) { section = s[1].trim(); continue; }
      const m = /^\s*(base_url|openai_base_url)\s*=\s*["']([^"']*)["']/.exec(line);
      if (m) pairs.push([section ? `${section}.${m[1]}` : m[1], m[2]]);
    }
    return pairs;
  }
  const doc = parseJsonc(raw);
  if (!doc || typeof doc !== 'object') return pairs;
  const env = doc.env && typeof doc.env === 'object' && !Array.isArray(doc.env) ? doc.env : {};
  for (const [k, v] of Object.entries(env)) if (['string', 'number', 'boolean'].includes(typeof v)) pairs.push([k, String(v)]);
  if (shape === 'gemini-settings' && typeof doc.proxy === 'string') pairs.push(['proxy', doc.proxy]);
  return pairs;
}

function hostOf(value) {
  const s = /^[a-z][\w+.-]*:\/\//i.test(value) ? value : `http://${value}`;
  try {
    const u = new URL(s);
    return u.hostname ? { host: u.hostname.toLowerCase(), scheme: u.protocol.replace(':', '') } : null;
  } catch {
    return null;
  }
}

export function classifyPair(key, value) {
  const v = String(value ?? '');
  if (TLS_OFF.some(([re, bad]) => re.test(key) && bad(v))) return { key, kind: 'tls-off' };
  const endpoint = ENDPOINT_KEY.test(key) || /(?:^|\.)(?:base_url|openai_base_url)$/.test(key);
  const proxy = PROXY_KEY.test(key) || key === 'proxy';
  if (!endpoint && !proxy) return null;
  const h = hostOf(v.trim());
  return h ? { key, kind: proxy ? 'proxy' : 'model-endpoint', host: h.host, scheme: h.scheme } : null;
}

export function readEnvRedirects(vendor, cwd = process.cwd(), env = process.env, opts = {}) {
  const out = [];
  for (const src of sourcesFor(vendor, cwd, opts.home)) {
    const raw = readSmall(src.file);
    if (raw == null) continue;
    for (const [k, v] of pairsOf(src.shape, raw)) {
      const hit = classifyPair(k, v);
      if (hit && out.length < MAX_ITEMS) out.push({ ...hit, scope: src.scope, source: src.file });
    }
  }
  const scoped = PROCESS_KEYS[vendor];
  if (scoped) {
    for (const [k, v] of Object.entries(env)) {
      if (!scoped.test(k) && !TLS_OFF.some(([re]) => re.test(k))) continue;
      const hit = classifyPair(k, v);
      if (hit && hit.kind !== 'proxy' && out.length < MAX_ITEMS) out.push({ ...hit, scope: 'process', source: 'environment' });
    }
  }
  return out;
}
