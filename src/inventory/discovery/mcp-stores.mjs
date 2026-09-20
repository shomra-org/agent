import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { extensionBundleServer, normalizeServerEntry, readMcpServers } from '../../detect/signals/mcp-config.mjs';
import { PLAT, userDirs } from './platform.mjs';

const require = createRequire(import.meta.url);
const MAX_DB_BYTES = 256 * 1024 * 1024;
const MAX_ROWS = 400;
const MAX_XML_BYTES = 2 * 1024 * 1024;
const MAX_EXTENSIONS = 200;

let sqlite;
function loadSqlite() {
  if (sqlite !== undefined) return sqlite;
  const original = process.emitWarning;
  process.emitWarning = function (warning, ...rest) {
    if (/sqlite/i.test(String(warning?.message ?? warning))) return;
    return original.call(process, warning, ...rest);
  };
  try { sqlite = require('node:sqlite'); } catch { sqlite = null; } finally { process.emitWarning = original; }
  return sqlite;
}

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const looksLikeServer = (v) => isObj(v) && (typeof v.command === 'string' || Array.isArray(v.command) || typeof v.url === 'string' || typeof v.serverUrl === 'string' || typeof v.httpUrl === 'string');

export function serversInValue(value, fallbackName) {
  if (value == null) return [];
  let v = value;
  if (typeof v === 'string' || Buffer.isBuffer(v) || v instanceof Uint8Array) {
    const text = Buffer.from(v).toString('utf8').trim();
    if (!/^[[{]/.test(text)) return [];
    try { v = JSON.parse(text); } catch { return []; }
  }
  const mapped = readMcpServers(v);
  if (mapped) return mapped;
  if (looksLikeServer(v)) return [normalizeServerEntry(String(v.name ?? v.title ?? fallbackName ?? 'server'), v)];
  if (Array.isArray(v)) return v.filter(looksLikeServer).slice(0, 100).map((s, i) => normalizeServerEntry(String(s.name ?? `${fallbackName ?? 'server'}-${i + 1}`), s));
  return [];
}

/* ─── Warp ─────────────────────────────────────────────────────────────── */

export function warpDatabases(home) {
  const { HOME, LOCALAPPDATA } = userDirs(home);
  const out = [];
  if (PLAT === 'darwin') {
    const group = path.join(HOME, 'Library', 'Group Containers');
    try {
      for (const g of fs.readdirSync(group).filter((d) => /\.dev\.warp$/i.test(d))) {
        const base = path.join(group, g, 'Library', 'Application Support');
        for (const app of safeList(base).filter((d) => /^dev\.warp\.Warp/i.test(d))) out.push(path.join(base, app, 'warp.sqlite'));
      }
    } catch { /* no Warp */ }
  } else if (PLAT === 'win32') {
    for (const d of ['warp', 'Warp']) out.push(path.join(LOCALAPPDATA, d, 'Warp', 'data', 'warp.sqlite'));
  } else {
    for (const d of ['warp-terminal', 'warp-terminal-preview']) {
      out.push(path.join(HOME, '.local', 'state', d, 'warp.sqlite'));
      out.push(path.join(HOME, '.local', 'share', d, 'warp.sqlite'));
    }
  }
  return [...new Set(out)].filter((f) => { try { return fs.statSync(f).isFile(); } catch { return false; } });
}

export function readSqliteMcpServers(file) {
  const lib = loadSqlite();
  if (!lib?.DatabaseSync) return { servers: [], state: 'no-sqlite' };
  let st;
  try { st = fs.statSync(file); } catch { return { servers: [], state: 'unreadable' }; }
  if (st.size > MAX_DB_BYTES) return { servers: [], state: 'oversized' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-mcpdb-'));
  const copy = path.join(dir, 'store.sqlite');
  let db;
  try {
    fs.copyFileSync(file, copy);
    for (const s of ['-wal', '-shm']) if (fs.existsSync(file + s)) fs.copyFileSync(file + s, copy + s);
    db = new lib.DatabaseSync(copy, { readOnly: true });
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => String(r.name));
    const servers = [];
    for (const t of tables.filter((n) => /mcp/i.test(n)).slice(0, 20)) {
      const quoted = `"${t.replace(/"/g, '""')}"`;
      const cols = db.prepare(`PRAGMA table_info(${quoted})`).all().map((c) => String(c.name));
      const nameCol = cols.find((c) => /^(?:name|title|display_name|server_name)$/i.test(c));
      for (const row of db.prepare(`SELECT * FROM ${quoted} LIMIT ${MAX_ROWS}`).all()) {
        const fallback = nameCol ? String(row[nameCol] ?? '') : undefined;
        if (cols.some((c) => /^(?:command|url)$/i.test(c))) {
          const entry = {};
          for (const c of cols) {
            const v = row[c];
            if (v == null) continue;
            if (/^(?:args|env|environment|headers)$/i.test(c) && typeof v === 'string' && /^[[{]/.test(v.trim())) { try { entry[c.toLowerCase()] = JSON.parse(v); continue; } catch { /* keep raw */ } }
            entry[c.toLowerCase()] = v;
          }
          if (looksLikeServer(entry)) servers.push(normalizeServerEntry(String(entry.name ?? fallback ?? t), entry));
        }
        for (const c of cols) for (const s of serversInValue(row[c], fallback)) servers.push(s);
      }
    }
    return { servers: dedupe(servers), state: 'read' };
  } catch {
    return { servers: [], state: 'unreadable' };
  } finally {
    try { db?.close(); } catch { /* ignore */ }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/* ─── JetBrains ────────────────────────────────────────────────────────── */

export function jetbrainsOptionFiles(home) {
  const { HOME, APPDATA } = userDirs(home);
  const roots = PLAT === 'win32' ? [path.join(APPDATA, 'JetBrains')] : PLAT === 'darwin' ? [path.join(HOME, 'Library', 'Application Support', 'JetBrains')] : [path.join(HOME, '.config', 'JetBrains')];
  const out = [];
  for (const root of roots) {
    for (const product of safeList(root)) {
      const options = path.join(root, product, 'options');
      for (const f of safeList(options)) if (/mcp|llm|ai[-_]?assistant|junie/i.test(f) && /\.xml$/i.test(f)) out.push(path.join(options, f));
    }
  }
  return out.slice(0, 200);
}

const unescapeXml = (s) => s.replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#10;/g, '\n').replace(/&#13;/g, '\r').replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n))).replace(/&amp;/g, '&');

function jsonBlobs(text) {
  const out = [];
  for (let i = text.indexOf('{'); i !== -1 && out.length < 50; i = text.indexOf('{', i + 1)) {
    let depth = 0, q = false, esc = false;
    for (let j = i; j < text.length && j - i < 500_000; j++) {
      const c = text[j];
      if (q) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') q = false; continue; }
      if (c === '"') q = true;
      else if (c === '{') depth++;
      else if (c === '}' && --depth === 0) {
        try { out.push(JSON.parse(text.slice(i, j + 1))); i = j; } catch { /* not JSON, keep scanning */ }
        break;
      }
    }
  }
  return out;
}

export function readJetbrainsMcpServers(file) {
  let xml;
  try {
    if (fs.statSync(file).size > MAX_XML_BYTES) return [];
    xml = fs.readFileSync(file, 'utf8');
  } catch { return []; }
  const servers = [];
  for (const blob of jsonBlobs(unescapeXml(xml))) servers.push(...serversInValue(blob));
  const attrsOf = (s) => Object.fromEntries([...s.matchAll(/([\w:-]+)="([^"]*)"/g)].map(([, k, v]) => [k.toLowerCase(), unescapeXml(v)]));
  const records = [];
  for (const m of xml.matchAll(/<[\w:-]+\s[^<>]*\b(?:command|url)="[^"]*"[^<>]*>/g)) records.push(attrsOf(m[0]));
  for (const m of xml.matchAll(/<[\w:-]+(\s[^<>]*)?>((?:\s*<option\s[^<>]*\/>)+)\s*<\/[\w:-]+>/g)) {
    records.push({ ...Object.fromEntries([...m[2].matchAll(/<option\s+name="([^"]+)"\s+value="([^"]*)"/g)].map(([, k, v]) => [k.toLowerCase(), unescapeXml(v)])), ...attrsOf(m[1] ?? '') });
  }
  for (const e of records.slice(0, 200)) {
    if (!(typeof e.command === 'string' || typeof e.url === 'string')) continue;
    if (typeof e.args === 'string') e.args = /^\[/.test(e.args.trim()) ? safeJson(e.args) ?? e.args.split(/\s+/) : e.args.split(/\s+/).filter(Boolean);
    if (typeof e.env === 'string' && /^\{/.test(e.env.trim())) e.env = safeJson(e.env);
    servers.push(normalizeServerEntry(String(e.name ?? e.id ?? path.basename(file, '.xml')), e));
  }
  return dedupe(servers);
}

/* ─── Claude Desktop extensions ────────────────────────────────────────── */

export function claudeDataDir(home) {
  const { HOME, APPDATA } = userDirs(home);
  if (PLAT === 'darwin') return path.join(HOME, 'Library', 'Application Support', 'Claude');
  if (PLAT === 'win32') return path.join(APPDATA, 'Claude');
  return path.join(HOME, '.config', 'Claude');
}

export function readClaudeExtensions(dataDir = claudeDataDir()) {
  const root = path.join(dataDir, 'Claude Extensions');
  const settingsDir = path.join(dataDir, 'Claude Extensions Settings');
  const out = [];
  for (const id of safeList(root).slice(0, MAX_EXTENSIONS)) {
    const manifestFile = path.join(root, id, 'manifest.json');
    let json;
    try { json = JSON.parse(fs.readFileSync(manifestFile, 'utf8')); } catch { continue; }
    const s = extensionBundleServer(json);
    if (!s) continue;
    let settings = null;
    try { settings = JSON.parse(fs.readFileSync(path.join(settingsDir, `${id}.json`), 'utf8')); } catch { /* none */ }
    const resolve = (v) => (typeof v === 'string' ? v.replace(/\$\{__dirname\}/g, path.join(root, id)) : v);
    out.push({ ...s, command: resolve(s.command), args: (s.args ?? []).map(resolve), disabled: s.disabled || settings?.isEnabled === false, file: manifestFile });
  }
  return out;
}

function safeList(dir) {
  try { return fs.readdirSync(dir); } catch { return []; }
}
function safeJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}
function dedupe(servers) {
  const seen = new Set();
  return servers.filter((s) => {
    const k = `${s.name}|${s.command ?? ''}|${(s.args ?? []).join(' ')}|${s.url ?? ''}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
