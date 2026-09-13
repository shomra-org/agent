import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const MAX_VALUE_BYTES = 8 * 1024 * 1024;
const MAX_ROWS = 20;

let sqlite;

function loadSqlite() {
  if (sqlite !== undefined) return sqlite;
  const original = process.emitWarning;
  process.emitWarning = function (warning, ...rest) {
    if (/sqlite/i.test(String(warning?.message ?? warning))) return;
    return original.call(process, warning, ...rest);
  };
  try {
    sqlite = require('node:sqlite');
  } catch {
    sqlite = null;
  } finally {
    process.emitWarning = original;
  }
  return sqlite;
}

export function stateDbAvailable() {
  return !!loadSqlite()?.DatabaseSync;
}

function openCopy(file) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shomra-state-'));
  const copy = path.join(dir, 'state.vscdb');
  fs.copyFileSync(file, copy);
  for (const suffix of ['-wal', '-shm']) {
    if (fs.existsSync(file + suffix)) fs.copyFileSync(file + suffix, copy + suffix);
  }
  return { copy, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function queryRows(db, keys) {
  const rows = [];
  const exact = db.prepare('SELECT key, value FROM ItemTable WHERE lower(key) = lower(?)');
  const like = db.prepare('SELECT key, value FROM ItemTable WHERE lower(key) LIKE lower(?) LIMIT ?');
  for (const k of keys) {
    if (k.includes('%')) rows.push(...like.all(k, MAX_ROWS));
    else {
      const row = exact.get(k);
      if (row) rows.push(row);
    }
    if (rows.length >= MAX_ROWS) break;
  }
  return rows.slice(0, MAX_ROWS);
}

function decode(value) {
  if (value == null) return null;
  const text = typeof value === 'string' ? value : Buffer.from(value).toString('utf8');
  if (text.length > MAX_VALUE_BYTES) return { oversized: true };
  try {
    return { json: JSON.parse(text) };
  } catch {
    return null;
  }
}

export function readStateKeys(file, keys) {
  if (!fs.existsSync(file)) return { state: 'absent' };
  const lib = loadSqlite();
  if (!lib?.DatabaseSync) return { state: 'unreadable', reason: 'sqlite-unavailable' };

  let db = null;
  let cleanup = null;
  try {
    try {
      db = new lib.DatabaseSync(file, { readOnly: true });
      db.prepare('SELECT 1 FROM ItemTable LIMIT 1').get();
    } catch {
      db?.close?.();
      const c = openCopy(file);
      cleanup = c.cleanup;
      db = new lib.DatabaseSync(c.copy, { readOnly: true });
    }
    const rows = queryRows(db, keys);
    if (!rows.length) return { state: 'absent' };
    const values = [];
    for (const row of rows) {
      const d = decode(row.value);
      if (d?.oversized) return { state: 'unreadable', reason: 'oversized' };
      if (d?.json !== undefined) values.push({ key: row.key, json: d.json });
    }
    return values.length ? { state: 'read', values } : { state: 'unreadable', reason: 'parse-failed' };
  } catch (err) {
    return { state: 'unreadable', reason: /locked|busy/i.test(String(err?.message)) ? 'locked' : 'db-read-failed' };
  } finally {
    try { db?.close?.(); } catch {}
    cleanup?.();
  }
}

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

export const CURSOR_APP_USER_KEY = 'src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser';

export function interpretCursor(json) {
  const cs = isObj(json?.composerState) ? json.composerState : null;
  if (!cs) return {};
  const doc = {};
  const allowlist = Array.isArray(cs.yoloCommandAllowlist) ? cs.yoloCommandAllowlist.filter((c) => typeof c === 'string') : [];
  if (cs.useYoloMode === true) {
    if (cs.yoloEnableRunEverything === true || !allowlist.length) doc.yoloEnableRunEverything = true;
    else doc.yoloCommandAllowlist = allowlist;
    if (cs.yoloMcpToolsDisabled === false) doc.mcpAllowlist = ['*:*'];
    if (cs.yoloOutsideWorkspaceDisabled === false) doc.fileSystem = { write: ['../**'] };
  }
  if (Array.isArray(cs.webFetchDomainAllowlist) && cs.webFetchDomainAllowlist.length) {
    doc.network = { outbound: cs.webFetchDomainAllowlist.filter((d) => typeof d === 'string') };
  }
  return doc;
}

const CLINE_KEYS = ['autoApprovalSettings', 'yoloModeToggled', 'allowedCommands', 'mode'];

export function interpretCline(json) {
  if (!isObj(json)) return {};
  const out = Object.fromEntries(CLINE_KEYS.filter((k) => k in json).map((k) => [k, json[k]]));
  const aas = json.autoApprovalSettings;
  if (isObj(aas) && aas.enabled !== false && aas.actions?.useMcp === true) out.mcpAllowlist = ['*:*'];
  return out;
}

export function interpretRoo(json) {
  if (!isObj(json) || json.autoApprovalEnabled === false) return {};
  return Object.fromEntries(
    Object.entries(json).filter(([k]) => /^(?:autoApprovalEnabled|alwaysAllow\w*|allowedCommands|alwaysApproveResubmit)$/.test(k)),
  );
}

export function interpretWindsurf(json) {
  if (!isObj(json)) return {};
  return Object.fromEntries(
    Object.entries(json).filter(([k]) => /autoexecut|cascade.*(?:allow|auto)|turbo|yolo|autorun/i.test(k)),
  );
}

export const INTERPRETERS = {
  cursor: interpretCursor,
  cline: interpretCline,
  roo: interpretRoo,
  windsurf: interpretWindsurf,
};
