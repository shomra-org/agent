import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';

const SECTION_TOOLS = [
  { re: /^save_memory$/i, file: () => path.join(os.homedir(), '.gemini', 'GEMINI.md'), heading: '## Gemini Added Memories' },
  { re: /^qwen[_-]?save_memory$/i, file: () => path.join(os.homedir(), '.qwen', 'QWEN.md'), heading: '## Qwen Added Memories' },
];

const readOr = (read, p) => {
  try {
    return read(p);
  } catch {
    return null;
  }
};

const readUtf8 = (p) => fs.readFileSync(p, 'utf8');

function replaceOnce(text, oldStr, newStr, all) {
  if (typeof oldStr !== 'string' || typeof newStr !== 'string') return null;
  if (oldStr === '') return text === '' ? newStr : null;
  if (!text.includes(oldStr)) return null;
  return all ? text.split(oldStr).join(newStr) : text.replace(oldStr, () => newStr);
}

function applySearchReplace(text, diff) {
  const blocks = [...String(diff).matchAll(/(?:-{3,} SEARCH|<{3,} SEARCH)\r?\n([\s\S]*?)\r?\n={3,}\r?\n([\s\S]*?)\r?\n(?:\+{3,} REPLACE|>{3,} REPLACE)/g)];
  if (!blocks.length) return null;
  let out = text;
  for (const [, search, replace] of blocks) {
    const next = replaceOnce(out, search, replace, false);
    if (next == null) return null;
    out = next;
  }
  return out;
}

function insertAt(text, line, insert) {
  if (typeof insert !== 'string') return null;
  const lines = text.split('\n');
  const at = Math.max(0, Math.min(Number(line) || 0, lines.length));
  lines.splice(at, 0, ...insert.split('\n'));
  return lines.join('\n');
}

function parsePatch(patch) {
  const files = [];
  let cur = null;
  for (const raw of String(patch).split(/\r?\n/)) {
    const add = /^\*\*\* Add File: (.+)$/.exec(raw);
    const upd = /^\*\*\* Update File: (.+)$/.exec(raw);
    const del = /^\*\*\* Delete File: (.+)$/.exec(raw);
    if (add || upd || del) {
      cur = { path: (add || upd || del)[1].trim(), op: add ? 'add' : upd ? 'update' : 'delete', hunks: [], lines: [] };
      files.push(cur);
      continue;
    }
    if (!cur || /^\*\*\* (Begin|End) Patch/.test(raw)) continue;
    if (cur.op === 'add') {
      if (raw.startsWith('+')) cur.lines.push(raw.slice(1));
      continue;
    }
    if (raw.startsWith('@@')) {
      cur.hunks.push({ before: [], after: [] });
      continue;
    }
    if (!cur.hunks.length) cur.hunks.push({ before: [], after: [] });
    const h = cur.hunks[cur.hunks.length - 1];
    if (raw.startsWith('-')) h.before.push(raw.slice(1));
    else if (raw.startsWith('+')) h.after.push(raw.slice(1));
    else {
      const ctx = raw.startsWith(' ') ? raw.slice(1) : raw;
      h.before.push(ctx);
      h.after.push(ctx);
    }
  }
  return files;
}

function applyHunks(text, hunks) {
  let out = text;
  for (const h of hunks) {
    const before = h.before.join('\n');
    const after = h.after.join('\n');
    const next = before ? replaceOnce(out, before, after, false) : out + (out.endsWith('\n') || !out ? '' : '\n') + after;
    if (next == null) return null;
    out = next;
  }
  return out;
}

function pathOf(input) {
  const p = input.file_path ?? input.path ?? input.target_file ?? input.filename ?? null;
  return typeof p === 'string' && p.trim() ? p : null;
}

function resolveAgainst(p, cwd) {
  if (!p) return null;
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2));
  return path.isAbsolute(p) ? p : path.resolve(cwd || process.cwd(), p);
}

export function memoryWritesFor(tool, input, { cwd, read = readUtf8 } = {}) {
  const name = String(tool ?? '');
  const i = input ?? {};

  const section = SECTION_TOOLS.find((s) => s.re.test(name));
  if (section) {
    const fact = typeof i.fact === 'string' ? i.fact : typeof i.content === 'string' ? i.content : null;
    if (!fact) return [];
    const file = section.file();
    const current = readOr(read, file) ?? '';
    const bullet = `- ${fact.trim()}`;
    const content = current.includes(section.heading)
      ? current.replace(section.heading, `${section.heading}\n${bullet}`)
      : `${current}${current && !current.endsWith('\n') ? '\n' : ''}\n${section.heading}\n${bullet}\n`;
    return [{ path: file, content, before: current, basis: 'whole' }];
  }

  if (/^apply_patch$/i.test(name)) {
    const patch = typeof i.patch === 'string' ? i.patch : typeof i.input === 'string' ? i.input : typeof i.command === 'string' ? i.command : Array.isArray(i.command) ? i.command.join('\n') : null;
    if (!patch) return [];
    const out = [];
    for (const f of parsePatch(patch)) {
      const abs = resolveAgainst(f.path, cwd);
      if (f.op === 'delete') continue;
      if (f.op === 'add') {
        out.push({ path: abs, content: f.lines.join('\n'), before: readOr(read, abs), basis: 'whole' });
        continue;
      }
      const current = readOr(read, abs);
      const next = current == null ? null : applyHunks(current, f.hunks);
      if (next != null) out.push({ path: abs, content: next, before: current, basis: 'whole' });
      else out.push({ path: abs, content: f.hunks.map((h) => h.after.join('\n')).join('\n'), before: current, basis: 'fragment' });
    }
    return out;
  }

  const target = resolveAgainst(pathOf(i), cwd);
  if (!target) return [];
  const command = typeof i.command === 'string' ? i.command : null;

  if (typeof i.content === 'string' && !Array.isArray(i.edits)) return [{ path: target, content: i.content, before: readOr(read, target), basis: 'whole' }];
  if (typeof i.file_text === 'string' && (!command || command === 'create')) return [{ path: target, content: i.file_text, before: readOr(read, target), basis: 'whole' }];

  const current = readOr(read, target);
  const whole = (content) => [{ path: target, content, before: current, basis: 'whole' }];
  const fragment = (content) => (typeof content === 'string' && content ? [{ path: target, content, before: current, basis: 'fragment' }] : []);

  if (typeof i.new_string === 'string') {
    const next = current == null ? null : replaceOnce(current, i.old_string, i.new_string, !!i.replace_all);
    return next != null ? whole(next) : fragment(i.new_string);
  }
  if (Array.isArray(i.edits)) {
    let next = current;
    for (const e of i.edits) {
      next = next == null ? null : replaceOnce(next, e?.old_string, e?.new_string, !!e?.replace_all);
    }
    return next != null ? whole(next) : fragment(i.edits.map((e) => e?.new_string ?? '').join('\n'));
  }
  if (command === 'str_replace' || typeof i.new_str === 'string') {
    const next = current == null ? null : replaceOnce(current, i.old_str, i.new_str ?? '', false);
    return next != null ? whole(next) : fragment(i.new_str);
  }
  if (command === 'insert') {
    const text = i.insert_text ?? i.new_str;
    const next = current == null ? null : insertAt(current, i.insert_line, text);
    return next != null ? whole(next) : fragment(text);
  }
  if (typeof i.diff === 'string') {
    const next = current == null ? null : applySearchReplace(current, i.diff);
    return next != null ? whole(next) : fragment(i.diff);
  }
  if (typeof i.code_edit === 'string') return fragment(i.code_edit);
  return [];
}

export const MEMORY_LEDGER_DIR = path.join(CONFIG_DIR, 'memory-ledger');

export const sha256 = (s) => crypto.createHash('sha256').update(String(s ?? ''), 'utf8').digest('hex');

function ledgerFile(p, dir) {
  const key = crypto.createHash('sha1').update(path.resolve(p).toLowerCase()).digest('hex');
  return path.join(dir, `${key}.json`);
}

export function readLedger(p, dir = MEMORY_LEDGER_DIR) {
  try {
    const row = JSON.parse(fs.readFileSync(ledgerFile(p, dir), 'utf8'));
    return row && Array.isArray(row.hashes) ? row : null;
  } catch {
    return null;
  }
}

export function recordLedger(p, hashes, dir = MEMORY_LEDGER_DIR) {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const prev = readLedger(p, dir);
    const merged = [...new Set([...hashes.filter(Boolean), ...(prev?.hashes ?? [])])].slice(0, 6);
    const file = ledgerFile(p, dir);
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ path: path.resolve(p), hashes: merged, at: new Date().toISOString() }), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch {
    return;
  }
}

export function outOfBandChange(p, currentContent, dir = MEMORY_LEDGER_DIR) {
  if (currentContent == null) return false;
  const row = readLedger(p, dir);
  if (!row) return false;
  return !row.hashes.includes(sha256(currentContent));
}
