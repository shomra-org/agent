import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';
import { patchTextOf } from './command-text.mjs';

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

/** Every index at which `needle` occurs in `hay` (non-overlapping is not required - two overlapping hits are still two). */
function occurrences(hay, needle, max = 3) {
  const out = [];
  for (let at = hay.indexOf(needle); at !== -1 && out.length < max; at = hay.indexOf(needle, at + 1)) out.push(at);
  return out;
}

/**
 * ⚠ THE VENDOR'S RULE, NOT A LOOSER ONE. Claude Code's Edit REFUSES an
 * `old_string` that occurs more than once unless `replace_all` is set; this
 * replaced the FIRST hit, so a rebuild could be sent for an edit the agent
 * would never apply - or, worse, for the wrong occurrence of a line that is in
 * the file twice (a multi-stage Dockerfile has two `USER` lines). Ambiguity is
 * `null`: nothing is sent and the server grades the fragment as a fragment.
 *
 * ⚠ CRLF: the editor matches an LF `old_string` against a CRLF file and keeps
 * the file's line endings (observed Claude Code behaviour; not a documented
 * contract). Tried only when the exact match fails, and the result is written
 * back with the file's own endings.
 */
function replaceOnce(text, oldStr, newStr, all) {
  if (typeof oldStr !== 'string' || typeof newStr !== 'string') return null;
  if (oldStr === '') return text === '' ? newStr : null;
  const direct = replaceIn(text, oldStr, newStr, all);
  if (direct != null) return direct;
  if (!text.includes('\r\n') || oldStr.includes('\r')) return null;
  const lf = replaceIn(text.replace(/\r\n/g, '\n'), oldStr, newStr.replace(/\r\n/g, '\n'), all);
  return lf == null ? null : lf.replace(/\n/g, '\r\n');
}

function replaceIn(text, oldStr, newStr, all) {
  const hits = occurrences(text, oldStr, 2);
  if (!hits.length) return null;
  if (all) return text.split(oldStr).join(newStr);
  if (hits.length > 1) return null;
  return text.slice(0, hits[0]) + newStr + text.slice(hits[0] + oldStr.length);
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

/**
 * Codex's patch envelope, parsed the way `apply_patch` reads it.
 *
 * ⚠ AN `@@` LINE IS AN ANCHOR, NOT DECORATION. `@@ FROM node:20 AS runtime`
 * says "the lines below are AFTER this one". Ignoring it and replacing the
 * first `USER node` in the file rebuilt the BUILD stage of a multi-stage
 * Dockerfile: the endpoint sent a file that ran as `node` for a patch that makes
 * the runtime stage run as root - a clean verdict for a refused change, and one
 * an agent can steer at will. Anchors are honoured in order; `*** End of File`
 * pins a hunk to the end; `*** Move to:` renames the result.
 */
function parsePatch(patch) {
  const files = [];
  let cur = null;
  let hunk = null;
  const newHunk = () => {
    hunk = { anchors: [], before: [], after: [], eof: false };
    cur.hunks.push(hunk);
    return hunk;
  };
  for (const raw of String(patch).split(/\r?\n/)) {
    const add = /^\*\*\* Add File: (.+)$/.exec(raw);
    const upd = /^\*\*\* Update File: (.+)$/.exec(raw);
    const del = /^\*\*\* Delete File: (.+)$/.exec(raw);
    if (add || upd || del) {
      cur = { path: (add || upd || del)[1].trim(), op: add ? 'add' : upd ? 'update' : 'delete', hunks: [], lines: [], moveTo: null };
      hunk = null;
      files.push(cur);
      continue;
    }
    if (!cur || /^\*\*\* (Begin|End) Patch/.test(raw)) continue;
    const move = /^\*\*\* Move to: (.+)$/.exec(raw);
    if (move) {
      cur.moveTo = move[1].trim();
      continue;
    }
    if (cur.op === 'add') {
      if (raw.startsWith('+')) cur.lines.push(raw.slice(1));
      continue;
    }
    if (/^\*\*\* End of File\s*$/.test(raw)) {
      if (hunk) hunk.eof = true;
      continue;
    }
    if (raw.startsWith('@@')) {
      const anchor = raw.slice(2).trim();
      // consecutive `@@` lines narrow the SAME hunk (`@@ class A` then `@@ def f`)
      const h = hunk && !hunk.before.length && !hunk.after.length ? hunk : newHunk();
      if (anchor) h.anchors.push(anchor);
      continue;
    }
    const h = hunk ?? newHunk();
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

/** `apply_patch`'s tolerance ladder: exact, then trailing whitespace, then both ends. */
const LINE_EQ = [(a, b) => a === b, (a, b) => a.trimEnd() === b.trimEnd(), (a, b) => a.trim() === b.trim()];

function seqAt(lines, seq, at, eq) {
  if (at < 0 || at + seq.length > lines.length) return false;
  for (let k = 0; k < seq.length; k++) if (!eq(lines[at + k], seq[k])) return false;
  return true;
}

/**
 * ⚠ UNIQUE AFTER THE ANCHOR, OR NOTHING. `apply_patch` itself takes the first
 * match past its cursor; this is stricter on purpose - a block that occurs
 * twice after its anchor is one where our cursor and Codex's could disagree,
 * and a rebuild of the wrong occurrence is graded as the truth. `null` here
 * means "send nothing": the server grades the fragment as a fragment.
 */
function findBlock(lines, seq, from, eof) {
  for (const eq of LINE_EQ) {
    if (eof) {
      const at = lines.length - seq.length;
      if (at >= from && seqAt(lines, seq, at, eq)) return at;
      continue;
    }
    const hits = [];
    for (let at = from; at + seq.length <= lines.length && hits.length < 2; at++) if (seqAt(lines, seq, at, eq)) hits.push(at);
    if (hits.length === 1) return hits[0];
    if (hits.length > 1) return -1;
  }
  return -1;
}

function applyHunks(text, hunks) {
  const crlf = text.includes('\r\n');
  const lines = text.split(/\r?\n/);
  const endsWithNewline = lines.length > 1 && lines[lines.length - 1] === '';
  if (endsWithNewline) lines.pop();
  let cursor = 0;
  for (const h of hunks) {
    for (const anchor of h.anchors) {
      const at = findBlock(lines, [anchor], cursor, false);
      if (at < 0) return null;
      cursor = at + 1;
    }
    if (!h.before.length) {
      // a pure addition lands at the end of the file, as `apply_patch` places it
      lines.push(...h.after);
      cursor = lines.length;
      continue;
    }
    const at = findBlock(lines, h.before, cursor, h.eof);
    if (at < 0) return null;
    lines.splice(at, h.before.length, ...h.after);
    cursor = at + h.after.length;
  }
  const out = lines.join(crlf ? '\r\n' : '\n');
  return endsWithNewline ? out + (crlf ? '\r\n' : '\n') : out;
}

function pathOf(input) {
  const p = input.file_path ?? input.path ?? input.filePath ?? input.target_file ?? input.filename ?? null;
  return typeof p === 'string' && p.trim() ? p : null;
}

function resolveAgainst(p, cwd) {
  if (!p) return null;
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2));
  return path.isAbsolute(p) ? p : path.resolve(cwd || process.cwd(), p);
}

/**
 * VS Code's Copilot agent tools speak camelCase (`replace_string_in_file`
 * `{ filePath, oldString, newString }`, `insert_edit_into_file { filePath, code }`),
 * and were read as carrying no edit at all. Aliased onto the shapes below;
 * `code` is Copilot's "…existing code…" sketch - a FRAGMENT, never the file.
 */
function aliasEditKeys(i) {
  if (typeof i.newString !== 'string' && typeof i.code !== 'string') return i;
  const out = { ...i };
  if (typeof i.newString === 'string' && typeof out.new_string !== 'string') out.new_string = i.newString;
  if (typeof i.oldString === 'string' && typeof out.old_string !== 'string') out.old_string = i.oldString;
  if (typeof i.code === 'string' && typeof out.code_edit !== 'string') out.code_edit = i.code;
  return out;
}

export function memoryWritesFor(tool, input, { cwd, read = readUtf8 } = {}) {
  const name = String(tool ?? '');
  const i = aliasEditKeys(input ?? {});

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
        out.push({ path: abs, name: f.path, content: f.lines.join('\n'), before: readOr(read, abs), basis: 'whole' });
        continue;
      }
      // ⚠ `*** Move to:` - the result lands at the NEW path, and that is the file a rule must read.
      const dest = f.moveTo ?? f.path;
      const destAbs = resolveAgainst(dest, cwd);
      const current = readOr(read, abs);
      const next = current == null ? null : applyHunks(current, f.hunks);
      if (next != null) out.push({ path: destAbs, name: dest, content: next, before: f.moveTo ? readOr(read, destAbs) : current, basis: 'whole' });
      else out.push({ path: destAbs, name: dest, content: f.hunks.map((h) => h.after.join('\n')).join('\n'), before: current, basis: 'fragment' });
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
    // ⚠ An Edit with an empty `old_string` on a file that does not exist CREATES it with `new_string`.
    if (current == null && i.old_string === '') return whole(i.new_string);
    const next = current == null ? null : replaceOnce(current, i.old_string, i.new_string, !!i.replace_all);
    return next != null ? whole(next) : fragment(i.new_string);
  }
  if (Array.isArray(i.edits)) {
    // ⚠ `oldText` / `newText` is the filesystem MCP server's `edit_file` shape.
    const oldOf = (e) => e?.old_string ?? e?.old_str ?? e?.oldText;
    const newOf = (e) => e?.new_string ?? e?.new_str ?? e?.newText;
    let next = current;
    for (const e of i.edits) {
      next = next == null ? null : replaceOnce(next, oldOf(e), newOf(e), !!e?.replace_all);
    }
    return next != null ? whole(next) : fragment(i.edits.map((e) => newOf(e) ?? '').join('\n'));
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

export const MAX_POST_CONTENT = 1024 * 1024;
const MAX_POST_FILES = 8;

/**
 * THE FILE AS IT WILL BE AFTER THIS CALL, for every governed file it edits.
 *
 * ⚠ AN EDIT IS NOT THE FILE, and the server was grading it as one. An Edit of
 * `package.json` carries `"left-pad": "^1.0.0",` - no manifest, no subject; an
 * Edit deleting `USER node` from a Dockerfile carries an empty string - no
 * image, though the result now runs as root; three lines of a workflow report
 * `triggers: []`. `memoryWritesFor` already rebuilt the post-edit file for
 * memory stores; the same reconstruction now serves every path `keep` names
 * (the subject-bearing ones), and travels with the escalation as
 * `post_content`.
 *
 * ⚠ ONLY A CLEAN APPLY IS SENT. An edit whose `old_string` is not in the file,
 * a patch hunk that does not match, a file over 1 MiB, an unreadable file - all
 * send NOTHING, and the server grades the fragment as a fragment. A guessed
 * file would be graded as the truth.
 * ⚠ A write that already carries the whole file (`content`) is not re-sent.
 */
export function postEditContents(tool, input, { cwd, read = readUtf8, keep = () => true } = {}) {
  const i = input ?? {};
  const name = String(tool ?? '');
  let writes;
  let names;
  const patch = patchTextOf(name, i);
  if (patch && /^\*\*\* (?:Add|Update) File:/m.test(patch)) {
    writes = memoryWritesFor('apply_patch', { patch }, { cwd, read });
    names = writes.map((w) => w.name);
  } else if (/^apply_patch$/i.test(name)) {
    return [];
  } else if (/^append$/i.test(String(i.mode ?? '')) && typeof i.content === 'string' && pathOf(i)) {
    // ⚠ desktop-commander `write_file` with `mode: "append"` - the content is a TAIL, not the file.
    const target = resolveAgainst(pathOf(i), cwd);
    const current = readOr(read, target);
    writes = current == null ? [] : [{ path: target, content: `${current}${i.content}`, before: current, basis: 'whole' }];
    names = [pathOf(i)];
  } else {
    if ((typeof i.content === 'string' && !Array.isArray(i.edits)) || (typeof i.file_text === 'string' && (!i.command || i.command === 'create'))) return [];
    writes = memoryWritesFor(name, i, { cwd, read });
    names = writes.map(() => pathOf(i));
  }
  const out = [];
  writes.forEach((w, k) => {
    const named = names[k] ?? w.path;
    if (out.length >= MAX_POST_FILES || w.basis !== 'whole' || typeof w.content !== 'string') return;
    if (Buffer.byteLength(w.content, 'utf8') > MAX_POST_CONTENT || !keep(named)) return;
    out.push({ path: String(named).replace(/\\/g, '/'), content: w.content });
  });
  return out;
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
