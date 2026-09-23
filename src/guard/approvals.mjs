import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';

export const ASKS_FILE = path.join(CONFIG_DIR, 'asks.json');

const WINDOW_MS = 12 * 60 * 60 * 1000;
const MAX_ENTRIES = 300;
const TRANSCRIPT_TAIL_BYTES = 4 * 1024 * 1024;
const SHELL_TOOL_NAMES = new Set(['Bash', 'bash', 'shell', 'run_shell_command', 'execute_command', 'run_terminal_cmd']);

export function askKey(session, command) {
  return crypto.createHash('sha256').update(`${session}\u0000${command}`).digest('hex').slice(0, 32);
}

function readAsks(file) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(doc?.asks) ? doc.asks : [];
  } catch {
    return [];
  }
}

export function priorAsk(session, command, { file = ASKS_FILE, now = Date.now() } = {}) {
  if (!session || !command) return null;
  const key = askKey(session, command);
  return readAsks(file).find((a) => a.key === key && now - Date.parse(a.at) < WINDOW_MS) ?? null;
}

function writeAsks(file, asks) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ asks: asks.slice(-MAX_ENTRIES) }), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function recordAsk(session, command, { file = ASKS_FILE, now = Date.now() } = {}) {
  if (!session || !command) return;
  try {
    const key = askKey(session, command);
    const kept = readAsks(file).filter((a) => a.key !== key && now - Date.parse(a.at) < WINDOW_MS);
    kept.push({ key, at: new Date(now).toISOString() });
    writeAsks(file, kept);
  } catch {
  }
}

export function markRan(session, command, { file = ASKS_FILE, now = Date.now() } = {}) {
  if (!session || !command) return false;
  try {
    const key = askKey(session, command);
    const asks = readAsks(file);
    const hit = asks.find((a) => a.key === key && now - Date.parse(a.at) < WINDOW_MS);
    if (!hit || hit.ranAt) return false;
    hit.ranAt = new Date(now).toISOString();
    writeAsks(file, asks);
    return true;
  } catch {
    return false;
  }
}

function readTail(file, bytes) {
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    const text = buf.toString('utf8');
    return start > 0 ? text.slice(text.indexOf('\n') + 1) : text;
  } finally {
    fs.closeSync(fd);
  }
}

function resultText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((c) => (typeof c?.text === 'string' ? c.text : '')).join('\n');
  return '';
}

export function ranAfterApproval(transcriptPath, command, sinceMs) {
  if (!transcriptPath || !command) return false;
  let text;
  try {
    text = readTail(transcriptPath, TRANSCRIPT_TAIL_BYTES);
  } catch {
    return false;
  }
  const uses = new Set();
  const executed = new Set();
  for (const line of text.split('\n')) {
    if (!line) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const blocks = entry?.message?.content;
    if (!Array.isArray(blocks)) continue;
    const at = Date.parse(entry.timestamp ?? '');
    for (const b of blocks) {
      if (b?.type === 'tool_use' && SHELL_TOOL_NAMES.has(b.name) && b.input?.command === command && (!Number.isFinite(at) || at >= sinceMs)) {
        uses.add(b.id);
      }
      if (b?.type === 'tool_result' && b.tool_use_id) {
        const body = resultText(b.content);
        if (b.is_error !== true || /^Exit code \d+/.test(body.trim())) executed.add(b.tool_use_id);
      }
    }
  }
  for (const id of uses) if (executed.has(id)) return true;
  return false;
}

export function rememberedApproval(normalized, command, opts = {}) {
  const session = normalized?.session_id;
  const prior = priorAsk(session, command, opts);
  if (!prior) return false;
  const since = Date.parse(prior.at) - 5000;
  if (opts.agent !== 'claude' && prior.ranAt && Date.parse(prior.ranAt) >= since) return true;
  return ranAfterApproval(normalized?.transcript_path, command, since);
}
