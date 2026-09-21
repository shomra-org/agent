import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isMemoryPath, reportMemoryWrite } from '../commands/memory-scan.mjs';
import { outOfBandChange, readLedger, recordLedger, sha256 } from './memory-write.mjs';
import { gateMachine } from '../core/api-client.mjs';

export const OUT_OF_BAND = 'changed outside any agent write the Shomra hook observed';
export const FIRST_SIGHT = 'first observation of this store - baseline only, no write attributed';
export const SESSION_START = 'loaded into session context at start - baseline only, no write attributed';

export const MAX_CONTEXT_FILES = 24;
export const MAX_CONTEXT_BYTES = 256 * 1024;
const MAX_ASCENT = 8;

export function memoryReportBase(filePath, normalized) {
  const machine = gateMachine();
  return {
    path: path.resolve(filePath).split(path.sep).join('/'),
    name: path.basename(String(filePath)),
    machineId: machine.machineId,
    hostname: machine.hostname,
    actor: machine.username,
    sessionId: normalized?.session_id,
  };
}

export async function reportFirstSight(url, apiKey, filePath, current, normalized, source = FIRST_SIGHT) {
  if (current == null || readLedger(filePath)) return false;
  await reportMemoryWrite(url, apiKey, { ...memoryReportBase(filePath, normalized), content: current, writer: 'SCAN', source });
  recordLedger(filePath, [sha256(current)]);
  return true;
}

export async function reportOutOfBand(url, apiKey, filePath, current, normalized, firstSource = FIRST_SIGHT) {
  if (current == null) return;
  if (await reportFirstSight(url, apiKey, filePath, current, normalized, firstSource)) return;
  if (!outOfBandChange(filePath, current)) return;
  await reportMemoryWrite(url, apiKey, { ...memoryReportBase(filePath, normalized), content: current, writer: 'UNKNOWN', source: OUT_OF_BAND });
  recordLedger(filePath, [sha256(current)]);
}

const CONTEXT_BASENAMES = [
  'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'AGENTS.local.md', 'AGENTS.override.md',
  'AGENT.md', 'GEMINI.md', 'QWEN.md', 'CONVENTIONS.md',
  '.cursorrules', '.windsurfrules', '.clinerules', '.aiderrules', '.goosehints', '.rules',
];

const USER_LEVEL = (home) => [
  path.join(home, '.claude', 'CLAUDE.md'),
  path.join(home, '.codex', 'AGENTS.md'),
  path.join(home, '.gemini', 'GEMINI.md'),
  path.join(home, '.qwen', 'QWEN.md'),
  path.join(home, '.config', 'goose', '.goosehints'),
];

function isRepoRoot(dir) {
  try {
    return fs.existsSync(path.join(dir, '.git'));
  } catch {
    return false;
  }
}

export function sessionContextFiles(cwd = process.cwd(), home = os.homedir()) {
  const out = [];
  const seen = new Set();
  const push = (p) => {
    const abs = path.resolve(p);
    if (seen.has(abs) || out.length >= MAX_CONTEXT_FILES) return;
    seen.add(abs);
    let st;
    try {
      st = fs.statSync(abs);
    } catch {
      return;
    }
    if (!st.isFile() || st.size > MAX_CONTEXT_BYTES) return;
    if (!isMemoryPath(abs)) return;
    out.push(abs);
  };

  let dir = path.resolve(cwd);
  for (let i = 0; i < MAX_ASCENT; i++) {
    for (const b of CONTEXT_BASENAMES) push(path.join(dir, b));
    if (isRepoRoot(dir)) break;
    const parent = path.dirname(dir);
    if (parent === dir || parent === path.dirname(home) || dir === home) break;
    dir = parent;
  }
  for (const p of USER_LEVEL(home)) push(p);
  return out;
}

export async function baselineSessionContext({ url, apiKey, cwd, sessionId, home }) {
  if (!url || !apiKey) return { checked: 0, reported: 0 };
  const files = sessionContextFiles(cwd, home);
  const normalized = { session_id: sessionId };
  let reported = 0;
  for (const f of files) {
    let current = null;
    try {
      current = fs.readFileSync(f, 'utf8');
    } catch {
      continue;
    }
    const before = readLedger(f);
    try {
      await reportOutOfBand(url, apiKey, f, current, normalized, SESSION_START);
    } catch {
      continue;
    }
    const after = readLedger(f);
    if (!before || (after && before.hashes?.[0] !== after.hashes?.[0])) reported++;
  }
  return { checked: files.length, reported };
}
