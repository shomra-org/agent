import fs from 'node:fs';
import path from 'node:path';
import { readText } from './file-read.mjs';
import { userDirs } from '../discovery/platform.mjs';

const MAX_SOURCE_FILES = 20;
const MAX_SOURCE_BYTES = 200_000;
const MAX_WALK_DEPTH = 4;
const CODE_RE = /\.(?:[cm]?js|jsx|ts|tsx|py|pyw)$/i;
const SKIP_DIRS = new Set(['node_modules', '.venv', 'venv', 'site-packages', '__pycache__', 'dist-packages', '.git']);

export const EXTENSIONS_DIR_NAME = 'Claude Extensions';

export function claudeDesktopDataDir(platform = process.platform, home) {
  const { HOME, APPDATA } = userDirs(home);
  if (platform === 'darwin') return path.join(HOME, 'Library', 'Application Support', 'Claude');
  if (platform === 'win32') return path.join(APPDATA, 'Claude');
  return path.join(HOME, '.config', 'Claude');
}

export const EXTENSION_MANIFEST_RE = /^claude extensions\/[^/]+\/manifest\.json$/i;

function inside(root, target) {
  const rel = path.relative(root, target);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function realInside(root, target) {
  try { return inside(fs.realpathSync(root), fs.realpathSync(target)); } catch { return false; }
}

function sourceFiles(dir, depth = 0, out = []) {
  if (depth > MAX_WALK_DEPTH || out.length >= MAX_SOURCE_FILES * 3) return out;
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) sourceFiles(full, depth + 1, out); }
    else if (e.isFile() && CODE_RE.test(e.name)) out.push(full);
  }
  return out;
}

export function bundleExtensionSource(artifact, absManifest, toRel, budget, capped) {
  const root = path.dirname(absManifest);
  let doc = null;
  try { doc = JSON.parse(artifact.content); } catch { return; }
  const entry = typeof doc?.server?.entry_point === 'string' ? doc.server.entry_point.replace(/^\$\{__dirname\}[\\/]?/, '') : null;
  const entryAbs = entry ? path.resolve(root, entry) : null;
  const candidates = [
    ...(entryAbs && inside(root, entryAbs) ? [entryAbs] : []),
    ...sourceFiles(root).filter((f) => f !== entryAbs),
  ];
  for (const abs of candidates) {
    if (artifact.files.length >= MAX_SOURCE_FILES) { capped.push({ reason: 'bundle-cap', path: artifact.path }); break; }
    if (!realInside(root, abs)) continue;
    const read = readText(abs, MAX_SOURCE_BYTES);
    if (!read || read.truncated) continue;
    if (Buffer.byteLength(read.text) > budget.bytes) { capped.push({ reason: 'byte-budget', path: toRel(abs) }); continue; }
    budget.bytes -= Buffer.byteLength(read.text);
    artifact.files.push({ path: toRel(abs), content: read.text, binary: false });
  }
  artifact.metadata.bundledCount = artifact.files.length;

  const id = path.basename(root);
  try {
    const dataDir = path.dirname(path.dirname(root));
    const settings = JSON.parse(fs.readFileSync(path.join(dataDir, 'Claude Extensions Settings', `${id}.json`), 'utf8'));
    if (settings?.isEnabled === false) artifact.metadata.activation = 'disabled';
  } catch {  }
}
