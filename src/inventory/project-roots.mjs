import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseLooseToml, stripJsonc } from './grant-extract.mjs';
import { userDirs } from './discovery/platform.mjs';

const MAX_ROOTS = 40;
const MAX_WORKSPACES = 150;
const MAX_CLAUDE_JSON = 8 * 1024 * 1024;

function readJson(file, max) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > max) return null;
    return JSON.parse(stripJsonc(fs.readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
}

function claudeProjects(HOME) {
  const json = readJson(path.join(HOME, '.claude.json'), MAX_CLAUDE_JSON);
  return json && typeof json.projects === 'object' && !Array.isArray(json.projects) ? Object.keys(json.projects).map((p) => ({ dir: p, at: 0 })) : [];
}

function codexProjects(HOME) {
  try {
    const doc = parseLooseToml(fs.readFileSync(path.join(HOME, '.codex', 'config.toml'), 'utf8'));
    return doc && typeof doc.projects === 'object' ? Object.keys(doc.projects).map((p) => ({ dir: p, at: 0 })) : [];
  } catch {
    return [];
  }
}

function folderFromUri(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('file://')) return null;
  try {
    return fileURLToPath(uri);
  } catch {
    return null;
  }
}

function editorWorkspaces(editorUserDir) {
  const out = [];
  for (const app of ['Code', 'Code - Insiders', 'Cursor', 'Windsurf']) {
    const dir = path.join(editorUserDir(app), 'workspaceStorage');
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory());
    } catch {
      continue;
    }
    const stamped = [];
    for (const e of entries) {
      const file = path.join(dir, e.name, 'workspace.json');
      try {
        stamped.push({ file, at: fs.statSync(file).mtimeMs });
      } catch {}
    }
    stamped.sort((a, b) => b.at - a.at);
    for (const { file, at } of stamped.slice(0, MAX_WORKSPACES)) {
      const folder = folderFromUri(readJson(file, 64 * 1024)?.folder);
      if (folder) out.push({ dir: folder, at });
    }
  }
  return out;
}

function isProjectDir(dir, HOME) {
  try {
    const resolved = path.resolve(dir);
    if (resolved === path.resolve(HOME) || resolved === path.parse(resolved).root) return false;
    return fs.statSync(resolved).isDirectory();
  } catch {
    return false;
  }
}

export function projectRoots(cwd = process.cwd(), extra = [], opts = {}) {
  const { HOME, vscodeUserDir } = userDirs(opts.home);
  const candidates = [
    ...extra.map((dir) => ({ dir, at: Infinity })),
    ...editorWorkspaces(vscodeUserDir),
    ...claudeProjects(HOME),
    ...codexProjects(HOME),
  ];
  candidates.sort((a, b) => b.at - a.at);
  const seen = new Set([path.resolve(cwd).toLowerCase()]);
  const roots = [];
  for (const { dir } of candidates) {
    if (!dir) continue;
    const key = path.resolve(dir).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    if (!isProjectDir(dir, HOME)) continue;
    roots.push(path.resolve(dir));
    if (roots.length >= MAX_ROOTS) break;
  }
  return roots;
}
