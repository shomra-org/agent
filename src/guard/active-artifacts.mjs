import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES } from '../artifacts/matchers.mjs';
import { CONFIG_DIR } from '../core/config.mjs';
import { artifactName } from '../inventory/artifacts/discover.mjs';
import { sha256 } from './memory-write.mjs';

export const ACTIVE_ARTIFACTS_DIR = path.join(CONFIG_DIR, 'active-artifacts');
export const MAX_ACTIVE_ARTIFACTS = 20;

const MAX_SESSIONS = 32;
const MAX_TRACKED = 400;
const MAX_DIR_ENTRIES = 200;
const MAX_DEPTH = 3;
const MAX_NAME = 200;

function sigOf(st) {
  return `${st.isDirectory() ? 'd' : 'f'}:${st.mtimeMs}:${st.size}`;
}

function statOf(p) {
  try {
    return fs.statSync(p);
  } catch {
    return null;
  }
}

function statSig(p) {
  const st = statOf(p);
  return st ? sigOf(st) : null;
}

function realOr(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

export function discoverActiveArtifacts({ projectDir, home = os.homedir() }) {
  const project = path.resolve(projectDir);
  const items = [];
  const sig = [];
  const taken = new Set();
  const full = () => items.length >= MAX_ACTIVE_ARTIFACTS || sig.length >= MAX_TRACKED;

  const track = (p) => {
    const st = statOf(p);
    sig.push([p, st ? sigOf(st) : null]);
    return st;
  };

  const list = (dir) => {
    if (full() || !track(dir)) return [];
    try {
      return fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)).slice(0, MAX_DIR_ENTRIES);
    } catch {
      return [];
    }
  };

  const take = (kind, base, file, withPath = true) => {
    if (full()) return;
    const st = track(file);
    if (!st?.isFile()) return;
    const real = realOr(file);
    if (taken.has(real)) return;
    taken.add(real);
    let content = null;
    try {
      if (st.size <= MAX_ARTIFACT_BYTES) content = fs.readFileSync(file, 'utf8');
    } catch {
      content = null;
    }
    const rel = path.relative(base, file).split(path.sep).join('/');
    const item = {
      kind,
      name: String(artifactName(kind, content ?? '', file) ?? '').slice(0, MAX_NAME),
      ...(withPath ? { path: rel } : {}),
      ...(content != null ? { hash: sha256(content) } : {}),
    };
    if (item.path || item.hash) items.push(item);
  };

  const markdown = (kind, base, dir, withPath, depth = 0) => {
    for (const e of list(dir)) {
      if (full()) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < MAX_DEPTH) markdown(kind, base, p, withPath, depth + 1);
      } else if (/\.md$/i.test(e.name)) take(kind, base, p, withPath);
    }
  };

  const skills = (base, dir) => {
    for (const e of list(dir)) {
      if (full()) return;
      if (e.isDirectory() || e.isSymbolicLink()) take('skill', base, path.join(dir, e.name, 'SKILL.md'));
    }
  };

  const scopes = [[project, path.join(project, '.claude')], [home, path.join(home, '.claude')]];
  take('rules', project, path.join(project, 'CLAUDE.md'), false);
  take('rules', project, path.join(project, '.claude', 'CLAUDE.md'), false);
  take('rules', project, path.join(project, 'CLAUDE.local.md'), false);
  take('rules', home, path.join(home, '.claude', 'CLAUDE.md'), false);
  for (const [base, dir] of scopes) markdown('rules', base, path.join(dir, 'rules'), false);
  for (const [base, dir] of scopes) skills(base, path.join(dir, 'skills'));
  for (const [base, dir] of scopes) markdown('subagent', base, path.join(dir, 'agents'), true);
  for (const [base, dir] of scopes) markdown('command', base, path.join(dir, 'commands'), true);
  return { items, sig };
}

function sessionFile(dir, sessionId, projectDir, home) {
  return path.join(dir, `${sha256(`${sessionId ?? ''}\u0000${path.resolve(projectDir)}\u0000${path.resolve(home)}`).slice(0, 32)}.json`);
}

function stillValid(entry) {
  return Array.isArray(entry?.sig) && Array.isArray(entry?.items) && entry.sig.every((row) => Array.isArray(row) && statSig(row[0]) === row[1]);
}

function prune(dir) {
  try {
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
    if (files.length <= MAX_SESSIONS) return;
    const aged = files.map((f) => ({ f, at: statOf(path.join(dir, f))?.mtimeMs ?? 0 })).sort((a, b) => a.at - b.at);
    for (const { f } of aged.slice(0, files.length - MAX_SESSIONS)) fs.rmSync(path.join(dir, f), { force: true });
  } catch {
  }
}

export function activeArtifactsFor({ sessionId, projectDir, home = os.homedir(), dir = ACTIVE_ARTIFACTS_DIR }) {
  const file = sessionFile(dir, sessionId, projectDir, home);
  try {
    const entry = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (stillValid(entry)) return entry.items;
  } catch {
  }
  const found = discoverActiveArtifacts({ projectDir, home });
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(found), { mode: 0o600 });
    fs.renameSync(tmp, file);
    prune(dir);
  } catch {
  }
  return found.items;
}

export function activeArtifactsField(agent, normalized, { home = os.homedir(), dir = ACTIVE_ARTIFACTS_DIR, env = process.env } = {}) {
  if (agent !== 'claude') return {};
  try {
    const projectDir = env.CLAUDE_PROJECT_DIR || normalized?.cwd || process.cwd();
    return { active_artifacts: activeArtifactsFor({ sessionId: normalized?.session_id, projectDir, home, dir }).slice(0, MAX_ACTIVE_ARTIFACTS) };
  } catch {
    return {};
  }
}
