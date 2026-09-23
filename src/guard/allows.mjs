import fs from 'node:fs';
import path from 'node:path';
import { CONFIG_DIR } from '../core/config.mjs';
import { loadIgnoreRules } from '../gate/suppressions.mjs';

export const ALLOWS_FILE = path.join(CONFIG_DIR, 'allows.json');
export const ORG_ALLOWS_FILE = path.join(CONFIG_DIR, 'org-allows.json');
export const TRUST_FILE = path.join(CONFIG_DIR, 'trusted-repos.json');

export const NEVER_ALLOWABLE = new Set(['shomra-self-modify']);

export const DESTRUCTIVE_RULE = 'destructive';

export function slugRule(label) {
  return String(label ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64) || 'unknown';
}

export function ruleIdOf(finding) {
  if (finding?.id) return finding.id;
  return slugRule(finding?.label);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function live(allow, now) {
  if (!allow || typeof allow.rule !== 'string' || !allow.rule) return false;
  if (allow.usedAt) return false;
  if (allow.expiresAt && !(Date.parse(allow.expiresAt) > now)) return false;
  return true;
}

export function readUserAllows(file = ALLOWS_FILE) {
  const doc = readJson(file);
  return Array.isArray(doc?.allows) ? doc.allows : [];
}

export function loadUserAllows(file = ALLOWS_FILE, now = Date.now()) {
  return readUserAllows(file).filter((a) => live(a, now)).map((a) => ({ ...a, source: 'user' }));
}

export function writeUserAllows(list, file = ALLOWS_FILE) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, allows: list }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function repoLineKey(item) {
  return item.glob != null ? `path::${item.glob}` : `${item.rule}::${item.match ?? ''}`;
}

function repoKey(root) {
  try {
    return fs.realpathSync(root);
  } catch {
    return path.resolve(root);
  }
}

export function readRepoTrust(file = TRUST_FILE) {
  const doc = readJson(file);
  return doc?.repos && typeof doc.repos === 'object' ? doc.repos : {};
}

export function trustRepoLines(root, allows, file = TRUST_FILE, now = Date.now()) {
  const repos = readRepoTrust(file);
  const key = repoKey(root);
  const lines = { ...(repos[key]?.lines ?? {}) };
  for (const a of allows) lines[repoLineKey(a)] = new Date(now).toISOString();
  repos[key] = { lines };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, repos }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function repoAllowStatus(root, file = TRUST_FILE) {
  if (!root) return [];
  let raw;
  try {
    raw = loadIgnoreRules(root).ruleAllows ?? [];
  } catch {
    return [];
  }
  if (!raw.length) return [];
  const trusted = readRepoTrust(file)[repoKey(root)]?.lines ?? {};
  return raw.map((a) => ({ ...a, source: 'repo', trusted: Object.prototype.hasOwnProperty.call(trusted, repoLineKey(a)) }));
}

export function loadRepoAllows(root, file = TRUST_FILE) {
  return repoAllowStatus(root, file).filter((a) => a.trusted);
}

export function repoPathStatus(root, file = TRUST_FILE) {
  if (!root) return [];
  let rules;
  try {
    rules = loadIgnoreRules(root);
  } catch {
    return [];
  }
  const sources = rules.fileGlobSources ?? [];
  if (!sources.length) return [];
  const trusted = readRepoTrust(file)[repoKey(root)]?.lines ?? {};
  return sources.map((glob, i) => ({ glob, re: rules.fileGlobs[i], source: 'repo', trusted: Object.prototype.hasOwnProperty.call(trusted, repoLineKey({ glob })) }));
}

export function loadOrgAllows(file = ORG_ALLOWS_FILE, now = Date.now()) {
  const doc = readJson(file);
  const list = Array.isArray(doc?.allows) ? doc.allows : [];
  return list.filter((a) => live(a, now)).map((a) => ({ ...a, source: 'org' }));
}

export function orgAllowsFetchedAt(file = ORG_ALLOWS_FILE) {
  const at = Date.parse(readJson(file)?.fetchedAt ?? '');
  return Number.isFinite(at) ? at : 0;
}

export function writeOrgAllows(allows, { url, now = Date.now() } = {}, file = ORG_ALLOWS_FILE) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const clean = (Array.isArray(allows) ? allows : [])
    .filter((a) => a && typeof a.rule === 'string' && a.rule.length <= 80)
    .slice(0, 500)
    .map((a) => ({
      id: typeof a.id === 'string' ? a.id.slice(0, 64) : undefined,
      rule: a.rule,
      match: typeof a.match === 'string' && a.match ? a.match.slice(0, 200) : undefined,
      expiresAt: typeof a.expiresAt === 'string' ? a.expiresAt : undefined,
    }));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ fetchedAt: new Date(now).toISOString(), url: url ?? null, allows: clean }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

export function allowMatches(allow, ruleId, command, severity) {
  if (NEVER_ALLOWABLE.has(ruleId)) return false;
  if (allow.rule !== ruleId) return false;
  if (!allow.match) return !(allow.source === 'repo' && (severity === 'CRITICAL' || ruleId === DESTRUCTIVE_RULE));
  return String(command ?? '').toLowerCase().includes(String(allow.match).toLowerCase());
}

export function applyAllows(findings, command, allows) {
  const kept = [];
  const allowed = [];
  for (const f of findings ?? []) {
    const id = ruleIdOf(f);
    const hit = (allows ?? []).find((a) => allowMatches(a, id, command, f.severity));
    if (hit) allowed.push({ finding: f, allow: hit });
    else kept.push(f);
  }
  return { findings: kept, allowed };
}

export function consumeOnce(allowed, file = ALLOWS_FILE, now = Date.now()) {
  const onceIds = new Set(allowed.filter((a) => a.allow.source === 'user' && a.allow.once && a.allow.id).map((a) => a.allow.id));
  if (!onceIds.size) return;
  try {
    const list = readUserAllows(file);
    for (const a of list) if (onceIds.has(a.id) && !a.usedAt) a.usedAt = new Date(now).toISOString();
    writeUserAllows(list, file);
  } catch {
  }
}

export function allowHint(ruleId, command, { root, severity } = {}) {
  if (NEVER_ALLOWABLE.has(ruleId)) return '';
  const pending = root ? repoAllowStatus(root).find((a) => !a.trusted && allowMatches(a, ruleId, command, severity)) : null;
  if (pending) return ` This repo's .shomraignore asks to allow it, but that line is not trusted on this machine. Review it, then run in your own terminal: shomra allow --trust-repo`;
  const host = /https?:\/\/([^/\s'"`]+)/i.exec(String(command ?? ''))?.[1];
  const match = host ? ` --match ${host}` : '';
  return ` If this is expected, run in your own terminal: shomra allow ${ruleId}${match} --once`;
}
