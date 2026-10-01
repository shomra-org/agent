import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES } from '../artifacts/matchers.mjs';
import { api, gateMachine } from '../core/api-client.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { CONFIG_DIR } from '../core/config.mjs';
import { collectSiblings, detectEnv } from '../gate/environment.mjs';
import { declaredName } from '../inventory/artifacts/classify.mjs';
import { installedPluginManifests, manifestName, pluginRootOf } from '../inventory/artifacts/plugins.mjs';
import { emitGuardDeny } from './emit.mjs';
import { sha256 } from './memory-write.mjs';
import { buildGuardBody, reportGuardDecision } from './report.mjs';
import { recordSelftest } from './selftest-marker.mjs';

export const SKILL_VERDICTS_FILE = path.join(CONFIG_DIR, 'skill-verdicts.json');
export const SKILL_VERDICT_TTL_MS = 10 * 60_000;

const VERDICTS = ['ALLOW', 'FLAG', 'BLOCK'];
const MAX_CACHED_VERDICTS = 200;
const MAX_SKILL_DIRS = 200;
const MAX_CANDIDATES = 4;
const MAX_PATH = 500;
const HEAD_BYTES = 4096;
const SKILL_NAME_RE = /^\w[\w.-]{0,127}$/;
const UNSAFE_TEXT_RE = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g;

function clean(text, max = 300) {
  return String(text ?? '').replace(UNSAFE_TEXT_RE, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

export function requestedSkill(input) {
  const raw = [input?.skill, input?.command].find((v) => typeof v === 'string' && v.trim());
  if (!raw) return null;
  const word = raw.trim().replace(/^\/+/, '').split(/\s+/)[0];
  if (!word) return null;
  const cut = word.lastIndexOf(':');
  return { raw: word, scope: cut > 0 ? word.slice(0, cut) : null, name: cut > 0 ? word.slice(cut + 1) : word };
}

function isFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function inside(root, target) {
  const rel = path.relative(root, target);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function realOr(p) {
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

function headOf(file) {
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(HEAD_BYTES);
      const n = fs.readSync(fd, buf, 0, HEAD_BYTES, 0);
      return buf.subarray(0, n).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return '';
  }
}

function skillIn(dir, name) {
  const direct = path.join(dir, name, 'SKILL.md');
  if (isFile(direct)) return direct;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  const dirs = entries.filter((e) => e.isDirectory() || e.isSymbolicLink()).map((e) => e.name).sort().slice(0, MAX_SKILL_DIRS);
  for (const d of dirs) {
    const file = path.join(dir, d, 'SKILL.md');
    if (isFile(file) && declaredName(headOf(file)) === name) return file;
  }
  return null;
}

function pluginSkillDirs(home, plugin) {
  const out = [];
  for (const { manifest } of installedPluginManifests(path.join(home, '.claude'), home)) {
    const root = pluginRootOf(manifest);
    let text = '';
    try {
      text = fs.readFileSync(manifest, 'utf8');
    } catch {
      continue;
    }
    if (manifestName(text, path.basename(root)) === plugin) out.push(path.join(root, 'skills'));
  }
  return out;
}

export function resolveSkill(wanted, { projectDir, cwd, home = os.homedir() }) {
  if (!wanted || !SKILL_NAME_RE.test(wanted.name)) return [];
  const project = path.resolve(projectDir || cwd || process.cwd());
  const roots = [];
  const add = (scope, base, dir) => {
    if (!roots.some((r) => r.dir === dir)) roots.push({ scope, base, dir });
  };
  if (wanted.scope) {
    for (const dir of pluginSkillDirs(home, wanted.scope)) add('user', home, dir);
    const nested = path.resolve(project, wanted.scope);
    if (inside(project, nested)) add('project', project, path.join(nested, '.claude', 'skills'));
  } else {
    add('project', project, path.join(project, '.claude', 'skills'));
    if (cwd) {
      const here = path.resolve(cwd);
      add('project', inside(project, here) ? project : here, path.join(here, '.claude', 'skills'));
    }
    add('user', home, path.join(home, '.claude', 'skills'));
  }
  const found = [];
  const seen = new Set();
  for (const r of roots) {
    const file = skillIn(r.dir, wanted.name);
    const real = file ? realOr(file) : null;
    if (!real || seen.has(real)) continue;
    seen.add(real);
    found.push({ file, scope: r.scope, path: path.relative(r.base, file).split(path.sep).join('/').slice(0, MAX_PATH) });
    if (found.length >= MAX_CANDIDATES) break;
  }
  return found;
}

function readSkill(file) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_ARTIFACT_BYTES) return null;
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

export function skillCacheKey({ url, apiKey, path: rel, content, siblings = [] }) {
  return sha256([url, apiKey, rel, content, ...siblings].join('\u0000'));
}

function readVerdicts(file) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
    return doc && typeof doc === 'object' && !Array.isArray(doc) ? doc : {};
  } catch {
    return {};
  }
}

export function cachedSkillVerdict(key, { file = SKILL_VERDICTS_FILE, now = Date.now(), ttl = SKILL_VERDICT_TTL_MS } = {}) {
  const row = readVerdicts(file)[key];
  if (!row || typeof row.at !== 'number' || now < row.at || now - row.at >= ttl) return null;
  if (!VERDICTS.includes(row.decision)) return null;
  return { decision: row.decision, ...(typeof row.reason === 'string' ? { reason: row.reason } : {}) };
}

export function rememberSkillVerdict(key, verdict, { file = SKILL_VERDICTS_FILE, now = Date.now(), ttl = SKILL_VERDICT_TTL_MS } = {}) {
  try {
    const rows = readVerdicts(file);
    rows[key] = { at: now, decision: verdict.decision, ...(verdict.reason ? { reason: verdict.reason } : {}) };
    const live = Object.entries(rows)
      .filter(([, v]) => v && typeof v.at === 'number' && now - v.at < ttl)
      .sort((a, b) => b[1].at - a[1].at)
      .slice(0, MAX_CACHED_VERDICTS);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(live)), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch {
  }
}

function refusalOf(res) {
  const findings = Array.isArray(res?.findings) ? res.findings : [];
  const top = findings.find((f) => f?.severity === 'CRITICAL') ?? findings.find((f) => f?.severity === 'HIGH') ?? findings[0];
  return clean([res?.decidedBy?.name, top?.title].filter(Boolean).join(': '));
}

function checkBody(skill, normalized) {
  const session = typeof normalized?.session_id === 'string' && normalized.session_id.length <= 200 ? normalized.session_id : null;
  return {
    kind: 'skill',
    path: skill.path,
    content: skill.content,
    ...(skill.siblings.length ? { siblings: skill.siblings } : {}),
    machine: gateMachine(),
    env: detectEnv(),
    ...(session ? { sessionId: session } : {}),
    agent: 'claude',
  };
}

async function verdictFor(skill, { url, apiKey, normalized }) {
  const key = skillCacheKey({ url, apiKey, path: skill.path, content: skill.content, siblings: skill.siblings });
  const hit = cachedSkillVerdict(key);
  if (hit) return { ...hit, skill, cached: true };
  let res;
  try {
    res = await api(url, apiKey, '/gate/check', checkBody(skill, normalized), { timeoutMs: guardTimeoutMs() });
  } catch (error) {
    if (!error?.status || error.status >= 500) breakerTrip();
    return { skill, error: clean(error?.message ?? error, 200) || 'the gate could not be reached' };
  }
  if (!VERDICTS.includes(res?.decision)) return { skill, error: 'the gate answered without a decision' };
  breakerReset();
  const verdict = { decision: res.decision, ...(res.decision === 'BLOCK' ? { reason: refusalOf(res) } : {}) };
  rememberSkillVerdict(key, verdict);
  return { ...verdict, skill };
}

export async function screenSkillInvocation({ agent, tool, input, normalized, url, apiKey, agentId, strict, home = os.homedir() }) {
  if (agent !== 'claude' || tool !== 'Skill' || !url || !apiKey) return null;
  const wanted = requestedSkill(input);
  const cwd = normalized?.cwd || process.cwd();
  const found = wanted ? resolveSkill(wanted, { projectDir: process.env.CLAUDE_PROJECT_DIR || cwd, cwd, home }) : [];
  const shown = clean(wanted?.raw, 120);
  if (!found.length) {
    const why = wanted ? `no SKILL.md found for "${shown}" in the project, ~/.claude/skills or an installed plugin` : 'the call names no skill';
    recordSelftest({ stage: 'skill-unresolved', tool, reason: why });
    process.stderr.write(`[shomra] skill not checked: ${why}\n`);
    return { unresolved: why };
  }
  if (!strict && breakerOpen()) return { unchecked: 'the guard is in its backoff window after an earlier failure' };

  const results = await Promise.all(found.map((f) => {
    const content = readSkill(f.file);
    if (content == null) return { skill: f, error: 'larger than 1 MB or unreadable' };
    const siblings = collectSiblings(f.file, f.path).filter((s) => s.length <= MAX_PATH);
    return verdictFor({ ...f, content, siblings }, { url, apiKey, normalized });
  }));

  const blocked = results.find((r) => r.decision === 'BLOCK');
  if (blocked) {
    const reason = `Blocked by Shomra: the skill "${shown}" (${clean(blocked.skill.path, 200)}) did not pass the gate check${blocked.reason ? ` - ${blocked.reason}` : ''}.`;
    recordSelftest({ stage: 'skill-block', tool, reason, cached: !!blocked.cached });
    await reportGuardDecision(url, apiKey, agentId, buildGuardBody(normalized, agent, 'BLOCK', `Skill "${shown}" refused by the gate check`));
    emitGuardDeny(agent, reason);
  }
  const failed = results.find((r) => r.error);
  if (failed && strict) {
    emitGuardDeny(agent, `Shomra could not check the skill "${shown}" (${failed.error}); blocked by fail-closed policy.`);
  }
  return { results };
}
