import { createHash, randomUUID } from 'node:crypto';
import os from 'node:os';
import { VENDOR_TOOLS } from '../agents/vendor-tools.mjs';
import { redactLocally } from '../detect/local-redact.mjs';
import { SHELL_TOOL_NAMES, WRITE_TOOLS } from '../guard/classify.mjs';
import { commandShape, targetShape } from './command-shape.mjs';

export const SCHEMA = 1;

export const CHANNELS = ['tool', 'result', 'prompt', 'plan', 'gate', 'add', 'mcp'];

export const VERDICTS = ['ALLOW', 'FLAG', 'BLOCK', 'ASK'];

export const LABELS = ['forced', 'suppressed', 'policy-allow', 'baseline', 'inline', 'feedback-fp', 'approved'];

const SEVERITIES = new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const MAX_RULES = 12;

export const MAX_SAMPLE = 1_000;

const READ_TOOLS = ['Read', 'Glob', 'Grep', 'LS', 'WebFetch', 'WebSearch', 'NotebookRead', 'Task', 'TodoWrite', 'ExitPlanMode', 'UserPromptSubmit', 'read_file', 'list_dir', 'list_directory', 'grep_search', 'file_search', 'codebase_search', 'web_search', 'web_fetch', 'view', 'search_files', 'glob', 'read_many_files'];

const KNOWN_TOOLS = new Set(
  [
    ...READ_TOOLS,
    ...WRITE_TOOLS,
    ...SHELL_TOOL_NAMES,
    ...Object.values(VENDOR_TOOLS).flatMap((v) => [...(v.required ?? []), ...(v.events ?? []), ...(v.postEvents ?? [])].map((t) => t.name)),
  ]
    .filter((n) => typeof n === 'string' && !n.includes('*'))
    .map((n) => n.toLowerCase()),
);

export function toolKey(name) {
  const t = String(name ?? '').trim();
  if (!t) return null;
  if (t === 'mcp' || t === 'other') return t;
  if (/^mcp__/i.test(t) || /^use_mcp_tool$/i.test(t) || (/mcp/i.test(t) && /[:/]/.test(t))) return 'mcp';
  return KNOWN_TOOLS.has(t.toLowerCase()) ? t.slice(0, 40) : 'other';
}

export function agentKey(agent) {
  const a = String(agent ?? '').trim().toLowerCase();
  return /^[a-z][a-z0-9-]{1,19}$/.test(a) ? a : 'other';
}

export function kindKey(kind) {
  const k = String(kind ?? '').trim();
  if (/^[A-Z][A-Z0-9_]{1,40}$/.test(k)) return k;
  if (/^[a-z][a-z0-9-]{1,24}$/.test(k)) return k;
  return 'other';
}

export function severityOf(s) {
  const v = String(s ?? '').toUpperCase();
  return SEVERITIES.has(v) ? v : 'INFO';
}

const clean = (s, max) => redactLocally(String(s ?? '')).text.replace(/\s+/g, ' ').trim().slice(0, max);

export function runtimeRule(f) {
  return { k: `${/^[a-z]{2,16}$/.test(f?.category ?? '') ? f.category : 'other'}:${clean(f?.label ?? f?.title, 120)}`, s: severityOf(f?.severity) };
}

export function normalizeTitle(title) {
  return clean(title, 400)
    .replace(/"[^"]*"|“[^”]*”|`[^`]*`/g, '"…"')
    .replace(/(^|[\s(])'[^'\n]{1,80}'(?=$|[\s.,;:)])/g, '$1"…"')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s)]+/gi, '<url>')
    .replace(/(^|[\s(])@?[\w.~-]*(?:[\\/][\w.@~-]+)+[\\/]?/g, '$1<path>')
    .replace(/\b[\w.-]+\.(?:js|mjs|cjs|ts|tsx|jsx|json|jsonc|ya?ml|md|toml|py|sh|ps1|env|txt|ipynb|lock|cfg|ini|xml)\b/gi, '<file>')
    .slice(0, 120);
}

export function gateRule(f) {
  if (typeof f?.ruleId === 'string' && /^[\w.:/-]{2,100}$/.test(f.ruleId)) return { k: `rule:${f.ruleId}`, s: severityOf(f?.severity) };
  return { k: `title:${normalizeTitle(f?.title ?? f?.label)}`, s: severityOf(f?.severity) };
}

function rulesOf(findings, rule) {
  const seen = new Set();
  const out = [];
  for (const f of findings ?? []) {
    const r = rule(f);
    if (!r.k || seen.has(r.k)) continue;
    seen.add(r.k);
    out.push(r);
    if (out.length >= MAX_RULES) break;
  }
  return out;
}

export function sessionKey(sessionId, salt) {
  const s = String(sessionId ?? '').trim();
  if (!s) return null;
  return createHash('sha256').update(`${salt ?? ''}:${s}`).digest('hex').slice(0, 16);
}

export function sizeBucket(n) {
  if (!Number.isFinite(n)) return undefined;
  return n < 100 ? 'xs' : n < 1_000 ? 's' : n < 10_000 ? 'm' : 'l';
}

function scrubIdentity(text) {
  let out = text;
  const swaps = [];
  try {
    swaps.push([os.homedir(), '~']);
    swaps.push([os.userInfo().username, '<user>']);
    swaps.push([os.hostname(), '<host>']);
  } catch {
    return out;
  }
  for (const [needle, repl] of swaps) if (needle && needle.length >= 3) out = out.split(needle).join(repl);
  return out;
}

export function sampleText(text, at) {
  const src = String(text ?? '');
  if (!src) return undefined;
  const start = Number.isFinite(at) ? Math.max(0, at - MAX_SAMPLE / 2) : 0;
  const redacted = redactLocally(src.slice(start, start + MAX_SAMPLE * 2)).text;
  return scrubIdentity(redacted).slice(0, MAX_SAMPLE);
}

export function verdictEvent(input) {
  const { channel, agent, tool, kind, verdict, findings, shadow, rule = runtimeRule, command, target, text, at, consequence, session, salt, latencyMs, decidedBy, level } = input;
  const rules = [...rulesOf(findings, rule), ...rulesOf(shadow, (f) => { const r = rule(f); return { ...r, k: r.k ? `shadow:${r.k}` : r.k }; })].slice(0, MAX_RULES);
  const shape = command ? commandShape(command) : null;
  const tg = target ? targetShape(target) : null;
  const ev = {
    k: 'verdict',
    id: randomUUID(),
    at: new Date().toISOString(),
    c: CHANNELS.includes(channel) ? channel : 'tool',
    ...(agent ? { a: agentKey(agent) } : {}),
    ...(tool ? { t: toolKey(tool) } : {}),
    ...(kind ? { kind: kindKey(kind) } : {}),
    d: VERDICTS.includes(verdict) ? verdict : 'ALLOW',
    ...(decidedBy ? { by: String(decidedBy).slice(0, 24) } : {}),
    ...(rules.length ? { r: rules } : {}),
    ...(shape ? { sh: shape } : {}),
    ...(tg ? { tg } : {}),
    ...(consequence ? { cx: String(consequence).slice(0, 16) } : {}),
    ...(typeof text === 'string' ? { len: sizeBucket(text.length) } : {}),
    ...(session ? { ses: sessionKey(session, salt) } : {}),
    ...(Number.isFinite(latencyMs) ? { ms: Math.max(0, Math.round(latencyMs)) } : {}),
  };
  if (level === 'samples' && ev.d !== 'ALLOW' && ev.c !== 'prompt' && typeof text === 'string' && text) ev.x = sampleText(text, at);
  return ev;
}

export function labelEvent(input) {
  const { channel, label, ref, findings, rule = gateRule, kind, tool, shape, dedupe } = input;
  const rules = Array.isArray(input.rules) ? input.rules.filter((r) => r && typeof r.k === 'string').slice(0, MAX_RULES) : rulesOf(findings, rule);
  return {
    k: 'label',
    id: dedupe ? createHash('sha256').update(`label|${dedupe}`).digest('hex').slice(0, 32) : randomUUID(),
    at: new Date().toISOString(),
    c: CHANNELS.includes(channel) ? channel : 'gate',
    lb: LABELS.includes(label) ? label : 'suppressed',
    ...(ref ? { ref: String(ref).slice(0, 64) } : {}),
    ...(tool ? { t: toolKey(tool) } : {}),
    ...(kind ? { kind: kindKey(kind) } : {}),
    ...(rules.length ? { r: rules } : {}),
    ...(shape ? { sh: String(shape).slice(0, 600) } : {}),
  };
}

export function tickOf(ev) {
  return {
    k: 'tick',
    at: Date.parse(ev.at),
    c: ev.c,
    ...(ev.t ? { t: ev.t } : {}),
    ...(ev.kind ? { kind: ev.kind } : {}),
    ...(ev.a ? { a: ev.a } : {}),
    d: ev.d,
    ...(ev.sh ? { sh: ev.sh } : {}),
    ...(ev.tg ? { tg: ev.tg } : {}),
    ...(ev.r?.length ? { r: ev.r } : {}),
  };
}

export function aggregateTicks(records, batchKey = '') {
  const groups = new Map();
  const events = [];
  for (const rec of records ?? []) {
    if (!rec || typeof rec !== 'object') continue;
    if (rec.k !== 'tick') {
      if (rec.k === 'verdict' || rec.k === 'label') events.push(rec);
      continue;
    }
    const key = JSON.stringify([rec.c, rec.t ?? null, rec.kind ?? null, rec.a ?? null, rec.d, rec.sh ?? null, rec.tg ?? null, (rec.r ?? []).map((r) => r.k)]);
    const at = Number.isFinite(rec.at) ? rec.at : Date.now();
    const g = groups.get(key);
    if (g) {
      g.n += 1;
      g.from = Math.min(g.from, at);
      g.to = Math.max(g.to, at);
    } else {
      groups.set(key, { rec, n: 1, from: at, to: at });
    }
  }
  for (const [key, g] of groups) {
    const { rec } = g;
    events.push({
      k: 'usage',
      id: createHash('sha256').update(`${batchKey}|${key}`).digest('hex').slice(0, 32),
      at: new Date(g.to).toISOString(),
      from: new Date(g.from).toISOString(),
      c: rec.c,
      ...(rec.t ? { t: rec.t } : {}),
      ...(rec.kind ? { kind: rec.kind } : {}),
      ...(rec.a ? { a: rec.a } : {}),
      d: rec.d,
      ...(rec.sh ? { sh: rec.sh } : {}),
      ...(rec.tg ? { tg: rec.tg } : {}),
      ...(rec.r?.length ? { r: rec.r } : {}),
      n: g.n,
    });
  }
  return events;
}
