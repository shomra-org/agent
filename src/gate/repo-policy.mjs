import fs from 'node:fs';
import path from 'node:path';
import { DEC_RANK } from './sast.mjs';

const SEV_THRESH = { none: 99, critical: 5, high: 4, medium: 3, low: 2, info: 1 };

const SEV_RANK_LOCAL = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

const WEIGHT_LOCAL = { INFO: 2, LOW: 8, MEDIUM: 20, HIGH: 40, CRITICAL: 70 };

function parseSimpleYaml(text) {
  const data = {}; let key = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '');
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const li = /^\s*-\s+(.*)$/.exec(line);
    if (li && key) { (Array.isArray(data[key]) ? data[key] : (data[key] = [])).push(unquote(li[1].trim())); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(line);
    if (!kv) continue;
    key = kv[1];
    const v = kv[2].trim();
    data[key] = v === '' ? (data[key] ?? null) : v.startsWith('[') ? v.replace(/^\[|\]$/g, '').split(',').map((s) => unquote(s.trim())).filter(Boolean) : unquote(v);
  }
  return data;
}

function unquote(s) { return String(s).replace(/^["']|["']$/g, ''); }

export function loadRepoPolicy(root) {
  let text, file;
  for (const f of ['policy.yml', 'policy.yaml', 'policy.json']) {
    try { text = fs.readFileSync(path.join(root, '.shomra', f), 'utf8'); file = f; break; } catch {  }
  }
  if (text === undefined) return null;
  let raw;
  if (file.endsWith('.json')) { try { raw = JSON.parse(text); } catch { return null; } }
  else raw = parseSimpleYaml(text);
  return {
    block: SEV_THRESH[String(raw.block || '').toLowerCase()] ?? SEV_RANK_LOCAL.CRITICAL,
    flag: SEV_THRESH[String(raw.flag || '').toLowerCase()] ?? SEV_RANK_LOCAL.HIGH,
    allow: [].concat(raw.allow || []).map((s) => String(s).toLowerCase()),
  };
}

export function applyRepoPolicy(r, policy) {
  if (!policy) return r;
  let findings = r.findings || [];
  let dropped = 0;
  if (policy.allow.length) {
    const keep = [];
    for (const f of findings) {
      if (policy.allow.some((sub) => sub && String(f.title || '').toLowerCase().includes(sub))) dropped++;
      else keep.push(f);
    }
    findings = keep;
  }
  let worst = 0;
  for (const f of findings) worst = Math.max(worst, SEV_RANK_LOCAL[f.severity] || 0);
  const pv = worst >= policy.block ? 'BLOCK' : worst >= policy.flag ? 'FLAG' : 'ALLOW';
  const riskScore = Math.min(100, findings.reduce((s, f) => s + (WEIGHT_LOCAL[f.severity] || 0), 0));

  const decision = r.source === 'server' ? (DEC_RANK[pv] > DEC_RANK[r.decision] ? pv : r.decision) : pv;
  const extra = dropped ? { suppressedCount: (r.suppressedCount || 0) + dropped, suppressedFindings: [...(r.suppressedFindings || []), ...(r.findings || []).filter((f) => !findings.includes(f)).map((f) => ({ ...f, suppressedBy: 'policy allow' }))] } : {};
  return { ...r, findings, findingCount: findings.length, decision, riskScore: r.source === 'server' ? Math.max(r.riskScore || 0, riskScore) : riskScore, ...extra };
}
