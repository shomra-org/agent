import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { isModelConfig, isScannableSource, scanSourceFile } from '../detect/code-sast.mjs';
import { grade } from '../detect/guard-signals.mjs';

const MAX_SAST_FILES = 60;

function walkScripts(root) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < MAX_SAST_FILES) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); continue; }
      if (isScannableSource(ent.name) || isModelConfig(ent.name)) {
        found.push({ full, rel: path.relative(process.cwd(), full).split(path.sep).join('/') });
        if (found.length >= MAX_SAST_FILES) break;
      }
    }
  }
  return found;
}

function sastToFinding(h) {
  const base = h.file ? h.file.split('/').pop() : '';
  return {
    severity: h.severity,
    title: `Risky code - ${h.title}${base ? ` in ${base}` : ''} (${h.sink})`,
    remediationText: h.remediation,
    ...(h.line ? { line: h.line } : {}),
    analysis: 'sast', ruleId: h.ruleId, cwe: h.cwe, sink: h.sink, source: h.source,
    file: h.file, snippet: h.snippet, snippetStartLine: h.snippetStartLine,
  };
}

export function collectLocalSast({ fullPath, relPath, kind, content }) {
  const out = [];
  if (relPath && (isScannableSource(relPath) || isModelConfig(relPath))) {
    for (const h of scanSourceFile(content || '', relPath)) out.push(sastToFinding(h));
  }
  const isSkill = kind === 'skill' || /(^|\/)SKILL\.md$/i.test(relPath || '');
  if (isSkill && fullPath) {
    for (const s of walkScripts(path.dirname(fullPath))) {
      let text;
      try { if (fs.statSync(s.full).size > MAX_ARTIFACT_BYTES) continue; text = fs.readFileSync(s.full, 'utf8'); } catch { continue; }
      for (const h of scanSourceFile(text, s.rel)) out.push(sastToFinding(h));
    }
  }
  return out;
}

export const DEC_RANK = { ALLOW: 0, FLAG: 1, BLOCK: 2 };

export function mergeSastIntoResult(result, sastFindings) {
  if (!sastFindings || !sastFindings.length) return result;
  const findings = [...(result.findings || []), ...sastFindings];
  const g = grade(findings);
  const decision = DEC_RANK[g.verdict] > DEC_RANK[result.decision] ? g.verdict : result.decision;
  return { ...result, decision, riskScore: Math.max(result.riskScore || 0, g.riskScore), findingCount: findings.length, findings };
}
