import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS, walkArtifacts } from '../artifacts/matchers.mjs';
import { isAiUsageScannable, scanAiUsage } from '../detect/ai-usage.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { isModelRefScannable, scanModelRefs } from '../detect/model-refs.mjs';
import { RULES_BEGIN, RULES_TARGETS } from './sections.mjs';

const MAX_RULES_ARTIFACTS = 200;

const MAX_RULES_SOURCE_FILES = 400;

const MAX_RULES_OBSERVED = 8;

const RULES_SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export function rulesContext(root) {

  const managed = new Set(Object.values(RULES_TARGETS).map((t) => t.file));
  const considered = [];
  for (const a of walkArtifacts(root).slice(0, MAX_RULES_ARTIFACTS)) {
    if (managed.has(a.rel)) continue;
    let content;
    try {
      if (fs.statSync(a.full).size > MAX_ARTIFACT_BYTES) continue;
      content = fs.readFileSync(a.full, 'utf8');
    } catch { continue; }
    if (content.includes(RULES_BEGIN)) continue;
    considered.push({ ...a, content });
  }
  const kinds = new Set(considered.map((a) => a.kind));

  const observed = new Map();
  for (const a of considered) {
    let g;
    try { g = localGate(a.content, { kind: a.kind, path: a.rel }); } catch { continue; }
    if (!g || g.verdict === 'ALLOW') continue;
    for (const f of g.findings || []) {
      if (f.severity === 'INFO' || f.severity === 'LOW') continue;
      const title = String(f.title || f.label || '').trim();
      if (!title) continue;
      const row = observed.get(title) || { title, severity: f.severity, files: [] };
      if (row.files.length < 3 && !row.files.includes(a.rel)) row.files.push(a.rel);
      observed.set(title, row);
    }
  }

  let modelRefs = 0, aiUsage = 0;
  for (const f of walkSourceFiles(root, MAX_RULES_SOURCE_FILES)) {
    let text;
    try { text = fs.readFileSync(f.full, 'utf8'); } catch { continue; }
    if (isModelRefScannable(f.rel)) { try { modelRefs += scanModelRefs(text, f.rel).length; } catch {  } }
    if (isAiUsageScannable(f.rel)) { try { aiUsage += scanAiUsage(text, f.rel).length; } catch {  } }
  }

  let mcpRegistered = false;
  for (const rel of ['.mcp.json', '.cursor/mcp.json', '.gemini/settings.json', '.windsurf/mcp_config.json']) {
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
      if (cfg && cfg.mcpServers && cfg.mcpServers.shomra) { mcpRegistered = true; break; }
    } catch {  }
  }

  return {
    kinds,
    mcpRegistered,
    artifactCount: considered.length,
    modelRefs,
    aiUsage,
    observed: [...observed.values()].sort((a, b) => (RULES_SEV_RANK[b.severity] || 0) - (RULES_SEV_RANK[a.severity] || 0)).slice(0, MAX_RULES_OBSERVED),
  };
}

function walkSourceFiles(root, cap) {
  const found = [];
  const stack = [root];
  while (stack.length && found.length < cap) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); continue; }
      if (!isModelRefScannable(ent.name) && !isAiUsageScannable(ent.name)) continue;
      found.push({ full, rel: path.relative(root, full).split(path.sep).join('/') });
      if (found.length >= cap) break;
    }
  }
  return found;
}

export function neutralizeFindingTitle(title) {
  return String(title || '')
    .replace(/\s*\([^)]*\)\s*$/, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
}
