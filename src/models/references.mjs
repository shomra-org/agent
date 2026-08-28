import fs from 'node:fs';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES } from '../artifacts/matchers.mjs';
import { isModelRefScannable, scanModelRefs } from '../detect/model-refs.mjs';
import { MODEL_SEV_RANK, modelFixPlan, modelLookup } from './lookup.mjs';

const DEFAULT_LOOKUP_CONCURRENCY = 6;

export function resolveScanScope(target, walkFiles) {
  try {
    const stats = fs.statSync(target);
    if (stats.isFile()) return { root: path.dirname(target), entries: [path.basename(target)] };
    return { root: target, entries: walkFiles(target) };
  } catch {
    return { root: target, entries: [] };
  }
}

function readScannableFile(root, relativePath) {
  try {
    const full = path.join(root, relativePath);
    if (fs.statSync(full).size > MAX_ARTIFACT_BYTES) return null;
    const content = fs.readFileSync(full, 'utf8');
    return content.includes('\0') ? null : content;
  } catch {
    return null;
  }
}

export function collectModelReferences(root, entries) {
  const byKey = new Map();
  for (const relativePath of entries) {
    if (!isModelRefScannable(relativePath)) continue;
    const content = readScannableFile(root, relativePath);
    if (content == null) continue;

    for (const reference of scanModelRefs(content, relativePath)) {
      const key = `${reference.source}:${reference.id}:${reference.revision || ''}`;
      if (!byKey.has(key)) {
        byKey.set(key, { id: reference.id, sha: reference.revision || null, source: reference.source, locations: [] });
      }
      byKey.get(key).locations.push({ file: reference.file, line: reference.line, via: reference.via });
    }
  }
  return [...byKey.values()];
}

export async function lookupModels(url, references, concurrency = DEFAULT_LOOKUP_CONCURRENCY) {
  const results = new Array(references.length).fill(null);
  let indexUnreachable = false;
  let nextIndex = 0;

  const worker = async () => {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= references.length || indexUnreachable) return;

      if (references[index].source === 'ollama') {
        results[index] = { found: false, local: true };
        continue;
      }
      try {
        results[index] = await modelLookup(url, references[index].id, references[index].sha);
      } catch (error) {
        indexUnreachable = true;
        results[index] = { error: error.message };
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, references.length) }, worker));
  return { results, indexUnreachable };
}

function alertLevel(lookup, findings) {
  const worst = findings.reduce((rank, finding) => Math.max(rank, MODEL_SEV_RANK[finding.severity] || 0), 0);
  if (!lookup.found) return 'OK';
  if (lookup.verdict === 'FAIL' || worst >= MODEL_SEV_RANK.CRITICAL) return 'BLOCK';
  if (lookup.verdict === 'REVIEW' || worst >= MODEL_SEV_RANK.HIGH) return 'FLAG';
  return 'OK';
}

export function assessModel(reference, rawLookup) {
  const lookup = rawLookup || {};
  const findings = lookup.findings || [];
  const alert = alertLevel(lookup, findings);

  return {
    ...reference,
    found: !!lookup.found,
    verdict: lookup.verdict || null,
    riskScore: lookup.riskScore ?? null,
    scannedSha: lookup.sha || null,
    findingCount: findings.length,
    findings,
    alert,
    fix: lookup.found && alert !== 'OK' && reference.source === 'hf' ? modelFixPlan(findings, lookup.sha) : null,
    alternatives: alert !== 'OK' ? (lookup.alternatives || []) : [],
    error: lookup.error,
    notIndexed: !lookup.found && !lookup.error,
  };
}
