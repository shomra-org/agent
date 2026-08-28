import fs from 'node:fs';
import { MAX_ARTIFACT_BYTES } from '../artifacts/matchers.mjs';
import { api, gateMachine } from '../core/api-client.mjs';
import { clampInt } from '../core/numbers.mjs';
import { SEV_COLOR, bold, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { applyRepoPolicy, loadRepoPolicy } from './repo-policy.mjs';
import { localAsGateResult } from './result.mjs';
import { collectLocalSast, mergeSastIntoResult } from './sast.mjs';
import { loadBaseline, loadIgnoreRules, suppressResult } from './suppressions.mjs';

const DEFAULT_CONCURRENCY = 8;
const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 32;
const MAX_FINDINGS_SHOWN = 3;
const FAIL_ON_RANK = { critical: 3, high: 2, medium: 1 };

function readArtifact(artifact, quiet) {
  try {
    if (fs.statSync(artifact.full).size > MAX_ARTIFACT_BYTES) {
      if (!quiet) console.log(`  ${gray('•')} ${dim(artifact.rel)} ${yellow('skipped (too large)')}`);
      return null;
    }
    return fs.readFileSync(artifact.full, 'utf8');
  } catch {
    return null;
  }
}

function analyseLocally(artifacts, quiet) {
  const prepared = [];
  for (const artifact of artifacts) {
    const content = readArtifact(artifact, quiet);
    if (content == null) continue;
    prepared.push({
      artifact,
      content,
      local: localGate(content, { kind: artifact.kind, path: artifact.rel }),
      sast: collectLocalSast({ fullPath: artifact.full, relPath: artifact.rel, kind: artifact.kind, content }),
    });
  }
  return prepared;
}

async function requestServerVerdicts(prepared, { apiKey, url, env, flags, quiet }) {
  const verdicts = new Array(prepared.length).fill(null);
  const rejected = [];
  let backendDown = false;
  if (!apiKey) return { verdicts, rejected, backendDown };

  const concurrency = clampInt(process.env.SHOMRA_GATE_CONCURRENCY, DEFAULT_CONCURRENCY, MIN_CONCURRENCY, MAX_CONCURRENCY);
  let nextIndex = 0;

  const worker = async () => {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= prepared.length || backendDown) return;

      const { artifact, content } = prepared[index];
      try {
        verdicts[index] = await api(url, apiKey, '/gate/check', {
          kind: artifact.kind,
          path: artifact.rel,
          content,
          machine: gateMachine(),
          env,
          ...(flags.project ? { projectId: String(flags.project) } : {}),
        });
      } catch (error) {
        if (error?.rejected) {
          rejected.push({ path: artifact.rel, kind: artifact.kind, reason: error.message });
          continue;
        }
        if (!backendDown && !quiet) {
          console.log(`  ${yellow('⚠')} ${dim(`backend unavailable (${error.message}) - on-machine analysis for the rest`)}`);
        }
        backendDown = true;
        return;
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, prepared.length) }, worker));
  return { verdicts, rejected, backendDown };
}

function printResult(result, artifact, source) {
  const colour = result.decision === 'BLOCK' ? red : result.decision === 'FLAG' ? yellow : green;
  const suppressedNote = result.suppressedCount ? dim(` · ${result.suppressedCount} suppressed`) : '';
  const pathNote = artifact.rel !== result.name ? ` ${dim(artifact.rel)}` : '';
  const localNote = source === 'local' ? dim(' ·local') : '';
  const findingCount = result.findingCount ?? (result.findings || []).length;

  console.log(`  ${colour('●')} ${bold(result.name)}${pathNote}${localNote} ${colour(result.decision)} ${dim(`risk ${result.riskScore} · ${findingCount} finding(s)`)}${suppressedNote}`);

  const findings = result.findings || [];
  for (const finding of findings.slice(0, MAX_FINDINGS_SHOWN)) {
    const location = finding.line ? dim(` (${finding.file || artifact.rel}:${finding.line})`) : '';
    console.log(`      ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}${location}`);
  }
  const remaining = findings.length - Math.min(findings.length, MAX_FINDINGS_SHOWN);
  if (remaining > 0) console.log(`      ${dim(`… and ${remaining} more (run with --json for all)`)}`);
}

function resolveSuppression(flags, root) {
  const enabled = !flags['no-suppress'];
  return {
    enabled,
    rules: enabled ? loadIgnoreRules(root) : { fileGlobs: [], findingRules: [] },
    baseline: enabled && !flags['no-baseline'] ? loadBaseline(root) : null,
    lineCache: new Map(),
  };
}

export async function gateArtifactList(artifacts, { apiKey, url, env, flags, root }) {
  const quiet = flags.json || flags.sarif;
  const workingRoot = root || process.cwd();
  const suppression = resolveSuppression(flags, workingRoot);
  const policy = flags['no-policy'] ? null : loadRepoPolicy(workingRoot);

  const prepared = analyseLocally(artifacts, quiet);
  const { verdicts, rejected, backendDown } = await requestServerVerdicts(prepared, { apiKey, url, env, flags, quiet });

  const results = [];
  let blocked = 0;
  let flagged = 0;
  let suppressed = 0;

  prepared.forEach(({ artifact, local, sast }, index) => {
    const serverVerdict = verdicts[index];
    const source = serverVerdict ? 'server' : 'local';
    const base = serverVerdict || localAsGateResult(local, artifact.rel.split('/').pop(), artifact.kind);
    const merged = mergeSastIntoResult(base, sast);

    const raw = { path: artifact.rel, full: artifact.full, kind: artifact.kind, source, ...merged };
    const withSuppressions = suppression.enabled
      ? suppressResult(raw, suppression.rules, suppression.baseline, suppression.lineCache)
      : raw;
    const result = applyRepoPolicy(withSuppressions, policy);

    suppressed += result.suppressedCount || 0;
    results.push(result);
    if (result.decision === 'BLOCK') blocked += 1;
    else if (result.decision === 'FLAG') flagged += 1;

    if (!quiet) printResult(result, artifact, source);
  });

  return { results, blocked, flagged, suppressed, backendDown, rejected };
}

export function failOnHit(flags, blocked, flagged) {
  const threshold = FAIL_ON_RANK[String(flags['fail-on'] || 'critical').toLowerCase()] ?? 3;
  const worst = blocked > 0 ? 3 : flagged > 0 ? 2 : 0;
  return worst > 0 && worst >= threshold;
}
