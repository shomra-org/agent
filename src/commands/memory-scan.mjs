import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MAX_ARTIFACT_BYTES, SKIP_DIRS } from '../artifacts/matchers.mjs';
import { api } from '../core/api-client.mjs';
import { guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';

const MEMORY_MATCHERS = [
  /(^|\/)MEMOR(Y|IES)\.(md|json|jsonl|txt)$/i,
  /(^|\/)memor(y|ies)\/[^/]+\.(md|mdx|json|jsonl|txt|ya?ml)$/i,
  /(^|\/)\.(mem0|letta|memgpt)\/[^/]+\.(md|json|jsonl|txt)$/i,
];

const INSTRUCTION_MATCHERS = [
  /(^|\/)(CLAUDE|AGENTS?|GEMINI|CONVENTIONS)\.md$/i,
  /(^|\/)LLMS(-FULL)?\.txt$/i,
  /(^|\/)\.(cursorrules|windsurfrules|clinerules|aiderrules|continuerules|goosehints)$/i,
  /(^|\/)\.github\/copilot-instructions\.md$/i,
  /(^|\/)copilot-instructions\.md$/i,
  /(^|\/)\.cursor\/rules\/.+\.mdc$/i,
  /(^|\/)\.clinerules\/.+\.md$/i,
];

export function isMemoryPath(p) {
  const rel = String(p || '').split(path.sep).join('/');
  return MEMORY_MATCHERS.some((re) => re.test(rel)) || INSTRUCTION_MATCHERS.some((re) => re.test(rel));
}

function walkMemoryFiles(root) {
  const found = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join('/');
      if (isMemoryPath(rel) || isMemoryPath(full)) found.push({ full, rel });
    }
  }
  return found;
}

export async function reportMemoryWrite(url, apiKey, body) {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), guardTimeoutMs());
    await fetch(`${url}/memory/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
  } catch {

  }
}

const NO_STORES_HINT = '(Looked for MEMORY.md, memory/ dirs, .mem0/.letta stores, and rules files: CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md, …)';

function resolveMemoryTarget(positional) {
  const argument = positional[0] || '.';
  const target = path.resolve(String(argument));
  if (!fs.existsSync(target)) {
    console.error(`${red('✗')} Not found: ${argument}`);
    process.exit(EXIT_USAGE);
  }
  return fs.statSync(target).isDirectory()
    ? { target, files: walkMemoryFiles(target) }
    : { target, files: [{ full: target, rel: path.basename(target) }] };
}

function readStoreContent(file, flags) {
  try {
    if (fs.statSync(file.full).size > MAX_ARTIFACT_BYTES) {
      if (!flags.json) console.log(`  ${gray('•')} ${dim(file.rel)} ${yellow('skipped (too large)')}`);
      return null;
    }
    return fs.readFileSync(file.full, 'utf8');
  } catch {
    return null;
  }
}

function worseVerdict(current, next) {
  if (current === 'FAIL' || next === 'FAIL') return 'FAIL';
  if (current === 'REVIEW' || next === 'REVIEW') return 'REVIEW';
  return 'PASS';
}

function printStore(file, report) {
  const verdict = report?.store?.verdict || 'PASS';
  const colour = VERDICT_COLOR[verdict] || gray;
  const poisonScore = report?.store?.poisonScore ?? 0;
  const anomalous = report?.provenance?.anomalous;

  const quarantineNote = report?.quarantined ? ` ${red('QUARANTINED')}` : '';
  const provenanceNote = anomalous ? ` ${red('OUT-OF-BAND WRITE')}` : '';
  console.log(`\n  ${colour('●')} ${bold(path.basename(file.rel))} ${dim(file.rel)} ${colour(verdict)} ${dim(`poison ${poisonScore}/100`)}${quarantineNote}${provenanceNote}`);

  for (const finding of (report?.analysis?.findings || []).filter((f) => f.severity !== 'INFO')) {
    console.log(`      ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}`);
  }
  if (anomalous) console.log(`      ${red('provenance:')} ${dim(report.provenance.reason)}`);
}

function summaryLine(worst) {
  if (worst === 'FAIL') return red('✗ Memory poisoning detected - roll back the affected stores.');
  if (worst === 'REVIEW') return yellow('⚠ Review the flagged memory before the agent reloads it.');
  return green('✓ No memory poisoning found.');
}

export async function cmdMemoryScan(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey) exitNotConfigured();

  const { target, files } = resolveMemoryTarget(positional);
  if (!files.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, stores: [] }, null, 2));
    else console.log(dim(`\n  No memory or rules files found under ${target}.\n  ${NO_STORES_HINT}\n`));
    return;
  }

  const ingestFields = {
    scope: flags.scope ? String(flags.scope).toLowerCase() : undefined,
    writer: flags.writer ? String(flags.writer).toUpperCase() : 'AGENT',
    actor: `${os.hostname()}/${os.userInfo().username}`,
    source: 'shomra memory-scan',
    ...(flags.project ? { projectId: String(flags.project) } : {}),
  };

  if (!flags.json) {
    console.log(bold(cyan('\n  Shomra Memory Integrity')) + dim(` - scanning ${files.length} store${files.length > 1 ? 's' : ''}`));
  }

  let worst = 'PASS';
  const stores = [];
  for (const file of files) {
    const content = readStoreContent(file, flags);
    if (content == null) continue;

    let report;
    try {
      report = await api(url, apiKey, '/memory/ingest', {
        ...ingestFields,
        path: file.rel,
        name: path.basename(file.rel),
        content,
      });
    } catch (error) {
      console.error(`  ${red('✗')} ${file.rel} ${red(`ingest error: ${error.message}`)}`);
      continue;
    }

    worst = worseVerdict(worst, report?.store?.verdict || 'PASS');
    stores.push({ path: file.rel, ...report });
    if (!flags.json) printStore(file, report);
  }

  if (flags.json) {
    console.log(JSON.stringify({ scanned: stores.length, worst, stores }, null, 2));
  } else {
    console.log(`\n  ${summaryLine(worst)}${dim(' Full timeline + rollback in the Shomra dashboard → Memory.\n')}`);
  }

  if (worst === 'FAIL') process.exitCode = 1;
  else if (worst === 'REVIEW' && flags.strict) process.exitCode = 2;
}
