import fs from 'node:fs';
import os from 'node:os';
import { api } from '../core/api-client.mjs';
import { PUBLIC_BACKEND_URL, loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { scanLocalModelPath } from '../models/local-scan.mjs';
import { modelLookup, printAlternatives } from '../models/lookup.mjs';

const USAGE = 'shomra model-scan <path | hf-url | owner/model | github-url> [--project <id>] [--json]';
const PUBLIC_SCAN_TIMEOUT_MS = 180_000;

async function requestModelScan({ url, apiKey, target, flags }) {
  if (!flags.json) process.stdout.write(dim(`\n  Scanning ${target}… `));
  try {
    const report = await api(url, apiKey, '/projects/agent-model-scan', {
      target: String(target),
      actor: `${os.hostname()}/${os.userInfo().username}`,
      ...(flags.project ? { projectId: String(flags.project) } : {}),
    });
    if (!flags.json) console.log(green('done'));
    return report;
  } catch (error) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${error.message}\n`);
    return process.exit(1);
  }
}

function printAssetVulnerabilities(report) {
  for (const asset of report.assets || []) {
    const vulnerabilities = (asset.vulnerabilities || []).filter((v) => v.severity !== 'INFO');
    if (!vulnerabilities.length) continue;

    console.log(`\n  ${bold(asset.name)} ${dim(`(${asset.assetType})`)}`);
    for (const vulnerability of vulnerabilities) {
      console.log(`    ${SEV_COLOR[vulnerability.severity](String(vulnerability.severity).padEnd(8))} ${vulnerability.title}`);
      const evidence = vulnerability.evidence?.analysis === 'sast' ? vulnerability.evidence : null;
      if (!evidence) continue;
      const source = evidence.source ? ` · source ${evidence.source}` : '';
      console.log(`        ${dim(`${evidence.ruleId} · ${evidence.file}:${evidence.line} · sink ${evidence.sink}${source}`)}`);
      if (evidence.snippet) console.log(`        ${gray(evidence.snippet)}`);
    }
  }
}

async function printSaferAlternatives(url, report, target) {
  if (report.verdict !== 'FAIL' && report.verdict !== 'REVIEW') return;
  const modelId = hfModelIdFromTarget(String(report.target || target));
  if (!modelId) return;

  try {
    const lookup = await modelLookup(url, modelId);
    if (!Array.isArray(lookup?.alternatives) || !lookup.alternatives.length) return;
    console.log(`\n  ${bold('Safer alternatives')}${dim(' (same category, lower risk):')}`);
    printAlternatives(lookup.alternatives, 'model', '    ');
  } catch {
    return;
  }
}

function summaryLine(verdict) {
  if (verdict === 'FAIL') return red('✗ Do not load this model unreviewed.');
  if (verdict === 'REVIEW') return yellow('⚠ Review the findings above before trusting this model.');
  return green('✓ No high-severity issues found.');
}

function exitFor(verdict, flags) {
  if (verdict === 'FAIL') process.exitCode = 1;
  else if (verdict === 'REVIEW' && flags.strict) process.exitCode = 2;
}

function printLocalScan(report) {
  const colour = VERDICT_COLOR[report.verdict] || gray;
  const f = report.files;
  console.log(`\n  ${bold(report.target)} ${dim('· on this machine')}`);
  console.log(`  ${colour('●')} ${colour(bold(report.verdict))} ${dim(`${f.read} of ${f.considered} file(s) read${f.partial ? ` · ${f.partial} partly` : ''}${f.unread ? ` · ${f.unread} not read` : ''}${f.truncated ? ' · stopped at the file limit' : ''}`)}`);
  for (const x of report.findings.filter((v) => v.severity !== 'INFO')) {
    const where = x.file && !x.title.includes(x.file) ? dim(` · ${x.file}${x.line ? `:${x.line}` : ''}`) : x.line ? dim(` (line ${x.line})`) : '';
    console.log(`    ${SEV_COLOR[x.severity](String(x.severity).padEnd(8))} ${x.title}${where}`);
    if (x.sink) console.log(`        ${dim(`sink ${x.sink}`)}`);
    if (x.remediation && (x.severity === 'CRITICAL' || x.severity === 'HIGH')) console.log(`        ${dim('fix: ' + x.remediation)}`);
  }
  const tail = report.coverage === 'floor' ? dim(' Part of this was not read - a floor, not a clearance.') : '';
  console.log(`\n  ${summaryLine(report.verdict)}${tail}\n`);
}

function localModelScan(target, flags) {
  let report;
  try {
    report = scanLocalModelPath(target);
  } catch (error) {
    console.error(`  ${red('✗')} cannot scan ${target}: ${error.message}`);
    return process.exit(1);
  }
  if (flags.json) console.log(JSON.stringify({ source: 'local', ...report }, null, 2));
  else printLocalScan(report);
  exitFor(report.verdict, flags);
}

async function publicModelScan(ref, flags, base) {
  if (!flags.json) process.stdout.write(dim(`\n  Scanning ${ref} with the free public scanner… `));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PUBLIC_SCAN_TIMEOUT_MS);
  let res;
  try {
    res = await fetch(`${base}/public/model-scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'shomra-agent' },
      body: JSON.stringify({ ref }),
      signal: ctrl.signal,
    });
  } catch (error) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} the public scanner could not be reached (${error.name === 'AbortError' ? 'timed out' : error.message})\n`);
    return process.exit(1);
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 429) {
    if (!flags.json) console.log(yellow('busy'));
    console.error(`  ${yellow('!')} The free scanner takes a few scans a minute from one address. Wait a minute, or enroll (${bold('shomra init')}) for org scans.\n`);
    return process.exit(1);
  }
  if (!res.ok) {
    if (!flags.json) console.log(red('failed'));
    const body = await res.text().catch(() => '');
    console.error(`  ${red('✗')} HTTP ${res.status}${body ? dim(` - ${body.replace(/\s+/g, ' ').slice(0, 200)}`) : ''}\n`);
    return process.exit(1);
  }
  const report = await res.json();
  if (flags.json) {
    console.log(JSON.stringify({ source: 'public', ...report }, null, 2));
  } else {
    console.log(green('done'));
    const colour = VERDICT_COLOR[report.verdict] || gray;
    console.log(`\n  ${bold(report.ref || ref)} ${dim(`· public scan${report.cached ? ' (cached)' : ''}${report.revisionSha ? ` · ${String(report.revisionSha).slice(0, 12)}` : ''}`)}`);
    console.log(`  ${colour('●')} ${colour(bold(report.verdict))} ${dim(`risk ${report.riskScore}/100 · ${(report.findings || []).length} finding(s)`)}`);
    for (const x of (report.findings || []).filter((v) => v.severity !== 'INFO')) {
      console.log(`    ${SEV_COLOR[x.severity](String(x.severity).padEnd(8))} ${x.title}${x.file ? dim(` · ${x.file}`) : ''}`);
    }
    if (report.executable?.statement) console.log(`\n  ${dim(report.executable.statement)}`);
    else if (report.coverage?.statement) console.log(`\n  ${dim(report.coverage.statement)}`);
    await printSaferAlternatives(base, report, ref);
    console.log(`\n  ${summaryLine(report.verdict)}${dim(' Only the model name was sent - nothing from this machine.\n')}`);
  }
  exitFor(report.verdict, flags);
}

export async function cmdModelScan(flags, positional) {
  const target = positional[0];
  if (!target) {
    console.error(`${red('✗')} Usage: ${bold(USAGE)}`);
    process.exit(EXIT_USAGE);
  }
  if (fs.existsSync(String(target))) return localModelScan(String(target), flags);

  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey) {
    const ref = hfModelIdFromTarget(String(target));
    if (ref) return publicModelScan(ref, flags, url || PUBLIC_BACKEND_URL);
    console.error(`\n  ${red('✗')} ${bold(String(target))} is not a file or folder here, and only Hugging Face models can be scanned without an account.`);
    console.error(`  ${dim('Clone it and run')} ${bold('shomra model-scan <folder>')}${dim(', or enroll with')} ${bold('shomra init --key shm_…')} ${dim('for repository scans.')}\n`);
    process.exit(EXIT_USAGE);
  }

  const report = await requestModelScan({ url, apiKey, target, flags });

  if (flags.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    const colour = VERDICT_COLOR[report.verdict] || gray;
    console.log(`\n  ${bold(report.target || target)} ${dim(`· ${report.scanType} scan`)}`);
    console.log(`  ${colour('●')} ${colour(bold(report.verdict))} ${dim(`risk ${report.riskScore}/100 · ${report.vulnCount} finding(s) · ${report.criticalCount} critical · ${report.highCount} high`)}`);

    printAssetVulnerabilities(report);
    await printSaferAlternatives(url, report, target);
    console.log(`\n  ${summaryLine(report.verdict)}${dim(' Full report in the Shomra dashboard → Projects.\n')}`);
  }

  exitFor(report.verdict, flags);
}

function hfModelIdFromTarget(target) {
  const t = String(target || '').trim();
  const hf = t.match(/huggingface\.co\/([^/\s?#]+\/[^/\s?#]+)/i);
  if (hf) return hf[1];
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !/github\.com/i.test(t)) return t;
  return null;
}
