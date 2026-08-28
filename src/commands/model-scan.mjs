import os from 'node:os';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { modelLookup, printAlternatives } from '../models/lookup.mjs';

const USAGE = 'shomra model-scan <hf-url | owner/model | github-url> [--project <id>] [--json]';

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

export async function cmdModelScan(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey) exitNotConfigured();

  const target = positional[0];
  if (!target) {
    console.error(`${red('✗')} Usage: ${bold(USAGE)}`);
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

  if (report.verdict === 'FAIL') process.exitCode = 1;
  else if (report.verdict === 'REVIEW' && flags.strict) process.exitCode = 2;
}

function hfModelIdFromTarget(target) {
  const t = String(target || '').trim();
  const hf = t.match(/huggingface\.co\/([^/\s?#]+\/[^/\s?#]+)/i);
  if (hf) return hf[1];
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !/github\.com/i.test(t)) return t;
  return null;
}
