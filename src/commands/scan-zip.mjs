import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE, exitNotConfigured } from '../core/exit-codes.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, dim, gray, green, red, yellow } from '../core/terminal.mjs';

const MAX_POLICY_HITS_SHOWN = 3;

function resolveArchive(positional) {
  const file = positional[0];
  if (!file) {
    console.error(`${red('✗')} Usage: ${bold('shomra scan-zip <workspace.zip> [--project <id>] [--json]')}`);
    process.exit(EXIT_USAGE);
  }
  const target = path.resolve(String(file));
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    console.error(`${red('✗')} File not found: ${file}`);
    process.exit(EXIT_USAGE);
  }
  if (!/\.zip$/i.test(target)) {
    console.error(`${red('✗')} ${file} is not a .zip archive.`);
    process.exit(EXIT_USAGE);
  }
  return target;
}

function buildUploadForm(target, flags) {
  const form = new FormData();
  form.append('file', new Blob([fs.readFileSync(target)], { type: 'application/zip' }), path.basename(target));
  form.append('actor', `${os.hostname()}/${os.userInfo().username}`);
  if (flags.project) form.append('projectId', String(flags.project));
  return form;
}

async function readResponse(response) {
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text };
  }
  if (response.ok) return body;

  const message = body?.message || body?.raw || response.statusText;
  throw new Error(`${response.status} ${Array.isArray(message) ? message.join(', ') : message}`);
}

async function uploadArchive({ url, apiKey, target, flags }) {
  if (!flags.json) process.stdout.write(dim('\n  Uploading to Workspace Scan… '));
  try {
    const response = await fetch(`${url}/bundle/agent-scan`, {
      method: 'POST',
      headers: { 'X-Shomra-Key': apiKey, Connection: 'close' },
      body: buildUploadForm(target, flags),
    });
    const report = await readResponse(response);
    if (!flags.json) console.log(green('done'));
    return report;
  } catch (error) {
    if (!flags.json) console.log(red('failed'));
    console.error(`  ${red('✗')} ${error.message}\n`);
    return process.exit(1);
  }
}

function printPolicyDecision(report) {
  if (!report.policyDecision || report.policyDecision === 'ALLOW') return;
  const colour = report.policyDecision === 'BLOCK' ? red : yellow;
  const policies = (report.policyHits || []).map((hit) => hit.policy).slice(0, MAX_POLICY_HITS_SHOWN).join(', ');
  console.log(`  ${colour('▎')} ${colour(`org policy: ${report.policyDecision}`)}${policies ? dim(` - ${policies}`) : ''}`);
}

function printArtifactGroups(report) {
  for (const group of report.groups || []) {
    if (!group.count) continue;
    console.log(`\n  ${bold(group.kind.replace(/_/g, ' ').toLowerCase())} ${dim(`(${group.count})`)}`);

    for (const artifact of group.artifacts || []) {
      const colour = VERDICT_COLOR[artifact.verdict] || gray;
      console.log(`    ${colour('●')} ${bold(artifact.name)} ${dim(artifact.path)} ${colour(artifact.verdict)} ${dim(`risk ${artifact.riskScore}`)}`);
      for (const finding of (artifact.findings || []).filter((f) => f.severity !== 'INFO')) {
        console.log(`        ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title}`);
      }
    }
  }
}

function summaryLine(verdict) {
  if (verdict === 'FAIL') return red('✗ Do not install this workspace unreviewed.');
  if (verdict === 'REVIEW') return yellow('⚠ Review the findings above before trusting this workspace.');
  return green('✓ Clean.');
}

function printReport(report) {
  const colour = VERDICT_COLOR[report.verdict] || gray;
  console.log(`\n  ${bold(report.filename)} ${dim(`· ${report.fileCount} files · ${report.artifactCount} AI artifact(s)`)}`);
  console.log(`  ${colour('●')} ${colour(bold(report.verdict))} ${dim(`risk ${report.riskScore}/100 · ${report.findingCount} finding(s) · ${report.criticalCount} critical · ${report.highCount} high`)}`);

  printPolicyDecision(report);
  printArtifactGroups(report);
  console.log(`\n  ${summaryLine(report.verdict)}${dim(' Full report in the Shomra dashboard → Workspace Scan.\n')}`);
}

export async function cmdScanZip(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey) exitNotConfigured();

  const target = resolveArchive(positional);
  const report = await uploadArchive({ url, apiKey, target, flags });

  if (flags.json) console.log(JSON.stringify(report, null, 2));
  else printReport(report);

  if (report.policyDecision === 'BLOCK' || report.verdict === 'FAIL') process.exitCode = 1;
  else if ((report.policyDecision === 'FLAG' || report.verdict === 'REVIEW') && flags.strict) process.exitCode = 2;
}
