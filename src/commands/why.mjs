import fs from 'node:fs';
import path from 'node:path';
import { api } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { SEV_COLOR, bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { GATE_KINDS } from '../gate/environment.mjs';

export async function cmdWhy(flags, positional) {
  const file = positional[0];
  if (!file) {
    console.error(red('✗') + ' Usage: ' + bold('shomra why <file> [--kind mcp|skill|command|subagent|hook|rules] [--json]'));
    process.exit(EXIT_USAGE);
  }
  let target = path.resolve(String(file));
  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    const skillMd = path.join(target, 'SKILL.md');
    if (!fs.existsSync(skillMd)) {
      console.error(red('✗') + ` ${file} is a directory with no SKILL.md - point at a file instead.`);
      process.exit(EXIT_USAGE);
    }
    target = skillMd;
  }
  if (!fs.existsSync(target)) {
    console.error(red('✗') + ` File not found: ${file}`);
    process.exit(EXIT_USAGE);
  }
  const content = fs.readFileSync(target, 'utf8');
  const rel = path.relative(process.cwd(), target).split(path.sep).join('/');
  const kind = flags.kind && GATE_KINDS.includes(String(flags.kind)) ? String(flags.kind) : undefined;

  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);

  if (apiKey) {
    try {
      if (!flags.json) process.stdout.write(dim(`  Explaining ${rel}… `));
      const res = await api(url, apiKey, '/gate/explain', { ...(kind ? { kind } : {}), path: rel, name: rel.split('/').pop(), content });
      if (!flags.json) console.log('');
      if (flags.json) console.log(JSON.stringify({ path: rel, ...res }, null, 2));
      else printWhy(res);
      return;
    } catch (e) {
      if (!flags.json) console.log(yellow('backend unavailable') + dim(` - on-machine explanation (${e.message})`));

    }
  }
  whyLocal(content, kind, rel, flags);
}

function whyLocal(content, kind, rel, flags) {
  const local = localGate(content, { kind, path: rel });
  if (flags.json) {
    console.log(JSON.stringify({ path: rel, source: 'local', ...local }, null, 2));
    return;
  }
  console.log(bold(cyan('\n  Shomra why')) + dim(` - ${rel} · on-machine`));
  if (!local.findings.length) {
    console.log(green('\n  ✓ No findings - nothing to explain.\n'));
    return;
  }
  for (const f of local.findings) {
    const at = f.line ? dim(` (line ${f.line})`) : '';
    console.log(`\n  ${SEV_COLOR[f.severity]('●')} ${SEV_COLOR[f.severity](f.severity)}  ${bold(f.title)}${at}`);
    if (f.remediationText) console.log(`     ${dim('fix: ' + f.remediationText)}`);
  }
  console.log(dim('\n  Enroll (') + bold('shomra init') + dim(') for an AI-distilled why + false-positive read.\n'));
}

function printWhy(res) {
  console.log(bold(cyan('\n  Shomra why')) + dim(` - ${res.path}${res.aiEnabled ? '' : ' · rule rationale (AI off)'}`));
  if (res.summary) console.log('  ' + res.summary);
  if (!res.findings || !res.findings.length) {
    console.log(green('\n  ✓ Nothing to explain.\n'));
    return;
  }
  for (const f of res.findings) {
    const at = f.line ? dim(` (line ${f.line})`) : '';
    const fp = f.likelyFalsePositive ? yellow('  · likely false positive') : '';
    console.log(`\n  ${SEV_COLOR[f.severity]('●')} ${SEV_COLOR[f.severity](f.severity)}  ${bold(f.title)}${at}${fp}`);
    if (f.why) console.log(`     ${f.why}`);
    if (f.exploit) console.log(`     ${dim('exploit: ' + f.exploit)}`);
    if (f.assessment) console.log(`     ${dim(f.assessment)}`);
    if (f.remediationText) console.log(`     ${dim('fix: ' + f.remediationText)}`);
  }
  console.log('');
}
