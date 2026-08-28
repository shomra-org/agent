import fs from 'node:fs';
import path from 'node:path';
import { api, gateMachine } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { DEC_RANK } from '../gate/sast.mjs';
import { rulesContext } from '../rules/context.mjs';
import { generateRules, mergeRulesBlock, resolveRulesTargets, rulesBlock } from '../rules/generate.mjs';
import { RULES_BEGIN, RULES_TARGETS } from '../rules/sections.mjs';

const ORG_POLICY_TIMEOUT_MS = 5000;
const MAX_ORG_DIRECTIVES = 20;

const plural = (count, word) => `${word}${count === 1 ? '' : 's'}`;

async function fetchOrgDirectives(root, flags) {
  const { apiKey, url } = resolveSettings(loadConfig());
  if (!apiKey || !url || flags['no-policy']) return { apiKey, orgLines: [], orgError: null };

  try {
    const response = await api(
      url,
      apiKey,
      '/gate/rules',
      { cwd: root, env: detectEnv(), machine: gateMachine() },
      { timeoutMs: ORG_POLICY_TIMEOUT_MS },
    );
    const directives = Array.isArray(response?.directives) ? response.directives : [];
    const orgLines = directives.filter((line) => typeof line === 'string' && line.trim()).slice(0, MAX_ORG_DIRECTIVES);
    return { apiKey, orgLines, orgError: null };
  } catch (error) {
    return { apiKey, orgLines: [], orgError: error.message };
  }
}

function gateRank(content, targetFile) {
  try {
    return DEC_RANK[localGate(content, { kind: 'rules', path: targetFile }).verdict] ?? 0;
  } catch {
    return 0;
  }
}

function planTarget(root, key, block) {
  const target = RULES_TARGETS[key];
  const absolutePath = path.join(root, target.file);

  let existing = '';
  try {
    existing = fs.readFileSync(absolutePath, 'utf8');
  } catch {
    existing = '';
  }

  const next = mergeRulesBlock(existing, block, target);
  const hadBlock = existing.includes(RULES_BEGIN);
  const worsens = next !== null && gateRank(next, target.file) > (existing ? gateRank(existing, target.file) : 0);

  return {
    key,
    label: target.label,
    file: target.file,
    abs: absolutePath,
    next,
    worsens,
    state: next === null ? 'current' : hadBlock ? 'stale' : 'absent',
  };
}

function buildJsonReport({ root, sections, orgLines, orgError, gate, context, written, plan, flags, body }) {
  return {
    root,
    sections,
    orgDirectives: orgLines.length,
    orgError,
    gate: gate ? { verdict: gate.verdict, riskScore: gate.riskScore } : null,
    observed: context.observed,
    artifacts: context.artifactCount,
    modelRefs: context.modelRefs,
    aiUsage: context.aiUsage,
    written,
    targets: plan.map(({ key, label, file, state, worsens }) => ({
      key, label, file, state, ...(worsens ? { skipped: 'would-worsen' } : {}),
    })),
    ...(flags.write ? {} : { block: body }),
  };
}

function printDriftReport(plan, drifted) {
  if (!drifted.length) {
    console.log(`\n  ${green(`✓ Shomra rules current in ${plan.length} ${plural(plan.length, 'file')}.`)}\n`);
    return;
  }
  console.log(`\n  ${red(`✗ Shomra rules out of date in ${drifted.length} ${plural(drifted.length, 'file')}:`)}`);
  for (const target of drifted) {
    const state = target.state === 'absent' ? red('absent') : yellow('stale ');
    console.log(`    ${state} ${bold(target.file)} ${dim(`· ${target.label}`)}`);
  }
  console.log(dim('\n  Run ') + bold('shomra rules --write') + dim(' and commit the result.\n'));
}

function writeTarget(target, flags) {
  if (target.state === 'current') {
    if (!flags.json) console.log(`  ${yellow('•')} ${target.label} ${dim(`already current (${target.file})`)}`);
    return { wrote: false, failed: false };
  }
  if (target.worsens) {
    if (!flags.json) {
      console.log(`  ${red('✗')} ${target.file} ${dim("- skipped: writing the block would raise this file's own gate verdict. Please report it.")}`);
    }
    return { wrote: false, failed: true };
  }
  try {
    fs.mkdirSync(path.dirname(target.abs), { recursive: true });
    fs.writeFileSync(target.abs, target.next);
    if (!flags.json) {
      console.log(`  ${green('✓')} ${target.state === 'stale' ? 'Updated' : 'Wrote'} ${bold(target.file)} ${dim(`· ${target.label}`)}`);
    }
    return { wrote: true, failed: false };
  } catch (error) {
    if (!flags.json) console.log(`  ${red('✗')} ${target.file} ${dim(`- ${error.message}`)}`);
    return { wrote: false, failed: true };
  }
}

function printWriteSummary(wrote, sections, orgLines) {
  const headline = wrote
    ? green(`✓ ${wrote} rules ${plural(wrote, 'file')} updated`)
    : green('✓ Already current');
  const orgNote = orgLines.length ? ` · ${orgLines.length} org ${plural(orgLines.length, 'directive')}` : '';
  console.log(`\n  ${headline}${dim(` · ${sections.length} ${plural(sections.length, 'section')}${orgNote}`)}`);
  console.log(dim('  Commit these - the agent reads them before it writes, so the blocked pattern is never generated.'));
  console.log(dim('  Keep them honest in CI with ') + bold('shomra rules --check') + dim('.\n'));
}

function printPreview({ root, context, sections, apiKey, orgError, body, gate, plan }) {
  const artifacts = `${context.artifactCount} ${plural(context.artifactCount, 'artifact')}`;
  console.log(bold(cyan('\n  Shomra rules')) + dim(` - ${sections.length} ${plural(sections.length, 'section')} for ${artifacts} under ${root}`));

  if (orgError) console.log(`  ${yellow('⚠')} ${dim(`org policy not applied - ${orgError}`)}`);
  else if (!apiKey) console.log(`  ${dim('On-machine rules only - run')} ${bold('shomra init')} ${dim('to layer your org policy on top.')}`);

  console.log('');
  console.log(body.split('\n').map((line) => `  ${dim(line)}`).join('\n'));

  const gateLabel = gate && gate.verdict === 'ALLOW'
    ? green('✓ gate: clean')
    : yellow(`gate: ${gate ? gate.verdict : 'unknown'}`);
  console.log(`  ${gateLabel}${dim(" - the block passes Shomra's own rules-file check.")}`);
  console.log('');

  for (const target of plan) {
    const mark = target.state === 'current' ? green('✓') : target.state === 'stale' ? yellow('~') : dim('+');
    console.log(`  ${mark} ${bold(target.file)} ${dim(`· ${target.label} · ${target.state}`)}`);
  }
  console.log(dim('\n  Write them with ') + bold('shomra rules --write') + dim(' (nothing outside the markers is touched).\n'));
}

export async function cmdRules(flags, positional) {
  const root = path.resolve(positional[0] || flags.path || '.');
  const context = rulesContext(root);
  const { apiKey, orgLines, orgError } = await fetchOrgDirectives(root, flags);

  const { body, sections, gate, observedOmitted } = generateRules(context, { orgLines });
  const block = rulesBlock(body);
  const plan = resolveRulesTargets(root, flags).map((key) => planTarget(root, key, block));
  const drifted = plan.filter((target) => target.state !== 'current');

  const written = [];
  const emitJson = () => {
    if (!flags.json) return;
    console.log(JSON.stringify(
      buildJsonReport({ root, sections, orgLines, orgError, gate, context, written, plan, flags, body }),
      null,
      2,
    ));
  };

  if (gate && gate.verdict === 'BLOCK') {
    emitJson();
    if (!flags.json) {
      console.error(`\n${red('✗')} The generated block does not pass Shomra's own rules-file gate - refusing to write. This is a bug in the CLI; please report it.`);
    }
    process.exitCode = 1;
    return;
  }

  if (observedOmitted && !flags.json) {
    const issues = `${observedOmitted} ${plural(observedOmitted, 'issue')}`;
    console.log(`  ${yellow('!')} ${dim(`Left out the "already present in this repo" section (${issues}) - quoting those titles tripped the rules gate. Run `)}${bold('shomra check')}${dim(' to see them.')}`);
  }

  if (flags.check) {
    emitJson();
    if (!flags.json) printDriftReport(plan, drifted);
    if (drifted.length) process.exitCode = 1;
    return;
  }

  if (flags.write) {
    let wrote = 0;
    for (const target of plan) {
      const result = writeTarget(target, flags);
      if (result.wrote) {
        wrote += 1;
        written.push(target.file);
      }
      if (result.failed) process.exitCode = 1;
    }
    emitJson();
    if (!flags.json) printWriteSummary(wrote, sections, orgLines);
    return;
  }

  emitJson();
  if (flags.json) return;
  printPreview({ root, context, sections, apiKey, orgError, body, gate, plan });
}
