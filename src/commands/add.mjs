import fs from 'node:fs';
import path from 'node:path';
import { didYouMean, levenshtein } from '../cli/suggestions.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { SEV_COLOR, bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { AI_USAGE_CATEGORY_LABEL, KNOWN_AI_PACKAGES } from '../detect/ai-usage.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { collectLocalSast, mergeSastIntoResult } from '../gate/sast.mjs';
import { MODEL_SEV_RANK, modelFixPlan, modelLookup, printAlternatives } from '../models/lookup.mjs';
import { cmdMcp } from './mcp.mjs';

const ADD_KINDS = ['mcp', 'skill', 'model', 'package'];

export async function cmdAdd(flags, positional) {
  const kind = String(positional[0] || '').toLowerCase();
  if (!ADD_KINDS.includes(kind)) {
    const near = didYouMean(kind, ADD_KINDS);
    console.error(red('✗') + ` Usage: ${bold('shomra add ' + ADD_KINDS.join('|') + ' <ref>')}` + (near ? dim(`  (did you mean ${near}?)`) : ''));
    console.error(dim('  mcp     ') + 'shomra add mcp files npx -y @modelcontextprotocol/server-filesystem /tmp');
    console.error(dim('  skill   ') + 'shomra add skill ./downloaded-skill');
    console.error(dim('  model   ') + 'shomra add model openai-community/gpt2');
    console.error(dim('  package ') + 'shomra add package langchain --type pypi');
    process.exit(EXIT_USAGE);
  }

  if (kind === 'mcp') return cmdMcp(flags, ['add', ...positional.slice(1)]);
  if (kind === 'skill') return addSkill(flags, positional.slice(1));
  if (kind === 'model') return addModel(flags, positional.slice(1));
  return addPackage(flags, positional.slice(1));
}

function finishAdd(kind, ref, verdict, lines, flags, extra = {}) {
  if (flags.json) {
    console.log(JSON.stringify({ kind, ref, verdict, accepted: verdict !== 'BLOCK' || !!flags.force, ...extra }, null, 2));
  } else {
    const vc = verdict === 'BLOCK' ? red : verdict === 'FLAG' ? yellow : green;
    console.log(`\n  ${vc(verdict === 'BLOCK' ? '✗ BLOCK' : verdict === 'FLAG' ? '⚠ FLAG' : '✓ ALLOW')} ${bold(ref)} ${dim('· ' + kind)}`);
    for (const l of lines) console.log('    ' + l);
    if (verdict === 'BLOCK' && !flags.force) console.log(`\n  ${red('Not acquired.')} ${dim('Review the findings, or override deliberately with')} ${bold('--force')}${dim('.')}`);
    else if (verdict === 'BLOCK') console.log(`\n  ${yellow('Forced past a BLOCK.')} ${dim('This is recorded as a deliberate override.')}`);
    console.log('');
  }
  if (verdict === 'BLOCK' && !flags.force) process.exitCode = 1;
  else if (verdict === 'FLAG' && flags.strict) process.exitCode = 2;
}

async function addSkill(flags, positional) {
  const ref = positional[0];
  if (!ref) { console.error(red('✗') + ' Usage: ' + bold('shomra add skill <path>')); process.exit(EXIT_USAGE); }
  let target = path.resolve(String(ref));
  if (!fs.existsSync(target)) { console.error(red('✗') + ` Not found: ${ref}`); process.exit(EXIT_USAGE); }
  if (fs.statSync(target).isDirectory()) {
    const md = path.join(target, 'SKILL.md');
    if (!fs.existsSync(md)) { console.error(red('✗') + ` ${ref} has no SKILL.md - point at the skill's directory or its SKILL.md.`); process.exit(EXIT_USAGE); }
    target = md;
  }
  const rel = path.relative(process.cwd(), target).split(path.sep).join('/');
  const content = fs.readFileSync(target, 'utf8');

  const merged = mergeSastIntoResult(
    { ...localGate(content, { kind: 'skill', path: rel }), decision: localGate(content, { kind: 'skill', path: rel }).verdict },
    collectLocalSast({ fullPath: target, relPath: rel, kind: 'skill', content }),
  );
  const findings = merged.findings || [];
  const lines = findings.slice(0, 8).map((f) => `${(SEV_COLOR[f.severity] || dim)(String(f.severity).padEnd(8))} ${f.title}${f.line ? dim(' (line ' + f.line + ')') : ''}`);
  if (!findings.length) lines.push(dim('no findings - manifest and bundled scripts both clean'));
  finishAdd('skill', rel, merged.decision, lines, flags, { findings, riskScore: merged.riskScore });
}

async function addModel(flags, positional) {
  const raw = String(positional[0] || '');
  if (!raw) { console.error(red('✗') + ' Usage: ' + bold('shomra add model <owner/model[@revision]>')); process.exit(EXIT_USAGE); }
  const [id, revision] = raw.split('@');
  const { url } = resolveSettings(loadConfig());

  let lk;
  try { lk = await modelLookup(url, id, revision); } catch (e) {

    return finishAdd('model', raw, 'FLAG', [
      yellow('could not check the Model Index') + dim(` - ${e.message}`),
      dim('This is unverified, not clean. Re-run when the index is reachable, or accept the risk explicitly.'),
    ], flags, { checked: false, error: e.message });
  }
  if (!lk || !lk.found) {
    return finishAdd('model', raw, 'FLAG', [
      yellow('not in the Model Index') + dim(' - nobody has scanned this model'),
      dim('Unscanned is not safe. `shomra admin model-scan ' + id + '` scans it on the platform.'),
    ], flags, { checked: true, found: false });
  }

  const findings = lk.findings || [];
  const worst = findings.reduce((m, f) => Math.max(m, MODEL_SEV_RANK[f.severity] || 0), 0);
  const verdict = lk.verdict === 'FAIL' || worst >= MODEL_SEV_RANK.CRITICAL ? 'BLOCK' : lk.verdict === 'REVIEW' || worst >= MODEL_SEV_RANK.HIGH ? 'FLAG' : 'ALLOW';
  const lines = [
    `${dim('index verdict')} ${lk.verdict === 'FAIL' ? red(lk.verdict) : lk.verdict === 'REVIEW' ? yellow(lk.verdict) : green(lk.verdict)} ${dim('· risk ' + (lk.riskScore ?? '?') + '/100')}${lk.cached ? dim(lk.stale ? ' · cached (stale)' : ' · cached') : ''}`,
    ...findings.slice(0, 6).map((f) => `${(SEV_COLOR[f.severity] || dim)(String(f.severity).padEnd(8))} ${f.title}`),
  ];
  const fix = modelFixPlan(findings, lk.sha);
  if (fix) lines.push(dim('load it safely with: ') + fix.kwargs.map((k) => `${k.name}=${k.value}`).join(', '));
  finishAdd('model', raw, verdict, lines, flags, { checked: true, found: true, indexVerdict: lk.verdict, riskScore: lk.riskScore, findings, fix });
  if (!flags.json) printAlternatives(lk.alternatives, 'model', '    ');
}

const TYPOSQUAT_MAX_DISTANCE = 2;

async function addPackage(flags, positional) {
  const name = String(positional[0] || '').trim();
  if (!name) { console.error(red('✗') + ' Usage: ' + bold('shomra add package <name> [--type npm|pypi]')); process.exit(EXIT_USAGE); }
  const type = flags.type ? String(flags.type).toLowerCase() : null;
  if (type && type !== 'npm' && type !== 'pypi') { console.error(red('✗') + ' --type must be npm or pypi.'); process.exit(EXIT_USAGE); }

  const pool = KNOWN_AI_PACKAGES.filter((p) => !type || p.ecosystem === type);
  const exact = pool.find((p) => p.name.toLowerCase() === name.toLowerCase());

  const near = exact || name.length <= 4
    ? []
    : pool
        .map((p) => ({ p, d: levenshtein(name.toLowerCase(), p.name.toLowerCase()) }))
        .filter((x) => x.d > 0 && x.d <= TYPOSQUAT_MAX_DISTANCE)
        .sort((a, b) => a.d - b.d)
        .slice(0, 3);

  const otherEco = exact ? null : KNOWN_AI_PACKAGES.find((p) => p.name.toLowerCase() === name.toLowerCase());

  let verdict = 'ALLOW';
  const lines = [];
  if (near.length) {
    verdict = 'BLOCK';
    lines.push(red('possible typosquat') + dim(` - ${near.length === 1 ? 'this is' : 'these are'} ${near.map((x) => `${x.d} edit${x.d === 1 ? '' : 's'} from ${bold(x.p.name)} (${x.p.label}, ${x.p.ecosystem})`).join('; ')}`));
    lines.push(dim('If you meant the real package, install that exact name. If this IS a distinct package, --force.'));
  } else if (otherEco && type) {
    verdict = 'FLAG';
    lines.push(yellow(`"${name}" is a known ${otherEco.ecosystem} package (${otherEco.label}), not ${type}`));
    lines.push(dim(`A ${type} package under a ${otherEco.ecosystem} project's name is a common squat. Confirm the publisher before installing.`));
  } else if (exact) {
    lines.push(green('known AI package') + dim(` - ${exact.label} · ${AI_USAGE_CATEGORY_LABEL[exact.category] || exact.category} · ${exact.ecosystem}`));
    lines.push(dim('Name recognised. That is not a supply-chain review: pin the version and check the publisher.'));
  } else {

    verdict = 'FLAG';
    lines.push(yellow('not in the AI package catalog') + dim(' - no typosquat signal, and no verification either'));
    lines.push(dim('Shomra knows AI packages by name only. Check the publisher, the download count, and the repo link yourself.'));
  }
  finishAdd('package', name + (type ? ` (${type})` : ''), verdict, lines, flags, {
    known: !!exact, ecosystem: exact ? exact.ecosystem : otherEco ? otherEco.ecosystem : null,
    nearMatches: near.map((x) => ({ name: x.p.name, distance: x.d, ecosystem: x.p.ecosystem, label: x.p.label })),
  });
}
