import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { ARTIFACT_MATCHERS, walkArtifacts } from '../artifacts/matchers.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { failOnHit, gateArtifactList } from '../gate/batch.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { toSarif } from '../gate/sarif.mjs';
import { findingFingerprint } from '../gate/suppressions.mjs';
import { fixOneFile } from './fix.mjs';

const GIT_TIMEOUT_MS = 3000;

function gitChangedArtifacts(root, { staged }) {
  const run = (args) => {
    try {
      return execSync(`git ${args}`, { cwd: root, stdio: ['ignore', 'pipe', 'ignore'], timeout: GIT_TIMEOUT_MS }).toString();
    } catch {
      return null;
    }
  };

  const output = staged
    ? run('diff --cached --name-only --relative --diff-filter=ACM')
    : run('diff HEAD --name-only --relative --diff-filter=ACM');
  if (output === null) return null;

  return output
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((relativePath) => ARTIFACT_MATCHERS.some((matcher) => matcher.re.test(relativePath)));
}

function narrowToChanged(artifacts, root, flags) {
  if (!flags.staged && !flags.changed) return artifacts;

  const changed = gitChangedArtifacts(root, { staged: !!flags.staged });
  if (changed === null) {
    if (!flags.json) console.error(`  ${yellow('⚠')} ${dim('not a git repo (or git unavailable) - checking the whole tree')}`);
    return artifacts;
  }
  const changedSet = new Set(changed);
  return artifacts.filter((artifact) => changedSet.has(artifact.rel));
}

function printNothingToCheck(flags, root) {
  if (flags.json) {
    console.log(JSON.stringify({ scanned: 0, blocked: 0, flagged: 0, results: [] }, null, 2));
    return;
  }
  const where = flags.staged || flags.changed ? ' in the changed set.' : ` under ${root}.`;
  console.log(`${green('\n  ✓ No AI artifacts to check')}${dim(where)}\n`);
}

function printHeader({ flags, artifacts, env, apiKey }) {
  if (flags.json || flags.sarif) return;

  const scope = flags.staged ? 'staged' : flags.changed ? 'changed' : env.environment;
  const provider = env.ciProvider ? ` · ${env.ciProvider}` : '';
  console.log(bold(cyan('\n  Shomra check')) + dim(` - ${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} · ${scope}${provider}`));
  if (!apiKey) console.error(`  ${dim('On-machine analysis only - run')} ${bold('shomra init')} ${dim('to also apply org policy.')}`);
}

async function applyFixes({ results, flags, apiKey, url, blocked, flagged }) {
  if (!flags.fix || !(blocked || flagged)) return 0;

  if (!apiKey) {
    if (!flags.json) {
      console.error(`  ${yellow('⚠')} ${dim('--fix needs enrollment (the fix runs on the platform). Run')} ${bold('shomra init')}${dim('.')}`);
    }
    return 0;
  }

  if (!flags.json) console.log(dim('\n  Fixing flagged artifacts…'));
  let fixed = 0;
  for (const result of results) {
    if (result.decision === 'ALLOW') continue;
    const done = await fixOneFile(result.full, { apiKey, url, flags: { ...flags, apply: true, quiet: flags.json } });
    if (done) fixed += 1;
  }
  return fixed;
}

function verdictLine({ blocked, flagged, suppressed, total }) {
  if (blocked) return red(`✗ ${blocked} blocked`) + dim(` · ${flagged} flagged · ${total - blocked - flagged} clean`);
  if (flagged) return yellow(`⚠ ${flagged} flagged`) + dim(` · ${total - flagged} clean`);
  if (suppressed) return green(`✓ ${total} passing`) + dim(' - nothing NEW; previously accepted findings are still there');
  return green(`✓ All ${total} clean.`);
}

function printSummary({ results, blocked, flagged, suppressed, backendDown, rejected, fixed, flags, strictOutage }) {
  const suppressedNote = suppressed ? dim(` · ${suppressed} accepted by baseline/ignore`) : '';
  const outageNote = backendDown ? yellow('  (on-machine only - org policy not applied)') : '';
  const rejectedNote = rejected.length
    ? yellow(`  (${rejected.length} artifact(s) the backend refused - org policy not applied to those)`)
    : '';

  console.log(`\n  ${verdictLine({ blocked, flagged, suppressed, total: results.length })}${suppressedNote}${outageNote}${rejectedNote}`);

  for (const entry of rejected) console.log(`  ${yellow('!')} ${dim(`${entry.path} (${entry.kind}) - ${entry.reason}`)}`);

  if (flags.fix && fixed) {
    console.log(`  ${green('✓')} ${dim(`applied ${fixed} fix${fixed > 1 ? 'es' : ''} - re-run`)} ${bold('shomra check')} ${dim('to confirm.')}`);
  } else if (!flags.fix && (blocked || flagged)) {
    console.log(dim('  Run ') + bold('shomra fix <file>') + dim(' or ') + bold('shomra check --fix') + dim(' to remediate.'));
  }
  if (strictOutage) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}`);
  console.log('');
}

export async function cmdCheck(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  const root = path.resolve(positional[0] || flags.path || '.');
  const env = detectEnv();

  const artifacts = narrowToChanged(walkArtifacts(root), root, flags);
  if (!artifacts.length) {
    printNothingToCheck(flags, root);
    return;
  }

  printHeader({ flags, artifacts, env, apiKey });
  const { results, blocked, flagged, suppressed, backendDown, rejected } =
    await gateArtifactList(artifacts, { apiKey, url, env, flags, root });

  if (flags.sarif) {
    console.log(JSON.stringify(toSarif(results), null, 2));
    if (blocked) process.exitCode = 1;
    else if (flagged && flags.strict) process.exitCode = 2;
    return;
  }

  const fixed = await applyFixes({ results, flags, apiKey, url, blocked, flagged });
  const strictOutage = backendDown && flags.strict;

  if (flags.json) {
    console.log(JSON.stringify({
      scanned: results.length, blocked, flagged, suppressed, fixed, backendDown, rejected,
      environment: env.environment, results,
    }, null, 2));
  } else {
    printSummary({ results, blocked, flagged, suppressed, backendDown, rejected, fixed, flags, strictOutage });
  }

  if (blocked > 0 || strictOutage) process.exitCode = 1;
  else if (failOnHit(flags, blocked, flagged)) process.exitCode = 1;
  else if (flagged > 0 && flags.strict) process.exitCode = 2;
}

export async function cmdBaseline(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  const root = path.resolve(positional[0] || flags.path || '.');
  const env = detectEnv();

  const artifacts = walkArtifacts(root);
  if (!artifacts.length) {
    console.log(dim(`\n  No AI artifacts under ${root} - nothing to baseline.\n`));
    return;
  }
  if (!flags.json) {
    process.stdout.write(dim(`  Scanning ${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} to baseline… `));
  }

  const { results } = await gateArtifactList(artifacts, {
    apiKey, url, env, root, flags: { ...flags, json: true, 'no-suppress': true },
  });

  const fingerprints = new Set();
  for (const result of results) {
    for (const finding of result.findings || []) fingerprints.add(findingFingerprint(result.path, finding));
  }

  const directory = path.join(root, '.shomra');
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, 'baseline.json');
  fs.writeFileSync(file, JSON.stringify({
    createdAt: new Date().toISOString(),
    agentVersion: VERSION,
    count: fingerprints.size,
    fingerprints: [...fingerprints],
  }, null, 2));

  const relative = path.relative(process.cwd(), file).split(path.sep).join('/');
  if (flags.json) {
    console.log(JSON.stringify({ baseline: relative, count: fingerprints.size, artifacts: results.length }, null, 2));
    return;
  }
  console.log(green('done'));
  console.log(`\n  ${green('✓ Baseline written')} ${dim(`- ${fingerprints.size} finding(s) across ${results.length} artifact(s) accepted.`)}`);
  console.log(`${dim(`  ${relative} - commit it so your team shares the baseline. Only NEW findings will fail now.`)}\n`);
}
