import fs from 'node:fs';
import path from 'node:path';
import { walkArtifacts } from '../artifacts/matchers.mjs';
import { api, gateMachine } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { failOnHit, gateArtifactList } from '../gate/batch.mjs';
import { GATE_KINDS, collectSiblings, detectEnv } from '../gate/environment.mjs';
import { localAsGateResult, printGateResult } from '../gate/result.mjs';
import { toSarif } from '../gate/sarif.mjs';
import { collectLocalSast, mergeSastIntoResult } from '../gate/sast.mjs';
import { withMcpAdvisories } from '../gate/advisories.mjs';
import { readZipEntry } from '../core/zip-lite.mjs';

const GATE_USAGE = 'shomra gate <file> [--kind mcp|skill|command|subagent|hook|rules|agent-card|memory|plugin|tool-manifest|extension|workflow|guardrail|framework] [--name x] [--strict] [--json]';

function resolveGateFile(file) {
  let target = path.resolve(String(file));

  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    const skillFile = path.join(target, 'SKILL.md');
    if (!fs.existsSync(skillFile)) {
      console.error(`${red('✗')} ${file} is a directory with no SKILL.md - point at a file instead.`);
      process.exit(EXIT_USAGE);
    }
    target = skillFile;
  }
  if (!fs.existsSync(target)) {
    console.error(`${red('✗')} File not found: ${file}`);
    process.exit(EXIT_USAGE);
  }
  return target;
}

function readGateTarget(flags, positional) {
  if (flags.stdin) {
    return { content: fs.readFileSync(0, 'utf8'), relPath: flags.path || null, fullTarget: null };
  }

  const file = positional[0];
  if (!file) {
    console.error(`${red('✗')} Usage: ${bold(GATE_USAGE)}`);
    process.exit(EXIT_USAGE);
  }
  const target = resolveGateFile(file);
  
  if (/\.(?:dxt|mcpb)$/i.test(target)) {
    const manifest = readZipEntry(fs.readFileSync(target), 'manifest.json');
    if (manifest == null) {
      console.error(`${red('✗')} ${file} is not a readable extension bundle (no manifest.json at its root).`);
      process.exit(EXIT_USAGE);
    }
    return {
      content: manifest,
      relPath: `${path.relative(process.cwd(), target).split(path.sep).join('/')}!/manifest.json`,
      fullTarget: null,
      bundle: true,
    };
  }
  return {
    content: fs.readFileSync(target, 'utf8'),
    relPath: path.relative(process.cwd(), target).split(path.sep).join('/'),
    fullTarget: target,
  };
}

async function requestGateVerdict({ url, apiKey, flags, kind, relPath, content, fullTarget }) {
  if (!flags.json) process.stdout.write(dim('  Checking with Shomra gate… '));
  try {
    const siblings = collectSiblings(fullTarget, relPath);
    const verdict = await api(url, apiKey, '/gate/check', {
      ...(kind ? { kind } : {}),
      ...(flags.name ? { name: String(flags.name) } : {}),
      ...(relPath ? { path: relPath } : {}),
      content,
      ...(siblings.length ? { siblings } : {}),
      machine: gateMachine(),
      env: detectEnv(),
      ...(flags.project ? { projectId: String(flags.project) } : {}),
    });
    if (!flags.json) console.log('');
    return { verdict };
  } catch (error) {
    if (!flags.json) {
      console.log(yellow('backend unavailable'));
      console.error(`  ${yellow('⚠')} ${error.message} ${dim('- falling back to on-machine analysis')}`);
    }
    return { verdict: null };
  }
}

export async function cmdGate(flags, positional) {
  const { apiKey, url } = resolveSettings(loadConfig());
  if (flags.all) return cmdGateAll(flags, positional, { apiKey, url });

  const { content, relPath, fullTarget, bundle } = readGateTarget(flags, positional);
  const kind = flags.kind && GATE_KINDS.includes(String(flags.kind)) ? String(flags.kind) : bundle ? 'mcp' : undefined;
  const name = flags.name ? String(flags.name) : (relPath ? relPath.split('/').pop() : 'artifact');
  const local = localGate(content, { kind, path: relPath });

  let serverVerdict = null;
  if (apiKey) {
    ({ verdict: serverVerdict } = await requestGateVerdict({ url, apiKey, flags, kind, relPath, content, fullTarget }));
    if (!serverVerdict && flags.strict) {
      printGateResult(localAsGateResult(local, name, kind), 'local', flags);
      if (!flags.json) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}\n`);
      process.exitCode = 1;
      return;
    }
  } else if (!flags.json) {
    console.error(`  ${dim('Not enrolled - on-machine analysis only. Run')} ${bold('shomra init')} ${dim('to also apply org policy.')}`);
  }

  let shownLocal = local;
  if (!serverVerdict) {
    const { local: withAdv, advisories } = await withMcpAdvisories(local, { content, path: relPath, kind, flags });
    shownLocal = withAdv;
    if (advisories === 'unavailable' && !flags.json) console.error(`  ${yellow('⚠')} ${dim('Advisory lookup (OSV) unreachable - pinned MCP packages were not checked for published CVEs.')}`);
  }
  const base = serverVerdict || localAsGateResult(shownLocal, name, kind);
  const result = mergeSastIntoResult(base, collectLocalSast({ fullPath: fullTarget, relPath, kind, content }));
  printGateResult(result, serverVerdict ? 'server' : 'local', flags);

  if (result.decision === 'BLOCK') process.exitCode = 1;
  else if (result.decision === 'FLAG' && flags.strict) process.exitCode = 2;
}

async function cmdGateAll(flags, positional, { apiKey, url }) {

  const dirArg = typeof flags.all === 'string' ? flags.all : positional[0] || '.';
  const root = path.resolve(dirArg);
  const env = detectEnv();
  const artifacts = walkArtifacts(root);

  if (!artifacts.length) {
    if (flags.json) console.log(JSON.stringify({ scanned: 0, results: [] }, null, 2));
    else console.log(dim(`\n  No AI artifacts found under ${root}. Nothing to gate.\n`));
    return;
  }

  if (!flags.json && !flags.sarif) console.log(bold(cyan('\n  Shomra gate')) + dim(` - batch (${artifacts.length} artifact${artifacts.length > 1 ? 's' : ''} · ${env.environment}${env.ciProvider ? ' · ' + env.ciProvider : ''})`));

  const { results, blocked, flagged, suppressed, backendDown, rejected } = await gateArtifactList(artifacts, { apiKey, url, env, flags, root });

  const strictOutage = backendDown && flags.strict;

  if (flags.sarif) {
    console.log(JSON.stringify(toSarif(results), null, 2));
    if (blocked > 0 || strictOutage) process.exitCode = 1;
    else if (failOnHit(flags, blocked, flagged)) process.exitCode = 1;
    else if (flagged > 0 && flags.strict) process.exitCode = 2;
    return;
  }
  if (flags.json) {
    console.log(JSON.stringify({ scanned: results.length, blocked, flagged, suppressed, backendDown, rejected, environment: env.environment, results }, null, 2));
  } else {
    console.log(
      '\n  ' +
        (blocked > 0
          ? red(`✗ ${blocked} blocked`) + dim(` · ${flagged} flagged · ${results.length - blocked - flagged} allowed`)
          : flagged > 0
            ? yellow(`⚠ ${flagged} flagged`) + dim(` · ${results.length - flagged} allowed`)
            : green(`✓ All ${results.length} artifacts allowed.`)) +
        (suppressed ? dim(` · ${suppressed} suppressed`) : '') +
        (backendDown ? yellow('  (on-machine analysis - org policy not applied)') : dim(' - full activity in the Shomra dashboard → Gate Activity')) +
        '\n',
    );
    if (strictOutage) console.log(`  ${red('✗ Failing closed (--strict): backend unreachable, org policy unverified.')}\n`);
  }

  if (blocked > 0 || strictOutage) process.exitCode = 1;
  else if (failOnHit(flags, blocked, flagged)) process.exitCode = 1;
  else if (flagged > 0 && flags.strict) process.exitCode = 2;
}
