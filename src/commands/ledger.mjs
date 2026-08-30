import fs from 'node:fs';
import path from 'node:path';
import { agentHookInstalled } from '../agents/hook-files.mjs';
import { AGENT_KEYS } from '../agents/installers.mjs';
import { mcpConfigCandidates } from '../mcp/config-wrapping.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { RUNG_LABEL, buildReport, isBeliefGap } from '../ledger/ladder.mjs';

const UNMEASURED = { discrimination: 'UNKNOWN', prevention: 'UNPROVEN', preventionBasis: null };

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}


function mcpReach() {
  let total = 0;
  let mediated = 0;
  let files = 0;
  const selfHints = ['mcp-guard', 'shomra'];

  for (const file of mcpConfigCandidates()) {
    const config = readJson(file);
    const servers = config?.mcpServers || config?.servers;
    if (!servers || typeof servers !== 'object') continue;
    files++;
    for (const entry of Object.values(servers)) {
      if (!entry || typeof entry !== 'object') continue;
      total++;
      const argv = [entry.command, ...(entry.args ?? [])].map((x) => String(x ?? '')).join(' ');
      const guarded = selfHints.some((h) => argv.includes(h));
      const routed = typeof entry.url === 'string' && /\/mcp\//.test(entry.url);
      if (guarded || routed) mediated++;
    }
  }
  return { total, mediated, files };
}

function precommitInstalled() {
  for (const dir of ['.git/hooks', path.join(process.cwd(), '.git', 'hooks')]) {
    const file = path.join(dir, 'pre-commit');
    try {
      if (fs.existsSync(file) && /shomra/i.test(fs.readFileSync(file, 'utf8'))) return true;
    } catch {
      /* unreadable is not installed */
    }
  }
  return false;
}

function subjects() {
  const hooked = AGENT_KEYS.filter((a) => agentHookInstalled(a).length);
  const mcp = mcpReach();
  const precommit = precommitInstalled();
  const enrolled = !!resolveSettings(loadConfig()).apiKey;

  const out = [];

  out.push({
    id: 'runtime-gate',
    label: 'the runtime firewall',
    plane: 'tool-call',
    chokepoint: 'every tool call this machine’s agents make',
    mode: hooked.length ? 'ENFORCE' : 'ABSENT',
    axes: { presence: hooked.length ? 'DEPLOYED' : 'NOT_DEPLOYED', reach: null, ...UNMEASURED },
    statement: hooked.length
      ? `The tool-call hook is installed for ${hooked.length} agent(s) on this machine. Nothing here has fired an attack at it, so what it does under one is untested.`
      : 'No tool-call hook is installed on this machine, so nothing screens what its agents run.',
  });

  out.push({
    id: 'mcp-gateway',
    label: 'MCP call mediation',
    plane: 'mcp-call',
    chokepoint: 'the tool-call path between an agent and the servers it uses',
    mode: mcp.mediated ? 'ENFORCE' : 'ABSENT',
    axes: {
      presence: mcp.total ? (mcp.mediated ? 'DEPLOYED' : 'NOT_DEPLOYED') : 'UNKNOWN',
      reach: mcp.total
        ? {
            state: mcp.mediated === 0 ? 'BYPASSING' : mcp.mediated < mcp.total ? 'PARTIAL' : 'ENFORCED_UNQUANTIFIED',
            observed: mcp.total,
            controlled: mcp.mediated,
            bypassRate: mcp.total ? (mcp.total - mcp.mediated) / mcp.total : null,
          }
        : null,
      ...UNMEASURED,
    },
    statement: mcp.total
      ? `${mcp.mediated} of ${mcp.total} MCP server(s) across ${mcp.files} local config(s) run through something that screens their calls.`
      : 'No MCP server is configured in any config this machine can read, so nothing is claimed about call-time mediation here.',
  });

  out.push({
    id: 'install-gate',
    label: 'the install-time gate',
    plane: 'mcp-install',
    chokepoint: 'the commit that brings an AI artifact into this repo',
    mode: precommit ? 'ENFORCE' : 'ABSENT',
    axes: { presence: precommit ? 'DEPLOYED' : 'NOT_DEPLOYED', reach: null, ...UNMEASURED },
    statement: precommit
      ? 'A Shomra pre-commit hook is installed in this repository.'
      : 'No install-time check runs in this repository, so an artifact reaches it without passing one.',
  });

  out.push({
    id: 'llm-guard',
    label: 'the LLM guard',
    plane: 'llm-egress',
    chokepoint: 'the model proxy every prompt and completion passes through',
    mode: 'ABSENT',
    axes: { presence: 'UNKNOWN', reach: null, ...UNMEASURED },
    statement:
      'Nothing on this machine can see where its prompts actually go, so whether a guard is in that path has not been established here. This is a limit of a local read, not a finding.',
  });

  return { rows: out, enrolled };
}

export function cmdLedger(flags = {}) {
  const { rows, enrolled } = subjects();
  const report = buildReport(rows, VERSION);

  if (flags.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return 0;
  }

  console.log(bold(cyan('\n  Control ledger')) + dim(` · ${report.controls.length} controls · local read, no account`));
  console.log(dim('  What has actually been shown about the controls on this machine.\n'));

  for (const c of report.controls) {
    const gap = isBeliefGap(c.rung);
    const paint = gap ? red : c.rung === 'HOLDING' ? green : c.rung === 'ABSENT' ? yellow : gray;
    console.log(`  ${paint('●')} ${bold(c.label.padEnd(24))} ${paint(RUNG_LABEL[c.rung])}`);
    console.log(`    ${dim(c.statement)}`);
    if (c.unmeasured.length) console.log(`    ${dim('unmeasured: ' + c.unmeasured.join(', '))}`);
    console.log('');
  }

  console.log(`  ${dim(report.statement)}`);
  console.log('');
  console.log(dim('  Discrimination and prevention need an attack. Nothing here fired one, so no row'));
  console.log(dim('  can reach "held under test" - and this report says so rather than rounding up.'));
  console.log('');
  console.log(`  ${dim('Publish it:')} shomra ledger --json > ledger.json`);
  console.log(`  ${dim('Check it:  ')} npx controlledger-verify ledger.json`);
  if (!enrolled) console.log(`  ${dim('Prove it:  ')} shomra init --key shm_…  ${dim('- to attack these controls and fill the last two axes')}`);
  console.log('');
  return 0;
}
