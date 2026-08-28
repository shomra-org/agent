import os from 'node:os';
import { agentHookInstalled } from '../agents/hook-files.mjs';
import { AGENT_KEYS, AGENT_LABELS } from '../agents/installers.mjs';
import { keyScope } from '../core/api-key.mjs';
import { breakerCooldownMs, breakerOpen, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { CONFIG_FILE, loadConfig, resolveSettings } from '../core/config.mjs';
import { bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { envFlag } from '../guard/options.mjs';

export function cmdStatus() {
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const enrolled = !!apiKey;
  console.log(bold(cyan('\n  Shomra agent')) + dim(` v${VERSION}`));

  if (enrolled) {
    console.log(`  ${dim('Mode     ')} ${green('● Enrolled')} ${dim(`(${keyScope(apiKey)} key)`)} - org policy, platform AI & dashboard telemetry active`);
  } else {
    console.log(`  ${dim('Mode     ')} ${cyan('● Local')} ${dim('- on-machine analysis only; nothing leaves this machine')}`);
    console.log(`  ${dim('         ')} ${dim('Run')} ${bold('shomra init --key shm_…')} ${dim('to add org policy, AI fixes, deep scans & the dashboard.')}`);
  }
  console.log(`  ${dim('Backend  ')} ${url || dim('none (local mode - set with shomra init --url)')}`);
  console.log(`  ${dim('API key  ')} ${apiKey ? green(apiKey.slice(0, 14) + '…') : dim('none (local mode)')}`);
  console.log(`  ${dim('Machine  ')} ${os.hostname()} ${dim('(' + (cfg.machineId || 'unenrolled') + ')')}`);
  console.log(`  ${dim('Config   ')} ${CONFIG_FILE}`);

  console.log(bold('\n  Available now') + dim(enrolled ? '' : ' (local, no key)'));
  console.log(`  ${green('✓')} ${dim('check · gate · doctor · protect · secrets · models · new · mcp add · why (offline)')}`);
  console.log(`  ${enrolled ? green('✓') : gray('○')} ${(enrolled ? dim : gray)('fix (AI) · deep scans (scan-zip/model-scan/memory-scan) · org policy · dashboard telemetry')}`);

  const localOff = process.env.SHOMRA_GUARD_LOCAL === '0' || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  console.log(bold('\n  Runtime firewall'));
  const installedAgents = AGENT_KEYS.map((a) => ({ agent: a, files: agentHookInstalled(a) })).filter((x) => x.files.length);
  if (installedAgents.length) {
    let first = true;
    for (const { agent, files } of installedAgents) {
      console.log(`  ${dim(first ? 'Hooks    ' : '         ')} ${green('installed')} ${bold(AGENT_LABELS[agent])} ${dim('→ ' + files.join(', '))}`);
      first = false;
    }
    const missing = AGENT_KEYS.filter((a) => !installedAgents.some((i) => i.agent === a));
    if (missing.length) console.log(`  ${dim('         ')} ${dim('not installed: ' + missing.map((m) => AGENT_LABELS[m]).join(', '))}`);
  } else {
    console.log(`  ${dim('Hooks    ')} ${yellow('not installed for any agent')}${dim('  (run: shomra install-hook --agent all  or  shomra protect)')}`);
  }
  console.log(`  ${dim('Tier 0   ')} ${localOff ? yellow('off') + dim(' (server-only)') : green('on') + dim(' - dangerous calls blocked on-machine, zero network')}`);
  console.log(`  ${dim('Mode     ')} ${strict ? 'fail-closed (strict)' : 'fail-open'}${dim(` · server timeout ${guardTimeoutMs()}ms · breaker ${breakerCooldownMs()}ms`)}`);
  console.log(`  ${dim('Breaker  ')} ${breakerOpen() ? red('OPEN') + dim(' - backend recently unreachable; server tier is being skipped') : green('closed')}\n`);
}
