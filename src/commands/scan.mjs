import path from 'node:path';
import { printArtifacts, printAssets } from '../artifacts/report.mjs';
import { api, machineInfo } from '../core/api-client.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { exitNotConfigured } from '../core/exit-codes.mjs';
import { clampInt } from '../core/numbers.mjs';
import { SEV_COLOR, VERDICT_COLOR, bold, cyan, dim, gray, green, red, yellow } from '../core/terminal.mjs';
import { VERSION } from '../core/version.mjs';
import { discoverAgentArtifacts } from '../inventory/agent-artifacts.mjs';
import { discoverAll } from '../inventory/discovery.mjs';

function discover(flags) {

  const roots = flags.path ? [path.resolve(String(flags.path))] : [process.cwd()];
  return discoverAll(roots, { autoExpand: !flags.path });
}

function discoverArtifacts(flags) {
  const cwd = flags.path ? path.resolve(String(flags.path)) : process.cwd();
  return discoverAgentArtifacts(cwd);
}

export async function cmdScan(flags) {
  const cfg = loadConfig();
  const assets = discover(flags);
  const { artifacts, capped, available } = discoverArtifacts(flags);
  if (flags.json && !flags.report) {
    console.log(JSON.stringify({ machine: machineInfo(cfg), assets, artifacts, capped, available }, null, 2));
    return;
  }
  console.log(bold(cyan('\n  Shomra')) + dim(` agent v${VERSION} - local scan`));
  printAssets(assets);
  printArtifacts(artifacts, capped, available);

  if (flags.report) {
    await sendReport(cfg, assets, flags, { artifacts, capped, available });
  } else {
    console.log(
      dim('\n  Run ') + bold('shomra report') + dim(' to analyze these on the platform and see findings.\n'),
    );
  }
}

async function sendReport(cfg, assets, flags, extra = {}) {
  const { apiKey, url } = resolveSettings(cfg);
  if (!apiKey) {
    exitNotConfigured();
  }
  const artifacts = extra.artifacts ?? [];
  const capped = extra.capped ?? [];
  const available = extra.available ?? [];
  process.stdout.write(dim('\n  Reporting to platform… '));
  try {
    const res = await api(url, apiKey, '/agent/report', {
      machine: machineInfo(cfg),
      assets,
      artifacts,

      capped,

      available,
    }, {

      timeoutMs: clampInt(process.env.SHOMRA_API_TIMEOUT_MS, 180000, 1000, 600000),
    });
    console.log(
      green('done') +
        dim(` (${res.assets} assets analyzed`) +
        (res.artifacts ? dim(`, ${res.artifacts.registered} artifacts registered`) : '') +
        dim(')'),
    );
    if (flags.json) {
      console.log(JSON.stringify(res, null, 2));
      return;
    }
    console.log('');
    if (Array.isArray(res.results)) {
      for (const r of res.results.filter((x) => x.findingCount > 0)) {
        const vc = VERDICT_COLOR[r.verdict] || gray;
        console.log(`  ${vc('●')} ${bold(r.name)} ${dim('risk ' + r.riskScore)} ${vc(r.verdict)}`);
        for (const f of r.findings || []) {
          console.log(`      ${SEV_COLOR[f.severity](f.severity.padEnd(8))} ${f.title}`);
        }
      }
    }
    const crit = res.critical ?? 0;
    const high = res.high ?? 0;
    console.log(
      '\n  ' +
        (crit + high > 0
          ? `${red(crit + ' critical')} · ${yellow(high + ' high')} ${dim('- view & remediate at the Shomra dashboard')}`
          : green('No high-severity findings. ') + dim('Nice and clean.')),
    );
    console.log(dim(`  Endpoint: ${res.endpointId}\n`));
    if (crit > 0) process.exitCode = 1;
  } catch (e) {
    console.log(red('failed'));
    console.error(`  ${red('✗')} ${e.message}\n`);

    process.exitCode = 1;
  }
}
