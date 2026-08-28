import fs from 'node:fs';
import path from 'node:path';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { SEV_COLOR, bold, cyan, dim, green, red, yellow } from '../core/terminal.mjs';
import { localGate } from '../detect/guard-signals.mjs';
import { mcpIndexAlert, mcpLookup, mcpLookupId, parseEnvKV, worstMcpVerdict } from '../mcp/lookup.mjs';
import { printAlternatives } from '../models/lookup.mjs';

const MAX_FINDINGS_SHOWN = 6;
const RUNNER_NAMES = /^(npx|bunx|pnpx|uvx|uv|node|deno|bun|python3?|py|docker|podman|sh|bash|zsh|ruby|go|cargo|dotnet)$/i;

function usageExit(message, hint) {
  console.error(`${red('✗')} ${message}`);
  if (hint) console.error(dim('  Try: ') + bold(hint));
  process.exit(EXIT_USAGE);
}

function buildServerEntry(flags, positional) {
  const server = {};
  if (flags.url) server.url = String(flags.url);

  const tokens = flags.command ? String(flags.command).split(/\s+/) : positional.slice(2);
  if (tokens.length) {
    [server.command] = tokens;
    if (tokens.length > 1) server.args = tokens.slice(1);
  }
  if (flags.env) server.env = parseEnvKV(flags.env);
  return { server, tokens };
}

function assertUsableArguments(name, server, tokens) {
  if (!server.command) return;
  if (String(server.command).startsWith('-')) {
    usageExit(
      `"${server.command}" is a flag, not a command - the server NAME comes first.`,
      `shomra mcp add <name> ${[server.command, ...(server.args || [])].join(' ')}`,
    );
  }
  if (RUNNER_NAMES.test(String(name))) {
    usageExit(
      `"${name}" is a runner, not a server name - it looks like the NAME argument was left out.`,
      `shomra mcp add <name> ${[name, ...tokens].join(' ')}`,
    );
  }
}

async function lookupSecurityIndex(flags, server, name) {
  if (flags['no-index']) return null;
  const { url } = resolveSettings(loadConfig());
  if (!url) return { error: 'no backend configured - set SHOMRA_URL or run shomra init --url' };
  try {
    return await mcpLookup(url, mcpLookupId(server, name));
  } catch (error) {
    return { error: error.message };
  }
}

function printIndexSummary(index) {
  if (!index) return;
  if (index.found && index.scanned) {
    const colour = index.verdict === 'FAIL' ? red : index.verdict === 'REVIEW' ? yellow : green;
    console.log(dim('    ── MCP Security Index: ') + bold(index.slug) + dim(' · verdict ') + colour(String(index.verdict)) + dim(` · risk ${index.riskScore} ──`));
    for (const finding of (index.findings || []).slice(0, MAX_FINDINGS_SHOWN)) {
      console.log(`    ${(SEV_COLOR[finding.severity] || dim)(String(finding.severity).padEnd(8))} ${finding.title} ${dim('(index)')}`);
    }
    printAlternatives(index.alternatives, 'mcp', '    ');
    return;
  }
  if (index.found && !index.scanned) {
    console.log(dim(`    MCP Security Index: found "${index.slug}" but it hasn't been scanned yet.`));
    return;
  }
  if (index.error) {
    console.log(dim(`    MCP Security Index: unavailable (${index.error}) - using local checks only.`));
    return;
  }
  console.log(dim('    MCP Security Index: not indexed - using local checks only.'));
}

function printVettingReport(name, localVerdict, index) {
  console.log(bold(cyan(`\n  Vetting MCP server "${name}"…`)));
  for (const finding of localVerdict.findings.slice(0, MAX_FINDINGS_SHOWN)) {
    console.log(`    ${SEV_COLOR[finding.severity](String(finding.severity).padEnd(8))} ${finding.title} ${dim('(local)')}`);
  }
  printIndexSummary(index);
}

function readConfigOrEmpty(configFile) {
  if (!fs.existsSync(configFile)) return {};
  try {
    return JSON.parse(fs.readFileSync(configFile, 'utf8'));
  } catch {
    return {};
  }
}

function readConfigOrExit(configFile) {
  if (!fs.existsSync(configFile)) return {};
  try {
    return JSON.parse(fs.readFileSync(configFile, 'utf8'));
  } catch {
    console.error(`${red('✗')} ${configFile} is not valid JSON.`);
    return process.exit(EXIT_USAGE);
  }
}

function writeServerEntry(configFile, name, server) {
  const config = readConfigOrExit(configFile);
  config.mcpServers = config.mcpServers || {};
  const existed = !!config.mcpServers[name];
  config.mcpServers[name] = server;
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  fs.writeFileSync(configFile, `${JSON.stringify(config, null, 2)}\n`);
  return existed;
}

function outcomeNote(verdict) {
  if (verdict === 'FLAG') return yellow('  (flagged - review the findings above)');
  if (verdict === 'BLOCK') return red('  (forced past a BLOCK)');
  return green('  ✓ clean');
}

export async function cmdMcpAdd(flags, positional, configFile) {
  const name = positional[1];
  if (!name) usageExit(`Usage: ${bold('shomra mcp add <name> <command…>')}`);

  const { server, tokens } = buildServerEntry(flags, positional);
  if (!server.url && !server.command) usageExit('Provide a launch command or --url.');
  assertUsableArguments(name, server, tokens);

  const candidate = JSON.stringify({ mcpServers: { [name]: server } }, null, 2);
  const localVerdict = localGate(candidate, { kind: 'mcp', path: '.mcp.json' });
  const index = await lookupSecurityIndex(flags, server, name);
  const verdict = worstMcpVerdict(localVerdict.verdict, mcpIndexAlert(index));

  if (!flags.json) printVettingReport(name, localVerdict, index);

  if (verdict === 'BLOCK' && !flags.force) {
    if (flags.json) {
      console.log(JSON.stringify({
        installed: false, verdict, local: localVerdict.verdict, index, findings: localVerdict.findings,
      }, null, 2));
    } else {
      console.log(`\n  ${red('✗ Blocked - not installed.')} ${dim('Review the findings, or override with')} ${bold('--force')}${dim('.')}\n`);
    }
    process.exitCode = 1;
    return;
  }

  const existed = writeServerEntry(configFile, name, server);
  const relative = path.relative(process.cwd(), configFile).split(path.sep).join('/');

  if (flags.json) {
    console.log(JSON.stringify({
      installed: true, name, verdict, local: localVerdict.verdict, index, config: relative, updated: existed,
    }, null, 2));
    return;
  }
  console.log(`\n  ${green(existed ? '✓ Updated' : '✓ Added')} MCP server ${bold(name)} ${dim(`→ ${relative}`)}${outcomeNote(verdict)}\n`);
}

export function cmdMcpList(flags, configFile) {
  const config = readConfigOrEmpty(configFile);
  const servers = config.mcpServers || config.servers || {};
  const names = Object.keys(servers);

  if (flags.json) {
    console.log(JSON.stringify({ config: configFile, servers }, null, 2));
    return;
  }

  const relative = path.relative(process.cwd(), configFile).split(path.sep).join('/');
  console.log(bold(cyan('\n  MCP servers')) + dim(` - ${relative}`));
  if (!names.length) {
    console.log(dim('  (none)\n'));
    return;
  }
  for (const name of names) {
    const entry = servers[name];
    const launch = entry.url || [entry.command, ...(entry.args || [])].filter(Boolean).join(' ');
    console.log(`  ${green('●')} ${bold(name)} ${dim(launch)}`);
  }
  console.log('');
}
