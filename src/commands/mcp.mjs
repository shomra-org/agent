import fs from 'node:fs';
import path from 'node:path';
import { SELF_PATH } from '../agents/hook-command.mjs';
import { EXIT_USAGE } from '../core/exit-codes.mjs';
import { bold, dim, green, red, yellow } from '../core/terminal.mjs';
import { MCP_HOST_CONFIGS, MCP_HOST_KEYS, shomraMcpEntry } from '../mcp/hosts.mjs';
import { runMcpServer } from '../mcp/server.mjs';
import { cmdMcpAdd, cmdMcpList } from './mcp-add.mjs';

function cmdMcpInstall(flags) {
  const requested = flags.agent
    ? String(flags.agent).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean)
    : MCP_HOST_KEYS;
  if (requested.includes('all')) requested.splice(0, requested.length, ...MCP_HOST_KEYS);
  const bad = requested.filter((a) => !MCP_HOST_CONFIGS[a]);
  if (bad.length) {
    console.error(red('✗') + ` No MCP config is known for: ${bad.join(', ')}. Supported: ${MCP_HOST_KEYS.join(', ')}, all.`);
    process.exit(EXIT_USAGE);
  }

  const global = !!flags.global;
  const entry = shomraMcpEntry();
  const out = [];

  for (const key of requested) {
    const host = MCP_HOST_CONFIGS[key];
    const file = global ? host.global() : host.local();
    let cfg = {};
    if (fs.existsSync(file)) {
      try { cfg = JSON.parse(fs.readFileSync(file, 'utf8')); } catch {
        console.log(`  ${red('✗')} ${host.label} ${dim('- ' + file + ' is not valid JSON; fix or move it first.')}`);
        out.push({ agent: key, file, changed: false, error: 'invalid json' });
        continue;
      }
    }
    cfg.mcpServers = cfg.mcpServers || {};
    const before = JSON.stringify(cfg.mcpServers.shomra || null);
    cfg.mcpServers.shomra = entry;
    const changed = before !== JSON.stringify(entry);
    if (changed) {
      try {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + '\n');
      } catch (e) {
        console.log(`  ${red('✗')} ${host.label} ${dim('- ' + e.message)}`);
        out.push({ agent: key, file, changed: false, error: e.message });
        continue;
      }
    }
    out.push({ agent: key, file, changed });
    if (!flags.json) {
      if (changed) console.log(`  ${green('✓')} Registered the Shomra MCP server for ${bold(host.label)} ${dim('→ ' + file)}`);
      else console.log(`  ${yellow('•')} ${host.label} ${dim('already registered (' + file + ')')}`);
    }
  }

  if (flags.json) { console.log(JSON.stringify({ scope: global ? 'global' : 'project', installed: out }, null, 2)); return; }
  console.log(dim('\n  The agent can now call Shomra in its own loop: ') + bold('shomra_review_change') + dim(' (gate content BEFORE writing it),'));
  console.log(dim('  ') + bold('shomra_rules') + dim(' (what will be refused here), plus check / explain / fix / scan_models.'));
  console.log(dim('  Restart the agent to pick up the new server.'));
  if (!global) {

    console.log(dim('  Note: the entry holds absolute paths for THIS machine. If you commit it, teammates should'));
    console.log(dim('        run ') + bold('shomra mcp install') + dim(' themselves rather than rely on the committed path.'));
  }
  console.log('');
}

export async function cmdMcpGuard(flags, positional) {
  const { runMcpShim } = await import('../mcp/shim.mjs');
  return runMcpShim(flags, positional);
}

async function cmdMcpGuardInstall(flags) {
  const { wrapMcpConfig, unwrapMcpConfig, mcpConfigCandidates } = await import('../mcp/shim.mjs');
  const undo = !!flags.uninstall;
  const files = flags.config
    ? [{ label: 'config', file: path.resolve(String(flags.config)) }]
    : mcpConfigCandidates();

  if (!files.length) {
    console.log(dim('\n  No MCP client config found on this machine. Nothing to guard.\n'));
    return;
  }

  const results = [];
  for (const { label, file } of files) {
    let cfg;
    try {
      cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      console.log(`  ${red('✗')} ${label} ${dim('- ' + file + ' is not valid JSON; fix or move it first.')}`);
      results.push({ file, error: 'invalid json' });
      continue;
    }
    const before = JSON.stringify(cfg);
    const out = undo ? unwrapMcpConfig(cfg, SELF_PATH) : wrapMcpConfig(cfg, SELF_PATH, process.execPath);
    const changed = JSON.stringify(cfg) !== before;
    if (changed) {
      try {

        const bak = file + '.shomra-backup';
        if (!undo && !fs.existsSync(bak)) fs.writeFileSync(bak, before);
        fs.writeFileSync(file, JSON.stringify(cfg, null, 2) + '\n');
      } catch (e) {
        console.log(`  ${red('✗')} ${label} ${dim('- ' + e.message)}`);
        results.push({ file, error: e.message });
        continue;
      }
    }
    results.push({ file, label, ...out, changed });
    if (!flags.json) {
      const names = undo ? out.restored : out.wrapped;
      if (names.length) console.log(`  ${green('✓')} ${bold(label)} ${dim('- ' + (undo ? 'restored ' : 'guarded ') + names.join(', '))}`);
      else console.log(`  ${yellow('•')} ${label} ${dim('- nothing to ' + (undo ? 'restore' : 'guard'))}`);
      for (const s of out.skipped ?? []) console.log(`    ${dim('· ' + s.name + ' - ' + s.why)}`);
    }
  }

  if (flags.json) { console.log(JSON.stringify({ mode: undo ? 'uninstall' : 'install', results }, null, 2)); return; }
  if (!undo) {
    console.log(dim('\n  Every stdio MCP server now starts through Shomra: a DENIED / REVOKED / QUARANTINED'));
    console.log(dim('  server is refused before its process exists, and poisoned tool descriptions are'));
    console.log(dim('  withheld from the model at tools/list rather than at the first call.'));
    console.log(dim('  Restart the agent to pick up the change. Undo: ') + bold('shomra mcp guard --uninstall') + '\n');
  } else {
    console.log(dim('\n  Original launch lines restored. Restart the agent.\n'));
  }
}

export async function cmdMcp(flags, positional) {
  const sub = String(positional[0] || '').toLowerCase();
  if (sub === 'guard') return cmdMcpGuardInstall(flags);
  if (sub === 'serve') return runMcpServer(flags);
  if (sub === 'install') return cmdMcpInstall(flags);

  const configFile = path.resolve(flags.config ? String(flags.config) : '.mcp.json');
  if (sub === 'list') return cmdMcpList(flags, configFile);
  if (sub === 'add') return cmdMcpAdd(flags, positional, configFile);

  console.error(red('✗') + ` Usage: ${bold('shomra mcp add <name> <command…> | --url <url>')} ${dim('|')} ${bold('shomra mcp list')}`);
  process.exit(EXIT_USAGE);
}
