import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function serversOf(config) {
  const servers = config?.mcpServers || config?.servers;
  return servers && typeof servers === 'object' ? servers : null;
}

function isShimmed(entry, selfPath) {
  const args = entry.args ?? [];
  return args.includes('mcp-guard') && args.some((argument) => String(argument) === selfPath);
}

function skipReason(entry) {
  if (!entry.command) return entry.url ? 'http - mediated by the gateway' : 'no launch command';
  return null;
}

export function wrapMcpConfig(config, selfPath, execPath) {
  const servers = serversOf(config);
  if (!servers) return { wrapped: [], skipped: [] };

  const wrapped = [];
  const skipped = [];
  for (const [name, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object') continue;
    const reason = skipReason(entry);
    if (reason) {
      skipped.push({ name, why: reason });
      continue;
    }
    if (isShimmed(entry, selfPath)) {
      skipped.push({ name, why: 'already guarded' });
      continue;
    }
    servers[name] = {
      ...entry,
      command: execPath,
      args: [selfPath, 'mcp-guard', '--name', name, '--', entry.command, ...(entry.args ?? [])],
    };
    wrapped.push(name);
  }
  return { wrapped, skipped };
}

export function unwrapMcpConfig(config, selfPath) {
  const servers = serversOf(config);
  if (!servers) return { restored: [] };

  const restored = [];
  for (const [name, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object' || !isShimmed(entry, selfPath)) continue;
    const args = entry.args ?? [];
    const separator = args.indexOf('--');
    if (separator === -1 || !args[separator + 1]) continue;
    servers[name] = { ...entry, command: args[separator + 1], args: args.slice(separator + 2) };
    if (!servers[name].args.length) delete servers[name].args;
    restored.push(name);
  }
  return { restored };
}

export function mcpConfigCandidates() {
  const home = os.homedir();
  const cwd = process.cwd();
  return [
    { label: 'Claude Code (project)', file: path.join(cwd, '.mcp.json') },
    { label: 'Claude Code (global)', file: path.join(home, '.claude.json') },
    { label: 'Cursor (project)', file: path.join(cwd, '.cursor', 'mcp.json') },
    { label: 'Cursor (global)', file: path.join(home, '.cursor', 'mcp.json') },
    { label: 'Windsurf', file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { label: 'Gemini CLI', file: path.join(home, '.gemini', 'settings.json') },
  ].filter((candidate) => fs.existsSync(candidate.file));
}
