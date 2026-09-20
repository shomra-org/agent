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

/**
 * The screening flag inside a wrapped launch line, set or replaced.
 * ⚠ It sits BEFORE `--`: everything after it is the real server's command.
 */
function withScreen(args, screen) {
  const separator = args.indexOf('--');
  const head = separator === -1 ? args.slice() : args.slice(0, separator);
  const tail = separator === -1 ? [] : args.slice(separator);
  const at = head.indexOf('--screen');
  if (at !== -1) head.splice(at, 2);
  if (screen) head.push('--screen', screen);
  return [...head, ...tail];
}

export function wrapMcpConfig(config, selfPath, execPath, opts = {}) {
  const servers = serversOf(config);
  if (!servers) return { wrapped: [], skipped: [], updated: [] };

  const wrapped = [];
  const skipped = [];
  const updated = [];
  for (const [name, entry] of Object.entries(servers)) {
    if (!entry || typeof entry !== 'object') continue;
    const reason = skipReason(entry);
    if (reason) {
      skipped.push({ name, why: reason });
      continue;
    }
    if (isShimmed(entry, selfPath)) {
      // Re-running with --screen changes the mode of an existing guard in place.
      if (opts.screen) {
        const next = withScreen(entry.args ?? [], opts.screen);
        if (JSON.stringify(next) !== JSON.stringify(entry.args ?? [])) {
          servers[name] = { ...entry, args: next };
          updated.push(name);
          continue;
        }
      }
      skipped.push({ name, why: 'already guarded' });
      continue;
    }
    servers[name] = {
      ...entry,
      command: execPath,
      args: withScreen([selfPath, 'mcp-guard', '--name', name, '--', entry.command, ...(entry.args ?? [])], opts.screen),
    };
    wrapped.push(name);
  }
  return { wrapped, skipped, updated };
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
