import fs from 'node:fs';
import path from 'node:path';
import { readText } from './fs-read.mjs';
import { redactEnv } from './model-keys.mjs';
import { PLAT, userDirs } from './platform.mjs';
import { walkWorkspace } from './workspace.mjs';
import { parseConfigDoc, readMcpServers } from '../../detect/signals/mcp-config.mjs';
import { claudeDataDir, jetbrainsOptionFiles, readClaudeExtensions, readJetbrainsMcpServers, readSqliteMcpServers, warpDatabases } from './mcp-stores.mjs';

export function vendorFromPath(file) {
  if (/[\\/]\.cursor[\\/]/.test(file)) return 'cursor';
  if (/[\\/]\.vscode[\\/]/.test(file)) return 'vscode';
  if (/[\\/]\.gemini[\\/]/.test(file)) return 'gemini';
  if (/[\\/]\.zed[\\/]/.test(file)) return 'zed';
  if (/[\\/]\.kiro[\\/]/.test(file)) return 'kiro';
  if (/[\\/]\.amazonq[\\/]/.test(file)) return 'amazonq';
  if (/[\\/]\.roo[\\/]/.test(file)) return 'roo';
  if (/[\\/]\.windsurf[\\/]/.test(file)) return 'windsurf';
  if (/[\\/]\.codex[\\/]/.test(file)) return 'codex';
  return 'project';
}

function appSupport(home, ...rel) {
  const { HOME, APPDATA } = userDirs(home);
  if (PLAT === 'darwin') return path.join(HOME, 'Library', 'Application Support', ...rel);
  if (PLAT === 'win32') return path.join(APPDATA, ...rel);
  return path.join(HOME, '.config', ...rel);
}

function claudeMsixConfigs(home) {
  if (PLAT !== 'win32') return [];
  const { LOCALAPPDATA } = userDirs(home);
  try {
    return fs.readdirSync(path.join(LOCALAPPDATA, 'Packages'))
      .filter((d) => /^(?:Claude|AnthropicPBC\.Claude)_/i.test(d))
      .map((d) => path.join(LOCALAPPDATA, 'Packages', d, 'LocalCache', 'Roaming', 'Claude', 'claude_desktop_config.json'));
  } catch {
    return [];
  }
}

function managedClaudeMcp() {
  if (PLAT === 'darwin') return path.join('/Library', 'Application Support', 'ClaudeCode', 'managed-mcp.json');
  if (PLAT === 'win32') return path.join(process.env.ProgramData || 'C:\\ProgramData', 'ClaudeCode', 'managed-mcp.json');
  return path.join('/etc', 'claude-code', 'managed-mcp.json');
}


function globalMcpCandidates(home) {
  const { HOME, APPDATA, LOCALAPPDATA, vscodeUserDir } = userDirs(home);
  const c = [];
  c.push({ vendor: 'claude', file: appSupport(home, 'Claude', 'claude_desktop_config.json') });
  for (const file of claudeMsixConfigs(home)) c.push({ vendor: 'claude', file });
  c.push({ vendor: 'claude-code', file: path.join(HOME, '.claude.json') }); // user + per-project (projects.*.mcpServers)
  c.push({ vendor: 'claude-code', file: managedClaudeMcp() });
  c.push({ vendor: 'cursor', file: path.join(HOME, '.cursor', 'mcp.json') });
  c.push({ vendor: 'windsurf', file: path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json') });
  c.push({ vendor: 'continue', file: path.join(HOME, '.continue', 'config.json') });
  c.push({ vendor: 'continue', file: path.join(HOME, '.continue', 'config.yaml') });
  c.push({ vendor: 'gemini', file: path.join(HOME, '.gemini', 'settings.json') });
  c.push({ vendor: 'qwen-code', file: path.join(HOME, '.qwen', 'settings.json') });
  c.push({ vendor: 'codex', file: path.join(HOME, '.codex', 'config.toml') });
  c.push({ vendor: 'copilot', file: path.join(HOME, '.copilot', 'mcp-config.json') });
  c.push({ vendor: 'kiro', file: path.join(HOME, '.kiro', 'settings', 'mcp.json') });
  c.push({ vendor: 'amazonq', file: path.join(HOME, '.aws', 'amazonq', 'mcp.json') });
  c.push({ vendor: 'opencode', file: path.join(HOME, '.config', 'opencode', 'opencode.json') });
  c.push({ vendor: 'crush', file: path.join(HOME, '.config', 'crush', 'crush.json') });
  c.push({ vendor: 'goose', file: PLAT === 'win32' ? path.join(APPDATA, 'Block', 'goose', 'config', 'config.yaml') : path.join(HOME, '.config', 'goose', 'config.yaml') });
  c.push({ vendor: 'lmstudio', file: path.join(HOME, '.lmstudio', 'mcp.json') });
  c.push({ vendor: 'junie', file: path.join(HOME, '.junie', 'mcp', 'mcp.json') });
  c.push({ vendor: 'visualstudio', file: path.join(HOME, '.mcp.json') }); // Visual Studio's user-scope config
  c.push({ vendor: 'copilot', file: PLAT === 'win32' ? path.join(LOCALAPPDATA, 'github-copilot', 'intellij', 'mcp.json') : path.join(HOME, '.config', 'github-copilot', 'intellij', 'mcp.json') });
  for (const file of warpDatabases(home)) c.push({ vendor: 'warp', file, store: 'sqlite' });
  for (const file of jetbrainsOptionFiles(home)) c.push({ vendor: 'jetbrains', file, store: 'jetbrains-xml' });

  const FORKS = [
    { variant: 'Code', vendor: 'vscode' },
    { variant: 'Code - Insiders', vendor: 'vscode' },
    { variant: 'VSCodium', vendor: 'vscode' },
    { variant: 'Cursor', vendor: 'cursor' },
    { variant: 'Windsurf', vendor: 'windsurf' },
  ];
  for (const { variant, vendor } of FORKS) {
    const user = vscodeUserDir(variant);
    c.push({ vendor, file: path.join(user, 'mcp.json') });
    c.push({ vendor, file: path.join(user, 'settings.json') });
    c.push({ vendor: 'cline', file: path.join(user, 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json') });
    c.push({ vendor: 'roo', file: path.join(user, 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json') });
  }
  c.push({ vendor: 'zed', file: PLAT === 'darwin' ? path.join(HOME, 'Library', 'Application Support', 'Zed', 'settings.json') : PLAT === 'win32' ? path.join(APPDATA, 'Zed', 'settings.json') : path.join(HOME, '.config', 'zed', 'settings.json') });
  return c;
}

/** Project-scope configs in the directories being swept (the workspace walker finds `.mcp.json` / `mcp.json` itself). */
function projectMcpCandidates(roots) {
  const rels = [
    ['.cursor', 'mcp.json'], ['.vscode', 'mcp.json'], ['.gemini', 'settings.json'], ['.kiro', 'settings', 'mcp.json'],
    ['.amazonq', 'mcp.json'], ['.roo', 'mcp.json'], ['.windsurf', 'mcp.json'], ['.codex', 'config.toml'],
    ['.junie', 'mcp', 'mcp.json'], ['opencode.json'], ['.zed', 'settings.json'], ['.vs', 'mcp.json'],
  ];
  return roots.flatMap((root) => rels.map((rel) => ({ vendor: vendorFromPath(path.join(root, ...rel)), file: path.join(root, ...rel) })));
}

function readServers(file, store) {
  if (store === 'sqlite') {
    const { servers, state } = readSqliteMcpServers(file);
    if (state !== 'read') unreadStores.push({ file, state });
    return servers.length ? servers : null;
  }
  if (store === 'jetbrains-xml') {
    const servers = readJetbrainsMcpServers(file);
    return servers.length ? servers : null;
  }
  const text = readText(file, 1_000_000);
  if (!text) return null;
  const doc = parseConfigDoc(text, file);
  return doc ? readMcpServers(doc) : null;
}

let unreadStores = [];
export function unreadMcpStores() {
  return unreadStores.slice();
}

export function discoverMcpServers(roots = [process.cwd()], files = null, opts = {}) {
  const walk = files || walkWorkspace(roots);
  const candidates = [
    ...globalMcpCandidates(opts.home),
    ...projectMcpCandidates(roots),
    ...walk.mcp.map(({ file }) => ({ vendor: vendorFromPath(file), file })),
  ];
  unreadStores = [];
  const assets = [];
  const seen = new Set();
  const seenFile = new Set();
  const sources = [];
  for (const { vendor, file, store } of candidates) {
    const key0 = path.resolve(file).toLowerCase();
    if (seenFile.has(key0)) continue;
    seenFile.add(key0);
    const servers = readServers(file, store);
    if (servers) sources.push({ vendor, file, servers });
  }
  for (const s of readClaudeExtensions(claudeDataDir(opts.home))) sources.push({ vendor: 'claude', file: s.file, servers: [s] });

  for (const { vendor, file, servers } of sources) {
    for (const s of servers) {
      const command = [s.command, ...(s.args ?? [])].filter(Boolean).join(' ');
      const identifier = s.url || command || s.name;
      const key = `${s.name}:${identifier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      assets.push({
        type: 'MCP_SERVER',
        name: s.name,
        identifier,
        vendor,
        metadata: {
          command,
          url: s.url || null,
          configFile: file,
          env: redactEnv(s.env),
          ...(s.scope ? { projectScope: s.scope } : {}),
          ...(s.disabled ? { disabled: true } : {}),
        },
        content: JSON.stringify({ command, url: s.url, env: s.env || {}, server: s }),
      });
    }
  }
  return assets;
}
