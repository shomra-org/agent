import path from 'node:path';
import { readJson } from './fs-read.mjs';
import { redactEnv } from './model-keys.mjs';
import { APPDATA, HOME, PLAT, vscodeUserDir } from './platform.mjs';
import { walkWorkspace } from './workspace.mjs';

export function vendorFromPath(file) {
  if (/[\\/]\.cursor[\\/]/.test(file)) return 'cursor';
  if (/[\\/]\.vscode[\\/]/.test(file)) return 'vscode';
  if (/[\\/]\.gemini[\\/]/.test(file)) return 'gemini';
  if (/[\\/]\.zed[\\/]/.test(file)) return 'zed';
  return 'project';
}

function globalMcpCandidates() {
  const c = [];
  if (PLAT === 'win32') c.push({ vendor: 'claude', file: path.join(APPDATA, 'Claude', 'claude_desktop_config.json') });
  else if (PLAT === 'darwin') c.push({ vendor: 'claude', file: path.join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') });
  else c.push({ vendor: 'claude', file: path.join(HOME, '.config', 'Claude', 'claude_desktop_config.json') });
  c.push({ vendor: 'cursor', file: path.join(HOME, '.cursor', 'mcp.json') });
  c.push({ vendor: 'windsurf', file: path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json') });
  c.push({ vendor: 'continue', file: path.join(HOME, '.continue', 'config.json') });
  c.push({ vendor: 'claude-code', file: path.join(HOME, '.claude.json') });
  c.push({ vendor: 'gemini', file: path.join(HOME, '.gemini', 'settings.json') });
  c.push({ vendor: 'cline', file: path.join(vscodeUserDir(), 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json') });
  c.push({ vendor: 'roo', file: path.join(vscodeUserDir(), 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json') });

  c.push({ vendor: 'vscode', file: path.join(vscodeUserDir(), 'mcp.json') });
  c.push({ vendor: 'vscode', file: path.join(vscodeUserDir(), 'settings.json') });
  c.push({ vendor: 'cursor', file: path.join(vscodeUserDir('Cursor'), 'settings.json') });
  c.push({ vendor: 'zed', file: PLAT === 'darwin' ? path.join(HOME, 'Library', 'Application Support', 'Zed', 'settings.json') : path.join(HOME, '.config', 'zed', 'settings.json') });
  return c;
}

function extractServers(json) {
  if (!json || typeof json !== 'object') return {};
  return (
    json.mcpServers ||
    json.servers ||
    json['mcp.servers'] ||
    json.mcp?.servers ||
    json.context_servers ||
    {}
  );
}

export function discoverMcpServers(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const candidates = [
    ...globalMcpCandidates(),
    ...walk.mcp.map(({ file }) => ({ vendor: vendorFromPath(file), file })),
  ];
  const assets = [];
  const seen = new Set();
  for (const { vendor, file } of candidates) {
    const json = readJson(file);
    if (!json) continue;
    const servers = extractServers(json);
    for (const [name, cfg] of Object.entries(servers)) {
      if (!cfg || typeof cfg !== 'object') continue;
      const command = [cfg.command, ...(Array.isArray(cfg.args) ? cfg.args : [])].filter(Boolean).join(' ');
      const identifier = cfg.url || cfg.serverUrl || command || name;
      const key = `${name}:${identifier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      assets.push({
        type: 'MCP_SERVER',
        name,
        identifier,
        vendor,
        metadata: { command, url: cfg.url || cfg.serverUrl || null, configFile: file, env: redactEnv(cfg.env) },

        content: JSON.stringify({ command, url: cfg.url || cfg.serverUrl, env: cfg.env || {} }),
      });
    }
  }
  return assets;
}
