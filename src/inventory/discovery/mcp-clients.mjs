import path from 'node:path';
import { readJson, readText } from './fs-read.mjs';
import { walkWorkspace } from './workspace.mjs';

const NPM_MCP_CLIENT = new Set(['mcp-use', 'mcp-client']);

const NPM_MCP_CLIENT_PREFIX = ['@modelcontextprotocol/', '@mastra/mcp', '@langchain/mcp'];

const PY_MCP_CLIENT = ['mcp', 'fastmcp', 'mcp-use', 'mcpadapt', 'langchain-mcp-adapters'];

function npmMcpClientDeps(pkg) {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}), ...(pkg.optionalDependencies || {}) };
  const hits = [];
  for (const name of Object.keys(deps)) {
    if (NPM_MCP_CLIENT.has(name) || NPM_MCP_CLIENT_PREFIX.some((p) => name.startsWith(p))) hits.push(name);
  }
  return hits;
}

function pyMcpClientDeps(text) {
  const hits = [];
  for (const pkg of PY_MCP_CLIENT) {
    const re = new RegExp(`(^|[^a-z0-9_.-])${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_.-]|$)`, 'im');
    if (re.test(text)) hits.push(pkg);
  }
  return hits;
}

export function discoverMcpClients(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const byPkg = new Map();
  const add = (eco, pkg, manifest) => {
    const key = `${eco}:${pkg}`;
    if (!byPkg.has(key)) byPkg.set(key, { pkg, eco, manifests: new Set() });
    byPkg.get(key).manifests.add(manifest);
  };
  for (const { file } of walk.manifests) {
    const base = path.basename(file);
    if (base === 'package.json') {
      const json = readJson(file);
      if (!json) continue;
      for (const pkg of npmMcpClientDeps(json)) add('npm', pkg, file);
    } else {
      const text = readText(file, 100_000);
      if (text == null) continue;
      for (const pkg of pyMcpClientDeps(text)) add('pip', pkg, file);
    }
  }
  const assets = [];
  for (const { pkg, eco, manifests } of byPkg.values()) {
    const list = [...manifests];
    assets.push({
      type: 'AI_TOOL',
      name: `${pkg} (${eco})`,
      identifier: `mcp-client:${eco}:${pkg}`,
      vendor: 'mcp-client',
      metadata: {
        category: 'mcp-client',
        ecosystem: eco,
        package: pkg,
        usedInProjects: list.length,
        manifests: list.slice(0, 10),
      },
    });
  }
  return assets;
}
