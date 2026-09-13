import path from 'node:path';
import { MAX_SPECS, pySpecFor } from './ai-dependencies.mjs';
import { readJson, readText } from './fs-read.mjs';
import { walkWorkspace } from './workspace.mjs';

const NPM_MCP_CLIENT = new Set(['mcp-use', 'mcp-client']);

const NPM_MCP_CLIENT_PREFIX = ['@modelcontextprotocol/', '@mastra/mcp', '@langchain/mcp'];

const PY_MCP_CLIENT = ['mcp', 'fastmcp', 'mcp-use', 'mcpadapt', 'langchain-mcp-adapters'];

function npmMcpClientDeps(pkg) {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}), ...(pkg.optionalDependencies || {}) };
  const hits = [];
  for (const [name, spec] of Object.entries(deps)) {
    if (NPM_MCP_CLIENT.has(name) || NPM_MCP_CLIENT_PREFIX.some((p) => name.startsWith(p))) {
      hits.push({ name, spec: typeof spec === 'string' ? spec : null });
    }
  }
  return hits;
}

function pyMcpClientDeps(text) {
  const hits = [];
  for (const pkg of PY_MCP_CLIENT) {
    const re = new RegExp(`(^|[^a-z0-9_.-])${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_.-]|$)`, 'im');
    if (re.test(text)) hits.push({ name: pkg, spec: pySpecFor(text, pkg) });
  }
  return hits;
}

export function discoverMcpClients(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const byPkg = new Map();
  const add = (eco, pkg, manifest, spec) => {
    const key = `${eco}:${pkg}`;
    if (!byPkg.has(key)) byPkg.set(key, { pkg, eco, manifests: new Set(), specs: new Set() });
    const row = byPkg.get(key);
    row.manifests.add(manifest);
    if (spec) row.specs.add(spec);
  };
  for (const { file } of walk.manifests) {
    const base = path.basename(file);
    if (base === 'package.json') {
      const json = readJson(file);
      if (!json) continue;
      for (const hit of npmMcpClientDeps(json)) add('npm', hit.name, file, hit.spec);
    } else {
      const text = readText(file, 100_000);
      if (text == null) continue;
      for (const hit of pyMcpClientDeps(text)) add('pip', hit.name, file, hit.spec);
    }
  }
  const assets = [];
  for (const { pkg, eco, manifests, specs } of byPkg.values()) {
    const list = [...manifests];
    assets.push({
      type: 'AI_LIBRARY',
      name: `${pkg} (${eco})`,
      identifier: `mcp-client:${eco}:${pkg}`,
      vendor: 'mcp-client',
      metadata: {
        category: 'mcp-client',
        ecosystem: eco,
        package: pkg,
        specs: [...specs].slice(0, MAX_SPECS),
        usedInProjects: list.length,
        manifests: list.slice(0, 10),
      },
    });
  }
  return assets;
}
