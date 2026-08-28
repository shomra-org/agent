import { clampAsset } from '../../core/wire-limits.mjs';
import { discoverAiDependencies, discoverAiUsageInCode } from './ai-dependencies.mjs';
import { discoverAiTools } from './ai-tools.mjs';
import { discoverCodingAgents } from './coding-agents.mjs';
import { discoverMcpClients } from './mcp-clients.mjs';
import { discoverMcpServers } from './mcp-servers.mjs';
import { discoverDotenvKeys, discoverModelKeys } from './model-keys.mjs';
import { discoverRulesFiles } from './rules-files.mjs';
import { discoverVectorStores } from './vector-stores.mjs';
import { resolveRoots, walkWorkspace } from './workspace.mjs';

export function discoverAll(roots = [process.cwd()], opts = {}) {
  const { autoExpand = true } = opts;
  const scanRoots = resolveRoots(roots, autoExpand);
  const files = walkWorkspace(scanRoots);
  const all = [
    ...discoverMcpServers(scanRoots, files),
    ...discoverRulesFiles(scanRoots, files),
    ...discoverAiDependencies(scanRoots, files),
    ...discoverAiUsageInCode(scanRoots, files),
    ...discoverMcpClients(scanRoots, files),
    ...discoverVectorStores(scanRoots, files),
    ...discoverDotenvKeys(scanRoots, files),
    ...discoverAiTools(),
    ...discoverCodingAgents(scanRoots),
    ...discoverModelKeys(),
  ];

  const clamped = all.map(clampAsset);

  const seen = new Set();
  const out = [];
  for (const a of clamped) {
    const key = `${a.type}::${a.identifier || a.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}
