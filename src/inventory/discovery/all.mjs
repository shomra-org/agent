import { clampAsset } from '../../core/wire-limits.mjs';
import { discoverAiDependencies, discoverAiUsageInCode } from './ai-dependencies.mjs';
import { discoverAiTools } from './ai-tools.mjs';
import { discoverCloudClis } from './cloud-clis.mjs';
import { discoverCodingAgents } from './coding-agents.mjs';
import { discoverMcpClients } from './mcp-clients.mjs';
import { discoverMcpServers } from './mcp-servers.mjs';
import { discoverDotenvKeys, discoverModelKeys } from './model-keys.mjs';
import { discoverRulesFiles } from './rules-files.mjs';
import { discoverVectorStores } from './vector-stores.mjs';
import { userDirs } from './platform.mjs';
import { resolveRoots, walkWorkspace } from './workspace.mjs';

export function discoverAll(roots = [process.cwd()], opts = {}) {
  const { autoExpand = true, home } = opts;
  const own = userDirs(home).own;
  const scanRoots = resolveRoots(roots, autoExpand, home);
  const files = walkWorkspace(scanRoots);
  const all = [
    ...discoverMcpServers(scanRoots, files, { home }),
    ...discoverRulesFiles(scanRoots, files),
    ...discoverAiDependencies(scanRoots, files),
    ...discoverAiUsageInCode(scanRoots, files),
    ...discoverMcpClients(scanRoots, files),
    ...discoverVectorStores(scanRoots, files),
    ...discoverDotenvKeys(scanRoots, files),
    ...discoverAiTools({ home }),
    ...discoverCodingAgents(scanRoots, { home }),
    ...(own ? discoverModelKeys() : []),
    // ⚠ What this HOST is logged into - the reach an agent with a shell
    // inherits and no agent policy granted. See `cloud-clis.mjs`.
    ...discoverCloudClis({ home }),
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
