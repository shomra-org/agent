import path from 'node:path';
import { readText } from './fs-read.mjs';
import { vendorFromPath } from './mcp-servers.mjs';
import { walkWorkspace } from './workspace.mjs';

export function discoverRulesFiles(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const assets = [];
  const seen = new Set();
  for (const { file } of walk.rules) {
    if (seen.has(file)) continue;
    seen.add(file);
    const content = readText(file, 50_000);
    if (content == null) continue;
    assets.push({
      type: 'AI_RULES',
      name: path.basename(file),
      identifier: file,
      vendor: vendorFromPath(file) === 'project' ? 'rules' : vendorFromPath(file),
      metadata: { bytes: content.length, dir: path.dirname(file) },
      content: content.slice(0, 50_000),
    });
  }
  return assets;
}
