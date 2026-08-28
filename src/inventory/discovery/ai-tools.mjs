import path from 'node:path';
import { firstExisting } from './fs-read.mjs';
import { discoverLocalRuntimes } from './local-runtimes.mjs';
import { APPDATA, HOME, LOCALAPPDATA, vscodeUserDir } from './platform.mjs';

export function discoverAiTools() {
  const checks = [
    { vendor: 'cursor', name: 'Cursor', probe: [path.join(HOME, '.cursor')] },
    { vendor: 'claude', name: 'Claude Desktop', probe: [path.join(APPDATA, 'Claude'), path.join(HOME, 'Library', 'Application Support', 'Claude'), path.join(HOME, '.config', 'Claude')] },
    { vendor: 'windsurf', name: 'Windsurf', probe: [path.join(HOME, '.codeium', 'windsurf')] },
    { vendor: 'continue', name: 'Continue', probe: [path.join(HOME, '.continue')] },
    { vendor: 'zed', name: 'Zed', probe: [path.join(HOME, '.config', 'zed'), path.join(HOME, 'Library', 'Application Support', 'Zed')] },
    { vendor: 'cody', name: 'Sourcegraph Cody', probe: [path.join(vscodeUserDir(), 'globalStorage', 'sourcegraph.cody-ai')] },
    { vendor: 'copilot', name: 'GitHub Copilot (VS Code)', probe: [path.join(vscodeUserDir(), 'globalStorage', 'github.copilot'), path.join(vscodeUserDir(), 'globalStorage', 'github.copilot-chat')] },
    { vendor: 'tabnine', name: 'Tabnine', probe: [path.join(HOME, '.tabnine'), path.join(LOCALAPPDATA, 'TabNine')] },
  ];
  const assets = [];
  for (const c of checks) {
    const at = firstExisting(c.probe);
    if (at) assets.push({ type: 'AI_TOOL', name: c.name, identifier: at, vendor: c.vendor, metadata: { category: 'assistant', detectedAt: at } });
  }
  return [...assets, ...discoverLocalRuntimes()];
}
