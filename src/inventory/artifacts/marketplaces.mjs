import path from 'node:path';
import { readJsonAt } from './file-read.mjs';

export const SETTINGS_BASENAMES = new Set([
  'settings.json', 'settings.local.json', 'hooks.json', 'config.toml',
]);

export const PLUGIN_PATH_RE = /(^|\/)plugins\/marketplaces\/([^/]+)\//;

export const CATALOGUE_DIR_RE = /(^|\/)(\.tmp|tmp|temp|vendor_imports|bundled-marketplaces|backups?)\//i;

export function installedMarketplaces(root) {

  const out = new Set();

  const manifest = readJsonAt(path.join(root, 'plugins', 'installed_plugins.json'));
  if (manifest === undefined) return null;
  if (manifest !== null) {
    const plugins = manifest?.plugins;
    if (plugins && typeof plugins === 'object') {
      for (const [key, value] of Object.entries(plugins)) {
        addPluginKey(out, key);
        const named = value && typeof value === 'object' ? (value.marketplace ?? value.source) : null;
        if (typeof named === 'string') out.add(named);
      }
    }
  }

  for (const f of ['settings.json', 'settings.local.json']) {
    const doc = readJsonAt(path.join(root, f));
    if (doc === undefined) return null;
    if (doc === null) continue;
    const enabled = doc?.enabledPlugins;
    if (enabled && typeof enabled === 'object') {
      for (const key of Object.keys(enabled)) addPluginKey(out, key);
    }
  }

  return out;
}

function addPluginKey(set, key) {
  const at = String(key).indexOf('@');
  set.add(at > -1 ? String(key).slice(at + 1) : String(key));
}
