import fs from 'node:fs';
import path from 'node:path';
import { readJsonAt, readText, stripJsonComments } from './file-read.mjs';
import { canonicalHooks } from './hooks.mjs';
import { userDirs } from '../discovery/platform.mjs';

export { PLUGIN_MANIFEST_RE } from '../../detect/signals/manifests.mjs';
export const MARKETPLACE_ROOT_RE = /(^|\/)plugins\/marketplaces\/[^/]+\/\.claude-plugin\/marketplace\.json$/i;
export const MAX_MANIFEST_BYTES = 200_000;

const MAX_COMPONENT_FILES = 12;
const MAX_BIN_NAMES = 40;

export function pluginRootOf(absManifest) {
  const dir = path.dirname(absManifest);
  const base = path.basename(dir).toLowerCase();
  if (/^\.(claude|codex|cursor|copilot|github)-plugin$|^\.plugin$/.test(base)) return path.dirname(dir);
  if (base === 'plugin' && path.basename(path.dirname(dir)).toLowerCase() === '.github') return path.dirname(path.dirname(dir));
  if (base === 'plugins' && path.basename(path.dirname(dir)).toLowerCase() === '.agents') return path.dirname(path.dirname(dir));
  return dir;
}

export function manifestName(text, fallback) {
  try {
    const doc = JSON.parse(stripJsonComments(text));
    const n = doc?.name ?? doc?.id;
    if (typeof n === 'string' && n.trim()) return n.trim().slice(0, 200);
  } catch {  }
  return fallback;
}

function inside(root, target) {
  const rel = path.relative(root, target);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function insideReal(root, target) {
  try {
    return inside(fs.realpathSync(root), fs.realpathSync(target));
  } catch {
    return false;
  }
}

function declaredComponentPaths(text) {
  let doc;
  try { doc = JSON.parse(stripJsonComments(text)); } catch { return []; }
  const out = [];
  for (const key of ['hooks', 'mcpServers', 'lspServers', 'monitors']) {
    const v = doc?.[key];
    for (const p of typeof v === 'string' ? [v] : Array.isArray(v) ? v : []) {
      if (typeof p === 'string' && p.trim()) out.push(p.trim().replace(/^\$\{?(?:CLAUDE_PLUGIN_ROOT|PLUGIN_ROOT)\}?\/?/, './'));
    }
  }
  return out;
}

export function bundlePluginComponents(artifact, absManifest, toRel, budget, capped) {
  const root = pluginRootOf(absManifest);
  const wanted = new Set(['hooks/hooks.json', '.mcp.json', 'mcp.json', '.lsp.json', 'monitors/monitors.json']);
  for (const p of declaredComponentPaths(artifact.content)) wanted.add(p.replace(/^\.\//, ''));

  for (const rel of wanted) {
    if (artifact.files.length >= MAX_COMPONENT_FILES) { capped.push({ reason: 'bundle-cap', path: artifact.path }); break; }
    const abs = path.resolve(root, rel);
    if (!inside(root, abs) || !/\.json$/i.test(abs) || !insideReal(root, abs)) continue;
    const read = readText(abs, MAX_MANIFEST_BYTES);
    if (!read || read.truncated) continue;
    const content = /hooks[^/\\]*\.json$/i.test(abs) ? canonicalHooks(read.text) : read.text;
    if (!content) continue;
    if (Buffer.byteLength(content) > budget.bytes) { capped.push({ reason: 'byte-budget', path: toRel(abs) }); continue; }
    budget.bytes -= Buffer.byteLength(content);
    artifact.files.push({ path: toRel(abs), content, binary: false });
  }

  let bin = [];
  try { bin = fs.readdirSync(path.join(root, 'bin'), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name); } catch {  }
  for (const name of bin.slice(0, MAX_BIN_NAMES)) artifact.files.push({ path: toRel(path.join(root, 'bin', name)), content: null, binary: true });

  artifact.metadata.bundledCount = artifact.files.length;
}

export function installedPluginManifests(claudeDir, home) {
  const { HOME } = userDirs(home);
  const doc = readJsonAt(path.join(claudeDir, 'plugins', 'installed_plugins.json'));
  if (!doc || typeof doc !== 'object') return [];
  const out = [];
  const seen = new Set();
  for (const [key, value] of Object.entries(doc.plugins ?? {})) {
    const records = Array.isArray(value) ? value : [value];
    for (const r of records) {
      const installPath = typeof r?.installPath === 'string' ? r.installPath : null;
      if (!installPath) continue;
      const abs = path.resolve(installPath);
      if (!inside(HOME, abs)) continue;
      for (const candidate of [path.join(abs, '.claude-plugin', 'plugin.json'), path.join(abs, 'plugin.json')]) {
        if (seen.has(candidate) || !fs.existsSync(candidate) || !insideReal(HOME, candidate)) continue;
        seen.add(candidate);
        const at = key.indexOf('@');
        out.push({ manifest: candidate, marketplace: at > -1 ? key.slice(at + 1) : null });
        break;
      }
    }
  }
  return out;
}
