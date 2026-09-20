import fs from 'node:fs';
import path from 'node:path';
import { clampArtifact } from '../../core/wire-limits.mjs';
import { classify, declaredName } from './classify.mjs';
import { readText } from './file-read.mjs';
import { canonicalHooks } from './hooks.mjs';
import { bundleHookScripts } from './hook-scripts.mjs';
import { MAX_ARTIFACTS, MAX_BUNDLED, MAX_DIRS, MAX_TOTAL_BYTES, TEXT_EXTS, extOf } from './limits.mjs';
import { extractInstructionImports } from '../../detect/signals/instruction-paths.mjs';
import { CATALOGUE_DIR_RE, PLUGIN_PATH_RE, installedMarketplaces } from './marketplaces.mjs';
import { MARKETPLACE_ROOT_RE, MAX_MANIFEST_BYTES, bundlePluginComponents, installedPluginManifests, manifestName, pluginRootOf } from './plugins.mjs';
import { bundleExtensionSource } from './extensions.mjs';
import { artifactRoots } from './roots.mjs';
import { walkRoot } from './walk.mjs';
import { userDirs } from '../discovery/platform.mjs';

const MAX_NAME_LENGTH = 200;

function relativeToSite(site, absolutePath) {
  return path.relative(path.dirname(site.dir), absolutePath).replace(/\\/g, '/');
}

function artifactName(kind, content, absolutePath) {
  if (kind === 'plugin') return manifestName(content, path.basename(pluginRootOf(absolutePath)) || path.basename(absolutePath));
  if (kind === 'extension') return manifestName(content, path.basename(path.dirname(absolutePath)));
  const declared = declaredName(content);
  if (declared) return declared;
  if (kind === 'skill') return path.basename(path.dirname(absolutePath));
  if (kind === 'hook') return `${path.basename(absolutePath)} · hooks`;
  if (kind === 'rules') return path.basename(absolutePath);
  return path.basename(absolutePath).replace(/\.(md|toml)$/i, '');
}

function resolveActivation(marketplace, installed) {
  if (!marketplace) return 'active';
  if (installed === null) return 'unknown';
  return installed.has(marketplace) ? 'active' : 'not-installed';
}

function readArtifactContent(kind, absolutePath) {
  const manifest = kind === 'plugin' || kind === 'extension';
  const read = readText(absolutePath, manifest ? MAX_MANIFEST_BYTES : undefined);
  if (!read) return null;
  if (manifest && read.truncated) return { ...read, content: null, oversize: true };
  if (kind !== 'hook') return { ...read, content: read.text };
  const content = canonicalHooks(read.text);
  return content ? { ...read, content } : null;
}

function buildArtifact({ kind, content, read, relativePath, site, project, marketplace, activation, absolutePath }) {
  return {
    kind,
    name: String(artifactName(kind, content, absolutePath)).slice(0, MAX_NAME_LENGTH),
    path: relativePath,
    scope: site.scope,
    vendor: site.vendor,
    content,
    files: [],
    metadata: {
      bytes: read.bytes,
      truncated: read.truncated,
      project: site.scope === 'project' ? project : null,
      activation,
      marketplace,
    },
  };
}

function collectFromSite({ site, files, state, project }) {
  const { artifacts, capped, consumed, skills, availableBy, budget } = state;
  const installed = installedMarketplaces(site.dir);

  for (const absolutePath of files) {
    if (artifacts.length >= MAX_ARTIFACTS) {
      capped.push({ reason: 'artifact-cap', path: absolutePath });
      return;
    }
    const relativePath = relativeToSite(site, absolutePath);
    const kind = classify(relativePath, site.vendor);
    if (!kind) continue;

    const catalogue = CATALOGUE_DIR_RE.exec(relativePath);
    if (catalogue) {
      const label = `${site.vendor}:${catalogue[2].toLowerCase()}`;
      availableBy.set(label, (availableBy.get(label) ?? 0) + 1);
      continue;
    }

    const marketplace = PLUGIN_PATH_RE.exec(relativePath)?.[2] ?? null;

    if (kind === 'plugin' && marketplace && !MARKETPLACE_ROOT_RE.test(relativePath)) {
      availableBy.set(marketplace, (availableBy.get(marketplace) ?? 0) + 1);
      continue;
    }
    const activation = kind === 'plugin' && marketplace ? 'active' : resolveActivation(marketplace, installed);
    if (activation === 'not-installed') {
      availableBy.set(marketplace, (availableBy.get(marketplace) ?? 0) + 1);
      continue;
    }

    const read = readArtifactContent(kind, absolutePath);
    if (!read) continue;
    if (read.oversize) {
      capped.push({ reason: 'manifest-too-large', path: relativePath });
      continue;
    }
    if (read.bytes > budget.bytes) {
      capped.push({ reason: 'byte-budget', path: relativePath });
      continue;
    }

    budget.bytes -= Buffer.byteLength(read.content);
    const artifact = buildArtifact({
      kind, content: read.content, read, relativePath, site, project, marketplace, activation, absolutePath,
    });
    consumed.add(absolutePath);
    artifacts.push(artifact);
    if (kind === 'skill') skills.push({ artifact, dir: path.dirname(absolutePath), site });
    if (kind === 'rules') state.rules.push({ artifact, absolutePath });
    if (kind === 'plugin') state.plugins.push({ artifact, absolutePath, site });
    if (kind === 'extension') state.extensions.push({ artifact, absolutePath, site });
    if (kind === 'hook') (state.hooks ??= []).push({ artifact, absolutePath, site });
  }
}

function collectInstalledPlugins({ sites, state, project, home }) {
  const { artifacts, capped, consumed, budget } = state;
  for (const site of sites) {
    if (site.vendor !== 'claude-code' || site.scope !== 'user') continue;
    for (const { manifest, marketplace } of installedPluginManifests(site.dir, home)) {
      if (consumed.has(manifest)) continue;
      if (artifacts.length >= MAX_ARTIFACTS) { capped.push({ reason: 'artifact-cap', path: manifest }); return; }
      const relativePath = relativeToSite(site, manifest);
      const read = readArtifactContent('plugin', manifest);
      if (!read) continue;
      if (read.oversize) { capped.push({ reason: 'manifest-too-large', path: relativePath }); continue; }
      if (read.bytes > budget.bytes) { capped.push({ reason: 'byte-budget', path: relativePath }); continue; }
      budget.bytes -= Buffer.byteLength(read.content);
      const artifact = buildArtifact({
        kind: 'plugin', content: read.content, read, relativePath, site, project, marketplace, activation: 'active', absolutePath: manifest,
      });
      consumed.add(manifest);
      artifacts.push(artifact);
      state.plugins.push({ artifact, absolutePath: manifest, site });
    }
  }
}

const IMPORT_READABLE_RE = /\.(?:md|mdx|markdown|mdc|rst|txt)$/i;
const IMPORT_SECRET_RE = /(?:^|[\\/])(?:\.env|\.ssh|\.aws|\.gnupg|\.netrc|\.npmrc)|id_(?:rsa|dsa|ecdsa|ed25519)|secret|credential|password|\.pem$|\.key$/i;
const MAX_IMPORT_DEPTH = 5;

function resolveImport(ref, fromFile, home) {
  if (ref.startsWith('~/')) return path.join(userDirs(home).HOME, ref.slice(2));
  if (path.isAbsolute(ref)) return ref;
  return path.resolve(path.dirname(fromFile), ref);
}

function bundleRuleImports(state, home) {
  const { capped, budget } = state;
  for (const { artifact, absolutePath } of state.rules) {
    const seen = new Set([absolutePath]);
    const queue = [{ file: absolutePath, text: artifact.content, depth: 0 }];
    while (queue.length) {
      const { file, text, depth } = queue.shift();
      if (depth >= MAX_IMPORT_DEPTH) continue;
      for (const ref of extractInstructionImports(text)) {
        if (!IMPORT_READABLE_RE.test(ref) || IMPORT_SECRET_RE.test(ref)) continue;
        const target = resolveImport(ref, file, home);
        if (seen.has(target)) continue;
        seen.add(target);
        if (artifact.files.length >= MAX_BUNDLED) {
          capped.push({ reason: 'bundle-cap', path: artifact.path });
          queue.length = 0;
          break;
        }
        const read = readText(target);
        if (!read) continue;
        if (read.bytes > budget.bytes) {
          capped.push({ reason: 'byte-budget', path: ref });
          continue;
        }
        budget.bytes -= Buffer.byteLength(read.text);
        artifact.files.push({ path: ref.replace(/^[~.]*\//, ''), content: read.text, binary: false });
        queue.push({ file: target, text: read.text, depth: depth + 1 });
      }
    }
    if (artifact.files.length) artifact.metadata.importCount = artifact.files.length;
  }
}

function bundleSkillFiles({ skills, walked, state }) {
  const { capped, consumed, budget } = state;

  for (const { artifact, dir, site } of skills) {
    const prefix = dir.endsWith(path.sep) ? dir : dir + path.sep;
    const siteFiles = walked.find((entry) => entry.site === site)?.files ?? [];

    for (const absolutePath of siteFiles.filter((file) => file.startsWith(prefix))) {
      if (consumed.has(absolutePath)) continue;
      if (artifact.files.length >= MAX_BUNDLED) {
        capped.push({ reason: 'bundle-cap', path: artifact.path });
        break;
      }
      const relativePath = relativeToSite(site, absolutePath);
      const read = TEXT_EXTS.has(extOf(absolutePath)) ? readText(absolutePath) : null;
      if (!read) {
        artifact.files.push({ path: relativePath, content: null, binary: true });
        consumed.add(absolutePath);
        continue;
      }
      if (read.bytes > budget.bytes) {
        capped.push({ reason: 'byte-budget', path: relativePath });
        continue;
      }
      budget.bytes -= Buffer.byteLength(read.text);
      artifact.files.push({ path: relativePath, content: read.text, binary: false });
      consumed.add(absolutePath);
    }
    artifact.metadata.bundledCount = artifact.files.length;
  }
}

function walkSites(sites, budget) {
  const walked = [];
  const seenRoot = new Set();
  for (const site of sites) {
    let realRoot;
    try {
      realRoot = fs.realpathSync(site.dir);
    } catch {
      continue;
    }
    if (seenRoot.has(realRoot)) continue;
    seenRoot.add(realRoot);
    walked.push({ site, files: walkRoot(site.dir, budget) });
  }
  return walked;
}

function availableCatalogue(availableBy) {
  return [...availableBy.entries()]
    .map(([marketplace, count]) => ({ marketplace, count, installed: false }))
    .sort((a, b) => b.count - a.count);
}

export function discoverAgentArtifacts(cwd = process.cwd(), roots = null, opts = {}) {
  const { home } = opts;
  const sites = roots || (userDirs(home).own ? artifactRoots(cwd) : artifactRoots(cwd, home).filter((s) => s.scope === 'user' && !s.managed));
  const project = path.basename(path.resolve(cwd)) || null;
  const state = {
    budget: { dirs: MAX_DIRS, bytes: MAX_TOTAL_BYTES },
    artifacts: [],
    capped: [],
    consumed: new Set(),
    skills: [],
    rules: [],
    plugins: [],
    extensions: [],
    availableBy: new Map(),
  };

  const walked = walkSites(sites, state.budget);
  for (const { site, files } of walked) collectFromSite({ site, files, state, project });
  collectInstalledPlugins({ sites, state, project, home });
  bundleSkillFiles({ skills: state.skills, walked, state });
  bundleRuleImports(state, home);
  for (const { artifact, absolutePath, site } of state.hooks ?? []) {
    bundleHookScripts(artifact, absolutePath, {
      projectDir: site.scope === 'project' ? path.dirname(site.dir) : cwd,
      relPath: (abs) => {
        const rel = relativeToSite(site, abs);
        return rel.startsWith('..') || path.isAbsolute(rel) ? null : rel;
      },
      budget: state.budget,
      capped: state.capped,
      home,
    });
  }
  for (const { artifact, absolutePath, site } of state.extensions) {
    bundleExtensionSource(artifact, absolutePath, (abs) => relativeToSite(site, abs), state.budget, state.capped);
  }
  for (const { artifact, absolutePath, site } of state.plugins) {
    bundlePluginComponents(artifact, absolutePath, (abs) => relativeToSite(site, abs), state.budget, state.capped);
  }

  if (state.budget.dirs <= 0) state.capped.push({ reason: 'walk-budget', path: null });

  return {
    artifacts: state.artifacts.map(clampArtifact),
    capped: state.capped,
    available: availableCatalogue(state.availableBy),
  };
}

export function rollupArtifacts(artifacts) {
  const counts = {};
  for (const artifact of artifacts) counts[artifact.kind] = (counts[artifact.kind] ?? 0) + 1;
  return counts;
}
