import fs from 'node:fs';
import path from 'node:path';
import { clampArtifact } from '../../core/wire-limits.mjs';
import { classify, declaredName } from './classify.mjs';
import { readText } from './file-read.mjs';
import { canonicalHooks } from './hooks.mjs';
import { MAX_ARTIFACTS, MAX_BUNDLED, MAX_DIRS, MAX_TOTAL_BYTES, TEXT_EXTS, extOf } from './limits.mjs';
import { CATALOGUE_DIR_RE, PLUGIN_PATH_RE, installedMarketplaces } from './marketplaces.mjs';
import { artifactRoots } from './roots.mjs';
import { walkRoot } from './walk.mjs';

const MAX_NAME_LENGTH = 200;

function relativeToSite(site, absolutePath) {
  return path.relative(path.dirname(site.dir), absolutePath).replace(/\\/g, '/');
}

function artifactName(kind, content, absolutePath) {
  const declared = declaredName(content);
  if (declared) return declared;
  if (kind === 'skill') return path.basename(path.dirname(absolutePath));
  if (kind === 'hook') return `${path.basename(absolutePath)} · hooks`;
  return path.basename(absolutePath).replace(/\.(md|toml)$/i, '');
}

function resolveActivation(marketplace, installed) {
  if (!marketplace) return 'active';
  if (installed === null) return 'unknown';
  return installed.has(marketplace) ? 'active' : 'not-installed';
}

function readArtifactContent(kind, absolutePath) {
  const read = readText(absolutePath);
  if (!read) return null;
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
    const activation = resolveActivation(marketplace, installed);
    if (activation === 'not-installed') {
      availableBy.set(marketplace, (availableBy.get(marketplace) ?? 0) + 1);
      continue;
    }

    const read = readArtifactContent(kind, absolutePath);
    if (!read) continue;
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

export function discoverAgentArtifacts(cwd = process.cwd(), roots = null) {
  const sites = roots || artifactRoots(cwd);
  const project = path.basename(path.resolve(cwd)) || null;
  const state = {
    budget: { dirs: MAX_DIRS, bytes: MAX_TOTAL_BYTES },
    artifacts: [],
    capped: [],
    consumed: new Set(),
    skills: [],
    availableBy: new Map(),
  };

  const walked = walkSites(sites, state.budget);
  for (const { site, files } of walked) collectFromSite({ site, files, state, project });
  bundleSkillFiles({ skills: state.skills, walked, state });

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
