import path from 'node:path';
import { PY_VECTOR, VECTOR_ENV, vectorLibInfo } from './ai-dependencies.mjs';
import { readJson, readText } from './fs-read.mjs';
import { walkWorkspace } from './workspace.mjs';

const MAX_ENV_BYTES = 100_000;
const MAX_INDEX_FILES = 20;
const MAX_MANIFESTS = 10;
const MAX_HOSTS = 5;
const PLACEHOLDER_VALUE = /(your|xxx|placeholder|changeme|<|example)/i;
const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/;
const URL_HOST = /^[a-z]+:\/\/([^/:?#\s]+)/i;
const BARE_HOST = /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/i;

function unquote(value) {
  return String(value || '').trim().replace(/^["']|["']$/g, '');
}

function endpointHost(value) {
  const raw = unquote(value);
  if (!raw) return null;
  const url = raw.match(URL_HOST);
  if (url) return url[1];
  return BARE_HOST.test(raw) ? raw.split(':')[0] : null;
}

function engineFromIndexFiles(names) {
  if (names.includes('chroma.sqlite3') || names.some((name) => name.startsWith('chroma-'))) return 'chroma';
  if (names.includes('index.faiss')) return 'faiss';
  if (names.some((name) => name.endsWith('.lance'))) return 'lancedb';
  if (names.some((name) => name.endsWith('.usearch'))) return 'usearch';
  if (names.includes('docstore.json') || names.includes('default__vector_store.json')) return 'llamaindex';
  return null;
}

function localIndexAssets(vectorFiles) {
  const byDirectory = new Map();
  for (const { file } of vectorFiles) {
    const directory = path.dirname(file);
    if (!byDirectory.has(directory)) byDirectory.set(directory, []);
    byDirectory.get(directory).push(path.basename(file).toLowerCase());
  }

  const assets = [];
  for (const [directory, names] of byDirectory) {
    const engine = engineFromIndexFiles(names);
    if (!engine) continue;
    assets.push({
      type: 'VECTOR_STORE',
      name: `${engine} index (${path.basename(directory)})`,
      identifier: `vector:local:${directory}`,
      vendor: engine,
      metadata: {
        surface: 'local-index',
        engine,
        hosted: false,
        pickleBacked: engine === 'faiss' && names.includes('index.pkl'),
        dir: directory,
        files: names.slice(0, MAX_INDEX_FILES),
      },
    });
  }
  return assets;
}

function npmVectorLibraries(file) {
  const json = readJson(file);
  if (!json) return [];
  const dependencies = {
    ...(json.dependencies || {}),
    ...(json.devDependencies || {}),
    ...(json.peerDependencies || {}),
    ...(json.optionalDependencies || {}),
  };
  return Object.keys(dependencies).map(vectorLibInfo).filter(Boolean);
}

function pythonVectorLibraries(file) {
  const text = readText(file, MAX_ENV_BYTES);
  if (text == null) return [];
  return PY_VECTOR
    .filter((pkg) => {
      const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(^|[^a-z0-9_.-])${escaped}([^a-z0-9_.-]|$)`, 'im').test(text);
    })
    .map(vectorLibInfo)
    .filter(Boolean);
}

function clientLibraryAssets(manifestFiles) {
  const byEngine = new Map();
  for (const { file } of manifestFiles) {
    const libraries = path.basename(file) === 'package.json'
      ? npmVectorLibraries(file)
      : pythonVectorLibraries(file);
    for (const { engine, hosted } of libraries) {
      if (!byEngine.has(engine)) byEngine.set(engine, { hosted, manifests: new Set() });
      byEngine.get(engine).manifests.add(file);
    }
  }

  return [...byEngine].map(([engine, { hosted, manifests }]) => {
    const list = [...manifests];
    return {
      type: 'VECTOR_STORE',
      name: `${engine} client`,
      identifier: `vector:client:${engine}`,
      vendor: engine,
      metadata: {
        surface: 'client-lib',
        engine,
        hosted,
        usedInProjects: list.length,
        manifests: list.slice(0, MAX_MANIFESTS),
      },
    };
  });
}

function collectCloudSettings(envFiles) {
  const byEngine = new Map();
  for (const { file } of envFiles) {
    const text = readText(file, MAX_ENV_BYTES);
    if (text == null) continue;

    for (const line of text.split(/\r?\n/)) {
      const assignment = line.match(ENV_ASSIGNMENT);
      if (!assignment) continue;
      const setting = VECTOR_ENV[assignment[1]];
      if (!setting) continue;

      const value = unquote(assignment[2]);
      if (!value || PLACEHOLDER_VALUE.test(value)) continue;

      if (!byEngine.has(setting.engine)) {
        byEngine.set(setting.engine, { hosts: new Set(), hasKey: false, hasEndpoint: false, files: new Set() });
      }
      const entry = byEngine.get(setting.engine);
      entry.files.add(file);
      if (setting.kind === 'key') {
        entry.hasKey = true;
      } else {
        entry.hasEndpoint = true;
        const host = endpointHost(value);
        if (host) entry.hosts.add(host);
      }
    }
  }
  return byEngine;
}

function cloudEndpointAssets(envFiles) {
  return [...collectCloudSettings(envFiles)].map(([engine, entry]) => ({
    type: 'VECTOR_STORE',
    name: `${engine} (cloud)`,
    identifier: `vector:cloud:${engine}`,
    vendor: engine,
    metadata: {
      surface: 'cloud-endpoint',
      engine,
      hosted: true,
      hasApiKey: entry.hasKey,
      hosts: [...entry.hosts].slice(0, MAX_HOSTS),
      files: [...entry.files].slice(0, MAX_MANIFESTS),
    },
  }));
}

export function discoverVectorStores(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  return [
    ...localIndexAssets(walk.vector),
    ...clientLibraryAssets(walk.manifests),
    ...cloudEndpointAssets(walk.env),
  ];
}
