import path from 'node:path';
import { AI_USAGE_CATEGORY_LABEL, isAiUsageScannable, rollupAiUsage, scanAiUsage } from '../../detect/ai-usage.mjs';
import { readJson, readText } from './fs-read.mjs';
import { walkWorkspace } from './workspace.mjs';

const NPM_AI = new Set([
  'openai', 'ai', 'langchain', 'llamaindex', 'ollama', 'replicate', 'cohere-ai',
  'groq-sdk', 'together-ai', 'openrouter', 'mistralai', 'chromadb',
]);

const NPM_AI_PREFIX = ['@anthropic-ai/', '@google/generative-ai', '@google/genai', '@ai-sdk/', '@langchain/', '@llamaindex/', '@mistralai/', '@huggingface/', '@pinecone-database/', '@qdrant/'];

const PY_AI = [
  'openai', 'anthropic', 'google-generativeai', 'google-genai', 'langchain',
  'langchain-openai', 'langchain-anthropic', 'langchain-community', 'llama-index',
  'llama_index', 'transformers', 'sentence-transformers', 'mistralai', 'cohere',
  'groq', 'huggingface-hub', 'huggingface_hub', 'ollama', 'litellm', 'guidance',
  'vllm', 'crewai', 'autogen', 'pyautogen', 'haystack-ai', 'instructor', 'dspy',
  'dspy-ai', 'semantic-kernel', 'replicate', 'together', 'chromadb', 'qdrant-client',
  'pinecone-client', 'pinecone', 'faiss-cpu', 'faiss-gpu', 'tiktoken',
];

const VECTOR_LIBS = {
  chromadb: { engine: 'chroma', hosted: false },
  'faiss-cpu': { engine: 'faiss', hosted: false },
  'faiss-gpu': { engine: 'faiss', hosted: false },
  lancedb: { engine: 'lancedb', hosted: false },
  pgvector: { engine: 'pgvector', hosted: false },
  'qdrant-client': { engine: 'qdrant', hosted: true },
  'pinecone-client': { engine: 'pinecone', hosted: true },
  pinecone: { engine: 'pinecone', hosted: true },
  'weaviate-client': { engine: 'weaviate', hosted: true },
  'weaviate-ts-client': { engine: 'weaviate', hosted: true },
  pymilvus: { engine: 'milvus', hosted: true },
};

export function vectorLibInfo(pkg) {
  if (VECTOR_LIBS[pkg]) return VECTOR_LIBS[pkg];
  if (pkg.startsWith('@pinecone-database/')) return { engine: 'pinecone', hosted: true };
  if (pkg.startsWith('@qdrant/')) return { engine: 'qdrant', hosted: true };
  return null;
}

const isVectorLib = (pkg) => !!vectorLibInfo(pkg);

export const PY_VECTOR = [
  'chromadb', 'faiss-cpu', 'faiss-gpu', 'lancedb', 'pgvector', 'qdrant-client',
  'pinecone-client', 'pinecone', 'weaviate-client', 'pymilvus',
];

export const VECTOR_ENV = {
  PINECONE_API_KEY: { engine: 'pinecone', kind: 'key' },
  PINECONE_ENVIRONMENT: { engine: 'pinecone', kind: 'endpoint' },
  PINECONE_HOST: { engine: 'pinecone', kind: 'endpoint' },
  PINECONE_INDEX: { engine: 'pinecone', kind: 'endpoint' },
  PINECONE_INDEX_NAME: { engine: 'pinecone', kind: 'endpoint' },
  WEAVIATE_URL: { engine: 'weaviate', kind: 'endpoint' },
  WEAVIATE_HOST: { engine: 'weaviate', kind: 'endpoint' },
  WEAVIATE_API_KEY: { engine: 'weaviate', kind: 'key' },
  QDRANT_URL: { engine: 'qdrant', kind: 'endpoint' },
  QDRANT_HOST: { engine: 'qdrant', kind: 'endpoint' },
  QDRANT_API_KEY: { engine: 'qdrant', kind: 'key' },
  MILVUS_URI: { engine: 'milvus', kind: 'endpoint' },
  MILVUS_HOST: { engine: 'milvus', kind: 'endpoint' },
  ZILLIZ_CLOUD_URI: { engine: 'milvus', kind: 'endpoint' },
  CHROMA_SERVER_HOST: { engine: 'chroma', kind: 'endpoint' },
  CHROMA_HOST: { engine: 'chroma', kind: 'endpoint' },
};

export const MAX_SPECS = 8;

const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const uncommented = (text) =>
  text
    .split(/\r?\n/)
    .map((l) => l.replace(/(^|[ \t])#[^\n]*$/, '$1'))
    .join('\n');

/**
 * ⚠ The SPEC TRAVELS RAW and the backend decides what counts as PINNED.
 * `parseExactVersion` lives once, on the server, so the endpoint plane and the
 * repo plane cannot disagree about which versions are precise enough to match
 * against an advisory.
 */
export function pySpecFor(text, pkg) {
  const body = uncommented(text);
  const name = escRe(pkg).replace(/[-_]/g, '[-_]');
  const req = body.match(new RegExp(`(^|[^a-z0-9_.-])${name}\\s*(?:\\[[^\\]]*\\])?\\s*(===?|~=|>=|<=|!=|>|<)\\s*([\\w.*+!-]+)`, 'im'));
  if (req) return `${req[2]}${req[3]}`;

  const toml = body.match(new RegExp(`(^|\\n)\\s*["\']?${name}["\']?\\s*=\\s*(?:["\']([^"\']+)["\']|\\{[^}\\n]*version\\s*=\\s*["\']([^"\']+)["\'])`, 'i'));
  const val = toml?.[2] ?? toml?.[3];
  return val && val !== '*' ? val : null;
}

function npmAiDeps(pkg) {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}), ...(pkg.optionalDependencies || {}) };
  const hits = [];
  for (const [name, spec] of Object.entries(deps)) {
    if (NPM_AI.has(name) || NPM_AI_PREFIX.some((p) => name.startsWith(p))) {
      hits.push({ name, spec: typeof spec === 'string' ? spec : null });
    }
  }
  return hits;
}

function pyAiDeps(text) {
  const hits = [];
  for (const pkg of PY_AI) {
    const re = new RegExp(`(^|[^a-z0-9_.-])${escRe(pkg)}([^a-z0-9_.-]|$)`, 'im');
    if (re.test(text)) hits.push({ name: pkg, spec: pySpecFor(text, pkg) });
  }
  return hits;
}

export function discoverAiDependencies(roots = [process.cwd()], files = null) {
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

      for (const hit of npmAiDeps(json)) if (!isVectorLib(hit.name)) add('npm', hit.name, file, hit.spec);
    } else {
      const text = readText(file, 100_000);
      if (text == null) continue;
      for (const hit of pyAiDeps(text)) if (!isVectorLib(hit.name)) add('pip', hit.name, file, hit.spec);
    }
  }
  const assets = [];
  for (const { pkg, eco, manifests, specs } of byPkg.values()) {
    const list = [...manifests];
    assets.push({
      type: 'AI_TOOL',
      name: `${pkg} (${eco})`,
      identifier: `dep:${eco}:${pkg}`,
      vendor: 'ai-sdk',
      metadata: {
        category: 'dependency',
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

export function discoverAiUsageInCode(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const usages = [];
  for (const { file } of walk.source || []) {
    if (!isAiUsageScannable(path.basename(file))) continue;
    const text = readText(file, 300_000);
    if (text == null) continue;
    for (const u of scanAiUsage(text, file)) usages.push(u);
  }
  const assets = [];
  for (const row of rollupAiUsage(usages)) {
    const site = row.firstSite;
    assets.push({
      type: 'AI_TOOL',
      name: `${row.label} (in code)`,
      identifier: `ai-usage:${row.provider}`,
      vendor: 'ai-sdk',
      metadata: {
        category: 'code-usage',
        provider: row.provider,
        aiCategory: row.category,
        aiCategoryLabel: AI_USAGE_CATEGORY_LABEL[row.category],
        fileCount: row.files.length,
        files: row.files.slice(0, 10),
        models: row.models.slice(0, 10),
        callSites: row.sightings,
        hasCallSite: row.hasCallSite,
        firstSite: site ? { file: site.file, line: site.line } : null,
      },
    });
  }
  return assets;
}
