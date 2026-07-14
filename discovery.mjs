/**
 * Cross-platform discovery of AI tooling on a developer machine. Pure Node
 * built-ins. Each discoverer is best-effort and isolated — a missing or
 * malformed file, a blocked process listing, or a slow walk never aborts the
 * scan. Returns a flat list of assets in the shape the Shomra backend's
 * /agent/report endpoint expects (types: MCP_SERVER | AI_TOOL | AI_RULES |
 * MODEL_KEY | AI_AGENT).
 *
 * Detection layers:
 *   1. Fixed global paths for known AI clients / coding agents / runtimes.
 *   2. A bounded walk of the developer's real workspace — cwd plus the common
 *      project-parent dirs under $HOME (Desktop, repos, source, projects, …) —
 *      that finds project-local MCP configs, AI rules files, AI-SDK
 *      dependencies in manifests, and API keys sitting in .env files.
 *   3. Local model runtimes (Ollama / LM Studio / Jan / GPT4All / HF cache)
 *      by directory AND by running process.
 *   4. Model-provider API keys in the environment.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';

const HOME = os.homedir();
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');
const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');
const PLAT = process.platform;

/** VS Code (and forks) per-user dir, where extensions keep global state. */
function vscodeUserDir(variant = 'Code') {
  if (PLAT === 'win32') return path.join(APPDATA, variant, 'User');
  if (PLAT === 'darwin') return path.join(HOME, 'Library', 'Application Support', variant, 'User');
  return path.join(HOME, '.config', variant, 'User');
}

function readJson(file) {
  try {
    return JSON.parse(stripJsonComments(fs.readFileSync(file, 'utf8')));
  } catch {
    return null;
  }
}
/** VS Code / Cursor settings are JSONC — tolerate // and /* *​/ comments. */
function stripJsonComments(s) {
  return String(s)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}
function readText(file, cap = 200_000) {
  try {
    const b = fs.readFileSync(file, 'utf8');
    return b.length > cap ? b.slice(0, cap) : b;
  } catch {
    return null;
  }
}
function exists(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}
function firstExisting(paths) {
  return paths.find((p) => p && exists(p)) || null;
}

// ── workspace root discovery ─────────────────────────────────────
// The old scanner only looked at cwd. Real AI assets live scattered across a
// developer's project folders, so we discover those folders instead of hoping
// the agent was launched from inside one.

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out', '.next', '.nuxt',
  '.cache', '.venv', 'venv', 'env', '__pycache__', '.tox', 'target', 'vendor',
  'bin', 'obj', '.gradle', '.idea', 'coverage', '.pytest_cache', '.mypy_cache',
  'Pods', '.terraform', '.expo', 'tmp', 'temp', '.turbo', '.parcel-cache',
  '.svelte-kit', 'bower_components', '.pnpm-store', 'site-packages', '.yarn',
]);

/** Common parent dirs under $HOME where people keep code checkouts. */
function workspaceParents() {
  const names = [
    'Desktop', 'Documents', 'source', 'source/repos', 'repos', 'Repos',
    'projects', 'Projects', 'dev', 'Dev', 'Developer', 'git', 'Git', 'code',
    'Code', 'workspace', 'Workspace', 'work', 'src', 'go/src', 'ghq',
    'OneDrive/Desktop', 'OneDrive/Documents',
  ];
  return names.map((n) => path.join(HOME, n)).filter(exists);
}

/**
 * Expand the caller's roots into the set of project directories to scan.
 * When autoExpand is on, add the immediate subdirectories of the common
 * workspace parents (depth 1) as candidate roots — capped so a machine with
 * hundreds of repos stays fast.
 */
function resolveRoots(roots, autoExpand) {
  const out = new Set();
  for (const r of roots || []) if (r) out.add(path.resolve(r));
  if (autoExpand) {
    out.add(HOME); // catch dotfile configs / .env at the home root (shallow — see maxDepth)
    for (const parent of workspaceParents()) {
      out.add(parent);
      try {
        for (const e of fs.readdirSync(parent, { withFileTypes: true })) {
          if (e.isDirectory() && !e.name.startsWith('.') && !IGNORE_DIRS.has(e.name)) {
            out.add(path.join(parent, e.name));
          }
        }
      } catch {
        /* unreadable parent */
      }
    }
  }
  return [...out].slice(0, 500);
}

const RULE_NAMES = new Set([
  '.cursorrules', '.windsurfrules', '.clinerules', '.roorules', '.aider.conf.yml',
  '.aider.conf.yaml', 'AGENTS.md', 'CLAUDE.md', 'GEMINI.md', 'copilot-instructions.md',
]);
const MANIFEST_NAMES = new Set([
  'package.json', 'requirements.txt', 'requirements-dev.txt', 'pyproject.toml',
  'Pipfile', 'environment.yml', 'environment.yaml',
]);
const isEnvFile = (base) =>
  /^\.env(\..+)?$/.test(base) && !/(example|sample|template|dist)/i.test(base);

// Persisted on-disk vector-store / embedding-index artifacts. `index.pkl` is
// LangChain FAISS.save_local's pickle sidecar — a code-execution surface on
// load — so we track it, but only mint a store when its `index.faiss` sibling
// is present (see discoverVectorStores) to avoid flagging unrelated pickles.
const VECTOR_INDEX_BASENAMES = new Set([
  'chroma.sqlite3', // Chroma persistent client (sqlite backend)
  'index.faiss', 'index.pkl', // LangChain FAISS.save_local pair
  'docstore.json', 'default__vector_store.json', // LlamaIndex persist dir
  'chroma-embeddings.parquet', 'chroma-collections.parquet', // legacy Chroma (duckdb+parquet)
]);
const VECTOR_INDEX_EXTS = new Set(['faiss', 'lance', 'usearch']);
const isVectorIndex = (base) =>
  VECTOR_INDEX_BASENAMES.has(base.toLowerCase()) ||
  VECTOR_INDEX_EXTS.has((base.slice(base.lastIndexOf('.') + 1) || '').toLowerCase());

/**
 * One bounded breadth-first walk per root that collects every file of interest.
 * Returns { mcp:[], rules:[], manifests:[], env:[], vector:[] } absolute-path lists.
 * Depth- and count-limited so it never turns into a full-disk crawl.
 */
function walkWorkspace(roots) {
  const found = { mcp: [], rules: [], manifests: [], env: [], vector: [] };
  const seenDir = new Set();
  let budget = 40_000; // total directories visited across all roots
  const maxDepth = 6;

  const consider = (base, full, parentBase) => {
    if (base === '.mcp.json' || base === 'mcp.json') found.mcp.push({ file: full, parentBase });
    else if (base === 'settings.json' && (parentBase === '.gemini' || parentBase === '.zed'))
      found.mcp.push({ file: full, parentBase });
    else if (RULE_NAMES.has(base)) {
      if (base === 'copilot-instructions.md' && parentBase !== '.github') return;
      found.rules.push({ file: full, parentBase });
    } else if (MANIFEST_NAMES.has(base)) found.manifests.push({ file: full, parentBase });
    else if (isEnvFile(base)) found.env.push({ file: full, parentBase });
    else if (isVectorIndex(base)) found.vector.push({ file: full, parentBase });
  };

  for (const root of roots) {
    const queue = [{ dir: root, depth: 0 }];
    while (queue.length && budget > 0) {
      const { dir, depth } = queue.shift();
      let real;
      try {
        real = fs.realpathSync(dir);
      } catch {
        continue;
      }
      if (seenDir.has(real)) continue; // dedup shared roots / symlink loops
      seenDir.add(real);
      budget--;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        const full = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth < maxDepth && !IGNORE_DIRS.has(e.name)) queue.push({ dir: full, depth: depth + 1 });
        } else if (e.isFile()) {
          consider(e.name, full, path.basename(dir));
        }
      }
    }
  }
  return found;
}

function vendorFromPath(file) {
  if (/[\\/]\.cursor[\\/]/.test(file)) return 'cursor';
  if (/[\\/]\.vscode[\\/]/.test(file)) return 'vscode';
  if (/[\\/]\.gemini[\\/]/.test(file)) return 'gemini';
  if (/[\\/]\.zed[\\/]/.test(file)) return 'zed';
  return 'project';
}

// ── MCP servers ──────────────────────────────────────────────────

/** Global MCP config files across the major AI clients, per-platform. */
function globalMcpCandidates() {
  const c = [];
  if (PLAT === 'win32') c.push({ vendor: 'claude', file: path.join(APPDATA, 'Claude', 'claude_desktop_config.json') });
  else if (PLAT === 'darwin') c.push({ vendor: 'claude', file: path.join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') });
  else c.push({ vendor: 'claude', file: path.join(HOME, '.config', 'Claude', 'claude_desktop_config.json') });
  c.push({ vendor: 'cursor', file: path.join(HOME, '.cursor', 'mcp.json') });
  c.push({ vendor: 'windsurf', file: path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json') });
  c.push({ vendor: 'continue', file: path.join(HOME, '.continue', 'config.json') });
  c.push({ vendor: 'claude-code', file: path.join(HOME, '.claude.json') });
  c.push({ vendor: 'gemini', file: path.join(HOME, '.gemini', 'settings.json') });
  c.push({ vendor: 'cline', file: path.join(vscodeUserDir(), 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json') });
  c.push({ vendor: 'roo', file: path.join(vscodeUserDir(), 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json') });
  // VS Code / Cursor native MCP + Zed context servers.
  c.push({ vendor: 'vscode', file: path.join(vscodeUserDir(), 'mcp.json') });
  c.push({ vendor: 'vscode', file: path.join(vscodeUserDir(), 'settings.json') });
  c.push({ vendor: 'cursor', file: path.join(vscodeUserDir('Cursor'), 'settings.json') });
  c.push({ vendor: 'zed', file: PLAT === 'darwin' ? path.join(HOME, 'Library', 'Application Support', 'Zed', 'settings.json') : path.join(HOME, '.config', 'zed', 'settings.json') });
  return c;
}

/** Pull the server map out of the many shapes these configs use. */
function extractServers(json) {
  if (!json || typeof json !== 'object') return {};
  return (
    json.mcpServers ||
    json.servers ||
    json['mcp.servers'] ||
    json.mcp?.servers ||
    json.context_servers || // Zed
    {}
  );
}

export function discoverMcpServers(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const candidates = [
    ...globalMcpCandidates(),
    ...walk.mcp.map(({ file }) => ({ vendor: vendorFromPath(file), file })),
  ];
  const assets = [];
  const seen = new Set();
  for (const { vendor, file } of candidates) {
    const json = readJson(file);
    if (!json) continue;
    const servers = extractServers(json);
    for (const [name, cfg] of Object.entries(servers)) {
      if (!cfg || typeof cfg !== 'object') continue;
      const command = [cfg.command, ...(Array.isArray(cfg.args) ? cfg.args : [])].filter(Boolean).join(' ');
      const identifier = cfg.url || cfg.serverUrl || command || name;
      const key = `${name}:${identifier}`;
      if (seen.has(key)) continue;
      seen.add(key);
      assets.push({
        type: 'MCP_SERVER',
        name,
        identifier,
        vendor,
        metadata: { command, url: cfg.url || cfg.serverUrl || null, configFile: file, env: redactEnv(cfg.env) },
        // Content the backend statically analyzes (command + env values + url).
        content: JSON.stringify({ command, url: cfg.url || cfg.serverUrl, env: cfg.env || {} }),
      });
    }
  }
  return assets;
}

// ── AI rules / instruction files ─────────────────────────────────

/** Known AI rules / instruction files an agent treats as trusted input. */
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

// ── AI-SDK dependencies in code ──────────────────────────────────
// A repo that imports openai / anthropic / langchain IS an AI asset even with
// no MCP config. We surface each AI library once per machine (with the sample
// manifests that pull it in) so shadow AI usage in code becomes visible.

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

// Vector-store / embedding-index client libraries. Each gets its own
// VECTOR_STORE asset (discoverVectorStores) instead of a generic AI_TOOL, so
// they're excluded from the AI-SDK dependency roll-up above. `hosted` marks a
// managed/cloud store — embedded data leaves the environment to a third party.
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
/** Resolve a package name (incl. scoped npm prefixes) to its vector engine. */
function vectorLibInfo(pkg) {
  if (VECTOR_LIBS[pkg]) return VECTOR_LIBS[pkg];
  if (pkg.startsWith('@pinecone-database/')) return { engine: 'pinecone', hosted: true };
  if (pkg.startsWith('@qdrant/')) return { engine: 'qdrant', hosted: true };
  return null;
}
const isVectorLib = (pkg) => !!vectorLibInfo(pkg);
// Python vector-store packages, matched by import/require name in text manifests.
const PY_VECTOR = [
  'chromadb', 'faiss-cpu', 'faiss-gpu', 'lancedb', 'pgvector', 'qdrant-client',
  'pinecone-client', 'pinecone', 'weaviate-client', 'pymilvus',
];
// .env variable names that configure a managed/cloud vector store. `kind`
// distinguishes an endpoint (egress target) from a credential.
const VECTOR_ENV = {
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

function npmAiDeps(pkg) {
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}), ...(pkg.optionalDependencies || {}) };
  const hits = [];
  for (const name of Object.keys(deps)) {
    if (NPM_AI.has(name) || NPM_AI_PREFIX.some((p) => name.startsWith(p))) hits.push(name);
  }
  return hits;
}
function pyAiDeps(text) {
  const hits = [];
  for (const pkg of PY_AI) {
    const re = new RegExp(`(^|[^a-z0-9_.-])${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_.-]|$)`, 'im');
    if (re.test(text)) hits.push(pkg);
  }
  return hits;
}

export function discoverAiDependencies(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const byPkg = new Map(); // `${eco}:${pkg}` -> { pkg, eco, manifests:Set }
  const add = (eco, pkg, manifest) => {
    const key = `${eco}:${pkg}`;
    if (!byPkg.has(key)) byPkg.set(key, { pkg, eco, manifests: new Set() });
    byPkg.get(key).manifests.add(manifest);
  };
  for (const { file } of walk.manifests) {
    const base = path.basename(file);
    if (base === 'package.json') {
      const json = readJson(file);
      if (!json) continue;
      // Vector-store libs are surfaced as VECTOR_STORE assets, not AI tools.
      for (const pkg of npmAiDeps(json)) if (!isVectorLib(pkg)) add('npm', pkg, file);
    } else {
      const text = readText(file, 100_000);
      if (text == null) continue;
      for (const pkg of pyAiDeps(text)) if (!isVectorLib(pkg)) add('pip', pkg, file);
    }
  }
  const assets = [];
  for (const { pkg, eco, manifests } of byPkg.values()) {
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
        usedInProjects: list.length,
        manifests: list.slice(0, 10),
      },
    });
  }
  return assets;
}

// ── API keys sitting in .env files ───────────────────────────────

const KEY_NAME_VENDOR = {
  OPENAI_API_KEY: 'openai', AZURE_OPENAI_API_KEY: 'azure-openai', AZURE_OPENAI_KEY: 'azure-openai',
  ANTHROPIC_API_KEY: 'anthropic', GOOGLE_API_KEY: 'google', GOOGLE_GENAI_API_KEY: 'google',
  GEMINI_API_KEY: 'google', MISTRAL_API_KEY: 'mistral', GROQ_API_KEY: 'groq', COHERE_API_KEY: 'cohere',
  HUGGINGFACE_API_KEY: 'huggingface', HUGGINGFACEHUB_API_TOKEN: 'huggingface', HF_TOKEN: 'huggingface',
  OPENROUTER_API_KEY: 'openrouter', XAI_API_KEY: 'xai', DEEPSEEK_API_KEY: 'deepseek',
  TOGETHER_API_KEY: 'together', TOGETHERAI_API_KEY: 'together', PERPLEXITY_API_KEY: 'perplexity',
  REPLICATE_API_TOKEN: 'replicate', FIREWORKS_API_KEY: 'fireworks', DASHSCOPE_API_KEY: 'alibaba',
  AI21_API_KEY: 'ai21', ANYSCALE_API_KEY: 'anyscale', VOYAGE_API_KEY: 'voyage', NVIDIA_API_KEY: 'nvidia',
  CEREBRAS_API_KEY: 'cerebras', STABILITY_API_KEY: 'stability', ELEVENLABS_API_KEY: 'elevenlabs',
  WATSONX_APIKEY: 'ibm', LANGCHAIN_API_KEY: 'langsmith', LANGSMITH_API_KEY: 'langsmith',
  PINECONE_API_KEY: 'pinecone', WEAVIATE_API_KEY: 'weaviate',
};
// Value-shape fingerprints — catch a key even under a non-standard var name.
const KEY_VALUE_PATTERNS = [
  { re: /^sk-ant-[A-Za-z0-9_-]{20,}/, vendor: 'anthropic' },
  { re: /^sk-or-[A-Za-z0-9_-]{20,}/, vendor: 'openrouter' },
  { re: /^sk-proj-[A-Za-z0-9_-]{20,}/, vendor: 'openai' },
  { re: /^sk-[A-Za-z0-9]{32,}/, vendor: 'openai' },
  { re: /^AIza[0-9A-Za-z_-]{30,}/, vendor: 'google' },
  { re: /^gsk_[A-Za-z0-9]{20,}/, vendor: 'groq' },
  { re: /^hf_[A-Za-z0-9]{20,}/, vendor: 'huggingface' },
  { re: /^xai-[A-Za-z0-9]{20,}/, vendor: 'xai' },
  { re: /^r8_[A-Za-z0-9]{20,}/, vendor: 'replicate' },
  { re: /^pplx-[A-Za-z0-9]{20,}/, vendor: 'perplexity' },
  { re: /^fw_[A-Za-z0-9]{20,}/, vendor: 'fireworks' },
];

function classifyKey(name, value) {
  if (KEY_NAME_VENDOR[name]) return KEY_NAME_VENDOR[name];
  for (const { re, vendor } of KEY_VALUE_PATTERNS) if (re.test(value)) return vendor;
  // Fall back: a *_API_KEY / *_API_TOKEN whose name hints at a model provider.
  if (/(_API_KEY|_API_TOKEN|_APIKEY)$/.test(name) && /(LLM|AI|GPT|CLAUDE|MODEL|OPENAI|ANTHROPIC|GEMINI)/.test(name)) return 'unknown';
  return null;
}

export function discoverDotenvKeys(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const assets = [];
  const seen = new Set();
  for (const { file } of walk.env) {
    const text = readText(file, 100_000);
    if (text == null) continue;
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/);
      if (!m) continue;
      const name = m[1];
      let value = m[2].trim().replace(/^["']|["']$/g, '');
      if (!value || value.length < 8 || /^\$\{/.test(value) || /(your|xxx|placeholder|changeme|<|example)/i.test(value)) continue;
      const vendor = classifyKey(name, value);
      if (!vendor) continue;
      const key = `${name}:${file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      assets.push({
        type: 'MODEL_KEY',
        name,
        identifier: `dotenv:${file}:${name}`,
        vendor,
        metadata: { source: 'dotenv', file, fingerprint: `${value.slice(0, 3)}…${value.slice(-2)}` },
        // The raw value is intentionally NOT transmitted.
      });
    }
  }
  return assets;
}

// ── RAG vector stores / embedding indexes ────────────────────────
// A vector store is a first-class AI asset: it holds embedded (often sensitive)
// corpus data, is a retrieval-poisoning target, and — when persisted as a
// pickle-backed index (LangChain FAISS) — executes code on load. We surface
// three shapes: a persisted local index on disk, a client library in a project
// manifest, and a managed/cloud endpoint configured in a .env. No file is
// executed and no index contents are read — detection is by path + config only.

/** Redact a connection value to a bare host, never transmitting credentials. */
function endpointHost(value) {
  const v = String(value || '').trim().replace(/^["']|["']$/g, '');
  if (!v) return null;
  const m = v.match(/^[a-z]+:\/\/([^/:?#\s]+)/i);
  if (m) return m[1];
  // bare host[:port] or a *.svc.<region>.pinecone.io style host
  if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?$/i.test(v)) return v.split(':')[0];
  return null;
}

export function discoverVectorStores(roots = [process.cwd()], files = null) {
  const walk = files || walkWorkspace(roots);
  const assets = [];

  // (1) Persisted local indexes — one asset per store directory.
  const byDir = new Map();
  for (const { file } of walk.vector) {
    const dir = path.dirname(file);
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir).push(path.basename(file).toLowerCase());
  }
  for (const [dir, names] of byDir.entries()) {
    let engine = 'unknown';
    if (names.includes('chroma.sqlite3') || names.some((n) => n.startsWith('chroma-'))) engine = 'chroma';
    else if (names.includes('index.faiss')) engine = 'faiss';
    else if (names.some((n) => n.endsWith('.lance'))) engine = 'lancedb';
    else if (names.some((n) => n.endsWith('.usearch'))) engine = 'usearch';
    else if (names.includes('docstore.json') || names.includes('default__vector_store.json')) engine = 'llamaindex';
    else continue; // a lone index.pkl with no recognised sibling — skip (avoid FP)
    // LangChain FAISS.save_local writes a pickle sidecar → code-exec on load.
    const pickleBacked = engine === 'faiss' && names.includes('index.pkl');
    assets.push({
      type: 'VECTOR_STORE',
      name: `${engine} index (${path.basename(dir)})`,
      identifier: `vector:local:${dir}`,
      vendor: engine,
      metadata: { surface: 'local-index', engine, hosted: false, pickleBacked, dir, files: names.slice(0, 20) },
    });
  }

  // (2) Client libraries in project manifests — one asset per engine.
  const byEngine = new Map(); // engine -> { hosted, manifests:Set }
  const addLib = (engine, hosted, manifest) => {
    if (!byEngine.has(engine)) byEngine.set(engine, { hosted, manifests: new Set() });
    byEngine.get(engine).manifests.add(manifest);
  };
  for (const { file } of walk.manifests) {
    const base = path.basename(file);
    if (base === 'package.json') {
      const json = readJson(file);
      if (!json) continue;
      const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}), ...(json.peerDependencies || {}), ...(json.optionalDependencies || {}) };
      for (const name of Object.keys(deps)) {
        const info = vectorLibInfo(name);
        if (info) addLib(info.engine, info.hosted, file);
      }
    } else {
      const text = readText(file, 100_000);
      if (text == null) continue;
      for (const pkg of PY_VECTOR) {
        const re = new RegExp(`(^|[^a-z0-9_.-])${pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9_.-]|$)`, 'im');
        if (re.test(text)) {
          const info = vectorLibInfo(pkg);
          if (info) addLib(info.engine, info.hosted, file);
        }
      }
    }
  }
  for (const [engine, { hosted, manifests }] of byEngine.entries()) {
    const list = [...manifests];
    assets.push({
      type: 'VECTOR_STORE',
      name: `${engine} client`,
      identifier: `vector:client:${engine}`,
      vendor: engine,
      metadata: { surface: 'client-lib', engine, hosted, usedInProjects: list.length, manifests: list.slice(0, 10) },
    });
  }

  // (3) Managed/cloud endpoints declared in .env files — one asset per engine.
  const byCloud = new Map(); // engine -> { hosts:Set, hasKey, hasEndpoint, files:Set }
  for (const { file } of walk.env) {
    const text = readText(file, 100_000);
    if (text == null) continue;
    for (const line of text.split(/\r?\n/)) {
      const m = line.match(/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/);
      if (!m) continue;
      const cfg = VECTOR_ENV[m[1]];
      if (!cfg) continue;
      const value = m[2].trim().replace(/^["']|["']$/g, '');
      if (!value || /(your|xxx|placeholder|changeme|<|example)/i.test(value)) continue;
      if (!byCloud.has(cfg.engine)) byCloud.set(cfg.engine, { hosts: new Set(), hasKey: false, hasEndpoint: false, files: new Set() });
      const e = byCloud.get(cfg.engine);
      e.files.add(file);
      if (cfg.kind === 'key') e.hasKey = true;
      else {
        e.hasEndpoint = true;
        const h = endpointHost(value);
        if (h) e.hosts.add(h);
      }
    }
  }
  for (const [engine, e] of byCloud.entries()) {
    assets.push({
      type: 'VECTOR_STORE',
      name: `${engine} (cloud)`,
      identifier: `vector:cloud:${engine}`,
      vendor: engine,
      metadata: {
        surface: 'cloud-endpoint',
        engine,
        hosted: true,
        hasApiKey: e.hasKey,
        hosts: [...e.hosts].slice(0, 5),
        files: [...e.files].slice(0, 10),
      },
    });
  }

  return assets;
}

// ── installed AI tools & local model runtimes (presence) ─────────

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

/** Local model runtimes — detected by directory AND by running process. */
export function discoverLocalRuntimes() {
  const runtimes = [
    { vendor: 'ollama', name: 'Ollama', dirs: [path.join(HOME, '.ollama'), path.join(LOCALAPPDATA, 'Ollama')], modelsDir: path.join(HOME, '.ollama', 'models', 'manifests'), proc: ['ollama'] },
    { vendor: 'lmstudio', name: 'LM Studio', dirs: [path.join(HOME, '.lmstudio'), path.join(HOME, '.cache', 'lm-studio'), path.join(LOCALAPPDATA, 'LM Studio')], proc: ['lm studio', 'lmstudio', 'lms'] },
    { vendor: 'jan', name: 'Jan', dirs: [path.join(HOME, 'jan'), path.join(HOME, '.jan'), path.join(APPDATA, 'Jan')], proc: ['jan'] },
    { vendor: 'gpt4all', name: 'GPT4All', dirs: [path.join(HOME, '.cache', 'gpt4all'), path.join(HOME, 'Library', 'Application Support', 'nomic.ai', 'GPT4All'), path.join(LOCALAPPDATA, 'nomic.ai', 'GPT4All')], proc: ['gpt4all'] },
    { vendor: 'huggingface', name: 'Hugging Face cache', dirs: [path.join(HOME, '.cache', 'huggingface'), path.join(process.env.HF_HOME || '', 'hub')], proc: [] },
    { vendor: 'localai', name: 'LocalAI', dirs: [path.join(HOME, '.localai')], proc: ['local-ai', 'localai'] },
    { vendor: 'textgen', name: 'Text Generation WebUI', dirs: [], proc: ['text-generation', 'oobabooga'] },
    { vendor: 'vllm', name: 'vLLM', dirs: [], proc: ['vllm'] },
  ];
  const procs = listProcesses();
  const assets = [];
  for (const r of runtimes) {
    const at = firstExisting(r.dirs);
    const running = r.proc.some((tok) => procs.some((p) => p.includes(tok)));
    if (!at && !running) continue;
    const meta = { category: 'local-runtime', detectedAt: at || null, running };
    if (r.vendor === 'ollama' && r.modelsDir) meta.models = ollamaModels(r.modelsDir);
    assets.push({ type: 'AI_TOOL', name: r.name, identifier: at || `proc:${r.vendor}`, vendor: r.vendor, metadata: meta });
  }
  return assets;
}

/** Enumerate locally-pulled Ollama models from the manifests tree (names only). */
function ollamaModels(manifestsDir) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 5 || out.length > 100) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile()) {
        // manifests/<registry>/<namespace>/<model>/<tag>  ->  namespace/model:tag
        const rel = path.relative(manifestsDir, full).split(path.sep);
        if (rel.length >= 2) out.push(`${rel.slice(1, -1).join('/')}:${rel[rel.length - 1]}`);
      }
    }
  };
  walk(manifestsDir, 0);
  return out.slice(0, 100);
}

/** Best-effort process listing (short timeout, never throws). */
function listProcesses() {
  try {
    if (PLAT === 'win32') {
      const out = execFileSync('tasklist', ['/fo', 'csv', '/nh'], { timeout: 4000, encoding: 'utf8', windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
      return out.split(/\r?\n/).map((l) => (l.match(/^"([^"]+)"/)?.[1] || '').toLowerCase()).filter(Boolean);
    }
    const out = execFileSync('ps', ['-eo', 'comm='], { timeout: 4000, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    return out.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean);
  } catch {
    return [];
  }
}

// ── coding agents (autonomous tool-runners) ──────────────────────

/**
 * Discover installed CODING AGENTS, separate from passive AI tools. For each we
 * record whether the Shomra runtime firewall hook is installed (`guarded`) so
 * the backend can flag an unguarded agent — one that can run shell / edit files
 * / call MCP with no policy checkpoint. This is the shadow-agent surface.
 */
export function discoverCodingAgents(roots = [process.cwd()]) {
  const cwd = process.cwd();
  const agents = [
    { vendor: 'claude-code', name: 'Claude Code', probes: [path.join(HOME, '.claude.json'), path.join(HOME, '.claude')], hookFiles: [path.join(HOME, '.claude', 'settings.json'), path.join(cwd, '.claude', 'settings.json')] },
    { vendor: 'cursor', name: 'Cursor', probes: [path.join(HOME, '.cursor')], hookFiles: [path.join(HOME, '.cursor', 'hooks.json'), path.join(cwd, '.cursor', 'hooks.json')] },
    { vendor: 'windsurf', name: 'Windsurf', probes: [path.join(HOME, '.codeium', 'windsurf')], hookFiles: [path.join(HOME, '.codeium', 'windsurf', 'hooks.json'), path.join(cwd, '.windsurf', 'hooks.json')] },
    { vendor: 'gemini', name: 'Gemini CLI', probes: [path.join(HOME, '.gemini')], hookFiles: [path.join(HOME, '.gemini', 'settings.json'), path.join(cwd, '.gemini', 'settings.json')] },
    { vendor: 'codex', name: 'OpenAI Codex CLI', probes: [path.join(HOME, '.codex')], hookFiles: [path.join(HOME, '.codex', 'hooks.json'), path.join(cwd, '.codex', 'hooks.json')] },
    { vendor: 'copilot', name: 'GitHub Copilot CLI', probes: [path.join(HOME, '.copilot')], hookFiles: [path.join(HOME, '.copilot', 'hooks', 'shomra.json'), path.join(cwd, '.github', 'hooks', 'shomra.json')] },
    { vendor: 'cline', name: 'Cline', probes: [path.join(vscodeUserDir(), 'globalStorage', 'saoudrizwan.claude-dev')], hookFiles: [path.join(HOME, '.cline', 'hooks.json'), path.join(cwd, '.cline', 'hooks.json')] },
    { vendor: 'roo', name: 'Roo Code', probes: [path.join(vscodeUserDir(), 'globalStorage', 'rooveterinaryinc.roo-cline')], hookFiles: [path.join(cwd, '.roo', 'hooks.json')] },
    { vendor: 'aider', name: 'Aider', probes: [path.join(HOME, '.aider.conf.yml'), path.join(cwd, '.aider.conf.yml'), path.join(HOME, '.aider')], hookFiles: [path.join(HOME, '.aider.conf.yml'), path.join(cwd, '.aider.conf.yml')] },
  ];
  const assets = [];
  for (const a of agents) {
    const installedAt = a.probes.find((p) => exists(p));
    if (!installedAt) continue;
    const guardFile = a.hookFiles.find((f) => {
      const t = readText(f, 20_000);
      return t != null && /shomra/i.test(t);
    });
    assets.push({
      type: 'AI_AGENT',
      name: a.name,
      identifier: `agent:${a.vendor}`,
      vendor: a.vendor,
      metadata: { detectedAt: installedAt, guarded: !!guardFile, guardFile: guardFile || null },
    });
  }
  return assets;
}

// ── model-provider API keys in the environment ───────────────────

export function discoverModelKeys() {
  const assets = [];
  for (const [name, v] of Object.entries(process.env)) {
    if (!v || v.length < 8) continue;
    const vendor = KEY_NAME_VENDOR[name] || (/(_API_KEY|_API_TOKEN|_APIKEY)$/.test(name) ? classifyKey(name, v) : null);
    if (!vendor) continue;
    assets.push({
      type: 'MODEL_KEY',
      name,
      identifier: `env:${name}`,
      vendor,
      metadata: { source: 'environment', fingerprint: `${v.slice(0, 3)}…${v.slice(-2)}` },
      // The raw value is intentionally NOT transmitted.
    });
  }
  return assets;
}

function redactEnv(env) {
  if (!env || typeof env !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    const s = String(v ?? '');
    out[k] = s.length > 8 ? `${s.slice(0, 3)}…${s.slice(-2)}` : s;
  }
  return out;
}

// ── aggregate ────────────────────────────────────────────────────

export function discoverAll(roots = [process.cwd()], opts = {}) {
  const { autoExpand = true } = opts;
  const scanRoots = resolveRoots(roots, autoExpand);
  const files = walkWorkspace(scanRoots); // one walk, shared by every file-based discoverer
  const all = [
    ...discoverMcpServers(scanRoots, files),
    ...discoverRulesFiles(scanRoots, files),
    ...discoverAiDependencies(scanRoots, files),
    ...discoverVectorStores(scanRoots, files),
    ...discoverDotenvKeys(scanRoots, files),
    ...discoverAiTools(),
    ...discoverCodingAgents(scanRoots),
    ...discoverModelKeys(),
  ];
  // Final dedup by (type, identifier) — a runtime can be found by both dir and
  // process; an env key can also appear in a .env file.
  const seen = new Set();
  const out = [];
  for (const a of all) {
    const key = `${a.type}::${a.identifier || a.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(a);
  }
  return out;
}
