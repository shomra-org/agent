import { readText } from './fs-read.mjs';
import { walkWorkspace } from './workspace.mjs';

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

      });
    }
  }
  return assets;
}

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

    });
  }
  return assets;
}

export function redactEnv(env) {
  if (!env || typeof env !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    const s = String(v ?? '');
    out[k] = s.length > 8 ? `${s.slice(0, 3)}…${s.slice(-2)}` : s;
  }
  return out;
}
