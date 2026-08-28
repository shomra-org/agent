
const LOADER_HINT = /\b(from_pretrained|SentenceTransformer|CrossEncoder|hf_hub_download|snapshot_download|InferenceClient|AutoModel\w*|AutoTokenizer|AutoConfig|AutoProcessor|AutoFeatureExtractor|from_hf_hub|hf_hub|load_dataset|torch\.hub\.load|ollama)\b|\bpipeline\s*\(|\bmodel\s*[=:]\s*['"]|huggingface\.co|\bhf\.co\b/i;

const QUOTED_ID = /['"]([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)['"]/g;

const FROM_PRETRAINED_ARG = /\bfrom_pretrained\s*\(\s*(?:[A-Za-z_][\w.]*\s*,\s*)?['"]([\w./-]+)['"]/g;
const ST_ARG = /\b(?:SentenceTransformer|CrossEncoder)\s*\(\s*['"]([\w./-]+)['"]/g;

const KW_ID = /\b(?:model|repo_id|model_name|model_id|model_name_or_path|pretrained_model_name_or_path|checkpoint|base_model)\s*[=:]\s*['"]([\w./-]+)['"]/gi;

const YAML_KW = /^[ \t-]*(?:model|model_name|model_id|base_model|checkpoint)\s*:\s*([A-Za-z0-9][\w./-]*[\w/.-])\s*(?:#.*)?$/gim;

const REVISION = /\b(?:revision|commit|sha)\s*=\s*['"]([\w.-]{4,})['"]/i;

const ID_STOPWORDS = new Set([
  'auto', 'cpu', 'cuda', 'mps', 'none', 'true', 'false', 'main', 'default',
  'text-classification', 'token-classification', 'question-answering', 'fill-mask',
  'summarization', 'translation', 'text-generation', 'text2text-generation',
  'feature-extraction', 'sentence-similarity', 'zero-shot-classification',
  'image-classification', 'object-detection', 'automatic-speech-recognition',
  'conversational', 'ner', 'sentiment-analysis', 'embeddings', 'chat', 'completion',
]);

const HF_URL = /https?:\/\/(?:www\.)?(?:huggingface\.co|hf\.co)\/([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)(?:\/tree\/([\w.-]+))?/gi;

const OLLAMA = /\bollama\s+(?:pull|run|cp|create)\s+([a-z0-9][\w.:\/-]*)/gi;

const TORCH_HUB = /torch\.hub\.load\s*\(\s*['"]([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)['"]/g;

const API_MODEL = /^(?:gpt-|gpt4|o[1-4](?:-|$)|text-embedding-|text-(?:davinci|curie|babbage|ada)|davinci|dall-e|whisper-|tts-|chatgpt|claude[-\d]|gemini[-.]|gemini$|models\/gemini|mistral-|mixtral-|codestral-|command(?:-|$)|command-r|grok-|deepseek-(?:chat|coder|reasoner)|sonar-)/i;
function apiProvider(id) {
  const s = String(id || '').toLowerCase();
  if (/^(gpt|o[1-4]|text-|davinci|curie|babbage|ada|dall-e|whisper|tts-|chatgpt)/.test(s)) return 'openai';
  if (/^claude/.test(s)) return 'anthropic';
  if (/^(gemini|models\/gemini)/.test(s)) return 'google';
  if (/^(mistral|mixtral|codestral)/.test(s)) return 'mistral';
  if (/^command/.test(s)) return 'cohere';
  if (/^grok/.test(s)) return 'xai';
  if (/^deepseek/.test(s)) return 'deepseek';
  if (/^sonar/.test(s)) return 'perplexity';
  return 'api';
}

const ASSET_EXT = /\.(py|pyc|ipynb|[mc]?[jt]sx?|json|ya?ml|toml|txt|md|lock|cfg|ini|sh|env|png|jpg|svg|css|html?|csv|tsv|parquet)$/i;

const NONMODEL_ORGS = new Set([
  'docs', 'blog', 'spaces', 'datasets', 'models', 'join', 'login', 'settings',
  'pricing', 'tasks', 'learn', 'papers', 'collections', 'organizations', 'new',
  'search', 'chat', 'posts', 'enterprise', 'inference-endpoints',
]);
function looksLikeModelId(id) {
  if (!id || id.startsWith('@') || id.startsWith('.') || id.startsWith('/')) return false;
  if (id.includes('..') || id.split('/').length !== 2) return false;
  if (ASSET_EXT.test(id)) return false;
  const [a, b] = id.split('/');
  if (!/[A-Za-z]/.test(a) || !/[A-Za-z]/.test(b)) return false;
  if (NONMODEL_ORGS.has(a.toLowerCase())) return false;
  return true;
}

function validBareId(id) {
  if (!id || id.startsWith('@') || id.startsWith('.') || id.startsWith('/') || id.includes('..')) return false;
  if (ID_STOPWORDS.has(id.toLowerCase())) return false;
  if (id.includes('/')) return looksLikeModelId(id);
  if (ASSET_EXT.test(id) || id.length < 2 || !/[A-Za-z]/.test(id)) return false;
  return true;
}

export function scanModelRefs(text, file = '') {
  if (!text) return [];
  const out = [];
  const seen = new Set();

  const add = (id, { revision, source, line, via, bare }) => {
    if (!id) return;

    if (source === 'hf' && !id.includes('/') && API_MODEL.test(id)) {
      source = 'api';
      via = `${via} · ${apiProvider(id)} API`;
    }
    if (source !== 'ollama' && !(bare ? validBareId(id) : looksLikeModelId(id))) return;
    const key = `${source}:${id}:${revision || ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ id, ...(revision ? { revision } : {}), source, line, via, file });
  };

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const ln = i + 1;

    for (const m of raw.matchAll(HF_URL)) add(m[1], { revision: m[2], source: 'hf', line: ln, via: 'huggingface.co URL' });

    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    const isTorchHub = /torch\.hub\.load/.test(raw);
    for (const m of raw.matchAll(TORCH_HUB)) add(m[1], { source: 'github', line: ln, via: 'torch.hub.load' });

    const isOllama = /\bollama\b/.test(raw);
    for (const m of raw.matchAll(OLLAMA)) add(m[1], { source: 'ollama', line: ln, via: 'ollama' });

    if (isTorchHub || isOllama || /huggingface\.co|hf\.co/.test(raw)) continue;

    const rev = (raw.match(REVISION) || [])[1];

    for (const m of raw.matchAll(FROM_PRETRAINED_ARG)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'from_pretrained', bare: true });
    for (const m of raw.matchAll(ST_ARG)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'sentence-transformers', bare: true });
    for (const m of raw.matchAll(KW_ID)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model= keyword', bare: true });

    for (const m of raw.matchAll(YAML_KW)) {
      if (!/[0-9./]/.test(m[1])) continue;
      add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model: yaml key', bare: true });
    }

    if (LOADER_HINT.test(raw)) {
      for (const m of raw.matchAll(QUOTED_ID)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model loader' });
    }
  }
  return out;
}

const SCAN_EXT = /\.(py|ipynb|[mc]?[jt]sx?|ya?ml|yml|toml|txt|md|env|cfg|ini|json)$/i;
export function isModelRefScannable(file) {
  return SCAN_EXT.test(String(file || ''));
}
