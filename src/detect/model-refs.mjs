/**
 * Model-reference extractor — finds the AI MODELS a dev's code loads, so the CLI
 * can look each one up in the platform's Model Security Index (GET /models/lookup)
 * and surface known vulnerabilities. This is the "you reference a model → we tell
 * you if it's dangerous" path: you can't read a model's weights from source, but
 * you CAN see which model id the code pulls, and the platform has already scanned
 * the popular ones.
 *
 * Dependency-free, line-oriented, low-false-positive: model ids are only extracted
 * from lines that carry a real loader hint (from_pretrained / SentenceTransformer /
 * hf_hub_download / snapshot_download / pipeline(model=…) / a huggingface.co URL /
 * torch.hub.load / ollama pull|run), never from arbitrary "a/b" strings (which are
 * usually file paths or npm packages).
 */

// A line must carry one of these to be considered a model load.
const LOADER_HINT = /\b(from_pretrained|SentenceTransformer|CrossEncoder|hf_hub_download|snapshot_download|InferenceClient|AutoModel\w*|AutoTokenizer|AutoConfig|AutoProcessor|AutoFeatureExtractor|from_hf_hub|hf_hub|load_dataset|torch\.hub\.load|ollama)\b|\bpipeline\s*\(|\bmodel\s*[=:]\s*['"]|huggingface\.co|\bhf\.co\b/i;

// A quoted HF-style id: "org/model" (one slash, HF-legal chars, no path/URL/ext).
const QUOTED_ID = /['"]([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)['"]/g;
// High-confidence positions whose quoted value IS a model id — so we can also
// accept BARE ids (no org, e.g. "gpt2", "distilbert-base-uncased") from them.
const FROM_PRETRAINED_ARG = /\bfrom_pretrained\s*\(\s*(?:[A-Za-z_][\w.]*\s*,\s*)?['"]([\w./-]+)['"]/g;
const ST_ARG = /\b(?:SentenceTransformer|CrossEncoder)\s*\(\s*['"]([\w./-]+)['"]/g;
// ⚠ `[=:]`, not `=`. This required an equals sign, so it saw Python and nothing
// else: JS/TS object literals and JSON all write `model: "gpt-4o"`, which is how
// every Node OpenAI/Anthropic SDK call declares its model. A JS repo full of
// model calls reported "✓ No AI model references found in the code." — a green
// pass over a blind spot, and no vuln lookups ran for the whole estate.
//
// The VALUE STAYS QUOTED. An unquoted value matches any identifier, so
// `const model = keyword` and `model: capabilities` came back as models named
// "keyword" and "capabilities" — an inventory of things that do not exist is
// worse than a short one. YAML's unquoted form is handled by YAML_KW below,
// where line anchoring makes it safe.
const KW_ID = /\b(?:model|repo_id|model_name|model_id|model_name_or_path|pretrained_model_name_or_path|checkpoint|base_model)\s*[=:]\s*['"]([\w./-]+)['"]/gi;

// YAML: `model: gpt-4o` with no quotes. Anchored to the start of a line and to
// end-of-value, so it cannot fire inside expressions the way a free-floating
// pattern does. The value must carry a digit, a slash or a dot — model ids do
// (`gpt-4o`, `openai-community/gpt2`, `claude-opus-4-8`); bare English words
// like `capabilities` do not.
const YAML_KW = /^[ \t-]*(?:model|model_name|model_id|base_model|checkpoint)\s*:\s*([A-Za-z0-9][\w./-]*[\w/.-])\s*(?:#.*)?$/gim;
// A pinned revision/commit in the same call.
const REVISION = /\b(?:revision|commit|sha)\s*=\s*['"]([\w.-]{4,})['"]/i;
// Bare-id positions can accidentally grab a pipeline TASK / device / dtype — drop those.
const ID_STOPWORDS = new Set([
  'auto', 'cpu', 'cuda', 'mps', 'none', 'true', 'false', 'main', 'default',
  'text-classification', 'token-classification', 'question-answering', 'fill-mask',
  'summarization', 'translation', 'text-generation', 'text2text-generation',
  'feature-extraction', 'sentence-similarity', 'zero-shot-classification',
  'image-classification', 'object-detection', 'automatic-speech-recognition',
  'conversational', 'ner', 'sentiment-analysis', 'embeddings', 'chat', 'completion',
]);
// Full huggingface.co / hf.co model URLs.
const HF_URL = /https?:\/\/(?:www\.)?(?:huggingface\.co|hf\.co)\/([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)(?:\/tree\/([\w.-]+))?/gi;
// `ollama pull llama3:8b` / `ollama run mistral` — local runtime models (no slash).
const OLLAMA = /\bollama\s+(?:pull|run|cp|create)\s+([a-z0-9][\w.:\/-]*)/gi;
// torch.hub.load("pytorch/vision", …) — a GitHub owner/repo that runs hubconf.py.
const TORCH_HUB = /torch\.hub\.load\s*\(\s*['"]([A-Za-z0-9][\w.-]*\/[A-Za-z0-9][\w.-]*)['"]/g;

// Hosted-API model families. A bare `model="gpt-4o"` / `model="claude-…"` is an
// OpenAI/Anthropic/Google/etc API call, NOT a Hugging Face repo — but `model=` is
// their SDK param too, so KW_ID/from_pretrained would otherwise tag these 'hf' and
// trigger a doomed HF-Index lookup ("gpt-4o (hf) lookup failed"). Recognize them
// and tag 'api' with the provider. Prefix-anchored to avoid matching HF repos.
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

// Reject ids that are really file paths, packages, or non-model strings.
const ASSET_EXT = /\.(py|pyc|ipynb|[mc]?[jt]sx?|json|ya?ml|toml|txt|md|lock|cfg|ini|sh|env|png|jpg|svg|css|html?|csv|tsv|parquet)$/i;
// First path segment on huggingface.co that is a SITE section, not an org — so
// huggingface.co/docs/datasets isn't mistaken for the model "docs/datasets".
const NONMODEL_ORGS = new Set([
  'docs', 'blog', 'spaces', 'datasets', 'models', 'join', 'login', 'settings',
  'pricing', 'tasks', 'learn', 'papers', 'collections', 'organizations', 'new',
  'search', 'chat', 'posts', 'enterprise', 'inference-endpoints',
]);
function looksLikeModelId(id) {
  if (!id || id.startsWith('@') || id.startsWith('.') || id.startsWith('/')) return false;
  if (id.includes('..') || id.split('/').length !== 2) return false;
  if (ASSET_EXT.test(id)) return false; // a model id never ends in a code/asset ext
  const [a, b] = id.split('/');
  if (!/[A-Za-z]/.test(a) || !/[A-Za-z]/.test(b)) return false; // kills "123/456"
  if (NONMODEL_ORGS.has(a.toLowerCase())) return false; // site path, not an org
  return true;
}
// A bare id (no org) from a high-confidence position — accept unless it's clearly
// a task/device token or an asset path.
function validBareId(id) {
  if (!id || id.startsWith('@') || id.startsWith('.') || id.startsWith('/') || id.includes('..')) return false;
  if (ID_STOPWORDS.has(id.toLowerCase())) return false;
  if (id.includes('/')) return looksLikeModelId(id);
  if (ASSET_EXT.test(id) || id.length < 2 || !/[A-Za-z]/.test(id)) return false;
  return true;
}

/**
 * Extract model references from one source file's text. Returns
 * `[{ id, revision?, source, line, via }]` — `source` is the origin registry
 * ('hf' | 'github' | 'ollama'), `via` names the matched loader for evidence.
 * De-duplicated per (id, revision) within the file, keeping the first line.
 */
export function scanModelRefs(text, file = '') {
  if (!text) return [];
  const out = [];
  const seen = new Set();
  // `bare` allows an org-less id ("gpt2") when it came from a high-confidence
  // position (from_pretrained/SentenceTransformer/model=); ollama ids are freeform.
  const add = (id, { revision, source, line, via, bare }) => {
    if (!id) return;
    // A bare hosted-API model name reached us via an HF-shaped matcher (`model=`,
    // from_pretrained). It is not an HF repo — reclassify to 'api' + provider so it
    // is labeled correctly and skips the HF-Index lookup. See API_MODEL.
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

    // 1. Full HF URLs — scanned on EVERY line (incl. comments / README / markdown
    //    headers), since a huggingface.co URL is an unambiguous model reference.
    for (const m of raw.matchAll(HF_URL)) add(m[1], { revision: m[2], source: 'hf', line: ln, via: 'huggingface.co URL' });

    // Code-oriented extractors below skip pure comment lines (a commented-out load).
    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    // 2. torch.hub.load("owner/repo", …) → GitHub-hosted, runs hubconf.py.
    const isTorchHub = /torch\.hub\.load/.test(raw);
    for (const m of raw.matchAll(TORCH_HUB)) add(m[1], { source: 'github', line: ln, via: 'torch.hub.load' });

    // 3. ollama pull/run <model>.
    const isOllama = /\bollama\b/.test(raw);
    for (const m of raw.matchAll(OLLAMA)) add(m[1], { source: 'ollama', line: ln, via: 'ollama' });

    // Lines already fully handled by a specific matcher shouldn't also be mined
    // by the generic HF extractors (avoids torch.hub's owner/repo re-added as hf).
    if (isTorchHub || isOllama || /huggingface\.co|hf\.co/.test(raw)) continue;

    const rev = (raw.match(REVISION) || [])[1];
    // 4a. High-confidence positions — accept BARE ids (org-less) too.
    for (const m of raw.matchAll(FROM_PRETRAINED_ARG)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'from_pretrained', bare: true });
    for (const m of raw.matchAll(ST_ARG)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'sentence-transformers', bare: true });
    for (const m of raw.matchAll(KW_ID)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model= keyword', bare: true });
    // Unquoted YAML values, only where a model id is plausible (see YAML_KW).
    for (const m of raw.matchAll(YAML_KW)) {
      if (!/[0-9./]/.test(m[1])) continue; // no digit, slash or dot → an English word, not a model id
      add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model: yaml key', bare: true });
    }

    // 4b. Any other loader line with a quoted org/model id (hf_hub_download,
    //     snapshot_download, InferenceClient(model=…), etc.).
    if (LOADER_HINT.test(raw)) {
      for (const m of raw.matchAll(QUOTED_ID)) add(m[1], { revision: rev, source: 'hf', line: ln, via: 'model loader' });
    }
  }
  return out;
}

/** Extensions worth scanning for model references. */
const SCAN_EXT = /\.(py|ipynb|[mc]?[jt]sx?|ya?ml|yml|toml|txt|md|env|cfg|ini|json)$/i;
export function isModelRefScannable(file) {
  return SCAN_EXT.test(String(file || ''));
}
