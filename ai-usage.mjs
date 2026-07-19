/**
 * AI-USAGE inventory extractor (CLI port of the backend's checks/ai-usage.ts,
 * kept in sync so both surfaces detect the same thing). Finds where a repo USES
 * an LLM/AI provider in its own source — SDK imports + provider-specific call
 * sites — so `shomra` can inventory "this code talks to OpenAI / a local model"
 * as plain shadow-AI usage, independent of whether that usage is vulnerable.
 *
 * Dependency-free, line-oriented, low-false-positive: a provider is only claimed
 * when a line either IMPORTS its SDK module or matches a provider-specific CALL
 * signature — never from a bare mention of the word "openai" in prose.
 */

/** Human label per category — shared by the report + backend. */
export const AI_USAGE_CATEGORY_LABEL = {
  'llm-api': 'hosted LLM API',
  'llm-framework': 'LLM framework',
  'local-runtime': 'local model runtime',
  'inference-gateway': 'inference gateway',
};

// The provider catalog — every entry is an LLM/AI *usage* surface.
const PROVIDERS = [
  { id: 'openai', label: 'OpenAI', category: 'llm-api', npm: ['openai'], npmPrefix: ['@azure/openai'], py: ['openai'],
    call: [/\b(?:Async)?(?:Azure)?OpenAI\s*\(/, /\bchat\.completions\.create\s*\(/, /\bresponses\.create\s*\(/, /\bembeddings\.create\s*\(/, /\bChatCompletion\.create\s*\(/, /\bopenai\.(?:ChatCompletion|Completion|Embedding)\b/] },
  { id: 'anthropic', label: 'Anthropic', category: 'llm-api', npm: ['@anthropic-ai/sdk', '@anthropic-ai/bedrock-sdk', '@anthropic-ai/vertex-sdk'], npmPrefix: ['@anthropic-ai/'], py: ['anthropic'],
    call: [/\b(?:Async)?Anthropic(?:Bedrock|Vertex)?\s*\(/, /\bmessages\.create\s*\(/, /\bmessages\.stream\s*\(/] },
  { id: 'google-gemini', label: 'Google Gemini', category: 'llm-api', npm: ['@google/generative-ai', '@google/genai'], py: ['google.generativeai', 'google.genai'], pyRoot: ['google.generativeai', 'google.genai'],
    call: [/\bGenerativeModel\s*\(/, /\bgenerate_content\s*\(/, /\bgetGenerativeModel\s*\(/] },
  { id: 'google-vertex', label: 'Google Vertex AI', category: 'llm-api', npm: ['@google-cloud/vertexai', '@google-cloud/aiplatform'], py: ['vertexai', 'google.cloud.aiplatform'], pyRoot: ['vertexai', 'google.cloud.aiplatform'],
    call: [/\bTextGenerationModel\b/, /\bGenerativeModel\.from_pretrained\s*\(/] },
  { id: 'aws-bedrock', label: 'AWS Bedrock', category: 'llm-api', npm: ['@aws-sdk/client-bedrock-runtime', '@aws-sdk/client-bedrock'],
    call: [/\bbedrock[-_]?runtime\b/i, /\bBedrockRuntime(?:Client)?\b/, /\binvoke_model(?:_with_response_stream)?\s*\(/, /\bclient\s*\(\s*['"]bedrock/i] },
  { id: 'cohere', label: 'Cohere', category: 'llm-api', npm: ['cohere-ai'], py: ['cohere'], call: [/\bcohere\.Client\w*\s*\(/, /\bClientV2\s*\(/] },
  { id: 'mistral', label: 'Mistral', category: 'llm-api', npm: ['@mistralai/mistralai'], py: ['mistralai'], call: [/\bMistral(?:Client|AsyncClient|)\s*\(/, /\bchat\.complete\s*\(/] },
  { id: 'groq', label: 'Groq', category: 'llm-api', npm: ['groq-sdk'], py: ['groq'], call: [/\bGroq\s*\(/] },
  { id: 'together', label: 'Together AI', category: 'llm-api', npm: ['together-ai'], py: ['together'], call: [/\bTogether\s*\(/] },
  { id: 'replicate', label: 'Replicate', category: 'llm-api', npm: ['replicate'], py: ['replicate'], call: [/\breplicate\.run\s*\(/, /\bReplicate\s*\(/] },
  { id: 'huggingface-inference', label: 'Hugging Face Inference', category: 'llm-api', npm: ['@huggingface/inference'], py: ['huggingface_hub'], call: [/\bInferenceClient\s*\(/] },

  { id: 'litellm', label: 'LiteLLM', category: 'inference-gateway', npm: ['litellm'], py: ['litellm'], call: [/\blitellm\.(?:a?completion|a?embedding)\s*\(/] },
  { id: 'openrouter', label: 'OpenRouter', category: 'inference-gateway', npm: ['openrouter'], call: [/\bopenrouter\.ai\b/i] },
  { id: 'vercel-ai', label: 'Vercel AI SDK', category: 'inference-gateway', npm: ['ai'], npmPrefix: ['@ai-sdk/'], call: [/\b(?:generateText|streamText|generateObject|streamObject)\s*\(/] },

  { id: 'langchain', label: 'LangChain', category: 'llm-framework', npmPrefix: ['@langchain/'], npm: ['langchain'], pyRoot: ['langchain'], call: [/\bChat(?:OpenAI|Anthropic|Google\w*|Bedrock|Vertex\w*|Cohere|Mistral\w*)\s*\(/, /\bLLMChain\s*\(/, /\bChatPromptTemplate\b/] },
  { id: 'langgraph', label: 'LangGraph', category: 'llm-framework', npm: ['@langchain/langgraph'], pyRoot: ['langgraph'], call: [/\bStateGraph\s*\(/] },
  { id: 'llama-index', label: 'LlamaIndex', category: 'llm-framework', npmPrefix: ['@llamaindex/'], npm: ['llamaindex'], pyRoot: ['llama_index'], call: [/\bVectorStoreIndex\b/, /\bServiceContext\b/] },
  { id: 'crewai', label: 'CrewAI', category: 'llm-framework', py: ['crewai'], pyRoot: ['crewai'], call: [/\bCrew\s*\(/, /\bAgent\s*\(\s*role\s*=/] },
  { id: 'autogen', label: 'AutoGen', category: 'llm-framework', py: ['autogen', 'pyautogen'], pyRoot: ['autogen', 'autogen_agentchat'], call: [/\bAssistantAgent\s*\(/, /\bConversableAgent\s*\(/] },
  { id: 'semantic-kernel', label: 'Semantic Kernel', category: 'llm-framework', py: ['semantic_kernel'], pyRoot: ['semantic_kernel'], npm: ['@microsoft/semantic-kernel'], call: [/\bKernel\.builder\b/] },
  { id: 'haystack', label: 'Haystack', category: 'llm-framework', py: ['haystack'], pyRoot: ['haystack'], call: [/\bPipeline\s*\(\s*\)/] },
  { id: 'dspy', label: 'DSPy', category: 'llm-framework', py: ['dspy'], pyRoot: ['dspy'], call: [/\bdspy\.(?:Predict|ChainOfThought|Signature)\b/] },
  { id: 'guidance', label: 'Guidance', category: 'llm-framework', py: ['guidance'], call: [/\bguidance\.\w+/] },
  { id: 'instructor', label: 'Instructor', category: 'llm-framework', py: ['instructor'], call: [/\binstructor\.(?:from_openai|patch|from_anthropic)\s*\(/] },
  { id: 'pydantic-ai', label: 'PydanticAI', category: 'llm-framework', py: ['pydantic_ai'], pyRoot: ['pydantic_ai'], call: [/\bAgent\s*\(\s*['"]/] },

  { id: 'ollama', label: 'Ollama', category: 'local-runtime', npm: ['ollama'], py: ['ollama'], call: [/\bollama\.(?:chat|generate|embeddings)\s*\(/] },
  { id: 'transformers', label: 'Transformers', category: 'local-runtime', py: ['transformers'], pyRoot: ['transformers'], call: [/\bpipeline\s*\(/, /\bAutoModel\w*\.from_pretrained\s*\(/] },
  { id: 'sentence-transformers', label: 'Sentence-Transformers', category: 'local-runtime', py: ['sentence_transformers'], call: [/\bSentenceTransformer\s*\(/] },
  { id: 'vllm', label: 'vLLM', category: 'local-runtime', py: ['vllm'], call: [/\bLLM\s*\(\s*model\s*=/, /\bSamplingParams\s*\(/] },
  { id: 'llama-cpp', label: 'llama.cpp', category: 'local-runtime', npm: ['node-llama-cpp'], py: ['llama_cpp'], call: [/\bLlama\s*\(\s*model_path\s*=/] },
];

const MODEL_ON_LINE = /\bmodel(?:_?id|_?name)?\s*[=:]\s*['"]([A-Za-z0-9][\w.:\/-]{1,80})['"]/;
const MAX_CODE_LEN = 240;
const clipLine = (s) => (s.length > MAX_CODE_LEN ? s.slice(0, MAX_CODE_LEN) + '…' : s);
const SCAN_EXT = /\.(py|ipynb|[mc]?[jt]sx?|java|kt|go|rb|php|cs|rs|scala)$/i;
export function isAiUsageScannable(file) {
  return SCAN_EXT.test(String(file || ''));
}

function importSpecifiers(raw) {
  const out = [];
  for (const m of raw.matchAll(/(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|\bimport\s+)['"]([^'"]+)['"]/g)) out.push(m[1]);
  let pm = raw.match(/^\s*from\s+([A-Za-z_][\w.]*)\s+import\b/);
  if (pm) out.push(pm[1]);
  pm = raw.match(/^\s*import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*)/);
  if (pm) for (const mod of pm[1].split(',')) out.push(mod.trim());
  return out;
}

function importMatches(spec, p) {
  if (!spec) return false;
  const s = spec.trim();
  if (p.npm?.includes(s)) return true;
  if (p.npmPrefix?.some((pre) => s === pre.replace(/\/$/, '') || s.startsWith(pre))) return true;
  if (p.py?.includes(s)) return true;
  if (p.pyRoot?.some((root) => s === root || s.startsWith(root + '.') || s.startsWith(root + '_'))) return true;
  return false;
}

/** Extract AI-usage sightings from one source file's text. */
export function scanAiUsage(text, file = '') {
  if (!text || !isAiUsageScannable(file)) return [];
  const out = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const ln = i + 1;
    const isComment = trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*');
    const specs = isComment ? [] : importSpecifiers(raw);
    const modelOnLine = (raw.match(MODEL_ON_LINE) || [])[1];
    const seenOnLine = new Set();
    for (const p of PROVIDERS) {
      const importedSpec = specs.find((s) => importMatches(s, p));
      if (importedSpec) {
        const key = `${p.id}:import`;
        if (!seenOnLine.has(key)) {
          seenOnLine.add(key);
          out.push({ provider: p.id, label: p.label, category: p.category, kind: 'import', via: importedSpec, code: clipLine(trimmed), line: ln, file });
        }
      }
      if (!isComment && p.call) {
        const hit = p.call.find((re) => re.test(raw));
        if (hit) {
          const key = `${p.id}:call`;
          if (!seenOnLine.has(key)) {
            seenOnLine.add(key);
            out.push({ provider: p.id, label: p.label, category: p.category, kind: 'call', via: (raw.match(hit) || [])[0] || p.label, code: clipLine(trimmed), ...(modelOnLine ? { model: modelOnLine } : {}), line: ln, file });
          }
        }
      }
    }
  }
  return out;
}

/** Cap on individual sites carried per provider row. */
const MAX_SITES_PER_PROVIDER = 60;

/** One inventory row per provider, aggregated across all files. */
export function rollupAiUsage(usages) {
  const byProvider = new Map();
  for (const u of usages) {
    let row = byProvider.get(u.provider);
    if (!row) {
      row = { provider: u.provider, label: u.label, category: u.category, files: [], firstSite: null, sites: [], models: [], sightings: 0, hasCallSite: false };
      byProvider.set(u.provider, row);
    }
    row.sightings++;
    if (!row.files.includes(u.file)) row.files.push(u.file);
    if (u.model && !row.models.includes(u.model)) row.models.push(u.model);
    if (u.kind === 'call') row.hasCallSite = true;
    if (row.sites.length < MAX_SITES_PER_PROVIDER) {
      row.sites.push({ file: u.file, line: u.line, kind: u.kind, via: u.via, ...(u.code ? { code: u.code } : {}), ...(u.model ? { model: u.model } : {}) });
    }
    const better = u.kind === 'call' && (!row.firstSite || row.firstSite.kind !== 'call');
    if (!row.firstSite || better) row.firstSite = { file: u.file, line: u.line, via: u.via, kind: u.kind };
  }
  for (const row of byProvider.values()) {
    row.sites.sort((a, b) => a.file.localeCompare(b.file) || (b.kind === 'call' ? 1 : 0) - (a.kind === 'call' ? 1 : 0) || a.line - b.line);
  }
  return [...byProvider.values()].sort((a, b) => a.label.localeCompare(b.label));
}
