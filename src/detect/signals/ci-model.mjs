export const CI_PATH_RE =
  /(^|\/)\.(?:github|gitea|forgejo)\/workflows\/[^/]+\.ya?ml$|(^|\/)\.github\/actions\/.+\/action\.ya?ml$|(^|\/)action\.ya?ml$|(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)\.gitlab-ci\/.+\.ya?ml$|(^|\/)\.gitlab\/ci\/.+\.ya?ml$|(^|\/)azure-pipelines[\w.-]*\.ya?ml$|(^|\/)\.azure-pipelines\/.+\.ya?ml$|(^|\/)bitbucket-pipelines\.ya?ml$|(^|\/)\.circleci\/config\.ya?ml$|(^|\/)\.buildkite\/.+\.ya?ml$|(^|\/)Jenkinsfile(?:\.[\w-]+)?$/i;

export function ciVendorOf(path        )                  {
  const p = path.replace(/\\/g, '/');
  if (!CI_PATH_RE.test(p)) return null;
  if (/gitlab/i.test(p)) return 'gitlab';
  if (/azure-pipelines/i.test(p)) return 'azure';
  if (/bitbucket-pipelines/i.test(p)) return 'bitbucket';
  if (/\.circleci\//i.test(p)) return 'circleci';
  if (/\.buildkite\//i.test(p)) return 'buildkite';
  if (/jenkinsfile/i.test(p)) return 'jenkins';
  return 'github';
}

const AI_ACTIONS                                                      = [
  { re: /^anthropics\/claude-code(?:-base)?-action\b/i, product: 'claude-code-action', kind: 'agent' },
  { re: /^google-github-actions\/run-gemini-cli\b/i, product: 'run-gemini-cli', kind: 'agent' },
  { re: /^openai\/codex-action\b/i, product: 'codex-action', kind: 'agent' },
  { re: /^github\/copilot-swe-agent\b/i, product: 'copilot-swe-agent', kind: 'agent' },
  { re: /^actions\/ai-inference\b/i, product: 'ai-inference', kind: 'model' },
  { re: /^(?:qodo-ai|codium-ai)\/pr-agent\b/i, product: 'pr-agent', kind: 'reviewer' },
  { re: /^coderabbitai\//i, product: 'coderabbit', kind: 'reviewer' },
  { re: /(?:claude|gemini|codex|openai|anthropic|copilot|gpt|llm|ai[-_]?(?:review|agent|inference|assistant)|aider|openhands|cursor|qwen|opencode|mistral|ollama)/i, product: 'ai-action', kind: 'agent' },
];

const AI_CLI_RE =
  /(?:^|[\s;&|(`$'"])(?:npx\s+(?:-y\s+|--yes\s+)?)?(?:@anthropic-ai\/claude-code|@openai\/codex|@google\/gemini-cli|@github\/copilot|@qwen-code\/qwen-code|@sourcegraph\/amp)(?:@[\w.-]+)?(?=$|[\s;&|)`'"])|(?:^|[\s;&|(`$'"])(?:npx\s+(?:-y\s+|--yes\s+)?)?(?:opencode-ai|claude|codex|gemini|qwen|copilot|cursor-agent|aider|opencode|openhands|goose|kiro-cli|amp)(?:@[\w.-]+)?\s+(?:-{1,2}[a-z]|exec\b|run\b|chat\b|"|')|(?:^|[\s;&|])aider(?=$|[\s;&|])|(?:^|[\s;&|])q\s+chat\b|(?:^|[\s;&|])agent\s+(?:-p|--print)\b/im;
const MODEL_API_RE = /\b(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|models\.github\.ai|models\.inference\.ai\.azure\.com|api\.mistral\.ai|api\.groq\.com|openrouter\.ai\/api)\b/i;

export function aiStepOf(uses               , run               )                {
  if (uses) {
    const repo = uses.replace(/^\.\//, '').split('@')[0];
    for (const a of AI_ACTIONS) if (a.re.test(repo)) return { product: a.product, kind: a.kind };
  }
  if (run) {
    const cli = AI_CLI_RE.exec(run);
    if (cli) return { product: cli[0].replace(/^[\s;&|(`$'"]+/, '').split(/\s/).filter((w) => !/^(npx|-y|--yes)$/.test(w))[0].replace(/^@[\w-]+\//, '').replace(/@[\w.-]+$/, '') || 'agent-cli', kind: 'agent' };
    if (MODEL_API_RE.test(run)) return { product: 'model-api', kind: 'model' };
  }
  return null;
}

