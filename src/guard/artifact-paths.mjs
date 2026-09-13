export const ARTIFACT_PATHS                                               = [

  { re: /(^|\/)\.?mcp\.json$/i, kind: 'mcp' },
  { re: /(^|\/)\.(?:vscode|cursor|roo|kilocode|trae|windsurf|kiro|amazonq|zed|gemini|qwen|junie)\/mcp\.json$/i, kind: 'mcp' },
  { re: /(^|\/)\.kiro\/settings\/mcp\.json$/i, kind: 'mcp' },
  { re: /(^|\/)claude_desktop_config\.json$/i, kind: 'mcp' },
  { re: /(^|\/)(?:cline_mcp_settings|mcp_settings)\.json$/i, kind: 'mcp' },
  { re: /(^|\/)\.codeium\/windsurf\/mcp_config\.json$/i, kind: 'mcp' },

  { re: /(^|\/)\.claude\/settings(?:\.local)?\.json$/i, kind: 'hook' },
  { re: /(^|\/)managed-settings\.json$/i, kind: 'hook' },
  { re: /(^|\/)\.(?:github|copilot)\/hooks\/[^/]+\.json$/i, kind: 'hook' },
  { re: /(^|\/)hooks\/hooks\.json$/i, kind: 'hook' },
  { re: /(^|\/)\.(?:cursor|windsurf|codeium|gemini|qwen|codex|cline|roo)\/hooks(?:\.json|\/[^/]+\.json)$/i, kind: 'hook' },

  { re: /(^|\/)SKILL\.md$/i, kind: 'skill' },
  { re: /(^|\/)\.(?:claude|cursor|windsurf|codex|agents)\/skills\/.+\.(?:md|markdown)$/i, kind: 'skill' },

  { re: /(^|\/)\.[\w-]+\/commands?\/[^/]*\.(?:md|markdown|toml)$/i, kind: 'command' },
  { re: /(^|\/)\.[\w-]+\/prompts?\/[^/]*\.(?:md|markdown|toml)$/i, kind: 'command' },
  { re: /(^|\/)\.(?:windsurf|devin|clinerules)\/workflows\/[^/]*\.(?:md|markdown|ya?ml)$/i, kind: 'command' },

  { re: /(^|\/)\.(?:claude|cursor|windsurf|roo|kilocode)\/agents\/[^/]+\.(?:md|ya?ml|json)$/i, kind: 'subagent' },
  { re: /(^|\/)\.github\/(?:agents|chatmodes)\/[^/]+\.md$/i, kind: 'subagent' },

  { re: /(^|\/)\.well-known\/agent(?:-card)?\.json$/i, kind: 'agent-card' },
  { re: /(^|\/)agent[-_]card\.json$/i, kind: 'agent-card' },

  { re: /(^|\/)\.claude-plugin\/(?:plugin|marketplace)\.json$/i, kind: 'plugin' },
  { re: /(^|\/)gemini-extension\.json$/i, kind: 'plugin' },
  { re: /(^|\/)(?:mcpb|dxt)\.json$/i, kind: 'extension' },

  { re: /(^|\/)(?:CLAUDE|AGENTS|AGENT|GEMINI|QWEN|KIRO|AMAZONQ|CONVENTIONS)(?:\.local|\.override)?\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.(?:cursor|aider|continue|kilocode|roo|trae|augment|windsurf|qoder|factory|opencode)rules$/i, kind: 'rules' },
  { re: /(^|\/)\.roorules(?:-[\w-]+)?$/i, kind: 'rules' },
  { re: /(^|\/)\.goosehints$/i, kind: 'rules' },
  { re: /(^|\/)\.augment-guidelines$/i, kind: 'rules' },
  { re: /(^|\/)global_rules\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.rules$/i, kind: 'rules' },
  { re: /(^|\/)\.aider\.conf\.ya?ml$/i, kind: 'rules' },
  { re: /(^|\/)\.github\/copilot-instructions\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.github\/instructions\/.+\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.copilot\/(?:copilot-instructions\.md|instructions\/.+\.md)$/i, kind: 'rules' },
  { re: /(^|\/)\.cursor\/rules\/.+\.(?:mdc|md)$/i, kind: 'rules' },
  { re: /(^|\/)\.claude\/rules\/.+\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.clinerules(?:\/[^/]+\.(?:md|txt))?$/i, kind: 'rules' },
  { re: /(^|\/)cline\/rules\/.+\.(?:md|txt)$/i, kind: 'rules' },
  { re: /(^|\/)\.(?:kilocode|roo|trae|junie|windsurf|augment|kiro|devin|amp|zed|goose|opencode|crush)\/(?:rules?|guidelines?|steering|memories)(?:\/.+)?\.(?:md|mdc|txt)$/i, kind: 'rules' },
  { re: /(^|\/)\.(?:roo|kilocode)\/rules-[\w-]+\/.+\.(?:md|mdc|txt)$/i, kind: 'rules' },
  { re: /(^|\/)\.continue\/rules\/.+\.(?:md|ya?ml)$/i, kind: 'rules' },
  { re: /(^|\/)\.amazonq\/rules\/.+\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.qwen\/team-memory\/.+\.(?:md|txt)$/i, kind: 'rules' },
  { re: /(^|\/)\.junie\/(?:playbook|guidelines)\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.trae\/(?:rules\/)?(?:project|user)_rules\.md$/i, kind: 'rules' },
  { re: /(^|\/)\.claude\/output-styles\/.+\.md$/i, kind: 'rules' },

  { re: /(^|\/)\.codex\/config\.(?:toml|json)$/i, kind: 'agent-config' },
  { re: /(^|\/)\.(?:gemini|qwen)\/settings\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)\.cursor\/(?:cli-config|cli|permissions|sandbox|settings)\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)\.vscode\/settings\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)\.kiro\/settings\/[^/]+\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)\.(?:copilot|roo|kilocode|amazonq|zed|opencode|augment|junie|trae)\/(?:settings|config)(?:\.local)?\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)\.github\/copilot\/settings(?:\.local)?\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)opencode\.jsonc?$/i, kind: 'agent-config' },
  { re: /(^|\/)crush\.json$/i, kind: 'agent-config' },
  { re: /(^|\/)goose\/config\.ya?ml$/i, kind: 'agent-config' },
  { re: /(^|\/)\.continue\/config\.(?:json|ya?ml)$/i, kind: 'agent-config' },

  { re: /(^|\/)(?:\.devcontainer\/)?devcontainer\.json$/i, kind: 'dev-environment' },
  { re: /(^|\/)\.devcontainer\/[^/]+\/devcontainer\.json$/i, kind: 'dev-environment' },

  { re: /(^|\/)[\w.-]*modelfile$/i, kind: 'model-config' },
  { re: /(^|\/)(?:tokenizer_config|generation_config)\.json$/i, kind: 'model-config' },
];

export const CONTENT_ONLY_KINDS                                  = [
  'automation', 'guardrail', 'tool-manifest', 'prompt-template',
  'agent-memory', 'exec-script', 'env-secret-file', 'other-artifact',

  'workflow',
];

export function normalizeArtifactPath(path        )         {
  const raw = String(path ?? '').replace(/\\/g, '/').trim();
  if (!raw) return '';
  const lead = raw.startsWith('/') ? '/' : '';
  const drive = /^[a-zA-Z]:\//.test(raw) ? raw.slice(0, 3) : '';
  const out           = [];
  for (const seg of (drive ? raw.slice(3) : raw).split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (out.length && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
      continue;
    }
    out.push(seg);
  }
  return (drive || lead) + out.join('/');
}

export function artifactKindFor(path        )                              {
  const p = normalizeArtifactPath(path);
  if (!p) return null;
  for (const { re, kind } of ARTIFACT_PATHS) if (re.test(p)) return kind;
  return null;
}

