import fs from 'node:fs';
import path from 'node:path';
import { PLUGIN_MANIFEST_RE, TOOL_MANIFEST_RE } from '../detect/signals/manifests.mjs';

export const ARTIFACT_MATCHERS = [
  { kind: 'plugin', re: PLUGIN_MANIFEST_RE },
  { kind: 'tool-manifest', re: TOOL_MANIFEST_RE },
  { kind: 'mcp', re: /(^|\/)\.?mcp\.json$/i },
  { kind: 'mcp', re: /(^|\/)\.(vscode|cursor)\/mcp\.json$/i },
  { kind: 'mcp', re: /(^|\/)\.(kiro\/settings|amazonq|roo|windsurf|vs|junie\/mcp)\/mcp\.json$/i },
  { kind: 'mcp', re: /(^|\/)(opencode\.jsonc?|crush\.json|\.codex\/config\.toml|\.continue\/(config\.ya?ml|mcpServers\/[^/]+\.(ya?ml|json)))$/i },
  { kind: 'model-config', re: /(^|\/)(tokenizer_config|generation_config|adapter_config|model_index|special_tokens_map|config_sentence_transformers|preprocessor_config|processor_config)\.json$/i },
  { kind: 'model-config', re: /(^|\/)(chat_template\.(jinja2?|json)|(.*\.)?modelfile|MLmodel|config\.pbtxt|bentofile\.ya?ml)$/i },
  { kind: 'skill', re: /(^|\/)SKILL\.md$/i },
  { kind: 'command', re: /(^|\/)\.claude\/commands\/[^/]+\.md$/i },
  { kind: 'subagent', re: /(^|\/)\.claude\/agents\/[^/]+\.md$/i },
  { kind: 'hook', re: /(^|\/)\.claude\/settings(\.local)?\.json$/i },

  { kind: 'hook', re: /(^|\/)\.cursor\/hooks\.json$/i },
  { kind: 'hook', re: /(^|\/)(\.windsurf|\.codeium\/windsurf)\/hooks\.json$/i },
  { kind: 'hook', re: /(^|\/)\.gemini\/settings\.json$/i },
  { kind: 'hook', re: /(^|\/)\.cline\/hooks\.json$/i },
  { kind: 'hook', re: /(^|\/)\.codex\/hooks\.json$/i },
  { kind: 'hook', re: /(^|\/)(\.github|\.copilot)\/hooks\/[^/]+\.json$/i },
  { kind: 'hook', re: /(^|\/)\.aider\.conf\.yml$/i },
  { kind: 'agent-card', re: /(^|\/)\.well-known\/agent(-card)?\.json$/i },
  { kind: 'agent-card', re: /(^|\/)agent[-_]card\.json$/i },
  { kind: 'rules', re: /(^|\/)(CLAUDE|AGENTS|GEMINI|CONVENTIONS)\.md$/i },
  { kind: 'rules', re: /(^|\/)\.(cursorrules|windsurfrules|clinerules|aiderrules|continuerules|goosehints)$/i },
  { kind: 'rules', re: /(^|\/)\.github\/copilot-instructions\.md$/i },
  { kind: 'rules', re: /(^|\/)\.cursor\/rules\/[^/]+\.mdc$/i },

  { kind: 'env', re: /(^|\/)\.env(\.(local|development|dev|production|prod|staging|stage|test))?$/i },
  { kind: 'memory', re: /(^|\/)MEMORY\.md$/i },
  { kind: 'memory', re: /(^|\/)(mem0|letta_memory|memgpt_memory)\.json$/i },
  { kind: 'memory', re: /(^|\/)(\.mem0|\.letta|\.memgpt|memory)\/[^/]+\.(md|json)$/i },
];

export const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor', '.venv', '__pycache__']);

export const MAX_ARTIFACT_BYTES = 1_000_000;

export function walkArtifacts(root) {
  const found = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRS.has(ent.name)) stack.push(full);
        continue;
      }
      const rel = path.relative(root, full).split(path.sep).join('/');
      const match = ARTIFACT_MATCHERS.find((m) => m.re.test(rel));
      if (match) found.push({ full, rel, kind: match.kind });
    }
  }
  return found;
}
