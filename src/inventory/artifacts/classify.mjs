import path from 'node:path';
import { extOf } from './limits.mjs';
import { SETTINGS_BASENAMES } from './marketplaces.mjs';
import { isInstructionPath } from '../../detect/signals/instruction-paths.mjs';
import { PLUGIN_MANIFEST_RE } from './plugins.mjs';
import { EXTENSION_MANIFEST_RE } from './extensions.mjs';

export const COMMAND_PATH_RE = /(^|\/)commands?\/|(^|\/)\.[\w-]+\/prompts?\/|(^|\/)\.(?:windsurf|devin|clinerules)\/workflows\//;

/* mirrors the server's detector - see instruction-pass.ts. Kept apart from
   COMMAND_PATH_RE, whose `commands?/` arm would claim every commands/*.yaml. */
export const SKILL_ENTRY_RE = /(^|\/)\.(?:claude|cursor|windsurf|codex|agents)\/skills\/.+\.(?:md|markdown)$/;
export const WORKFLOW_COMMAND_RE = /(^|\/)\.(?:windsurf|devin|clinerules)\/workflows\/[^/]*\.(?:md|markdown|ya?ml)$/;
export const CHATMODE_DIR_RE = /(^|\/)chatmodes?\//;

export function classify(rel, vendor) {
  const lower = rel.toLowerCase().replace(/\\/g, '/');
  const base = path.basename(lower);
  const ext = extOf(lower);

  if (vendor === 'claude-desktop') return EXTENSION_MANIFEST_RE.test(lower) ? 'extension' : null;
  if (PLUGIN_MANIFEST_RE.test(lower)) return 'plugin';
  if (base === 'skill.md' || SKILL_ENTRY_RE.test(lower)) return 'skill';
  if (SETTINGS_BASENAMES.has(base)) return 'hook';
  if (vendor === 'copilot' && ext === 'json' && /(^|\/)hooks\/[^/]+\.json$/.test(lower)) return 'hook';
  if (/(^|\/)(sub)?agents?\//.test(lower) && ext === 'md') return 'subagent';
  if (CHATMODE_DIR_RE.test(lower) && ext === 'md') return 'subagent';
  if (COMMAND_PATH_RE.test(lower) && !/(^|\/)\.github\/workflows\//.test(lower) && (ext === 'md' || ext === 'toml' || WORKFLOW_COMMAND_RE.test(lower))) {

    if (vendor === 'copilot' && !/(^|\/)(prompts|chatmodes)\//.test(lower)) return null;
    return 'command';
  }
  if (lower.split('/').length <= 5 && !/(^|\/)(extensions|plugins|marketplaces|node_modules|cache|projects)\//.test(lower) && isInstructionPath(lower)) return 'rules';
  return null;
}

export function declaredName(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  const n = /^name:\s*(.+)$/m.exec(m[1]);
  return n ? n[1].trim().replace(/^["']|["']$/g, '').slice(0, 120) || null : null;
}
