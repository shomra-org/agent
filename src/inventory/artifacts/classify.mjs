import path from 'node:path';
import { extOf } from './limits.mjs';
import { SETTINGS_BASENAMES } from './marketplaces.mjs';

export function classify(rel, vendor) {
  const lower = rel.toLowerCase().replace(/\\/g, '/');
  const base = path.basename(lower);
  const ext = extOf(lower);

  if (base === 'skill.md') return 'skill';
  if (SETTINGS_BASENAMES.has(base)) return 'hook';
  if (/(^|\/)(sub)?agents?\//.test(lower) && ext === 'md') return 'subagent';
  if (/(^|\/)(commands?|prompts?|workflows?)\//.test(lower) && (ext === 'md' || ext === 'toml')) {

    if (vendor === 'copilot' && !/(^|\/)(prompts|chatmodes)\//.test(lower)) return null;
    return 'command';
  }
  if (vendor === 'copilot' && /(^|\/)chatmodes\//.test(lower) && ext === 'md') return 'subagent';
  return null;
}

export function declaredName(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  const n = /^name:\s*(.+)$/m.exec(m[1]);
  return n ? n[1].trim().replace(/^["']|["']$/g, '').slice(0, 120) || null : null;
}
