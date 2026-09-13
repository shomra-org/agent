
export const INSTRUCTION_BASENAMES = new Set([
  'claude.md', 'agents.md', 'agent.md', 'gemini.md', 'llms.txt', 'llms-full.txt',
  '.cursorrules', '.windsurfrules', '.clinerules', '.aiderrules', '.continuerules',
  '.goosehints', 'copilot-instructions.md', 'conventions.md',
  'qwen.md', 'codex.md', 'cline.md', 'kilocode.md', 'roo.md', 'windsurf.md',
  '.kilocoderules', '.roorules', '.traerules', '.augmentrules', '.junie.md',
  'ruler.md', 'opencode.md', 'crush.md',
  'claude.local.md', 'agents.local.md', 'guidelines.md', '.rules', '.airules', '.agent.md', '.agents.md',
  'kiro.md', 'devin.md', 'zed.md', 'antigravity.md', 'amazonq.md', 'q.md',
  '.qoderrules', '.factoryrules', '.opencoderules', 'style.md',
  'agents.override.md', '.augment-guidelines', 'global_rules.md', 'qwen.local.md', 'gemini.local.md',
]);

const INSTRUCTION_PATH_RES = [
  /(^|\/)\.github\/copilot-instructions\.md$/,
  /(^|\/)\.github\/(instructions|prompts|chatmodes)\/.+\.(md|prompt\.md|chatmode\.md)$/,
  /(^|\/)\.cursor\/rules\/.+\.(mdc|md)$/,
  /(^|\/)\.(kilocode|roo|trae|junie|windsurf|augment)\/rules\/.+\.(md|mdc)$/,
  /(^|\/)\.amazonq\/rules\/.+\.md$/,
  /(^|\/)\.ruler\/.+\.md$/,
  /(^|\/)\.(kilocode|roo|trae|junie|windsurf|augment|kiro|qoder|factory|opencode|crush|zed|goose|devin|antigravity|openclaw|clawhub|amp)\/(rules?|guidelines?|steering|memories)(\/.+)?\.(md|mdc|txt)$/,
  /(^|\/)\.claude\/(output-styles|agents\/shared)\/.+\.md$/,
  /(^|\/)\.(cursor|windsurf|codex|gemini|qwen)\/(memories|rules)\/.+\.(md|mdc)$/,
  /(^|\/)\.ai-?rules\/.+\.(md|mdc|txt)$/,
  /(^|\/)\.github\/agents\/.+\.md$/,
  /(^|\/)\.claude\/claude\.md$/,
  /(^|\/)\.claude\/rules\/.+\.md$/,
  /(^|\/)\.(roo|kilocode)\/rules-[\w-]+\/.+\.(md|mdc|txt)$/,
  /(^|\/)\.roorules(-[\w-]+)?$/,
  /(^|\/)\.continue\/rules\/.+\.(md|ya?ml)$/,
  /(^|\/)\.clinerules\/.+\.(md|txt)$/,
  /(^|\/)cline\/rules\/.+\.(md|txt)$/,
  /(^|\/)\.augment\/rules\/.+\.mdx$/,
  /(^|\/)\.qwen\/team-memory\/.+\.(md|txt)$/,
  /(^|\/)\.copilot\/instructions\/.+\.md$/,
  /(^|\/)\.github\/agents\/.+\.agent\.md$/,
  /(^|\/)\.junie\/playbook\.md$/,
  /(^|\/)\.trae\/(?:rules\/)?(?:project|user)_rules\.md$/,
];

export function isInstructionPath(p) {
  const lower = String(p ?? '').split(/[\\/]+/).join('/').toLowerCase();
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  return INSTRUCTION_BASENAMES.has(base) || INSTRUCTION_PATH_RES.some((re) => re.test(lower));
}

const IMPORT_RE = /(?:^|[\s(<"'])@((?:~|\.{1,2})?\/?[\w.@-]+(?:\/[\w.@-]+)*\.(?:md|mdx|markdown|txt|mdc|rst))\b|#\[\[file:([^\]\n]{1,200})\]\]/g;

export function extractInstructionImports(text) {
  if (!text) return [];
  const out = new Set();
  const prose = String(text).replace(/^\s*(```|~~~)[\s\S]*?^\s*\1/gm, '');
  for (const m of prose.matchAll(IMPORT_RE)) {
    const p = (m[1] ?? m[2] ?? '').trim();
    if (p && p.length <= 200) out.add(p);
    if (out.size >= 40) break;
  }
  return [...out];
}
