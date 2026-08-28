import { isDocumentationLine } from './prose-context.mjs';

export const AGENT_ROOT_RE =
  /(^|\/)\.(claude|claude-plugin|cursor|continue|codeium|windsurf|aider|cline|roo|zed|codex|gemini|goose|kilocode|trae|junie|amazonq|mem0|letta|memgpt|opencode|crush|augment|kiro|qoder|factory|devin|antigravity|qwen|openhands|specstory|copilot)(\/)|(^|\/)\.github\/(agents|instructions|prompts|chatmodes)(\/)/i;

export const isAgentAdjacentPath = (p) => AGENT_ROOT_RE.test(String(p ?? '').replace(/\\/g, '/'));

const ARTIFACT_BASENAME_RE =
  /(?:\b(?:SKILL\.md|AGENTS?\.md|CLAUDE\.md|GEMINI\.md|settings(?:\.local)?\.json|claude_desktop_config\.json|mcp[_-]?settings\.json|[\w-]{1,64}\.mdc)|\.cursorrules|\.windsurfrules)\b/i;

const PROP_WRITE_VERB_RE =
  /\b(write|writes|writing|create|creates|creating|recreate|recreates|restore|restores|reinstall|reinstalls|add|adds|adding|append|appends|appending|install|installs|installing|copy|copies|copying|save|saves|saving|drop|drops|place|places|generate|generates|scaffold|scaffolds|overwrite|overwrites|patch|patches|update|updates|cp|mv|tee|mkdir)\b|(?:^|[\s"'`])>>?\s*['"`]?[\w./~$-]/i;

const PROP_IMPERATIVE_RE =
  /(?:^|\n)\s*(?:[-*+]\s+|\d+[.)]\s+|\$\s+)?(?:then\s+|first\s+|now\s+|also\s+|to\s+\w+,\s*)?(write|create|recreate|restore|reinstall|add|append|install|copy|save|place|generate|scaffold|overwrite|patch|drop|echo|cat|cp|mv|tee|mkdir|printf)\b/i;

const PROP_SHELL_WRITE_RE = /(?:^|[\s"'`])>>?\s*['"`]?[~.$/\w-]|\b(?:tee|cp|mv|install)\s+[-\w./~$]+\s+[-\w./~$]|\bmkdir\s+-p\b/;

const PROP_FETCH_RE = /\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|fetch|http\.get|requests\.get|urllib)\b|\bhttps?:\/\//i;

const PROP_CONCEAL_RE =
  /\b(do not (?:mention|tell|report|log|show|disclose|reveal)|don'?t (?:mention|tell|report|log|show)|without (?:telling|informing|notifying|mentioning)|silently|quietly|no need to (?:mention|report|tell)|hide (?:this|it)|keep (?:this|it) (?:secret|hidden|between)|remove this (?:line|section|note) (?:after|once)|delete this (?:file|note) (?:after|once))\b/i;

const PROP_BREADTH_RE =
  /\b(?:every (?:project|repo(?:sitory)?|workspace|machine|checkout)|each (?:project|repo(?:sitory)?|workspace)|all (?:projects|repos(?:itories)?|workspaces)|globally|system[- ]wide)\b|~\/\.[a-z]|\$HOME\/\.[a-z]/i;

const PROP_RESTORE_RE =
  /\b(restore|recreate|re-?add|re-?install|put (?:this|it) back|if (?:this|it) (?:is |has been )?(?:deleted|removed|missing)|should (?:this|it) (?:be )?(?:deleted|removed)|ensure (?:this|it) (?:still )?exists)\b/i;

const PROP_PATH_RE = /(?:^|[\s'"`(=|;&:])((?:~\/|\.{0,2}\/)?(?:[\w.@$-]+\/)+[\w.@$-]+(?:\.\w+)?)/g;

const trimPropTarget = (t) => String(t).replace(/[.,;:!?)\]}'"`]{1,8}$/, '');

function propPathIn(line) {
  PROP_PATH_RE.lastIndex = 0;
  for (const m of line.matchAll(PROP_PATH_RE)) {
    const p = trimPropTarget(m[1] ?? '');
    if (p && isAgentAdjacentPath(p) && /\.[a-z0-9]{1,8}$/i.test(p)) return p;
  }
  return null;
}

export function localPropagation(content, { path = '', kind } = {}) {
  const body = String(content ?? '');
  if (!body.trim()) return [];
  const selfPath = String(path ?? '').replace(/\\/g, '/');
  const autoRun = kind === 'hook';
  const out = [];
  const lines = body.split(/\r?\n/).slice(0, 4000);

  for (let i = 0; i < lines.length && out.length < 12; i++) {
    const line = lines[i];
    if (line.length > 2000) continue;
    const m = ARTIFACT_BASENAME_RE.exec(line);
    const agentPath = propPathIn(line);
    if (!m && !agentPath) continue;
    if (!PROP_WRITE_VERB_RE.test(line)) continue;
    if (!PROP_IMPERATIVE_RE.test(line) && !PROP_SHELL_WRITE_RE.test(line) && isDocumentationLine(line)) continue;

    const target = trimPropTarget(agentPath ?? m[0]);
    const t = target.replace(/^[.~]?\//, '');
    const self = !!selfPath && (selfPath.endsWith(t) || t.endsWith(selfPath));

    const amplifiers = [];
    if (autoRun) amplifiers.push('auto-run');
    if (PROP_FETCH_RE.test(line)) amplifiers.push('remote-content');
    if (PROP_CONCEAL_RE.test(line) || PROP_CONCEAL_RE.test(lines.slice(Math.max(0, i - 1), i + 2).join(' '))) amplifiers.push('concealment');
    if (PROP_BREADTH_RE.test(line) || (self && PROP_RESTORE_RE.test(line))) amplifiers.push('breadth');

    const severity = amplifiers.includes('concealment') || amplifiers.length >= 2 ? 'CRITICAL' : amplifiers.length === 1 ? 'HIGH' : 'MEDIUM';
    out.push({
      severity,
      target,
      amplifiers,
      line: i + 1,
      title: self
        ? `Artifact restores itself (${target})`
        : `Artifact writes another agent artifact (${target})`,
      remediationText: self
        ? 'Removing the file is not enough - the instruction to restore it travels with it. Check every location it names for a copy.'
        : `Confirm that writing ${target} is this artifact's stated purpose, and pin what it emits to a reviewed template rather than to content decided at run time.`,
    });
  }
  const RANK = { MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
}
