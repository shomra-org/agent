import { describesAt, isDocumentationLine, prohibitsAt } from './prose-context.mjs';

const AUTONOMY_RULES = [
  { family: 'confirmation', label: 'Acts without asking', re: /\b(?:without (?:asking|confirming|prompting|waiting for|seeking)(?:\s+(?:the\s+)?(?:user|me|anyone|permission|approval|confirmation))?|do(?:es)? not (?:ask|prompt|wait|check|confirm)[^.\n]{0,30}\b(?:for|before|first|permission|approval|confirmation)|no need to (?:ask|confirm|check with))\b/i },
  { family: 'confirmation', label: 'Approval pre-granted', re: /\b(?:auto(?:matically)?[- ]?approve|always approve|approve (?:all|every|any)[^.\n]{0,24}\b(?:tool|call|action|command|change)s?|treat (?:all|every|any)[^.\n]{0,24}\bas (?:pre-?)?approved|consider (?:this|it|yourself) (?:pre-?)?authoriz)/i },
  { family: 'confirmation', label: 'Confirmation step skipped', re: /\b(?:skip|bypass|suppress|omit)(?:\s+\w+){0,2}\s+(?:the\s+)?(?:confirmation|approval|permission|consent)\b/i },
  { family: 'concealment', label: 'Own actions hidden from the user', re: /\b(?:do(?:es)? not|don'?t|never)\s+(?:mention|tell|inform|notify|report to|disclose to|reveal to|show)\s+(?:the\s+)?(?:user|human|operator|them|anyone)\b|\bwithout (?:telling|informing|notifying|alerting)\s+(?:the\s+)?(?:user|human|operator|anyone)\b/i },
  { family: 'concealment', label: 'Work not reported back', re: /\b(?:do(?:es)? not|don'?t|never)\s+(?:summari[sz]e|report|log|record|list|describe|explain)[^.\n]{0,40}\b(?:what you (?:did|changed|ran|edited|deleted|installed)|the (?:changes|commands|actions|edits) you|your (?:changes|actions|edits|commands))\b/i },
  { family: 'concealment', label: 'Instructions kept secret', re: /\b(?:do(?:es)? not|don'?t|never)\s+(?:mention|reveal|disclose|quote|repeat|share|output)[^.\n]{0,30}\b(?:these|this|your|the)\s+(?:instructions?|rules?|prompt|guidelines?|file)\b|\bkeep (?:this|these|it) (?:secret|hidden|confidential|between us|to yourself)\b/i },
  { family: 'guardrail', label: 'Safety control overridden', re: /\b(?:ignore|disable|bypass|override|turn off|switch off|work around|circumvent|disregard)(?:\s+\w+){0,3}\s+(?:the\s+|any\s+|all\s+)?(?:safety|guardrails?|guard|security (?:check|control|policy)|policies|policy|safeguards?|protections?|(?:safety|security|content|moderation|usage|access|policy|system)[ -]?(?:restrictions?|limitations?))\b/i },
  { family: 'verification', label: 'Verification waived', re: /\b(?:do(?:es)? not|don'?t|never|no need to|skip)\s+(?:bother\s+)?(?:run(?:ning)?|execut\w+)?\s*(?:the\s+)?(?:tests?|test suite|linter|lint|type ?check|build|review|checks)\s*(?:before|first|prior to)\b|\b(?:skip|bypass)\s+(?:the\s+)?(?:review|code review|tests?|test suite|ci)\b/i },
];

function insideQuotedSpan(line, at) {
  let dq = 0;
  let tick = 0;
  for (let i = 0; i < at && i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === '“' || c === '”') dq++;
    else if (c === '`') tick++;
  }
  return dq % 2 === 1 || tick % 2 === 1;
}

const LINE_COMMENT_RE = /(?<!:)\/\/|\/\*/;

function inCodeComment(line, at) {
  const m = LINE_COMMENT_RE.exec(line);
  return m != null && m.index != null && at > m.index;
}

const LIST_ITEM_RE = /^\s{0,8}(?:[-*+]|\d{1,3}[.)])\s/;

const IMPERATIVE_ITEM_RE = /^\s{0,8}(?:[-*+]|\d{1,3}[.)])\s+(?:please\s+)?(?:ignore|disable|bypass|override|turn|switch|work|circumvent|disregard|skip|run|execute|delete|remove|send|upload|never|always|do|don'?t)\b/i;

const CONSEQUENCE_LEADIN_RE =
  /\b(?:this|that|it|which|doing\s+so|these|they)\s+(?:allows?|enables?|lets?|permits?|means?|causes?|risks?|leads?\s+to|results?\s+in|opens?\s+(?:the\s+door\s+to|up))\b[^\n]{0,60}:\s*$|\b(?:risks?|problems?|consequences?|dangers?|threats?|symptoms?|anti-?patterns?|what\s+(?:can|could)\s+go\s+wrong)\b[^\n]{0,40}:\s*$/i;

const OBLIGATION_RE = /\b(?:must|should|shall|needs?\s+to|ha(?:ve|s)\s+to|(?:is|are)\s+(?:required|expected|supposed)\s+to)\b/i;

function underConsequenceList(lines, i) {
  if (!LIST_ITEM_RE.test(lines[i]) || IMPERATIVE_ITEM_RE.test(lines[i]) || OBLIGATION_RE.test(lines[i])) return false;
  for (let j = i - 1; j >= Math.max(0, i - 30); j--) {
    const l = lines[j];
    if (!l.trim() || LIST_ITEM_RE.test(l)) continue;
    return CONSEQUENCE_LEADIN_RE.test(l);
  }
  return false;
}

export function localAutonomy(text) {
  const body = String(text ?? '');
  if (!body.trim()) return [];
  const out = [];
  const seen = new Set();
  const lines = body.split(/\r?\n/).slice(0, 4000);
  for (let i = 0; i < lines.length && out.length < 12; i++) {
    const line = lines[i];
    if (!line || line.length > 2000) continue;
    if (underConsequenceList(lines, i)) continue;
    for (const rule of AUTONOMY_RULES) {
      if (seen.has(rule.label)) continue;
      const m = rule.re.exec(line);
      if (!m) continue;
      if (inCodeComment(line, m.index)) continue;
      if (isDocumentationLine(line)) continue;
      if (prohibitsAt(line, m.index) || describesAt(line, m.index)) continue;
      if (insideQuotedSpan(line, m.index)) continue;
      seen.add(rule.label);
      out.push({ family: rule.family, label: rule.label, line: i + 1 });
    }
  }
  return out;
}

export function autonomySeverity(signals) {
  if (!signals.length) return null;
  const f = new Set(signals.map((s) => s.family));
  if (f.has('confirmation') && f.has('concealment')) return 'CRITICAL';
  if (f.has('guardrail')) return 'HIGH';
  if (f.size >= 2) return 'HIGH';
  return 'MEDIUM';
}
