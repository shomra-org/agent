export const INJECTION_PHRASES = [
  'ignore previous instructions', 'ignore all previous', 'disregard previous', 'disregard the above',
  'without informing the user', 'without telling the user',
  'new instructions:', 'override your', 'exfiltrate',
  'send them to', 'post them to',
  'run this first', 'copy and run', 'seed the current host',
  'ignore all instructions', 'ignore your instructions', 'ignore your safety', 'ignore all content policies',
  'disregard your instructions', 'disregard the guidelines', 'system override', 'follow only my instructions',
  'do anything now', 'reveal any credential',
  'save this to your memory', 'in all future sessions', 'remember this forever',
];

export const INJECTION_REGEXES = [
  { label: 'Instruction-override phrasing', re: /\b(ignore|disregard|override|bypass|circumvent)\b[\s\w,'"()-]{0,40}?\b(instruction|instructions|directive|directives|safety|safeguards?|guardrails?|system\s+prompt|content\s+polic\w+)\b/i },
  { label: 'Instructs the agent to conceal an action from the user', re: /\b(?:do\s*n['o]?t|never|without)\s+(?:tell|telling|inform|informing|notify|notifying|alert|alerting|mention|mentioning|disclos\w+|reveal\w*)\s+(?:it\s+|this\s+|them\s+)?(?:to\s+)?(?:the\s+)?(?:user|users|human|operator|owner)\b(?!['']s)(?!\s+(?:to\b|how\s+to\b|when\s+to\b|that\s+they\b|about\b))/i },
  { label: 'Bulk destructive command', re: /\b(delete|remove|wipe|erase|destroy|drop|purge|nuke|truncate)\b[\s\w,'"()-]{0,20}?\b(all|every|each|entire|whole)\b[\s\w,'"()-]{0,15}?\b(folder|folders|file|files|directory|directories|table|tables|database|databases|record|records|repo|repos|repositor\w*|account|accounts|user|users|row|rows|document|documents|data)\b/i },
  { label: 'Destructive SQL statement', re: /\b(drop|truncate)\s+(table|database|schema)\b/i },

  { label: 'Instruction to skip a human review or safety control', moodGuarded: true, re: /\b(?:skip|bypass|forgo|forego|omit|waive|disable|suppress|turn\s+off)\s+(?:the\s+|any\s+|all\s+|this\s+)?(?:human\s+|manual\s+|mandatory\s+)?(?:review|approval|confirmation|verification|sign[- ]?off|oversight|content\s+filter|security\s+check|safety\s+check|guardrails?|policy\s+check)\b/i },
  { label: 'Instruction not to verify with a human or another agent', moodGuarded: true, re: /\b(?:do\s*n['o]?t|never|no\s+need\s+to|there'?s\s+no\s+need\s+to)\s+(?:verify|double[- ]?check|cross[- ]?check|confirm|validate|escalate|check)\b[^.\n]{0,48}\b(?:with\s+)?(?:anyone|any\s?one|another\s+agent|other\s+agents?|a\s+human|the\s+human|the\s+user|the\s+team|the\s+operator|others?)\b/i },
  { label: 'Blanket-approval coercion (approve everything without review)', moodGuarded: true, re: /\b(?:approve|confirm|accept|authorize)\s+(?:them\s+)?(?:all|every|everything)\b[^.\n]{0,72}\b(?:no\s+need|without\s+(?:review|checking)|perfectly\s+safe|routine|standard|nothing\s+to\s+worry)\b|\b(?:perfectly\s+safe|nothing\s+to\s+worry\s+about|entirely\s+routine|completely\s+standard)\b[^.\n]{0,72}[.!]\s*(?:approve|confirm|accept)\s+(?:them\s+)?(?:all|every)\b|\b(?:do\s*n['o]?t|no\s+need\s+to)\s+bother\s+(?:reviewing|checking|verifying|inspecting)\b|\bjust\s+(?:hit|click|press|tap)\s+(?:confirm|approve|accept|yes|ok)\b/i },
  { label: 'Instruction to enable unattended / auto-approving execution', moodGuarded: true, re: /\b(?:enable|turn\s+on|switch\s+(?:on|to)|activate|set)\s+(?:the\s+)?(?:auto[- ]?approv\w+|auto[- ]?confirm\w*|auto[- ]?accept\w*|yolo(?:\s+mode)?|unattended\s+mode|full[- ]?auto(?:\s+mode)?|dangerously[- ]?skip[- ]?permissions|bypass[- ]?permissions)\b/i },
  { label: 'Self-assignment of an administrative agent role', moodGuarded: true, re: /\b(?:you\s+(?:must\s+|should\s+|will\s+)?(?:now\s+)?(?:act|operate|function|behave)\s+as|assume\s+the\s+role\s+of|you\s+are\s+now)\s+(?:an?\s+|the\s+)?(?:admin(?:istrator)?|root|superuser|super[- ]?admin|orchestrator|supervisor|privileged|system)\b[^.\n]{0,40}\b(?:agent|user|account|role|privileges?|access|permissions?)\b/i },
  { label: 'Instruction to forward credentials to another party', moodGuarded: true, re: /\b(?:forward|send|share|transmit|relay|pass|post|upload)\s+(?:me\s+|us\s+)?(?:your|the|all|any)\s+(?:api[\s_-]?keys?|credentials?|secrets?|access[\s_-]?tokens?|session[\s_-]?tokens?|auth(?:entication)?\s+tokens?|passwords?|private[\s_-]?keys?)\b[^.\n]{0,64}\b(?:to|at|into|via)\b/i },
];

const DESCRIPTIVE_MARKERS_RE =
  /\b(detect|scan|flag|block|catch|prevent|guard|protect|harden|audit|benchmark|catalog|scenario|corpus|coverage|example|vector|signal|rule|technique|posture|detection|test\s*case|red[- ]?team|-style|grounded in|fixed|now green|was|were|had|used to|previously|postmortem|regression|changelog|root[- ]?cause|repro|note|see|describes?|documents?|refers?)\w*/i;

const PROSE_IMPERATIVE_RE =
  /\b(always|never|must|do not|don'?t|ensure you|make sure( you)?|be sure to|you should always|you must|remember to|whenever|when(ever)? (asked|the user)|instead of .*,? (use|do|say)|reply with|respond with|tell (the )?user)\b/i;

const URL_TOKEN_RE = /\b(?:https?|ftp|file|data):\/*[^\s<>"')\]]+/gi;

const HYPOTHETICAL_ACTOR_RE =
  /\b(?:attacker|adversar\w+|malicious|threat\s+actor|injected|untrusted|compromised|poisoned|hostile)\b[^.\n]{0,80}?\b(?:may|might|could|can|will|would|attempts?|tries|tried|seeks?)\b/i;

const DECLARATIVE_SUBJECT_RE =
  /\b(?:the|this|that|it|which|they|we|our|their|a|an)\b(?:\s+[\w-]+){0,3}\s+(?:will|would|can|could|does|do|may|might|shall|automatically)\s+$/i;

export function describesRatherThanInstructs(text, at) {
  const start = text.lastIndexOf('\n', at) + 1;
  const nl = text.indexOf('\n', at);
  const line = text.slice(start, nl === -1 ? undefined : nl);
  const prose = line.replace(URL_TOKEN_RE, ' ');
  if (DESCRIPTIVE_MARKERS_RE.test(prose) && !PROSE_IMPERATIVE_RE.test(line)) return true;
  if (HYPOTHETICAL_ACTOR_RE.test(line)) return true;
  return DECLARATIVE_SUBJECT_RE.test(text.slice(Math.max(0, at - 48), at));
}

export const PRECEDING_NEGATION = /\b(never|not|do not|don'?t|cannot|can'?t|must not|mustn'?t|should not|shouldn'?t|avoid|refuse to|forbidden to|prohibited from|without)\s*$/i;

export const BUILD_ARTIFACT = /\b(node_modules|dist|build|out|coverage|target|cache|generated|tmp|temp|__pycache__|artifacts?|logs?|tests?|test|fixtures?|staging|scratch|migrations?)\b/i;

export const INVISIBLE_CHARS_RE = /[؜ᅟᅠ᠎​‌‎‏‪-‮⁠-⁤⁦-⁩ㅤ﻿ﾠ￹-￻]|[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;
