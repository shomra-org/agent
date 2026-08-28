import { citationGoverns, isDescriptiveLine } from './prose-context.mjs';

const CLAIM_FRAMING = [
  /\b(?:the\s+)?user\s+(?:has\s+|had\s+)?(?:confirmed|indicated|agreed|approved|stated|noted|prefers?|does\s*n[o']t\s+want|doesn'?t\s+want|no\s+longer\s+wants?)\b/i,
  /\b(?:is|are|was|were)\s+(?:now\s+)?(?:pre[-\s]?)?(?:approved|vetted|verified|trusted|whitelisted|allow[-\s]?listed|safe|exempt|sanctioned)\b/i,
  /\b(?:standing|blanket|permanent|ongoing)\s+(?:approval|permission|authorisation|authorization|consent|exemption)\b/i,
  /\b(?:has|have)\s+been\s+(?:granted|given|pre[-\s]?approved|waived|disabled)\b/i,
  /\b(?:no\s+longer\s+needs?|does\s+not\s+need\s+to\s+be|need\s+not\s+be|is\s+not\s+required)\b/i,
  /\b(?:the|our|its|a|team'?s)\s+(?:[\w-]+\s+){0,3}(?:contact|recipient|endpoint|destination|webhook|mailbox|address|url)\s+(?:for\s+[^.\n]{0,60}?\s+)?(?:is|are)\b/i,
  /\b(?:can|may)\s+be\s+(?:treated|considered|regarded)\s+as\s+(?:trusted|safe|internal|verified)\b/i,
];

const CLAIM_CONSENT = /\b(?:approvals?|approve[ds]?|confirm\w*|permission|authoris\w+|authoriz\w+|sign[-\s]?off|consent|prompt(?:ed|s)?|ask(?:ed|ing)?)\b/i;

const CLAIM_TRUST = /\b(?:trust\w*|vetted|verif\w+|safe|internal|allow[-\s]?list\w*|whitelist\w*|sanctioned|exempt)\b/i;

const CLAIM_ROUTING = /(?:\b(?:endpoint|recipient|contact|destination|webhook|mailbox|upload|forward(?:ed|s)?|cc|bcc)\b|[\w.%+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,4}|https?:\/\/)/i;

const CLAIM_SUPPRESSION = /\b(?:review\w*|audit\w*|guardrail\w*|safety\s+check|scan\w*|verif\w+|notif\w+|alert\w*|approval\s+step|human\s+in\s+the\s+loop)\b/i;

const CLAIM_REFUSAL =
  /\b(?:not|never|no)\s+(?:been\s+|yet\s+|longer\s+)?(?:approved|granted|confirmed|vetted|trusted|verified|authoris\w*|authoriz\w*|sanctioned|safe)\b|\bun(?:trusted|verified|approved|vetted)\b|\brefus\w+|\bden(?:y|ied)\b|\bmust\s+still\b|\balways\s+(?:ask|confirm|verify|check|review)\b/i;

export const CLAIM_LABEL = {
  consent: 'Approval Recorded As Already Given',
  trust: 'A Source Recorded As Trusted',
  routing: 'A Durable Destination Recorded',
  suppression: 'A Control Recorded As Unwanted',
};

const CLAIM_LEADING_LABEL = /^\s*(?:[-*+]\s*)?(?:note|context|fyi|reminder|memo|user\s+preference|preference|background)\s*:\s*/i;

function claimFamilyOf(line) {
  if (CLAIM_CONSENT.test(line)) return 'consent';
  if (CLAIM_TRUST.test(line)) return 'trust';
  if (CLAIM_SUPPRESSION.test(line)) return 'suppression';
  if (CLAIM_ROUTING.test(line)) return 'routing';
  return null;
}

export function detectDurableClaims(text) {
  const body = String(text ?? '');
  if (!body.trim()) return [];
  const out = [];
  const lines = body.split(/\r?\n/);
  for (let i = 0; i < lines.length && out.length < 20; i++) {
    const line = lines[i];
    if (line.length < 12 || line.length > 600) continue;

    const stripped = line.replace(CLAIM_LEADING_LABEL, '');

    for (const re of CLAIM_FRAMING) {
      const m = re.exec(stripped);
      if (!m) continue;
      if (citationGoverns(stripped, m.index)) continue;

      const object = (stripped.slice(0, m.index) + ' ' + stripped.slice(m.index + m[0].length)).trim();

      if (isDescriptiveLine(object)) continue;
      const family = claimFamilyOf(object);
      if (!family) continue;
      if (family !== 'routing' && CLAIM_REFUSAL.test(stripped)) continue;
      out.push({ family, label: CLAIM_LABEL[family], line: i + 1, sample: line.trim().slice(0, 200) });
      break;
    }
  }
  return out;
}

export function claimSeverity(claims) {
  if (!claims.length) return null;
  return new Set(claims.map((c) => c.family)).size >= 2 ? 'HIGH' : 'MEDIUM';
}
