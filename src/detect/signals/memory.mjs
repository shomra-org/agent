import { CLAIM_LABEL, claimSeverity, detectDurableClaims } from './durable-claims.mjs';
import { LOCAL_URL_RE, egressHost } from './egress.mjs';
import { lineOf, lineTextAt } from './lines.mjs';
import { citationGoverns, describesAt, isDescriptiveLine, isDocumentationLine, isRiskTableRow, prohibitsAt } from './prose-context.mjs';
import { localScan } from './scan.mjs';
import { NETWORK_VERBS, SENSITIVE_READ } from './sensitive.mjs';
import { DANGEROUS_SHELL } from './shell.mjs';
import { containsWord } from './text-match.mjs';

const PERSISTENCE_MARKERS = /\b(in (all|every|future) (sessions?|conversations?|chats?|projects?)|from now on|going forward|permanently|persist(ent|ed)?|across (all )?sessions|every time|each time|whenever you|forever|always remember to|never forget( to)?|for all future)\b/i;

const MALICIOUS_OVERRIDE = /\b(ignore (all |any |the )?(previous|prior|earlier|above|system)|disregard (the |your |all )?(instructions?|guidelines?|system|rules?)|do not (tell|inform|mention|reveal|disclose) (the |any)?(user|anyone|them)|without (telling|informing|asking|notifying) the user|no matter what (the )?(user|system|instructions?) (say|says|state)|bypass (the |all )?(safety|guard|security|policy|restrictions?))\b/i;

const PRECEDENCE_MARKERS = /\b(regardless of (what|any|your|the)|supersede?s?|takes? precedence|highest[- ]priority|overrid(e|ing|es)\b[^.\n]{0,30}\b(instruction|prompt|rule|system|user|guidance|directive|context|behaviou?r|polic|guardrail|safety))\b/i;

const OVERRIDE_MARKERS = new RegExp(`${MALICIOUS_OVERRIDE.source}|${PRECEDENCE_MARKERS.source}`, 'i');

const AUTHORITY_SPOOF_STRONG = /(^|\n)\s*(#{0,3}\s*system\s+(prompt|message|instruction)s?\s*[:>]|\[system\]|<\/?system>|\bas an? (system|admin|root|developer)[- ]?(instruction|directive|message|mode)|authority\s*[:=]\s*(system|admin|root)|you are now\b|new (system )?(instructions?|directive)s?\s*[:>])/i;

const AUTHORITY_SPOOF = AUTHORITY_SPOOF_STRONG;

const LIFECYCLE_VECTOR = /(?:\b(?:postinstall|preinstall|node[_-]?gyp|npm\s+lifecycle|package\.json[^.\n]{0,40}scripts|install hook|lifecycle (?:script|hook))|\.npmrc)\b/i;

export const IMPERATIVE = /\b(always|never|must|do not|don'?t|ensure you|make sure( you)?|be sure to|you should always|you must|remember to|whenever|when(ever)? (asked|the user)|instead of .*,? (use|do|say)|reply with|respond with|tell (the )?user)\b/i;

const NEGATION_GUARD = /\b(never|do not|don'?t|cannot|can'?t|avoid|refuse|must not|mustn'?t|should not|shouldn'?t|won'?t|will not|under no circumstances|forbidden|prohibited|not allowed|disallow(ed)?)\b/i;

const SABOTAGE_RULES = [

  { re: /\b(disabl|turn(ing)? off|deactivat|switch off|remov|drop|skip|suppress|circumvent)\w*\b[^.\n]{0,50}\b(security|safety|guard(?:rail)?s?|protection|moderation|content[- ]?filters?|safeguards?|sandbox(?:ing)?|controls?|restrictions?|policies|policy|filters?)\b/i, label: 'disable-safety', guarded: true },
  { re: /\bbypass(?:ing)?\b[^.\n]{0,50}\b(human(?:[- ]in[- ]the[- ]loop)?|hitl|verification|approval|confirmation|review|guard(?:rail)?s?|safety|security|checks?|policy|policies|restrictions?|sandbox|permission)\b/i, label: 'bypass-controls', guarded: true },
  { re: /\bprioriti[sz]e\b[^.\n]{0,60}\b(above|over)\b[^.\n]{0,40}\b(prompt|instruction|input|request|message|command|direction)s?\b/i, label: 'priority-hijack', guarded: true },

  { re: /\bignore\b[^.\n]{0,40}\b(user|human)\b[^.\n]{0,25}\b(prompt|instruction|request|command|wish|intent|question)s?\b/i, label: 'ignore-user', guarded: true },

  { re: /\bdo not\b[^.\n]{0,20}\b(log|display|show|print|record|surface|expose|output)\b[^.\n]{0,60}\buser\b(?!['’]s)/i, label: 'conceal-from-user', guarded: false, context: /\b(transfer|transmit|send|network|exfil|upload|post|copy|collect)\b/i },
];

export function offendingLine(sig, text) {
  const g = new RegExp(sig.re.source, sig.re.flags.includes('g') ? sig.re.flags : sig.re.flags + 'g');
  for (const m of text.matchAll(g)) {
    if (m.index == null) continue;
    const line = lineTextAt(text, m.index);
    if (sig.refine && !sig.refine(line)) continue;
    if (isDocumentationLine(line)) continue;
    if (prohibitsAt(line, line.indexOf(m[0])) || describesAt(line, line.indexOf(m[0]))) continue;
    if (isRiskTableRow(line)) continue;
    return line;
  }
  return null;
}

function firstDirectiveLine(text, re) {
  for (const line of text.split(/\r?\n/)) {
    if (!re.test(line)) continue;
    if (NEGATION_GUARD.test(line)) continue;
    if (isDescriptiveLine(line)) continue;
    if (citationGoverns(line, re.exec(line)?.index)) continue;
    return line;
  }
  return null;
}

function lineMatchingAll(text, ...res) {
  for (const line of text.split(/\r?\n/)) {
    if (res.every((re) => re.test(line))) return line;
  }
  return null;
}

const EXFIL_RULES = [
  { re: /\b(exfiltrat|smuggl)\w*/i, label: 'exfiltration', severity: 'CRITICAL', descGuard: true },
  { re: /\bleak\w*\b[^.\n]{0,60}(?:\b(?:content|data|secret|file|credential|key|token|password|env|private[- ]?key|id_rsa|api[- ]?key)|\.ssh)\b/i, label: 'leak-secrets', severity: 'CRITICAL', descGuard: true },

  { re: /\b(base64|hex|rot13|gzip|xor|url[- ]?encod)\w*\b[^.\n]{0,50}\b(before|then|prior to|and\s+then|and\s+immediately)\b[^.\n]{0,25}\b(send|post|upload|transmit|exfil|deliver|beacon|forward|transfer)\w*/i, label: 'obfuscate-before-send', severity: 'CRITICAL', descGuard: true },
  { re: /\bsilent(ly)?\b[^.\n]{0,70}\b(send|post|upload|collect|encod|transmit|copy|forward|read|leak|deliver|beacon|transfer)\w*/i, label: 'covert-action', severity: 'CRITICAL', descGuard: true },
  { re: /\b(send|post|upload|transmit|forward|deliver|beacon|report|ship|push|transfer)\w*\b[^.\n]{0,80}\b(https?:\/\/\S+|attacker|c2\b|command[- ]and[- ]control|remote (server|host|endpoint)|external (server|host|endpoint|url|site|service))/i, label: 'send-to-external', severity: 'HIGH' },

  {
    re: /\b(?:read|open|cat|load|import|source|inspect|include|copy|dump|print|show)\b(?:[^.\n]|\.(?!\s)){0,50}(?:~?\/?\.ssh\/(?:id_[a-z0-9]+|config)(?!\.pub)|~?\/?\.aws\/credentials|~?\/?\.kube\/config|~?\/?\.gnupg|\bid_(?:rsa|ed25519|dsa)\b(?!\.pub)|~?\/?\.npmrc|~?\/?\.netrc|\/etc\/shadow|(?:^|[\s'"`(])\.env(?:\.[\w-]+)?\b)/i,
    label: 'read-credential-path',
    severity: 'HIGH',
    descGuard: true,
  },
];

function scanDirectives(text) {
  const sabotage = new Map(), exfil = new Map();
  for (const line of text.split(/\r?\n/)) {
    for (const r of SABOTAGE_RULES) {
      const m = r.re.exec(line);
      if (!m) continue;
      if (r.guarded && NEGATION_GUARD.test(line)) continue;
      if (r.guarded && isDescriptiveLine(line)) continue;
      if (r.guarded && citationGoverns(line, m.index)) continue;
      if (r.context && !r.context.test(line)) continue;
      if (!sabotage.has(r.label)) sabotage.set(r.label, line);
    }
    for (const r of EXFIL_RULES) {
      const m = r.re.exec(line);
      if (!m) continue;

      if (NEGATION_GUARD.test(line)) continue;
      if (r.descGuard && isDescriptiveLine(line)) continue;
      if (r.descGuard && citationGoverns(line, m.index)) continue;
      if (r.descGuard && isRiskTableRow(line)) continue;
      if (r.label === 'send-to-external' && LOCAL_URL_RE.test(line) && !/\b(attacker|c2|command[- ]and[- ]control|external|evil)\b/i.test(line)) continue;
      const prev = exfil.get(r.label);
      if (!prev || (prev === 'HIGH' && r.severity === 'CRITICAL')) exfil.set(r.label, r.severity);
    }
  }
  return { sabotage, exfil };
}

const SELF_REFERENCE =
  /(\b(?:th(?:is|ese) (?:note|entry|entries|memory|memories|instruction|directive|rule|line|section|block|paragraph|file|text)s?|the (?:above|following|preceding) (?:instruction|directive|note|rule|entry|section|line)s?|your memor(?:y|ies)|the memory (?:file|store|entry)|MEMORY\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md)\b|\.cursorrules\b|\.windsurfrules\b)/i;

const SELF_RECREATE =
  /\b(re-?(add|writ(e|ing)|creat(e|ing)|insert(ing)?|instat(e|ing)|appl(y|ying)|introduc(e|ing))|restor(e|ing)|recreat(e|ing)|reinstat(e|ing)|re-?establish(ing)?|put .{0,20}back|add .{0,20}back)\b/i;

const SELF_PROPAGATE =
  /\b(copy|copies|duplicat(e|ing)|replicat(e|ing)|propagat(e|ing)|carry (it |this )?over|mirror|append|add|includ(e|ing)|writ(e|ing)|sav(e|ing))\b[^.\n]{0,60}\b(every|each|all|any (new|other)|other|future|subsequent)\b[^.\n]{0,40}\b(session|conversation|chat|project|repo|repositor(y|ies)|workspace|memor(y|ies)|context|file|store)s?\b/i;

const SELF_UNDELETABLE =
  /\b(do not|don'?t|never|must not|should not|shall not)\s+(delete|remove|erase|clear|drop|strip|discard|overwrite|forget|prune|purge|edit|modify|alter|change)\b/i;

function detectSelfReinforcement(text, isInstruction) {
  let weak = null;
  for (const line of text.split(/\r?\n/)) {
    const ref = SELF_REFERENCE.exec(line);
    if (!ref) continue;

    if (isDescriptiveLine(line.replace(ref[0], ' '))) continue;
    if (SELF_RECREATE.test(line)) return { form: 'recreate', line };
    if (SELF_PROPAGATE.test(line)) return { form: 'propagate', line };
    if (!isInstruction && !weak && SELF_UNDELETABLE.test(line)) weak = { form: 'undeletable', line };
  }
  return weak;
}

function memoryNouns(kind) {
  const isInstruction = kind === 'INSTRUCTION';
  return {
    isInstruction,
    noun: isInstruction ? 'rules file' : 'memory',
    Noun: isInstruction ? 'Rules file' : 'Memory',
  };
}

function createFindingSink(text) {
  const findings = [];
  const push = (severity, title, remediationText, needle, explicitLine) => {
    const line = explicitLine ?? (needle != null ? lineOf(text, needle) : undefined);
    findings.push({ severity, title, remediationText, ...(line ? { line } : {}) });
  };
  return { findings, push };
}

function reportDurableClaims(text, { isInstruction, Noun }, push) {
  const claims = detectDurableClaims(text);
  const severity = claimSeverity(claims);
  if (!severity) return;

  const families = [...new Set(claims.map((claim) => claim.family))];
  push(
    severity,
    `${Noun} records a standing security decision (${families.map((f) => CLAIM_LABEL[f]).join(', ')})`,
    'Move the decision to a reviewed policy, or remove it. If nobody granted that approval and nothing vetted that source, treat whatever wrote this as compromised.',
    null,
    claims[0].line,
  );
}

function reportOverride(text, { isInstruction, noun }, push) {
  const overrideLine = firstDirectiveLine(text, isInstruction ? MALICIOUS_OVERRIDE : OVERRIDE_MARKERS);
  const authorityLine = firstDirectiveLine(text, isInstruction ? AUTHORITY_SPOOF_STRONG : AUTHORITY_SPOOF);
  const hasOverride = !!overrideLine;
  const hasAuthority = !!authorityLine;

  if (hasOverride || hasAuthority) {
    const firedRe = hasAuthority
      ? (isInstruction ? AUTHORITY_SPOOF_STRONG : AUTHORITY_SPOOF)
      : (isInstruction ? MALICIOUS_OVERRIDE : OVERRIDE_MARKERS);
    push(
      'CRITICAL',
      `Poisoned ${noun}: ${hasAuthority ? 'system-authority spoofing' : 'injected override directive'}`,
      `Remove the injected directive and roll the ${noun} back to its approved baseline; restrict who/what may write it.`,
      firedRe,
    );
    return { hasOverride, hasAuthority };
  }

  const durableImperativeLine = isInstruction ? null : lineMatchingAll(text, PERSISTENCE_MARKERS, IMPERATIVE);
  if (durableImperativeLine && !isDescriptiveLine(durableImperativeLine)) {
    push(
      'HIGH',
      'Suspicious standing instruction in memory',
      'Rewrite as a neutral fact or remove it. Encode intended standing behavior in a reviewed rules/policy file, not agent-writable memory.',
      durableImperativeLine,
    );
  }
  return { hasOverride, hasAuthority };
}

function reportDirectives(text, { noun }, push) {
  const { sabotage, exfil } = scanDirectives(text);

  if (sabotage.size) {
    push(
      'CRITICAL',
      `Guardrail-sabotage directive in ${noun} (${[...sabotage.keys()].join(', ')})`,
      `Remove these directives and roll the ${noun} back to its baseline; treat whatever wrote this as compromised.`,
      [...sabotage.values()][0],
    );
  }
  if (!exfil.size) return;

  const worst = [...exfil.values()].some((severity) => severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
  const readOnly = [...exfil.keys()].every((key) => key === 'read-credential-path');
  push(
    worst,
    readOnly
      ? `${noun} directs the agent to read a credential file`
      : `Exfiltration directive in ${noun} (${[...exfil.keys()].join(', ')})`,
    readOnly
      ? 'Remove the instruction. A credential an agent needs should reach it from the host at the moment of use, not be loaded into context at the start of every session.'
      : 'Remove the directive and roll back to baseline; gate any egress behind explicit approval and an allow-list.',
  );
}

function reportStagedPayload(text, { noun }, push) {
  for (const signal of DANGEROUS_SHELL) {
    const line = offendingLine(signal, text);
    if (!line) continue;
    const severity = signal.severity === 'MEDIUM' || signal.severity === 'LOW' ? 'HIGH' : 'CRITICAL';
    push(
      severity,
      `Executable payload staged in ${noun}: ${signal.name}`,
      `Delete the command from the ${noun}; treat the writer as untrusted.`,
      line,
    );
    return;
  }
}

function reportToxicFlow(text, { noun }, push) {
  if (!IMPERATIVE.test(text)) return;
  const line = text.split(/\r?\n/).find((candidate) => IMPERATIVE.test(candidate)
    && !NEGATION_GUARD.test(candidate)
    && containsWord(candidate, SENSITIVE_READ)
    && containsWord(candidate, NETWORK_VERBS)
    && !isDescriptiveLine(candidate));
  if (!line) return;
  push(
    'HIGH',
    `Toxic instruction in ${noun}: reads sensitive data + reaches the network`,
    'Remove the entry; gate any network step behind explicit approval and an egress allow-list.',
    line,
  );
}

function reportSelfReinforcement(text, { isInstruction, noun }, push) {
  const selfRef = detectSelfReinforcement(text, isInstruction);
  if (!selfRef) return;

  const undeletable = selfRef.form === 'undeletable';
  push(
    undeletable ? 'HIGH' : 'CRITICAL',
    `Self-reinforcing ${noun} entry (${selfRef.form})`,
    undeletable
      ? `Remove the entry and roll the ${noun} back to its approved baseline; an entry asserting its own permanence is how a planted directive discourages the one action that would remove it.`
      : `Remove the entry and roll the ${noun} back to its approved baseline, then re-check the agent's OTHER memory stores and projects for the same text before re-approving - a self-reinforcing entry is rarely in one place. Restrict who may write this store.`,
    undefined,
    selfRef.line,
  );
}

function reportScanFindings(text, { noun, Noun }, push, findings, seenInjection) {
  const scan = localScan(text, { categories: ['injection', 'secret', 'pii'] });
  for (const finding of scan.findings) {
    if (finding.category === 'injection') {
      if (seenInjection) continue;
      push(
        'HIGH',
        `Injected instruction in ${noun}: ${finding.label}`,
        'Remove the injected/obfuscated text and roll back to the approved baseline.',
        undefined,
        finding.line,
      );
    } else if (finding.category === 'secret') {
      push(
        'CRITICAL',
        `Live credential stored in ${noun}: ${finding.label}`,
        'Revoke and rotate the credential; inject secrets at runtime from a secret manager.',
        undefined,
        finding.line,
      );
    } else if (finding.category === 'pii') {
      findings.push({
        severity: 'MEDIUM',
        title: `Personal data stored in ${noun}: ${finding.label}`,
        remediationText: `Strip personal data from the ${noun}.`,
        ...(finding.line ? { line: finding.line } : {}),
      });
    }
  }
}

function dedupeByTitle(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    if (seen.has(finding.title)) return false;
    seen.add(finding.title);
    return true;
  });
}

export function localMemory(content, { kind = 'MEMORY' } = {}) {
  const text = content || '';
  const names = memoryNouns(kind);
  const { findings, push } = createFindingSink(text);

  reportDurableClaims(text, names, push);
  const { hasOverride, hasAuthority } = reportOverride(text, names, push);
  reportDirectives(text, names, push);
  reportStagedPayload(text, names, push);

  const host = egressHost(text);
  if (host) {
    push(
      'HIGH',
      `${names.Noun} references a data-exfiltration host (${host})`,
      'Remove the reference and roll back to the approved baseline.',
      host,
    );
  }

  reportToxicFlow(text, names, push);

  const lifecycleLine = text.split(/\r?\n/).find((line) => LIFECYCLE_VECTOR.test(line) && !isDocumentationLine(line));
  if (lifecycleLine) {
    push(
      'MEDIUM',
      `${names.Noun} references a package-lifecycle hook (MemoryTrap vector)`,
      'Verify no dependency writes to this store during install; pin dependencies and audit lifecycle scripts.',
      lifecycleLine,
    );
  }

  reportSelfReinforcement(text, names, push);

  const durablePersistence = !names.isInstruction && PERSISTENCE_MARKERS.test(text) && IMPERATIVE.test(text);
  const seenInjection = hasOverride || hasAuthority || durablePersistence;
  reportScanFindings(text, names, push, findings, seenInjection);

  return dedupeByTitle(findings);
}
