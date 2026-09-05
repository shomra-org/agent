import { egressHost } from './egress.mjs';
import { IMPERATIVE } from './memory.mjs';

const DESCRIPTIVE_MARKERS =
  /\b(detect|scan|flag|block|catch|prevent|guard|protect|harden|audit|benchmark|catalog|scenario|corpus|coverage|example|vector|signal|rule|technique|posture|detection|test\s*case|red[- ]?team|-style|grounded in|fixed|now green|was|were|had|used to|previously|postmortem|regression|changelog|root[- ]?cause|repro|note|see|describes?|documents?|refers?|treat(s|ed|ing)?|counts?|reads?)\w*/i;

export function isDescriptiveLine(line) {
  return DESCRIPTIVE_MARKERS.test(line) && !IMPERATIVE.test(line);
}

const RESEARCH_CITATION_RE =
  /\b(?:in\s+their\s+(?:\d{4}\s+)?paper|et\s+al\.|we\s+(?:analys|analyz|studi|examin|evaluat|benchmark|review|investigat)\w*|(?:this|the)\s+(?:paper|study|report|article|post|research|survey|technique|attack|jailbreak)\b|according\s+to\s+(?:researchers|the\s+authors)|characteriz\w+\s+(?:and\s+)?evaluat\w+|published\s+(?:in|by)\b|\barxiv\b|\bCVE-\d{4}-|\bis\s+a\s+(?:critical\s+|active\s+|growing\s+)?(?:research|study)\s+(?:area|topic|field)|\b(?:the\s+)?ethics\s+of\b)/i;

const ATTACK_NAMING_RE = /(?:[Tt]his|[Tt]he)\s+(?:[A-Z][\w.-]{1,24}\s+){1,3}(?:attack|jailbreak|technique|exploit|payload)\b/;

const ATTACK_CHARACTERISATION_RE =
  /\bis\s+a\s+(?:well[-\s]documented|well[-\s]known|widely[-\s]known|classic|common|known|documented)\s+(?:attack|technique|jailbreak|pattern|exploit|vector)\b/i;

const CITATION_HANDOFF_RE = /[:;\u2014\u2013]\s*$/;

const CITATION_FRAMES = [RESEARCH_CITATION_RE, ATTACK_NAMING_RE, ATTACK_CHARACTERISATION_RE];

export function citationGoverns(segment, offset) {
  const text = String(segment ?? '');

  for (const re of CITATION_FRAMES) {
    const cit = text.match(re);
    if (!cit) continue;
    if (offset == null) return true;
    const citEnd = (cit.index ?? 0) + cit[0].length;
    if (citEnd > offset) continue;
    if (!CITATION_HANDOFF_RE.test(text.slice(citEnd, offset))) return true;
  }
  return false;
}

const ELLIPSIS_RE = /…|\.\.\./;

const REGEX_PATTERN_RE = /\\[sdwbSDWB]|\\\+|\\\*|\\\(|\\\||\(\?:|\.\*|\.\+/;

const CREDENTIAL_PATH_RE =
  /~\/\.(ssh|aws|kube|gnupg|docker|npmrc?)\b|\bid_(rsa|ed25519|dsa)\b|\.pem\b|\bcredentials\b\s*(file)?|\bAWS_SECRET|\bANTHROPIC_API_KEY\b|\bOPENAI_API_KEY\b/i;

const EXECUTABLE_FETCH_RE =
  /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,200}?(?:https?:\/\/|\bwww\.|\b\d{1,3}(?:\.\d{1,3}){3}\b)[^\n]{0,200}?\|\s*(?:sudo\s+)?(?:(?:ba|z|k|da)?sh|python\d?|perl|ruby|node)\b/i;

function carriesHardEvidence(line) {
  return CREDENTIAL_PATH_RE.test(line) || EXECUTABLE_FETCH_RE.test(line) || !!egressHost(line);
}

export function isDocumentationLine(line) {
  if (!line) return false;
  if (carriesHardEvidence(line)) return false;
  if (ELLIPSIS_RE.test(line) || REGEX_PATTERN_RE.test(line)) return true;
  return isDescriptiveLine(line);
}

const PROHIBITION_MARKER_RE =
  /\b(?:never|do not|don'?t|cannot|can'?t|must not|mustn'?t|should not|shouldn'?t|avoid|avoids|avoiding|refuse to|refrain from|forbidden|prohibited|disallow\w*|instead of|rather than|beware of)\b[^.:;\n]{0,60}$/i;

const DOUBLE_NEGATIVE_RE = /\b(?:hesitate|worry|be afraid|forget|fail|neglect|shy away)\b/i;

const COORDINATE_TAIL_RE = /(?:\b(?:and|or|but|then|also)\b|[,;])\s*$/i;

export function prohibitsAt(line, offset) {
  if (!line) return false;
  const at = offset == null || offset < 0 ? line.length : Math.min(offset, line.length);
  const before = line.slice(Math.max(0, at - 90), at);
  if (!PROHIBITION_MARKER_RE.test(before)) return false;
  if (COORDINATE_TAIL_RE.test(before)) return false;
  return !DOUBLE_NEGATIVE_RE.test(before);
}

/**
 * ⚠ AN OFFSET ON THE OPENING BACKTICK IS INSIDE THE SPAN. Several rules anchor
 * on the backtick itself (a markdown code span and a shell command substitution
 * are the same character), so counting only what precedes the offset put every
 * code-span guard one character outside the span it was meant to be inside.
 */
function insideCodeSpan(line, offset) {
  let ticks = 0;
  for (let i = 0; i < offset && i < line.length; i++) if (line[i] === '`') ticks++;
  if (ticks % 2 === 1) return true;
  return line[offset] === '`' && line.indexOf('`', offset + 1) !== -1;
}

/**
 * ⚠ A LINE THAT NAMES A COMMAND AS ITS SUBJECT IS DESCRIBING IT — the second
 * carve-out `carriesHardEvidence` needs, for the same reason `prohibitsAt` was
 * the first. Security documentation is written in exactly this mood -
 * *"`curl … | sh` is a pipe-to-shell installer"*, *"`chmod 777` means the file
 * is world-writable"* - so offline, where no server verdict ever arrives to
 * correct it, every threat model and runbook in a careful repo blocked.
 *
 * ⚠ THE LEAD-IN IS NOT THE SIGNAL, THE PREDICATE IS. "For example, run
 * `curl … | sh`" is an instruction wearing a documentation opener, and
 * "example" is one token an attacker adds for free. What cannot be faked
 * cheaply is the command sitting in SUBJECT position with a copular or
 * reporting verb after it: an instruction puts the command in OBJECT position
 * after an imperative.
 *
 * ⚠ THE MATCH MUST BE INSIDE A CODE SPAN, and ⚠ AN IMPERATIVE BEFORE IT WINS.
 *
 * Mirrors `describesAt` in the backend's prose-context.ts — `local-mirror-bench`
 * compares the two on every mood, in both directions.
 */
const DESCRIPTIVE_PREDICATE_RE =
  /^\s*(?:,\s*)?(?:is|are|was|were|means?|meant|shows?|showed|demonstrates?|indicates?|signals?|denotes?|describes?|represents?|counts?\s+as|reads?\s+as|matches?|fires?|triggers?|flags?|catches?|becomes?|remains?|stays?|looks?\s+like|would\s+\w+|will\s+\w+|has|have|had)\b/i;

const IMPERATIVE_LEAD_RE =
  /\b(?:run|execute|exec|invoke|call|use|paste|copy|type|enter|apply|install|download|fetch|curl|wget|pipe|add|append|write|put|send|post)\b[^.:;\n]{0,40}$/i;

export function describesAt(line, offset) {
  if (!line || offset == null || offset < 0 || offset >= line.length) return false;
  if (!insideCodeSpan(line, offset)) return false;

  const onTick = line[offset] === '`';
  const close = line.indexOf('`', onTick ? offset + 1 : offset);
  if (close === -1) return false;
  if (!DESCRIPTIVE_PREDICATE_RE.test(line.slice(close + 1, close + 60))) return false;

  const open = onTick ? offset : line.lastIndexOf('`', offset);
  const before = line.slice(Math.max(0, open - 60), open);
  return !IMPERATIVE_LEAD_RE.test(before) && !IMPERATIVE.test(before);
}

const RISK_CELL_RE = /\b(?:critical|high|medium|low|severity|risk|danger\w*|forbidden|blocked|denied|prohibited|never|do not|example|attack|threat|mitigation|why|impact)\b/i;

export function isRiskTableRow(line) {
  const t = String(line ?? '').trim();
  if (!t.startsWith('|') || !t.endsWith('|')) return false;
  const cells = t.slice(1, -1).split('|');
  if (cells.length < 3) return false;
  return cells.some((c) => RISK_CELL_RE.test(c));
}
