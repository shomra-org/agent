// GENERATED MIRROR of Dragox.Backend analysis/checks/text/credential-fields.ts (types stripped, imports swapped).
// Do not hand-edit the rules here - change the backend file and regenerate, so
// the CLI and the platform locate and grade agent memory identically.
export const CODE_SENT = String.raw`code\s+(?:just\s+)?(?:sent|texted|e-?mailed)`;
export const CODE_BASE = String.raw`one[- ]time\s+(?:pass)?(?:code|password|pin|passcode)s?|otps?\b|(?:2fa|mfa|two[- ]factor|multi[- ]factor|2-step|two[- ]step)(?:\s+(?:authentication|verification|auth))?\s+(?:codes?|tokens?|pins?|numbers?)|(?:verification|security|authentication|auth|login|log-in|sign[- ]?in|sms|texted|authenticator|reset)\s+codes?|(?:\d|six|four|eight)[- ]digit\s+(?:codes?|pins?|numbers?)|(?:backup|recovery)\s+codes?|code\s+(?:that\s+)?(?:(?:we|i|they)\s+(?:just\s+)?|(?:was|is|has\s+been)\s+(?:just\s+)?)(?:sent|texted|e-?mailed)(?:\s+(?:you|to\s+you))?|code\s+(?:that\s+)?you\s+(?:just\s+)?(?:received|got)`;
const CODE_SECRET = String.raw`${CODE_BASE}|${CODE_SENT}(?=\s+(?:to\s+)?(?:you|your)\b)`;

export const PERSON_SECRET = String.raw`(?:[\w.'’-]{2,24}\s+){0,2}?(?:password|passcode|pass\s+code|credentials|login\s+details|sign[- ]?in\s+details)s?|(?:card|atm|debit|bank|account|security|sim)\s+pins?\b|pin(?:\s+(?:code|number))?\b|${CODE_SECRET}|recovery\s+keys?|(?:seed|recovery|secret\s+recovery|mnemonic|wallet|backup)\s+(?:phrases?|words)|mnemonic(?:\s+phrase)?|(?:12|24|twelve|twenty[- ]four)[- ]word\s+(?:phrases?|seed|recovery\s+phrases?)|cvv2?\b|cvc\b|card\s+security\s+codes?|(?:full\s+)?card\s+(?:number|details)|(?:login|log-in|sign[- ]?in|account)\s+(?:details|credentials|info(?:rmation)?)|credentials|username\s+and\s+password`;

export const DEV_SECRET = String.raw`(?:[\w.-]{2,24}\s+){0,2}?(?:(?:api|access|secret|private|client|ssh|signing|deploy|service\s+account)\s+keys?|apikeys?|(?:api|access|auth|bearer|session|refresh|personal\s+access|oauth)\s+tokens?|client\s+secrets?|pats?\b|tokens?\b)`;

export const NEGATION_RE = /\b(?:never|not|no\s+one|nobody|avoid|refuse|cannot)\b|n['’]t\b/i;

export const CREDENTIAL_FIELD_RE =
  /^(?:(?:user|account|login|admin|db|database|root|wifi|email|bank|card|vpn|current|old|new|confirm|repeat)[ _-]?)?(?:password|passwd|pass|pwd|passcode|pass[ _-]?phrase|pin(?:[ _-]?(?:code|number))?|otp|totp|hotp|one[ _-]?time[ _-]?(?:code|password|pass(?:code)?|pin)|mfa(?:[ _-]?(?:code|token))?|2fa(?:[ _-]?(?:code|token))?|two[ _-]?factor(?:[ _-]?(?:code|token))?|(?:verification|security|auth(?:entication)?|sms|login)[ _-]?code|recovery[ _-]?(?:codes?|key|phrase)|backup[ _-]?codes?|seed[ _-]?(?:phrase|words?)|mnemonic(?:[ _-]?phrase)?|secret(?:[ _-]?(?:key|phrase|token|value))?|private[ _-]?key|api[ _-]?(?:key|token|secret)|apikey|access[ _-]?(?:token|key)|auth[ _-]?token|bearer(?:[ _-]?token)?|token|session[ _-]?(?:token|key|cookie)|refresh[ _-]?token|client[ _-]?secret|credentials?|cvv2?|cvc|card[ _-]?(?:number|pin|security[ _-]?code)|ssh[ _-]?key)$/i;

export const NUMERIC_FIELD_RE =
  /^(?:(?:user|account|login|admin|bank|card|atm|security|current|old|new|confirm|repeat)[ _-]?)?(?:password|passwd|pwd|passcode|pin(?:[ _-]?(?:code|number))?|otp|totp|hotp|one[ _-]?time[ _-]?(?:code|password|pass(?:code)?|pin)|mfa[ _-]?code|2fa[ _-]?code|two[ _-]?factor[ _-]?code|(?:verification|security|auth(?:entication)?|sms|login)[ _-]?code|cvv2?|cvc|card[ _-]?number)$/i;

export const FIELD_TITLE_RE = new RegExp(String.raw`\b(?:${PERSON_SECRET}|${DEV_SECRET})`, 'i');

export const NUMERIC_TITLE_RE = new RegExp(String.raw`\b(?:${PERSON_SECRET})`, 'i');

export const HEAD_SHIFT_RE =
  /^[\s'’-]*(?:length|strength|polic(?:y|ies)|hints?|rules?|requirements?|complexity|expiry|expiration|age|history|reset|manager|vault|location|symbol|ticker|names?|counts?|budget|limits?|usage|types?|format|ids?|labels?|scopes?|prefix|suffix|lifetime|ttl|rotation|settings?|options?|preferences?|mode|position|style|size|width|price|amount|balance|address|contract|standard|list|selection|choice|cost|rate|window|per)\b/i;

export const TITLE_BREAK_RE = /[.!?,;:—–()]|\s-\s/g;

function titleClauseBefore(text        , at        )         {
  let from = 0;
  for (const b of text.slice(0, at).matchAll(TITLE_BREAK_RE)) from = (b.index ?? 0) + b[0].length;
  return text.slice(from, at);
}

function titleAsks(title        , numeric         )          {
  const scan = new RegExp((numeric ? NUMERIC_TITLE_RE : FIELD_TITLE_RE).source, 'gi');
  for (const m of title.matchAll(scan)) {
    const at = m.index ?? 0;
    if (NEGATION_RE.test(`${titleClauseBefore(title, at)} ${m[0]}`)) continue;
    if (!HEAD_SHIFT_RE.test(title.slice(at + m[0].length))) return true;
  }
  return false;
}

export const MAX_FIELDS_READ = 64;

const allConstants = (list     )          =>
  Array.isArray(list) && list.length > 0 && list.every((b     ) => !!b && typeof b === 'object' && 'const' in b);

export function isChoice(spec     )          {
  if (!spec || typeof spec !== 'object') return false;
  const type = String(spec.type ?? '').toLowerCase();
  if (type === 'boolean') return true;
  if ((Array.isArray(spec.enum) && spec.enum.length > 0) || allConstants(spec.oneOf) || allConstants(spec.anyOf)) return true;
  const items = spec.items;
  if (type !== 'array' || !items || typeof items !== 'object') return false;
  return (Array.isArray(items.enum) && items.enum.length > 0) || allConstants(items.oneOf) || allConstants(items.anyOf);
}

export function credentialFieldShape(name        , spec     )                {
  const shown = String(name ?? '').slice(0, 60);
  const key = String(name ?? '')
    .slice(0, 120)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .trim()
    .toLowerCase();
  if (isChoice(spec)) return null;
  const typed = spec && typeof spec === 'object' ? String(spec.type ?? 'string').toLowerCase() : 'string';
  const numeric = typed === 'number' || typed === 'integer';
  if ((numeric ? NUMERIC_FIELD_RE : CREDENTIAL_FIELD_RE).test(key)) return `the field is named "${shown}"`;
  if (!spec || typeof spec !== 'object') return null;
  if (String(spec.format ?? '').toLowerCase() === 'password') return `the field "${shown}" is declared with the password format`;
  const title = typeof spec.title === 'string' ? spec.title.slice(0, 200) : '';
  if (title && titleAsks(title, numeric)) return `the field is titled "${title.slice(0, 60)}"`;
  return null;
}
