import { PII_PATTERNS, SECRET_PATTERNS, isPlaceholderSecret, luhnValid } from './signals/secrets.mjs';

const MAX_TEXT = 200_000;
const MAX_SPANS = 200;


export function redactLocally(text, opts = {}) {
  const src = String(text ?? '');
  if (!src || src.length > MAX_TEXT) return { text: src, masked: [], unmaskable: [], changed: false };

  const categories = opts.categories ?? ['secret', 'pii'];
  const spans = [];

  const collect = (re, label, category) => {
    const rx = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    let m;
    let guard = 0;
    while ((m = rx.exec(src)) !== null && guard++ < MAX_SPANS) {
      if (!m[0]) { rx.lastIndex += 1; continue; }
      if (category === 'secret' && isPlaceholderSecret(m[0])) continue;
      if (label === 'Credit card number' && !luhnValid(m[0])) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, label, category });
    }
  };

  if (categories.includes('secret')) for (const { name, re } of SECRET_PATTERNS) collect(re, name, 'secret');
  if (categories.includes('pii')) for (const { name, re } of PII_PATTERNS) collect(re, name, 'pii');

  if (!spans.length) return { text: src, masked: [], unmaskable: [], changed: false };

  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const s of spans) {
    const last = merged[merged.length - 1];
    if (last && s.start < last.end) {
      last.end = Math.max(last.end, s.end);
      if (!last.labels.includes(s.label)) last.labels.push(s.label);
      continue;
    }
    merged.push({ start: s.start, end: s.end, labels: [s.label], category: s.category });
  }

  let out = '';
  let cursor = 0;
  const masked = [];
  for (const m of merged) {
    out += src.slice(cursor, m.start);
    out += `[shomra:redacted:${m.category}]`;
    cursor = m.end;
    masked.push({ label: m.labels.join(' + '), category: m.category, chars: m.end - m.start });
  }
  out += src.slice(cursor);

  return { text: out, masked, unmaskable: [], changed: true };
}


export function unmaskableFindings(findings, redaction) {
  const maskedLabels = new Set((redaction?.masked ?? []).flatMap((m) => String(m.label).split(' + ')));
  return (findings ?? [])
    .filter((f) => f && (f.category === 'secret' || f.category === 'pii'))
    .filter((f) => {
      const label = String(f.label ?? '').replace(/^Live credential:\s*/, '');
      return !maskedLabels.has(label);
    })
    .map((f) => f.label);
}
