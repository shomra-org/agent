import { markerRe } from './text-match.mjs';

export const RISKY_CONFIG_MARKERS = [
  'yolo', 'auto-approve', 'autoapprove', 'auto_approve', 'autorun', 'auto-run',
  'always allow', 'alwaysallow', 'dangerously', 'skip confirmation', 'no confirmation',
  'disable safety', 'bypass approval', 'full access', 'unrestricted',
];

const FLAG_BEFORE = /(?:^|\s)--?[\w-]*$/;

const ENABLE_AFTER = /^["'`\]]?\s*[:=]/;

const ENABLE_BEFORE = /[:=]\s*["'`\[]?\s*$/;

function isEnablement(text, at, len) {
  const before = text.slice(Math.max(0, at - 24), at);
  const after = text.slice(at + len, at + len + 12);
  return FLAG_BEFORE.test(before) || ENABLE_AFTER.test(after) || ENABLE_BEFORE.test(before);
}

export function riskyConfigHit(text, marker) {
  const re = markerRe(marker);
  let m;
  while ((m = re.exec(text)) !== null) {
    if (isEnablement(text, m.index, m[0].length)) return { start: m.index, end: m.index + m[0].length };
  }
  return null;
}
