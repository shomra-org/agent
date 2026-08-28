import { MARK_CONCEALED } from './masking.mjs';

export function lineTextAt(text, index) {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? undefined : end);
}

export function lineAt(text, index) {
  let line = 1;
  const end = Math.min(index, text.length);
  for (let i = 0; i < end; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export function lineOf(text, needle) {
  if (!text || !needle) return undefined;
  let idx = -1;
  if (typeof needle === 'string') {
    const probe = needle.split('•')[0].trim().slice(0, 80);
    if (probe.length < 3) return undefined;
    idx = text.toLowerCase().indexOf(probe.toLowerCase());
  } else {
    const m = text.match(needle);
    idx = m && m.index != null ? m.index : -1;
  }
  return idx >= 0 ? lineAt(text, idx) : undefined;
}

export function locate(text, needle, mask) {
  let idx = -1;
  if (typeof needle === 'string') {
    const probe = needle.split('•')[0].trim().slice(0, 80);
    if (probe.length >= 3) idx = text.toLowerCase().indexOf(probe.toLowerCase());
  } else {
    const m = text.match(needle);
    idx = m && m.index != null ? m.index : -1;
  }
  if (idx < 0) return { line: undefined, codeContext: false, concealed: false };

  return { line: lineAt(text, idx), codeContext: mask[idx] === 1, concealed: mask[idx] === MARK_CONCEALED };
}
