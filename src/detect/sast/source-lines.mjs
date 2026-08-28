const MAX_SNIPPET = 400;

const CONTEXT_RADIUS = 3;

const MAX_JOIN_LINES = 40;

export function contextChunk(lines, idx) {
  const start = Math.max(0, idx - CONTEXT_RADIUS);
  const end = Math.min(lines.length - 1, idx + CONTEXT_RADIUS);
  const snippet = lines.slice(start, end + 1).join('\n').slice(0, MAX_SNIPPET);
  return { snippet, snippetStartLine: start + 1 };
}

export function isCommentLine(trimmed) {
  return trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
}

function lineDepthDelta(line) {
  let delta = 0;
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
    if (c === '#') break;
    if (c === '/' && line[i + 1] === '/') break;
    if (c === '(' || c === '[' || c === '{') delta++;
    else if (c === ')' || c === ']' || c === '}') delta--;
  }
  return { delta, backslash: !quote && /\\\s*$/.test(line) };
}

export function logicalLines(lines) {
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const startLine = i + 1;
    const buf = [];
    let depth = 0;
    while (i < lines.length) {
      const line = lines[i];
      buf.push(line);
      const { delta, backslash } = lineDepthDelta(line);
      depth += delta;
      i++;
      if ((depth <= 0 && !backslash) || buf.length >= MAX_JOIN_LINES) break;
    }
    out.push({ text: buf.join('\n'), startLine });
  }
  return out;
}

export function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function callArgText(text, from) {
  const open = text.indexOf('(', from);
  if (open < 0) return '';
  let depth = 0;
  let quote = '';
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return '';
}

export function isInsideString(text, offset) {
  let quote = null;
  let triple = false;
  for (let i = 0; i < offset && i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (triple) {
        if (c === quote && text[i + 1] === quote && text[i + 2] === quote) { i += 2; quote = null; triple = false; }
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === '#') {
      const nl = text.indexOf('\n', i);
      if (nl === -1) return false;
      i = nl;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      triple = text[i + 1] === c && text[i + 2] === c;
      if (triple) i += 2;
    }
  }
  return quote !== null;
}

export function physicalIdx(unit, offset) {
  const newlines = unit.text.slice(0, offset).match(/\n/g);
  return unit.startLine - 1 + (newlines ? newlines.length : 0);
}
