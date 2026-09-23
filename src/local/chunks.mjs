const MAX_SCAN_CHARS = 256 * 1024;
const MIN_ADDRESS = 2;

const ADDRESS_RE = /\b(?:you|your|yourself|assistant|ai|agent|agents|model|llm|claude|copilot|gpt|chatbot|bot|bots|system|instructions?|directive|prompt|ignore|disregard|override|supersede|must|instead|do not|don'?t|never|always|reveal|send|forward|upload|email|paste|push|approve|grant|bypass|disable|exfiltrate|execute|run|curl|wget|delete|secret|secrets|password|token|credentials?|private keys?)\b/gi;

export function addressScore(text) {
  let n = 0;
  for (const _ of String(text).matchAll(ADDRESS_RE)) if (++n >= 24) break;
  return n;
}

function segments(text) {
  const out = [];
  for (const piece of text.split(/\n+|(?<=[.!?])\s+(?=[A-Z<[(#*"'`-])/)) {
    const s = piece.replace(/\s+/g, ' ').trim();
    if (s) out.push(s);
  }
  return out;
}

export function pickWindows(input, { max = 6, width = 320 } = {}) {
  const text = String(input ?? '').slice(0, MAX_SCAN_CHARS);
  if (!text.trim()) return [];
  const windows = [];
  let cur = '';
  const flush = () => {
    if (cur) windows.push(cur);
    cur = '';
  };
  for (const seg of segments(text)) {
    if (seg.length > width) {
      flush();
      for (let i = 0; i < seg.length; i += width) windows.push(seg.slice(i, i + width));
      continue;
    }
    if (cur && cur.length + 1 + seg.length > width) flush();
    cur = cur ? `${cur} ${seg}` : seg;
  }
  flush();
  const seen = new Set();
  return windows
    .map((w, i) => ({ w, i, score: addressScore(w) }))
    .filter((x) => x.score >= MIN_ADDRESS && !seen.has(x.w) && seen.add(x.w))
    .sort((a, b) => b.score - a.score || a.i - b.i)
    .slice(0, max)
    .sort((a, b) => a.i - b.i)
    .map((x) => x.w);
}

export function textLeaves(value, { max = MAX_SCAN_CHARS } = {}) {
  if (typeof value === 'string') return value.slice(0, max);
  const out = [];
  const stack = [value];
  let total = 0;
  let steps = 0;
  while (stack.length && total < max && steps++ < 20_000) {
    const v = stack.pop();
    if (typeof v === 'string') {
      if (v.length >= 12) {
        out.push(v);
        total += v.length + 1;
      }
    } else if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push(v[i]);
    } else if (v && typeof v === 'object') {
      const vals = Object.values(v);
      for (let i = vals.length - 1; i >= 0; i--) stack.push(vals[i]);
    }
  }
  return out.join('\n').slice(0, max);
}
