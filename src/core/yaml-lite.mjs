const MAX_BYTES = 1024 * 1024;
const MAX_DEPTH = 64;
const MAX_ALIASES = 1000;
const MAX_EXPANDED = 100_000;

class YamlError extends Error {}

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (q === '"' && c === '\\') { i++; continue; }
      if (c === q) q = null;
      continue;
    }
    if (c === '"' || c === "'") {
      if (i === 0 || /[\s:,[{-]/.test(s[i - 1])) q = c;
      continue;
    }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
}

function scalar(raw) {
  const v = raw.trim();
  if (v === '' || v === '~' || v === 'null' || v === 'Null' || v === 'NULL') return null;
  if (/^(?:true|True|TRUE)$/.test(v)) return true;
  if (/^(?:false|False|FALSE)$/.test(v)) return false;
  if (/^[-+]?\d+$/.test(v) && v.length < 16) return Number(v);
  if (/^[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?$/.test(v)) return Number(v);
  if (v[0] === '"') return doubleQuoted(v);
  if (v[0] === "'") return v.slice(1, v.endsWith("'") ? -1 : undefined).replace(/''/g, "'");
  return v;
}

function doubleQuoted(v) {
  const body = v.slice(1, v.endsWith('"') ? -1 : undefined);
  return body.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_, e) => {
    if (e[0] === 'u' || e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
    return { n: '\n', t: '\t', r: '\r', '0': '\0', '"': '"', '\\': '\\', '/': '/', ' ': ' ', b: '\b', e: '\x1b' }[e] ?? e;
  });
}

function parseFlow(src, ctx) {
  let i = 0;
  const ws = () => { while (i < src.length && /\s/.test(src[i])) i++; };
  const value = (depth) => {
    if (depth > MAX_DEPTH) throw new YamlError('depth');
    ws();
    const c = src[i];
    if (c === '[') {
      i++;
      const out = [];
      for (;;) {
        ws();
        if (src[i] === ']') { i++; return out; }
        if (i >= src.length) throw new YamlError('unterminated [');
        out.push(value(depth + 1));
        ws();
        if (src[i] === ',') i++;
        else if (src[i] !== ']') throw new YamlError('flow seq');
      }
    }
    if (c === '{') {
      i++;
      const out = {};
      for (;;) {
        ws();
        if (src[i] === '}') { i++; return out; }
        if (i >= src.length) throw new YamlError('unterminated {');
        const k = token(true);
        ws();
        let v = null;
        if (src[i] === ':') { i++; v = value(depth + 1); }
        out[String(k ?? '')] = v;
        ws();
        if (src[i] === ',') i++;
        else if (src[i] !== '}') throw new YamlError('flow map');
      }
    }
    return token(false);
  };
  const token = (isKey) => {
    ws();
    const c = src[i];
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < src.length) {
        if (c === '"' && src[j] === '\\') { j += 2; continue; }
        if (src[j] === c) { if (c === "'" && src[j + 1] === "'") { j += 2; continue; } break; }
        j++;
      }
      const raw = src.slice(i, j + 1);
      i = j + 1;
      return scalar(raw);
    }
    if (c === '*') {
      let j = i + 1;
      while (j < src.length && !/[\s,\]}]/.test(src[j])) j++;
      const name = src.slice(i + 1, j);
      i = j;
      return ctx.alias(name);
    }
    let j = i;
    while (j < src.length && !(src[j] === ',' || src[j] === ']' || src[j] === '}' || (isKey && src[j] === ':' && /[\s,\]}]|$/.test(src[j + 1] ?? '')))) j++;
    const raw = src.slice(i, j);
    i = j;
    return scalar(raw);
  };
  const out = value(0);
  return out;
}

function balanced(s) {
  let depth = 0;
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (q === '"' && c === '\\') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") q = c;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
  }
  return depth <= 0;
}

export function parseYaml(text) {
  if (typeof text !== 'string' || text.length > MAX_BYTES) return null;
  const rawLines = text.replace(/^﻿/, '').replace(/\t/g, '  ').split(/\r?\n/);
  const lines = [];
  let started = false;
  for (let n = 0; n < rawLines.length; n++) {
    const raw = rawLines[n];
    if (/^%/.test(raw) && !started) continue;
    if (/^(?:---|\.\.\.)(?:\s|$)/.test(raw)) {
      if (started) break;
      const rest = raw.replace(/^---\s*/, '');
      if (rest && !rest.startsWith('#')) { started = true; lines.push({ indent: 0, text: rest, raw, n }); }
      continue;
    }
    const indent = raw.search(/\S/);
    if (indent === -1) { lines.push({ indent: -1, text: '', raw, n }); continue; }
    const stripped = stripComment(raw.slice(indent));
    if (!stripped) continue;
    started = true;
    lines.push({ indent, text: stripped, raw, n });
  }

  const anchors = new Map();
  let aliasUses = 0;
  let expanded = 0;
  const weights = new WeakMap();
  const weight = (v) => {
    if (!v || typeof v !== 'object') return 1;
    if (weights.has(v)) return weights.get(v);
    weights.set(v, 1);
    let w = 1;
    for (const c of Array.isArray(v) ? v : Object.values(v)) { w += weight(c); if (w > MAX_EXPANDED) break; }
    weights.set(v, w);
    return w;
  };
  const ctx = {
    alias(name) {
      if (++aliasUses > MAX_ALIASES) throw new YamlError('alias bomb');
      if (!anchors.has(name)) throw new YamlError(`unknown alias ${name}`);
      const v = anchors.get(name);
      expanded += weight(v);
      if (expanded > MAX_EXPANDED) throw new YamlError('alias bomb');
      return v;
    },
  };
  let i = 0;
  const peek = () => { while (i < lines.length && lines[i].indent === -1) i++; return lines[i]; };

  const KEY_RE = /^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^\s#'"{[][^:]*?|[^\s#'"{[]))\s*:(?:\s+(.*)|$)/;

  function blockScalar(header, parentIndent) {
    const style = header[0];
    const chomp = /-/.test(header) ? 'strip' : /\+/.test(header) ? 'keep' : 'clip';
    const explicit = /\d/.exec(header);
    const collected = [];
    let blockIndent = explicit ? parentIndent + Number(explicit[0]) : -1;
    while (i < lines.length) {
      const l = lines[i];
      const rawIndent = l.raw.search(/\S/);
      if (rawIndent === -1) { collected.push(''); i++; continue; }
      if (rawIndent <= parentIndent) break;
      if (blockIndent === -1) blockIndent = rawIndent;
      if (rawIndent < blockIndent) break;
      collected.push(l.raw.replace(/\t/g, '  ').slice(blockIndent));
      i++;
    }
    while (collected.length && collected[collected.length - 1] === '' && chomp !== 'keep') collected.pop();
    let out;
    if (style === '|') out = collected.join('\n');
    else {
      out = '';
      for (let k = 0; k < collected.length; k++) {
        const line = collected[k];
        if (line === '') out += '\n';
        else if (/^\s/.test(line)) out += (out && !out.endsWith('\n') ? '\n' : '') + line + '\n';
        else out += (out && !out.endsWith('\n') && !out.endsWith(' ') ? ' ' : '') + line;
      }
      out = out.replace(/\n+$/, '');
    }
    return chomp === 'strip' ? out : out + '\n';
  }

  function inlineValue(rest, parentIndent, depth) {
    let v = rest.trim();
    let anchor = null;
    const am = /^&([^\s,\]}]+)\s*(.*)$/.exec(v);
    if (am) { anchor = am[1]; v = am[2]; }
    v = v.replace(/^!\S*\s*/, ''); // tags are ignored
    let out;
    if (v === '') {
      const nx = peek();
      if (nx && (nx.indent > parentIndent || (nx.indent === parentIndent && /^-(?:\s|$)/.test(nx.text)))) out = node(nx.indent, depth + 1);
      else out = null;
    } else if (/^[|>][-+0-9]*$/.test(v)) out = blockScalar(v, parentIndent);
    else if (v[0] === '*') out = ctx.alias(v.slice(1).trim());
    else if (v[0] === '[' || v[0] === '{') {
      let src = v;
      while (!balanced(src) && i < lines.length) { const l = lines[i++]; if (l.indent !== -1) src += ' ' + l.text; }
      out = parseFlow(src, ctx);
    } else if ((v[0] === '"' && !/"$/.test(v.slice(1))) || (v[0] === "'" && !/'$/.test(v.slice(1)))) {
      let src = v;
      const q = v[0];
      while (i < lines.length && !new RegExp(`${q}\\s*$`).test(src.slice(1))) { const l = lines[i++]; src += ' ' + (l.indent === -1 ? '' : l.text); }
      out = scalar(src);
    } else {
      let src = v;
      while (i < lines.length) {
        const l = lines[i];
        if (l.indent === -1 || l.indent <= parentIndent || KEY_RE.test(l.text) || /^-(?:\s|$)/.test(l.text)) break;
        src += ' ' + l.text;
        i++;
      }
      out = scalar(src);
    }
    if (anchor) anchors.set(anchor, out);
    return out;
  }

  function node(indent, depth) {
    if (depth > MAX_DEPTH) throw new YamlError('depth');
    const l = peek();
    if (!l) return null;
    if (/^-(?:\s|$)/.test(l.text)) return seq(l.indent, depth);
    if (KEY_RE.test(l.text)) return map(l.indent, depth);
    i++;
    return inlineValue(l.text, indent - 1, depth);
  }

  function seq(indent, depth) {
    const out = [];
    for (;;) {
      const l = peek();
      if (!l || l.indent !== indent || !/^-(?:\s|$)/.test(l.text)) break;
      const content = l.text.replace(/^-\s*/, '');
      const offset = l.text.length - content.length;
      if (content && (KEY_RE.test(content) || /^-(?:\s|$)/.test(content)) && !/^[[{"']/.test(content)) {
        lines[i] = { ...l, indent: indent + offset, text: content };
        out.push(node(indent + offset, depth + 1));
      } else {
        i++;
        out.push(inlineValue(content, indent, depth));
      }
    }
    return out;
  }

  function map(indent, depth) {
    const out = {};
    const merges = [];
    for (;;) {
      const l = peek();
      if (!l || l.indent !== indent) break;
      const m = KEY_RE.exec(l.text);
      if (!m) break;
      i++;
      const key = m[1] != null ? doubleQuoted(`"${m[1]}"`) : m[2] != null ? m[2].replace(/''/g, "'") : m[3].trim();
      const val = inlineValue(m[4] ?? '', indent, depth);
      if (key === '<<') merges.push(...(Array.isArray(val) ? val : [val]));
      else out[key] = val;
    }
    for (const src of merges) if (src && typeof src === 'object' && !Array.isArray(src)) for (const [k, v] of Object.entries(src)) if (!(k in out)) out[k] = v;
    return out;
  }

  try {
    const first = peek();
    if (!first) return null;
    return node(first.indent, 0);
  } catch {
    return null;
  }
}
