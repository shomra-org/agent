const BASE64_BLOB_RE = /\b[A-Za-z0-9+/_-]{20,}={0,2}/g;

const DECODED_PAYLOAD_RE = /(\/bin\/(ba|z|k)?sh|\b(ba|z|k)?sh\s+-c|\bcurl\b|\bwget\b|\beval\b|\bexec\b|https?:\/\/|invoke-expression|\biex\b|powershell|\bnc\b|\bncat\b|\bchmod\b|\bbase64\b)/i;

const DECODED_COMMAND_RE = /(\/bin\/(ba|z|k)?sh|\b(ba|z|k)?sh\s+-c|\bcurl\b|\bwget\b|\beval\b|\bexec\b|invoke-expression|\biex\b|powershell|\bnc\b|\bncat\b|\bchmod\b|\bbase64\b|\bsystem\s*\(|\bos\.system|\bsubprocess\b)/i;

const HEX_ESCAPE_RUN_RE = /(?:\\x[0-9A-Fa-f]{2}){3,}/g;

const URL_ESCAPE_RUN_RE = /(?:%[0-9A-Fa-f]{2}){3,}/g;

const UNICODE_ESCAPE_RUN_RE = /(?:\\u\{?00[0-9A-Fa-f]{2}\}?){3,}/g;

const DECIMAL_CHAR_RUN_RE = /(?:\b(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\s*,\s*){6,}(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\b/g;

const printableRatio = (s) => (s ? s.replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '').length / s.length : 0);

export function deobfuscate(text) {
  const decoded = [];
  let payload = false;
  for (const m of text.matchAll(BASE64_BLOB_RE)) {
    let out = '';
    try { out = Buffer.from(m[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); } catch { continue; }
    if (!out || printableRatio(out) < 0.85) continue;
    if (DECODED_PAYLOAD_RE.test(out)) { decoded.push(out); payload = true; }
  }
  const literal = (run, decode) => {
    for (const m of text.matchAll(run)) {
      let out = '';
      try { out = decode(m[0]); } catch { continue; }
      if (!out || printableRatio(out) < 0.85) continue;
      decoded.push(out);
      if (DECODED_COMMAND_RE.test(out)) payload = true;
    }
  };
  const fromHex = (h) => String.fromCharCode(parseInt(h, 16));
  literal(HEX_ESCAPE_RUN_RE, (v) => v.replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => fromHex(h)));
  literal(URL_ESCAPE_RUN_RE, (v) => decodeURIComponent(v));
  literal(UNICODE_ESCAPE_RUN_RE, (v) => v.replace(/\\u\{?00([0-9A-Fa-f]{2})\}?/g, (_, h) => fromHex(h)));
  literal(DECIMAL_CHAR_RUN_RE, (v) => v.split(',').map((n) => String.fromCharCode(parseInt(n.trim(), 10))).join(''));
  return { text: decoded.length ? `${text}\n${decoded.join('\n')}` : text, decodedPayload: payload };
}

export const MARK_CONCEALED = 2;

export function codeMask(text) {
  const n = text.length;
  const mask = new Uint8Array(n);
  const REGEX_START = new Set(['=', '(', ',', '[', '{', ';', ':', '!', '&', '|', '?', '+', '*', '~', '%', '^', '<', '>', 'return', 'typeof']);
  let state = 0;
  let prevSig = '';
  let inClass = false;
  let i = 0;
  while (i < n) {
    const c = text[i], c2 = text[i + 1];
    if (state === 0) {

      if (text.startsWith('```', i) || text.startsWith('~~~', i)) {
        const fence = text.slice(i, i + 3);
        const nl = text.indexOf('\n', i);
        let end = n;
        if (nl !== -1) {
          const closeRe = new RegExp('\\n[ \\t]*' + fence.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
          const cm = text.slice(nl).match(closeRe);
          end = cm && cm.index != null ? nl + cm.index + cm[0].length : n;
        }
        for (let k = i; k < end; k++) mask[k] = 1;
        prevSig = ''; i = end; continue;
      }
      if (c === "'") { state = 1; mask[i++] = 1; continue; }
      if (c === '"') { state = 2; mask[i++] = 1; continue; }
      if (c === '`') { state = 3; mask[i++] = 1; continue; }
      if (c === '/' && c2 === '/') { state = 4; mask[i++] = 1; continue; }
      if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) { state = 4; mask[i++] = 1; continue; }
      if (c === '/' && c2 === '*') { state = 5; mask[i++] = 1; continue; }
      if (c === '<' && text.startsWith('<!--', i)) { state = 6; mask[i++] = MARK_CONCEALED; continue; }
      if (c === '/' && REGEX_START.has(prevSig)) { state = 7; inClass = false; mask[i++] = 1; continue; }
      if (!/\s/.test(c)) prevSig = c;
      i++;
      continue;
    }
    mask[i] = state === 6 ? MARK_CONCEALED : 1;
    if (state === 1) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === "'") { state = 0; prevSig = "'"; } i++; continue; }
    if (state === 2) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === '"') { state = 0; prevSig = '"'; } i++; continue; }
    if (state === 3) { if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; } if (c === '`') { state = 0; prevSig = '`'; } i++; continue; }
    if (state === 4) { if (c === '\n') state = 0; i++; continue; }
    if (state === 5) { if (c === '*' && c2 === '/') { mask[i + 1] = 1; i += 2; state = 0; } else i++; continue; }
    if (state === 6) { if (text.startsWith('-->', i)) { mask[i + 1] = MARK_CONCEALED; mask[i + 2] = MARK_CONCEALED; i += 3; state = 0; } else i++; continue; }
    if (state === 7) {
      if (c === '\\') { if (i + 1 < n) mask[++i] = 1; i++; continue; }
      if (c === '\n') { state = 0; }
      else if (c === '[') inClass = true;
      else if (c === ']') inClass = false;
      else if (c === '/' && !inClass) { state = 0; prevSig = '/'; }
      i++;
      continue;
    }
  }
  return mask;
}
