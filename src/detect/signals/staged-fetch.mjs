const STAGED_LOOPBACK_RE = /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\]|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})$/i;

const STAGED_METADATA_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal']);

function targetsExternalNetwork(line) {
  const urls = line.match(/https?:\/\/[^\s'"`;|)&]+/gi);
  if (!urls?.length) return true;
  return urls.some((raw) => {
    let host;
    try { host = new URL(raw).hostname.toLowerCase(); } catch { return true; }
    if (STAGED_METADATA_HOSTS.has(host)) return true;
    return !STAGED_LOOPBACK_RE.test(host);
  });
}

const FETCH_TO_FILE = [
  /\b(?:curl|wget)\b[^\n;|&]{0,200}?(?:-o|-O|--output(?:-document)?)[= ]\s*["']?([^\s"'>;|&]+)/gi,
  /\b(?:curl|wget)\b[^\n;|&]{0,200}?>\s*["']?([^\s"'>;|&]+)/gi,
  /\b(?:invoke-webrequest|iwr|curl)\b[^\n;|&]{0,200}?-outfile\s+["']?([^\s"';|&]+)/gi,
];

const BARE_WGET_RE = /\bwget\b(?![^\n;|&]{0,200}(?:-O|--output-document))[^\n;|&]{0,200}?(https?:\/\/[^\s"';|&]+)/gi;

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function execPattern(target) {
  const full = escapeRe(target);
  const base = escapeRe(target.replace(/^.*\//, ''));
  const p = `(?:${full}|(?:\\./|/tmp/|~/|\\$\\w+/)?${base})`;
  return new RegExp(
    `\\bchmod\\b[^\\n;|&]{0,40}\\+x[^\\n;|&]{0,40}${p}` +
      `|\\bchmod\\b[^\\n;|&]{0,40}\\b[0-7]*[1357]\\b[^\\n;|&]{0,40}${p}` +
      `|(?:^|[\\n;&|]\\s*|\\bsudo\\s+)(?:ba|z|k|da)?sh\\s+[^\\n]{0,40}${p}` +
      `|(?:^|[\\n;&|]\\s*|\\bsudo\\s+)(?:python[0-9.]*|node|perl|ruby|php|pwsh|powershell)\\s+[^\\n]{0,40}${p}` +
      `|(?:^|[\\n;&|]\\s*)(?:\\.|source)\\s+${p}` +
      `|(?:^|[\\n;&|]\\s*|&&\\s*)(?:sudo\\s+)?\\./${base}\\b`,
    'i',
  );
}

export function scanStagedFetchExec(text) {
  if (!text) return [];
  const targets = new Map();
  const record = (name, at, stmt) => {
    if (!name || targets.has(name)) return;
    if (/^\/dev\/(null|stdout|stderr)$/i.test(name)) return;
    if (!targetsExternalNetwork(stmt)) return;
    targets.set(name, at);
  };
  for (const re of FETCH_TO_FILE) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) record(m[1], m.index ?? 0, m[0]);
  }
  BARE_WGET_RE.lastIndex = 0;
  for (const m of text.matchAll(BARE_WGET_RE)) {
    let base = '';
    try { base = new URL(m[1]).pathname.split('/').filter(Boolean).pop() ?? ''; } catch { continue; }
    record(base, m.index ?? 0, m[0]);
  }
  for (const [target, at] of targets) {
    if (execPattern(target).test(text.slice(at))) {
      return [{ name: 'Downloads a file and then executes it (staged fetch-to-execute)', re: new RegExp(escapeRe(target), 'i'), severity: 'CRITICAL' }];
    }
  }
  return [];
}
