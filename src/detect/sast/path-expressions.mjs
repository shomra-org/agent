import { escapeRe } from './source-lines.mjs';

const DECL_PREFIX_RE = /\b(?:function|async|get|set|static|private|public|protected|readonly)\s*\*?\s*$/;

export function isNotAModuleLoad(m, unitText, argText) {
  if (DECL_PREFIX_RE.test(unitText.slice(Math.max(0, m.index - 24), m.index))) return true;
  if (/^\s*import\b/.test(m[0])) return false;
  let depth = 0;
  let quote = '';
  for (let i = 0; i < argText.length; i++) {
    const ch = argText[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = '';
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if ('([{'.includes(ch)) depth++;
    else if (')]}'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) return true;
  }
  return false;
}

const PATH_BIND_RE =
  /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?:node:)?path(?:\/(?:posix|win32))?['"]\s*\)|import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?path(?:\/(?:posix|win32))?['"]/g;

export function pathBindings(text) {
  const ns = new Set(['path']);
  PATH_BIND_RE.lastIndex = 0;
  for (let m = PATH_BIND_RE.exec(text); m; m = PATH_BIND_RE.exec(text)) ns.add(m[1] || m[2]);
  return ns;
}

const CONST_DECL_RE = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^\n;]+)/g;

const PATHISH_RE = /__dirname|__filename|import\.meta\.url|process\.cwd|os\.(?:homedir|tmpdir)|fileURLToPath|new\s+URL|\.(?:join|resolve|normalize)\s*\(/;

export function constPathBindings(text, pathNs) {
  const found = new Set();
  for (let round = 0; round < 2; round++) {
    CONST_DECL_RE.lastIndex = 0;
    for (let m = CONST_DECL_RE.exec(text); m; m = CONST_DECL_RE.exec(text)) {
      const [, name, rhsRaw] = m;
      if (found.has(name)) continue;
      const rhs = rhsRaw.replace(/[,;]\s*$/, '').trim();

      const buildsOnKnown = [...found].some((n) => new RegExp(`\\b${escapeRe(n)}\\b`).test(rhs));
      if (!PATHISH_RE.test(rhs) && !buildsOnKnown) continue;
      if (isStaticPathExpr(rhs, pathNs, found)) found.add(name);
    }
  }
  return found;
}

const PATH_FNS = 'join|resolve|normalize|relative|dirname|basename|extname';

export function isStaticPathExpr(argText, pathNs = new Set(['path']), constPaths = new Set()) {
  if (!argText.trim()) return false;
  const ns = [...pathNs].map(escapeRe).join('|');
  const consts = constPaths.size ? `|${[...constPaths].map(escapeRe).join('|')}` : '';
  const staticTokens = new RegExp(
    `\\b(?:(?:${ns})(?:\\.(?:posix|win32))?\\.(?:${PATH_FNS})|__dirname|__filename|import\\.meta\\.url|process\\.cwd|os\\.(?:homedir|tmpdir)|fileURLToPath|require\\.resolve|new\\s+URL|String\\.raw${consts})\\b`,
    'g',
  );

  const pureMembers = /\.(?:href|pathname|toString|toLowerCase|toUpperCase|trim|normalize|valueOf)\b/g;

  let t = argText
    .replace(/`(?:[^`\\]|\\.)*`/g, (lit) => ` ${[...lit.matchAll(/\$\{([^{}]*)\}/g)].map((x) => x[1]).join(' , ')} `)
    .replace(/'(?:[^'\\]|\\.)*'/g, ' ')
    .replace(/"(?:[^"\\]|\\.)*"/g, ' ');
  t = t.replace(pureMembers, ' ').replace(staticTokens, ' ');

  return !/[A-Za-z0-9_$]/.test(t.replace(/[\s(),.+[\]/\\:-]/g, ''));
}
