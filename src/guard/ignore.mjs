import path from 'node:path';
import { globToRe } from '../gate/suppressions.mjs';
import { repoPathStatus } from './allows.mjs';

const _guardIgnoreCache = new Map();

function guardIgnoreGlobs(root) {
  if (_guardIgnoreCache.has(root)) return _guardIgnoreCache.get(root);
  const globs = [];
  try { for (const p of repoPathStatus(root)) if (p.trusted) globs.push(p.re); } catch {  }
  const env = process.env.SHOMRA_GUARD_IGNORE;
  if (env) for (const g of String(env).split(/[,\n]+/).map((s) => s.trim()).filter(Boolean)) { try { globs.push(globToRe(g)); } catch {  } }
  _guardIgnoreCache.set(root, globs);
  return globs;
}

function relOf(root, filePath) {
  let rel;
  try { rel = path.relative(root, path.resolve(root, filePath)); } catch { rel = filePath; }
  rel = String(rel).split(path.sep).join('/');
  return { rel, base: rel.split('/').pop() };
}

export function guardPathAllowlisted(cwd, filePath) {
  if (!filePath) return false;
  const root = cwd || process.cwd();
  const { rel, base } = relOf(root, filePath);
  return guardIgnoreGlobs(root).some((re) => re.test(rel) || re.test(base));
}

export function untrustedPathLine(cwd, filePath) {
  if (!filePath) return null;
  const root = cwd || process.cwd();
  const { rel, base } = relOf(root, filePath);
  return repoPathStatus(root).find((p) => !p.trusted && (p.re.test(rel) || p.re.test(base)))?.glob ?? null;
}

export function pathTrustHint(glob) {
  return glob ? ` This repo's .shomraignore lists this file (${glob}), but that line is not trusted on this machine. Review it, then run in your own terminal: shomra allow --trust-repo` : '';
}
