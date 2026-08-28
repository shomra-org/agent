import path from 'node:path';
import { globToRe, loadIgnoreRules } from '../gate/suppressions.mjs';

const _guardIgnoreCache = new Map();

function guardIgnoreGlobs(root) {
  if (_guardIgnoreCache.has(root)) return _guardIgnoreCache.get(root);
  const globs = [];
  try { for (const re of loadIgnoreRules(root).fileGlobs) globs.push(re); } catch {  }
  const env = process.env.SHOMRA_GUARD_IGNORE;
  if (env) for (const g of String(env).split(/[,\n]+/).map((s) => s.trim()).filter(Boolean)) { try { globs.push(globToRe(g)); } catch {  } }
  _guardIgnoreCache.set(root, globs);
  return globs;
}

export function guardPathAllowlisted(cwd, filePath) {
  if (!filePath) return false;
  const root = cwd || process.cwd();
  let rel;
  try { rel = path.relative(root, path.resolve(root, filePath)); } catch { rel = filePath; }
  rel = String(rel).split(path.sep).join('/');
  const base = rel.split('/').pop();
  return guardIgnoreGlobs(root).some((re) => re.test(rel) || re.test(base));
}
