import { chainFindings } from './chains.mjs';
import { constPathBindings, pathBindings } from './path-expressions.mjs';
import { CONFIG_RULES } from './rules-config.mjs';
import { JS_RULES, JS_TAINT } from './rules-javascript.mjs';
import { PY_RULES, PY_TAINT } from './rules-python.mjs';
import { contextChunk, isCommentLine, isInsideString, logicalLines, physicalIdx } from './source-lines.mjs';
import { taintFindings } from './taint.mjs';

function scanLines(text, file, rules, taintCfg) {
  const lines = text.split(/\r?\n/);
  const units = logicalLines(lines);
  const out = [];
  const seen = new Set();

  const pathNs = pathBindings(text);
  const ctx = { pathNs, constPaths: constPathBindings(text, pathNs) };
  for (const unit of units) {
    for (const rule of rules) {
      rule.re.lastIndex = 0;
      const m = rule.re.exec(unit.text);
      if (!m) continue;

      if (rule.codeOnly && isInsideString(unit.text, m.index)) continue;

      if (rule.suppress && rule.suppress(m, unit.text, ctx)) continue;
      const idx = physicalIdx(unit, m.index);
      const trimmed = (lines[idx] ?? '').trim();
      if (!trimmed || isCommentLine(trimmed)) continue;
      const key = `${rule.id}@${idx}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: rule.category,
        confidence: rule.confidence,
        file,
        line: idx + 1,
        sink: (rule.sink ? rule.sink(m) : m[0]).slice(0, 120),
        source: rule.source || undefined,
        ...contextChunk(lines, idx),
        message: rule.message,
        remediation: rule.remediation,
        cwe: rule.cwe,
      });
    }
  }
  if (taintCfg) out.push(...taintFindings(lines, units, file, taintCfg));
  out.push(...chainFindings(lines, out, file));
  return out;
}

export function scanPythonSource(text, file) { return text ? scanLines(text, file, PY_RULES, PY_TAINT) : []; }

export function scanJsSource(text, file) { return text ? scanLines(text, file, JS_RULES, JS_TAINT) : []; }

export function scanModelConfig(text, file) { return text ? scanLines(text, file, CONFIG_RULES, null) : []; }

export function scanNotebook(text, file) {
  if (!text) return [];
  let nb;
  try { nb = JSON.parse(text); } catch { return []; }
  const cells = Array.isArray(nb?.cells) ? nb.cells : [];
  const lang = String(nb?.metadata?.kernelspec?.language || nb?.metadata?.language_info?.name || 'python').toLowerCase();
  const isJs = /javascript|typescript|deno|node|^js$|^ts$/.test(lang);
  const rules = isJs ? JS_RULES : PY_RULES;
  const taintCfg = isJs ? JS_TAINT : PY_TAINT;
  const out = [];
  let codeCell = 0;
  for (const cell of cells) {
    if (cell?.cell_type !== 'code') continue;
    codeCell++;
    const src = Array.isArray(cell.source) ? cell.source.join('') : String(cell.source ?? '');
    if (!src.trim()) continue;
    out.push(...scanLines(src, `${file}#cell${codeCell}`, rules, taintCfg));
  }
  return out;
}

const PY_EXT = /\.py$/i;

const JS_EXT = /\.(m|c)?[jt]sx?$/i;

const NB_EXT = /\.ipynb$/i;

const MODEL_CONFIG_RE = /(^|\/)(config|tokenizer_config|generation_config|preprocessor_config)\.json$/i;

export function isScannableSource(path) {
  return PY_EXT.test(path) || JS_EXT.test(path) || NB_EXT.test(path);
}

export function isModelConfig(path) {
  return MODEL_CONFIG_RE.test(String(path ?? '').split(/[\\/]+/).join('/'));
}

export function scanSourceFile(text, file) {
  if (!text) return [];
  if (NB_EXT.test(file)) return scanNotebook(text, file);
  if (PY_EXT.test(file)) return scanPythonSource(text, file);
  if (JS_EXT.test(file)) return scanJsSource(text, file);
  if (isModelConfig(file)) return scanModelConfig(text, file);
  return [];
}
