import { contextChunk, escapeRe, isCommentLine, physicalIdx } from './source-lines.mjs';

function parseAssign(text) {
  const m = /^\s*(?:export\s+)?(?:const|let|var|await\s+)?\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::[^=\n]+?)?=(?![=>])\s*([\s\S]+)$/.exec(text);
  if (!m) return null;
  const vars = m[1].split(',').map((s) => s.trim()).filter(Boolean);
  return { vars, rhs: m[2] };
}

export function taintFindings(lines, units, file, cfg) {
  const tainted = new Set();

  for (let pass = 0; pass < 2; pass++) {
    for (const unit of units) {
      const a = parseAssign(unit.text);
      if (!a) continue;
      let taint = cfg.aiCall.test(a.rhs);
      if (!taint) {
        for (const t of tainted) {
          if (new RegExp(`\\b${escapeRe(t)}\\b`).test(a.rhs)) { taint = true; break; }
        }
      }
      if (taint) for (const v of a.vars) tainted.add(v);
    }
    if (!tainted.size) break;
  }
  if (!tainted.size) return [];

  const out = [];
  const seen = new Set();
  for (const unit of units) {
    cfg.execSink.lastIndex = 0;
    let m;
    while ((m = cfg.execSink.exec(unit.text))) {

      const paren = unit.text.indexOf('(', m.index);
      const argRegion = paren >= 0 ? unit.text.slice(paren) : '';
      let via = null;
      for (const t of tainted) {
        if (new RegExp(`\\b${escapeRe(t)}\\b`).test(argRegion)) { via = t; break; }
      }
      if (via) {
        const idx = physicalIdx(unit, m.index);
        const trimmed = (lines[idx] ?? '').trim();
        if (trimmed && !isCommentLine(trimmed) && !seen.has(idx)) {
          seen.add(idx);
          const sink = m[0].replace(/\s*\($/, '').trim();
          out.push({
            ruleId: cfg.ruleId,
            title: 'LLM output may reach a code-execution sink (heuristic)',

            severity: 'HIGH',
            category: 'taint-heuristic',
            confidence: 0.5,
            file,
            line: idx + 1,
            sink: sink.slice(0, 120),
            source: 'LLM output',
            taint: `${via} (LLM output) → ${sink} (heuristic name match - confirm)`,
            ...contextChunk(lines, idx),
            message: `A variable that appears to derive from an LLM call ("${via}") is used in ${sink}. If that value really is model-controlled, a prompt-injected instruction becomes code execution in the host - a critical agent vulnerability. Flagged by a name-propagation heuristic (no dataflow proof), so confirm the value is actually the model output and not reassigned/sanitized before this line.`,
            remediation: 'If confirmed, never pass model output to eval/exec/subprocess. Constrain the model to structured output (a fixed schema / tool-call allowlist), validate it, and dispatch on named handlers - never execute it.',
            cwe: 'CWE-94',
          });
        }
      }
      if (!cfg.execSink.global) break;
    }
  }
  return out;
}
