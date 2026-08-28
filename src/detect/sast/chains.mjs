import { CHAINS } from './rules-chains.mjs';
import { contextChunk } from './source-lines.mjs';

export function chainFindings(lines, findings, file) {
  const ids = new Set(findings.map((f) => f.ruleId));
  const out = [];
  for (const chain of CHAINS) {
    if (!chain.needs(ids)) continue;

    const anchor = findings.find((f) => chain.anchor.includes(f.ruleId));
    const line = anchor ? anchor.line : 1;
    const idx = Math.max(0, line - 1);
    out.push({
      ruleId: chain.id,
      title: chain.title,
      severity: chain.severity,
      category: chain.category,
      confidence: chain.confidence,
      file,
      line,
      sink: 'multi-signal',
      chain: [...new Set(findings.filter((f) => chain.parts.includes(f.ruleId)).map((f) => f.ruleId))],
      ...contextChunk(lines, idx),
      message: chain.message,
      remediation: chain.remediation,
      cwe: chain.cwe,
    });
  }
  return out;
}
