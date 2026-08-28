import path from 'node:path';
import { VERSION } from '../core/version.mjs';

const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };

const SARIF_SEC = { CRITICAL: '9.0', HIGH: '7.5', MEDIUM: '5.0', LOW: '3.0', INFO: '1.0' };

function sarifRuleId(f) {
  return f.ruleId || 'shomra.' + String(f.title || 'finding').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}

export function toSarif(results) {
  const rules = new Map();
  const sarifResults = [];
  for (const r of results) {
    for (const f of r.findings || []) {
      const id = sarifRuleId(f);
      if (!rules.has(id)) rules.set(id, { id, name: id, shortDescription: { text: String(f.title || id).slice(0, 200) }, ...(f.cwe ? { properties: { cwe: f.cwe, tags: ['security', f.cwe] } } : { properties: { tags: ['security'] } }) });
      sarifResults.push({
        ruleId: id,
        level: SARIF_LEVEL[f.severity] || 'warning',
        message: { text: f.remediationText ? `${f.title} - ${f.remediationText}` : String(f.title || id) },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file || r.path }, ...(f.line ? { region: { startLine: f.line } } : {}) } }],
        properties: { severity: f.severity, 'security-severity': SARIF_SEC[f.severity] || '5.0', ...(f.cwe ? { cwe: f.cwe } : {}) },
      });
    }
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Shomra', informationUri: 'https://shomra.dev', version: VERSION, rules: [...rules.values()] } }, results: sarifResults }],
  };
}
