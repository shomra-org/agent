import { grade } from '../detect/guard-signals.mjs';
import { lineOf } from '../detect/signals/lines.mjs';
import { advisoriesDisabled, mcpAdvisoryFindings } from '../detect/signals/mcp-advisories.mjs';


export async function withMcpAdvisories(local, { content, path, kind, flags = {}, fetchImpl } = {}) {
  if (!['mcp', 'auto', undefined].includes(kind) || advisoriesDisabled(flags)) return { local, advisories: 'skipped' };
  const { status, findings } = await mcpAdvisoryFindings(content, path ?? '', fetchImpl ? { fetchImpl } : {});
  if (!findings.length) return { local, advisories: status };
  const seen = new Set(local.findings.map((f) => f.title));
  const added = findings
    .filter((f) => !seen.has(f.title))
    .map((f) => ({ severity: f.severity, title: f.title, remediationText: f.remediationText, ...(lineOf(content, f.anchor) ? { line: lineOf(content, f.anchor) } : {}) }));
  const all = [...local.findings, ...added];
  return { local: { ...local, ...grade(all), findings: all }, advisories: status };
}
