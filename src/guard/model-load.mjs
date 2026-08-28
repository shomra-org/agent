import path from 'node:path';
import { gateMachine } from '../core/api-client.mjs';
import { guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { isModelRefScannable, scanModelRefs } from '../detect/model-refs.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { MODEL_SEV_RANK, modelFixPlan, modelLookup } from '../models/lookup.mjs';
import { MODEL_WRITE_TOOLS } from './classify.mjs';
import { emitGuardAsk } from './emit.mjs';
import { reportGuardDecision } from './report.mjs';

export async function screenModelLoad(agent, tool, input, url) {
  if (process.env.SHOMRA_MODEL_GUARD === '0' || String(process.env.SHOMRA_MODEL_GUARD).toLowerCase() === 'false') return;
  if (!MODEL_WRITE_TOOLS.includes(String(tool).toLowerCase())) return;
  const filePath = input.file_path || input.path || input.filePath;
  if (!filePath || !isModelRefScannable(filePath)) return;
  let content = '';
  if (typeof input.content === 'string') content = input.content;
  else if (typeof input.new_string === 'string') content = input.new_string;
  else if (typeof input.new_str === 'string') content = input.new_str;
  else if (Array.isArray(input.edits)) content = input.edits.map((e) => e.new_string || e.new_str || '').join('\n');
  if (!content) return;
  const refs = scanModelRefs(content, path.basename(String(filePath))).filter((r) => r.source === 'hf');
  if (!refs.length) return;

  const flagged = [];

  const deadline = Date.now() + guardTimeoutMs();
  for (const r of refs) {
    const left = deadline - Date.now();
    if (left <= 0) break;
    let lk;
    try { lk = await modelLookup(url, r.id, r.revision, left); } catch { return; }
    const findings = (lk && lk.findings) || [];
    const worst = findings.reduce((m, f) => Math.max(m, MODEL_SEV_RANK[f.severity] || 0), 0);
    const bad = lk && lk.found && (lk.verdict === 'FAIL' || lk.verdict === 'REVIEW' || worst >= MODEL_SEV_RANK.HIGH);
    if (bad) flagged.push({ id: lk.resolvedId || r.id, verdict: lk.verdict, riskScore: lk.riskScore, findings, fix: modelFixPlan(findings, lk.sha) });
  }
  if (!flagged.length) return;

  const m = flagged[0];
  const titles = m.findings.slice(0, 2).map((f) => f.title).join('; ');
  const kw = ((m.fix || {}).kwargs || []).map((k) => `${k.name}=${k.value}`).join(', ');
  const extra = flagged.length > 1 ? ` (+${flagged.length - 1} more flagged model${flagged.length - 1 === 1 ? '' : 's'})` : '';
  const reason =
    `⚠ Shomra: "${m.id}" has known vulnerabilities (${m.verdict}, risk ${m.riskScore}) - ${titles}.${extra} ` +
    `Safer: add ${kw || 'safe-loading arguments'} to the load call, pin the reviewed revision, or choose another model. (SHOMRA_MODEL_GUARD=0 to silence.)`;
  await reportGuardDecision(url, resolveSettings(loadConfig()).apiKey, null, { tool_name: tool, tool_input: { file_path: filePath }, client_decision: 'FLAG', client_reason: `vulnerable model: ${m.id}`, machine: gateMachine(), env: detectEnv(), agent });
  emitGuardAsk(agent, reason);
}
