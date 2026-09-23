import fs from 'node:fs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { classifyConsequence, downrankCodeContext, grade, localScan } from '../detect/guard-signals.mjs';
import { runtimeRule } from '../telemetry/events.mjs';
import { recordLabel, recordVerdict, telemetryContext } from '../telemetry/record.mjs';
import { resolveAgentIdentityHandle } from './agent-handle.mjs';
import { DESTRUCTIVE_RULE, allowHint, allowMatches, applyAllows, consumeOnce, loadOrgAllows, loadRepoAllows, loadUserAllows, ruleIdOf } from './allows.mjs';
import { recordAsk, rememberedApproval } from './approvals.mjs';
import { MODEL_WRITE_TOOLS, SHELL_TOOLS_RE, WRITE_TOOLS, guardTargetPath, guardText, shellCommandOf } from './classify.mjs';
import { emitGuardAsk, emitGuardDeny } from './emit.mjs';
import { guardPathAllowlisted } from './ignore.mjs';
import { normalizeGuardInput } from './normalize.mjs';
import { envFlag, localTierDisabled, resolveAgentFlag } from './options.mjs';
import { selfProtectionFindings } from './self-protect.mjs';
import { recordSelftest } from './selftest-marker.mjs';

const ALLOW_VERDICT = { verdict: 'ALLOW', top: null, findings: [] };


function failOpenOnSevere() {
  return envFlag('SHOMRA_GUARD_FAILOPEN_SEVERE');
}

function unscreenedSevere(normalized, tool, input) {
  if (failOpenOnSevere()) return false;
  return classifyConsequence({
    tool,
    args: guardText(tool, input),
    isShell: !WRITE_TOOLS.has(tool) && typeof input?.command === 'string',
  }) === 'severe';
}

function unscreenedReason(why) {
  return `Shomra could not screen this call (${why}), and it is a destructive one - a delete, a force push, `
    + 'or a write to a file that survives the session. Nothing has judged it: approve it only if you meant it. '
    + 'Set SHOMRA_GUARD_FAILOPEN_SEVERE=1 to let these through unscreened.';
}

function destructiveReason(command) {
  const match = String(command ?? '').trim().split(/\s+/).slice(0, 4).join(' ');
  return 'Shomra: this command is destructive - a delete, a hard reset, a force push or a volume wipe - so it needs a person to say yes. '
    + `Approve it only if you meant it. To stop being asked for it: shomra allow destructive --match "${match}" --for 1h`;
}

function confirmReason(finding) {
  return `Shomra: ${finding.label}. This runs with your permissions on this machine, so it needs a person to say yes. `
    + 'Approve it only if you asked for it.';
}

function askHuman(agent, normalized, command, reason, tctx, finding) {
  if (command && rememberedApproval(normalized, command)) {
    if (finding) recordLabel({ channel: 'tool', label: 'approved', findings: [finding], rule: runtimeRule, dedupe: `approved|${normalized.session_id}|${command}` }, tctx);
    return false;
  }
  recordAsk(normalized?.session_id, command);
  emitGuardAsk(agent, reason);
  return true;
}

function askUnscreened(agent, why, normalized, command, tctx) {
  askHuman(agent, normalized, command, unscreenedReason(why), tctx, null);
}

function readHookPayload() {
  try {
    return JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    return process.exit(0);
  }
}

function summarize(findings, shadow = []) {
  const top = findings.find((finding) => finding.severity === 'CRITICAL') || findings.find((finding) => finding.confirm) || findings[0] || null;
  return { ...grade(findings), top, findings, shadow, confirm: findings.find((finding) => finding.confirm) ?? null };
}

function screenLocally(normalized, tool, input) {
  const scan = localScan(guardText(tool, input));
  const isWrite = WRITE_TOOLS.has(tool);
  const target = isWrite ? guardTargetPath(normalized) : null;
  const allowlisted = isWrite && guardPathAllowlisted(normalized.cwd, target);

  let findings = scan.findings;
  if (allowlisted) findings = [];
  else if (isWrite) findings = downrankCodeContext(scan.findings);

  const command = isWrite ? null : shellCommandOf(input);
  findings = [...findings, ...selfProtectionFindings({ isWrite, targetPath: target, command, cwd: normalized.cwd })];
  return summarize(findings, allowlisted ? [] : scan.shadow ?? []);
}

function allowSources(normalized) {
  return [...loadUserAllows(), ...loadRepoAllows(normalized.cwd || process.cwd()), ...loadOrgAllows()];
}

function destructiveAllowed(command, normalized) {
  if (!command) return false;
  const hit = allowSources(normalized).find((a) => allowMatches(a, DESTRUCTIVE_RULE, command));
  if (hit) consumeOnce([{ allow: hit }]);
  return !!hit;
}

function applyLocalAllows(local, command, normalized, tctx, tool) {
  if (!local.findings.length) return local;
  const sources = allowSources(normalized);
  if (!sources.length) return local;
  const { findings, allowed } = applyAllows(local.findings, command, sources);
  if (!allowed.length) return local;
  consumeOnce(allowed);
  recordLabel({ channel: 'tool', label: 'policy-allow', tool, findings: allowed.map((a) => a.finding), rule: runtimeRule }, tctx);
  return { ...summarize(findings, local.shadow), allowedBy: allowed.map((a) => a.allow.source) };
}

function recordToolVerdict(tctx, { agent, normalized, tool, input, verdict, local, decidedBy, consequence }) {
  const shell = SHELL_TOOLS_RE.test(tool) || typeof input?.command === 'string' || Array.isArray(input?.command) || Array.isArray(input?.argv);
  recordVerdict({
    channel: 'tool',
    agent,
    tool,
    verdict,
    findings: local.findings,
    shadow: local.shadow,
    decidedBy,
    consequence,
    command: shell ? shellCommandOf(input) : null,
    target: WRITE_TOOLS.has(tool) ? guardTargetPath(normalized) : null,
    text: guardText(tool, input),
    at: local.top?.at,
    session: normalized.session_id,
    latencyMs: performance.now(),
  }, tctx);
}

export async function cmdToolGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const agentId = resolveAgentIdentityHandle(flags);
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const alwaysEscalate = envFlag('SHOMRA_GUARD_ALWAYS_ESCALATE');
  const cfg = loadConfig();
  const { apiKey, url } = resolveSettings(cfg);
  const tctx = telemetryContext(cfg);

  const normalized = normalizeGuardInput(agent, readHookPayload());
  const tool = (normalized.tool_name ?? '').trim();
  const input = normalized.tool_input ?? {};

  const commandText = WRITE_TOOLS.has(tool) ? guardText(tool, input) : shellCommandOf(input) || guardText(tool, input);
  let local = localTierDisabled() ? ALLOW_VERDICT : screenLocally(normalized, tool, input);
  const decidedBy = localTierDisabled() ? 'unscreened' : 'local';
  if (apiKey && (local.verdict === 'BLOCK' || local.confirm)) {
    const { refreshOrgAllows } = await import('./org-allows.mjs');
    await refreshOrgAllows({ url, apiKey });
  }
  local = applyLocalAllows(local, commandText, normalized, tctx, tool);
  if (local.verdict === 'BLOCK') {
    recordSelftest({ stage: 'local-block', tool, reason: local.top?.label ?? 'dangerous tool call' });
    recordToolVerdict(tctx, { agent, normalized, tool, input, verdict: 'BLOCK', local, decidedBy });
    if (apiKey) {
      const { buildGuardBody, reportGuardDecision } = await import('./report.mjs');
      await reportGuardDecision(url, apiKey, agentId, buildGuardBody(normalized, agent, 'BLOCK', local.top?.label));
    }
    emitGuardDeny(agent, `Blocked on-machine by Shomra: ${local.top?.label || 'dangerous tool call'}.${allowHint(ruleIdOf(local.top), commandText)}`);
  }

  if (MODEL_WRITE_TOOLS.includes(String(tool).toLowerCase())) {
    const { screenModelLoad } = await import('./model-load.mjs');
    await screenModelLoad(agent, tool, input, url);
  }

  if (!apiKey) {
    recordSelftest({ stage: 'not-configured', tool });
    if (strict) {
      emitGuardDeny(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    }
    const severe = unscreenedSevere(normalized, tool, input) && !destructiveAllowed(commandText, normalized);
    const confirm = local.confirm;
    recordToolVerdict(tctx, {
      agent, normalized, tool, input, local,
      verdict: severe || confirm ? 'ASK' : local.verdict,
      decidedBy: confirm ? decidedBy : severe ? 'consequence' : decidedBy,
      consequence: severe ? 'severe' : null,
    });
    if (confirm) askHuman(agent, normalized, commandText, confirmReason(confirm), tctx, confirm);
    else if (severe) askHuman(agent, normalized, commandText, destructiveReason(commandText), tctx, null);
    process.exit(0);
  }

  const severe = unscreenedSevere(normalized, tool, input) && !destructiveAllowed(commandText, normalized);
  const { escalateToServer } = await import('./tool-guard-server.mjs');
  return escalateToServer({
    agent,
    agentId,
    strict,
    alwaysEscalate,
    url,
    apiKey,
    normalized,
    tool,
    input,
    local,
    severe,
    askConfirm: () => askHuman(agent, normalized, commandText, confirmReason(local.confirm), tctx, local.confirm),
    askSevere: (why) => askUnscreened(agent, why, normalized, commandText, tctx),
  });
}
