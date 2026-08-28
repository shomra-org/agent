import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveAgentIdentityHandle } from '../commands/agent-identity.mjs';
import { isMemoryPath, reportMemoryWrite } from '../commands/memory-scan.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { loadConfig, resolveSettings } from '../core/config.mjs';
import { downrankCodeContext, grade, localScan } from '../detect/guard-signals.mjs';
import { WRITE_TOOLS, guardNeedsServer, guardTargetPath, guardText } from './classify.mjs';
import { emitGuardAsk, emitGuardDeny } from './emit.mjs';
import { guardPathAllowlisted } from './ignore.mjs';
import { screenModelLoad } from './model-load.mjs';
import { normalizeGuardInput } from './normalize.mjs';
import { envFlag, resolveAgentFlag } from './options.mjs';
import { buildGuardBody, reportGuardDecision } from './report.mjs';

const ALLOW_VERDICT = { verdict: 'ALLOW', top: null, findings: [] };

function readHookPayload() {
  try {
    return JSON.parse(fs.readFileSync(0, 'utf8') || '{}');
  } catch {
    return process.exit(0);
  }
}

function localTierDisabled() {
  return process.env.SHOMRA_GUARD_LOCAL === '0'
    || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
}

function screenLocally(normalized, tool, input) {
  const scan = localScan(guardText(tool, input));
  const isWrite = WRITE_TOOLS.has(tool);
  const allowlisted = isWrite && guardPathAllowlisted(normalized.cwd, guardTargetPath(normalized));

  let findings = scan.findings;
  if (allowlisted) findings = [];
  else if (isWrite) findings = downrankCodeContext(scan.findings);

  const top = findings.find((finding) => finding.severity === 'CRITICAL') || findings[0] || null;
  return { ...grade(findings), top, findings };
}

function memoryWriteContent(input) {
  if (typeof input.content === 'string') return input.content;
  if (typeof input.new_string === 'string') return input.new_string;
  return null;
}

async function recordMemoryWrite({ url, apiKey, input, normalized }) {
  const memoryPath = input.file_path || input.path;
  if (!memoryPath || !isMemoryPath(memoryPath) || breakerOpen()) return;

  const content = memoryWriteContent(input);
  if (content == null) return;

  await reportMemoryWrite(url, apiKey, {
    path: String(memoryPath).split(path.sep).join('/'),
    name: path.basename(String(memoryPath)),
    content,
    writer: 'AGENT',
    source: os.hostname(),
    actor: os.userInfo().username,
    sessionId: normalized.session_id,
  });
}

function reportUnauthenticated(agent, status, strict) {
  process.stderr.write(
    `[shomra] guard NOT enforced: the backend rejected this API key (HTTP ${status}). `
    + 'Local Tier-0 screening still ran; org policy, agent identity and flow control did not. '
    + 'Re-enroll with `shomra init --key <key>`.\n',
  );
  if (strict) {
    emitGuardDeny(agent, `Shomra guard could not authenticate (HTTP ${status}); blocked by fail-closed policy.`);
  }
  process.exit(0);
}

async function requestServerDecision({ url, apiKey, agentId, body, agent, strict }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), guardTimeoutMs());
  try {
    const response = await fetch(`${url}/gate/tool-call`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shomra-Key': apiKey,
        ...(agentId ? { 'X-Shomra-Agent': agentId } : {}),
        Connection: 'close',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      if (response.status === 401 || response.status === 403) reportUnauthenticated(agent, response.status, strict);
      throw new Error(`HTTP ${response.status}`);
    }
    const decision = await response.json();
    breakerReset();
    return decision;
  } catch (error) {
    clearTimeout(timer);
    breakerTrip();
    if (strict) emitGuardDeny(agent, `Shomra guard could not be reached (${error.message}); blocked by fail-closed policy.`);
    return process.exit(0);
  }
}

function enforceServerDecision(agent, decision) {
  if (decision?.hold) {
    emitGuardAsk(agent, decision.reason || 'Held for approval by Shomra - waiting on a reviewer. Retry once it’s approved.');
  }
  if (decision?.decision === 'BLOCK') {
    emitGuardDeny(agent, decision.reason || 'Blocked by Shomra security policy.');
  }
}

export async function cmdToolGuard(flags) {
  const agent = resolveAgentFlag(flags);
  const agentId = resolveAgentIdentityHandle(flags);
  const strict = envFlag('SHOMRA_GUARD_STRICT');
  const alwaysEscalate = envFlag('SHOMRA_GUARD_ALWAYS_ESCALATE');
  const { apiKey, url } = resolveSettings(loadConfig());

  const normalized = normalizeGuardInput(agent, readHookPayload());
  const tool = (normalized.tool_name ?? '').trim();
  const input = normalized.tool_input ?? {};

  const local = localTierDisabled() ? ALLOW_VERDICT : screenLocally(normalized, tool, input);
  if (local.verdict === 'BLOCK') {
    await reportGuardDecision(url, apiKey, agentId, buildGuardBody(normalized, agent, 'BLOCK', local.top?.label));
    emitGuardDeny(agent, `Blocked on-machine by Shomra: ${local.top?.label || 'dangerous tool call'}.`);
  }

  await screenModelLoad(agent, tool, input, url);

  if (!apiKey) {
    if (strict) {
      emitGuardDeny(agent, 'Shomra is not configured on this machine (SHOMRA_GUARD_STRICT). Run: shomra init --key shm_…');
    }
    process.exit(0);
  }

  await recordMemoryWrite({ url, apiKey, input, normalized });

  const escalate = alwaysEscalate || local.verdict === 'FLAG' || guardNeedsServer(tool, input, !!agentId);
  if (!escalate) process.exit(0);
  if (!strict && breakerOpen()) process.exit(0);

  const flagged = local.verdict === 'FLAG';
  const decision = await requestServerDecision({
    url,
    apiKey,
    agentId,
    agent,
    strict,
    body: buildGuardBody(normalized, agent, flagged ? 'FLAG' : undefined, flagged ? local.top?.label : undefined),
  });

  enforceServerDecision(agent, decision);
  process.exit(0);
}
