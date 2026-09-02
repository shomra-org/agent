import { gateMachine } from '../core/api-client.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { resolveCommand } from './command-resolve.mjs';

export function buildGuardBody(norm, agent, clientDecision, clientReason) {
  const command = norm.tool_input?.command ?? norm.tool_input?.cmd ?? norm.tool_input?.script;
  const resolved = typeof command === 'string' ? resolveCommand(command) : null;
  return {
    tool_name: norm.tool_name,
    tool_input: norm.tool_input,
    ...(resolved ? { resolved } : {}),
    cwd: norm.cwd,
    session_id: norm.session_id,
    ...(norm.parent_session_id ? { parent_session_id: norm.parent_session_id } : {}),
    machine: gateMachine(),
    env: detectEnv(),
    agent,
    ...(clientDecision ? { client_decision: clientDecision, client_reason: clientReason } : {}),
  };
}

export async function reportGuardDecision(url, apiKey, agentId, body) {
  if (!apiKey || breakerOpen()) return;
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), Math.min(guardTimeoutMs(), 1000));
    await fetch(`${url}/gate/tool-call`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shomra-Key': apiKey, ...(agentId ? { 'X-Shomra-Agent': agentId } : {}), Connection: 'close' },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(timer);
    breakerReset();
  } catch {
    breakerTrip();
  }
}
