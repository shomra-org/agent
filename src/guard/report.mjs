import { gateMachine } from '../core/api-client.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { detectEnv } from '../gate/environment.mjs';

/**
 * ⚠ `fast` buys latency by SPENDING COVERAGE: the server times out every
 * provider-backed screen inside a 100ms budget and reports `minimal` basis, so
 * the verdict comes back honest about what did not run. Unset means FULL - a
 * caller has to ask for the cheaper screen, it is never the default.
 */
export function screenTier() {
  const raw = String(process.env.SHOMRA_GUARD_TIER ?? '').trim().toLowerCase();
  return raw === 'fast' ? 'fast' : undefined;
}

export function buildGuardBody(norm, agent, clientDecision, clientReason) {
  const tier = screenTier();
  return {
    tool_name: norm.tool_name,
    tool_input: norm.tool_input,
    cwd: norm.cwd,
    session_id: norm.session_id,
    ...(norm.parent_session_id ? { parent_session_id: norm.parent_session_id } : {}),
    machine: gateMachine(),
    env: detectEnv(),
    agent,
    ...(clientDecision ? { client_decision: clientDecision, client_reason: clientReason } : {}),
    ...(tier ? { screen_tier: tier } : {}),
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
