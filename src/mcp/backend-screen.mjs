import { randomUUID } from 'node:crypto';
import { gateMachine } from '../core/api-client.mjs';
import { breakerOpen, breakerReset, breakerTrip, guardTimeoutMs } from '../core/circuit-breaker.mjs';
import { detectEnv } from '../gate/environment.mjs';
import { keyedFetch } from '../core/keyed-fetch.mjs';

/**
 * WHERE THE SHIM JUDGES A TOOL CALL AND ITS RESULT.
 *
 *   backend   Each call goes to /gate/tool-call and each result to /gate/tool-result -
 *             the same screens the HTTP MCP gateway and the coding-agent hooks use:
 *             the agent's tool policy, taint, steering, the org's own policies, and
 *             findings that land in the org. The local rules still run if the backend
 *             cannot be reached (and SHOMRA_GUARD_STRICT refuses instead).
 *   local     The built-in on-machine rules only. Nothing about the call leaves the
 *             machine - for a user who does not want tool arguments or results sent.
 *
 * ⚠ LOCAL IS A REAL, WEAKER TIER, and it is chosen, never fallen into silently: no
 * tool policy, no taint, no steering, no org policies. The startup check and the
 * tool-list screen still ask the backend in both modes when the machine is enrolled.
 */
export const SCREEN_MODES = ['backend', 'local'];

/**
 * Precedence: the `--screen` flag written into the wrapped launch line, then
 * SHOMRA_MCP_SCREEN, then `mcpScreen` in ~/.shomra/config.json, then the default.
 *
 * ⚠ THE DEFAULT FOLLOWS ENROLMENT: `backend` when this machine has a Shomra key and
 * URL, `local` when it has neither - there is nothing to send to. An unrecognised
 * value is refused loudly rather than read as either mode.
 */
export function resolveScreenMode({ flag, env, config, enrolled }) {
  for (const [source, raw] of [['--screen', flag], ['SHOMRA_MCP_SCREEN', env], ['mcpScreen', config]]) {
    if (raw === undefined || raw === null || raw === '') continue;
    const value = String(raw).trim().toLowerCase();
    if (!SCREEN_MODES.includes(value)) {
      return { mode: null, source, error: `${source}="${raw}" is not a screening mode - use ${SCREEN_MODES.join(' or ')}.` };
    }
    return { mode: value, source };
  }
  return { mode: enrolled ? 'backend' : 'local', source: 'default' };
}

/**
 * One id per shim process. ⚠ A client starts a stdio server once per session, so the
 * process lifetime IS the conversation - which is what taint needs: the secret read
 * on the third call and the upload on the fifth share it. SHOMRA_SESSION_ID wins when
 * the launcher knows the real one.
 */
export function shimSessionId(server) {
  return process.env.SHOMRA_SESSION_ID || `mcp-shim:${String(server).slice(0, 60)}:${randomUUID()}`;
}

/** The server segment is sanitised so `__` in a server name cannot split the tool id wrongly. */
export function mcpToolId(server, tool) {
  const seg = (v) => String(v ?? '').trim().replace(/__+/g, '_').replace(/[^A-Za-z0-9_.-]/g, '_');
  return `mcp__${seg(server)}__${String(tool ?? '').trim()}`;
}

async function post(settings, route, body, agentId) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), guardTimeoutMs());
  try {
    const response = await keyedFetch(`${settings.url}${route}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Shomra-Key': settings.apiKey,
        ...(agentId ? { 'X-Shomra-Agent': agentId } : {}),
        Connection: 'close',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) throw Object.assign(new Error(`HTTP ${response.status}`), { status: response.status });
    const decision = await response.json();
    // ⚠ A 2xx without a decision is not a pass - it is a screen that did not answer.
    if (!['ALLOW', 'FLAG', 'BLOCK'].includes(decision?.decision)) throw new Error('response carried no decision');
    breakerReset();
    return decision;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Returns `{ blocked, held, reason }`, or `{ unreachable: reason }` when the backend
 * did not answer - the caller then runs the local rules (or refuses under strict).
 */
async function judge(settings, route, body, agentId) {
  if (breakerOpen()) return { unreachable: 'circuit open after recent failures' };
  try {
    const d = await post(settings, route, body, agentId);
    const held = d.hold === true;
    return { blocked: d.decision === 'BLOCK' || held, held, approvalId: d.approvalId ?? null, reason: String(d.reason ?? ''), decision: d.decision };
  } catch (error) {
    breakerTrip();
    return { unreachable: error?.message ?? String(error) };
  }
}

export function screenCallRemote({ settings, server, tool, args, sessionId, agentId }) {
  return judge(
    settings,
    '/gate/tool-call',
    {
      tool_name: mcpToolId(server, tool),
      tool_input: args && typeof args === 'object' && !Array.isArray(args) ? args : { arguments: args ?? null },
      session_id: sessionId,
      machine: gateMachine(),
      env: detectEnv(),
      agent: 'mcp-shim',
    },
    agentId,
  );
}

export function screenResultRemote({ settings, server, tool, args, result, sessionId, agentId }) {
  return judge(
    settings,
    '/gate/tool-result',
    {
      tool_name: mcpToolId(server, tool),
      tool_response: result,
      ...(args && typeof args === 'object' && !Array.isArray(args) ? { tool_input: args } : {}),
      session_id: sessionId,
      machine: gateMachine(),
      env: detectEnv(),
      agent: 'mcp-shim',
    },
    agentId,
  );
}
