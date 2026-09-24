import { AGENT_KEYS } from '../agents/installers.mjs';
import { guardTimeoutMs } from '../core/circuit-breaker.mjs';

export function resolveAgentFlag(flags) {
  const agent = String(flags.agent || 'claude').toLowerCase();
  return AGENT_KEYS.includes(agent) ? agent : 'claude';
}

export function envFlag(name) {
  return ['1', 'true', 'yes', 'on'].includes(String(process.env[name] ?? '').toLowerCase());
}

export function guardWait() {
  return {
    guard_timeout_ms: guardTimeoutMs(),
    ...(String(process.env.SHOMRA_GUARD_TIER ?? '').trim().toLowerCase() === 'fast' ? { screen_tier: 'fast' } : {}),
  };
}
