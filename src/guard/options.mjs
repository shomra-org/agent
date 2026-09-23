import { AGENT_KEYS } from '../agents/installers.mjs';

export function resolveAgentFlag(flags) {
  const agent = String(flags.agent || 'claude').toLowerCase();
  return AGENT_KEYS.includes(agent) ? agent : 'claude';
}

export function envFlag(name) {
  return ['1', 'true', 'yes', 'on'].includes(String(process.env[name] ?? '').toLowerCase());
}

export function localTierDisabled() {
  return process.env.SHOMRA_GUARD_LOCAL === '0'
    || String(process.env.SHOMRA_GUARD_LOCAL).toLowerCase() === 'false';
}
