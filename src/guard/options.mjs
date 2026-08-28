import { AGENT_KEYS } from '../agents/installers.mjs';

export function resolveAgentFlag(flags) {
  const agent = String(flags.agent || 'claude').toLowerCase();
  return AGENT_KEYS.includes(agent) ? agent : 'claude';
}

export function envFlag(name) {
  return ['1', 'true', 'yes', 'on'].includes(String(process.env[name] ?? '').toLowerCase());
}
