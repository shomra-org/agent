export function resolveAgentIdentityHandle(flags) {
  const v = (flags && flags['agent-id'] && String(flags['agent-id'])) || process.env.SHOMRA_AGENT || '';
  return v && String(v).trim() ? String(v).trim() : null;
}
