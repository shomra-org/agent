const SPAWN_TOOLS = [
  /^task$/i,
  /^agent$/i,
  /^dispatch[_-]?agent$/i,
  /^(spawn|run|start|invoke|delegate[_-]?to|create|call|route[_-]?to|fork|hand[_-]?off[_-]?to)[_-]?(sub)?[_-]?agents?$/i,
  /^sub[_-]?agents?$/i,
  /^(transfer|hand[_-]?off|handover)[_-]?to[_-]?[\w-]*agent$/i,
  /^(transfer|hand[_-]?off|handover)([_-]?agent)?$/i,
  /^agent[_-]?collaborator$/i,
  /^initiate[_-]?chat$/i,
  /^(delegate[_-]?work|ask[_-]?question)[_-]?to[_-]?co[_-]?worker$/i,
  /^mcp__[^_]+(?:_[^_]+)*__(?:spawn|run|start|invoke|dispatch|delegate[_-]?to|transfer[_-]?to|hand[_-]?off)[_-]?(?:sub[_-]?)?agents?$/i,
];

const AGENT_CLI_SPAWN = [
  /(?:^|[\s;&|(`]|\$\()(?:npx\s+(?:-y\s+)?@anthropic-ai\/claude-code|claude)\b(?:(?![;&|]).)*\s(?:-p|--print)(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()codex\s+(?:exec|e)(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()(?:gemini|qwen)\b(?:(?![;&|]).)*\s(?:-p|--prompt)(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()cursor-agent\b(?:(?![;&|]).)*\s(?:-p|--print)(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()aider\b(?:(?![;&|]).)*\s(?:-m|--message)(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()(?:opencode|goose)\s+run(?=\s|$)/,
  /(?:^|[\s;&|(`]|\$\()amp\s+(?:-x|--execute)(?=\s|$)/,
];

export function isSubAgentSpawnTool(tool) {
  const name = String(tool ?? '').trim();
  if (!name) return false;
  const flat = name.replace(/\s+/g, '_');
  return SPAWN_TOOLS.some((re) => re.test(name) || re.test(flat));
}

export function agentCliSpawn(command) {
  const cmd = String(command ?? '').slice(0, 4000);
  if (!cmd.trim()) return false;
  return AGENT_CLI_SPAWN.some((re) => re.test(cmd));
}
