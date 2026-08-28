import path from 'node:path';

export const NEW_TEMPLATES = {
  skill: (name) => ({
    file: path.join(name, 'SKILL.md'),
    content: `---\nname: ${name}\ndescription: One line - what this skill does and when to use it.\nallowed-tools: [Read]\n---\n\n# ${name}\n\nDescribe the skill's job here. Keep the tool grant least-privilege - add only the\ntools it truly needs (Read, Grep, …), never a wildcard ("*").\n\n## Steps\n1. …\n`,
  }),
  command: (name) => ({
    file: path.join('.claude', 'commands', `${name}.md`),
    content: `---\ndescription: One line - what this command does.\nallowed-tools: [Read, Grep]\n---\n\nWrite the prompt here. Avoid \`!\`-bash blocks that run before the prompt and\n\`@\`-references to secret files (.env, .ssh, *.pem) - both pull untrusted content\nstraight into the model.\n`,
  }),
  subagent: (name) => ({
    file: path.join('.claude', 'agents', `${name}.md`),
    content: `---\nname: ${name}\ndescription: When this subagent should be used.\ntools: [Read, Grep]\n---\n\nSystem prompt for the ${name} subagent. Grant only the tools it needs.\n`,
  }),
  'agent-card': (name) => ({
    file: path.join('.well-known', 'agent-card.json'),
    content: JSON.stringify({
      name, description: 'One line - what this agent does.',
      url: `https://example.com/agents/${name}`, version: '0.1.0',
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } },
      skills: [{ id: 'example', name: 'Example', description: 'What this skill does.' }],
    }, null, 2) + '\n',
  }),
  mcp: (name) => ({
    file: '.mcp.json',
    content: JSON.stringify({
      mcpServers: { [name]: { command: 'npx', args: ['-y', '@your-scope/your-mcp-server'], env: { API_TOKEN: '${env:API_TOKEN}' } } },
    }, null, 2) + '\n',
  }),
  rules: () => ({
    file: 'CLAUDE.md',
    content: `# Project rules\n\nGuidance the agent should follow in this repo. Legitimate standing directives are\nfine here - but never instruct the agent to ignore the system prompt, hide actions\nfrom the user, disable safety checks, or send data to an external host.\n\n## Conventions\n- …\n`,
  }),
};
