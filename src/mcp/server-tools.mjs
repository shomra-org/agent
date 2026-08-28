export const MCP_TOOLS = [
  {
    name: 'shomra_check',
    description: 'Gate every AI artifact (MCP configs, skills, slash commands, hooks, rules files) under a path for security issues - local-first, no network needed. Returns findings with file, line, severity and verdict. Run this after editing AI artifacts.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'File or directory to check (default: workspace root).' } },
    },
  },
  {
    name: 'shomra_scan_models',
    description: 'Detect the AI models the code loads (from_pretrained, hf_hub_download, SentenceTransformer, …) and look each up in the Shomra Model Index for known vulnerabilities. Returns each model\'s verdict, findings, and a safe-loading fix plan (kwargs to add to the load call). Run this after adding or changing model-loading code.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'File or directory to scan (default: workspace root).' } },
    },
  },
  {
    name: 'shomra_fix',
    description: 'Generate a minimal security fix for one AI artifact. Returns the fixed content; set apply=true to write it to disk in place.',
    inputSchema: {
      type: 'object',
      properties: {
        file: { type: 'string', description: 'Path to the artifact to fix.' },
        apply: { type: 'boolean', description: 'Write the fix to disk (default: false - return it only).' },
      },
      required: ['file'],
    },
  },
  {
    name: 'shomra_explain',
    description: 'Explain the findings in one AI artifact: why each matters, a one-line exploit, and an honest false-positive read.',
    inputSchema: {
      type: 'object',
      properties: { file: { type: 'string', description: 'Path to the artifact to explain.' } },
      required: ['file'],
    },
  },
  {
    name: 'shomra_review_change',
    description:
      'Security-review content you are ABOUT TO WRITE, before writing it. Pass the proposed file content and its intended path; returns a verdict (ALLOW/FLAG/BLOCK) with findings and line numbers. Nothing is written to disk. Call this before creating or rewriting an MCP config, skill, slash command, subagent, hook, agent card, or rules/memory file - a BLOCK here costs nothing, the same content on disk costs a blocked tool call.',
    inputSchema: {
      type: 'object',
      properties: {
        content: { type: 'string', description: 'The full proposed file content.' },
        path: { type: 'string', description: 'The path you intend to write it to (drives which checks apply).' },
        kind: { type: 'string', description: 'Optional artifact kind: mcp, skill, command, subagent, hook, rules, agent-card, memory.' },
      },
      required: ['content', 'path'],
    },
  },
  {
    name: 'shomra_rules',
    description:
      'Get the security rules in force for this workspace - what Shomra\'s runtime firewall will refuse, tailored to what this repo actually contains, plus any org policy. Call this before writing shell commands, MCP configs, agent artifacts, or model-loading code so you do not generate something that will be blocked.',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string', description: 'Workspace root (default: workspace root).' } },
    },
  },
  {
    name: 'shomra_review_plan',
    description:
      'Threat-model a plan BEFORE implementing it. Pass your plan text; returns any attack paths it would create (untrusted input reaching execution, sensitive data reaching network egress, and so on) plus the conditions to satisfy while you build. Call this once you have a plan for any task that touches untrusted input, credentials, agent tools, or actions with consequences - building the guarded version first is far cheaper than retrofitting it after the firewall refuses a call.',
    inputSchema: {
      type: 'object',
      properties: { plan: { type: 'string', description: 'Your plan, as prose. The steps you intend to take and what they will read and do.' } },
      required: ['plan'],
    },
  },
];

export function mcpToolInvocation(name, rawArguments) {
  const args = rawArguments || {};
  if (name === 'shomra_check') return { args: ['check', args.path ? String(args.path) : '.'] };
  if (name === 'shomra_scan_models') return { args: ['models', args.path ? String(args.path) : '.'] };
  if (name === 'shomra_fix') return { args: ['fix', String(args.file || ''), ...(args.apply ? ['--apply'] : [])] };
  if (name === 'shomra_explain') return { args: ['why', String(args.file || '')] };
  if (name === 'shomra_review_change') {
    if (typeof args.content !== 'string' || !args.path) {
      return { error: 'shomra_review_change requires `content` and `path`.' };
    }
    return {
      args: ['gate', '--stdin', '--path', String(args.path), ...(args.kind ? ['--kind', String(args.kind)] : [])],
      stdin: args.content,
    };
  }
  if (name === 'shomra_rules') return { args: ['rules', args.path ? String(args.path) : '.'] };
  if (name === 'shomra_review_plan') {
    if (typeof args.plan !== 'string' || !args.plan.trim()) {
      return { error: 'shomra_review_plan requires `plan` text.' };
    }
    return { args: ['plan', '-'], stdin: args.plan };
  }
  return { error: `Unknown tool: ${name}` };
}
