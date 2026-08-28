import os from 'node:os';
import path from 'node:path';
import { SELF_PATH } from '../agents/hook-command.mjs';

export const MCP_HOST_CONFIGS = {
  claude: { label: 'Claude Code', global: () => path.join(os.homedir(), '.claude.json'), local: () => path.join(process.cwd(), '.mcp.json') },
  cursor: { label: 'Cursor', global: () => path.join(os.homedir(), '.cursor', 'mcp.json'), local: () => path.join(process.cwd(), '.cursor', 'mcp.json') },
  gemini: { label: 'Gemini CLI', global: () => path.join(os.homedir(), '.gemini', 'settings.json'), local: () => path.join(process.cwd(), '.gemini', 'settings.json') },
  windsurf: { label: 'Windsurf', global: () => path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json'), local: () => path.join(process.cwd(), '.windsurf', 'mcp_config.json') },
};

export const MCP_HOST_KEYS = Object.keys(MCP_HOST_CONFIGS);

export function shomraMcpEntry() {
  return { command: process.execPath, args: [SELF_PATH, 'mcp', 'serve'] };
}
