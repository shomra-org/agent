import path from 'node:path';

const ARTIFACT_PATH_RE = /(^|\/)(\.?mcp\.json|SKILL\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.aider\.conf\.yml|agent[-_]card\.json)$|(^|\/)\.claude\/(commands|agents)\/[^/]+\.md$|(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.well-known\/agent(-card)?\.json$|(^|\/)\.clinerules|(^|\/)\.github\/copilot-instructions\.md$/i;

export const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool', 'write_to_file', 'replace_in_file', 'new_rule']);

const SHELL_TOOLS_RE = /^(bash|shell|sh|run_command|run_terminal_cmd|execute_command|terminal|exec)$/i;

const EGRESS_TOOL_RE = /fetch|web|http|browser|request|download|curl|url|open/i;

const EGRESS_CMD_RE = /\b(curl|wget|nc|ncat|http|https|invoke-restmethod|invoke-webrequest|irm|iwr|scp|rsync|ftp|telnet)\b/i;

export function guardText(tool, input) {
  const parts = [];
  if (typeof input.command === 'string') parts.push(input.command);
  if (typeof input.cmd === 'string') parts.push(input.cmd);
  if (typeof input.script === 'string') parts.push(input.script);
  if (typeof input.content === 'string') parts.push(input.content);
  if (typeof input.new_string === 'string') parts.push(input.new_string);
  if (typeof input.new_source === 'string') parts.push(input.new_source);
  if (Array.isArray(input.edits)) parts.push(input.edits.map((e) => e?.new_string ?? '').join('\n'));
  if (!parts.length) { try { parts.push(JSON.stringify(input)); } catch { parts.push(String(input)); } }
  return parts.join('\n');
}

export function guardTargetPath(norm) {
  const i = norm.tool_input || {};
  const p = i.file_path ?? i.path ?? i.notebook_path ?? i.filename ?? null;
  return typeof p === 'string' && p.trim() ? p : null;
}

export function guardNeedsServer(tool, input, hasIdentity) {
  if (hasIdentity) return true;
  if (WRITE_TOOLS.has(tool)) {
    const target = String(input.file_path ?? input.path ?? input.notebook_path ?? '').replace(/\\/g, '/');
    return ARTIFACT_PATH_RE.test(target);
  }
  if (tool && tool.startsWith('mcp__')) return true;
  if (EGRESS_TOOL_RE.test(tool || '')) return true;
  if (SHELL_TOOLS_RE.test(tool || '')) {
    const cmd = String(input.command ?? input.cmd ?? input.script ?? '');
    if (EGRESS_CMD_RE.test(cmd)) return true;
    if (/\bmcp\s+add\b|claude\s+mcp\b|@modelcontextprotocol\b|\bmcp[-_]server\b/i.test(cmd)) return true;
  }
  const url = input?.url ?? input?.uri ?? input?.href ?? input?.endpoint;
  if (typeof url === 'string' && url) return true;
  return false;
}

export const MODEL_WRITE_TOOLS = ['write', 'edit', 'multiedit', 'notebookedit', 'create_file', 'str_replace_editor', 'apply_patch', 'write_file'];
